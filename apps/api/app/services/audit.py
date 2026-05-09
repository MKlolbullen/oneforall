"""Append-only, hash-chained audit log.

Each event's signature is sha256(prev_signature || canonical_json(event_body)).
verify_chain() walks rows in sequence and re-checks every signature. Any tamper
- inserted row, edited payload, deleted row - breaks the chain at that row.

If RECONFORGE_AUDIT_HMAC_KEY is set in the environment, an HMAC-SHA256 over the
same body is computed in addition. The HMAC key never leaves the API host;
verify_chain() will reject rows whose hmac is missing or wrong when a key is
configured.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func
from sqlmodel import Session, select

from app.models import AuditEvent, Role, User


@dataclass
class AuditMaterial:
    sequence: int
    actor_id: str | None
    actor_role: str | None
    action: str
    target_kind: str | None
    target_id: str | None
    payload: dict[str, Any]
    prev_signature: str

    def canonical(self) -> str:
        body = {
            "sequence": self.sequence,
            "actor_id": self.actor_id,
            "actor_role": self.actor_role,
            "action": self.action,
            "target_kind": self.target_kind,
            "target_id": self.target_id,
            "payload": self.payload,
            "prev_signature": self.prev_signature,
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)


def _hmac_key() -> bytes | None:
    val = os.getenv("RECONFORGE_AUDIT_HMAC_KEY")
    return val.encode("utf-8") if val else None


def sign(material: AuditMaterial) -> tuple[str, str | None]:
    canonical = material.canonical()
    sha = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    key = _hmac_key()
    mac = hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest() if key else None
    return sha, mac


def _next_sequence(session: Session) -> int:
    last = session.exec(select(func.max(AuditEvent.sequence))).one()
    return int(last or 0) + 1


def _last_signature(session: Session) -> str:
    last = session.exec(
        select(AuditEvent).order_by(AuditEvent.sequence.desc()).limit(1)
    ).first()
    return last.signature if last else ""


def record(
    session: Session,
    *,
    actor: User | None,
    action: str,
    target_kind: str | None = None,
    target_id: str | None = None,
    payload: dict[str, Any] | None = None,
) -> AuditEvent:
    sequence = _next_sequence(session)
    prev = _last_signature(session)
    actor_id = actor.id if actor else None
    actor_role = (actor.role.value if isinstance(actor.role, Role) else str(actor.role)) if actor else None

    material = AuditMaterial(
        sequence=sequence,
        actor_id=actor_id,
        actor_role=actor_role,
        action=action,
        target_kind=target_kind,
        target_id=target_id,
        payload=payload or {},
        prev_signature=prev,
    )
    sig, mac = sign(material)

    body = {**material.payload}
    if mac is not None:
        body["_hmac"] = mac

    evt = AuditEvent(
        sequence=sequence,
        actor_id=actor_id,
        actor_role=actor_role,
        action=action,
        target_kind=target_kind,
        target_id=target_id,
        payload=body,
        prev_signature=prev,
        signature=sig,
    )
    # Flush so the row gets a sequence in this transaction without expiring
    # other ORM objects in the caller's session. The caller commits.
    session.add(evt)
    session.flush()
    return evt


@dataclass
class ChainBreak:
    sequence: int
    reason: str


def verify_chain(session: Session) -> list[ChainBreak]:
    """Re-walk the chain in order. Returns a list of breaks; an empty list
    means the chain is intact."""
    breaks: list[ChainBreak] = []
    rows = list(session.exec(select(AuditEvent).order_by(AuditEvent.sequence)).all())
    prev = ""
    expected_seq = 1
    key = _hmac_key()
    for row in rows:
        if row.sequence != expected_seq:
            breaks.append(ChainBreak(row.sequence,
                                      f"non-contiguous sequence (expected {expected_seq})"))
        if row.prev_signature != prev:
            breaks.append(ChainBreak(row.sequence, "prev_signature mismatch"))

        # Recompute signature without the embedded _hmac (we add it after signing)
        body = dict(row.payload or {})
        recorded_mac = body.pop("_hmac", None)
        material = AuditMaterial(
            sequence=row.sequence,
            actor_id=row.actor_id,
            actor_role=row.actor_role,
            action=row.action,
            target_kind=row.target_kind,
            target_id=row.target_id,
            payload=body,
            prev_signature=row.prev_signature,
        )
        sha, mac = sign(material)
        if sha != row.signature:
            breaks.append(ChainBreak(row.sequence, "signature mismatch"))
        if key is not None:
            if recorded_mac is None:
                breaks.append(ChainBreak(row.sequence, "missing _hmac (key configured)"))
            elif recorded_mac != mac:
                breaks.append(ChainBreak(row.sequence, "_hmac mismatch"))
        prev = row.signature
        expected_seq = row.sequence + 1
    return breaks
