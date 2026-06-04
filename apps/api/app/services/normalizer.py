from __future__ import annotations

import contextlib
import json
import re
from typing import Any

from sqlmodel import Session, select

from app.models import Asset, Finding
from app.services import loot as loot_svc
from app.services.file_artifact import FileArtifactHint, classify_file_url
from app.services.secrets_extractor import (
    SecretMatch,
    extract_secrets_from_text,
    parse_gitleaks_json,
    parse_secretfinder_json,
    parse_trufflehog_json,
)

DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
URL_RE = re.compile(r"^https?://", re.IGNORECASE)
SEVERITY_RE = re.compile(r"\[(critical|high|medium|low|info)\]", re.IGNORECASE)


def upsert_asset(
    session: Session,
    *,
    workspace_id: str,
    run_id: str,
    type_: str,
    value: str,
    source: str,
    confidence: float = 0.8,
    meta: dict[str, Any] | None = None,
) -> Asset:
    existing = session.exec(
        select(Asset).where(
            Asset.workspace_id == workspace_id,
            Asset.type == type_,
            Asset.value == value,
        )
    ).first()
    if existing:
        existing.source = source
        existing.confidence = max(existing.confidence, confidence)
        existing.run_id = run_id
        existing.meta = {**(existing.meta or {}), **(meta or {})}
        session.add(existing)
        session.commit()
        session.refresh(existing)
        return existing
    asset = Asset(
        workspace_id=workspace_id,
        run_id=run_id,
        type=type_,
        value=value,
        source=source,
        confidence=confidence,
        meta=meta or {},
    )
    session.add(asset)
    session.commit()
    session.refresh(asset)
    return asset


def _finding(
    session: Session,
    *,
    workspace_id: str,
    run_id: str,
    tool_id: str,
    title: str,
    severity: str = "info",
    category: str = "scanner-output",
    evidence: str | None = None,
    meta: dict[str, Any] | None = None,
) -> Finding:
    finding = Finding(
        workspace_id=workspace_id,
        run_id=run_id,
        title=title[:180],
        severity=severity.lower(),
        category=category,
        evidence=evidence or title,
        tool_source=tool_id,
        meta=meta or {},
    )
    session.add(finding)
    session.commit()
    session.refresh(finding)
    with contextlib.suppress(Exception):
        loot_svc.record_from_finding(session, finding)
    return finding


def _secret_finding(
    session: Session,
    *,
    workspace_id: str,
    run_id: str,
    tool_id: str,
    match: SecretMatch,
    raw: str,
) -> Finding:
    """Persist a SecretMatch as a high-severity Finding.

    The finding carries the fingerprint and kind in `meta` so a downstream
    artifact writer (runner._maybe_emit_secrets_artifact) can join on it.
    We deliberately don't put the redacted value in the title — the title
    has to stay short for the Results table — but the evidence field gets
    enough context for triage."""
    return _finding(
        session,
        workspace_id=workspace_id,
        run_id=run_id,
        tool_id=tool_id,
        title=f"Secret detected: {match.kind} ({match.fingerprint})",
        severity=match.severity,
        category="secret-exposed",
        evidence=f"{match.rationale}\nfingerprint: {match.fingerprint}\nredacted: {match.redacted}\ncontext: {match.context}",
        meta={
            "secret": match.as_payload(),
            "raw": raw[:1000] if raw else "",
        },
    )


def _normalize_json_line(
    session: Session,
    *,
    workspace_id: str,
    run_id: str,
    tool_id: str,
    raw: str,
    data: dict[str, Any],
) -> Asset | Finding | None:
    # Secret-scanner shapes come first so a trufflehog or gitleaks JSON line
    # never falls into the generic url/host extractor — its `Raw` field
    # would otherwise be misclassified as a URL or domain.
    if any(key in data for key in ("DetectorName", "detector_name", "Verified", "verified")):
        match = parse_trufflehog_json(data)
        if match is not None:
            return _secret_finding(session, workspace_id=workspace_id, run_id=run_id, tool_id=tool_id, match=match, raw=raw)
    if "RuleID" in data or "Secret" in data:
        match = parse_gitleaks_json(data)
        if match is not None:
            return _secret_finding(session, workspace_id=workspace_id, run_id=run_id, tool_id=tool_id, match=match, raw=raw)
    if "match" in data and ("name" in data or "type" in data) and "string" not in data.get("kind", ""):
        match = parse_secretfinder_json(data)
        if match is not None:
            return _secret_finding(session, workspace_id=workspace_id, run_id=run_id, tool_id=tool_id, match=match, raw=raw)

    # ProjectDiscovery-style httpx output commonly has url/input/host fields.
    for key in ("url", "matched-at", "matched", "endpoint"):
        value = data.get(key)
        if isinstance(value, str) and URL_RE.match(value):
            hint = classify_file_url(value)
            meta: dict[str, Any] = {"raw": raw, "json": data}
            if hint is not None:
                # Attach the file classification on the asset so the Loot
                # service can promote noisy-but-juicy URLs without re-parsing.
                meta["file_artifact"] = hint.as_meta()
            return upsert_asset(
                session,
                workspace_id=workspace_id,
                run_id=run_id,
                type_="url",
                value=value,
                source=tool_id,
                confidence=0.9,
                meta=meta,
            )

    host = data.get("host") or data.get("input") or data.get("ip")
    if isinstance(host, str):
        clean_host = host.split(":", 1)[0].strip()
        if IP_RE.match(clean_host):
            return upsert_asset(
                session,
                workspace_id=workspace_id,
                run_id=run_id,
                type_="ip",
                value=clean_host,
                source=tool_id,
                confidence=0.9,
                meta={"raw": raw, "json": data},
            )
        if DOMAIN_RE.match(clean_host):
            return upsert_asset(
                session,
                workspace_id=workspace_id,
                run_id=run_id,
                type_="domain",
                value=clean_host.lower(),
                source=tool_id,
                confidence=0.9,
                meta={"raw": raw, "json": data},
            )

    # Nuclei JSONL usually exposes template-id, info.severity and matched-at.
    if "template-id" in data or "template" in data:
        info = data.get("info") if isinstance(data.get("info"), dict) else {}
        severity = str(info.get("severity") or data.get("severity") or "info")
        name = str(info.get("name") or data.get("template-id") or data.get("template") or "Nuclei finding")
        matched = str(data.get("matched-at") or data.get("host") or "")
        return _finding(
            session,
            workspace_id=workspace_id,
            run_id=run_id,
            tool_id=tool_id,
            title=f"{name} {matched}".strip(),
            severity=severity,
            category="template-finding",
            evidence=raw,
            meta={"json": data},
        )

    return None


def normalize_tool_line(
    session: Session,
    *,
    workspace_id: str,
    run_id: str,
    tool_id: str,
    line: str,
) -> Asset | Finding | None:
    value = line.strip()
    if not value:
        return None

    if value.startswith("{") and value.endswith("}"):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict):
            normalized = _normalize_json_line(
                session,
                workspace_id=workspace_id,
                run_id=run_id,
                tool_id=tool_id,
                raw=line,
                data=parsed,
            )
            if normalized:
                return normalized

    # Raw-text secret detection. Runs after JSON / URL / IP / domain matches
    # so a trufflehog JSONL line still hits the structured branch above. For
    # plain stdout from custom scripts or curl, the regex catalogue picks up
    # leaked credentials and turns them into a high-severity Finding.
    matches = extract_secrets_from_text(value, max_matches=3)
    if matches:
        return _secret_finding(
            session,
            workspace_id=workspace_id,
            run_id=run_id,
            tool_id=tool_id,
            match=matches[0],
            raw=line,
        )

    if URL_RE.match(value):
        hint = classify_file_url(value)
        meta: dict[str, Any] = {"raw": line}
        if hint is not None:
            meta["file_artifact"] = hint.as_meta()
        return upsert_asset(
            session,
            workspace_id=workspace_id,
            run_id=run_id,
            type_="url",
            value=value,
            source=tool_id,
            meta=meta,
        )
    if IP_RE.match(value):
        return upsert_asset(
            session,
            workspace_id=workspace_id,
            run_id=run_id,
            type_="ip",
            value=value,
            source=tool_id,
            meta={"raw": line},
        )
    if DOMAIN_RE.match(value):
        return upsert_asset(
            session,
            workspace_id=workspace_id,
            run_id=run_id,
            type_="domain",
            value=value.lower(),
            source=tool_id,
            meta={"raw": line},
        )

    severity_match = SEVERITY_RE.search(value)
    if "CVE-" in value or severity_match or ("[" in value and "]" in value):
        return _finding(
            session,
            workspace_id=workspace_id,
            run_id=run_id,
            tool_id=tool_id,
            title=value,
            severity=severity_match.group(1).lower() if severity_match else "info",
            evidence=value,
            meta={"raw": line},
        )
    return None
