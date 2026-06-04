"""Webhook CRUD + test.

Workspace-scoped outbound webhooks fired on run lifecycle events. Each row
is owned by the user who created it; owner-or-admin may edit/delete (mirrors
the API-key and workflow rules). POST /{id}/test sends a synthetic message
so operators can validate a URL without waiting for a real run to finish.
"""
from __future__ import annotations

import asyncio
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from app.db import get_session
from app.models import ROLE_RANK, Role, User, Webhook, Workspace, now_utc
from app.services import audit
from app.services.auth import current_user, require_role

router = APIRouter(prefix="/webhooks", tags=["webhooks"])

ALLOWED_EVENTS = {"run.completed", "run.failed", "run.cancelled"}
WEBHOOK_TIMEOUT = 5.0


# ---------- IO models ------------------------------------------------------

class WebhookCreate(BaseModel):
    workspace_id: str
    name: str = Field(min_length=1, max_length=120)
    url: str = Field(min_length=8, max_length=2048)
    events: list[str] = Field(default_factory=lambda: ["run.completed", "run.failed"])
    is_active: bool = True


class WebhookUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    url: str | None = Field(default=None, min_length=8, max_length=2048)
    events: list[str] | None = None
    is_active: bool | None = None


class WebhookRead(BaseModel):
    id: str
    workspace_id: str
    name: str
    url: str
    events: list[str]
    is_active: bool
    created_by: str | None
    created_at: str
    updated_at: str
    last_used_at: str | None
    last_status: int | None
    last_error: str | None


class WebhookTestResult(BaseModel):
    delivered: bool
    status: int | None
    error: str | None


def _to_read(wh: Webhook) -> WebhookRead:
    return WebhookRead(
        id=wh.id, workspace_id=wh.workspace_id, name=wh.name, url=wh.url,
        events=wh.events or [], is_active=wh.is_active,
        created_by=wh.created_by,
        created_at=wh.created_at.isoformat() if wh.created_at else "",
        updated_at=wh.updated_at.isoformat() if wh.updated_at else "",
        last_used_at=wh.last_used_at.isoformat() if wh.last_used_at else None,
        last_status=wh.last_status,
        last_error=wh.last_error,
    )


def _can_mutate(user: User, wh: Webhook) -> bool:
    return wh.created_by == user.id or ROLE_RANK[user.role] >= ROLE_RANK[Role.admin]


def _validate_events(events: list[str]) -> list[str]:
    cleaned = [e for e in events if e in ALLOWED_EVENTS]
    if not cleaned:
        raise HTTPException(
            422,
            f"events must include at least one of {sorted(ALLOWED_EVENTS)}",
        )
    return cleaned


# ---------- Routes --------------------------------------------------------

@router.get("", response_model=list[WebhookRead])
def list_webhooks(
    workspace_id: str | None = None,
    session: Session = Depends(get_session),
    _user: User = Depends(current_user),
) -> list[WebhookRead]:
    query = select(Webhook).order_by(Webhook.created_at.desc())
    if workspace_id:
        query = query.where(Webhook.workspace_id == workspace_id)
    return [_to_read(w) for w in session.exec(query).all()]


@router.get("/{webhook_id}", response_model=WebhookRead)
def get_webhook(
    webhook_id: str,
    session: Session = Depends(get_session),
    _user: User = Depends(current_user),
) -> WebhookRead:
    wh = session.get(Webhook, webhook_id)
    if not wh:
        raise HTTPException(404, "Webhook not found")
    return _to_read(wh)


@router.post("", response_model=WebhookRead, status_code=201)
def create_webhook(
    payload: WebhookCreate,
    session: Session = Depends(get_session),
    user: User = Depends(require_role(Role.operator)),
) -> WebhookRead:
    workspace = session.get(Workspace, payload.workspace_id)
    if not workspace:
        raise HTTPException(404, "Workspace not found")
    if not (payload.url.startswith("http://") or payload.url.startswith("https://")):
        raise HTTPException(422, "url must start with http:// or https://")
    events = _validate_events(payload.events)
    wh = Webhook(
        workspace_id=payload.workspace_id,
        name=payload.name,
        url=payload.url,
        events=events,
        is_active=payload.is_active,
        created_by=user.id,
    )
    session.add(wh)
    session.commit()
    session.refresh(wh)
    audit.record(
        session, actor=user, action="webhook.created",
        target_kind="webhook", target_id=wh.id,
        payload={"workspace_id": wh.workspace_id, "events": events, "is_active": wh.is_active},
    )
    session.commit()
    return _to_read(wh)


@router.put("/{webhook_id}", response_model=WebhookRead)
def update_webhook(
    webhook_id: str,
    payload: WebhookUpdate,
    session: Session = Depends(get_session),
    user: User = Depends(require_role(Role.operator)),
) -> WebhookRead:
    wh = session.get(Webhook, webhook_id)
    if not wh:
        raise HTTPException(404, "Webhook not found")
    if not _can_mutate(user, wh):
        raise HTTPException(403, "Only the webhook's owner or an admin may edit it")

    changes: dict[str, Any] = {}
    if payload.name is not None and payload.name != wh.name:
        changes["name"] = {"from": wh.name, "to": payload.name}
        wh.name = payload.name
    if payload.url is not None and payload.url != wh.url:
        if not (payload.url.startswith("http://") or payload.url.startswith("https://")):
            raise HTTPException(422, "url must start with http:// or https://")
        changes["url"] = "updated"
        wh.url = payload.url
    if payload.events is not None:
        events = _validate_events(payload.events)
        if events != (wh.events or []):
            changes["events"] = events
            wh.events = events
    if payload.is_active is not None and payload.is_active != wh.is_active:
        changes["is_active"] = {"from": wh.is_active, "to": payload.is_active}
        wh.is_active = payload.is_active

    if changes:
        wh.updated_at = now_utc()
        session.add(wh)
        audit.record(session, actor=user, action="webhook.updated",
                     target_kind="webhook", target_id=wh.id, payload=changes)
        session.commit()
        session.refresh(wh)
    return _to_read(wh)


@router.delete("/{webhook_id}", status_code=204)
def delete_webhook(
    webhook_id: str,
    session: Session = Depends(get_session),
    user: User = Depends(require_role(Role.operator)),
) -> None:
    wh = session.get(Webhook, webhook_id)
    if not wh:
        raise HTTPException(404, "Webhook not found")
    if not _can_mutate(user, wh):
        raise HTTPException(403, "Only the webhook's owner or an admin may delete it")
    audit.record(session, actor=user, action="webhook.deleted",
                 target_kind="webhook", target_id=wh.id, payload={"name": wh.name})
    session.delete(wh)
    session.commit()


@router.post("/{webhook_id}/test", response_model=WebhookTestResult)
async def test_webhook(
    webhook_id: str,
    session: Session = Depends(get_session),
    user: User = Depends(require_role(Role.operator)),
) -> WebhookTestResult:
    """Fire a synthetic message at the webhook so an operator can confirm
    the URL is reachable + the receiver accepts the payload shape. Updates
    last_used_at / last_status / last_error on the row so the UI shows the
    same delivery state real-run notifications would have produced."""
    wh = session.get(Webhook, webhook_id)
    if not wh:
        raise HTTPException(404, "Webhook not found")
    body = {"text": f":wave: ReconForge webhook test from `{user.username}` "
                    f"({wh.name}) — if you see this in your channel, delivery works."}
    status_code: int | None = None
    error: str | None = None
    try:
        async with httpx.AsyncClient(timeout=WEBHOOK_TIMEOUT) as client:
            r = await client.post(wh.url, json=body)
            status_code = r.status_code
            if r.status_code >= 300:
                error = f"HTTP {r.status_code}: {r.text[:200]}"
    except Exception as exc:  # noqa: BLE001 - surface any delivery failure
        error = str(exc)[:400]

    wh.last_used_at = now_utc()
    wh.last_status = status_code
    wh.last_error = error
    session.add(wh)
    audit.record(session, actor=user, action="webhook.tested",
                 target_kind="webhook", target_id=wh.id,
                 payload={"status": status_code, "error": error})
    session.commit()
    return WebhookTestResult(delivered=error is None, status=status_code, error=error)


# ---------- Internal: used by notifications fan-out ------------------------

async def deliver(wh: Webhook, body: dict[str, Any]) -> tuple[int | None, str | None]:
    """Single delivery attempt. Used by services/notifications.py for fan-out
    on real run events. Returns (status_code, error) without raising — webhook
    failures must never crash the run lifecycle."""
    try:
        async with httpx.AsyncClient(timeout=WEBHOOK_TIMEOUT) as client:
            r = await client.post(wh.url, json=body)
            if r.status_code >= 300:
                return r.status_code, f"HTTP {r.status_code}: {r.text[:200]}"
            return r.status_code, None
    except Exception as exc:  # noqa: BLE001
        return None, str(exc)[:400]


async def fanout(workspace_id: str, event_type: str, text: str,
                 session_factory: Any) -> None:
    """Deliver `text` to every active workspace webhook subscribed to
    event_type. Updates each webhook's last_used_at/last_status/last_error
    so the UI reflects reality. Concurrent fan-out for speed."""
    with session_factory() as session:
        hooks = list(session.exec(
            select(Webhook).where(
                Webhook.workspace_id == workspace_id,
                Webhook.is_active == True,  # noqa: E712 — SQLAlchemy needs `==`
            )
        ).all())
    targets = [h for h in hooks if event_type in (h.events or [])]
    if not targets:
        return

    async def _one(h: Webhook) -> None:
        status_code, error = await deliver(h, {"text": text})
        with session_factory() as session:
            row = session.get(Webhook, h.id)
            if row is None:
                return
            row.last_used_at = now_utc()
            row.last_status = status_code
            row.last_error = error
            session.add(row)
            session.commit()

    await asyncio.gather(*[_one(h) for h in targets], return_exceptions=True)
