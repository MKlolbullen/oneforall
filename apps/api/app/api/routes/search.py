"""Cross-entity search.

Single endpoint backing the global search palette. Returns up to `limit` hits
per entity type so an operator can jump to any target / run / finding / loot /
workflow / workspace without remembering which page filter to use.

Tools and profiles come from the registry (in-memory) rather than the DB; we
join them into the same payload shape so the frontend only needs one fetch.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlmodel import Session, select

from app.db import get_session
from app.models import Finding, LootItem, Run, Target, User, Webhook, Workflow, Workspace
from app.services.auth import current_user
from app.services.tool_registry import get_registry

router = APIRouter(prefix="/search", tags=["search"])

# Same LIKE-escape pattern the findings list uses; keeps wildcard / metachar
# characters in the operator's query from leaking into the SQL pattern.
def _escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")


@router.get("")
def search(
    q: str = Query(min_length=1, max_length=120),
    workspace_id: str | None = Query(None, description="Optional workspace scope"),
    limit: int = Query(8, ge=1, le=25),
    session: Session = Depends(get_session),
    _user: User = Depends(current_user),
) -> dict[str, Any]:
    """Return up to `limit` matches per category. Empty `q` is rejected by the
    Query validator so the endpoint never returns the full table."""
    needle = q.strip()
    if not needle:
        return _empty()
    like = f"%{_escape_like(needle)}%"

    # Targets — host substring; workspace_id narrows when present
    t_q = select(Target).where(Target.value.ilike(like, escape="\\"))  # type: ignore[union-attr]
    if workspace_id:
        t_q = t_q.where(Target.workspace_id == workspace_id)
    targets = list(session.exec(t_q.order_by(Target.created_at.desc()).limit(limit)).all())

    # Runs — id prefix (operators often paste a short run id) OR profile name
    r_q = select(Run).where(
        Run.id.like(f"{needle}%") | Run.profile_id.ilike(like, escape="\\")  # type: ignore[union-attr]
    )
    if workspace_id:
        r_q = r_q.where(Run.workspace_id == workspace_id)
    runs = list(session.exec(r_q.order_by(Run.created_at.desc()).limit(limit)).all())

    # Findings — title or evidence substring
    f_q = select(Finding).where(
        Finding.title.ilike(like, escape="\\")  # type: ignore[union-attr]
        | Finding.evidence.ilike(like, escape="\\")  # type: ignore[union-attr]
    )
    if workspace_id:
        f_q = f_q.where(Finding.workspace_id == workspace_id)
    findings = list(session.exec(f_q.order_by(Finding.created_at.desc()).limit(limit)).all())

    # Loot — label or host substring
    l_q = select(LootItem).where(
        LootItem.label.ilike(like, escape="\\")  # type: ignore[union-attr]
        | LootItem.host.ilike(like, escape="\\")  # type: ignore[union-attr]
    )
    if workspace_id:
        l_q = l_q.where(LootItem.workspace_id == workspace_id)
    loot = list(session.exec(l_q.order_by(LootItem.created_at.desc()).limit(limit)).all())

    # Workflows / Workspaces / Webhooks — name substring
    wf_q = select(Workflow).where(Workflow.name.ilike(like, escape="\\"))  # type: ignore[union-attr]
    if workspace_id:
        wf_q = wf_q.where(Workflow.workspace_id == workspace_id)
    workflows = list(session.exec(wf_q.order_by(Workflow.updated_at.desc()).limit(limit)).all())

    ws_q = select(Workspace).where(Workspace.name.ilike(like, escape="\\"))  # type: ignore[union-attr]
    workspaces = list(session.exec(ws_q.order_by(Workspace.created_at.desc()).limit(limit)).all())

    wh_q = select(Webhook).where(Webhook.name.ilike(like, escape="\\"))  # type: ignore[union-attr]
    if workspace_id:
        wh_q = wh_q.where(Webhook.workspace_id == workspace_id)
    webhooks = list(session.exec(wh_q.order_by(Webhook.created_at.desc()).limit(limit)).all())

    # Tools + profiles live in the registry; filter in Python on id / name /
    # description / tags. Registries are small enough (~200 entries) that a
    # full scan per keystroke is cheaper than building a search index.
    registry = get_registry()
    needle_lc = needle.lower()
    tool_hits: list[dict[str, Any]] = []
    for tool in registry.list_tools():
        hay = " ".join((tool.id, tool.name, tool.description, " ".join(tool.tags or []))).lower()
        if needle_lc in hay:
            tool_hits.append({
                "id": tool.id, "name": tool.name, "category": tool.category,
                "risk": tool.risk.value if hasattr(tool.risk, "value") else str(tool.risk),
                "description": (tool.description or "")[:120],
            })
        if len(tool_hits) >= limit:
            break

    profile_hits: list[dict[str, Any]] = []
    for profile in registry.list_profiles():
        hay = " ".join((profile.get("id", ""), profile.get("name", ""),
                        profile.get("description", ""))).lower()
        if needle_lc in hay:
            profile_hits.append({
                "id": profile.get("id"), "name": profile.get("name"),
                "risk": profile.get("risk"),
                "description": (profile.get("description") or "")[:120],
                "step_count": len(profile.get("steps") or []),
            })
        if len(profile_hits) >= limit:
            break

    return {
        "q": needle,
        "workspaces": [{"id": w.id, "name": w.name, "description": w.description} for w in workspaces],
        "targets": [
            {"id": t.id, "value": t.value, "type": t.type, "workspace_id": t.workspace_id,
             "active_allowed": t.active_allowed, "in_scope": t.in_scope}
            for t in targets
        ],
        "runs": [
            {"id": r.id, "profile_id": r.profile_id, "workspace_id": r.workspace_id,
             "target_id": r.target_id,
             "status": r.status.value if hasattr(r.status, "value") else str(r.status),
             "risk": r.risk.value if hasattr(r.risk, "value") else str(r.risk),
             "created_at": r.created_at.isoformat() if r.created_at else None}
            for r in runs
        ],
        "findings": [
            {"id": f.id, "title": f.title, "severity": f.severity, "category": f.category,
             "status": f.status, "run_id": f.run_id, "workspace_id": f.workspace_id,
             "tool_source": f.tool_source}
            for f in findings
        ],
        "loot": [
            {"id": it.id, "label": it.label, "kind": it.kind, "severity": it.severity,
             "run_id": it.run_id, "workspace_id": it.workspace_id, "host": it.host}
            for it in loot
        ],
        "workflows": [
            {"id": wf.id, "name": wf.name, "workspace_id": wf.workspace_id,
             "step_count": len((wf.body or {}).get("steps") or []),
             "updated_at": wf.updated_at.isoformat() if wf.updated_at else None}
            for wf in workflows
        ],
        "webhooks": [
            {"id": wh.id, "name": wh.name, "workspace_id": wh.workspace_id,
             "is_active": wh.is_active}
            for wh in webhooks
        ],
        "tools": tool_hits,
        "profiles": profile_hits,
    }


def _empty() -> dict[str, Any]:
    return {"q": "", "workspaces": [], "targets": [], "runs": [], "findings": [],
            "loot": [], "workflows": [], "webhooks": [], "tools": [], "profiles": []}
