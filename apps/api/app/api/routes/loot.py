"""Loot API.

Read + export the curated high-signal layer (secrets, credentials, takeovers,
exposures, critical/high vulns) and trigger an explicit re-index of a run.

Loot rows are derived from Findings; see app.services.loot.
"""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy import case
from sqlmodel import Session, select

from app.db import get_session
from app.models import LootItem, Role, Run, User
from app.services import audit, loot as loot_svc
from app.services.auth import current_user, require_role

router = APIRouter(prefix="/loot", tags=["loot"])

# Severity-rank ordering in SQL so pagination is stable across pages (an
# in-Python sort would re-order each page in isolation and bury criticals).
_SEVERITY_CASE = case(
    {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4},
    value=LootItem.severity,
    else_=5,
)


class LootPage(BaseModel):
    total: int
    items: list[LootItem]
    facets: dict[str, list[str]] = Field(default_factory=dict)


def _apply_filters(query, *, workspace_id, run_id, kind, severity, host):
    if workspace_id:
        query = query.where(LootItem.workspace_id == workspace_id)
    if run_id:
        query = query.where(LootItem.run_id == run_id)
    if kind:
        query = query.where(LootItem.kind == kind)
    if severity:
        query = query.where(LootItem.severity == severity)
    if host:
        query = query.where(LootItem.host == host)
    return query


@router.get("", response_model=LootPage)
def list_loot(
    workspace_id: str | None = None,
    run_id: str | None = None,
    kind: str | None = None,
    severity: str | None = None,
    host: str | None = None,
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_session),
    _user: User = Depends(current_user),
) -> LootPage:
    """Severity-ranked loot list with kind/severity facets in one round trip."""
    base = _apply_filters(
        select(LootItem), workspace_id=workspace_id, run_id=run_id,
        kind=kind, severity=severity, host=host,
    )
    rows = list(
        session.exec(
            base.order_by(_SEVERITY_CASE, LootItem.created_at.desc())
            .offset(offset)
            .limit(limit)
        ).all()
    )

    # Facets reflect the workspace/run scope, not the kind/severity filter, so
    # the UI dropdowns stay populated after a selection narrows the rows.
    facet_scope = select(LootItem)
    if workspace_id:
        facet_scope = facet_scope.where(LootItem.workspace_id == workspace_id)
    if run_id:
        facet_scope = facet_scope.where(LootItem.run_id == run_id)
    all_rows = list(session.exec(facet_scope).all())
    kinds = sorted({r.kind for r in all_rows})
    severities = sorted(
        {r.severity for r in all_rows},
        key=lambda s: loot_svc.SEVERITY_RANK.get(s, 9),
    )

    return LootPage(
        total=len(all_rows),
        items=rows,
        facets={"kinds": kinds, "severities": severities},
    )


EXPORT_FORMATS = {"csv", "json", "md"}
EXPORT_MEDIA = {
    "csv": "text/csv; charset=utf-8",
    "json": "application/json",
    "md": "text/markdown; charset=utf-8",
}
EXPORT_MAX_ROWS = 10_000


@router.get("/export")
def export_loot(
    fmt: str = Query("csv", alias="format", description="csv | json | md"),
    workspace_id: str | None = None,
    run_id: str | None = None,
    kind: str | None = None,
    severity: str | None = None,
    host: str | None = None,
    session: Session = Depends(get_session),
    _user: User = Depends(current_user),
) -> Response:
    """Export loot (filtered like /api/loot) as CSV / JSON / Markdown so an
    operator can drop it straight into a report. Capped at EXPORT_MAX_ROWS."""
    if fmt not in EXPORT_FORMATS:
        raise HTTPException(400, f"invalid format {fmt!r}; one of {sorted(EXPORT_FORMATS)}")

    base = _apply_filters(
        select(LootItem), workspace_id=workspace_id, run_id=run_id,
        kind=kind, severity=severity, host=host,
    )
    rows = list(
        session.exec(
            base.order_by(_SEVERITY_CASE, LootItem.created_at.desc()).limit(EXPORT_MAX_ROWS)
        ).all()
    )

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"reconforge-loot-{stamp}.{fmt}"

    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)
        writer.writerow(["id", "kind", "label", "severity", "source_tool", "host",
                         "run_id", "finding_id", "value_preview", "created_at"])
        for r in rows:
            writer.writerow([
                r.id, r.kind, r.label, r.severity, r.source_tool or "", r.host or "",
                r.run_id or "", r.finding_id or "",
                (r.value_preview or "").replace("\n", " ⏎ "),
                r.created_at.isoformat() if r.created_at else "",
            ])
        body = buf.getvalue().encode()
    elif fmt == "json":
        body = json.dumps(
            [{**r.model_dump(),
              "created_at": r.created_at.isoformat() if r.created_at else None}
             for r in rows],
            indent=2,
        ).encode()
    else:  # md
        lines = [
            f"# Loot export — {len(rows)} rows",
            "",
            f"_Generated: {stamp} UTC_",
            "",
            "| Severity | Kind | Label | Host | Tool |",
            "|---|---|---|---|---|",
        ]
        for r in rows:
            label = (r.label or "").replace("|", "\\|")
            host = (r.host or "").replace("|", "\\|")
            tool = (r.source_tool or "").replace("|", "\\|")
            lines.append(f"| {r.severity} | {r.kind} | {label} | {host} | {tool} |")
        body = ("\n".join(lines) + "\n").encode()

    return Response(
        content=body,
        media_type=EXPORT_MEDIA[fmt],
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Row-Count": str(len(rows)),
            "X-Row-Cap": str(EXPORT_MAX_ROWS),
        },
    )


class ReindexResult(BaseModel):
    run_id: str
    indexed: int


@router.post("/runs/{run_id}/reindex", response_model=ReindexResult)
def reindex_run_loot(
    run_id: str,
    session: Session = Depends(get_session),
    user: User = Depends(require_role(Role.operator)),
) -> ReindexResult:
    """Re-derive loot for a run from its current findings. Idempotent — existing
    rows are kept, only newly-qualifying findings add rows."""
    run = session.get(Run, run_id)
    if not run:
        raise HTTPException(404, "Run not found")
    items = loot_svc.index_run(session, workspace_id=run.workspace_id, run_id=run_id)
    audit.record(
        session, actor=user, action="loot.reindex",
        target_kind="run", target_id=run_id, payload={"indexed": len(items)},
    )
    session.commit()
    return ReindexResult(run_id=run_id, indexed=len(items))
