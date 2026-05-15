from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy import case
from sqlmodel import Session, select, func

from app.db import get_session
from app.models import Artifact, Asset, Finding, Role, Run, Target, User, now_utc
from app.services import audit
from app.services.artifacts import ArtifactStore
from app.services.auth import current_user, require_role

import csv
import io
import json
from datetime import datetime, timezone

router = APIRouter(tags=["assets-findings"])

VALID_FINDING_STATUSES = {"new", "triaged", "false_positive", "fixed", "closed"}
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
# SQL CASE expression that mirrors SEVERITY_RANK so the DB does the
# severity-rank ordering before LIMIT/OFFSET. Sorting in Python after
# pagination would silently misorder cross-page (page 2 would never see a
# critical finding that page 1's by-date window missed).
_SEVERITY_CASE = case(
    {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4},
    value=Finding.severity,
    else_=5,
)


def _escape_like(text: str) -> str:
    """Escape SQL LIKE metacharacters in user input. `%` and `_` are otherwise
    interpreted as wildcards, so a search for `test_` would unexpectedly match
    `testa`, `testb`, etc."""
    return text.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")


@router.get("/assets", response_model=list[Asset])
def list_assets(
    workspace_id: str | None = None,
    session: Session = Depends(get_session),
    _user: User = Depends(current_user),
) -> list[Asset]:
    query = select(Asset).order_by(Asset.last_seen.desc())
    if workspace_id:
        query = query.where(Asset.workspace_id == workspace_id)
    return list(session.exec(query).all())


class FindingPage(BaseModel):
    total: int
    items: list[Finding]
    facets: dict[str, list[str]] = Field(default_factory=dict)


@router.get("/findings", response_model=FindingPage)
def list_findings(
    workspace_id: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    tool: str | None = None,
    target_id: str | None = None,
    q: str | None = Query(None, description="Substring match on title or evidence"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_session),
    _user: User = Depends(current_user),
) -> FindingPage:
    """Workspace-wide findings list. Filters and facets in one round trip so
    the Results page can build its dropdowns + counts without 4 extra
    requests."""
    base = select(Finding)
    count_q = select(func.count(Finding.id))

    def _apply(q, *, with_target: bool):
        if workspace_id:
            q = q.where(Finding.workspace_id == workspace_id)
        if severity:
            q = q.where(Finding.severity == severity)
        if status:
            q = q.where(Finding.status == status)
        if tool:
            q = q.where(Finding.tool_source == tool)
        if target_id and with_target:
            # Join through Run to filter by target. SQLite needs an explicit
            # join; SQLModel handles it via the foreign-key relationship.
            q = q.join(Run, Run.id == Finding.run_id).where(Run.target_id == target_id)
        return q

    base = _apply(base, with_target=True)
    count_q = _apply(count_q, with_target=True)

    if q:
        # Substring search on title/evidence. Escape LIKE metacharacters so
        # `%` and `_` in user input don't leak through as wildcards (a search
        # for `test_` would otherwise match testa/testb/...).
        like = f"%{_escape_like(q)}%"
        base = base.where(
            (Finding.title.ilike(like, escape="\\"))  # type: ignore[union-attr]
            | (Finding.evidence.ilike(like, escape="\\"))  # type: ignore[union-attr]
        )
        count_q = count_q.where(
            (Finding.title.ilike(like, escape="\\"))  # type: ignore[union-attr]
            | (Finding.evidence.ilike(like, escape="\\"))  # type: ignore[union-attr]
        )

    total = int(session.exec(count_q).one() or 0)
    # Severity-rank ordering moved into SQL via CASE so pagination is
    # consistent across pages (in-Python sort would re-order each page in
    # isolation, hiding critical findings on later pages).
    rows = list(session.exec(
        base.order_by(_SEVERITY_CASE, Finding.created_at.desc())
            .offset(offset).limit(limit)
    ).all())

    # Facets via SELECT DISTINCT — three small queries instead of three
    # full-table scans.
    sev_q = select(Finding.severity).distinct()
    st_q = select(Finding.status).distinct()
    tool_q = select(Finding.tool_source).distinct()
    if workspace_id:
        sev_q = sev_q.where(Finding.workspace_id == workspace_id)
        st_q = st_q.where(Finding.workspace_id == workspace_id)
        tool_q = tool_q.where(Finding.workspace_id == workspace_id)
    severities = sorted([s for s in session.exec(sev_q).all() if s],
                        key=lambda s: SEVERITY_RANK.get(s, 5))
    statuses = sorted([s for s in session.exec(st_q).all() if s])
    tools = sorted([t for t in session.exec(tool_q).all() if t])

    return FindingPage(
        total=total,
        items=rows,
        facets={
            "severities": severities,
            "statuses": statuses,
            "tools": tools,
        },
    )


EXPORT_FORMATS = {"csv", "json", "md"}
EXPORT_MEDIA = {
    "csv": "text/csv; charset=utf-8",
    "json": "application/json",
    "md": "text/markdown; charset=utf-8",
}
# Capped at 10k rows so a misconfigured filter can't try to ship a 5GB CSV
# through uvicorn. Operators who need everything should paginate via /api/findings.
EXPORT_MAX_ROWS = 10_000


def _filter_findings(
    *,
    workspace_id: str | None,
    severity: str | None,
    status: str | None,
    tool: str | None,
    target_id: str | None,
    q: str | None,
):
    """Build the same select() the list endpoint does, minus pagination.
    Kept inline-duplicated rather than refactored out of list_findings to
    avoid touching the page-shape contract the SPA already speaks."""
    base = select(Finding)
    if workspace_id:
        base = base.where(Finding.workspace_id == workspace_id)
    if severity:
        base = base.where(Finding.severity == severity)
    if status:
        base = base.where(Finding.status == status)
    if tool:
        base = base.where(Finding.tool_source == tool)
    if target_id:
        base = base.join(Run, Run.id == Finding.run_id).where(Run.target_id == target_id)
    if q:
        like = f"%{_escape_like(q)}%"
        base = base.where(
            (Finding.title.ilike(like, escape="\\"))  # type: ignore[union-attr]
            | (Finding.evidence.ilike(like, escape="\\"))  # type: ignore[union-attr]
        )
    return base.order_by(_SEVERITY_CASE, Finding.created_at.desc())


@router.get("/findings/export")
def export_findings(
    fmt: str = Query("csv", alias="format", description="csv | json | md"),
    workspace_id: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    tool: str | None = None,
    target_id: str | None = None,
    q: str | None = None,
    session: Session = Depends(get_session),
    _user: User = Depends(current_user),
) -> Response:
    """Export findings (filtered same way as /api/findings) as CSV / JSON /
    Markdown so operators can drop them straight into a ticket / report.
    Capped at EXPORT_MAX_ROWS rows."""
    if fmt not in EXPORT_FORMATS:
        raise HTTPException(400, f"invalid format {fmt!r}; one of {sorted(EXPORT_FORMATS)}")

    rows = list(session.exec(
        _filter_findings(
            workspace_id=workspace_id, severity=severity, status=status,
            tool=tool, target_id=target_id, q=q,
        ).limit(EXPORT_MAX_ROWS)
    ).all())

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"reconforge-findings-{stamp}.{fmt}"

    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)
        w.writerow(["id", "workspace_id", "run_id", "asset_id",
                    "title", "severity", "confidence", "category", "status",
                    "tool_source", "evidence", "created_at"])
        for r in rows:
            w.writerow([r.id, r.workspace_id, r.run_id or "", r.asset_id or "",
                        r.title, r.severity, r.confidence, r.category, r.status,
                        r.tool_source or "", (r.evidence or "").replace("\n", " ⏎ "),
                        r.created_at.isoformat() if r.created_at else ""])
        body = buf.getvalue().encode()
    elif fmt == "json":
        body = json.dumps(
            [{**r.model_dump(), "created_at": r.created_at.isoformat() if r.created_at else None,
              "updated_at": r.updated_at.isoformat() if r.updated_at else None} for r in rows],
            indent=2,
        ).encode()
    else:  # md
        lines = [
            f"# Findings export — {len(rows)} rows",
            "",
            f"_Generated: {stamp} UTC_",
            "",
            "| Severity | Status | Category | Title | Tool | Run |",
            "|---|---|---|---|---|---|",
        ]
        for r in rows:
            title = (r.title or "").replace("|", "\\|")
            tool_s = (r.tool_source or "").replace("|", "\\|")
            lines.append(f"| {r.severity} | {r.status} | {r.category} | {title} | {tool_s} | `{r.run_id or ''}` |")
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


class FindingStatusUpdate(BaseModel):
    status: str = Field(min_length=1, max_length=32)


@router.patch("/findings/{finding_id}", response_model=Finding)
def update_finding_status(
    finding_id: str,
    payload: FindingStatusUpdate,
    session: Session = Depends(get_session),
    user: User = Depends(require_role(Role.operator)),
) -> Finding:
    if payload.status not in VALID_FINDING_STATUSES:
        raise HTTPException(
            400,
            f"invalid status {payload.status!r}; one of {sorted(VALID_FINDING_STATUSES)}",
        )
    finding = session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found")
    old = finding.status
    finding.status = payload.status
    finding.updated_at = now_utc()
    session.add(finding)
    audit.record(session, actor=user, action="finding.status_updated",
                 target_kind="finding", target_id=finding.id,
                 payload={"from": old, "to": finding.status})
    session.commit()
    session.refresh(finding)
    return finding


@router.get("/artifacts/{artifact_id}", response_model=Artifact)
def get_artifact(
    artifact_id: str,
    session: Session = Depends(get_session),
    _user: User = Depends(current_user),
) -> Artifact:
    artifact = session.get(Artifact, artifact_id)
    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found")
    return artifact


@router.get("/artifacts/{artifact_id}/content")
def get_artifact_content(
    artifact_id: str,
    session: Session = Depends(get_session),
    _user: User = Depends(current_user),
) -> Response:
    artifact = session.get(Artifact, artifact_id)
    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found")
    try:
        data = ArtifactStore().read_bytes(artifact)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Artifact content not found") from exc

    return Response(
        content=data,
        media_type=artifact.content_type or "application/octet-stream",
        headers={
            "Content-Disposition": f'inline; filename="{artifact.name}"',
            "X-Artifact-Sha256": artifact.sha256 or "",
            "X-Artifact-Backend": artifact.storage_backend,
        },
    )
