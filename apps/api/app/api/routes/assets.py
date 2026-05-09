from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlmodel import Session, select, func

from app.db import get_session
from app.models import Artifact, Asset, Finding, Role, Run, Target, User, now_utc
from app.services import audit
from app.services.artifacts import ArtifactStore
from app.services.auth import current_user, require_role

router = APIRouter(tags=["assets-findings"])

VALID_FINDING_STATUSES = {"new", "triaged", "false_positive", "fixed", "closed"}
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


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
        # Substring search on title/evidence — SQLite + Postgres both support LIKE.
        like = f"%{q}%"
        base = base.where((Finding.title.ilike(like)) | (Finding.evidence.ilike(like)))  # type: ignore[union-attr]
        count_q = count_q.where((Finding.title.ilike(like)) | (Finding.evidence.ilike(like)))  # type: ignore[union-attr]

    total = int(session.exec(count_q).one() or 0)
    rows = list(session.exec(
        base.order_by(Finding.created_at.desc()).offset(offset).limit(limit)
    ).all())
    # In-Python severity-rank sort within the page so critical/high lead
    rows.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 5), -f.created_at.timestamp()))

    # Facets across the workspace (no per-filter scoping — Burp-style: the
    # dropdown options stay stable while filters narrow the set).
    facet_base = select(Finding)
    if workspace_id:
        facet_base = facet_base.where(Finding.workspace_id == workspace_id)
    severities = sorted({f.severity for f in session.exec(facet_base).all() if f.severity},
                        key=lambda s: SEVERITY_RANK.get(s, 5))
    facet_base2 = select(Finding)
    if workspace_id:
        facet_base2 = facet_base2.where(Finding.workspace_id == workspace_id)
    statuses = sorted({f.status for f in session.exec(facet_base2).all() if f.status})
    facet_base3 = select(Finding)
    if workspace_id:
        facet_base3 = facet_base3.where(Finding.workspace_id == workspace_id)
    tools = sorted({f.tool_source for f in session.exec(facet_base3).all() if f.tool_source})

    return FindingPage(
        total=total,
        items=rows,
        facets={
            "severities": severities,
            "statuses": statuses,
            "tools": tools,
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
