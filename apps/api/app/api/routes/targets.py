from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select

from app.db import get_session
from app.models import Asset, Finding, Role, Run, Target, User, Workspace
from app.schemas import BulkTargetCreate, BulkTargetResult, TargetCreate
from app.services import audit
from app.services.auth import current_user, require_role
from app.services.target_validation import normalize_target

router = APIRouter(prefix="/targets", tags=["targets"])

# Severity ranking used for sorting findings — `vulnerable` rows from dalfox /
# arachni etc. that don't fit nuclei's bucket get parked under "info".
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


@router.get("", response_model=list[Target])
def list_targets(
    workspace_id: str | None = None,
    session: Session = Depends(get_session),
    _user: User = Depends(current_user),
) -> list[Target]:
    query = select(Target).order_by(Target.created_at.desc())
    if workspace_id:
        query = query.where(Target.workspace_id == workspace_id)
    return list(session.exec(query).all())


@router.post("", response_model=Target, status_code=201)
def create_target(
    payload: TargetCreate,
    session: Session = Depends(get_session),
    user: User = Depends(require_role(Role.operator)),
) -> Target:
    workspace = session.get(Workspace, payload.workspace_id)
    if not workspace:
        raise HTTPException(status_code=404, detail="Workspace not found")
    try:
        normalized = normalize_target(payload.value, payload.type)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    target_data = payload.model_dump()
    target_data["value"] = normalized.value
    target_data["type"] = normalized.type
    target = Target(**target_data)
    session.add(target)
    session.commit()
    session.refresh(target)
    audit.record(session, actor=user, action="target.created",
                 target_kind="target", target_id=target.id,
                 payload={"value": target.value, "active_allowed": target.active_allowed})
    session.commit()
    return target


@router.post("/bulk", response_model=BulkTargetResult, status_code=201)
def create_targets_bulk(
    payload: BulkTargetCreate,
    session: Session = Depends(get_session),
    user: User = Depends(require_role(Role.operator)),
) -> BulkTargetResult:
    """Paste-a-list bulk import. Skips empties, comments, and duplicates that
    already exist in the same workspace. Caps at 500 rows per request."""
    workspace = session.get(Workspace, payload.workspace_id)
    if not workspace:
        raise HTTPException(status_code=404, detail="Workspace not found")

    # Normalise: strip, drop blanks + lines starting with `#`, dedupe in-batch.
    seen: set[str] = set()
    candidates: list[str] = []
    invalid: list[dict[str, str]] = []
    for raw in payload.values:
        v = raw.strip()
        if not v or v.startswith("#"):
            continue
        try:
            normalized = normalize_target(v, payload.type)
        except ValueError as exc:
            invalid.append({"value": v, "reason": str(exc)})
            continue
        v = normalized.value
        if v in seen:
            continue
        seen.add(v)
        candidates.append(v)

    # Pre-load existing values in this workspace so we don't insert dupes.
    existing = {
        row for row in session.exec(
            select(Target.value).where(Target.workspace_id == payload.workspace_id)
        ).all()
    }

    created: list[Target] = []
    skipped: list[dict[str, str]] = list(invalid)
    for v in candidates:
        if v in existing:
            skipped.append({"value": v, "reason": "duplicate"})
            continue
        target = Target(
            workspace_id=payload.workspace_id,
            value=v,
            type=normalize_target(v, payload.type).type,
            in_scope=payload.in_scope,
            passive_allowed=payload.passive_allowed,
            active_allowed=payload.active_allowed,
            notes=payload.notes,
        )
        session.add(target)
        created.append(target)

    if created:
        session.commit()
        for t in created:
            session.refresh(t)
        audit.record(
            session, actor=user, action="target.bulk_created",
            target_kind="workspace", target_id=payload.workspace_id,
            payload={"count": len(created), "skipped": len(skipped),
                      "active_allowed": payload.active_allowed},
        )
        session.commit()

    return BulkTargetResult(
        created=[t.model_dump() for t in created],
        skipped=skipped,
        workspace_id=payload.workspace_id,
    )


# ---------------------------- Target detail ----------------------------

def _target_or_404(session: Session, target_id: str) -> Target:
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


def _run_ids_for_target(session: Session, target_id: str) -> list[str]:
    return [r for r in session.exec(select(Run.id).where(Run.target_id == target_id)).all()]


@router.get("/{target_id}", response_model=Target)
def get_target(
    target_id: str,
    session: Session = Depends(get_session),
    _user: User = Depends(current_user),
) -> Target:
    return _target_or_404(session, target_id)


@router.get("/{target_id}/runs", response_model=list[Run])
def get_target_runs(
    target_id: str,
    session: Session = Depends(get_session),
    _user: User = Depends(current_user),
) -> list[Run]:
    _target_or_404(session, target_id)
    return list(session.exec(
        select(Run).where(Run.target_id == target_id).order_by(Run.created_at.desc())
    ).all())


@router.get("/{target_id}/assets", response_model=list[Asset])
def get_target_assets(
    target_id: str,
    type: str | None = None,
    session: Session = Depends(get_session),
    _user: User = Depends(current_user),
) -> list[Asset]:
    _target_or_404(session, target_id)
    run_ids = _run_ids_for_target(session, target_id)
    if not run_ids:
        return []
    query = select(Asset).where(Asset.run_id.in_(run_ids))  # type: ignore[attr-defined]
    if type:
        query = query.where(Asset.type == type)
    query = query.order_by(Asset.last_seen.desc())
    return list(session.exec(query).all())


@router.get("/{target_id}/findings", response_model=list[Finding])
def get_target_findings(
    target_id: str,
    session: Session = Depends(get_session),
    _user: User = Depends(current_user),
) -> list[Finding]:
    _target_or_404(session, target_id)
    run_ids = _run_ids_for_target(session, target_id)
    if not run_ids:
        return []
    rows = list(session.exec(
        select(Finding).where(Finding.run_id.in_(run_ids))  # type: ignore[attr-defined]
    ).all())
    rows.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 5), f.created_at.timestamp() * -1))
    return rows


@router.get("/{target_id}/summary")
def get_target_summary(
    target_id: str,
    session: Session = Depends(get_session),
    _user: User = Depends(current_user),
) -> dict[str, Any]:
    target = _target_or_404(session, target_id)
    run_ids = _run_ids_for_target(session, target_id)

    runs = list(session.exec(
        select(Run).where(Run.target_id == target_id).order_by(Run.created_at.desc())
    ).all())
    runs_by_status: dict[str, int] = {}
    for r in runs:
        runs_by_status[r.status.value] = runs_by_status.get(r.status.value, 0) + 1

    if not run_ids:
        return {
            "target": target.model_dump(),
            "runs_total": 0,
            "runs_by_status": {},
            "last_run_at": None,
            "assets_total": 0,
            "assets_by_type": {},
            "findings_total": 0,
            "findings_by_severity": {},
        }

    assets = list(session.exec(
        select(Asset).where(Asset.run_id.in_(run_ids))  # type: ignore[attr-defined]
    ).all())
    assets_by_type: dict[str, int] = {}
    for a in assets:
        assets_by_type[a.type] = assets_by_type.get(a.type, 0) + 1

    findings = list(session.exec(
        select(Finding).where(Finding.run_id.in_(run_ids))  # type: ignore[attr-defined]
    ).all())
    findings_by_severity: dict[str, int] = {}
    for f in findings:
        findings_by_severity[f.severity] = findings_by_severity.get(f.severity, 0) + 1

    return {
        "target": target.model_dump(),
        "runs_total": len(runs),
        "runs_by_status": runs_by_status,
        "last_run_at": runs[0].created_at.isoformat() if runs else None,
        "assets_total": len(assets),
        "assets_by_type": assets_by_type,
        "findings_total": len(findings),
        "findings_by_severity": findings_by_severity,
    }


@router.get("/{target_id}/tech")
def get_target_tech(
    target_id: str,
    session: Session = Depends(get_session),
    _user: User = Depends(current_user),
) -> dict[str, Any]:
    """Aggregate tech fingerprints from httpx-style JSON assets.

    Each url asset has `meta.json` with whatever the source tool emitted; httpx
    typically populates `tech: [..]`, `webserver`, `tls.subject_cn`, etc.
    Aggregating here keeps the UI simple and lets us evolve the heuristic without
    redeploying the frontend.
    """
    _target_or_404(session, target_id)
    run_ids = _run_ids_for_target(session, target_id)
    if not run_ids:
        return {"tech": {}, "servers": {}, "by_url": []}

    assets = list(session.exec(
        select(Asset).where(Asset.run_id.in_(run_ids), Asset.type == "url")  # type: ignore[attr-defined]
    ).all())

    tech_count: dict[str, int] = {}
    server_count: dict[str, int] = {}
    by_url: list[dict[str, Any]] = []

    for asset in assets:
        meta = asset.meta or {}
        info = meta.get("json") if isinstance(meta.get("json"), dict) else {}
        techs = info.get("tech") or info.get("technologies") or []
        if isinstance(techs, list):
            for t in techs:
                if isinstance(t, str):
                    tech_count[t] = tech_count.get(t, 0) + 1
        server = info.get("webserver") or info.get("server")
        if isinstance(server, str) and server:
            server_count[server] = server_count.get(server, 0) + 1
        title = info.get("title")
        status = info.get("status_code") or info.get("status-code") or info.get("status")
        if title or techs or server:
            by_url.append({
                "url": asset.value,
                "title": title,
                "status_code": status,
                "tech": techs if isinstance(techs, list) else [],
                "server": server,
            })

    return {
        "tech": dict(sorted(tech_count.items(), key=lambda kv: -kv[1])),
        "servers": dict(sorted(server_count.items(), key=lambda kv: -kv[1])),
        "by_url": by_url,
    }
