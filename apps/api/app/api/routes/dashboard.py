"""Dashboard endpoints — small KPI summary plus a richer detailed view that
powers the main screen.

The detailed view rolls up everything the main screen needs into a single
request so the dashboard renders in one shot rather than firing 8 parallel
fetches. Counts are aggregated server-side; recent-activity arrays are
pre-joined and capped at sensible limits.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends
from sqlmodel import Session, select, func

from app.db import get_session
from app.models import (
    Asset, AuditEvent, Finding, Run, RunStatus, RunStep, Target, User, Workspace,
)
from app.schemas import DashboardStats
from app.services.auth import current_user

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


@router.get("/stats", response_model=DashboardStats)
def stats(
    session: Session = Depends(get_session),
    _user: User = Depends(current_user),
) -> DashboardStats:
    def count(model):
        return session.exec(select(func.count()).select_from(model)).one()

    open_findings = session.exec(
        select(func.count()).select_from(Finding).where(Finding.status != "closed")
    ).one()
    return DashboardStats(
        workspaces=count(Workspace),
        targets=count(Target),
        runs=count(Run),
        assets=count(Asset),
        findings=count(Finding),
        open_findings=open_findings,
    )


@router.get("/detailed")
def detailed(
    session: Session = Depends(get_session),
    _user: User = Depends(current_user),
) -> dict[str, Any]:
    """Richer dashboard payload. One request, everything the main screen needs.

    Shape:
      {
        kpis: {workspaces, targets, runs, assets, findings, open_findings},
        runs_by_status: {queued, running, completed, failed, cancelled},
        findings_by_severity: {critical, high, medium, low, info},
        active_runs: [{id, profile_id, status, risk, target_id, ...}],
        recent_runs: [{...same shape, last 10}],
        recent_findings: [{id, title, severity, run_id, created_at, ...}],
        top_targets: [{id, value, workspace_id, run_count}],   # last 30 days
        top_tools:   [{tool_id, run_count}],                    # last 30 days
        recent_audit: [{sequence, action, target_kind, target_id, ...}],
      }
    """
    def count(model):
        return int(session.exec(select(func.count()).select_from(model)).one() or 0)

    open_findings = int(session.exec(
        select(func.count()).select_from(Finding).where(Finding.status != "closed")
    ).one() or 0)

    kpis = {
        "workspaces": count(Workspace),
        "targets": count(Target),
        "runs": count(Run),
        "assets": count(Asset),
        "findings": count(Finding),
        "open_findings": open_findings,
    }

    # Runs by status — pre-fill every status so the UI gets stable keys
    rs_rows = session.exec(
        select(Run.status, func.count(Run.id)).group_by(Run.status)  # type: ignore[arg-type]
    ).all()
    runs_by_status = {s.value: 0 for s in RunStatus}
    for status, n in rs_rows:
        key = status.value if hasattr(status, "value") else str(status)
        runs_by_status[key] = int(n or 0)

    # Findings by severity — same pattern; SEVERITY_ORDER drives the keys
    fb_rows = session.exec(
        select(Finding.severity, func.count(Finding.id)).group_by(Finding.severity)  # type: ignore[arg-type]
    ).all()
    findings_by_severity = {sev: 0 for sev in SEVERITY_ORDER}
    for sev, n in fb_rows:
        if sev in findings_by_severity:
            findings_by_severity[sev] = int(n or 0)

    def _run_brief(r: Run) -> dict[str, Any]:
        return {
            "id": r.id,
            "profile_id": r.profile_id,
            "status": r.status.value if hasattr(r.status, "value") else str(r.status),
            "risk": r.risk.value if hasattr(r.risk, "value") else str(r.risk),
            "target_id": r.target_id,
            "workspace_id": r.workspace_id,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "finished_at": r.finished_at.isoformat() if r.finished_at else None,
        }

    active_runs = list(session.exec(
        select(Run).where(Run.status.in_(  # type: ignore[union-attr]
            [RunStatus.queued, RunStatus.running]
        )).order_by(Run.created_at.desc()).limit(10)
    ).all())
    recent_runs = list(session.exec(
        select(Run).order_by(Run.created_at.desc()).limit(10)
    ).all())
    recent_findings_rows = list(session.exec(
        select(Finding).order_by(Finding.created_at.desc()).limit(15)
    ).all())
    recent_findings = [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "category": f.category,
            "status": f.status,
            "run_id": f.run_id,
            "tool_source": f.tool_source,
            "created_at": f.created_at.isoformat(),
        }
        for f in recent_findings_rows
    ]

    # Top targets by run count over the last 30 days
    cutoff = datetime.now(timezone.utc) - timedelta(days=30)
    top_targets_rows = session.exec(
        select(Target.id, Target.value, Target.workspace_id, func.count(Run.id))  # type: ignore[arg-type]
        .join(Run, Run.target_id == Target.id)
        .where(Run.created_at >= cutoff)
        .group_by(Target.id, Target.value, Target.workspace_id)
        .order_by(func.count(Run.id).desc())
        .limit(5)
    ).all()
    top_targets = [
        {"id": tid, "value": value, "workspace_id": ws, "run_count": int(n or 0)}
        for tid, value, ws, n in top_targets_rows
    ]

    # Top tools by RunStep count over the last 30 days. Joined through Run
    # for the date filter; RunStep carries tool_id directly.
    top_tools_rows = session.exec(
        select(RunStep.tool_id, func.count(RunStep.id))  # type: ignore[arg-type]
        .join(Run, Run.id == RunStep.run_id)
        .where(Run.created_at >= cutoff)
        .group_by(RunStep.tool_id)
        .order_by(func.count(RunStep.id).desc())
        .limit(8)
    ).all()
    top_tools = [
        {"tool_id": tid, "run_count": int(n or 0)} for tid, n in top_tools_rows if tid
    ]

    audit_rows = list(session.exec(
        select(AuditEvent).order_by(AuditEvent.sequence.desc()).limit(15)
    ).all())
    recent_audit = [
        {
            "sequence": e.sequence,
            "action": e.action,
            "target_kind": e.target_kind,
            "target_id": e.target_id,
            "actor_role": e.actor_role,
            "created_at": e.created_at.isoformat(),
        }
        for e in audit_rows
    ]

    return {
        "kpis": kpis,
        "runs_by_status": runs_by_status,
        "findings_by_severity": findings_by_severity,
        "active_runs": [_run_brief(r) for r in active_runs],
        "recent_runs": [_run_brief(r) for r in recent_runs],
        "recent_findings": recent_findings,
        "top_targets": top_targets,
        "top_tools": top_tools,
        "recent_audit": recent_audit,
    }
