"""Agent API.

Machine-facing surface for external agents (e.g. a Claude-driven operator)
that need structured run context without going through the LLM advisor. The
brief is a bounded, deterministic snapshot: run metadata, per-step status,
severity-ranked findings, assets by type, artifact fetch URLs, and the curated
loot summary. Fetch raw bytes via the artifact `content_url`; never expect the
brief to inline megabytes.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from app.db import get_session
from app.models import Artifact, Asset, Finding, LootItem, Run, RunStep, Target, User
from app.services import loot as loot_svc
from app.services.auth import current_user

router = APIRouter(prefix="/agent", tags=["agent"])

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

# Bounds so a chatty profile can't make one brief unmanageable.
_MAX_FINDINGS = 50
_MAX_ASSETS_PER_TYPE = 50
_MAX_ARTIFACTS = 60


class StepBrief(BaseModel):
    index: int
    tool: str
    status: str
    error: str | None = None


class FindingBrief(BaseModel):
    id: str
    title: str
    severity: str
    category: str
    tool_source: str | None = None
    status: str
    evidence_excerpt: str = ""


class ArtifactRef(BaseModel):
    id: str
    name: str
    type: str
    size_bytes: int
    sha256: str | None = None
    content_url: str


class RunBrief(BaseModel):
    run: dict[str, Any]
    target: dict[str, Any] | None
    counts: dict[str, int]
    findings_by_severity: dict[str, int]
    steps: list[StepBrief]
    findings: list[FindingBrief]
    assets_by_type: dict[str, list[str]]
    artifacts: list[ArtifactRef]
    loot: dict[str, Any] = Field(default_factory=dict)


def _status_value(obj: Any) -> str:
    return obj.value if hasattr(obj, "value") else str(obj)


@router.get("/runs/{run_id}/brief", response_model=RunBrief)
def get_run_brief(
    run_id: str,
    session: Session = Depends(get_session),
    _user: User = Depends(current_user),
) -> RunBrief:
    """Structured, bounded snapshot of one run for agent consumption."""
    run = session.get(Run, run_id)
    if not run:
        raise HTTPException(404, "Run not found")

    target = session.get(Target, run.target_id)
    steps = list(session.exec(
        select(RunStep).where(RunStep.run_id == run_id).order_by(RunStep.index)
    ).all())
    findings = list(session.exec(select(Finding).where(Finding.run_id == run_id)).all())
    assets = list(session.exec(select(Asset).where(Asset.run_id == run_id)).all())
    artifacts = list(session.exec(
        select(Artifact).where(Artifact.run_id == run_id).order_by(Artifact.created_at)
    ).all())

    findings.sort(key=lambda f: _SEVERITY_RANK.get(f.severity, 9))

    findings_by_severity = {
        sev: sum(1 for f in findings if f.severity == sev)
        for sev in ("critical", "high", "medium", "low", "info")
    }

    assets_by_type: dict[str, list[str]] = {}
    for asset in assets:
        bucket = assets_by_type.setdefault(asset.type, [])
        if len(bucket) < _MAX_ASSETS_PER_TYPE:
            bucket.append(asset.value)

    loot_items = list(session.exec(select(LootItem).where(LootItem.run_id == run_id)).all())
    if not loot_items and loot_svc.loot_enabled():
        loot_items = loot_svc.index_run(
            session, workspace_id=run.workspace_id, run_id=run_id
        )

    return RunBrief(
        run={
            "id": run.id,
            "workspace_id": run.workspace_id,
            "target_id": run.target_id,
            "profile_id": run.profile_id,
            "status": _status_value(run.status),
            "risk": _status_value(run.risk),
            "created_at": run.created_at.isoformat() if run.created_at else None,
            "started_at": run.started_at.isoformat() if run.started_at else None,
            "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        },
        target=(
            {"id": target.id, "value": target.value, "type": target.type,
             "in_scope": target.in_scope, "passive_allowed": target.passive_allowed,
             "active_allowed": target.active_allowed}
            if target else None
        ),
        counts={
            "steps": len(steps),
            "findings": len(findings),
            "assets": len(assets),
            "artifacts": len(artifacts),
            "loot": len(loot_items),
        },
        findings_by_severity=findings_by_severity,
        steps=[
            StepBrief(index=s.index, tool=s.tool_id,
                      status=_status_value(s.status), error=s.error)
            for s in steps
        ],
        findings=[
            FindingBrief(
                id=f.id, title=f.title, severity=f.severity, category=f.category,
                tool_source=f.tool_source, status=f.status,
                evidence_excerpt=(f.evidence or "")[:400],
            )
            for f in findings[:_MAX_FINDINGS]
        ],
        assets_by_type=assets_by_type,
        artifacts=[
            ArtifactRef(
                id=a.id, name=a.name, type=a.type, size_bytes=a.size_bytes,
                sha256=a.sha256, content_url=f"/api/artifacts/{a.id}/content",
            )
            for a in artifacts[:_MAX_ARTIFACTS]
        ],
        loot=loot_svc.summarize_loot(loot_items),
    )
