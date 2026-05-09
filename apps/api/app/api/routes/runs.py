import asyncio

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select
from sqlmodel import Session as SQLSession

from app.core.config import get_settings
from app.db import engine, get_session
from app.models import Artifact, Asset, Finding, Run, RunEvent, RunStatus, RunStep, Target, now_utc
from app.schemas import RunCreate
from app.services.events import event_bus
from app.services.queue import enqueue_run, request_run_cancel
from app.services.runner import execute_run
from app.services.scope import ScopeError, enforce_target_scope
from app.services.platform_config import load_platform_config
from app.services.tool_availability import unavailable_profile_tools
from app.services.tool_registry import get_registry

router = APIRouter(prefix="/runs", tags=["runs"])


def session_factory() -> SQLSession:
    return SQLSession(engine)


@router.get("", response_model=list[Run])
def list_runs(session: Session = Depends(get_session)) -> list[Run]:
    return list(session.exec(select(Run).order_by(Run.created_at.desc())).all())


@router.post("", response_model=Run, status_code=201)
async def create_run(payload: RunCreate, session: Session = Depends(get_session)) -> Run:
    target = session.get(Target, payload.target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    if target.workspace_id != payload.workspace_id:
        raise HTTPException(status_code=400, detail="Target does not belong to workspace")

    registry = get_registry()
    try:
        profile = registry.get_profile(payload.profile_id)
        risk = registry.profile_risk(profile)
        manual_approval = bool(payload.params.get("manual_approval", False))
        enforce_target_scope(target, risk, manual_approval=manual_approval)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ScopeError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    settings = get_settings()
    if settings.live_execution_enabled and settings.block_live_runs_on_missing_tools:
        missing = unavailable_profile_tools(registry, payload.profile_id)
        if missing:
            raise HTTPException(
                status_code=409,
                detail={
                    "message": "Live run blocked because required tool executables are missing or broken in the runner image.",
                    "profile_id": payload.profile_id,
                    "missing_tools": [item.model_dump() for item in missing],
                    "hint": "Install the missing tools in the API/worker image or switch back to dry_run mode.",
                },
            )

    run = Run(
        workspace_id=payload.workspace_id,
        target_id=payload.target_id,
        profile_id=payload.profile_id,
        requested_by=payload.requested_by,
        risk=risk,
        config_snapshot={
            "platform_config": load_platform_config(),
            "profile": profile,
            "target_value": target.value,
            "target_type": target.type,
            "params": {"target": target.value, **payload.params},
        },
    )
    session.add(run)
    session.commit()
    session.refresh(run)

    await event_bus.publish(
        session,
        run.id,
        "run.queued",
        f"Run {run.id} queued",
        payload={"runner_mode": settings.runner_mode, "queue": settings.run_queue_name},
    )

    if settings.queued_runner_enabled:
        await enqueue_run(run.id)
    else:
        asyncio.create_task(execute_run(run.id, registry, session_factory))

    return run


@router.get("/{run_id}", response_model=Run)
def get_run(run_id: str, session: Session = Depends(get_session)) -> Run:
    run = session.get(Run, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return run


@router.post("/{run_id}/cancel")
async def cancel_run(run_id: str, session: Session = Depends(get_session)) -> Run:
    run = session.get(Run, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    if run.status in {RunStatus.completed, RunStatus.failed, RunStatus.cancelled}:
        return run

    await request_run_cancel(run_id)
    run.status = RunStatus.cancelled
    run.finished_at = now_utc() if run.started_at is None else run.finished_at
    session.add(run)
    session.commit()
    session.refresh(run)
    await event_bus.publish(
        session,
        run.id,
        "run.cancel_requested",
        f"Cancellation requested for {run.id}",
        level="warning",
        payload={"run_id": run.id},
    )
    return run


@router.get("/{run_id}/events", response_model=list[RunEvent])
def get_run_events(run_id: str, session: Session = Depends(get_session)) -> list[RunEvent]:
    return list(session.exec(select(RunEvent).where(RunEvent.run_id == run_id).order_by(RunEvent.sequence)).all())


@router.get("/{run_id}/steps", response_model=list[RunStep])
def get_run_steps(run_id: str, session: Session = Depends(get_session)) -> list[RunStep]:
    return list(session.exec(select(RunStep).where(RunStep.run_id == run_id).order_by(RunStep.index)).all())


@router.get("/{run_id}/assets", response_model=list[Asset])
def get_run_assets(run_id: str, session: Session = Depends(get_session)) -> list[Asset]:
    return list(session.exec(select(Asset).where(Asset.run_id == run_id).order_by(Asset.last_seen.desc())).all())


@router.get("/{run_id}/findings", response_model=list[Finding])
def get_run_findings(run_id: str, session: Session = Depends(get_session)) -> list[Finding]:
    return list(session.exec(select(Finding).where(Finding.run_id == run_id).order_by(Finding.created_at.desc())).all())


@router.get("/{run_id}/artifacts", response_model=list[Artifact])
def get_run_artifacts(run_id: str, session: Session = Depends(get_session)) -> list[Artifact]:
    return list(session.exec(select(Artifact).where(Artifact.run_id == run_id).order_by(Artifact.created_at.desc())).all())
