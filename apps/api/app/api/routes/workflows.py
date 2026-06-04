"""Workflow CRUD + launch.

Saved Workflow Builder graphs. Each workflow is a workspace-scoped, named
ad-hoc workflow: its body holds the execution steps[] plus the visual
nodes/edges so the canvas can rehydrate it. Launching a workflow goes
through the same /api/runs/adhoc execution path so behaviour stays in lock
step.
"""
from __future__ import annotations

import asyncio
from typing import Any

import yaml
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from app.core.config import get_settings
from app.db import engine, get_session
from app.models import ROLE_RANK, Role, Run, Target, User, Workflow, Workspace, now_utc
from app.schemas import AdHocStep
from app.services import audit
from app.services.auth import current_user, require_role
from app.services.events import event_bus
from app.services.platform_config import load_platform_config
from app.services.queue import enqueue_run
from app.services.runner import execute_run
from app.services.roe_guard import enforce_profile_run
from app.services.scope import ScopeError, enforce_target_scope
from app.services.tool_availability import check_tool_availability
from app.services.tool_registry import get_registry
from sqlmodel import Session as SQLSession

router = APIRouter(prefix="/workflows", tags=["workflows"])


# ---------- IO models -------------------------------------------------------

class WorkflowBody(BaseModel):
    """Workflow.body shape — the execution steps + (optional) editor graph.

    `steps` mirrors AdHocStep[] so launches feed straight into the same code
    path. `graph` is opaque persistence for the React Flow canvas (nodes +
    edges); the runner never reads it.
    """
    steps: list[AdHocStep] = Field(min_length=1, max_length=50)
    graph: dict[str, Any] | None = None


class WorkflowCreate(BaseModel):
    workspace_id: str
    name: str = Field(min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=2000)
    body: WorkflowBody


class WorkflowUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=2000)
    body: WorkflowBody | None = None


class WorkflowLaunch(BaseModel):
    target_id: str
    params: dict[str, Any] = Field(default_factory=dict)


class WorkflowRead(BaseModel):
    id: str
    workspace_id: str
    name: str
    description: str | None
    body: dict[str, Any]
    created_by: str | None
    created_at: str
    updated_at: str


def _to_read(workflow: Workflow) -> WorkflowRead:
    return WorkflowRead(
        id=workflow.id,
        workspace_id=workflow.workspace_id,
        name=workflow.name,
        description=workflow.description,
        body=workflow.body or {},
        created_by=workflow.created_by,
        created_at=workflow.created_at.isoformat() if workflow.created_at else "",
        updated_at=workflow.updated_at.isoformat() if workflow.updated_at else "",
    )


def _can_mutate(user: User, workflow: Workflow) -> bool:
    """Owner or admin. Mirrors the API key rule on auth.py."""
    return workflow.created_by == user.id or ROLE_RANK[user.role] >= ROLE_RANK[Role.admin]


def session_factory() -> SQLSession:
    """Match the factory pattern from runs.py so execute_run can re-open
    a session per step inside the in-process worker."""
    return SQLSession(engine)


# ---------- Routes ---------------------------------------------------------

@router.get("", response_model=list[WorkflowRead])
def list_workflows(
    workspace_id: str | None = None,
    session: Session = Depends(get_session),
    _user: User = Depends(current_user),
) -> list[WorkflowRead]:
    """List saved workflows, optionally scoped to a workspace."""
    query = select(Workflow).order_by(Workflow.updated_at.desc())
    if workspace_id:
        query = query.where(Workflow.workspace_id == workspace_id)
    return [_to_read(w) for w in session.exec(query).all()]


@router.get("/{workflow_id}", response_model=WorkflowRead)
def get_workflow(
    workflow_id: str,
    session: Session = Depends(get_session),
    _user: User = Depends(current_user),
) -> WorkflowRead:
    wf = session.get(Workflow, workflow_id)
    if not wf:
        raise HTTPException(404, "Workflow not found")
    return _to_read(wf)


@router.post("", response_model=WorkflowRead, status_code=201)
def create_workflow(
    payload: WorkflowCreate,
    session: Session = Depends(get_session),
    user: User = Depends(require_role(Role.operator)),
) -> WorkflowRead:
    workspace = session.get(Workspace, payload.workspace_id)
    if not workspace:
        raise HTTPException(404, "Workspace not found")

    # Validate every step references a real tool — same check the ad-hoc run
    # endpoint runs at launch time, hoisted earlier so a broken workflow can
    # never get saved.
    registry = get_registry()
    for step in payload.body.steps:
        try:
            registry.get_tool(step.tool)
        except KeyError as exc:
            raise HTTPException(404, f"Unknown tool in workflow: {exc}") from exc

    wf = Workflow(
        workspace_id=payload.workspace_id,
        name=payload.name,
        description=payload.description,
        body={
            "steps": [s.model_dump(exclude_none=True) for s in payload.body.steps],
            "graph": payload.body.graph or None,
        },
        created_by=user.id,
    )
    session.add(wf)
    session.commit()
    session.refresh(wf)
    audit.record(
        session, actor=user, action="workflow.created",
        target_kind="workflow", target_id=wf.id,
        payload={"name": wf.name, "workspace_id": wf.workspace_id, "step_count": len(payload.body.steps)},
    )
    session.commit()
    return _to_read(wf)


@router.put("/{workflow_id}", response_model=WorkflowRead)
def update_workflow(
    workflow_id: str,
    payload: WorkflowUpdate,
    session: Session = Depends(get_session),
    user: User = Depends(require_role(Role.operator)),
) -> WorkflowRead:
    wf = session.get(Workflow, workflow_id)
    if not wf:
        raise HTTPException(404, "Workflow not found")
    if not _can_mutate(user, wf):
        raise HTTPException(403, "Only the workflow's owner or an admin may edit it")

    changes: dict[str, Any] = {}
    if payload.name is not None and payload.name != wf.name:
        changes["name"] = {"from": wf.name, "to": payload.name}
        wf.name = payload.name
    if payload.description is not None and payload.description != wf.description:
        changes["description"] = "updated"
        wf.description = payload.description
    if payload.body is not None:
        registry = get_registry()
        for step in payload.body.steps:
            try:
                registry.get_tool(step.tool)
            except KeyError as exc:
                raise HTTPException(404, f"Unknown tool in workflow: {exc}") from exc
        wf.body = {
            "steps": [s.model_dump(exclude_none=True) for s in payload.body.steps],
            "graph": payload.body.graph or None,
        }
        changes["body"] = {"step_count": len(payload.body.steps)}
    if changes:
        wf.updated_at = now_utc()
        session.add(wf)
        audit.record(session, actor=user, action="workflow.updated",
                     target_kind="workflow", target_id=wf.id, payload=changes)
        session.commit()
        session.refresh(wf)
    return _to_read(wf)


@router.delete("/{workflow_id}", status_code=204)
def delete_workflow(
    workflow_id: str,
    session: Session = Depends(get_session),
    user: User = Depends(require_role(Role.operator)),
) -> None:
    wf = session.get(Workflow, workflow_id)
    if not wf:
        raise HTTPException(404, "Workflow not found")
    if not _can_mutate(user, wf):
        raise HTTPException(403, "Only the workflow's owner or an admin may delete it")
    audit.record(session, actor=user, action="workflow.deleted",
                 target_kind="workflow", target_id=wf.id,
                 payload={"name": wf.name})
    session.delete(wf)
    session.commit()


class WorkflowImportPayload(BaseModel):
    """JSON-shaped import body for shipping workflows between instances
    (and round-tripping the export endpoint). `yaml` carries the raw YAML
    text; the server parses + validates against the same step schema as
    create."""
    workspace_id: str
    yaml: str = Field(min_length=1, max_length=200_000)
    # Override the in-document name + description if the operator wants to.
    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=2000)


@router.get("/{workflow_id}/export")
def export_workflow(
    workflow_id: str,
    fmt: str = Query("yaml", alias="format", description="yaml | json"),
    session: Session = Depends(get_session),
    _user: User = Depends(current_user),
) -> Response:
    """Export a workflow as YAML (or JSON). The output is portable: paste it
    into another instance via POST /api/workflows/import to recreate the
    same canvas. Keys match the YAML profile shape operators already know."""
    fmt = (fmt or "yaml").lower()
    if fmt not in {"yaml", "json"}:
        raise HTTPException(400, "format must be 'yaml' or 'json'")
    wf = session.get(Workflow, workflow_id)
    if not wf:
        raise HTTPException(404, "Workflow not found")
    body = wf.body or {}
    doc: dict[str, Any] = {
        "schema": "reconforge.workflow/v1",
        "name": wf.name,
        "description": wf.description or "",
        "steps": body.get("steps") or [],
    }
    # Include the visual graph so a round-trip preserves canvas layout. The
    # consumer can ignore it if they only care about the runnable steps[].
    graph = body.get("graph")
    if graph:
        doc["graph"] = graph

    if fmt == "json":
        import json as _json
        text = _json.dumps(doc, indent=2, default=str)
        media = "application/json"
        ext = "json"
    else:
        text = yaml.safe_dump(doc, sort_keys=False, default_flow_style=False)
        media = "application/yaml"
        ext = "yaml"
    safe = "".join(c if c.isalnum() or c in "-." else "-" for c in wf.name)
    return Response(
        content=text.encode("utf-8"),
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="reconforge-workflow-{safe}.{ext}"'},
    )


@router.post("/import", response_model=WorkflowRead, status_code=201)
def import_workflow(
    payload: WorkflowImportPayload,
    session: Session = Depends(get_session),
    user: User = Depends(require_role(Role.operator)),
) -> WorkflowRead:
    """Create a workflow from a YAML / JSON-as-YAML document. yaml.safe_load
    is used so a malicious file can't pull arbitrary Python types into the
    process — only standard YAML scalars and containers."""
    workspace = session.get(Workspace, payload.workspace_id)
    if not workspace:
        raise HTTPException(404, "Workspace not found")

    try:
        doc = yaml.safe_load(payload.yaml)
    except yaml.YAMLError as exc:
        raise HTTPException(422, f"invalid YAML: {exc}") from exc
    if not isinstance(doc, dict):
        raise HTTPException(422, "workflow document must be a YAML mapping")

    steps_raw = doc.get("steps")
    if not isinstance(steps_raw, list) or not steps_raw:
        raise HTTPException(422, "workflow document must contain a non-empty `steps` list")

    # Validate each step against the same Pydantic model used at create
    # time, so the rules match (tool id required, optional timeout / retry
    # / argv overrides). Pulls a clean ValueError on any malformed step.
    try:
        validated = [AdHocStep.model_validate(s) for s in steps_raw]
    except Exception as exc:  # noqa: BLE001 - bubble Pydantic's message verbatim
        raise HTTPException(422, f"invalid step in workflow: {exc}") from exc

    # Every step's tool must exist in the registry. Same gate as create.
    registry = get_registry()
    for step in validated:
        try:
            registry.get_tool(step.tool)
        except KeyError as exc:
            raise HTTPException(404, f"Unknown tool in workflow: {exc}") from exc

    name = payload.name or doc.get("name") or "Imported workflow"
    description = payload.description if payload.description is not None else doc.get("description")
    graph = doc.get("graph") if isinstance(doc.get("graph"), dict) else None

    wf = Workflow(
        workspace_id=payload.workspace_id,
        name=str(name)[:120],
        description=(str(description) if description is not None else None),
        body={
            "steps": [s.model_dump(exclude_none=True) for s in validated],
            "graph": graph,
        },
        created_by=user.id,
    )
    session.add(wf)
    session.commit()
    session.refresh(wf)
    audit.record(
        session, actor=user, action="workflow.imported",
        target_kind="workflow", target_id=wf.id,
        payload={"name": wf.name, "workspace_id": wf.workspace_id, "step_count": len(validated)},
    )
    session.commit()
    return _to_read(wf)


@router.post("/{workflow_id}/launch", response_model=Run, status_code=201)
async def launch_workflow(
    workflow_id: str,
    payload: WorkflowLaunch,
    session: Session = Depends(get_session),
    user: User = Depends(require_role(Role.operator)),
) -> Run:
    """Build a Run from a saved workflow's steps and queue it. Behaves
    identically to POST /api/runs/adhoc once the run row is created."""
    wf = session.get(Workflow, workflow_id)
    if not wf:
        raise HTTPException(404, "Workflow not found")
    target = session.get(Target, payload.target_id)
    if not target:
        raise HTTPException(404, "Target not found")
    if target.workspace_id != wf.workspace_id:
        raise HTTPException(400, "Target does not belong to workflow's workspace")

    raw_steps = (wf.body or {}).get("steps") or []
    if not raw_steps:
        raise HTTPException(409, "Workflow has no steps")

    registry = get_registry()
    profile_inline: dict[str, Any] = {
        "id": "adhoc",
        "name": f"workflow:{wf.name}",
        "description": f"Saved workflow {wf.id}",
        "steps": raw_steps,
        "workflow_id": wf.id,
    }
    try:
        risk = registry.profile_risk(profile_inline)
    except KeyError as exc:
        raise HTTPException(404, f"Workflow references unknown tool: {exc}") from exc

    manual_approval = bool(payload.params.get("manual_approval", False))
    try:
        enforce_target_scope(target, risk, manual_approval=manual_approval)
    except ScopeError as exc:
        raise HTTPException(403, str(exc)) from exc

    # ROE engine — same per-tool + argv-derived port/method/rps evaluation
    # as the other run-creation paths. Workflow steps already validated.
    enforce_profile_run(
        target=target.value,
        risk=risk.value if hasattr(risk, "value") else str(risk),
        steps=[s for s in raw_steps if isinstance(s, dict)],
        manual_approval=manual_approval,
    )

    settings = get_settings()
    if settings.live_execution_enabled and settings.block_live_runs_on_missing_tools:
        missing: list[dict[str, Any]] = []
        seen: set[str] = set()
        for step in raw_steps:
            tool_id = step.get("tool")
            if not tool_id or tool_id in seen:
                continue
            seen.add(tool_id)
            try:
                avail = check_tool_availability(registry.get_tool(tool_id))
            except KeyError:
                continue
            if not avail.available:
                missing.append(avail.model_dump())
        if missing:
            raise HTTPException(409, {
                "message": "Live run blocked because required tool executables are missing or broken.",
                "workflow_id": wf.id,
                "missing_tools": missing,
            })

    profile_inline["risk"] = risk.value

    run = Run(
        workspace_id=wf.workspace_id,
        target_id=payload.target_id,
        profile_id="adhoc",
        requested_by=user.username,
        risk=risk,
        config_snapshot={
            "platform_config": load_platform_config(),
            "profile": profile_inline,
            "profile_inline": profile_inline,
            "target_value": target.value,
            "target_type": target.type,
            "params": {"target": target.value, **payload.params},
            "workflow_id": wf.id,
        },
    )
    session.add(run)
    session.commit()
    session.refresh(run)

    audit.record(
        session, actor=user, action="workflow.launched",
        target_kind="workflow", target_id=wf.id,
        payload={"run_id": run.id, "target_id": run.target_id, "risk": run.risk.value},
    )
    session.commit()

    await event_bus.publish(
        session, run.id, "run.queued",
        f"Run {run.id} queued (workflow: {wf.name})",
        payload={
            "runner_mode": settings.runner_mode, "queue": settings.run_queue_name,
            "workflow_id": wf.id, "profile_id": "adhoc",
        },
    )

    if settings.queued_runner_enabled:
        await enqueue_run(run.id)
    else:
        asyncio.create_task(execute_run(run.id, registry, session_factory))

    return run
