"""Scope policy management.

  - POST /api/scope/evaluate — preflight one ScopeAction against the
    loaded engine. Open to any authenticated user. Used by launch UIs
    to show the policy decision before posting a real run.
  - GET  /api/scope/policy   — read the current ROE policy as YAML +
    parsed dict + activation state. Open to any authenticated user
    (the policy is not sensitive — it's already on disk in the repo).
  - PUT  /api/scope/policy   — write a new policy. Admin only. Validates
    yaml.safe_load returns a mapping, then writes to disk and busts the
    engine cache so the next run-creation sees the new policy. Audits
    the change.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlmodel import Session

from app.core.config import get_settings
from app.db import get_session
from app.models import Role, User
from app.services import audit
from app.services.auth import current_user, require_role
from app.services.roe_guard import clear_engine_cache, evaluate_run

router = APIRouter(prefix="/scope", tags=["scope"])


class ScopeEvaluateRequest(BaseModel):
    """One action's worth of context for the engine.

    Fields mirror `ScopeAction` so an extension to the engine (new policy
    field, new constraint) is automatic here. `risk` is a string so the UI
    can pass the platform's RiskLevel enum value or a custom label the
    policy understands.
    """
    target: str = Field(min_length=1, max_length=2048)
    tool_id: str | None = None
    risk: str = "low"
    method: str | None = None
    port: int | None = Field(default=None, ge=0, le=65535)
    path: str | None = None
    requested_rps: float | None = Field(default=None, ge=0, le=1_000_000)
    manual_approval: bool = False


class ScopeEvaluateResponse(BaseModel):
    decision: str  # "allow" | "deny" | "require_approval" | "rate_limit" | "no-engine"
    reason: str | None = None
    matched_rule: str | None = None
    normalized_target: str | None = None
    risk: str | None = None
    trace: list[str] = Field(default_factory=list)
    effective_limits: dict[str, Any] = Field(default_factory=dict)


@router.post("/evaluate", response_model=ScopeEvaluateResponse)
def evaluate(
    payload: ScopeEvaluateRequest,
    _session: Session = Depends(get_session),
    _user: User = Depends(current_user),
) -> ScopeEvaluateResponse:
    decision = evaluate_run(
        target=payload.target,
        tool_id=payload.tool_id,
        risk=payload.risk,
        manual_approval=payload.manual_approval,
        port=payload.port,
        method=payload.method,
        path=payload.path,
        requested_rps=payload.requested_rps,
    )
    if decision is None:
        # No policy file loaded — frontend should hide the badge so the
        # engine's opt-in is invisible to operators who haven't enabled it.
        return ScopeEvaluateResponse(decision="no-engine")
    return ScopeEvaluateResponse(
        decision=decision.decision,
        reason=decision.reason,
        matched_rule=decision.matched_rule,
        normalized_target=decision.normalized_target,
        risk=decision.risk,
        trace=decision.trace,
        effective_limits=decision.effective_limits,
    )


class ScopePolicyResponse(BaseModel):
    """What `GET /api/scope/policy` returns. `enabled` is True when the
    policy file exists; UI uses it to decide whether to show "engine
    disabled" guidance. `yaml` is the raw text so a YAML editor can
    round-trip; `parsed` is what the engine actually sees."""
    enabled: bool
    path: str
    yaml: str
    parsed: dict[str, Any]


class ScopePolicyUpdate(BaseModel):
    yaml: str = Field(min_length=0, max_length=200_000)


# ---------- Structured policy form ----------------------------------------
# Mirrors the YAML schema the engine reads. Used by the frontend's form
# editor so operators can manage policy without touching YAML.

class ScopeAllowed(BaseModel):
    domains: list[str] = Field(default_factory=list)
    cidrs: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)


class ScopeDenied(BaseModel):
    domains: list[str] = Field(default_factory=list)
    cidrs: list[str] = Field(default_factory=list)
    methods: list[str] = Field(default_factory=list)
    paths: list[str] = Field(default_factory=list)


class ScopeActiveWindow(BaseModel):
    start: str
    end: str
    timezone: str = "UTC"


class ScopeLimits(BaseModel):
    max_rps: float | None = None
    max_hosts: int | None = None
    active_scan_window: ScopeActiveWindow | None = None


class ScopeApproval(BaseModel):
    require_for_risk: list[str] = Field(default_factory=list)
    require_for_tools: list[str] = Field(default_factory=list)


class ScopePolicyStructured(BaseModel):
    """The form editor's typed payload. Empty sections are dropped on
    YAML serialisation so the on-disk file stays minimal — an operator
    who only sets allowed.domains doesn't see five empty headers."""
    allowed: ScopeAllowed = Field(default_factory=ScopeAllowed)
    denied: ScopeDenied = Field(default_factory=ScopeDenied)
    limits: ScopeLimits | None = None
    approval: ScopeApproval = Field(default_factory=ScopeApproval)


def _serialise_policy(structured: ScopePolicyStructured) -> str:
    """Render the structured payload as YAML, dropping every empty subsection
    so an operator who only touched `allowed.domains` gets a 3-line file
    instead of a 25-line skeleton.

    We hand-fold the dict because Pydantic's `exclude_defaults=True` would
    also drop intentionally-zero values (e.g. `max_hosts: 0`).
    """
    out: dict[str, Any] = {}

    allowed = {}
    if structured.allowed.domains:
        allowed["domains"] = list(structured.allowed.domains)
    if structured.allowed.cidrs:
        allowed["cidrs"] = list(structured.allowed.cidrs)
    if structured.allowed.ports:
        allowed["ports"] = list(structured.allowed.ports)
    if allowed:
        out["allowed"] = allowed

    denied = {}
    if structured.denied.domains:
        denied["domains"] = list(structured.denied.domains)
    if structured.denied.cidrs:
        denied["cidrs"] = list(structured.denied.cidrs)
    if structured.denied.methods:
        denied["methods"] = [m.upper() for m in structured.denied.methods]
    if structured.denied.paths:
        denied["paths"] = list(structured.denied.paths)
    if denied:
        out["denied"] = denied

    if structured.limits is not None:
        limits: dict[str, Any] = {}
        if structured.limits.max_rps is not None:
            limits["max_rps"] = structured.limits.max_rps
        if structured.limits.max_hosts is not None:
            limits["max_hosts"] = structured.limits.max_hosts
        if structured.limits.active_scan_window is not None:
            limits["active_scan_window"] = {
                "start": structured.limits.active_scan_window.start,
                "end": structured.limits.active_scan_window.end,
                "timezone": structured.limits.active_scan_window.timezone,
            }
        if limits:
            out["limits"] = limits

    approval = {}
    if structured.approval.require_for_risk:
        approval["require_for_risk"] = list(structured.approval.require_for_risk)
    if structured.approval.require_for_tools:
        approval["require_for_tools"] = list(structured.approval.require_for_tools)
    if approval:
        out["approval"] = approval

    if not out:
        return ""
    return yaml.safe_dump(out, sort_keys=False, default_flow_style=False)


@router.get("/policy", response_model=ScopePolicyResponse)
def read_policy(_user: User = Depends(current_user)) -> ScopePolicyResponse:
    """Return the current ROE policy as YAML + parsed dict + state.

    Empty `yaml` + `enabled=False` means no policy file exists at
    `settings.roe_policy_path` — the engine is disabled until an admin
    writes one via PUT.
    """
    path = Path(get_settings().roe_policy_path)
    if not path.exists():
        return ScopePolicyResponse(
            enabled=False, path=str(path), yaml="", parsed={},
        )
    raw = path.read_text(encoding="utf-8")
    try:
        parsed = yaml.safe_load(raw) or {}
    except yaml.YAMLError:
        # File on disk is malformed — surface what's there so the editor
        # can show + fix it, but mark engine as disabled. The next read
        # of the engine will return None (ScopeEngine.from_file uses
        # yaml.safe_load too and would raise; the engine cache catches
        # the exception).
        parsed = {}
    if not isinstance(parsed, dict):
        parsed = {}
    return ScopePolicyResponse(
        enabled=True, path=str(path), yaml=raw, parsed=parsed,
    )


@router.put("/policy", response_model=ScopePolicyResponse)
def write_policy(
    payload: ScopePolicyUpdate,
    session: Session = Depends(get_session),
    user: User = Depends(require_role(Role.admin)),
) -> ScopePolicyResponse:
    """Replace the policy on disk + invalidate the engine cache so the
    next run-creation sees the new rules.

    An empty `yaml` body deletes the file → engine becomes disabled. A
    non-empty body must `yaml.safe_load` into a mapping; non-mapping
    documents (a bare list, a scalar) are refused with 422 so a typo
    doesn't silently break enforcement.
    """
    path = Path(get_settings().roe_policy_path)
    raw = payload.yaml

    if not raw.strip():
        # Delete the file → disable the engine.
        was_present = path.exists()
        if was_present:
            path.unlink()
        clear_engine_cache()
        audit.record(
            session, actor=user, action="scope.policy.deleted",
            target_kind="scope_policy", target_id=str(path),
            payload={"was_present": was_present},
        )
        session.commit()
        return ScopePolicyResponse(
            enabled=False, path=str(path), yaml="", parsed={},
        )

    try:
        parsed = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise HTTPException(422, f"invalid YAML: {exc}") from exc
    if not isinstance(parsed, dict):
        raise HTTPException(422, "policy document must be a YAML mapping")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(raw, encoding="utf-8")
    clear_engine_cache()
    audit.record(
        session, actor=user, action="scope.policy.updated",
        target_kind="scope_policy", target_id=str(path),
        payload={
            "size": len(raw),
            "sections": sorted([k for k in parsed if isinstance(k, str)]),
        },
    )
    session.commit()
    return ScopePolicyResponse(
        enabled=True, path=str(path), yaml=raw, parsed=parsed,
    )


@router.post("/policy/render")
def render_policy(
    payload: ScopePolicyStructured,
    _user: User = Depends(current_user),
) -> dict[str, str]:
    """Preview the YAML the form editor would write to disk. Open to any
    authenticated user — it's a pure transformation, no side effects, so
    the operator can switch between Form and YAML views any time."""
    return {"yaml": _serialise_policy(payload)}


@router.put("/policy/structured", response_model=ScopePolicyResponse)
def write_policy_structured(
    payload: ScopePolicyStructured,
    session: Session = Depends(get_session),
    user: User = Depends(require_role(Role.admin)),
) -> ScopePolicyResponse:
    """Admin-only structured save. Serialises the form payload to YAML
    via `_serialise_policy`, then funnels through the same on-disk write
    + engine-cache-bust + audit-row path as the YAML PUT, so a form save
    and a YAML save are indistinguishable downstream.

    An entirely-empty form (`ScopePolicyStructured()` with no fields set)
    serialises to "" → deletes the file → engine disables. Symmetric to
    the YAML PUT's empty-body semantics so the two endpoints agree."""
    rendered = _serialise_policy(payload)
    path = Path(get_settings().roe_policy_path)

    if not rendered.strip():
        was_present = path.exists()
        if was_present:
            path.unlink()
        clear_engine_cache()
        audit.record(
            session, actor=user, action="scope.policy.deleted",
            target_kind="scope_policy", target_id=str(path),
            payload={"was_present": was_present, "via": "structured"},
        )
        session.commit()
        return ScopePolicyResponse(
            enabled=False, path=str(path), yaml="", parsed={},
        )

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered, encoding="utf-8")
    clear_engine_cache()

    # Re-parse so the response matches what GET would return after the write.
    try:
        parsed = yaml.safe_load(rendered) or {}
    except yaml.YAMLError:
        parsed = {}
    if not isinstance(parsed, dict):
        parsed = {}

    audit.record(
        session, actor=user, action="scope.policy.updated",
        target_kind="scope_policy", target_id=str(path),
        payload={
            "size": len(rendered),
            "sections": sorted([k for k in parsed if isinstance(k, str)]),
            "via": "structured",
        },
    )
    session.commit()
    return ScopePolicyResponse(
        enabled=True, path=str(path), yaml=rendered, parsed=parsed,
    )
