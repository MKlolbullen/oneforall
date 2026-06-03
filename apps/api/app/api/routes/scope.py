"""Scope policy preflight.

`POST /api/scope/evaluate` is the read-only counterpart to the run-creation
guards. The frontend hits it before posting an actual run so operators see
the engine's decision in-place: a green "scope clear" badge for allow, an
amber "needs approval" prompt for require_approval, a red blocker for
deny, etc.

Behaviour mirrors the run-creation path exactly so what shows in the UI
is what the run-creation endpoints will decide. When no ROE policy file
is loaded the response carries `decision: "no-engine"` — the UI then hides
the badge so the engine's opt-in nature stays invisible to operators who
haven't enabled it.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlmodel import Session

from app.db import get_session
from app.models import User
from app.services.auth import current_user
from app.services.roe_guard import evaluate_run

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
