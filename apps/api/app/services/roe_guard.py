"""ROE engine integration for the run-creation paths.

Bridges the standalone `scope_engine.ScopeEngine` into the four endpoints
that queue runs: POST /api/runs, POST /api/runs/adhoc, POST /api/runs/{id}/rerun,
POST /api/workflows/{id}/launch.

Two important behavioural choices:

  1. Opt-in by default. The engine activates only when the file at
     `settings.roe_policy_path` exists. If it's missing, this module
     no-ops — the legacy target-level scope check stays the sole gate,
     keeping existing deployments unchanged.

  2. Fail-closed once active. An empty policy denies everything (the
     engine's design); once an operator opts in by creating the file,
     forgetting to declare an `allowed:` section will refuse runs rather
     than silently let them through.

The engine evaluates one `ScopeAction` at a time. At run-creation we know
target / risk / per-step tool ids; we don't yet know per-request port,
method, path, or actual RPS. Those gates remain available for any future
enforcement point (HTTP-capture middleware, tool argv parser) that has
the data — calling `evaluate_run` with them works exactly the same.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Iterable

from fastapi import HTTPException

from app.core.config import get_settings
from app.services.scope_engine import ScopeAction, ScopeDecisionResult, ScopeEngine


@lru_cache(maxsize=1)
def _engine() -> ScopeEngine | None:
    """Lazy + cached engine load. Returns None when no policy file exists
    so the guard short-circuits to a no-op (opt-in default)."""
    path = Path(get_settings().roe_policy_path)
    if not path.exists():
        return None
    return ScopeEngine.from_file(path)


def clear_engine_cache() -> None:
    """Tests that monkeypatch `roe_policy_path` call this so the next
    `_engine()` reloads from the new path."""
    _engine.cache_clear()


def evaluate_run(
    *,
    target: str,
    tool_id: str | None,
    risk: str,
    manual_approval: bool = False,
    port: int | None = None,
    method: str | None = None,
    path: str | None = None,
    requested_rps: float | None = None,
) -> ScopeDecisionResult | None:
    """Evaluate a single action against the loaded policy. Returns None
    when no policy is loaded (engine disabled); otherwise returns the
    engine's structured decision. Caller decides whether to raise."""
    engine = _engine()
    if engine is None:
        return None
    return engine.evaluate_action(ScopeAction(
        target=target, tool_id=tool_id, risk=risk,
        port=port, method=method, path=path,
        requested_rps=requested_rps, manual_approval=manual_approval,
    ))


def _raise_for_decision(decision: ScopeDecisionResult) -> None:
    """403 with the full decision body so the operator / agent can see
    exactly which rule denied and why. `trace` carries the per-check
    debug output the engine produces during evaluation."""
    raise HTTPException(
        status_code=403,
        detail={
            "decision": decision.decision,
            "reason": decision.reason,
            "matched_rule": decision.matched_rule,
            "normalized_target": decision.normalized_target,
            "risk": decision.risk,
            "trace": decision.trace,
            "effective_limits": decision.effective_limits,
        },
    )


def enforce_profile_run(
    *,
    target: str,
    risk: str,
    tools: Iterable[str] = (),
    manual_approval: bool = False,
) -> ScopeDecisionResult | None:
    """Evaluate the engine for a whole run.

    Two passes:
      1. Target + risk (tool-independent) — catches denied domains/CIDRs
         and risk-level approval requirements.
      2. Per-tool — `approval.require_for_tools` fires on the first step
         whose tool id is in the policy's per-tool approval list. This is
         the gate the legacy code lacks: a profile that's only
         medium_active can still contain a sqlmap step, and the engine
         now refuses it without fresh consent.

    Raises HTTPException(403, decision=...) on deny / require_approval.
    Returns the decision object on allow / rate_limit / no-engine; the
    rate_limit case is non-fatal here because requested_rps isn't known
    at run-creation. Future enforcement points (tool argv parser, http
    capture) can call `evaluate_run` directly with the live values.
    """
    decision = evaluate_run(target=target, tool_id=None, risk=risk,
                             manual_approval=manual_approval)
    if decision is None:
        return None
    if decision.decision in {"deny", "require_approval"}:
        _raise_for_decision(decision)

    for tool_id in tools:
        if not tool_id:
            continue
        per_tool = evaluate_run(
            target=target, tool_id=tool_id, risk=risk,
            manual_approval=manual_approval,
        )
        if per_tool is None:
            continue
        if per_tool.decision in {"deny", "require_approval"}:
            _raise_for_decision(per_tool)

    return decision
