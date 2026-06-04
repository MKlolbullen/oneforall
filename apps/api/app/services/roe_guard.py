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
target / risk / per-step tool ids; the argv extractor pulls explicit
port / method / rate-limit values out of each step's effective argv so
the engine's `allowed.ports`, `denied.methods`, `limits.max_rps` gates
become effective without an HTTP-capture middleware. The engine still
exposes per-path enforcement for future callers (`scope/evaluate` etc.)
that can supply a URL path.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

from fastapi import HTTPException

from app.core.config import get_settings
from app.services.argv_extractor import (
    BROAD_PROBE_PORT,
    ArgvSignals,
    effective_argv,
    extract,
)
from app.services.scope_engine import ScopeAction, ScopeDecisionResult, ScopeEngine
from app.services.tool_registry import get_registry


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


def _resolve_signals(step: dict[str, Any]) -> tuple[str, ArgvSignals]:
    """Look up the step's tool in the registry, resolve its effective
    argv (honouring step.argv_replace / step.argv_extra), and extract the
    policy-relevant signals. Returns (tool_id, signals).

    Unknown tools surface as empty signals so the engine's other gates
    (allowed.domains, approval.require_for_tools by name) still fire."""
    tool_id = step.get("tool", "") if isinstance(step, dict) else ""
    if not tool_id:
        return tool_id, ArgvSignals()
    try:
        tool = get_registry().get_tool(tool_id)
    except KeyError:
        return tool_id, ArgvSignals()
    default_argv = list((tool.command or {}).get("argv") or [])
    resolved = effective_argv(default_argv, step)
    return tool_id, extract(resolved)


def enforce_profile_run(
    *,
    target: str,
    risk: str,
    steps: Iterable[dict[str, Any]],
    manual_approval: bool = False,
) -> ScopeDecisionResult | None:
    """Evaluate the engine for a whole run.

    Three layers of checks for each step:

      1. Target + risk (tool-independent). Catches denied domains/CIDRs,
         risk-level approval requirements, and time-window violations.

      2. Per-tool. `approval.require_for_tools` fires on the first step
         whose tool id is in the policy's per-tool approval list. This is
         the gate the legacy code lacks: a profile that's only
         medium_active can still contain a sqlmap step and the engine
         refuses it without fresh consent.

      3. Per-step argv signals. For every step we parse its effective
         argv (honouring argv_replace / argv_extra) and feed each
         extracted port, method, and rate-limit value into the engine.
         A broad-port-scan signal (e.g. `--top-ports 1000`) is probed
         against port 22 so a policy that allowlists only 80/443 refuses
         broad scans.

    Raises HTTPException(403, decision=...) on deny / require_approval.
    Returns the decision on allow / rate_limit / no-engine; rate_limit
    is non-fatal here because the operator may still want the run to
    proceed at the engine's effective_limits.max_rps. Callers that
    need a strict cap can re-check the returned decision themselves.
    """
    decision = evaluate_run(target=target, tool_id=None, risk=risk,
                             manual_approval=manual_approval)
    if decision is None:
        # Engine disabled — short-circuit so the call sites stay clean.
        return None
    if decision.decision in {"deny", "require_approval"}:
        _raise_for_decision(decision)

    materialised = list(steps)

    # Layer 2: per-tool approval.
    for step in materialised:
        tool_id = step.get("tool") if isinstance(step, dict) else None
        if not tool_id:
            continue
        per_tool = evaluate_run(
            target=target, tool_id=tool_id, risk=risk,
            manual_approval=manual_approval,
        )
        if per_tool and per_tool.decision in {"deny", "require_approval"}:
            _raise_for_decision(per_tool)

    # Layer 3: per-step argv signals (port / method / rps / broad scan).
    for step in materialised:
        if not isinstance(step, dict):
            continue
        tool_id, signals = _resolve_signals(step)
        if signals.is_empty():
            continue

        # Each explicit port is one action. The first denial wins.
        for port in sorted(signals.ports):
            d = evaluate_run(
                target=target, tool_id=tool_id, risk=risk,
                manual_approval=manual_approval, port=port,
            )
            if d and d.decision in {"deny", "require_approval"}:
                _raise_for_decision(d)

        # Broad-port-scan signal: probe a representative high-impact
        # port. An operator that allowlists 80/443 then sees broad
        # scans denied at this layer with the right matched_rule.
        if signals.broad_port_scan:
            d = evaluate_run(
                target=target, tool_id=tool_id, risk=risk,
                manual_approval=manual_approval, port=BROAD_PROBE_PORT,
            )
            if d and d.decision in {"deny", "require_approval"}:
                _raise_for_decision(d)

        for method in sorted(signals.methods):
            d = evaluate_run(
                target=target, tool_id=tool_id, risk=risk,
                manual_approval=manual_approval, method=method,
            )
            if d and d.decision in {"deny", "require_approval"}:
                _raise_for_decision(d)

        if signals.rps is not None:
            d = evaluate_run(
                target=target, tool_id=tool_id, risk=risk,
                manual_approval=manual_approval, requested_rps=signals.rps,
            )
            # An argv-derived rps that exceeds the policy's max_rps is
            # treated as fatal — the operator set the rate explicitly
            # in the step spec; the run should not proceed at that rate.
            # This is the one place we elevate rate_limit to a deny.
            if d and d.decision in {"deny", "require_approval", "rate_limit"}:
                _raise_for_decision(d)

    return decision
