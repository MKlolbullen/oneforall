from __future__ import annotations

from fnmatch import fnmatch

from app.models import RiskLevel, Target
from app.services.platform_config import load_platform_config


class ScopeError(ValueError):
    pass


def _matches_any(value: str, patterns: list[str]) -> str | None:
    normalized = value.lower().strip().rstrip('.')
    for pattern in patterns:
        pat = pattern.lower().strip().rstrip('.')
        if not pat:
            continue
        if fnmatch(normalized, pat):
            return pattern
        # Treat a bare domain as matching exactly and one-level wildcard-like children only when operator used *.
        if normalized == pat:
            return pattern
    return None


def enforce_target_scope(target: Target, risk: RiskLevel, *, manual_approval: bool = False) -> None:
    config = load_platform_config()
    scope = config.get('scope') or {}

    if not target.in_scope:
        raise ScopeError('Target is marked out-of-scope')

    if scope.get('enforce_out_of_scope_patterns', True):
        patterns = list(scope.get('default_out_of_scope') or [])
        matched = _matches_any(target.value, patterns)
        if matched:
            raise ScopeError(f'Target matches configured out-of-scope pattern: {matched}')

    if risk == RiskLevel.passive and not target.passive_allowed:
        raise ScopeError('Passive recon is disabled for this target')

    active_risks = {RiskLevel.low_active, RiskLevel.medium_active, RiskLevel.high_active}
    if risk in active_risks:
        require_active = bool(scope.get('require_active_authorization', True))
        if require_active and not target.active_allowed:
            raise ScopeError('Active scanning requires explicit authorization on the target')

    if risk == RiskLevel.high_active and scope.get('require_high_risk_manual_approval', True) and not manual_approval:
        raise ScopeError('High-risk profiles require manual_approval=true in run params')
