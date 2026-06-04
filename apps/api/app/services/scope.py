"""Target scope / Rules-of-Engagement enforcement.

Hands-off design:
  - Operators declare scope in platform-config YAML and on each Target row.
  - This module decides yes/no at run-creation time.
  - Workers never re-decide: by the time a step fires, scope has already
    cleared the action.

For richer policies (per-port allowlist, HTTP method denial, rate limits,
time windows) see `app.services.scope_engine` and the matching ROE engine
guard. This module covers the strict subset that every run must pass.
"""
from __future__ import annotations

from fnmatch import fnmatch
from ipaddress import ip_address, ip_network

from app.models import RiskLevel, Target
from app.services.platform_config import load_platform_config


class ScopeError(ValueError):
    pass


def _try_ip_network(pattern: str):
    """Return an ip_network if `pattern` is a valid CIDR string, else None.
    Operators routinely paste CIDR notation into the deny list; the previous
    fnmatch-only matcher silently failed to ever match a CIDR pattern
    against an IP target (see PoC V2)."""
    if "/" not in pattern:
        return None
    try:
        return ip_network(pattern, strict=False)
    except ValueError:
        return None


def _matches_any(value: str, patterns: list[str]) -> str | None:
    """Match `value` against each `pattern`. Three kinds of pattern:

      - CIDR `10.10.50.0/24`  → matches if `value` parses as an IP inside
                                 the network. (V2 fix.)
      - `*.example.com`        → matches subdomains AND the apex `example.com`.
                                 (V3 fix — old matcher missed the apex.)
      - bare host / fnmatch    → matches when fnmatch returns True OR
                                 when the lowercased value equals the pattern.
    """
    raw = value.strip()
    normalized = raw.lower().rstrip(".")
    for pattern in patterns:
        pat = pattern.strip().rstrip(".")
        if not pat:
            continue

        # V2: real CIDR semantics for CIDR patterns. Skip non-IP target
        # values cleanly so a domain target doesn't trip a CIDR pattern.
        net = _try_ip_network(pat)
        if net is not None:
            try:
                if ip_address(raw) in net:
                    return pattern
            except ValueError:
                pass
            continue

        pat_lower = pat.lower()

        # V3: `*.x.y` covers the apex `x.y` too. Operators reasonably expect
        # a wildcard deny pattern to take the bare apex with it.
        if pat_lower.startswith("*.") and normalized == pat_lower[2:]:
            return pattern

        if fnmatch(normalized, pat_lower):
            return pattern
        if normalized == pat_lower:
            return pattern
    return None


# RFC1918 + link-local + loopback + carrier-grade NAT. Anything `is_private`
# under the stdlib `ipaddress` module — covers IPv6 ULA + link-local too.
def _is_private_target(value: str) -> bool:
    try:
        ip = ip_address(value.strip())
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def enforce_target_scope(target: Target, risk: RiskLevel, *, manual_approval: bool = False) -> None:
    config = load_platform_config()
    scope = config.get("scope") or {}

    if not target.in_scope:
        raise ScopeError("Target is marked out-of-scope")

    # V1: honour `scope.block_private_ranges_by_default`. Previously this
    # field appeared in the example YAML but was never read by any code,
    # so operators toggling it on got a false sense of security. The check
    # only fires when the policy is explicitly opted in.
    if scope.get("block_private_ranges_by_default", False) and _is_private_target(target.value):
        raise ScopeError(
            f"Target {target.value} is in a private / loopback range and "
            f"scope.block_private_ranges_by_default is enabled"
        )

    if scope.get("enforce_out_of_scope_patterns", True):
        patterns = list(scope.get("default_out_of_scope") or [])
        matched = _matches_any(target.value, patterns)
        if matched:
            raise ScopeError(f"Target matches configured out-of-scope pattern: {matched}")

    if risk == RiskLevel.passive and not target.passive_allowed:
        raise ScopeError("Passive recon is disabled for this target")

    active_risks = {RiskLevel.low_active, RiskLevel.medium_active, RiskLevel.high_active}
    if risk in active_risks:
        require_active = bool(scope.get("require_active_authorization", True))
        if require_active and not target.active_allowed:
            raise ScopeError("Active scanning requires explicit authorization on the target")

    if risk == RiskLevel.high_active and scope.get("require_high_risk_manual_approval", True) and not manual_approval:
        raise ScopeError("High-risk profiles require manual_approval=true in run params")
