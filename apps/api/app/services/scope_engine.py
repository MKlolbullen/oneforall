from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, time
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse
import fnmatch
import yaml

try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover
    ZoneInfo = None


@dataclass
class ScopeAction:
    target: str
    tool_id: str | None = None
    risk: str = "low"
    method: str | None = None
    port: int | None = None
    path: str | None = None
    requested_rps: float | None = None
    manual_approval: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScopeDecisionResult:
    decision: str
    reason: str
    matched_rule: str | None
    normalized_target: str
    risk: str
    trace: list[str] = field(default_factory=list)
    effective_limits: dict[str, Any] = field(default_factory=dict)


class ScopeEngine:
    """Pure Python rules-of-engagement evaluator."""

    def __init__(self, policy: dict[str, Any] | None = None):
        self.policy = policy or {}

    @classmethod
    def from_file(cls, path: str | Path) -> "ScopeEngine":
        p = Path(path)
        if not p.exists():
            return cls({})
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        return cls(data)

    def evaluate_action(self, action: ScopeAction) -> ScopeDecisionResult:
        trace: list[str] = []
        normalized = self._normalize_target(action.target)
        parsed = urlparse(normalized if "://" in normalized else f"//{normalized}")
        host = parsed.hostname or normalized
        path = action.path or parsed.path or "/"
        method = action.method.upper() if action.method else None

        trace.extend([f"normalized_target={normalized}", f"host={host}", f"path={path}"])

        denied = self.policy.get("denied", {}) or {}
        allowed = self.policy.get("allowed", {}) or {}
        limits = self.policy.get("limits", {}) or {}
        approval = self.policy.get("approval", {}) or {}

        if self._match_domain(host, denied.get("domains", [])):
            return self._result("deny", f"Host {host} matches denied domain rule", "denied.domains", normalized, action, trace)

        if self._match_cidr(host, denied.get("cidrs", [])):
            return self._result("deny", f"Host {host} matches denied CIDR rule", "denied.cidrs", normalized, action, trace)

        if method and method in {m.upper() for m in denied.get("methods", [])}:
            return self._result("deny", f"HTTP method {method} is denied", f"denied.methods:{method}", normalized, action, trace)

        denied_paths = denied.get("paths", []) or []
        if any(path == p or path.startswith(p.rstrip("/") + "/") for p in denied_paths):
            return self._result("deny", f"Path {path} matches denied path rule", "denied.paths", normalized, action, trace)

        allowed_by_domain = self._match_domain(host, allowed.get("domains", []))
        allowed_by_cidr = self._match_cidr(host, allowed.get("cidrs", []))
        allowed_ports = {int(p) for p in allowed.get("ports", []) or []}
        port_ok = action.port is None or not allowed_ports or action.port in allowed_ports

        trace.extend([
            f"allowed_by_domain={allowed_by_domain}",
            f"allowed_by_cidr={allowed_by_cidr}",
            f"port_ok={port_ok}",
        ])

        if not (allowed_by_domain or allowed_by_cidr):
            return self._result("deny", f"Host {host} is not in allowed domains or CIDRs", "allowed.domains|allowed.cidrs", normalized, action, trace)

        if not port_ok:
            return self._result("deny", f"Port {action.port} is outside allowed port list", "allowed.ports", normalized, action, trace)

        effective_limits: dict[str, Any] = {}
        max_rps = limits.get("max_rps")
        if max_rps is not None:
            effective_limits["max_rps"] = max_rps
            if action.requested_rps is not None and float(action.requested_rps) > float(max_rps):
                return self._result("rate_limit", f"Requested RPS {action.requested_rps} exceeds max_rps {max_rps}", "limits.max_rps", normalized, action, trace, effective_limits)

        active_window = limits.get("active_scan_window")
        if active_window and action.risk in {"low_active", "medium_active", "high_active", "destructive"}:
            if not self._within_time_window(active_window):
                return self._result("require_approval", "Active scan is outside configured active_scan_window", "limits.active_scan_window", normalized, action, trace, effective_limits)

        approval_risks = set(approval.get("require_for_risk", []) or [])
        approval_tools = set(approval.get("require_for_tools", []) or [])
        needs_approval = action.risk in approval_risks or (action.tool_id in approval_tools if action.tool_id else False)
        if needs_approval and not action.manual_approval:
            return self._result("require_approval", "Manual approval required by ROE policy", "approval.require_for_risk|approval.require_for_tools", normalized, action, trace, effective_limits)

        return self._result("allow", "Action is within scope", "allowed", normalized, action, trace, effective_limits)

    def _result(self, decision: str, reason: str, matched_rule: str | None, normalized: str, action: ScopeAction, trace: list[str], effective_limits: dict[str, Any] | None = None) -> ScopeDecisionResult:
        return ScopeDecisionResult(decision=decision, reason=reason, matched_rule=matched_rule, normalized_target=normalized, risk=action.risk, trace=trace, effective_limits=effective_limits or {})

    def _normalize_target(self, target: str) -> str:
        return target.strip().lower()

    def _match_domain(self, host: str, patterns: Iterable[str]) -> bool:
        host = host.rstrip(".").lower()
        for pattern in patterns or []:
            p = str(pattern).rstrip(".").lower()
            if p.startswith("*."):
                suffix = p[1:]
                if host.endswith(suffix) and host != p[2:]:
                    return True
            if fnmatch.fnmatch(host, p) or host == p:
                return True
        return False

    def _match_cidr(self, host: str, cidrs: Iterable[str]) -> bool:
        try:
            ip = ip_address(host)
        except ValueError:
            return False
        for cidr in cidrs or []:
            try:
                if ip in ip_network(str(cidr), strict=False):
                    return True
            except ValueError:
                continue
        return False

    def _within_time_window(self, cfg: dict[str, Any]) -> bool:
        start_raw = cfg.get("start")
        end_raw = cfg.get("end")
        tz_raw = cfg.get("timezone", "UTC")
        if not start_raw or not end_raw:
            return True

        def parse_hhmm(value: str) -> time:
            hour, minute = [int(x) for x in value.split(":", 1)]
            return time(hour=hour, minute=minute)

        start = parse_hhmm(str(start_raw))
        end = parse_hhmm(str(end_raw))
        now = datetime.now(ZoneInfo(str(tz_raw))).time() if ZoneInfo is not None else datetime.utcnow().time()

        if start <= end:
            return start <= now <= end
        return now >= start or now <= end
