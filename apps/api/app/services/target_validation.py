from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

ALLOWED_TARGET_TYPES = {"domain", "url", "ip", "cidr"}
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class NormalizedTarget:
    value: str
    type: str


def _normalize_domain(value: str) -> str:
    raw = value.strip().lower().rstrip(".")
    if "://" in raw:
        parsed = urlparse(raw)
        raw = parsed.hostname or ""
    if "/" in raw:
        # Operators often paste https://host/path into a domain field by accident.
        # Keep the host part rather than silently storing an invalid domain.
        raw = raw.split("/", 1)[0]
    if not raw:
        raise ValueError("target domain is empty")
    try:
        raw = raw.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("target domain is not valid IDNA") from exc
    if not DOMAIN_RE.match(raw):
        raise ValueError("target domain must be a DNS name like example.com")
    return raw


def _normalize_url(value: str) -> str:
    raw = value.strip()
    if not raw:
        raise ValueError("target URL is empty")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("target URL scheme must be http or https")
    if not parsed.hostname:
        raise ValueError("target URL must include a host")
    host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    port = f":{parsed.port}" if parsed.port else ""
    path = parsed.path or ""
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{parsed.scheme}://{host}{port}{path}{query}"


def _normalize_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ValueError("target IP must be a valid IPv4 or IPv6 address") from exc


def _normalize_cidr(value: str) -> str:
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError as exc:
        raise ValueError("target CIDR must be a valid IPv4 or IPv6 network") from exc


def normalize_target(value: str, target_type: str) -> NormalizedTarget:
    """Canonicalize and validate operator-supplied target values.

    This deliberately does not block private/loopback/link-local ranges: internal
    AD, Entra hybrid, Kubernetes, and lab work often need them. Scope and ROE are
    enforced separately by `enforce_target_scope()` at run creation time.
    """
    t = (target_type or "domain").strip().lower()
    if t not in ALLOWED_TARGET_TYPES:
        raise ValueError(f"target type must be one of: {', '.join(sorted(ALLOWED_TARGET_TYPES))}")
    if t == "domain":
        return NormalizedTarget(value=_normalize_domain(value), type=t)
    if t == "url":
        return NormalizedTarget(value=_normalize_url(value), type=t)
    if t == "ip":
        return NormalizedTarget(value=_normalize_ip(value), type=t)
    return NormalizedTarget(value=_normalize_cidr(value), type=t)
