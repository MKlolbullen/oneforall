"""Findings schema. Each stage merges into a single findings.json."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class Finding:
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Subdomain(Finding):
    name: str
    sources: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    live: bool | None = None
    status_code: int | None = None
    title: str | None = None


@dataclass
class Port(Finding):
    host: str
    port: int
    service: str | None = None
    product: str | None = None
    tech: list[str] = field(default_factory=list)


@dataclass
class Url(Finding):
    url: str
    params: list[str] = field(default_factory=list)
    methods: list[str] = field(default_factory=list)
    source: str = ""


@dataclass
class Secret(Finding):
    file: str
    type: str
    match: str
    confidence: str = "medium"


@dataclass
class Vuln(Finding):
    id: str
    url: str
    severity: str
    evidence: str = ""
    tool: str = ""


def empty_findings(target: str) -> dict[str, Any]:
    return {
        "target": target,
        "scope": {"in": [], "out": []},
        "stages_completed": [],
        "subdomains": [],
        "ports": [],
        "urls": [],
        "secrets": [],
        "vulns": [],
        "api_findings": [],
        "tech": [],
    }
