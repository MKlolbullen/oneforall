"""Workspace layout + findings.json read/merge/write."""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from oneforall.schema import empty_findings

logger = logging.getLogger(__name__)


@dataclass
class Workspace:
    target: str
    root: Path

    @classmethod
    def for_target(cls, target: str, base: Path | None = None) -> "Workspace":
        base = base or Path.cwd() / "workspace"
        root = base / target
        ws = cls(target=target, root=root)
        ws.ensure_layout()
        return ws

    def ensure_layout(self) -> None:
        for sub in ("raw", "logs", "report"):
            (self.root / sub).mkdir(parents=True, exist_ok=True)
        for stage_id in (f"s{n:02d}" for n in range(1, 11)):
            (self.root / "raw" / stage_id).mkdir(parents=True, exist_ok=True)
        if not self.findings_path.exists():
            self.write_findings(empty_findings(self.target))

    @property
    def findings_path(self) -> Path:
        return self.root / "findings.json"

    @property
    def scope_path(self) -> Path:
        return self.root / "scope.yaml"

    def raw_dir(self, stage_id: str) -> Path:
        d = self.root / "raw" / stage_id
        d.mkdir(parents=True, exist_ok=True)
        return d

    def log_path(self, stage_id: str) -> Path:
        return self.root / "logs" / f"{stage_id}.log"

    def read_findings(self) -> dict[str, Any]:
        if not self.findings_path.exists():
            return empty_findings(self.target)
        return json.loads(self.findings_path.read_text())

    def write_findings(self, data: dict[str, Any]) -> None:
        self.findings_path.write_text(json.dumps(data, indent=2, sort_keys=True))

    def load_scope(self) -> dict[str, list[str]] | None:
        if not self.scope_path.exists():
            return None
        return yaml.safe_load(self.scope_path.read_text())

    # ---- Merge helpers (each stage calls these) ----

    def merge_subdomain(self, name: str, source: str, ip: str | None = None,
                        live: bool | None = None, status_code: int | None = None) -> None:
        data = self.read_findings()
        existing = next((s for s in data["subdomains"] if s["name"] == name), None)
        if existing is None:
            existing = {
                "name": name, "sources": [], "ips": [],
                "live": None, "status_code": None, "title": None,
            }
            data["subdomains"].append(existing)
        if source and source not in existing["sources"]:
            existing["sources"].append(source)
        if ip and ip not in existing["ips"]:
            existing["ips"].append(ip)
        if live is not None:
            existing["live"] = live
        if status_code is not None:
            existing["status_code"] = status_code
        self.write_findings(data)

    def merge_url(self, url: str, source: str = "", params: list[str] | None = None) -> None:
        data = self.read_findings()
        existing = next((u for u in data["urls"] if u["url"] == url), None)
        if existing is None:
            data["urls"].append({
                "url": url, "params": params or [], "methods": [], "source": source,
            })
        elif params:
            for p in params:
                if p not in existing["params"]:
                    existing["params"].append(p)
        self.write_findings(data)

    def merge_port(self, host: str, port: int, service: str | None = None,
                   product: str | None = None, tech: list[str] | None = None) -> None:
        data = self.read_findings()
        existing = next(
            (p for p in data["ports"] if p["host"] == host and p["port"] == port), None
        )
        if existing is None:
            data["ports"].append({
                "host": host, "port": port, "service": service,
                "product": product, "tech": tech or [],
            })
        else:
            if service and not existing.get("service"):
                existing["service"] = service
            if product and not existing.get("product"):
                existing["product"] = product
            for t in tech or []:
                if t not in existing["tech"]:
                    existing["tech"].append(t)
        self.write_findings(data)

    def append_secret(self, file: str, type_: str, match: str, confidence: str = "medium") -> None:
        data = self.read_findings()
        data["secrets"].append({
            "file": file, "type": type_, "match": match, "confidence": confidence,
        })
        self.write_findings(data)

    def append_vuln(self, id_: str, url: str, severity: str, evidence: str = "", tool: str = "") -> None:
        data = self.read_findings()
        data["vulns"].append({
            "id": id_, "url": url, "severity": severity, "evidence": evidence, "tool": tool,
        })
        self.write_findings(data)

    def mark_stage_done(self, stage_id: str) -> None:
        data = self.read_findings()
        if stage_id not in data["stages_completed"]:
            data["stages_completed"].append(stage_id)
        self.write_findings(data)
