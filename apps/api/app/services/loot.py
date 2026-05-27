"""Loot layer.

Loot is the curated, high-signal slice of a run's output: secrets, credentials,
subdomain takeovers, exposed sensitive files, and critical/high vulnerabilities.
It is *derived* from Findings — not a second copy of every scanner line. Operators
and external agents read loot first ("what deserves attention") and fall back to
the raw Finding / Artifact for full evidence.

Two entry points feed the table:
  - record_from_finding(session, finding)  passive hook from the normalizer; runs
                                            on every new finding when loot is on.
  - index_run(session, run_id=...)          explicit sweep at run completion (and
                                            on demand from the API / advisor).

Both are idempotent on finding_id, so re-indexing a run never duplicates rows.
The `LOOT` env var / `runtime.loot_enabled` config toggle only gates the passive
hook; an explicit index_run is always honoured.
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterable
from typing import Any

from sqlmodel import Session, select

from app.models import Finding, LootItem, now_utc
from app.services.platform_config import load_platform_config

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

# Tools whose output is, by construction, a secret/credential dump.
_SECRET_TOOLS = {
    "trufflehog", "gitleaks", "secretfinder", "jsubfinder", "shhgit",
    "detect-secrets", "gitdorker", "apkleaks",
}

_TAKEOVER_RE = re.compile(
    r"\b(take[\s-]?over|dangling\s+cname|unclaimed|can\s+be\s+claimed|"
    r"nxdomain\s+cname)\b",
    re.IGNORECASE,
)
_SECRET_RE = re.compile(
    r"(secret|api[_-]?key|apikey|access[_-]?key|access[_-]?token|bearer\s+token|"
    r"private[_-]?key|begin\s+(?:rsa|openssh|ec|dsa|pgp)\s+private\s+key|"
    r"aws_secret|client[_-]?secret|\bjwt\b|authorization:\s*bearer)",
    re.IGNORECASE,
)
_CRED_RE = re.compile(
    r"(\bntlm\b|\bcredential|cleartext\s+password|password\s*[:=]|"
    r"hash(?:es)?\s+(?:dumped|captured)|default\s+credential|valid\s+login)",
    re.IGNORECASE,
)
_EXPOSURE_RE = re.compile(
    r"(\.git/|\.svn/|/\.env\b|\.env\s|\bbackup\b|\.sql\b|\.bak\b|\bdump\b|"
    r"swagger|actuator|phpinfo|server-status|\.DS_Store|wp-config|web\.config|"
    r"id_rsa|\bexposed\b|directory\s+listing|index\s+of\s*/)",
    re.IGNORECASE,
)

_URL_HOST_RE = re.compile(r"https?://([^/\s:\"']+)", re.IGNORECASE)
_HOSTISH_RE = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})\b", re.IGNORECASE)
_IP_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\b")

_PREVIEW_MAX = 512


def loot_enabled() -> bool:
    """Gate for the passive normalizer hook. Honours `runtime.loot_enabled`
    (set via YAML or the `LOOT` env override). Defaults to on."""
    config = load_platform_config()
    runtime = config.get("runtime", {}) if isinstance(config, dict) else {}
    return bool(runtime.get("loot_enabled", True))


def _norm_sev(value: str | None) -> str:
    sev = (value or "info").lower()
    return sev if sev in SEVERITY_RANK else "info"


def _more_severe(a: str, b: str) -> str:
    """Return whichever severity ranks higher (critical beats info)."""
    a, b = _norm_sev(a), _norm_sev(b)
    return a if SEVERITY_RANK[a] <= SEVERITY_RANK[b] else b


def _classify(finding: Finding) -> tuple[str, str] | None:
    """Decide if a finding is loot-worthy.

    Returns (kind, severity_floor) or None for raw noise that should stay a
    plain Finding. The floor lifts inherently high-signal kinds (secrets,
    takeovers) up to at least `high` even when the source tool tagged them low.
    """
    text = " ".join(
        part for part in (finding.title, finding.category, finding.evidence, finding.tool_source)
        if part
    )
    tool = (finding.tool_source or "").lower()
    sev = _norm_sev(finding.severity)

    if tool in _SECRET_TOOLS or _SECRET_RE.search(text):
        return ("secret", "high")
    if _TAKEOVER_RE.search(text):
        return ("takeover", "high")
    if _CRED_RE.search(text):
        return ("credential", "high")
    if _EXPOSURE_RE.search(text):
        return ("exposure", "medium")
    if sev in {"critical", "high"}:
        return ("vulnerability", sev)
    return None


def _preview(text: str) -> str:
    one_line = " ".join((text or "").split())
    if len(one_line) > _PREVIEW_MAX:
        return one_line[: _PREVIEW_MAX - 3] + "..."
    return one_line


def _extract_host(finding: Finding) -> str | None:
    meta = finding.meta if isinstance(finding.meta, dict) else {}
    parsed = meta.get("json") if isinstance(meta.get("json"), dict) else {}
    candidates: list[str] = []
    for key in ("matched-at", "matched", "url", "host", "input", "ip"):
        value = parsed.get(key)
        if isinstance(value, str) and value:
            candidates.append(value)
    candidates.append(finding.evidence or "")
    candidates.append(finding.title or "")

    for candidate in candidates:
        match = _URL_HOST_RE.search(candidate)
        if match:
            return match.group(1)[:255]
    for candidate in candidates:
        match = _HOSTISH_RE.search(candidate) or _IP_RE.search(candidate)
        if match:
            return match.group(1)[:255]
    return None


def _record(session: Session, finding: Finding) -> LootItem | None:
    """Create (idempotently) a LootItem for a loot-worthy finding.

    No-ops and returns the existing row if this finding already produced loot,
    so both the passive hook and an explicit re-index converge on one row.
    """
    classified = _classify(finding)
    if not classified:
        return None
    kind, floor = classified

    existing = session.exec(
        select(LootItem).where(LootItem.finding_id == finding.id)
    ).first()
    if existing:
        return existing

    item = LootItem(
        workspace_id=finding.workspace_id,
        run_id=finding.run_id,
        finding_id=finding.id,
        kind=kind,
        label=(finding.title or kind)[:255],
        value_preview=_preview(finding.evidence or finding.title or ""),
        severity=_more_severe(finding.severity, floor),
        source_tool=finding.tool_source,
        host=_extract_host(finding),
        meta={"category": finding.category},
    )
    session.add(item)
    session.commit()
    session.refresh(item)
    return item


def record_from_finding(session: Session, finding: Finding) -> LootItem | None:
    """Passive hook called by the normalizer for every new finding.

    Gated by the loot_enabled toggle so operators can silence it without
    touching the indexing path. The normalizer wraps this in suppress(), so a
    failure here never blocks finding creation.
    """
    if not loot_enabled():
        return None
    return _record(session, finding)


def _sorted(items: Iterable[LootItem]) -> list[LootItem]:
    return sorted(
        items,
        key=lambda i: (SEVERITY_RANK.get(i.severity, 9), i.created_at or now_utc()),
    )


def index_run(session: Session, *, workspace_id: str, run_id: str) -> list[LootItem]:
    """Sweep every finding in a run and ensure loot rows exist. Always honoured
    (not gated by the toggle) since it is an explicit request. Returns the run's
    full loot list, severity-ranked."""
    findings = list(session.exec(select(Finding).where(Finding.run_id == run_id)).all())
    for finding in findings:
        _record(session, finding)
    items = list(session.exec(select(LootItem).where(LootItem.run_id == run_id)).all())
    return _sorted(items)


def _item_summary(item: LootItem) -> dict[str, Any]:
    return {
        "id": item.id,
        "kind": item.kind,
        "label": item.label,
        "severity": item.severity,
        "source_tool": item.source_tool,
        "host": item.host,
    }


def summarize_loot(loot_items: Iterable[LootItem]) -> dict[str, Any]:
    """Compact, bounded summary for embedding in advisor / agent payloads.

    Counts by kind and severity plus the top 25 rows. Never inlines full
    secrets — only the label and metadata; the value lives on the Finding.
    """
    items = _sorted(loot_items)
    by_kind: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for item in items:
        by_kind[item.kind] = by_kind.get(item.kind, 0) + 1
        by_severity[item.severity] = by_severity.get(item.severity, 0) + 1
    return {
        "total": len(items),
        "by_kind": by_kind,
        "by_severity": by_severity,
        "items": [_item_summary(i) for i in items[:25]],
    }


def _item_full(item: LootItem) -> dict[str, Any]:
    return {
        "id": item.id,
        "kind": item.kind,
        "label": item.label,
        "value_preview": item.value_preview,
        "severity": item.severity,
        "source_tool": item.source_tool,
        "host": item.host,
        "finding_id": item.finding_id,
        "artifact_id": item.artifact_id,
        "meta": item.meta or {},
        "created_at": item.created_at.isoformat() if item.created_at else None,
    }


def manifest_json(session: Session, *, workspace_id: str, run_id: str) -> str:
    """Render the run's loot as a JSON manifest, written to the
    `loot.manifest.json` artifact at run completion."""
    items = _sorted(
        session.exec(select(LootItem).where(LootItem.run_id == run_id)).all()
    )
    document = {
        "schema": "reconforge.loot.manifest/v1",
        "workspace_id": workspace_id,
        "run_id": run_id,
        "generated_at": now_utc().isoformat(),
        "total": len(items),
        "summary": summarize_loot(items),
        "loot": [_item_full(i) for i in items],
    }
    return json.dumps(document, indent=2, default=str)
