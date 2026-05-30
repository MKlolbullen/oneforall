"""Run report rendering.

Bundle a run's metadata + steps + findings + loot + assets + artifacts into a
shareable document. Three formats, all generated on demand (no persistence):

  - html  — self-contained, inline CSS, paste-into-email-friendly
  - md    — drop into a ticket / wiki / GitHub issue
  - json  — machine-readable, comprehensive (a superset of the agent brief)

The HTML output deliberately avoids `<script>` tags and external assets so the
document is safe to forward without leaking out to a tracker. Findings + loot
include full evidence — this report IS the operator's hand-off package.
"""
from __future__ import annotations

import html as _html
import json
from datetime import datetime, timezone
from typing import Any

from sqlmodel import Session, select

from app.models import Artifact, Asset, Finding, LootItem, Run, RunStep, Target

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
SEVERITY_COLOR = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#0284c7",
    "info": "#6b7280",
}


def _fmt_dt(value: datetime | str | None) -> str:
    if value is None:
        return "—"
    if isinstance(value, str):
        return value
    return value.isoformat()


def _status_value(obj: Any) -> str:
    return obj.value if hasattr(obj, "value") else str(obj)


def _collect(session: Session, run: Run) -> dict[str, Any]:
    """Pull the raw dataset behind a run report — used by every format."""
    target = session.get(Target, run.target_id)
    steps = list(session.exec(
        select(RunStep).where(RunStep.run_id == run.id).order_by(RunStep.index)
    ).all())
    findings = list(session.exec(
        select(Finding).where(Finding.run_id == run.id)
    ).all())
    findings.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 9), f.created_at or now_utc_sortable()))
    assets = list(session.exec(
        select(Asset).where(Asset.run_id == run.id).order_by(Asset.type, Asset.value)
    ).all())
    artifacts = list(session.exec(
        select(Artifact).where(Artifact.run_id == run.id).order_by(Artifact.created_at)
    ).all())
    loot = list(session.exec(
        select(LootItem).where(LootItem.run_id == run.id)
    ).all())
    loot.sort(key=lambda i: (SEVERITY_RANK.get(i.severity, 9), i.created_at))

    findings_by_severity = {sev: 0 for sev in ("critical", "high", "medium", "low", "info")}
    for f in findings:
        if f.severity in findings_by_severity:
            findings_by_severity[f.severity] += 1

    loot_by_kind: dict[str, int] = {}
    for it in loot:
        loot_by_kind[it.kind] = loot_by_kind.get(it.kind, 0) + 1

    assets_by_type: dict[str, list[str]] = {}
    for a in assets:
        assets_by_type.setdefault(a.type, []).append(a.value)

    return {
        "run": run,
        "target": target,
        "steps": steps,
        "findings": findings,
        "findings_by_severity": findings_by_severity,
        "assets": assets,
        "assets_by_type": assets_by_type,
        "artifacts": artifacts,
        "loot": loot,
        "loot_by_kind": loot_by_kind,
        "generated_at": datetime.now(timezone.utc),
    }


def now_utc_sortable() -> datetime:
    return datetime.now(timezone.utc)


# ---------- JSON -------------------------------------------------------------

def render_json(session: Session, run: Run) -> bytes:
    data = _collect(session, run)
    run_ = data["run"]
    target = data["target"]
    document = {
        "schema": "reconforge.run.report/v1",
        "generated_at": data["generated_at"].isoformat(),
        "run": {
            "id": run_.id,
            "workspace_id": run_.workspace_id,
            "target_id": run_.target_id,
            "profile_id": run_.profile_id,
            "status": _status_value(run_.status),
            "risk": _status_value(run_.risk),
            "requested_by": run_.requested_by,
            "created_at": _fmt_dt(run_.created_at),
            "started_at": _fmt_dt(run_.started_at),
            "finished_at": _fmt_dt(run_.finished_at),
        },
        "target": (
            {"id": target.id, "value": target.value, "type": target.type,
             "in_scope": target.in_scope, "passive_allowed": target.passive_allowed,
             "active_allowed": target.active_allowed}
            if target else None
        ),
        "counts": {
            "steps": len(data["steps"]),
            "findings": len(data["findings"]),
            "assets": len(data["assets"]),
            "artifacts": len(data["artifacts"]),
            "loot": len(data["loot"]),
        },
        "findings_by_severity": data["findings_by_severity"],
        "loot_by_kind": data["loot_by_kind"],
        "steps": [
            {"index": s.index, "tool": s.tool_id, "status": _status_value(s.status),
             "attempt": s.attempt, "timeout_seconds": s.timeout_seconds,
             "exit_code": s.exit_code, "error": s.error,
             "started_at": _fmt_dt(s.started_at), "finished_at": _fmt_dt(s.finished_at)}
            for s in data["steps"]
        ],
        "findings": [
            {"id": f.id, "title": f.title, "severity": f.severity,
             "confidence": f.confidence, "category": f.category, "status": f.status,
             "tool_source": f.tool_source, "evidence": f.evidence or "",
             "meta": f.meta or {}, "created_at": _fmt_dt(f.created_at)}
            for f in data["findings"]
        ],
        "loot": [
            {"id": it.id, "kind": it.kind, "label": it.label, "severity": it.severity,
             "value_preview": it.value_preview, "source_tool": it.source_tool,
             "host": it.host, "finding_id": it.finding_id, "artifact_id": it.artifact_id,
             "meta": it.meta or {}, "created_at": _fmt_dt(it.created_at)}
            for it in data["loot"]
        ],
        "assets_by_type": data["assets_by_type"],
        "artifacts": [
            {"id": a.id, "name": a.name, "type": a.type, "size_bytes": a.size_bytes,
             "sha256": a.sha256, "storage_backend": a.storage_backend,
             "content_url": f"/api/artifacts/{a.id}/content",
             "created_at": _fmt_dt(a.created_at)}
            for a in data["artifacts"]
        ],
    }
    return json.dumps(document, indent=2, default=str).encode("utf-8")


# ---------- Markdown ---------------------------------------------------------

def render_markdown(session: Session, run: Run) -> bytes:
    data = _collect(session, run)
    run_ = data["run"]
    target = data["target"]
    lines: list[str] = []

    target_label = target.value if target else "(target deleted)"
    lines.append(f"# Run report — {target_label}")
    lines.append("")
    lines.append(f"_Generated {data['generated_at'].isoformat()} · ReconForge_")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **Run ID**: `{run_.id}`")
    lines.append(f"- **Profile**: `{run_.profile_id}`")
    lines.append(f"- **Status**: {_status_value(run_.status)}")
    lines.append(f"- **Risk**: {_status_value(run_.risk)}")
    if run_.started_at and run_.finished_at:
        try:
            delta = (run_.finished_at - run_.started_at).total_seconds()
            lines.append(f"- **Duration**: {delta:.1f}s")
        except Exception:  # noqa: BLE001 - fields could be strings if loaded oddly
            pass
    lines.append(f"- **Findings**: {len(data['findings'])} total")
    fbs = data["findings_by_severity"]
    if any(fbs.values()):
        sev_line = " · ".join(f"{k}: **{v}**" for k, v in fbs.items() if v)
        lines.append(f"  - by severity: {sev_line}")
    lines.append(f"- **Loot items**: {len(data['loot'])}")
    if data["loot_by_kind"]:
        lines.append("  - by kind: " + " · ".join(f"{k}: **{v}**" for k, v in data["loot_by_kind"].items()))
    lines.append(f"- **Assets**: {len(data['assets'])}")
    lines.append(f"- **Artifacts**: {len(data['artifacts'])}")
    lines.append("")

    if data["loot"]:
        lines.append("## Loot (curated high-signal)")
        lines.append("")
        lines.append("| Severity | Kind | Label | Host | Tool |")
        lines.append("|---|---|---|---|---|")
        for it in data["loot"]:
            label = (it.label or "").replace("|", "\\|")
            host = (it.host or "").replace("|", "\\|")
            tool = (it.source_tool or "").replace("|", "\\|")
            lines.append(f"| {it.severity} | {it.kind} | {label} | {host} | {tool} |")
        lines.append("")

    if data["findings"]:
        lines.append("## Findings")
        lines.append("")
        for f in data["findings"]:
            lines.append(f"### [{f.severity.upper()}] {f.title}")
            lines.append("")
            lines.append(f"- **ID**: `{f.id}`")
            lines.append(f"- **Category**: {f.category}  ·  **Status**: {f.status}  ·  **Tool**: {f.tool_source or '—'}")
            if f.evidence:
                lines.append("")
                lines.append("```")
                lines.append(f.evidence)
                lines.append("```")
            lines.append("")

    if data["assets_by_type"]:
        lines.append("## Assets discovered")
        lines.append("")
        for type_, values in sorted(data["assets_by_type"].items()):
            lines.append(f"### {type_} ({len(values)})")
            lines.append("")
            for v in values[:50]:
                lines.append(f"- `{v}`")
            if len(values) > 50:
                lines.append(f"- … +{len(values) - 50} more")
            lines.append("")

    if data["steps"]:
        lines.append("## Steps")
        lines.append("")
        lines.append("| # | Tool | Status | Attempts | Error |")
        lines.append("|---|---|---|---|---|")
        for s in data["steps"]:
            err = (s.error or "").replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {s.index} | `{s.tool_id}` | {_status_value(s.status)} | {s.attempt + 1}/{s.max_retries + 1} | {err} |")
        lines.append("")

    if data["artifacts"]:
        lines.append("## Artifacts")
        lines.append("")
        lines.append("| Name | Type | Size | SHA-256 |")
        lines.append("|---|---|---|---|")
        for a in data["artifacts"]:
            size_kb = (a.size_bytes or 0) / 1024
            sha = (a.sha256 or "")[:12]
            name = (a.name or "").replace("|", "\\|")
            lines.append(f"| `{name}` | {a.type} | {size_kb:.1f} KB | `{sha}…` |")
        lines.append("")

    return ("\n".join(lines) + "\n").encode("utf-8")


# ---------- HTML -------------------------------------------------------------

_HTML_STYLE = """
:root { --bg:#0b1220; --fg:#e5e7eb; --muted:#94a3b8; --border:#1f2937; --accent:#22d3ee; }
* { box-sizing: border-box; }
body { margin:0; padding:24px; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
       background:var(--bg); color:var(--fg); line-height:1.5; }
.page { max-width: 980px; margin: 0 auto; }
header { border-bottom: 1px solid var(--border); padding-bottom: 14px; margin-bottom: 22px; }
h1 { margin: 0 0 4px; font-size: 22px; color: var(--accent); }
h2 { font-size: 16px; margin: 24px 0 8px; padding-bottom: 4px; border-bottom: 1px solid var(--border); }
h3 { font-size: 14px; margin: 14px 0 6px; }
.muted { color: var(--muted); font-size: 12.5px; }
.mono, code, pre { font-family: ui-monospace, 'Cascadia Code', Menlo, monospace; }
.kv-grid { display: grid; grid-template-columns: 140px 1fr; gap: 4px 12px; font-size: 13px; }
.kv-grid .k { color: var(--muted); }
.summary-bar { display: flex; flex-wrap: wrap; gap: 6px; margin: 8px 0 14px; }
.chip { display: inline-flex; align-items: center; padding: 3px 8px; border-radius: 999px;
        border: 1px solid var(--border); font-size: 12px; }
.chip.sev-critical { border-color:#dc2626; color:#fca5a5; }
.chip.sev-high { border-color:#ea580c; color:#fdba74; }
.chip.sev-medium { border-color:#d97706; color:#fbbf24; }
.chip.sev-low { border-color:#0284c7; color:#7dd3fc; }
.chip.sev-info { border-color:#6b7280; color:#cbd5e1; }
table { width: 100%; border-collapse: collapse; font-size: 13px; margin: 6px 0; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--border); vertical-align: top; }
th { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .06em; }
.finding { border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px; margin: 8px 0; }
.finding.sev-critical, .finding.sev-high { border-color: #ea580c; background: rgba(234,88,12,.05); }
.finding pre { background:#0a0f1c; border:1px solid var(--border); padding:8px 10px;
               border-radius:6px; white-space: pre-wrap; word-break: break-word;
               max-height: 280px; overflow:auto; margin: 6px 0 0; font-size: 12px; }
.asset-bucket { border: 1px solid var(--border); border-radius: 6px; padding: 8px 10px; margin-bottom: 6px; }
.asset-bucket ul { margin: 4px 0 0 18px; padding: 0; }
.asset-bucket li { font-size: 12px; font-family: ui-monospace, monospace; padding: 1px 0; }
footer { margin-top: 32px; padding-top: 12px; border-top: 1px solid var(--border);
         color: var(--muted); font-size: 12px; text-align: center; }
"""


def _h(text: Any) -> str:
    """HTML-escape any value, coercing to str."""
    return _html.escape("" if text is None else str(text))


def _sev_chip(sev: str, count: int | None = None) -> str:
    label = f"{_h(sev)}{f': {count}' if count is not None else ''}"
    return f'<span class="chip sev-{_h(sev)}">{label}</span>'


def render_html(session: Session, run: Run) -> bytes:
    data = _collect(session, run)
    run_ = data["run"]
    target = data["target"]
    target_label = target.value if target else "(target deleted)"

    parts: list[str] = []
    parts.append("<!doctype html><html lang='en'><head><meta charset='utf-8'>")
    parts.append(f"<title>ReconForge run report — {_h(target_label)}</title>")
    parts.append(f"<style>{_HTML_STYLE}</style></head><body><div class='page'>")

    parts.append(f"<header><h1>Run report — {_h(target_label)}</h1>")
    parts.append(f"<div class='muted'>Generated {_h(data['generated_at'].isoformat())} · ReconForge</div></header>")

    # Summary
    parts.append("<h2>Summary</h2>")
    parts.append("<div class='kv-grid'>")
    parts.append(f"<div class='k'>Run ID</div><div class='mono'>{_h(run_.id)}</div>")
    parts.append(f"<div class='k'>Profile</div><div class='mono'>{_h(run_.profile_id)}</div>")
    parts.append(f"<div class='k'>Status</div><div>{_h(_status_value(run_.status))}</div>")
    parts.append(f"<div class='k'>Risk</div><div>{_h(_status_value(run_.risk))}</div>")
    parts.append(f"<div class='k'>Requested by</div><div>{_h(run_.requested_by)}</div>")
    if run_.started_at:
        parts.append(f"<div class='k'>Started</div><div>{_h(_fmt_dt(run_.started_at))}</div>")
    if run_.finished_at:
        parts.append(f"<div class='k'>Finished</div><div>{_h(_fmt_dt(run_.finished_at))}</div>")
    parts.append("</div>")

    parts.append("<div class='summary-bar'>")
    for sev, n in data["findings_by_severity"].items():
        if n:
            parts.append(_sev_chip(sev, n))
    parts.append(f"<span class='chip'>{len(data['findings'])} findings</span>")
    parts.append(f"<span class='chip'>{len(data['loot'])} loot</span>")
    parts.append(f"<span class='chip'>{len(data['assets'])} assets</span>")
    parts.append(f"<span class='chip'>{len(data['artifacts'])} artifacts</span>")
    parts.append("</div>")

    # Loot
    if data["loot"]:
        parts.append("<h2>Loot — curated high-signal</h2>")
        parts.append("<table><thead><tr><th>Severity</th><th>Kind</th><th>Label</th><th>Host</th><th>Tool</th></tr></thead><tbody>")
        for it in data["loot"]:
            parts.append("<tr>")
            parts.append(f"<td>{_sev_chip(it.severity)}</td>")
            parts.append(f"<td>{_h(it.kind)}</td>")
            parts.append(f"<td>{_h(it.label)}</td>")
            parts.append(f"<td class='mono'>{_h(it.host or '—')}</td>")
            parts.append(f"<td class='mono'>{_h(it.source_tool or '—')}</td>")
            parts.append("</tr>")
        parts.append("</tbody></table>")

    # Findings
    if data["findings"]:
        parts.append("<h2>Findings</h2>")
        for f in data["findings"]:
            parts.append(f"<div class='finding sev-{_h(f.severity)}'>")
            parts.append(f"<h3>{_sev_chip(f.severity)} {_h(f.title)}</h3>")
            parts.append(f"<div class='muted'>id: <span class='mono'>{_h(f.id)}</span> · category: {_h(f.category)} · status: {_h(f.status)} · tool: {_h(f.tool_source or '—')}</div>")
            if f.evidence:
                parts.append(f"<pre>{_h(f.evidence)}</pre>")
            parts.append("</div>")

    # Assets
    if data["assets_by_type"]:
        parts.append("<h2>Assets discovered</h2>")
        for type_, values in sorted(data["assets_by_type"].items()):
            parts.append(f"<div class='asset-bucket'><h3>{_h(type_)} ({len(values)})</h3><ul>")
            for v in values[:50]:
                parts.append(f"<li>{_h(v)}</li>")
            if len(values) > 50:
                parts.append(f"<li class='muted'>… +{len(values) - 50} more</li>")
            parts.append("</ul></div>")

    # Steps
    if data["steps"]:
        parts.append("<h2>Steps</h2>")
        parts.append("<table><thead><tr><th>#</th><th>Tool</th><th>Status</th><th>Attempts</th><th>Error</th></tr></thead><tbody>")
        for s in data["steps"]:
            parts.append("<tr>")
            parts.append(f"<td>{_h(s.index)}</td>")
            parts.append(f"<td class='mono'>{_h(s.tool_id)}</td>")
            parts.append(f"<td>{_h(_status_value(s.status))}</td>")
            parts.append(f"<td>{_h(s.attempt + 1)}/{_h(s.max_retries + 1)}</td>")
            parts.append(f"<td class='mono'>{_h(s.error or '')}</td>")
            parts.append("</tr>")
        parts.append("</tbody></table>")

    # Artifacts
    if data["artifacts"]:
        parts.append("<h2>Artifacts</h2>")
        parts.append("<table><thead><tr><th>Name</th><th>Type</th><th>Size</th><th>SHA-256</th></tr></thead><tbody>")
        for a in data["artifacts"]:
            size_kb = (a.size_bytes or 0) / 1024
            sha = (a.sha256 or "")[:12]
            parts.append("<tr>")
            parts.append(f"<td class='mono'>{_h(a.name)}</td>")
            parts.append(f"<td>{_h(a.type)}</td>")
            parts.append(f"<td>{size_kb:.1f} KB</td>")
            parts.append(f"<td class='mono'>{_h(sha)}…</td>")
            parts.append("</tr>")
        parts.append("</tbody></table>")

    parts.append("<footer>ReconForge run report · self-contained · safe to forward</footer>")
    parts.append("</div></body></html>")
    return "".join(parts).encode("utf-8")


# ---------- Target-level aggregation ----------------------------------------

def _collect_target(session: Session, target: Target) -> dict[str, Any]:
    """Aggregate every run against a target into the same shape `_collect`
    returns for a single run. Findings + loot + assets are unioned across
    runs and deduplicated by id; counts roll up so the report header tells
    the story of the whole engagement against this target."""
    runs = list(session.exec(
        select(Run).where(Run.target_id == target.id).order_by(Run.created_at.desc())
    ).all())
    run_ids = [r.id for r in runs]
    findings: list[Finding] = []
    loot: list[LootItem] = []
    assets: list[Asset] = []
    artifacts: list[Artifact] = []
    if run_ids:
        findings = list(session.exec(
            select(Finding).where(Finding.run_id.in_(run_ids))  # type: ignore[attr-defined]
        ).all())
        loot = list(session.exec(
            select(LootItem).where(LootItem.run_id.in_(run_ids))  # type: ignore[attr-defined]
        ).all())
        assets = list(session.exec(
            select(Asset).where(Asset.run_id.in_(run_ids))  # type: ignore[attr-defined]
        ).all())
        artifacts = list(session.exec(
            select(Artifact).where(Artifact.run_id.in_(run_ids))  # type: ignore[attr-defined]
        ).all())

    findings.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 9), f.created_at or now_utc_sortable()))
    loot.sort(key=lambda i: (SEVERITY_RANK.get(i.severity, 9), i.created_at))

    findings_by_severity = {sev: 0 for sev in ("critical", "high", "medium", "low", "info")}
    for f in findings:
        if f.severity in findings_by_severity:
            findings_by_severity[f.severity] += 1
    loot_by_kind: dict[str, int] = {}
    for it in loot:
        loot_by_kind[it.kind] = loot_by_kind.get(it.kind, 0) + 1

    # Deduplicate assets by (type, value) — the same domain showing up in
    # five runs becomes one row in the engagement-level report.
    seen_asset: set[tuple[str, str]] = set()
    assets_by_type: dict[str, list[str]] = {}
    for a in assets:
        key = (a.type, a.value)
        if key in seen_asset:
            continue
        seen_asset.add(key)
        assets_by_type.setdefault(a.type, []).append(a.value)

    runs_by_status: dict[str, int] = {}
    for r in runs:
        s = _status_value(r.status)
        runs_by_status[s] = runs_by_status.get(s, 0) + 1

    return {
        "target": target,
        "runs": runs,
        "runs_by_status": runs_by_status,
        "findings": findings,
        "findings_by_severity": findings_by_severity,
        "assets": assets,
        "assets_by_type": assets_by_type,
        "artifacts": artifacts,
        "loot": loot,
        "loot_by_kind": loot_by_kind,
        "generated_at": datetime.now(timezone.utc),
    }


def render_target_json(session: Session, target: Target) -> bytes:
    data = _collect_target(session, target)
    document = {
        "schema": "reconforge.target.report/v1",
        "generated_at": data["generated_at"].isoformat(),
        "target": {
            "id": target.id, "value": target.value, "type": target.type,
            "workspace_id": target.workspace_id, "in_scope": target.in_scope,
            "passive_allowed": target.passive_allowed,
            "active_allowed": target.active_allowed,
            "notes": target.notes,
        },
        "counts": {
            "runs": len(data["runs"]),
            "findings": len(data["findings"]),
            "loot": len(data["loot"]),
            "assets_unique": sum(len(v) for v in data["assets_by_type"].values()),
        },
        "runs_by_status": data["runs_by_status"],
        "findings_by_severity": data["findings_by_severity"],
        "loot_by_kind": data["loot_by_kind"],
        "runs": [
            {"id": r.id, "profile_id": r.profile_id, "status": _status_value(r.status),
             "risk": _status_value(r.risk), "created_at": _fmt_dt(r.created_at),
             "started_at": _fmt_dt(r.started_at), "finished_at": _fmt_dt(r.finished_at)}
            for r in data["runs"]
        ],
        "findings": [
            {"id": f.id, "title": f.title, "severity": f.severity,
             "confidence": f.confidence, "category": f.category, "status": f.status,
             "tool_source": f.tool_source, "evidence": f.evidence or "",
             "run_id": f.run_id, "meta": f.meta or {},
             "created_at": _fmt_dt(f.created_at)}
            for f in data["findings"]
        ],
        "loot": [
            {"id": it.id, "kind": it.kind, "label": it.label, "severity": it.severity,
             "value_preview": it.value_preview, "source_tool": it.source_tool,
             "host": it.host, "finding_id": it.finding_id, "run_id": it.run_id,
             "meta": it.meta or {}, "created_at": _fmt_dt(it.created_at)}
            for it in data["loot"]
        ],
        "assets_by_type": data["assets_by_type"],
    }
    return json.dumps(document, indent=2, default=str).encode("utf-8")


def render_target_markdown(session: Session, target: Target) -> bytes:
    data = _collect_target(session, target)
    lines: list[str] = []
    lines.append(f"# Engagement report — {target.value}")
    lines.append("")
    lines.append(f"_Generated {data['generated_at'].isoformat()} · ReconForge_")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **Target**: `{target.value}` ({target.type})")
    lines.append(f"- **Workspace**: `{target.workspace_id}`")
    lines.append(f"- **Scope / authorization**: in_scope={target.in_scope}, active_allowed={target.active_allowed}")
    lines.append(f"- **Runs**: {len(data['runs'])} total")
    if data["runs_by_status"]:
        lines.append("  - by status: " + " · ".join(f"{k}: **{v}**" for k, v in sorted(data["runs_by_status"].items())))
    lines.append(f"- **Findings**: {len(data['findings'])} total")
    fbs = data["findings_by_severity"]
    if any(fbs.values()):
        lines.append("  - by severity: " + " · ".join(f"{k}: **{v}**" for k, v in fbs.items() if v))
    lines.append(f"- **Loot**: {len(data['loot'])} items")
    if data["loot_by_kind"]:
        lines.append("  - by kind: " + " · ".join(f"{k}: **{v}**" for k, v in data["loot_by_kind"].items()))
    unique_assets = sum(len(v) for v in data["assets_by_type"].values())
    lines.append(f"- **Unique assets**: {unique_assets}")
    lines.append("")

    if data["loot"]:
        lines.append("## Loot — curated high-signal across the engagement")
        lines.append("")
        lines.append("| Severity | Kind | Label | Host | Tool | Run |")
        lines.append("|---|---|---|---|---|---|")
        for it in data["loot"]:
            label = (it.label or "").replace("|", "\\|")
            host = (it.host or "").replace("|", "\\|")
            tool = (it.source_tool or "").replace("|", "\\|")
            rid = (it.run_id or "")[:14]
            lines.append(f"| {it.severity} | {it.kind} | {label} | {host} | {tool} | `{rid}…` |")
        lines.append("")

    if data["findings"]:
        lines.append("## Findings")
        lines.append("")
        for f in data["findings"]:
            lines.append(f"### [{f.severity.upper()}] {f.title}")
            lines.append("")
            lines.append(f"- **ID**: `{f.id}`  ·  **Run**: `{(f.run_id or '')[:14]}…`")
            lines.append(f"- **Category**: {f.category}  ·  **Status**: {f.status}  ·  **Tool**: {f.tool_source or '—'}")
            if f.evidence:
                lines.append("")
                lines.append("```")
                lines.append(f.evidence)
                lines.append("```")
            lines.append("")

    if data["assets_by_type"]:
        lines.append("## Assets discovered (deduplicated across runs)")
        lines.append("")
        for type_, values in sorted(data["assets_by_type"].items()):
            lines.append(f"### {type_} ({len(values)})")
            lines.append("")
            for v in values[:100]:
                lines.append(f"- `{v}`")
            if len(values) > 100:
                lines.append(f"- … +{len(values) - 100} more")
            lines.append("")

    if data["runs"]:
        lines.append("## Run history")
        lines.append("")
        lines.append("| Profile | Status | Risk | When |")
        lines.append("|---|---|---|---|")
        for r in data["runs"]:
            lines.append(f"| `{r.profile_id}` | {_status_value(r.status)} | {_status_value(r.risk)} | {_fmt_dt(r.created_at)} |")
        lines.append("")

    return ("\n".join(lines) + "\n").encode("utf-8")


def render_target_html(session: Session, target: Target) -> bytes:
    data = _collect_target(session, target)
    parts: list[str] = []
    parts.append("<!doctype html><html lang='en'><head><meta charset='utf-8'>")
    parts.append(f"<title>ReconForge engagement report — {_h(target.value)}</title>")
    parts.append(f"<style>{_HTML_STYLE}</style></head><body><div class='page'>")
    parts.append(f"<header><h1>Engagement report — {_h(target.value)}</h1>")
    parts.append(f"<div class='muted'>Generated {_h(data['generated_at'].isoformat())} · ReconForge</div></header>")

    parts.append("<h2>Summary</h2><div class='kv-grid'>")
    parts.append(f"<div class='k'>Target</div><div class='mono'>{_h(target.value)} ({_h(target.type)})</div>")
    parts.append(f"<div class='k'>Workspace</div><div class='mono'>{_h(target.workspace_id)}</div>")
    parts.append(f"<div class='k'>In scope</div><div>{_h(target.in_scope)}</div>")
    parts.append(f"<div class='k'>Active allowed</div><div>{_h(target.active_allowed)}</div>")
    if target.notes:
        parts.append(f"<div class='k'>Notes</div><div>{_h(target.notes)}</div>")
    parts.append("</div>")

    parts.append("<div class='summary-bar'>")
    for sev, n in data["findings_by_severity"].items():
        if n:
            parts.append(_sev_chip(sev, n))
    parts.append(f"<span class='chip'>{len(data['runs'])} runs</span>")
    parts.append(f"<span class='chip'>{len(data['findings'])} findings</span>")
    parts.append(f"<span class='chip'>{len(data['loot'])} loot</span>")
    unique_assets = sum(len(v) for v in data["assets_by_type"].values())
    parts.append(f"<span class='chip'>{unique_assets} unique assets</span>")
    parts.append("</div>")

    if data["loot"]:
        parts.append("<h2>Loot — curated high-signal across the engagement</h2>")
        parts.append("<table><thead><tr><th>Severity</th><th>Kind</th><th>Label</th><th>Host</th><th>Tool</th><th>Run</th></tr></thead><tbody>")
        for it in data["loot"]:
            parts.append("<tr>")
            parts.append(f"<td>{_sev_chip(it.severity)}</td>")
            parts.append(f"<td>{_h(it.kind)}</td>")
            parts.append(f"<td>{_h(it.label)}</td>")
            parts.append(f"<td class='mono'>{_h(it.host or '—')}</td>")
            parts.append(f"<td class='mono'>{_h(it.source_tool or '—')}</td>")
            parts.append(f"<td class='mono'>{_h((it.run_id or '')[:14])}…</td>")
            parts.append("</tr>")
        parts.append("</tbody></table>")

    if data["findings"]:
        parts.append("<h2>Findings</h2>")
        for f in data["findings"]:
            parts.append(f"<div class='finding sev-{_h(f.severity)}'>")
            parts.append(f"<h3>{_sev_chip(f.severity)} {_h(f.title)}</h3>")
            parts.append(
                f"<div class='muted'>id: <span class='mono'>{_h(f.id)}</span> · run: "
                f"<span class='mono'>{_h((f.run_id or '')[:14])}…</span> · category: {_h(f.category)} · "
                f"status: {_h(f.status)} · tool: {_h(f.tool_source or '—')}</div>"
            )
            if f.evidence:
                parts.append(f"<pre>{_h(f.evidence)}</pre>")
            parts.append("</div>")

    if data["assets_by_type"]:
        parts.append("<h2>Assets discovered (deduplicated across runs)</h2>")
        for type_, values in sorted(data["assets_by_type"].items()):
            parts.append(f"<div class='asset-bucket'><h3>{_h(type_)} ({len(values)})</h3><ul>")
            for v in values[:100]:
                parts.append(f"<li>{_h(v)}</li>")
            if len(values) > 100:
                parts.append(f"<li class='muted'>… +{len(values) - 100} more</li>")
            parts.append("</ul></div>")

    if data["runs"]:
        parts.append("<h2>Run history</h2>")
        parts.append("<table><thead><tr><th>Profile</th><th>Status</th><th>Risk</th><th>When</th></tr></thead><tbody>")
        for r in data["runs"]:
            parts.append("<tr>")
            parts.append(f"<td class='mono'>{_h(r.profile_id)}</td>")
            parts.append(f"<td>{_h(_status_value(r.status))}</td>")
            parts.append(f"<td>{_h(_status_value(r.risk))}</td>")
            parts.append(f"<td>{_h(_fmt_dt(r.created_at))}</td>")
            parts.append("</tr>")
        parts.append("</tbody></table>")

    parts.append("<footer>ReconForge engagement report · self-contained · safe to forward</footer>")
    parts.append("</div></body></html>")
    return "".join(parts).encode("utf-8")


# ---------- Public selector --------------------------------------------------

def render(session: Session, run: Run, format_: str) -> tuple[bytes, str]:
    """Render a run report. Returns (body, content_type)."""
    fmt = (format_ or "html").lower()
    if fmt == "html":
        return render_html(session, run), "text/html; charset=utf-8"
    if fmt == "json":
        return render_json(session, run), "application/json"
    if fmt in {"md", "markdown"}:
        return render_markdown(session, run), "text/markdown; charset=utf-8"
    raise ValueError(f"unknown report format: {format_}")


def render_target(session: Session, target: Target, format_: str) -> tuple[bytes, str]:
    """Render an engagement-level report aggregating every run against the
    target. Returns (body, content_type)."""
    fmt = (format_ or "html").lower()
    if fmt == "html":
        return render_target_html(session, target), "text/html; charset=utf-8"
    if fmt == "json":
        return render_target_json(session, target), "application/json"
    if fmt in {"md", "markdown"}:
        return render_target_markdown(session, target), "text/markdown; charset=utf-8"
    raise ValueError(f"unknown report format: {format_}")
