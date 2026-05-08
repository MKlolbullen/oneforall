"""Stage 10 — Reporting.

Produces report.md and report.html from findings.json.
"""
from __future__ import annotations

import datetime
import logging
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from oneforall.workspace import Workspace

logger = logging.getLogger(__name__)

STAGE_ID = "s10_report"

TEMPLATE_DIR = Path(__file__).resolve().parents[1] / "templates"


def _markdown(findings: dict, generated_at: str) -> str:
    lines = [f"# OneForAll report — {findings['target']}", "",
             f"_Generated {generated_at}_  ",
             f"Stages completed: {', '.join(findings.get('stages_completed', []))}",
             ""]

    subs = findings.get("subdomains", [])
    live = [s for s in subs if s.get("live")]
    lines += [
        "## Summary",
        f"- Subdomains: **{len(subs)}**",
        f"- Live hosts: **{len(live)}**",
        f"- URLs: **{len(findings.get('urls', []))}**",
        f"- Open ports recorded: **{len(findings.get('ports', []))}**",
        f"- Secrets: **{len(findings.get('secrets', []))}**",
        f"- Vulns: **{len(findings.get('vulns', []))}**",
        "",
    ]

    if findings.get("vulns"):
        lines += ["## Vulnerabilities", "",
                  "| ID | Severity | URL | Tool | Evidence |",
                  "|----|----------|-----|------|----------|"]
        for v in findings["vulns"]:
            lines.append(
                f"| `{v['id']}` | {v['severity']} | {v['url']} | {v.get('tool', '')} | "
                f"{(v.get('evidence') or '')[:120]} |"
            )
        lines.append("")

    if findings.get("secrets"):
        lines += ["## Secrets", "",
                  "| Type | Confidence | File | Match |",
                  "|------|------------|------|-------|"]
        for s in findings["secrets"]:
            lines.append(
                f"| {s['type']} | {s.get('confidence','')} | {s['file']} | `{s['match']}` |"
            )
        lines.append("")

    lines += ["## Subdomains", ""]
    for s in subs:
        flag = "live" if s.get("live") else "dead"
        srcs = ", ".join(s.get("sources", []))
        lines.append(f"- {s['name']} ({flag}) — sources: {srcs}")
    lines.append("")

    if findings.get("ports"):
        lines += ["## Ports / tech", "",
                  "| Host | Port | Service | Tech |",
                  "|------|------|---------|------|"]
        for p in findings["ports"]:
            lines.append(
                f"| {p['host']} | {p['port']} | {p.get('service','')} | "
                f"{', '.join(p.get('tech', []))} |"
            )
        lines.append("")

    return "\n".join(lines)


def run(ws: Workspace, authorized: bool = False) -> None:
    findings = ws.read_findings()
    report_dir = ws.root / "report"
    report_dir.mkdir(parents=True, exist_ok=True)
    generated_at = datetime.datetime.now().isoformat(timespec="seconds")

    # Markdown
    md_path = report_dir / "report.md"
    md_path.write_text(_markdown(findings, generated_at))

    # HTML via Jinja
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml", "j2"]),
    )
    tpl = env.get_template("report.html.j2")
    html = tpl.render(
        target=findings["target"],
        generated_at=generated_at,
        stages_completed=findings.get("stages_completed", []),
        subdomains=findings.get("subdomains", []),
        live_count=sum(1 for s in findings.get("subdomains", []) if s.get("live")),
        urls=findings.get("urls", []),
        ports=findings.get("ports", []),
        secrets=findings.get("secrets", []),
        vulns=findings.get("vulns", []),
        api_findings=findings.get("api_findings", []),
    )
    html_path = report_dir / "report.html"
    html_path.write_text(html)

    logger.info("[%s] wrote %s and %s", STAGE_ID, md_path, html_path)
