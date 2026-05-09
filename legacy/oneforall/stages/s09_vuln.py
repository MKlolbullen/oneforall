"""Stage 9 — Vulnerability scanning (GATED).

Active probes. Requires --i-have-authorization and a populated scope.yaml.

Targets are pulled from stage 8's classified URL files.
  xss bucket  -> dalfox + xsstrike
  all buckets -> nuclei (with severity high,critical by default)
  ssrf/ssti/rce/idor/lfi -> nuclei tag-based scans
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from urllib.parse import urlparse

from oneforall.auth import require_authorization
from oneforall.tools import have, read_lines, run
from oneforall.workspace import Workspace

logger = logging.getLogger(__name__)

STAGE_ID = "s09_vuln"


def _filter_scope(urls: list[str], scope_in: list[str]) -> list[str]:
    out = []
    for u in urls:
        host = urlparse(u).netloc.split(":")[0]
        for entry in scope_in:
            e = entry.lstrip("*.")
            if host == e or host.endswith("." + e):
                out.append(u)
                break
    return out


def _parse_nuclei(json_text: str) -> list[dict]:
    rows = []
    for line in json_text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            j = json.loads(line)
        except Exception:
            continue
        info = j.get("info", {})
        rows.append({
            "id": j.get("template-id") or info.get("name", "nuclei"),
            "url": j.get("matched-at") or j.get("host", ""),
            "severity": info.get("severity", "info"),
            "evidence": (j.get("matcher-name") or info.get("name", ""))[:200],
            "tool": "nuclei",
        })
    return rows


def run(ws: Workspace, authorized: bool = False) -> None:
    require_authorization(ws, authorized, STAGE_ID)
    scope = ws.load_scope() or {"in": []}
    raw_dir = ws.raw_dir(STAGE_ID)
    log = ws.log_path(STAGE_ID)
    sort_raw = ws.raw_dir("s08_urlsort")

    def bucket(klass: str) -> Path:
        return sort_raw / f"{klass}.txt"

    # --- XSS: dalfox + xsstrike on the xss bucket ---
    xss_bucket = bucket("xss")
    if xss_bucket.exists():
        targets = _filter_scope(read_lines(xss_bucket), scope["in"])
        if targets:
            in_path = raw_dir / "xss_in.txt"
            in_path.write_text("\n".join(targets) + "\n")
            if have("dalfox"):
                out_json = raw_dir / "dalfox.json"
                run(f"dalfox file {in_path} --format json -o {out_json} --silence",
                    log_file=log, timeout=3600)
                if out_json.exists():
                    try:
                        for hit in json.loads(out_json.read_text() or "[]"):
                            ws.append_vuln(
                                id_=hit.get("type", "xss"),
                                url=hit.get("data", ""),
                                severity=hit.get("severity", "medium"),
                                evidence=hit.get("message", "")[:200],
                                tool="dalfox",
                            )
                    except Exception as e:
                        logger.warning("dalfox parse failed: %s", e)
            if have("xsstrike"):
                # XSStrike is interactive-ish; we run per-URL with --crawl off
                for url in targets[:30]:
                    rc, out = run(
                        f"xsstrike -u '{url}' --skip --skip-dom --headers 'User-Agent: oneforall'",
                        log_file=log, timeout=600,
                    )
                    if "Vulnerable" in out or "Payload:" in out:
                        ws.append_vuln(id_="xsstrike-hit", url=url, severity="medium",
                                       evidence=out[:200], tool="xsstrike")

    # --- nuclei: severity-based + tag-based runs across whole URL space ---
    if have("nuclei"):
        # Build URL list from all classified buckets (in scope)
        all_urls: set[str] = set()
        for klass in ("xss", "ssrf", "ssti", "rce", "sqli", "lfi", "redirect", "idor"):
            if bucket(klass).exists():
                all_urls.update(read_lines(bucket(klass)))
        targets = _filter_scope(sorted(all_urls), scope["in"])
        if not targets:
            # fall back to every in-scope URL
            findings = ws.read_findings()
            targets = _filter_scope([u["url"] for u in findings["urls"]], scope["in"])

        if targets:
            in_path = raw_dir / "nuclei_in.txt"
            in_path.write_text("\n".join(targets) + "\n")
            out_path = raw_dir / "nuclei.jsonl"
            run(
                f"nuclei -l {in_path} -severity high,critical,medium "
                f"-tags ssrf,ssti,rce,idor,lfi,xss,redirect,sqli,exposure "
                f"-jsonl -o {out_path} -silent",
                log_file=log, timeout=7200,
            )
            if out_path.exists():
                for row in _parse_nuclei(out_path.read_text()):
                    ws.append_vuln(**row)

    logger.info("[%s] %d vulns recorded", STAGE_ID, len(ws.read_findings()["vulns"]))
