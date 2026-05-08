"""Stage 8 — URL sorting.

Group URLs by likely vuln class so stage 9 can run targeted scanners.
Uses gf if available; otherwise pure-Python heuristics.
"""
from __future__ import annotations

import logging
import re
from urllib.parse import urlparse, parse_qs

from oneforall.tools import anew, have, run as shell_run  # noqa: F401  (anew kept for future use)
from oneforall.workspace import Workspace

logger = logging.getLogger(__name__)

STAGE_ID = "s08_urlsort"

CLASS_PATTERNS = {
    "xss":     [r"q", r"search", r"name", r"keyword", r"query", r"s", r"input", r"text"],
    "ssrf":    [r"url", r"uri", r"link", r"src", r"dest", r"redirect", r"callback", r"feed", r"u", r"path", r"continue"],
    "ssti":    [r"template", r"page", r"view", r"layout"],
    "rce":     [r"cmd", r"exec", r"command", r"system", r"run"],
    "sqli":    [r"id", r"user", r"username", r"email", r"order", r"sort"],
    "lfi":     [r"file", r"path", r"page", r"include", r"doc", r"folder"],
    "redirect":[r"redirect", r"url", r"next", r"return", r"returnurl", r"continue", r"to"],
    "idor":    [r"id", r"user_id", r"account", r"order_id", r"uid", r"profile"],
}


def _classify(url: str) -> list[str]:
    classes = []
    try:
        params = list(parse_qs(urlparse(url).query).keys())
    except Exception:
        return []
    plower = [p.lower() for p in params]
    for klass, names in CLASS_PATTERNS.items():
        if any(p in plower for p in names):
            classes.append(klass)
    return classes


def run(ws: Workspace, authorized: bool = False) -> None:
    raw = ws.raw_dir(STAGE_ID)
    log = ws.log_path(STAGE_ID)

    findings = ws.read_findings()
    urls = sorted({u["url"] for u in findings["urls"]})
    all_file = raw / "all_urls.txt"
    all_file.write_text("\n".join(urls) + "\n")

    # Try gf for each class if available
    gf_buckets: dict[str, list[str]] = {}
    if have("gf"):
        for klass in CLASS_PATTERNS:
            _rc, out = shell_run(f"cat {all_file} | gf {klass}", log_file=log, timeout=120)
            buckets = [line.strip() for line in out.splitlines() if line.strip()]
            if buckets:
                gf_buckets[klass] = buckets

    # uro for dedup-by-shape
    if have("uro"):
        _rc, out = shell_run(f"cat {all_file} | uro", log_file=log, timeout=300)
        (raw / "uro.txt").write_text(out)

    # Always run our heuristic on top of gf so we don't miss anything
    heur_buckets: dict[str, list[str]] = {k: [] for k in CLASS_PATTERNS}
    for u in urls:
        for k in _classify(u):
            heur_buckets[k].append(u)

    for klass in CLASS_PATTERNS:
        merged = sorted(set(heur_buckets.get(klass, []) + gf_buckets.get(klass, [])))
        if merged:
            (raw / f"{klass}.txt").write_text("\n".join(merged) + "\n")

    logger.info("[%s] sorted %d urls into %d classes", STAGE_ID, len(urls),
                sum(1 for k in CLASS_PATTERNS if (raw / f"{k}.txt").exists()))
