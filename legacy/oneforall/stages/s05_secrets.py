"""Stage 5 — Secrets & sensitive-file discovery.

Tools: cariddi, gf with json/secret patterns, jsubfinder.
Local regex pass on .js files as a fallback when none of those are installed.
"""
from __future__ import annotations

import json
import logging
import re

import httpx

from oneforall.tools import have, read_lines, run
from oneforall.workspace import Workspace

logger = logging.getLogger(__name__)

STAGE_ID = "s05_secrets"

# A small built-in secret regex set used when gf isn't available.
LOCAL_PATTERNS = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret_key": re.compile(r"(?i)aws(.{0,20})?(secret|sk)[\"' :=]+([A-Za-z0-9/+=]{40})"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "slack_token": re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    "stripe_key": re.compile(r"sk_(live|test)_[0-9a-zA-Z]{24,}"),
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
    "private_key": re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH|PRIVATE) KEY-----"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
}


def _scan_local(js_urls: list[str], ws: Workspace) -> int:
    found = 0
    for url in js_urls[:200]:  # cap
        try:
            r = httpx.get(url, timeout=10.0, follow_redirects=True, verify=False)
            if r.status_code != 200:
                continue
            body = r.text
        except Exception:
            continue
        for name, rx in LOCAL_PATTERNS.items():
            for m in rx.finditer(body):
                match = m.group(0)
                ws.append_secret(file=url, type_=name, match=match[:80], confidence="medium")
                found += 1
    return found


def run(ws: Workspace, authorized: bool = False) -> None:
    raw = ws.raw_dir(STAGE_ID)
    log = ws.log_path(STAGE_ID)
    findings = ws.read_findings()

    urls = [u["url"] for u in findings["urls"]]
    js_urls = [u for u in urls if u.endswith(".js") or ".js?" in u]

    urls_file = raw / "urls.txt"
    urls_file.write_text("\n".join(urls) + "\n")
    js_file = raw / "js.txt"
    js_file.write_text("\n".join(js_urls) + "\n")

    if have("cariddi") and urls:
        rc, out = run(f"cat {urls_file} | cariddi -s -info -err -plain",
                      log_file=log, timeout=1800)
        (raw / "cariddi.txt").write_text(out)
        # cariddi's output flags secrets/info; treat each non-empty line as a hit
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("[Secret]") or line.startswith("[Info]"):
                ws.append_secret(file="(cariddi)", type_="cariddi", match=line[:200])

    if have("gf") and urls:
        for pat in ("json-sec", "secrets", "aws-keys"):
            rc, out = run(f"cat {urls_file} | gf {pat}", log_file=log, timeout=300)
            tag = (raw / f"gf_{pat}.txt")
            tag.write_text(out)
            for line in out.splitlines():
                if line.strip():
                    ws.append_secret(file=line.strip(), type_=f"gf:{pat}", match=line.strip()[:200], confidence="low")

    if have("jsubfinder") and js_urls:
        rc, out = run(f"jsubfinder -f {js_file} -s",
                      log_file=log, timeout=1800)
        (raw / "jsubfinder.txt").write_text(out)
        for line in out.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                ws.append_secret(file="(jsubfinder)", type_="jsubfinder", match=line[:200])

    # Local fallback: if nothing above ran AND we have .js URLs, do regex scan.
    if not (have("cariddi") or have("gf") or have("jsubfinder")) and js_urls:
        n = _scan_local(js_urls, ws)
        logger.info("[%s] local regex scan: %d hits", STAGE_ID, n)

    logger.info("[%s] %d secrets total", STAGE_ID, len(ws.read_findings()["secrets"]))
