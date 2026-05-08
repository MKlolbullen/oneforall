"""Stage 6 — Content fuzzing & directory brute force.

Tools: feroxbuster (preferred) > ffuf > gobuster, plus hakrawler for spidering.
Reads live hosts from findings.json, picks first available wordlist, runs against each.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

from oneforall.tools import anew, have, read_lines, run
from oneforall.workspace import Workspace

logger = logging.getLogger(__name__)

STAGE_ID = "s06_fuzz"

WORDLIST_CANDIDATES = [
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
]


def _pick_wordlist() -> str | None:
    for p in WORDLIST_CANDIDATES:
        if os.path.exists(p):
            return p
    return None


def run(ws: Workspace, authorized: bool = False) -> None:
    raw = ws.raw_dir(STAGE_ID)
    log = ws.log_path(STAGE_ID)
    findings = ws.read_findings()

    live = [s["name"] for s in findings["subdomains"] if s.get("live")][:20]
    if not live:
        live = [findings["target"]]

    wordlist = _pick_wordlist()
    if not wordlist:
        logger.warning("[%s] no wordlist found; install seclists or pass one. Skipping brute force.",
                       STAGE_ID)
    new_urls_file = raw / "new_urls.txt"

    if wordlist:
        for host in live:
            url = f"https://{host}"
            if have("feroxbuster"):
                out_path = raw / f"ferox_{host}.txt"
                run(f"feroxbuster -u {url} -w {wordlist} -q -o {out_path} -k -t 50",
                    log_file=log, timeout=1800)
                if out_path.exists():
                    anew([l.split()[-1] for l in read_lines(out_path) if l.startswith("2")],
                         new_urls_file)
            elif have("ffuf"):
                out_path = raw / f"ffuf_{host}.json"
                run(f"ffuf -u {url}/FUZZ -w {wordlist} -mc 200,204,301,302,307,401,403 "
                    f"-of json -o {out_path} -t 50", log_file=log, timeout=1800)
            elif have("gobuster"):
                out_path = raw / f"gobuster_{host}.txt"
                run(f"gobuster dir -u {url} -w {wordlist} -q -o {out_path} -k -t 50",
                    log_file=log, timeout=1800)
                if out_path.exists():
                    anew(read_lines(out_path), new_urls_file)

    # hakrawler — pulls links from live hosts
    if have("hakrawler"):
        rc, out = run(f"echo '{','.join('https://' + h for h in live)}' | "
                      f"hakrawler -d 2 -subs",
                      log_file=log, timeout=900)
        (raw / "hakrawler.txt").write_text(out)
        anew(out.splitlines(), new_urls_file)

    # merge new URLs into findings
    for u in read_lines(new_urls_file):
        if u.startswith(("http://", "https://")):
            ws.merge_url(u, source="fuzz")

    logger.info("[%s] urls now %d", STAGE_ID, len(ws.read_findings()["urls"]))
