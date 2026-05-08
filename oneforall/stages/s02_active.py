"""Stage 2 — Active DNS recon.

Tools (all optional; missing -> warn + skip):
  subfinder -all -recursive -d <d>
  assetfinder <d>
  chaos-client -d <d>            (needs CHAOS_CLIENT_KEY)
  amass enum -passive -d <d>
  nextnet                        (CIDR-walking, optional)

Followed by a httpx-based liveness probe to mark live hosts.
"""
from __future__ import annotations

import concurrent.futures as cf
import logging
import os
import socket

import httpx

from oneforall.tools import anew, have, read_lines, run
from oneforall.workspace import Workspace

logger = logging.getLogger(__name__)

STAGE_ID = "s02_active"
LIVE_TIMEOUT = 5.0


def _resolve(host: str) -> list[str]:
    try:
        return list({a[4][0] for a in socket.getaddrinfo(host, None)})
    except Exception:
        return []


def _is_live(host: str) -> tuple[str, bool, int | None]:
    for scheme in ("https", "http"):
        try:
            r = httpx.get(f"{scheme}://{host}", timeout=LIVE_TIMEOUT,
                          follow_redirects=True, verify=False)
            return host, True, r.status_code
        except Exception:
            continue
    return host, False, None


def run(ws: Workspace, authorized: bool = False) -> None:
    raw = ws.raw_dir(STAGE_ID)
    log = ws.log_path(STAGE_ID)
    domain = ws.target

    subs_file = raw / "subs.txt"

    # Seed with whatever s01 already collected so anew()'s dedup is meaningful.
    seeded = [s["name"] for s in ws.read_findings()["subdomains"]]
    if seeded:
        anew(seeded, subs_file)

    cmds: list[tuple[str, str]] = []
    if have("subfinder"):
        cmds.append(("subfinder", f"subfinder -all -recursive -silent -d {domain}"))
    if have("assetfinder"):
        cmds.append(("assetfinder", f"assetfinder --subs-only {domain}"))
    if have("chaos-client"):
        if os.getenv("CHAOS_CLIENT_KEY"):
            cmds.append(("chaos-client", f"chaos-client -d {domain} -silent"))
        else:
            logger.warning("CHAOS_CLIENT_KEY not set; skipping chaos-client")
    if have("amass"):
        cmds.append(("amass", f"amass enum -passive -d {domain} -silent"))
    if have("nextnet"):
        # nextnet expects a CIDR; resolve apex and feed the /24 it lands in.
        ips = _resolve(domain)
        if ips:
            cidr = ".".join(ips[0].split(".")[:3]) + ".0/24"
            cmds.append(("nextnet", f"nextnet -targets {cidr}"))

    for name, cmd in cmds:
        _rc, out = run(cmd, log_file=log, timeout=600)
        (raw / f"{name}.txt").write_text(out)
        candidates: list[str] = []
        for raw_line in out.splitlines():
            host = raw_line.strip().lower()
            if host and (host == domain or host.endswith(f".{domain}")):
                candidates.append(host)
                ws.merge_subdomain(host, source=name)
        added = anew(candidates, subs_file)
        with log.open("a") as f:
            f.write(f"[{name}] +{added} new\n")

    # Liveness probe
    all_subs = read_lines(subs_file)
    logger.info("[%s] probing %d hosts for liveness", STAGE_ID, len(all_subs))
    live_count = 0
    with cf.ThreadPoolExecutor(max_workers=30) as ex:
        for host, live, code in ex.map(_is_live, all_subs):
            ws.merge_subdomain(host, source="httpx", live=live, status_code=code)
            if live:
                live_count += 1
    anew([s["name"] for s in ws.read_findings()["subdomains"] if s.get("live")],
         raw / "live.txt")
    logger.info("[%s] %d live / %d total", STAGE_ID, live_count, len(all_subs))
