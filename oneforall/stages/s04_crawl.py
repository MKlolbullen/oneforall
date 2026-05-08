"""Stage 4 — Crawling & URL gathering.

Tools: urlfinder, katana, photon, x8 (param discovery), arjun (param fuzz).
All optional. Output merged into findings.urls[] with source tracking.
"""
from __future__ import annotations

import json
import logging
import re
from urllib.parse import urlparse, parse_qs

from oneforall.tools import anew, have, read_lines, run as shell_run
from oneforall.workspace import Workspace

logger = logging.getLogger(__name__)

STAGE_ID = "s04_crawl"


def _params(url: str) -> list[str]:
    try:
        return list(parse_qs(urlparse(url).query).keys())
    except Exception:
        return []


def run(ws: Workspace, authorized: bool = False) -> None:
    raw = ws.raw_dir(STAGE_ID)
    log = ws.log_path(STAGE_ID)

    findings = ws.read_findings()
    live = [s["name"] for s in findings["subdomains"] if s.get("live")]
    if not live:
        live = [findings["target"]]

    hosts_file = raw / "hosts.txt"
    hosts_file.write_text("\n".join(live) + "\n")

    urls_file = raw / "urls.txt"

    if have("urlfinder"):
        rc, out = shell_run(f"urlfinder -d {findings['target']} -silent", log_file=log, timeout=900)
        (raw / "urlfinder.txt").write_text(out)
        anew(out.splitlines(), urls_file)

    if have("katana"):
        rc, out = shell_run(
            f"katana -list {hosts_file} -d 3 -jc -jsl -silent -kf all",
            log_file=log, timeout=1800,
        )
        (raw / "katana.txt").write_text(out)
        anew(out.splitlines(), urls_file)

    if have("photon"):
        # photon writes to a directory; use the first live host as seed
        seed = live[0]
        out_dir = raw / "photon"
        shell_run(f"photon -u http://{seed} -o {out_dir} -l 2 -t 10",
            log_file=log, timeout=1800)
        photon_urls = out_dir / "urls.txt"
        if photon_urls.exists():
            anew(read_lines(photon_urls), urls_file)

    # x8 — parameter discovery on each live host root
    if have("x8"):
        for host in live[:25]:  # cap so this doesn't run forever
            rc, out = shell_run(
                f"x8 -u https://{host}/ --output-format url --one-worker-per-host",
                log_file=log, timeout=300,
            )
            (raw / f"x8_{host}.txt").write_text(out)
            anew(out.splitlines(), urls_file)

    # arjun — param fuzz on URLs that don't already have a query
    if have("arjun"):
        targets = [u for u in read_lines(urls_file) if "?" not in u][:50]
        if targets:
            t_path = raw / "arjun_input.txt"
            t_path.write_text("\n".join(targets))
            out_json = raw / "arjun.json"
            shell_run(f"arjun -i {t_path} -oJ {out_json} -t 10",
                log_file=log, timeout=1800)
            if out_json.exists():
                try:
                    data = json.loads(out_json.read_text())
                    for url, info in data.items():
                        params = info.get("params") if isinstance(info, dict) else []
                        ws.merge_url(url, source="arjun", params=params or [])
                except Exception as e:
                    logger.warning("arjun parse failed: %s", e)

    # Final merge: every collected url -> findings.urls[]
    for url in read_lines(urls_file):
        if url.startswith(("http://", "https://")):
            ws.merge_url(url, source="crawl", params=_params(url))

    logger.info("[%s] %d urls in findings.json", STAGE_ID, len(ws.read_findings()["urls"]))
