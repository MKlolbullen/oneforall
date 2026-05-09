"""Stage 3 — Tech stack + port scanning.

naabu (fast SYN sweep) -> nmap -sV on open ports -> whatweb + wappalyzer for tech.
"""
from __future__ import annotations

import json
import logging
import re
import xml.etree.ElementTree as ET

from oneforall.tools import have, read_lines, run
from oneforall.workspace import Workspace

logger = logging.getLogger(__name__)

STAGE_ID = "s03_techscan"


def _parse_naabu(text: str) -> dict[str, list[int]]:
    out: dict[str, list[int]] = {}
    for line in text.splitlines():
        line = line.strip()
        if ":" not in line:
            continue
        host, _, port = line.rpartition(":")
        if port.isdigit():
            out.setdefault(host, []).append(int(port))
    return out


def _parse_nmap_xml(xml_text: str) -> list[dict]:
    rows: list[dict] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return rows
    for host in root.findall("host"):
        addr = host.find("address")
        hostname_el = host.find("hostnames/hostname")
        host_id = (hostname_el.get("name") if hostname_el is not None
                   else (addr.get("addr") if addr is not None else ""))
        for port in host.findall("ports/port"):
            portid = int(port.get("portid"))
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            rows.append({
                "host": host_id,
                "port": portid,
                "service": svc.get("name") if svc is not None else None,
                "product": (svc.get("product") if svc is not None else None),
            })
    return rows


def _parse_whatweb(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        m = re.match(r"^(\S+)\s+\[\d+\s+\S+\]\s+(.*)$", line)
        if not m:
            continue
        url, plugins = m.group(1), m.group(2)
        techs = [t.strip().split("[")[0] for t in plugins.split(",")]
        out[url] = techs
    return out


def run(ws: Workspace, authorized: bool = False) -> None:
    raw = ws.raw_dir(STAGE_ID)
    log = ws.log_path(STAGE_ID)

    findings = ws.read_findings()
    live_hosts = [s["name"] for s in findings["subdomains"] if s.get("live")]
    if not live_hosts:
        live_hosts = [findings["target"]]

    hosts_file = raw / "hosts.txt"
    hosts_file.write_text("\n".join(live_hosts) + "\n")

    # naabu -> open ports per host (fall back to nmap-only if naabu fails or returns nothing)
    open_ports: dict[str, list[int]] = {}
    if have("naabu"):
        rc, out = run(
            f"naabu -list {hosts_file} -top-ports 1000 -silent",
            log_file=log, timeout=1800,
        )
        (raw / "naabu.txt").write_text(out)
        open_ports = _parse_naabu(out)
        if rc != 0 or not open_ports:
            logger.warning("naabu returned rc=%s with %d hosts; falling back to nmap-only",
                           rc, len(open_ports))
            open_ports = {h: [] for h in live_hosts}
    else:
        logger.warning("naabu missing — falling back to nmap top-1000 directly")
        open_ports = {h: [] for h in live_hosts}

    # nmap -sV against the discovered open ports per host
    if have("nmap"):
        for host, ports in open_ports.items():
            xml_path = raw / f"nmap_{host}.xml"
            ports_arg = ",".join(str(p) for p in sorted(set(ports))) if ports else "--top-ports 1000"
            cmd = (f"nmap -sV -Pn -T4 -p {ports_arg} {host} -oX {xml_path}"
                   if ports else f"nmap -sV -Pn -T4 --top-ports 1000 {host} -oX {xml_path}")
            run(cmd, log_file=log, timeout=1800)
            if xml_path.exists():
                for row in _parse_nmap_xml(xml_path.read_text()):
                    ws.merge_port(row["host"], row["port"],
                                  service=row["service"], product=row["product"])
    else:
        for host, ports in open_ports.items():
            for p in ports:
                ws.merge_port(host, p)

    # whatweb covers what we need for tech fingerprinting; the previous wappalyzer
    # block wrote a file that nothing read, so it's been dropped.
    tech_map: dict[str, list[str]] = {}
    if have("whatweb"):
        _rc, out = run(
            f"whatweb -i {hosts_file} --no-errors --color=never",
            log_file=log, timeout=1200,
        )
        (raw / "whatweb.txt").write_text(out)
        tech_map = _parse_whatweb(out)

    for url, techs in tech_map.items():
        host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]
        # attach techs to all known ports for that host
        data = ws.read_findings()
        touched = False
        for p in data["ports"]:
            if p["host"] == host:
                for t in techs:
                    if t and t not in p["tech"]:
                        p["tech"].append(t)
                        touched = True
        if touched:
            ws.write_findings(data)

    logger.info("[%s] %d hosts probed; ports recorded in findings.json",
                STAGE_ID, len(live_hosts))
