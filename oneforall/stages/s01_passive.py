"""Stage 1 — Passive DNS recon.

Sources: crt.sh (no key), Shodan, Censys, FOFA, BeVigil, ipinfo.
Each source is gated on its env var. Missing keys -> warn + skip.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import re

import httpx

from oneforall.tools import anew
from oneforall.workspace import Workspace

logger = logging.getLogger(__name__)

STAGE_ID = "s01_passive"
TIMEOUT = 30.0


def _crtsh(domain: str) -> tuple[set[str], dict]:
    """crt.sh — no API key required."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = httpx.get(url, timeout=TIMEOUT, follow_redirects=True)
        if r.status_code != 200:
            return set(), {"error": f"http {r.status_code}"}
        rows = r.json()
    except Exception as e:
        logger.warning("crt.sh failed: %s", e)
        return set(), {"error": str(e)}
    subs = set()
    for row in rows:
        for name in re.split(r"\s+|\n", row.get("name_value", "")):
            name = name.strip().lstrip("*.").lower()
            if name and (name == domain or name.endswith(f".{domain}")):
                subs.add(name)
    return subs, {"count": len(subs)}


def _shodan(domain: str, key: str) -> tuple[set[str], dict]:
    url = f"https://api.shodan.io/dns/domain/{domain}?key={key}"
    try:
        r = httpx.get(url, timeout=TIMEOUT)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        logger.warning("shodan failed: %s", e)
        return set(), {"error": str(e)}
    subs = {f"{sub}.{domain}".lower() for sub in data.get("subdomains", [])}
    return subs, data


def _censys(domain: str, api_id: str, api_secret: str) -> tuple[set[str], dict]:
    auth = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
    url = "https://search.censys.io/api/v2/certificates/search"
    params = {"q": f"names: {domain}", "per_page": 100}
    try:
        r = httpx.get(url, headers={"Authorization": f"Basic {auth}"},
                      params=params, timeout=TIMEOUT)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        logger.warning("censys failed: %s", e)
        return set(), {"error": str(e)}
    subs: set[str] = set()
    for hit in data.get("result", {}).get("hits", []):
        for name in hit.get("names", []):
            name = name.lstrip("*.").lower()
            if name == domain or name.endswith(f".{domain}"):
                subs.add(name)
    return subs, {"count": len(subs)}


def _fofa(domain: str, email: str, key: str) -> tuple[set[str], dict]:
    qbase64 = base64.b64encode(f'domain="{domain}"'.encode()).decode()
    url = "https://fofa.info/api/v1/search/all"
    params = {"email": email, "key": key, "qbase64": qbase64, "size": 1000, "fields": "host"}
    try:
        r = httpx.get(url, params=params, timeout=TIMEOUT)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        logger.warning("fofa failed: %s", e)
        return set(), {"error": str(e)}
    subs: set[str] = set()
    for row in data.get("results", []):
        host = row[0] if isinstance(row, list) else row
        host = re.sub(r"^https?://", "", str(host)).split("/")[0].split(":")[0].lower()
        if host == domain or host.endswith(f".{domain}"):
            subs.add(host)
    return subs, {"count": len(subs)}


def _bevigil(domain: str, key: str) -> tuple[set[str], dict]:
    url = f"https://osint.bevigil.com/api/{domain}/subdomains/"
    try:
        r = httpx.get(url, headers={"X-Access-Token": key}, timeout=TIMEOUT)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        logger.warning("bevigil failed: %s", e)
        return set(), {"error": str(e)}
    subs = {s.lower() for s in data.get("subdomains", [])}
    return subs, {"count": len(subs)}


def _ipinfo(domain: str, token: str) -> tuple[set[str], dict]:
    """ipinfo gives IP/ASN context for the apex; we resolve via Google DNS first."""
    try:
        r = httpx.get(f"https://dns.google/resolve?name={domain}&type=A", timeout=TIMEOUT)
        ips = [a["data"] for a in r.json().get("Answer", []) if a.get("type") == 1]
    except Exception as e:
        return set(), {"error": str(e)}
    out = {}
    for ip in ips:
        try:
            r = httpx.get(f"https://ipinfo.io/{ip}", params={"token": token}, timeout=TIMEOUT)
            out[ip] = r.json()
        except Exception as e:
            out[ip] = {"error": str(e)}
    return set(), {"ips": out}


def run(ws: Workspace, authorized: bool = False) -> None:
    raw = ws.raw_dir(STAGE_ID)
    log = ws.log_path(STAGE_ID)
    domain = ws.target

    sources: dict[str, tuple[set[str], dict]] = {}

    # crt.sh — always
    sources["crtsh"] = _crtsh(domain)

    if key := os.getenv("SHODAN_API_KEY"):
        sources["shodan"] = _shodan(domain, key)
    if (cid := os.getenv("CENSYS_API_ID")) and (cs := os.getenv("CENSYS_API_SECRET")):
        sources["censys"] = _censys(domain, cid, cs)
    if (em := os.getenv("FOFA_EMAIL")) and (fk := os.getenv("FOFA_KEY")):
        sources["fofa"] = _fofa(domain, em, fk)
    if bk := os.getenv("BEVIGIL_API_KEY"):
        sources["bevigil"] = _bevigil(domain, bk)
    if it := os.getenv("IPINFO_TOKEN"):
        sources["ipinfo"] = _ipinfo(domain, it)

    all_subs: set[str] = set()
    for name, (subs, payload) in sources.items():
        (raw / f"{name}.json").write_text(json.dumps({"subs": sorted(subs), "payload": payload}, indent=2))
        for s in subs:
            ws.merge_subdomain(s, source=name)
            all_subs.add(s)
        with log.open("a") as f:
            f.write(f"[{name}] +{len(subs)} subdomains\n")

    anew(sorted(all_subs), raw / "all_subs.txt")
    logger.info("[%s] %d unique subdomains from %d sources", STAGE_ID, len(all_subs), len(sources))
