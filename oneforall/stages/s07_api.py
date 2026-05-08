"""Stage 7 — API testing (GATED).

Active probe: requires --i-have-authorization AND a populated scope.yaml.

What it does:
  - Look for OpenAPI/Swagger docs at common paths
  - Replay each discovered API URL with httpx and record status / shape
  - Simple unauth-vs-Authorized comparison: GET with and without a fake bearer
  - Method-confusion check: try OPTIONS, HEAD, PUT on read endpoints
"""
from __future__ import annotations

import json
import logging
from urllib.parse import urlparse

import httpx

from oneforall.auth import require_authorization
from oneforall.workspace import Workspace

logger = logging.getLogger(__name__)

STAGE_ID = "s07_api"

SWAGGER_PATHS = [
    "/openapi.json", "/swagger.json", "/swagger/v1/swagger.json",
    "/api-docs", "/api/swagger.json", "/v2/api-docs", "/docs",
    "/swagger-ui.html", "/swagger-ui/", "/api/swagger-ui",
]


def _in_scope(host: str, scope_in: list[str]) -> bool:
    for entry in scope_in:
        e = entry.lstrip("*.")
        if host == e or host.endswith("." + e):
            return True
    return False


def _swagger_probe(client: httpx.Client, host: str) -> list[dict]:
    """Probe each SWAGGER_PATHS entry. Try https first, fall back to http per host."""
    if host.startswith(("http://", "https://")):
        bases = [host.rstrip("/")]
    else:
        bases = [f"https://{host}", f"http://{host}"]
    hits: list[dict] = []
    for base in bases:
        any_succeeded = False
        for path in SWAGGER_PATHS:
            url = f"{base}{path}"
            try:
                r = client.get(url, timeout=10.0, follow_redirects=True)
                any_succeeded = True
                if r.status_code == 200 and ("openapi" in r.text.lower() or "swagger" in r.text.lower()):
                    hits.append({"url": url, "status": r.status_code, "len": len(r.text)})
            except Exception:
                pass
        # If https worked at all (any response), don't also waste requests on http.
        if any_succeeded:
            break
    return hits


def _replay(client: httpx.Client, url: str) -> dict:
    out = {"url": url}
    try:
        r = client.get(url, timeout=10.0, follow_redirects=False)
        out["GET"] = {"status": r.status_code, "len": len(r.content),
                      "ct": r.headers.get("content-type", "")}
    except Exception as e:
        out["GET"] = {"error": str(e)}
    # Method confusion
    for method in ("OPTIONS", "HEAD", "PUT"):
        try:
            r = client.request(method, url, timeout=10.0)
            out[method] = {"status": r.status_code}
        except Exception:
            pass
    # Bogus auth — flag if it succeeds where unauth failed
    try:
        r = client.get(url, timeout=10.0,
                       headers={"Authorization": "Bearer faketoken123"})
        out["FAKE_BEARER"] = {"status": r.status_code}
    except Exception:
        pass
    return out


def run(ws: Workspace, authorized: bool = False) -> None:
    require_authorization(ws, authorized, STAGE_ID)
    scope = ws.load_scope()
    raw = ws.raw_dir(STAGE_ID)
    log = ws.log_path(STAGE_ID)

    findings = ws.read_findings()
    urls = [u["url"] for u in findings["urls"]]
    api_urls = [u for u in urls
                if any(seg in u for seg in ("/api/", "/v1/", "/v2/", "/graphql", "/rest/"))]

    in_scope_urls = [u for u in api_urls
                     if _in_scope(urlparse(u).netloc.split(":")[0], scope.get("in", []))]
    skipped = len(api_urls) - len(in_scope_urls)
    if skipped:
        logger.warning("[%s] %d API URLs skipped (out of scope)", STAGE_ID, skipped)

    findings_out: list[dict] = []
    with httpx.Client(verify=False) as client:
        # Swagger probe per live host (in scope)
        live_hosts = [s["name"] for s in findings["subdomains"]
                      if s.get("live") and _in_scope(s["name"], scope.get("in", []))]
        for host in live_hosts:
            hits = _swagger_probe(client, host)
            for h in hits:
                findings_out.append({"kind": "openapi_doc", **h})
        # Replay per URL
        for u in in_scope_urls[:200]:
            findings_out.append({"kind": "replay", **_replay(client, u)})

    (raw / "api.json").write_text(json.dumps(findings_out, indent=2))
    # Replace, not extend, so reruns are idempotent.
    data = ws.read_findings()
    data["api_findings"] = findings_out
    ws.write_findings(data)

    logger.info("[%s] %d api findings", STAGE_ID, len(findings_out))
