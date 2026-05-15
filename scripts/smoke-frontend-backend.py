#!/usr/bin/env python3
"""End-to-end smoke check that the SPA's API surfaces all work.

Walks the same code paths the React app does:
  POST /api/auth/login          -> bearer token
  GET  /api/auth/me              -> whoami
  GET  /api/workspaces           -> list
  POST /api/targets              -> create
  GET  /api/tools/profiles       -> list
  POST /api/runs                 -> launch (passive)
  GET  /api/runs/{id}            -> poll until terminal
  GET  /api/workspaces/{id}/graph -> the new endpoint

Prints PASS/FAIL per step. Exits non-zero on first failure.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.request
import urllib.error

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8765"


class Client:
    def __init__(self, base: str) -> None:
        self.base = base
        self.token: str | None = None

    def _req(self, method: str, path: str, body=None, expect=(200, 201)):
        if isinstance(expect, int):
            expect = (expect,)
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                code = r.status
                payload = r.read().decode() or "{}"
        except urllib.error.HTTPError as e:
            code = e.code
            payload = e.read().decode() or "{}"
        ok = code in expect
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError:
            parsed = payload
        return ok, code, parsed

    def login(self, u: str, p: str):
        ok, code, body = self._req("POST", "/api/auth/login",
                                    {"username": u, "password": p})
        if not ok:
            raise RuntimeError(f"login failed: HTTP {code} {body}")
        self.token = body["token"]
        return body


def step(label, fn):
    try:
        result = fn()
        print(f"  PASS  {label}")
        return result
    except Exception as exc:  # noqa: BLE001
        print(f"  FAIL  {label}: {exc}")
        sys.exit(1)


def main() -> None:
    print(f"smoke-check against {BASE}")
    c = Client(BASE)

    step("anon /api/workspaces -> 401", lambda: (
        Client(BASE)._req("GET", "/api/workspaces", expect=401)[0] or _fail("expected 401")
    ))

    me = step("login admin", lambda: c.login("admin", "admin-passw0rd"))
    print(f"        token prefix={me['token_prefix']} role={me['role']}")

    whoami = step("whoami", lambda: _ok(c._req("GET", "/api/auth/me")))
    print(f"        {whoami['username']} ({whoami['role']})")

    ws = step("list workspaces", lambda: _ok(c._req("GET", "/api/workspaces")))
    if not ws:
        raise SystemExit("no workspaces seeded")
    ws_id = ws[0]["id"]
    print(f"        workspace={ws_id}")

    targets = step("list demo targets",
                   lambda: _ok(c._req("GET", f"/api/targets?workspace_id={ws_id}")))
    target = next((t for t in targets if t["passive_allowed"]), targets[0])
    print(f"        using target {target['id']}={target['value']}")

    profiles = step("list profiles", lambda: _ok(c._req("GET", "/api/tools/profiles")))
    passive_ids = [p["id"] for p in profiles if p.get("risk") == "passive"]
    print(f"        {len(profiles)} profiles, passive: {passive_ids[:4]}")

    if not passive_ids:
        raise SystemExit("no passive profile available — can't smoke-test runs")
    profile_id = passive_ids[0]

    run = step(f"launch run on {profile_id}",
               lambda: _ok(c._req("POST", "/api/runs",
                                    {"workspace_id": ws_id,
                                     "target_id": target["id"],
                                     "profile_id": profile_id})))
    rid = run["id"]
    print(f"        run={rid} status={run['status']}")

    def poll():
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            ok, _, body = c._req("GET", f"/api/runs/{rid}")
            if not ok:
                raise RuntimeError(f"poll failed: {body}")
            if body["status"] in {"completed", "failed", "cancelled"}:
                return body
            time.sleep(0.5)
        raise RuntimeError("run did not terminate within 60s")

    final = step("run reaches terminal state", poll)
    print(f"        final status={final['status']}")

    graph = step("workspace graph endpoint",
                 lambda: _ok(c._req("GET", f"/api/workspaces/{ws_id}/graph")))
    nodes = graph["nodes"]; edges = graph["edges"]
    print(f"        nodes={len(nodes)} edges={len(edges)} truncated={graph['truncated']}")
    print(f"        by_kind={graph['stats']['by_kind']}")
    target_node = next((n for n in nodes if n["kind"] == "target"), None)
    if not target_node:
        raise SystemExit("no target node in graph payload")
    print(f"        target_node={target_node['label']} centrality={target_node['centrality']}")

    step("graph 404 for unknown workspace",
         lambda: c._req("GET", "/api/workspaces/ws_nope/graph", expect=404))

    # GraphPayload schema is consumed by apps/web/src/types.ts — keep them in sync.
    required_top  = {"nodes", "edges", "stats", "truncated"}
    required_node = {"id", "kind", "label", "centrality"}
    required_edge = {"source", "target", "kind"}
    step("graph payload matches types.ts shape", lambda: (
        (required_top  - set(graph.keys()))         and _fail("missing top-level keys")
        or (graph["nodes"] and required_node - set(graph["nodes"][0])) and _fail("missing node keys")
        or (graph["edges"] and required_edge - set(graph["edges"][0])) and _fail("missing edge keys")
        or "OK"
    ))

    # Browser will hit the API cross-origin from VITE_API_BASE_URL; verify CORS.
    step("CORS preflight allows http://localhost:5173", lambda:
         _cors_preflight(BASE, "http://localhost:5173", expect_allow=True))
    step("CORS rejects untrusted origin", lambda:
         _cors_preflight(BASE, "http://evil.example", expect_allow=False))

    print()
    print("ALL GREEN — frontend ↔ backend contract is intact.")


def _cors_preflight(base: str, origin: str, expect_allow: bool):
    req = urllib.request.Request(base + "/api/workspaces", method="OPTIONS")
    req.add_header("Origin", origin)
    req.add_header("Access-Control-Request-Method", "GET")
    req.add_header("Access-Control-Request-Headers", "authorization,content-type")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            allowed = r.headers.get("access-control-allow-origin") == origin
            if expect_allow and not allowed:
                raise RuntimeError(f"origin {origin} expected to be allowed")
            if not expect_allow and allowed:
                raise RuntimeError(f"origin {origin} should not have been allowed")
    except urllib.error.HTTPError as e:
        # Starlette CORS rejects unknown origins with a 400 — that's a "not allowed".
        if expect_allow:
            raise RuntimeError(f"preflight failed: HTTP {e.code}") from None
    return "OK"


def _ok(triple):
    ok, code, body = triple
    if not ok:
        raise RuntimeError(f"HTTP {code}: {body}")
    return body


def _fail(msg):
    raise RuntimeError(msg)


if __name__ == "__main__":
    main()
