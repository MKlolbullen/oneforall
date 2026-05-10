"""Detailed dashboard payload + workspace-wide findings list/update.

Covers:
- /api/dashboard/stats (existing) and /api/dashboard/detailed shapes
- /api/findings filters: severity, status, tool, target_id, q substring
- /api/findings facets stay stable across filter narrows
- pagination (limit/offset, no overlap)
- in-page severity-rank ordering (critical -> info)
- PATCH /api/findings/{id} status update + audit row
- 401 anonymous, 403 viewer-on-PATCH, 404 unknown id, 400 invalid status
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
API_DIR = REPO / "apps" / "api"
sys.path.insert(0, str(API_DIR))


@pytest.fixture
def stack(tmp_path, monkeypatch):
    db_path = tmp_path / "dash.db"
    art_dir = tmp_path / "artifacts"
    art_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("TOOL_REGISTRY_DIR", str(REPO / "packages/tool-registry/tools"))
    monkeypatch.setenv("PROFILE_REGISTRY_DIR", str(REPO / "packages/tool-registry/profiles"))
    monkeypatch.setenv("PLATFORM_CONFIG_PATH",
                       str(REPO / "packages/platform-config/sniper-inspired.yaml"))
    monkeypatch.setenv("GREP_PATTERNS_PATH",
                       str(REPO / "packages/patterns/sniper-grep-patterns.yaml"))
    monkeypatch.setenv("WORDLISTS_DIR", str(REPO / "packages/wordlists"))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("ARTIFACT_BACKEND", "local")
    monkeypatch.setenv("ARTIFACT_DIR", str(art_dir))
    monkeypatch.setenv("EXECUTION_MODE", "dry_run")
    monkeypatch.setenv("ALLOW_LIVE_EXECUTION", "false")
    monkeypatch.setenv("RUNNER_MODE", "in_process")
    monkeypatch.setenv("RECONFORGE_BOOTSTRAP_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("RECONFORGE_BOOTSTRAP_ADMIN_PASSWORD", "admin-passw0rd")
    monkeypatch.setenv("RECONFORGE_TEST_AUTH_BYPASS", "1")

    from conftest import rebind_engine_to_database_url
    rebind_engine_to_database_url()

    from fastapi.testclient import TestClient
    from app.main import app
    headers = {"X-Test-User": "admin"}
    with TestClient(app) as client:
        yield client, headers
    from app.core.config import get_settings
    get_settings.cache_clear()


def _seed_run_with_findings(client, headers, *, severities, statuses=None,
                             tools=None, target_value="lab.example.com"):
    """Run a real passive_recon, then synthesize a Finding row per severity."""
    ws_id = client.get("/api/workspaces", headers=headers).json()[0]["id"]
    target = client.post("/api/targets", headers=headers, json={
        "workspace_id": ws_id, "value": target_value, "type": "domain",
        "in_scope": True, "passive_allowed": True, "active_allowed": True,
    }).json()
    run = client.post("/api/runs", headers=headers, json={
        "workspace_id": ws_id, "target_id": target["id"], "profile_id": "passive_recon",
    }).json()
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        if client.get(f"/api/runs/{run['id']}", headers=headers).json()["status"] == "completed":
            break
        time.sleep(0.3)
    else:
        raise AssertionError(f"run {run['id']} did not complete within 90s")

    from app.db import engine
    from app.models import Finding
    from sqlmodel import Session
    statuses = statuses or ["new"] * len(severities)
    tools = tools or ["nuclei"] * len(severities)
    inserted = []
    with Session(engine) as session:
        for sev, st, tool in zip(severities, statuses, tools, strict=True):
            f = Finding(
                workspace_id=ws_id, run_id=run["id"],
                title=f"{sev} test finding via {tool}",
                severity=sev, status=st,
                category="test", evidence=f"evidence for {sev}",
                tool_source=tool,
            )
            session.add(f)
            session.commit()
            session.refresh(f)
            inserted.append(f.id)
    return ws_id, target, run, inserted


# ---------- /api/dashboard/stats (regression — auth gate) -------------------


def test_dashboard_stats_requires_auth(stack):
    client, _ = stack
    assert client.get("/api/dashboard/stats").status_code == 401


def test_dashboard_stats_basic(stack):
    client, headers = stack
    body = client.get("/api/dashboard/stats", headers=headers).json()
    for k in ("workspaces", "targets", "runs", "assets", "findings", "open_findings"):
        assert k in body and isinstance(body[k], int)


# ---------- /api/dashboard/detailed ------------------------------------------


def test_dashboard_detailed_empty_state(stack):
    client, headers = stack
    body = client.get("/api/dashboard/detailed", headers=headers).json()
    # Stable keys present even with no data
    assert set(body.keys()) >= {
        "kpis", "runs_by_status", "findings_by_severity",
        "active_runs", "recent_runs", "recent_findings",
        "top_targets", "top_tools", "recent_audit",
    }
    assert set(body["runs_by_status"].keys()) == {
        "queued", "running", "completed", "failed", "cancelled",
    }
    assert set(body["findings_by_severity"].keys()) == {
        "critical", "high", "medium", "low", "info",
    }
    assert all(v == 0 for v in body["runs_by_status"].values())
    assert all(v == 0 for v in body["findings_by_severity"].values())


def test_dashboard_detailed_after_run(stack):
    client, headers = stack
    _ws_id, target, _run, _ = _seed_run_with_findings(
        client, headers,
        severities=["critical", "high", "medium", "low", "info"],
    )
    body = client.get("/api/dashboard/detailed", headers=headers).json()

    # KPIs reflect actual rows
    assert body["kpis"]["runs"] >= 1
    assert body["kpis"]["targets"] >= 1
    assert body["kpis"]["findings"] >= 5

    # All severities counted
    sb = body["findings_by_severity"]
    assert sb["critical"] >= 1 and sb["high"] >= 1 and sb["info"] >= 1

    # Recent runs + recent findings populated and shaped
    assert body["recent_runs"], "recent_runs should be non-empty"
    rr = body["recent_runs"][0]
    assert {"id", "profile_id", "status", "risk", "target_id",
            "workspace_id", "created_at"}.issubset(rr.keys())
    assert body["recent_findings"], "recent_findings should be non-empty"
    rf = body["recent_findings"][0]
    assert {"id", "title", "severity", "status", "run_id", "created_at"}.issubset(rf.keys())

    # Top targets + tools surfaced via 30-day window aggregation
    assert any(t["id"] == target["id"] for t in body["top_targets"])
    assert body["top_tools"], "passive_recon should produce step rows"

    # Audit chain rolled up; the run.created action must be there
    actions = [e["action"] for e in body["recent_audit"]]
    assert any(a == "run.created" for a in actions)


# ---------- /api/findings list + filters -------------------------------------


def test_findings_anonymous_blocked(stack):
    client, _ = stack
    assert client.get("/api/findings").status_code == 401


def test_findings_filter_by_severity(stack):
    client, headers = stack
    _w, _t, _r, _ids = _seed_run_with_findings(
        client, headers,
        severities=["critical", "critical", "high", "low", "info"],
    )
    body = client.get("/api/findings?severity=critical", headers=headers).json()
    assert body["total"] == 2
    assert all(f["severity"] == "critical" for f in body["items"])
    # Facet list still includes ALL severities present in the workspace
    assert {"critical", "high", "low", "info"}.issubset(set(body["facets"]["severities"]))


def test_findings_filter_by_status(stack):
    client, headers = stack
    _w, _t, _r, _ = _seed_run_with_findings(
        client, headers,
        severities=["high", "high", "high"],
        statuses=["new", "triaged", "false_positive"],
    )
    only_triaged = client.get("/api/findings?status=triaged", headers=headers).json()
    assert only_triaged["total"] == 1
    assert only_triaged["items"][0]["status"] == "triaged"


def test_findings_filter_by_tool(stack):
    client, headers = stack
    _w, _t, _r, _ = _seed_run_with_findings(
        client, headers,
        severities=["high", "medium"],
        tools=["nuclei", "dalfox"],
    )
    body = client.get("/api/findings?tool=dalfox", headers=headers).json()
    assert body["total"] == 1
    assert body["items"][0]["tool_source"] == "dalfox"


def test_findings_filter_by_target(stack):
    client, headers = stack
    _, target_a, _, _ = _seed_run_with_findings(
        client, headers,
        severities=["critical"], target_value="a.example.com",
    )
    _, _target_b, _, _ = _seed_run_with_findings(
        client, headers,
        severities=["high"], target_value="b.example.com",
    )
    only_a = client.get(f"/api/findings?target_id={target_a['id']}",
                         headers=headers).json()
    assert only_a["total"] == 1
    assert only_a["items"][0]["severity"] == "critical"


def test_findings_substring_search(stack):
    client, headers = stack
    ws_id = client.get("/api/workspaces", headers=headers).json()[0]["id"]
    from app.db import engine
    from app.models import Finding
    from sqlmodel import Session
    with Session(engine) as session:
        for title in ("XSS in /search", "SQLi in /api/users", "Open redirect"):
            session.add(Finding(workspace_id=ws_id, title=title, severity="high",
                                 category="t", status="new", evidence=""))
        session.commit()
    body = client.get("/api/findings?q=SQLi", headers=headers).json()
    assert body["total"] == 1
    assert "SQLi" in body["items"][0]["title"]


def test_findings_pagination(stack):
    client, headers = stack
    ws_id = client.get("/api/workspaces", headers=headers).json()[0]["id"]
    from app.db import engine
    from app.models import Finding
    from sqlmodel import Session
    with Session(engine) as session:
        for i in range(15):
            session.add(Finding(workspace_id=ws_id, title=f"fnd-{i}", severity="info",
                                 status="new", category="t"))
        session.commit()
    p1 = client.get("/api/findings?limit=5&offset=0", headers=headers).json()
    p2 = client.get("/api/findings?limit=5&offset=5", headers=headers).json()
    p3 = client.get("/api/findings?limit=5&offset=10", headers=headers).json()
    assert (len(p1["items"]), len(p2["items"]), len(p3["items"])) == (5, 5, 5)
    ids = [f["id"] for p in (p1, p2, p3) for f in p["items"]]
    assert len(set(ids)) == 15


def test_findings_severity_ordering(stack):
    client, headers = stack
    _, _, _, _ = _seed_run_with_findings(
        client, headers,
        severities=["info", "low", "critical", "medium", "high"],
    )
    body = client.get("/api/findings", headers=headers).json()
    sevs = [f["severity"] for f in body["items"]]
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    assert sevs == sorted(sevs, key=lambda s: rank.get(s, 5))


# ---------- PATCH /api/findings/{id} -----------------------------------------


def test_patch_finding_status_persists_and_audits(stack):
    client, headers = stack
    _, _, _, ids = _seed_run_with_findings(
        client, headers, severities=["high"],
    )
    fid = ids[0]
    r = client.patch(f"/api/findings/{fid}",
                     headers=headers, json={"status": "triaged"})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "triaged"

    # Audit row exists
    admin_token = client.post("/api/auth/login",
                               json={"username": "admin",
                                      "password": "admin-passw0rd"}).json()["token"]
    audit = client.get("/api/auth/audit",
                       headers={"Authorization": f"Bearer {admin_token}"}).json()
    assert any(e["action"] == "finding.status_updated" for e in audit["events"])
    assert audit["ok"] is True


def test_patch_finding_invalid_status(stack):
    client, headers = stack
    _, _, _, ids = _seed_run_with_findings(
        client, headers, severities=["high"],
    )
    r = client.patch(f"/api/findings/{ids[0]}",
                     headers=headers, json={"status": "definitely_invalid"})
    assert r.status_code == 400
    assert "invalid status" in r.json()["detail"]


def test_patch_finding_404(stack):
    client, headers = stack
    r = client.patch("/api/findings/nope", headers=headers,
                     json={"status": "triaged"})
    assert r.status_code == 404


def test_patch_finding_viewer_blocked(stack):
    client, headers = stack
    _, _, _, ids = _seed_run_with_findings(
        client, headers, severities=["high"],
    )
    admin_token = client.post("/api/auth/login",
                               json={"username": "admin",
                                      "password": "admin-passw0rd"}).json()["token"]
    client.post("/api/auth/users",
                headers={"Authorization": f"Bearer {admin_token}"},
                json={"username": "vw", "password": "viewer-p4ssword", "role": "viewer"})
    vt = client.post("/api/auth/login",
                     json={"username": "vw", "password": "viewer-p4ssword"}).json()["token"]
    r = client.patch(f"/api/findings/{ids[0]}",
                     headers={"Authorization": f"Bearer {vt}"},
                     json={"status": "triaged"})
    assert r.status_code == 403
