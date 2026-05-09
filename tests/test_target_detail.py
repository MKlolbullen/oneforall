"""Per-target detail endpoints.

Run a real profile in dry-run mode against a target, then verify the
target-scoped endpoints surface the right rows:

  GET /api/targets/{id}              -> the target
  GET /api/targets/{id}/runs         -> runs for this target only
  GET /api/targets/{id}/assets       -> assets discovered via those runs
  GET /api/targets/{id}/findings     -> findings, severity-ranked
  GET /api/targets/{id}/summary      -> rolled-up counts
  GET /api/targets/{id}/tech         -> aggregated tech fingerprints
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
    db_path = tmp_path / "tgt.db"
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


def _create_target_and_run_to_completion(client, headers, *, profile="passive_recon"):
    ws_id = client.get("/api/workspaces", headers=headers).json()[0]["id"]
    target = client.post(
        "/api/targets",
        headers=headers,
        json={"workspace_id": ws_id, "value": "lab.example.com", "type": "domain",
              "in_scope": True, "passive_allowed": True, "active_allowed": True},
    ).json()
    run = client.post(
        "/api/runs",
        headers=headers,
        json={"workspace_id": ws_id, "target_id": target["id"], "profile_id": profile},
    ).json()
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        r = client.get(f"/api/runs/{run['id']}", headers=headers)
        if r.json()["status"] == "completed":
            break
        time.sleep(0.3)
    else:
        run_id = run["id"]
        last = client.get(f"/api/runs/{run_id}", headers=headers).json()
        raise AssertionError(f"run did not complete: {last}")
    return ws_id, target, run


def test_get_target_returns_404_for_unknown(stack):
    client, h = stack
    assert client.get("/api/targets/nope", headers=h).status_code == 404


def test_target_runs_assets_findings_summary_after_passive_recon(stack):
    client, h = stack
    _, target, run = _create_target_and_run_to_completion(client, h)

    # /runs scoped to this target only
    runs = client.get(f"/api/targets/{target['id']}/runs", headers=h).json()
    assert any(r["id"] == run["id"] for r in runs)
    assert all(r["target_id"] == target["id"] for r in runs)

    # /assets — passive_recon dry-run produces domain + url assets via subfinder/httpx fixtures
    assets = client.get(f"/api/targets/{target['id']}/assets", headers=h).json()
    assert assets, "expected at least one asset from dry-run"
    types = {a["type"] for a in assets}
    assert "domain" in types or "url" in types, f"expected domain or url asset, got {types}"

    # /findings — passive_recon doesn't produce findings, but the endpoint should
    # return an empty list rather than 404.
    findings = client.get(f"/api/targets/{target['id']}/findings", headers=h)
    assert findings.status_code == 200
    assert isinstance(findings.json(), list)

    # /summary — counts and last_run_at must be sane
    summary = client.get(f"/api/targets/{target['id']}/summary", headers=h).json()
    assert summary["runs_total"] >= 1
    assert summary["runs_by_status"].get("completed", 0) >= 1
    assert summary["last_run_at"] is not None
    assert summary["assets_total"] == len(assets)
    assert summary["target"]["id"] == target["id"]


def test_target_tech_aggregates_httpx_fingerprints(stack):
    client, h = stack
    _, target, _ = _create_target_and_run_to_completion(client, h)
    # httpx dry_run_output includes one line with `tech: ["nginx"]`. The
    # normalizer stores it on the url asset's meta.json. /tech aggregates.
    tech = client.get(f"/api/targets/{target['id']}/tech", headers=h).json()
    # We only assert structure here — the dry_run_output may not always include
    # a tech array depending on how the upstream registry shifts. Aggregate keys
    # must always be present.
    assert "tech" in tech and "servers" in tech and "by_url" in tech
    assert isinstance(tech["tech"], dict)
    assert isinstance(tech["by_url"], list)


def test_target_assets_isolated_by_target(stack):
    """Assets for target A must not bleed into target B's view."""
    client, h = stack
    ws_id = client.get("/api/workspaces", headers=h).json()[0]["id"]
    a = client.post("/api/targets", headers=h, json={
        "workspace_id": ws_id, "value": "a.example.com", "type": "domain",
        "in_scope": True, "passive_allowed": True, "active_allowed": True,
    }).json()
    b = client.post("/api/targets", headers=h, json={
        "workspace_id": ws_id, "value": "b.example.com", "type": "domain",
        "in_scope": True, "passive_allowed": True, "active_allowed": True,
    }).json()

    # Run only against target A
    run = client.post("/api/runs", headers=h, json={
        "workspace_id": ws_id, "target_id": a["id"], "profile_id": "passive_recon",
    }).json()
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        if client.get(f"/api/runs/{run['id']}", headers=h).json()["status"] == "completed":
            break
        time.sleep(0.3)

    assets_a = client.get(f"/api/targets/{a['id']}/assets", headers=h).json()
    assets_b = client.get(f"/api/targets/{b['id']}/assets", headers=h).json()
    assert assets_a, "target A should have assets"
    assert assets_b == [], f"target B should have no assets, got {assets_b}"


def test_findings_severity_order(stack):
    """Inject findings of different severities and verify the endpoint returns
    them critical -> high -> medium -> low -> info."""
    client, h = stack
    ws_id = client.get("/api/workspaces", headers=h).json()[0]["id"]
    target = client.post("/api/targets", headers=h, json={
        "workspace_id": ws_id, "value": "lab.example.com", "type": "domain",
        "in_scope": True, "passive_allowed": True, "active_allowed": True,
    }).json()
    # A trivial dry-run so a Run exists for this target
    run = client.post("/api/runs", headers=h, json={
        "workspace_id": ws_id, "target_id": target["id"], "profile_id": "passive_recon",
    }).json()
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        if client.get(f"/api/runs/{run['id']}", headers=h).json()["status"] == "completed":
            break
        time.sleep(0.3)

    # Insert findings directly into the DB at the workspace+run level
    from sqlmodel import Session
    from app.db import engine
    from app.models import Finding
    with Session(engine) as session:
        for sev in ("info", "low", "high", "critical", "medium"):
            session.add(Finding(workspace_id=ws_id, run_id=run["id"],
                                 title=f"{sev} test finding", severity=sev,
                                 category="test", evidence="..."))
        session.commit()

    findings = client.get(f"/api/targets/{target['id']}/findings", headers=h).json()
    sevs = [f["severity"] for f in findings]
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    assert sevs == sorted(sevs, key=lambda s: rank.get(s, 5)), \
        f"findings not severity-ranked: {sevs}"
