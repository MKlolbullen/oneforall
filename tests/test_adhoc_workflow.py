"""Ad-hoc workflow runs (POST /api/runs/adhoc).

The Workflow Builder posts a JSON DAG instead of looking up a YAML profile.
These tests cover the new endpoint:
  - happy path: a 2-step dry-run completes and persists assets/findings
  - unknown tool → 404
  - scope violation (medium_active without active_allowed) → 403
  - the inline profile survives the round-trip into the brief and triage
    paths (so advisor / agent can reason about ad-hoc runs too)
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
    db_path = tmp_path / "adhoc.db"
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


def _make_target(client, headers, value="adhoc.example.com", *, active=True):
    ws_id = client.get("/api/workspaces", headers=headers).json()[0]["id"]
    r = client.post("/api/targets", headers=headers, json={
        "workspace_id": ws_id, "value": value, "type": "domain",
        "in_scope": True, "passive_allowed": True, "active_allowed": active,
    })
    assert r.status_code == 201, r.text
    return ws_id, r.json()


def _wait_completed(client, headers, run_id, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        body = client.get(f"/api/runs/{run_id}", headers=headers).json()
        if body["status"] in {"completed", "failed", "cancelled"}:
            return body
        time.sleep(0.25)
    raise AssertionError(f"run {run_id} did not complete in {timeout}s")


def test_adhoc_dry_run_completes(stack):
    client, headers = stack
    ws_id, target = _make_target(client, headers)

    r = client.post("/api/runs/adhoc", headers=headers, json={
        "workspace_id": ws_id,
        "target_id": target["id"],
        "name": "Quick subdomain sweep",
        "steps": [
            {"tool": "subfinder"},
            {"tool": "dnsx",
             "argv_extra": ["-l", "{{upstream.domain_list.merged_path}}"]},
        ],
    })
    assert r.status_code == 201, r.text
    run = r.json()
    assert run["profile_id"] == "adhoc"
    assert run["risk"] == "passive"

    final = _wait_completed(client, headers, run["id"])
    assert final["status"] == "completed", final

    # Steps were persisted in the same order as the inline workflow.
    steps = client.get(f"/api/runs/{run['id']}/steps", headers=headers).json()
    assert [s["tool_id"] for s in steps] == ["subfinder", "dnsx"]
    assert all(s["status"] == "completed" for s in steps)

    # The brief reflects this run too — proves the ad-hoc profile flows
    # through the same agent / advisor context shaping.
    brief = client.get(f"/api/agent/runs/{run['id']}/brief", headers=headers).json()
    assert brief["run"]["profile_id"] == "adhoc"
    assert brief["counts"]["steps"] == 2


def test_adhoc_unknown_tool_returns_404(stack):
    client, headers = stack
    ws_id, target = _make_target(client, headers)
    r = client.post("/api/runs/adhoc", headers=headers, json={
        "workspace_id": ws_id, "target_id": target["id"],
        "name": "broken", "steps": [{"tool": "definitely-not-a-real-tool"}],
    })
    assert r.status_code == 404
    assert "definitely-not-a-real-tool" in r.json()["detail"]


def test_adhoc_scope_violation_returns_403(stack):
    client, headers = stack
    # active_allowed=False — but the step list includes httpx (low_active).
    ws_id, target = _make_target(client, headers, value="no-active.example.com", active=False)
    r = client.post("/api/runs/adhoc", headers=headers, json={
        "workspace_id": ws_id, "target_id": target["id"],
        "name": "should-be-blocked",
        "steps": [{"tool": "httpx"}],
    })
    assert r.status_code == 403, r.text


def test_adhoc_target_workspace_mismatch_returns_400(stack):
    client, headers = stack
    ws_id, target = _make_target(client, headers)
    r = client.post("/api/runs/adhoc", headers=headers, json={
        "workspace_id": "ws_bogus", "target_id": target["id"],
        "name": "wrong-ws", "steps": [{"tool": "subfinder"}],
    })
    assert r.status_code == 400


def test_adhoc_anonymous_blocked(stack):
    client, _ = stack
    r = client.post("/api/runs/adhoc", json={
        "workspace_id": "x", "target_id": "y",
        "name": "anon", "steps": [{"tool": "subfinder"}],
    })
    assert r.status_code == 401
