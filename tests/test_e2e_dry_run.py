"""End-to-end stack validation: boot the FastAPI app with SQLite + local artifacts +
in-process runner, drive a real profile from the API, and assert that the run
reaches `completed` with steps, events, and artifacts persisted."""
from __future__ import annotations

import asyncio
import os
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "apps" / "api"))


@pytest.fixture(autouse=True)
def _env(monkeypatch, tmp_path):
    db_path = tmp_path / "reconforge.db"
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
    monkeypatch.setenv("REDIS_URL", "redis://nonexistent-host-on-purpose:6379/0")
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

    yield
    from app.core.config import get_settings
    get_settings.cache_clear()


def _wait_for(predicate, timeout=10.0, interval=0.2):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def test_full_dry_run_through_api():
    from fastapi.testclient import TestClient
    from app.main import app

    # Test-bypass header auths every API call as admin (created via bootstrap env).
    headers = {"X-Test-User": "admin"}

    with TestClient(app) as client:
        # 1. Health check is unauthenticated
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["execution_mode"] == "dry_run"
        assert r.json()["runner_mode"] == "in_process"

        # 2. Seed data should have created Demo Workspace + example.com target
        r = client.get("/api/workspaces", headers=headers)
        assert r.status_code == 200
        workspaces = r.json()
        assert workspaces, "lifespan seed should have created a workspace"
        ws_id = workspaces[0]["id"]

        # passive_recon now includes httpx (low_active), so the run requires a
        # target with active_allowed=True. Create a fresh one rather than
        # mutating the demo seed.
        created = client.post(
            "/api/targets",
            json={"workspace_id": ws_id, "value": "lab.example.com",
                  "type": "domain", "in_scope": True,
                  "passive_allowed": True, "active_allowed": True,
                  "notes": "e2e test target"},
            headers=headers,
        )
        assert created.status_code == 201, created.text
        target_id = created.json()["id"]

        # 3. Create a run on the cheapest profile we know works in dry_run
        r = client.post(
            "/api/runs",
            json={
                "workspace_id": ws_id,
                "target_id": target_id,
                "profile_id": "passive_recon",
                "requested_by": "e2e-test",
            },
            headers=headers,
        )
        assert r.status_code == 201, r.text
        run = r.json()
        run_id = run["id"]

        # 4. Wait for the in-process runner to flip the run to completed
        def _completed():
            resp = client.get(f"/api/runs/{run_id}", headers=headers)
            return resp.status_code == 200 and resp.json()["status"] == "completed"

        assert _wait_for(_completed, timeout=60.0), \
            f"run {run_id} did not complete in 60s; final state: " \
            f"{client.get(f'/api/runs/{run_id}', headers=headers).json()}"

        # 5. Steps were persisted, all completed
        r = client.get(f"/api/runs/{run_id}/steps", headers=headers)
        assert r.status_code == 200
        steps = r.json()
        assert len(steps) >= 4, f"expected >=4 steps, got {len(steps)}"
        for s in steps:
            assert s["status"] == "completed", f"step {s['tool_id']} status={s['status']}"

        # 6. Events persisted including run.completed
        r = client.get(f"/api/runs/{run_id}/events", headers=headers)
        assert r.status_code == 200
        evs = r.json()
        types = {e["type"] for e in evs}
        assert {"run.queued", "run.started", "run.completed"}.issubset(types)
        assert any(e["type"] == "run.step.completed" for e in evs)

        # 7. Artifacts written to local backend (one stdout per step)
        r = client.get(f"/api/runs/{run_id}/artifacts", headers=headers)
        assert r.status_code == 200
        arts = r.json()
        assert len(arts) >= 4, f"expected >=4 artifacts, got {len(arts)}"
        names = {a["name"] for a in arts}
        # subfinder is the first step in passive_recon and emits dry_run_output
        assert any("subfinder" in n for n in names), f"no subfinder artifact in {names}"


def test_oneforall_chain_profile_dry_run():
    """The wired-up oneforall_chain profile must resolve all 8 of its steps."""
    from app.services.tool_registry import ToolRegistry
    from app.core.config import get_settings
    s = get_settings()
    reg = ToolRegistry(s.tool_registry_dir, s.profile_registry_dir)
    profile = reg.get_profile("oneforall_chain")
    assert profile["id"] == "oneforall_chain"
    for step in profile["steps"]:
        tool = reg.get_tool(step["tool"])
        assert tool.id.startswith("oneforall_")
        assert tool.dry_run_output, f"{tool.id} has no dry_run_output for dry-mode runs"
