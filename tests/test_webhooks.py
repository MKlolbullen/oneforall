"""Webhooks: CRUD + test endpoint + lifecycle fan-out from notifications.

Validates that:
- the auth and ownership rules match workflows / API keys
- /test deliveries write last_status / last_error back to the row
- a real run completion fans out to active workspace webhooks
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
    db_path = tmp_path / "wh.db"
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
    monkeypatch.setenv("DRY_RUN_LINE_DELAY_SECONDS", "0")
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


def _ws_id(client, headers) -> str:
    return client.get("/api/workspaces", headers=headers).json()[0]["id"]


def test_webhooks_anonymous_blocked(stack):
    client, _ = stack
    assert client.get("/api/webhooks").status_code == 401
    assert client.post("/api/webhooks", json={
        "workspace_id": "x", "name": "y", "url": "https://example.com/h",
    }).status_code == 401


def test_create_and_list_webhook(stack):
    client, headers = stack
    ws_id = _ws_id(client, headers)
    r = client.post("/api/webhooks", headers=headers, json={
        "workspace_id": ws_id, "name": "ops-slack",
        "url": "https://hooks.slack.com/services/T0/X/Y",
        "events": ["run.completed", "run.failed"], "is_active": True,
    })
    assert r.status_code == 201, r.text
    wh = r.json()
    assert wh["name"] == "ops-slack" and wh["events"] == ["run.completed", "run.failed"]
    listing = client.get("/api/webhooks", headers=headers).json()
    assert any(row["id"] == wh["id"] for row in listing)


def test_create_rejects_bad_url(stack):
    client, headers = stack
    ws_id = _ws_id(client, headers)
    r = client.post("/api/webhooks", headers=headers, json={
        "workspace_id": ws_id, "name": "bad", "url": "javascript:alert(1)",
        "events": ["run.completed"],
    })
    assert r.status_code == 422


def test_create_rejects_unknown_events(stack):
    client, headers = stack
    ws_id = _ws_id(client, headers)
    r = client.post("/api/webhooks", headers=headers, json={
        "workspace_id": ws_id, "name": "bad",
        "url": "https://example.com/h", "events": ["something.weird"],
    })
    assert r.status_code == 422


def test_test_endpoint_records_failure(stack):
    """A test delivery to an unreachable host returns delivered=false and the
    failure is captured on the row so the operator can debug."""
    client, headers = stack
    ws_id = _ws_id(client, headers)
    wh = client.post("/api/webhooks", headers=headers, json={
        "workspace_id": ws_id, "name": "dead",
        "url": "http://127.0.0.1:1/never-listens",
        "events": ["run.completed"],
    }).json()
    r = client.post(f"/api/webhooks/{wh['id']}/test", headers=headers)
    assert r.status_code == 200
    result = r.json()
    assert result["delivered"] is False
    assert result["error"]
    # Row reflects the failed attempt.
    fresh = client.get(f"/api/webhooks/{wh['id']}", headers=headers).json()
    assert fresh["last_error"]
    assert fresh["last_used_at"] is not None


def test_update_owner_only(stack):
    client, headers = stack
    ws_id = _ws_id(client, headers)
    wh = client.post("/api/webhooks", headers=headers, json={
        "workspace_id": ws_id, "name": "v1",
        "url": "https://example.com/h1", "events": ["run.completed"],
    }).json()
    r = client.put(f"/api/webhooks/{wh['id']}", headers=headers,
                   json={"name": "v2", "is_active": False})
    assert r.status_code == 200
    assert r.json()["name"] == "v2" and r.json()["is_active"] is False

    # Non-owner operator: 403
    admin_token = client.post("/api/auth/login",
                               json={"username": "admin", "password": "admin-passw0rd"}).json()["token"]
    client.post("/api/auth/users",
                headers={"Authorization": f"Bearer {admin_token}"},
                json={"username": "op", "password": "op-secret-1", "role": "operator"})
    op_token = client.post("/api/auth/login",
                            json={"username": "op", "password": "op-secret-1"}).json()["token"]
    r = client.put(f"/api/webhooks/{wh['id']}",
                   headers={"Authorization": f"Bearer {op_token}"},
                   json={"name": "v3"})
    assert r.status_code == 403


def test_delete_webhook(stack):
    client, headers = stack
    ws_id = _ws_id(client, headers)
    wh = client.post("/api/webhooks", headers=headers, json={
        "workspace_id": ws_id, "name": "doomed",
        "url": "https://example.com/h", "events": ["run.completed"],
    }).json()
    r = client.delete(f"/api/webhooks/{wh['id']}", headers=headers)
    assert r.status_code == 204
    assert client.get(f"/api/webhooks/{wh['id']}", headers=headers).status_code == 404


def test_run_completion_fans_out(stack, monkeypatch):
    """A real run completion records `last_used_at` on each active webhook
    in the run's workspace. The webhook URL points at 127.0.0.1:1 so the
    delivery will fail — we don't care about delivery success, just that the
    fan-out path was hit and the row was updated."""
    client, headers = stack
    ws_id = _ws_id(client, headers)
    wh = client.post("/api/webhooks", headers=headers, json={
        "workspace_id": ws_id, "name": "ops",
        "url": "http://127.0.0.1:1/never",
        "events": ["run.completed"], "is_active": True,
    }).json()

    target = client.post("/api/targets", headers=headers, json={
        "workspace_id": ws_id, "value": "wh.example.com", "type": "domain",
        "in_scope": True, "passive_allowed": True, "active_allowed": True,
    }).json()
    run = client.post("/api/runs", headers=headers, json={
        "workspace_id": ws_id, "target_id": target["id"], "profile_id": "passive_recon",
    }).json()
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if client.get(f"/api/runs/{run['id']}", headers=headers).json()["status"] == "completed":
            break
        time.sleep(0.3)
    else:
        raise AssertionError("run did not complete")

    # Give the fire-and-forget fan-out a moment to flush
    time.sleep(0.3)
    fresh = client.get(f"/api/webhooks/{wh['id']}", headers=headers).json()
    assert fresh["last_used_at"] is not None, fresh
