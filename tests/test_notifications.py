"""Outbound webhook notifications.

Tests cover:
- silent no-op when slack.enabled=false in platform config
- silent no-op when SLACK_WEBHOOK_URL is unset
- POST is fired with the expected message shape when both are configured
- Webhook delivery failure does NOT propagate (best-effort by design)
- An end-to-end run with a stubbed webhook records exactly one outbound call
  on completion
"""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
API_DIR = REPO / "apps" / "api"
sys.path.insert(0, str(API_DIR))


@pytest.fixture
def stack(tmp_path, monkeypatch):
    db_path = tmp_path / "notif.db"
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

    yield monkeypatch
    from app.core.config import get_settings
    get_settings.cache_clear()


def _force_slack_config(monkeypatch, enabled: bool):
    """Patch load_platform_config to return a fake config rather than reading
    the YAML so we can flip slack.enabled cleanly per test."""
    cfg = {
        "integrations": {
            "slack": {"enabled": enabled, "webhook_env": "RECONFORGE_TEST_WEBHOOK_URL"},
        },
    }
    import app.services.notifications as notifications_mod
    monkeypatch.setattr(notifications_mod, "load_platform_config", lambda: cfg)


def test_disabled_in_config_is_silent(stack):
    _force_slack_config(stack, enabled=False)
    stack.setenv("RECONFORGE_TEST_WEBHOOK_URL", "https://example.invalid/hook")
    from app.services.notifications import is_configured, notify_run_event
    assert is_configured() is False
    # Coroutine completes without making any HTTP call
    asyncio.get_event_loop().run_until_complete(
        notify_run_event("run.completed", "run_x", {"profile_id": "p", "target_value": "t"})
    )


def test_no_webhook_env_is_silent(stack):
    _force_slack_config(stack, enabled=True)
    stack.delenv("RECONFORGE_TEST_WEBHOOK_URL", raising=False)
    from app.services.notifications import is_configured, notify_run_event
    assert is_configured() is False
    asyncio.get_event_loop().run_until_complete(
        notify_run_event("run.completed", "run_y", {})
    )


def test_post_fires_when_configured(stack, monkeypatch):
    _force_slack_config(stack, enabled=True)
    stack.setenv("RECONFORGE_TEST_WEBHOOK_URL", "https://example.invalid/hook")

    captured: list[tuple[str, dict]] = []

    class FakeResponse:
        status_code = 200
        text = "ok"

    class FakeClient:
        def __init__(self, *_, **__): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *_): return False
        async def post(self, url, json=None):  # noqa: A002 - matching httpx kwarg
            captured.append((url, json))
            return FakeResponse()

    import app.services.notifications as notifications_mod
    monkeypatch.setattr(notifications_mod.httpx, "AsyncClient", FakeClient)

    asyncio.get_event_loop().run_until_complete(
        notifications_mod.notify_run_event("run.completed", "run_abc", {
            "profile_id": "passive_recon",
            "target_value": "lab.example.com",
            "runner_mode": "in_process",
        })
    )

    assert len(captured) == 1
    url, body = captured[0]
    assert url == "https://example.invalid/hook"
    text = body["text"]
    assert "Run completed" in text
    assert "run_abc" in text
    assert "passive_recon" in text
    assert "lab.example.com" in text


def test_webhook_failure_is_swallowed(stack, monkeypatch):
    _force_slack_config(stack, enabled=True)
    stack.setenv("RECONFORGE_TEST_WEBHOOK_URL", "https://example.invalid/hook")

    class ExplodingClient:
        def __init__(self, *_, **__): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *_): return False
        async def post(self, *_args, **_kwargs):
            raise RuntimeError("connection refused")

    import app.services.notifications as notifications_mod
    monkeypatch.setattr(notifications_mod.httpx, "AsyncClient", ExplodingClient)

    # Must NOT raise
    asyncio.get_event_loop().run_until_complete(
        notifications_mod.notify_run_event("run.failed", "run_xyz", {"error": "boom"})
    )


def test_unknown_event_type_no_op(stack, monkeypatch):
    _force_slack_config(stack, enabled=True)
    stack.setenv("RECONFORGE_TEST_WEBHOOK_URL", "https://example.invalid/hook")
    posted: list = []

    class FakeClient:
        def __init__(self, *_, **__): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *_): return False
        async def post(self, *a, **k): posted.append((a, k)); return type("R", (), {"status_code": 200, "text": ""})()

    import app.services.notifications as notifications_mod
    monkeypatch.setattr(notifications_mod.httpx, "AsyncClient", FakeClient)
    asyncio.get_event_loop().run_until_complete(
        notifications_mod.notify_run_event("run.queued", "r", {})
    )
    assert posted == [], "lifecycle filter must skip non-completion events"


def test_full_run_with_webhook_fires_once(stack, monkeypatch):
    """End-to-end: a real in-process run with the platform config patched to
    enable slack must trigger exactly one POST on completion."""
    _force_slack_config(stack, enabled=True)
    stack.setenv("RECONFORGE_TEST_WEBHOOK_URL", "https://example.invalid/hook")

    posted: list[dict] = []

    class FakeClient:
        def __init__(self, *_, **__): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *_): return False
        async def post(self, url, json=None):
            posted.append(json or {})
            return type("R", (), {"status_code": 200, "text": ""})()

    import app.services.notifications as notifications_mod
    monkeypatch.setattr(notifications_mod.httpx, "AsyncClient", FakeClient)

    from fastapi.testclient import TestClient
    from app.main import app
    headers = {"X-Test-User": "admin"}
    with TestClient(app) as client:
        ws_id = client.get("/api/workspaces", headers=headers).json()[0]["id"]
        target = client.post("/api/targets", headers=headers, json={
            "workspace_id": ws_id, "value": "lab.example.com", "type": "domain",
            "in_scope": True, "passive_allowed": True, "active_allowed": True,
        }).json()
        run = client.post("/api/runs", headers=headers, json={
            "workspace_id": ws_id, "target_id": target["id"],
            "profile_id": "passive_recon",
        }).json()
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if client.get(f"/api/runs/{run['id']}", headers=headers).json()["status"] == "completed":
                break
            time.sleep(0.3)

    assert len(posted) == 1, f"expected 1 webhook POST, got {len(posted)}: {posted}"
    text = posted[0]["text"]
    assert "Run completed" in text
    assert "passive_recon" in text
    assert "lab.example.com" in text
