"""Phase-2 embedded runner: prove the stack runs on one process with no Redis.

Covers:
  - RUNNER_MODE=embedded drains an in-process queue from the API's own loop and
    drives a dry-run profile to completion (Redis URL points at a dead host).
  - /health reports the resolved memory transports.
  - The in-process event broker fans out to many concurrent subscribers.
  - Live WebSocket delivery works through the real ws route with several
    simultaneous clients.
  - Cancellation sets the durable DB flag without touching Redis.
"""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "apps" / "api"))


def _base_env(monkeypatch, tmp_path):
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
    # Deliberately unreachable: nothing in embedded mode may dial Redis.
    monkeypatch.setenv("REDIS_URL", "redis://nonexistent-host-on-purpose:6379/0")
    monkeypatch.setenv("ARTIFACT_BACKEND", "local")
    monkeypatch.setenv("ARTIFACT_DIR", str(art_dir))
    monkeypatch.setenv("EXECUTION_MODE", "dry_run")
    monkeypatch.setenv("ALLOW_LIVE_EXECUTION", "false")
    monkeypatch.setenv("DRY_RUN_LINE_DELAY_SECONDS", "0")
    monkeypatch.setenv("RECONFORGE_BOOTSTRAP_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("RECONFORGE_BOOTSTRAP_ADMIN_PASSWORD", "admin-passw0rd")
    monkeypatch.setenv("RECONFORGE_TEST_AUTH_BYPASS", "1")


@pytest.fixture
def embedded_env(monkeypatch, tmp_path):
    _base_env(monkeypatch, tmp_path)
    monkeypatch.setenv("RUNNER_MODE", "embedded")
    from conftest import rebind_engine_to_database_url
    rebind_engine_to_database_url()
    yield
    from app.core.config import get_settings
    get_settings.cache_clear()


def _wait_for(predicate, timeout=60.0, interval=0.2):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def _make_target(client, headers, ws_id):
    created = client.post(
        "/api/targets",
        json={"workspace_id": ws_id, "value": "lab.example.com",
              "type": "domain", "in_scope": True,
              "passive_allowed": True, "active_allowed": True,
              "notes": "embedded test target"},
        headers=headers,
    )
    assert created.status_code == 201, created.text
    return created.json()["id"]


def test_embedded_run_completes_without_redis(embedded_env):
    from fastapi.testclient import TestClient
    from app.main import app

    headers = {"X-Test-User": "admin"}
    with TestClient(app) as client:
        h = client.get("/health").json()
        assert h["runner_mode"] == "embedded"
        assert h["event_transport"] == "memory"
        assert h["queue_backend"] == "memory"

        ws_id = client.get("/api/workspaces", headers=headers).json()[0]["id"]
        target_id = _make_target(client, headers, ws_id)

        r = client.post(
            "/api/runs",
            json={"workspace_id": ws_id, "target_id": target_id,
                  "profile_id": "passive_recon", "requested_by": "embedded-test"},
            headers=headers,
        )
        assert r.status_code == 201, r.text
        run_id = r.json()["id"]

        def _completed():
            resp = client.get(f"/api/runs/{run_id}", headers=headers)
            return resp.status_code == 200 and resp.json()["status"] == "completed"

        assert _wait_for(_completed), \
            f"embedded run {run_id} did not complete; " \
            f"{client.get(f'/api/runs/{run_id}', headers=headers).json()}"

        evs = client.get(f"/api/runs/{run_id}/events", headers=headers).json()
        types = {e["type"] for e in evs}
        assert {"run.queued", "run.started", "run.completed"}.issubset(types)


def test_health_memory_transport_via_explicit_override(monkeypatch, tmp_path):
    """queue mode normally implies redis, but explicit overrides win."""
    _base_env(monkeypatch, tmp_path)
    monkeypatch.setenv("RUNNER_MODE", "queue")
    monkeypatch.setenv("EVENT_TRANSPORT", "memory")
    monkeypatch.setenv("QUEUE_BACKEND", "memory")
    from conftest import rebind_engine_to_database_url
    rebind_engine_to_database_url()

    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as client:
        h = client.get("/health").json()
        assert h["runner_mode"] == "queue"
        assert h["event_transport"] == "memory"
        assert h["queue_backend"] == "memory"

    from app.core.config import get_settings
    get_settings.cache_clear()


def test_websocket_fanout_to_concurrent_subscribers(embedded_env):
    from fastapi.testclient import TestClient
    from app.main import app

    headers = {"X-Test-User": "admin"}
    with TestClient(app) as client:
        ws_id = client.get("/api/workspaces", headers=headers).json()[0]["id"]
        target_id = _make_target(client, headers, ws_id)
        run_id = client.post(
            "/api/runs",
            json={"workspace_id": ws_id, "target_id": target_id,
                  "profile_id": "passive_recon", "requested_by": "ws-test"},
            headers=headers,
        ).json()["id"]

        # Let the run finish so the full event history (incl. run.completed) is
        # on record; every concurrent subscriber must replay it on connect.
        def _completed():
            resp = client.get(f"/api/runs/{run_id}", headers=headers)
            return resp.status_code == 200 and resp.json()["status"] == "completed"

        assert _wait_for(_completed)

        def _collect_until_completed(ws, limit=400):
            seen = set()
            for _ in range(limit):
                evt = ws.receive_json()
                seen.add(evt["type"])
                if evt["type"] == "run.completed":
                    return seen
            return seen

        # Three simultaneous clients on the same run channel.
        with client.websocket_connect(f"/ws/runs/{run_id}") as ws1, \
             client.websocket_connect(f"/ws/runs/{run_id}") as ws2, \
             client.websocket_connect(f"/ws/runs/{run_id}") as ws3:
            for ws in (ws1, ws2, ws3):
                types = _collect_until_completed(ws)
                assert {"run.queued", "run.started", "run.completed"}.issubset(types)


def test_cancel_sets_db_flag_without_redis(monkeypatch, tmp_path):
    """A queued run (no worker draining) cancels cleanly via the DB flag, no Redis."""
    _base_env(monkeypatch, tmp_path)
    # queue mode → no embedded worker is started, so the run sits in the queue
    # and we can observe the cancel transition deterministically. memory backend
    # keeps the whole thing off Redis.
    monkeypatch.setenv("RUNNER_MODE", "queue")
    monkeypatch.setenv("EVENT_TRANSPORT", "memory")
    monkeypatch.setenv("QUEUE_BACKEND", "memory")
    from conftest import rebind_engine_to_database_url
    rebind_engine_to_database_url()

    from fastapi.testclient import TestClient
    from app.main import app

    headers = {"X-Test-User": "admin"}
    with TestClient(app) as client:
        ws_id = client.get("/api/workspaces", headers=headers).json()[0]["id"]
        target_id = _make_target(client, headers, ws_id)
        run_id = client.post(
            "/api/runs",
            json={"workspace_id": ws_id, "target_id": target_id,
                  "profile_id": "passive_recon", "requested_by": "cancel-test"},
            headers=headers,
        ).json()["id"]

        # Nothing drains the queue in plain queue mode under the test client, so
        # the run is still queued.
        assert client.get(f"/api/runs/{run_id}", headers=headers).json()["status"] == "queued"

        cancelled = client.post(f"/api/runs/{run_id}/cancel", headers=headers)
        assert cancelled.status_code == 200, cancelled.text
        body = cancelled.json()
        assert body["status"] == "cancelled"
        assert body["cancel_requested_at"] is not None

        events = client.get(f"/api/runs/{run_id}/events", headers=headers).json()
        assert any(e["type"] == "run.cancel_requested" for e in events)

    from app.core.config import get_settings
    get_settings.cache_clear()


def test_memory_broker_fans_out_to_many_subscribers():
    """Unit-level guarantee for the in-process pub/sub primitive itself."""
    from app.services.memory_transport import MemoryBroker

    async def scenario():
        broker = MemoryBroker()
        channel = "reconforge:runs:r1:events"
        n_subs = 5
        n_msgs = 10
        received: list[list[dict]] = [[] for _ in range(n_subs)]

        async def consumer(idx):
            count = 0
            async for body in broker.subscribe(channel):
                received[idx].append(body)
                count += 1
                if count >= n_msgs:
                    return

        consumers = [asyncio.create_task(consumer(i)) for i in range(n_subs)]
        # Wait until every consumer has registered its queue.
        while broker.subscriber_count(channel) < n_subs:
            await asyncio.sleep(0.005)

        for seq in range(n_msgs):
            await broker.publish(channel, {"sequence": seq})

        await asyncio.wait_for(asyncio.gather(*consumers), timeout=5)
        # Every subscriber saw every message, in order.
        for got in received:
            assert [m["sequence"] for m in got] == list(range(n_msgs))
        # Queues cleaned up after the async generators closed.
        assert broker.subscriber_count(channel) == 0

    asyncio.run(scenario())
