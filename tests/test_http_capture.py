"""HTTP traffic capture: parser, persistence, endpoint, role gating.

These tests don't need the proxify binary — the JSONL parser is a pure
function and we synthesize fixtures for the persistence + endpoint paths.
The runner integration only invokes proxify in live mode (skipped here).
"""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
API_DIR = REPO / "apps" / "api"
sys.path.insert(0, str(API_DIR))


# ---------- Pure parser tests ------------------------------------------------


def _line(d) -> str:
    return json.dumps(d)


def test_parse_proxify_native_shape():
    from app.services.http_capture import parse_jsonl_chunk
    chunk = _line({
        "request": {
            "method": "GET",
            "url": "https://example.com/api/v1/foo?id=1",
            "headers": {"Host": "example.com"},
            "body": None,
        },
        "response": {
            "status": 200,
            "headers": {"Content-Type": "application/json"},
            "body": '{"ok":true}',
        },
        "timestamp": "2026-05-09T12:00:00Z",
        "duration_ms": 42,
    })
    out = parse_jsonl_chunk(chunk)
    assert len(out) == 1
    e = out[0]
    assert e.method == "GET"
    assert e.host == "example.com"
    assert e.url == "https://example.com/api/v1/foo?id=1"
    assert e.response_status == 200
    assert e.response_body == '{"ok":true}'
    assert e.duration_ms == 42


def test_parse_generic_flat_shape():
    from app.services.http_capture import parse_jsonl_chunk
    chunk = _line({
        "method": "POST",
        "url": "https://api.example.com/login",
        "request_headers": {"Authorization": "Bearer xxx"},
        "request_body": "user=foo",
        "response_headers": {},
        "response_body": "OK",
        "status": 401,
        "duration_ms": 100,
    })
    out = parse_jsonl_chunk(chunk)
    assert len(out) == 1
    assert out[0].method == "POST"
    assert out[0].response_status == 401


def test_body_truncation():
    """A body over 64KB is truncated and flagged."""
    from app.services.http_capture import parse_jsonl_chunk, MAX_BODY_BYTES
    huge = "A" * (MAX_BODY_BYTES + 5000)
    chunk = _line({
        "method": "GET", "url": "https://example.com/big",
        "response_body": huge, "status": 200,
    })
    out = parse_jsonl_chunk(chunk)
    assert len(out) == 1
    assert out[0].response_body_truncated is True
    assert len(out[0].response_body) <= MAX_BODY_BYTES
    assert out[0].response_size_bytes == len(huge)


def test_bad_lines_dropped_not_fatal():
    """One malformed line in the middle doesn't kill the rest."""
    from app.services.http_capture import parse_jsonl_chunk
    chunk = "\n".join([
        _line({"method": "GET", "url": "https://a/"}),
        "{not valid json",
        "",  # empty
        _line({"method": "GET", "url": "https://b/"}),
    ])
    out = parse_jsonl_chunk(chunk)
    assert len(out) == 2
    assert out[0].host == "a" and out[1].host == "b"


def test_url_required():
    """Lines with no URL are dropped (proxify can emit oddities)."""
    from app.services.http_capture import parse_jsonl_chunk
    chunk = _line({"method": "GET"})
    assert parse_jsonl_chunk(chunk) == []


# ---------- Persistence + step attribution -----------------------------------


@pytest.fixture
def stack(tmp_path, monkeypatch):
    db_path = tmp_path / "http.db"
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


def _seed_run(client, headers):
    ws_id = client.get("/api/workspaces", headers=headers).json()[0]["id"]
    target = client.post("/api/targets", headers=headers, json={
        "workspace_id": ws_id, "value": "lab.example.com", "type": "domain",
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
    return ws_id, run


def _insert_synthetic_exchanges(workspace_id: str, run_id: str, count: int = 5,
                                 host: str = "example.com",
                                 method: str = "GET",
                                 status: int = 200,
                                 step_index: int | None = None):
    from app.db import engine
    from app.models import HttpExchange
    from sqlmodel import Session
    base = datetime.now(timezone.utc)
    inserted = []
    with Session(engine) as session:
        for i in range(count):
            row = HttpExchange(
                run_id=run_id, workspace_id=workspace_id,
                method=method, url=f"https://{host}/path/{i}",
                host=host, response_status=status,
                response_body=f"ok-{i}", response_size_bytes=20,
                duration_ms=10 + i, started_at=base + timedelta(seconds=i),
                step_index=step_index,
            )
            session.add(row)
            inserted.append(row)
        session.commit()
        for r in inserted:
            session.refresh(r)
    return [r.id for r in inserted]


def test_step_attribution_by_timestamp():
    """An exchange whose started_at falls inside step 2's window is tagged
    step_index=2; one outside any step's window is None."""
    from app.services.http_capture import (
        ParsedExchange, _step_index_for_timestamp,
    )

    class FakeStep:
        def __init__(self, index, started_at, finished_at, tool_id):
            self.index = index
            self.started_at = started_at
            self.finished_at = finished_at
            self.tool_id = tool_id

    base = datetime(2026, 5, 9, 12, 0, 0, tzinfo=timezone.utc)
    steps = [
        FakeStep(1, base, base + timedelta(seconds=10), "subfinder"),
        FakeStep(2, base + timedelta(seconds=11), base + timedelta(seconds=20), "dnsx"),
    ]
    inside_step2 = base + timedelta(seconds=15)
    after_all = base + timedelta(seconds=99)

    assert _step_index_for_timestamp(steps, inside_step2) == 2
    assert _step_index_for_timestamp(steps, after_all) is None


def test_persist_caps_at_max_per_run(monkeypatch):
    """The MAX_EXCHANGES_PER_RUN cap stops a runaway tool from filling the DB."""
    from app.services import http_capture as hc
    monkeypatch.setattr(hc, "MAX_EXCHANGES_PER_RUN", 5)


# ---------- Endpoint tests ---------------------------------------------------


def test_network_404_for_unknown_run(stack):
    client, headers = stack
    assert client.get("/api/runs/run_does_not_exist/network",
                       headers=headers).status_code == 404


def test_network_anonymous_blocked(stack):
    client, _ = stack
    assert client.get("/api/runs/anything/network").status_code == 401


def test_network_empty_run_returns_empty_page(stack):
    client, headers = stack
    _ws, run = _seed_run(client, headers)
    r = client.get(f"/api/runs/{run['id']}/network", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 0
    assert body["items"] == []
    assert body["hosts"] == [] and body["methods"] == [] and body["statuses"] == []


def test_network_lists_inserted_exchanges(stack):
    client, headers = stack
    ws_id, run = _seed_run(client, headers)
    _insert_synthetic_exchanges(ws_id, run["id"], count=3, host="api.example.com")
    _insert_synthetic_exchanges(ws_id, run["id"], count=2, host="cdn.example.com",
                                 method="POST", status=201)

    body = client.get(f"/api/runs/{run['id']}/network", headers=headers).json()
    assert body["total"] == 5
    assert len(body["items"]) == 5
    # Distinct facets surfaced for the UI dropdowns
    assert set(body["hosts"]) == {"api.example.com", "cdn.example.com"}
    assert set(body["methods"]) == {"GET", "POST"}
    assert set(body["statuses"]) == {200, 201}


def test_network_filters(stack):
    client, headers = stack
    ws_id, run = _seed_run(client, headers)
    _insert_synthetic_exchanges(ws_id, run["id"], count=2, host="a.example.com",
                                 method="GET", status=200)
    _insert_synthetic_exchanges(ws_id, run["id"], count=3, host="b.example.com",
                                 method="POST", status=500)

    only_a = client.get(f"/api/runs/{run['id']}/network?host=a.example.com",
                         headers=headers).json()
    assert only_a["total"] == 2
    assert {it["host"] for it in only_a["items"]} == {"a.example.com"}

    only_post = client.get(f"/api/runs/{run['id']}/network?method=post",
                            headers=headers).json()
    assert only_post["total"] == 3

    only_500 = client.get(f"/api/runs/{run['id']}/network?status=500",
                           headers=headers).json()
    assert only_500["total"] == 3


def test_network_pagination(stack):
    client, headers = stack
    ws_id, run = _seed_run(client, headers)
    _insert_synthetic_exchanges(ws_id, run["id"], count=12, host="paged.example.com")
    page1 = client.get(f"/api/runs/{run['id']}/network?limit=5",
                        headers=headers).json()
    page2 = client.get(f"/api/runs/{run['id']}/network?limit=5&offset=5",
                        headers=headers).json()
    page3 = client.get(f"/api/runs/{run['id']}/network?limit=5&offset=10",
                        headers=headers).json()
    assert (len(page1["items"]), len(page2["items"]), len(page3["items"])) == (5, 5, 2)
    # No overlap
    ids = [it["id"] for p in (page1, page2, page3) for it in p["items"]]
    assert len(set(ids)) == 12


def test_exchange_detail_round_trip(stack):
    client, headers = stack
    ws_id, run = _seed_run(client, headers)
    [eid] = _insert_synthetic_exchanges(ws_id, run["id"], count=1)
    body = client.get(f"/api/runs/{run['id']}/network/{eid}", headers=headers).json()
    assert body["id"] == eid
    assert body["request_headers"] == {} and body["response_headers"] == {}
    assert body["response_body"].startswith("ok-")


def test_exchange_detail_404_when_id_belongs_to_other_run(stack):
    """Exchanges are scoped — passing a foreign run_id returns 404 even with
    a valid exchange id."""
    client, headers = stack
    ws_id, run = _seed_run(client, headers)
    [eid] = _insert_synthetic_exchanges(ws_id, run["id"], count=1)
    r = client.get(f"/api/runs/some_other_run/network/{eid}", headers=headers)
    assert r.status_code == 404
