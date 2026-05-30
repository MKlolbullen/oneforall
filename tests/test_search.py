"""Cross-entity search — GET /api/search?q=...

The palette UI fans all categories through this one endpoint, so the test
fixture seeds at least one matchable row of every type and checks the
expected hits surface in their bucket.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
API_DIR = REPO / "apps" / "api"
sys.path.insert(0, str(API_DIR))


@pytest.fixture
def stack(tmp_path, monkeypatch):
    db_path = tmp_path / "search.db"
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


def _seed_everything(client, headers):
    """Insert one needle row for every searchable entity type. Uses 'acmecorp'
    as the shared needle so a single query covers them all."""
    from app.db import engine
    from app.models import Finding, LootItem, Run, RunStatus, Target, Workflow
    from sqlmodel import Session
    ws_id = client.get("/api/workspaces", headers=headers).json()[0]["id"]
    with Session(engine) as session:
        target = Target(workspace_id=ws_id, value="acmecorp.example.com", type="domain")
        session.add(target)
        session.commit()
        session.refresh(target)
        run = Run(workspace_id=ws_id, target_id=target.id, profile_id="passive_recon",
                  status=RunStatus.completed)
        session.add(run)
        session.commit()
        session.refresh(run)
        finding = Finding(workspace_id=ws_id, run_id=run.id,
                          title="acmecorp internal SSO exposed", severity="high",
                          category="exposure", evidence="…", tool_source="nuclei")
        session.add(finding)
        session.commit()
        session.refresh(finding)
        session.add(LootItem(workspace_id=ws_id, run_id=run.id, finding_id=finding.id,
                             kind="exposure", label="acmecorp SSO leak", severity="high",
                             host="sso.acmecorp.example.com", source_tool="nuclei"))
        session.add(Workflow(workspace_id=ws_id, name="acmecorp daily sweep",
                             description="", body={"steps": [{"tool": "subfinder"}]}))
        session.commit()
    # Webhook is created via API so the audit row exists and is_active defaults true.
    client.post("/api/webhooks", headers=headers, json={
        "workspace_id": ws_id, "name": "acmecorp-slack",
        "url": "https://example.com/hook", "events": ["run.completed"],
    })
    return ws_id


def test_search_anonymous_blocked(stack):
    client, _ = stack
    assert client.get("/api/search?q=acme").status_code == 401


def test_search_empty_query_rejected(stack):
    client, headers = stack
    # Empty q fails the min_length=1 validator → 422
    r = client.get("/api/search?q=", headers=headers)
    assert r.status_code == 422


def test_search_returns_shape_with_all_buckets(stack):
    client, headers = stack
    _seed_everything(client, headers)
    body = client.get("/api/search?q=acmecorp", headers=headers).json()
    assert body["q"] == "acmecorp"
    # Bucket shape contract — every key always present so the UI can render
    # empty groups uniformly.
    for key in ("targets", "runs", "findings", "loot", "workflows",
                "workspaces", "webhooks", "tools", "profiles"):
        assert key in body, f"missing bucket {key!r}"


def test_search_finds_seeded_rows(stack):
    client, headers = stack
    _seed_everything(client, headers)
    body = client.get("/api/search?q=acmecorp", headers=headers).json()
    assert any(t["value"] == "acmecorp.example.com" for t in body["targets"])
    assert any("acmecorp" in f["title"] for f in body["findings"])
    assert any("acmecorp" in i["label"] for i in body["loot"])
    assert any("acmecorp" in w["name"] for w in body["workflows"])
    assert any("acmecorp" in w["name"] for w in body["webhooks"])


def test_search_matches_tool_registry(stack):
    client, headers = stack
    # 'subfinder' is a registry tool with that exact id — verifies the
    # in-memory tool/profile search path works alongside DB results.
    body = client.get("/api/search?q=subfinder", headers=headers).json()
    assert any(t["id"] == "subfinder" for t in body["tools"])


def test_search_workspace_scope_filters(stack):
    """Same needle scoped to a non-matching workspace returns no DB rows."""
    client, headers = stack
    ws_id = _seed_everything(client, headers)
    # Create a second workspace; search scoped there must NOT see the seeded
    # rows (registry tool/profile hits are global by design — they're not
    # workspace-scoped resources).
    other = client.post("/api/workspaces", headers=headers,
                        json={"name": "Other"}).json()
    body = client.get(f"/api/search?q=acmecorp&workspace_id={other['id']}",
                      headers=headers).json()
    assert body["targets"] == []
    assert body["findings"] == []
    assert body["loot"] == []
    assert body["workflows"] == []
    # First-workspace query still returns hits
    body2 = client.get(f"/api/search?q=acmecorp&workspace_id={ws_id}",
                       headers=headers).json()
    assert body2["targets"]


def test_search_caps_per_category(stack):
    """`limit` query caps each bucket — important for the palette UX so the
    modal never has to scroll for hundreds of weak matches."""
    client, headers = stack
    # Seed 20 targets matching the needle so the limit can clamp them down.
    ws_id = client.get("/api/workspaces", headers=headers).json()[0]["id"]
    for i in range(20):
        client.post("/api/targets", headers=headers, json={
            "workspace_id": ws_id, "value": f"scan{i}.searchtest.example.com",
            "type": "domain", "in_scope": True,
        })
    body = client.get("/api/search?q=searchtest&limit=5", headers=headers).json()
    assert len(body["targets"]) == 5


def test_search_like_metacharacters_escaped(stack):
    """A '%' in the query must not act as a wildcard (regression check on
    _escape_like). A '%' won't match the seeded target whose value contains no
    literal percent sign."""
    client, headers = stack
    _seed_everything(client, headers)
    # Search for "%cme%" (literal percent + cme + literal percent) — should
    # only match a row containing literally `%cme%`, which we never seeded.
    body = client.get("/api/search?q=%25cme%25", headers=headers).json()
    assert body["targets"] == [], body["targets"]
