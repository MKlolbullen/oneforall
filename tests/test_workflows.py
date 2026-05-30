"""Saved Workflows: CRUD + launch via /api/workflows.

Covers:
  - POST /api/workflows by an operator persists + audits + returns the row
  - validation: 404 on unknown tool / unknown workspace
  - PUT by owner OR admin is allowed; non-owner non-admin is 403
  - DELETE same rule
  - POST /api/workflows/{id}/launch builds a run that completes in dry mode
    and reaches the agent brief with profile_id=adhoc
  - launching with a target in the wrong workspace is rejected (400)
  - scope violation surfaces as 403 just like ad-hoc runs
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
    db_path = tmp_path / "wf.db"
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


def _seed_target(client, headers, value="wf.example.com", active=True):
    ws_id = client.get("/api/workspaces", headers=headers).json()[0]["id"]
    target = client.post("/api/targets", headers=headers, json={
        "workspace_id": ws_id, "value": value, "type": "domain",
        "in_scope": True, "passive_allowed": True, "active_allowed": active,
    }).json()
    return ws_id, target


def test_create_list_get_workflow(stack):
    client, headers = stack
    ws_id, _ = _seed_target(client, headers)

    r = client.post("/api/workflows", headers=headers, json={
        "workspace_id": ws_id,
        "name": "Passive sweep",
        "description": "subfinder + dnsx",
        "body": {
            "steps": [{"tool": "subfinder"}, {"tool": "dnsx"}],
            "graph": {"nodes": [], "edges": []},
        },
    })
    assert r.status_code == 201, r.text
    wf = r.json()
    assert wf["name"] == "Passive sweep"
    assert wf["body"]["steps"] == [{"tool": "subfinder"}, {"tool": "dnsx"}]

    # List shows it; GET by id matches.
    listing = client.get("/api/workflows", headers=headers).json()
    assert any(row["id"] == wf["id"] for row in listing)
    one = client.get(f"/api/workflows/{wf['id']}", headers=headers).json()
    assert one["id"] == wf["id"]

    # Audit row recorded.
    audit = client.get("/api/auth/audit", headers=headers).json()
    assert any(e["action"] == "workflow.created" for e in audit["events"])


def test_create_workflow_unknown_tool_404(stack):
    client, headers = stack
    ws_id, _ = _seed_target(client, headers)
    r = client.post("/api/workflows", headers=headers, json={
        "workspace_id": ws_id, "name": "bad",
        "body": {"steps": [{"tool": "definitely-not-a-real-tool"}]},
    })
    assert r.status_code == 404


def test_create_workflow_unknown_workspace_404(stack):
    client, headers = stack
    r = client.post("/api/workflows", headers=headers, json={
        "workspace_id": "ws_nope", "name": "x",
        "body": {"steps": [{"tool": "subfinder"}]},
    })
    assert r.status_code == 404


def _wait_completed(client, headers, run_id, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        body = client.get(f"/api/runs/{run_id}", headers=headers).json()
        if body["status"] in {"completed", "failed", "cancelled"}:
            return body
        time.sleep(0.25)
    raise AssertionError(f"run {run_id} did not complete in {timeout}s")


def test_launch_workflow_completes_dry_run(stack):
    client, headers = stack
    ws_id, target = _seed_target(client, headers)
    wf = client.post("/api/workflows", headers=headers, json={
        "workspace_id": ws_id, "name": "Quick",
        "body": {"steps": [{"tool": "subfinder"}]},
    }).json()

    r = client.post(f"/api/workflows/{wf['id']}/launch", headers=headers,
                    json={"target_id": target["id"]})
    assert r.status_code == 201, r.text
    run = r.json()
    assert run["profile_id"] == "adhoc"

    final = _wait_completed(client, headers, run["id"])
    assert final["status"] == "completed"

    brief = client.get(f"/api/agent/runs/{run['id']}/brief", headers=headers).json()
    assert brief["counts"]["steps"] == 1
    # The workflow_id round-trips through config_snapshot, so the brief
    # implicitly proves it (steps were executed and persisted).
    audit = client.get("/api/auth/audit", headers=headers).json()
    assert any(e["action"] == "workflow.launched" for e in audit["events"])


def test_launch_workflow_wrong_workspace_400(stack):
    client, headers = stack
    ws_id, target = _seed_target(client, headers)
    # Make a second workspace + workflow scoped to it
    other_ws = client.post("/api/workspaces", headers=headers,
                           json={"name": "Other"}).json()
    wf = client.post("/api/workflows", headers=headers, json={
        "workspace_id": other_ws["id"], "name": "Foreign",
        "body": {"steps": [{"tool": "subfinder"}]},
    }).json()
    r = client.post(f"/api/workflows/{wf['id']}/launch", headers=headers,
                    json={"target_id": target["id"]})
    assert r.status_code == 400


def test_launch_workflow_scope_violation_403(stack):
    client, headers = stack
    ws_id, target = _seed_target(client, headers, value="passive-only.example.com", active=False)
    wf = client.post("/api/workflows", headers=headers, json={
        "workspace_id": ws_id, "name": "Active",
        "body": {"steps": [{"tool": "httpx"}]},
    }).json()
    r = client.post(f"/api/workflows/{wf['id']}/launch", headers=headers,
                    json={"target_id": target["id"]})
    assert r.status_code == 403


def test_update_workflow_owner_or_admin(stack):
    client, headers = stack
    ws_id, _ = _seed_target(client, headers)
    wf = client.post("/api/workflows", headers=headers, json={
        "workspace_id": ws_id, "name": "v1",
        "body": {"steps": [{"tool": "subfinder"}]},
    }).json()
    # Admin (owner here) can update.
    r = client.put(f"/api/workflows/{wf['id']}", headers=headers,
                   json={"name": "v2"})
    assert r.status_code == 200, r.text
    assert r.json()["name"] == "v2"

    # Operator-other tries to edit admin's workflow -> 403.
    admin_token = client.post("/api/auth/login",
                              json={"username": "admin", "password": "admin-passw0rd"}).json()["token"]
    client.post("/api/auth/users",
                headers={"Authorization": f"Bearer {admin_token}"},
                json={"username": "op", "password": "op-secret-1", "role": "operator"})
    op_token = client.post("/api/auth/login",
                           json={"username": "op", "password": "op-secret-1"}).json()["token"]
    r = client.put(f"/api/workflows/{wf['id']}",
                   headers={"Authorization": f"Bearer {op_token}"},
                   json={"name": "v3"})
    assert r.status_code == 403


def test_delete_workflow(stack):
    client, headers = stack
    ws_id, _ = _seed_target(client, headers)
    wf = client.post("/api/workflows", headers=headers, json={
        "workspace_id": ws_id, "name": "doomed",
        "body": {"steps": [{"tool": "subfinder"}]},
    }).json()
    r = client.delete(f"/api/workflows/{wf['id']}", headers=headers)
    assert r.status_code == 204
    assert client.get(f"/api/workflows/{wf['id']}", headers=headers).status_code == 404


def test_workflows_anonymous_blocked(stack):
    client, _ = stack
    assert client.get("/api/workflows").status_code == 401
    assert client.post("/api/workflows", json={"workspace_id": "x", "name": "y",
                                                "body": {"steps": [{"tool": "subfinder"}]}}).status_code == 401


# ----- Export / import round-trip ----------------------------------------

def test_export_workflow_yaml_roundtrips(stack):
    """A workflow saved to one instance can be exported, then imported into
    the same (or another) instance via /workflows/import. Step count, name,
    description, and the canvas graph all survive."""
    import yaml as _yaml
    client, headers = stack
    ws_id, _ = _seed_target(client, headers)

    orig = client.post("/api/workflows", headers=headers, json={
        "workspace_id": ws_id, "name": "Quick passive",
        "description": "subfinder + dnsx + httpx",
        "body": {
            "steps": [
                {"tool": "subfinder"},
                {"tool": "dnsx", "argv_extra": ["-l", "{{upstream.domain_list.merged_path}}"]},
                {"tool": "httpx", "timeout_seconds": 600},
            ],
            "graph": {"nodes": [{"id": "n1"}], "edges": []},
        },
    }).json()

    # Export YAML
    r = client.get(f"/api/workflows/{orig['id']}/export", headers=headers)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/yaml")
    doc = _yaml.safe_load(r.text)
    assert doc["schema"] == "reconforge.workflow/v1"
    assert doc["name"] == "Quick passive"
    assert len(doc["steps"]) == 3
    assert doc["steps"][1]["argv_extra"] == ["-l", "{{upstream.domain_list.merged_path}}"]
    assert "graph" in doc

    # Import it back as a NEW workflow (server creates a new id; the doc's
    # name + description are honoured when no override is supplied).
    imported = client.post("/api/workflows/import", headers=headers, json={
        "workspace_id": ws_id, "yaml": r.text,
    }).json()
    assert imported["id"] != orig["id"]
    assert imported["name"] == "Quick passive"
    assert len(imported["body"]["steps"]) == 3
    # Audit row written
    audit = client.get("/api/auth/audit", headers=headers).json()
    assert any(e["action"] == "workflow.imported" for e in audit["events"])


def test_import_rejects_malformed_yaml(stack):
    client, headers = stack
    ws_id, _ = _seed_target(client, headers)
    # Unclosed quote → YAML parse error → 422.
    r = client.post("/api/workflows/import", headers=headers, json={
        "workspace_id": ws_id, "yaml": "name: oops\nsteps: [{",
    })
    assert r.status_code == 422


def test_import_rejects_missing_steps(stack):
    client, headers = stack
    ws_id, _ = _seed_target(client, headers)
    r = client.post("/api/workflows/import", headers=headers, json={
        "workspace_id": ws_id, "yaml": "name: just a name\n",
    })
    assert r.status_code == 422


def test_import_rejects_unknown_tool(stack):
    client, headers = stack
    ws_id, _ = _seed_target(client, headers)
    bad_yaml = "name: weird\nsteps:\n  - tool: definitely-not-a-real-tool\n"
    r = client.post("/api/workflows/import", headers=headers, json={
        "workspace_id": ws_id, "yaml": bad_yaml,
    })
    assert r.status_code == 404


def test_import_name_override(stack):
    """A caller can override the doc's name without editing the YAML — useful
    when forking a shared template into multiple per-engagement variants."""
    client, headers = stack
    ws_id, _ = _seed_target(client, headers)
    doc = "name: original\nsteps:\n  - tool: subfinder\n"
    r = client.post("/api/workflows/import", headers=headers, json={
        "workspace_id": ws_id, "yaml": doc, "name": "renamed-on-import",
    })
    assert r.status_code == 201
    assert r.json()["name"] == "renamed-on-import"


def test_export_404_unknown(stack):
    client, headers = stack
    assert client.get("/api/workflows/wf_nope/export", headers=headers).status_code == 404


def test_export_bad_format(stack):
    client, headers = stack
    ws_id, _ = _seed_target(client, headers)
    wf = client.post("/api/workflows", headers=headers, json={
        "workspace_id": ws_id, "name": "x",
        "body": {"steps": [{"tool": "subfinder"}]},
    }).json()
    r = client.get(f"/api/workflows/{wf['id']}/export?format=toml", headers=headers)
    assert r.status_code == 400


def test_import_anonymous_blocked(stack):
    client, _ = stack
    r = client.post("/api/workflows/import", json={
        "workspace_id": "x", "yaml": "name: a\nsteps:\n  - tool: subfinder\n",
    })
    assert r.status_code == 401
