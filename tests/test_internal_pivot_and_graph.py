"""Internal-pivot tool YAMLs + workspace graph endpoint."""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
API_DIR = REPO / "apps" / "api"
sys.path.insert(0, str(API_DIR))


# ---------- Tool registry: impacket family + netexec ------------------------


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("TOOL_REGISTRY_DIR", str(REPO / "packages/tool-registry/tools"))
    monkeypatch.setenv("PROFILE_REGISTRY_DIR", str(REPO / "packages/tool-registry/profiles"))
    monkeypatch.setenv("PLATFORM_CONFIG_PATH",
                       str(REPO / "packages/platform-config/sniper-inspired.yaml"))
    monkeypatch.setenv("GREP_PATTERNS_PATH",
                       str(REPO / "packages/patterns/sniper-grep-patterns.yaml"))
    monkeypatch.setenv("WORDLISTS_DIR", str(REPO / "packages/wordlists"))
    monkeypatch.setenv("DATABASE_URL", "sqlite:///./reconforge-pivot-test.db")
    monkeypatch.setenv("ARTIFACT_BACKEND", "local")
    monkeypatch.setenv("ARTIFACT_DIR", "./artifacts")
    monkeypatch.setenv("EXECUTION_MODE", "dry_run")
    monkeypatch.setenv("ALLOW_LIVE_EXECUTION", "false")
    monkeypatch.setenv("RUNNER_MODE", "in_process")
    monkeypatch.setenv("RECONFORGE_BOOTSTRAP_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("RECONFORGE_BOOTSTRAP_ADMIN_PASSWORD", "admin-passw0rd")
    monkeypatch.setenv("RECONFORGE_TEST_AUTH_BYPASS", "1")
    from app.core.config import get_settings
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


PIVOT_TOOLS = {
    "impacket_secretsdump", "impacket_smbexec", "impacket_psexec",
    "impacket_wmiexec", "impacket_getuserspns", "netexec",
}


def test_pivot_tools_load_and_validate():
    from app.services.tool_registry import ToolRegistry
    from app.core.config import get_settings
    s = get_settings()
    reg = ToolRegistry(s.tool_registry_dir, s.profile_registry_dir)
    ids = {t.id for t in reg.list_tools()}
    missing = PIVOT_TOOLS - ids
    assert not missing, f"pivot tools missing from registry: {missing}"

    # Every pivot tool MUST be high_active + requires_authorization=True
    for tid in PIVOT_TOOLS:
        tool = reg.get_tool(tid)
        assert str(tool.risk).endswith("high_active"), \
            f"{tid} should be high_active, got {tool.risk!r}"
        assert tool.requires_authorization is True, \
            f"{tid} should require_authorization=True"


def test_internal_pivot_profile_resolves():
    from app.services.tool_registry import ToolRegistry
    from app.core.config import get_settings
    s = get_settings()
    reg = ToolRegistry(s.tool_registry_dir, s.profile_registry_dir)
    profile = reg.get_profile("internal_pivot")
    assert profile["risk"] == "high_active"
    step_tools = {step["tool"] for step in profile["steps"]}
    assert step_tools <= PIVOT_TOOLS, f"profile references unknown tool: {step_tools - PIVOT_TOOLS}"


def test_pivot_tool_argv_renders_cleanly():
    from app.services.runner import render_argv
    from app.services.tool_registry import ToolRegistry
    from app.core.config import get_settings
    s = get_settings()
    reg = ToolRegistry(s.tool_registry_dir, s.profile_registry_dir)
    for tid in PIVOT_TOOLS:
        tool = reg.get_tool(tid)
        rendered = render_argv(tool.command["argv"], {"target": "10.0.0.5"})
        assert "{{" not in " ".join(rendered)
        bin_name = tool.binary or tid
        assert any(bin_name == tok or bin_name in tok for tok in rendered), \
            f"{tid} argv {rendered} missing binary {bin_name!r}"


# ---------- Workspace graph endpoint ----------------------------------------


@pytest.fixture
def stack(tmp_path, monkeypatch):
    db_path = tmp_path / "graph.db"
    art_dir = tmp_path / "artifacts"
    art_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("ARTIFACT_DIR", str(art_dir))

    from conftest import rebind_engine_to_database_url
    rebind_engine_to_database_url()

    from fastapi.testclient import TestClient
    from app.main import app
    headers = {"X-Test-User": "admin"}
    with TestClient(app) as client:
        yield client, headers
    from app.core.config import get_settings
    get_settings.cache_clear()


def test_graph_404_for_unknown_workspace(stack):
    client, headers = stack
    assert client.get("/api/workspaces/nope/graph",
                       headers=headers).status_code == 404


def test_graph_anonymous_blocked(stack):
    client, _ = stack
    assert client.get("/api/workspaces/x/graph").status_code == 401


def test_graph_empty_workspace(stack):
    client, headers = stack
    ws_id = client.get("/api/workspaces", headers=headers).json()[0]["id"]
    body = client.get(f"/api/workspaces/{ws_id}/graph", headers=headers).json()
    assert "nodes" in body and "edges" in body
    # Demo seed creates one target, so we expect that target node at minimum
    assert any(n["kind"] == "target" for n in body["nodes"])
    assert body["truncated"] is False


def test_graph_builds_target_domain_url_finding_chain(stack):
    """End-to-end: create a target, run passive_recon (dry), insert a few url
    + ip assets and a finding, then assert the graph wires them up correctly."""
    client, headers = stack
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
    else:
        raise AssertionError(f"run {run['id']} did not complete in 90s")

    # Inject some structured rows directly: the dry-run normalizer creates
    # plain domain assets; we want to add a url + ip + finding to exercise
    # the cross-edge logic.
    from app.db import engine
    from app.models import Asset, Finding
    from sqlmodel import Session
    with Session(engine) as session:
        session.add(Asset(workspace_id=ws_id, run_id=run["id"], type="ip",
                           value="10.0.0.5", source="dnsx",
                           meta={}))
        session.add(Asset(workspace_id=ws_id, run_id=run["id"], type="url",
                           value="https://api.lab.example.com/v1/users",
                           source="httpx",
                           meta={"json": {"ip": "10.0.0.5", "title": "Users API"}}))
        # ensure the host of the url exists as a domain asset
        session.add(Asset(workspace_id=ws_id, run_id=run["id"], type="domain",
                           value="api.lab.example.com", source="subfinder",
                           meta={}))
        session.add(Finding(
            workspace_id=ws_id, run_id=run["id"],
            title="exposed admin endpoint", severity="high",
            category="exposure", evidence="https://api.lab.example.com/admin",
            tool_source="nuclei",
        ))
        session.commit()

    body = client.get(f"/api/workspaces/{ws_id}/graph", headers=headers).json()
    nodes = {n["id"]: n for n in body["nodes"]}
    edges = body["edges"]

    # Target node present
    assert "target:lab.example.com" in nodes
    # Domain hangs off target
    assert "domain:api.lab.example.com" in nodes
    assert any(e["source"] == "target:lab.example.com"
               and e["target"] == "domain:api.lab.example.com"
               and e["kind"] == "owns" for e in edges)
    # URL hangs off domain
    assert "url:https://api.lab.example.com/v1/users" in nodes
    assert any(e["source"] == "domain:api.lab.example.com"
               and e["target"] == "url:https://api.lab.example.com/v1/users"
               and e["kind"] == "hosts" for e in edges)
    # URL resolves to IP
    assert "ip:10.0.0.5" in nodes
    assert any(e["source"] == "url:https://api.lab.example.com/v1/users"
               and e["target"] == "ip:10.0.0.5"
               and e["kind"] == "resolves_to" for e in edges)
    # Finding hangs off target
    finding_ids = [n["id"] for n in body["nodes"] if n["kind"] == "finding"]
    assert finding_ids, "expected at least one finding node"
    assert any(e["source"] == "target:lab.example.com"
               and e["target"] in finding_ids
               and e["kind"] == "finds" for e in edges)
    # Centrality computed (non-zero for at least the target hub)
    target_node = nodes["target:lab.example.com"]
    assert target_node["centrality"] > 0


def test_graph_truncates_when_over_max(stack):
    client, headers = stack
    ws_id = client.get("/api/workspaces", headers=headers).json()[0]["id"]
    # Insert 80 isolated url assets so the graph has lots of low-degree leaves.
    from app.db import engine
    from app.models import Asset, Run, Target
    from sqlmodel import Session
    with Session(engine) as session:
        # Need a Target + Run for the workspace so url assets have a parent
        # edge candidate; the test mostly cares about node-count truncation.
        target = Target(workspace_id=ws_id, value="busy.example.com",
                         type="domain", in_scope=True,
                         passive_allowed=True, active_allowed=False)
        session.add(target); session.commit(); session.refresh(target)
        for i in range(80):
            session.add(Asset(workspace_id=ws_id, type="url",
                               value=f"https://x{i}.busy.example.com/p",
                               source="test", meta={}))
        session.commit()

    body = client.get(f"/api/workspaces/{ws_id}/graph?max_nodes=20",
                       headers=headers).json()
    assert body["truncated"] is True
    assert body["stats"]["node_count"] <= 20
    # Targets always survive truncation
    assert any(n["kind"] == "target" for n in body["nodes"])
