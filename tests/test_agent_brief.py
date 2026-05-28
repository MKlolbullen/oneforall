"""Agent-facing run brief: GET /api/agent/runs/{id}/brief.

A bounded, deterministic snapshot for external agents — run metadata, steps,
severity-ranked findings, assets by type, artifact fetch URLs, and loot summary.
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
    db_path = tmp_path / "agent.db"
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


def _seed_run_with_data(client, headers):
    from app.db import engine
    from app.models import (Asset, Finding, Run, RunStatus, RunStep, StepStatus, Target)
    from sqlmodel import Session
    ws_id = client.get("/api/workspaces", headers=headers).json()[0]["id"]
    with Session(engine) as session:
        target = Target(workspace_id=ws_id, value="brief.example.com", type="domain")
        session.add(target)
        session.commit()
        session.refresh(target)
        run = Run(workspace_id=ws_id, target_id=target.id, profile_id="passive_recon",
                  status=RunStatus.completed)
        session.add(run)
        session.commit()
        session.refresh(run)
        session.add(RunStep(run_id=run.id, workspace_id=ws_id, tool_id="subfinder",
                            tool_name="subfinder", index=0, status=StepStatus.completed))
        session.add(Asset(workspace_id=ws_id, run_id=run.id, type="domain",
                          value="api.brief.example.com", source="subfinder"))
        session.add(Asset(workspace_id=ws_id, run_id=run.id, type="url",
                          value="https://api.brief.example.com/v1", source="httpx"))
        session.add(Finding(workspace_id=ws_id, run_id=run.id,
                            title="Apache RCE CVE-2017-5638", severity="critical",
                            category="rce", evidence="boom", tool_source="nuclei"))
        session.add(Finding(workspace_id=ws_id, run_id=run.id,
                            title="robots.txt", severity="info", category="info",
                            evidence="", tool_source="httpx"))
        session.commit()
        return ws_id, target.id, run.id


def test_brief_anonymous_blocked(stack):
    client, _ = stack
    assert client.get("/api/agent/runs/whatever/brief").status_code == 401


def test_brief_404_unknown_run(stack):
    client, headers = stack
    assert client.get("/api/agent/runs/nope/brief", headers=headers).status_code == 404


def test_brief_shape_and_contents(stack):
    client, headers = stack
    ws_id, target_id, run_id = _seed_run_with_data(client, headers)
    body = client.get(f"/api/agent/runs/{run_id}/brief", headers=headers).json()

    # Top-level shape
    assert set(body.keys()) >= {
        "run", "target", "counts", "findings_by_severity",
        "steps", "findings", "assets_by_type", "artifacts", "loot",
    }
    assert body["run"]["id"] == run_id
    assert body["run"]["profile_id"] == "passive_recon"
    assert body["target"]["value"] == "brief.example.com"

    # Counts
    assert body["counts"]["findings"] == 2
    assert body["counts"]["assets"] == 2
    assert body["counts"]["steps"] == 1

    # Findings severity-ranked: critical before info
    sevs = [f["severity"] for f in body["findings"]]
    assert sevs[0] == "critical"
    assert body["findings_by_severity"]["critical"] == 1
    assert body["findings_by_severity"]["info"] == 1

    # Assets grouped by type
    assert set(body["assets_by_type"].keys()) == {"domain", "url"}

    # Loot auto-indexed from findings: the RCE is loot, robots.txt is not.
    assert body["loot"]["total"] == 1
    assert body["loot"]["by_kind"] == {"vulnerability": 1}


def test_brief_artifact_refs_have_content_url(stack):
    client, headers = stack
    _ws_id, _tid, run_id = _seed_run_with_data(client, headers)
    from app.db import engine
    from app.models import Artifact
    from sqlmodel import Session
    with Session(engine) as session:
        session.add(Artifact(workspace_id=_ws_id, run_id=run_id, name="out.txt",
                            type="text", path="/tmp/out.txt", size_bytes=10))
        session.commit()
    body = client.get(f"/api/agent/runs/{run_id}/brief", headers=headers).json()
    assert body["artifacts"], "expected at least one artifact ref"
    ref = body["artifacts"][0]
    assert ref["content_url"] == f"/api/artifacts/{ref['id']}/content"
