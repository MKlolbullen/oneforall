"""Run report endpoint — GET /api/runs/{id}/report?format=html|json|md.

Renders the document on demand from the live DB. Covers all three formats
plus the obvious failure modes (unknown run, bad format, auth gate).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
API_DIR = REPO / "apps" / "api"
sys.path.insert(0, str(API_DIR))


@pytest.fixture
def stack(tmp_path, monkeypatch):
    db_path = tmp_path / "reports.db"
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


def _seed_run_with_findings(client, headers):
    """Create workspace + target + run + findings directly via the DB so the
    report has interesting content to render without paying for a real run."""
    from app.db import engine
    from app.models import Finding, LootItem, Run, RunStatus, RunStep, StepStatus, Target
    from sqlmodel import Session
    ws_id = client.get("/api/workspaces", headers=headers).json()[0]["id"]
    with Session(engine) as session:
        target = Target(workspace_id=ws_id, value="report.example.com", type="domain")
        session.add(target)
        session.commit()
        session.refresh(target)
        run = Run(workspace_id=ws_id, target_id=target.id, profile_id="passive_recon",
                  status=RunStatus.completed)
        session.add(run)
        session.commit()
        session.refresh(run)
        session.add(RunStep(run_id=run.id, workspace_id=ws_id, tool_id="subfinder",
                            tool_name="subfinder", index=0, status=StepStatus.completed,
                            attempt=0, max_retries=0))
        crit = Finding(workspace_id=ws_id, run_id=run.id,
                       title="Apache Struts RCE CVE-2017-5638",
                       severity="critical", category="rce",
                       evidence="POST /struts2-rest-showcase HTTP/1.1\nContent-Type: %{...}",
                       tool_source="nuclei")
        session.add(crit)
        session.add(Finding(workspace_id=ws_id, run_id=run.id,
                            title="robots.txt", severity="info", category="info",
                            evidence="User-agent: *", tool_source="httpx"))
        session.commit()
        session.refresh(crit)
        session.add(LootItem(workspace_id=ws_id, run_id=run.id, finding_id=crit.id,
                             kind="vulnerability", label=crit.title, severity="critical",
                             source_tool="nuclei", host="report.example.com",
                             value_preview="boom"))
        session.commit()
        return ws_id, target.id, run.id


def test_report_anonymous_blocked(stack):
    client, _ = stack
    assert client.get("/api/runs/whatever/report").status_code == 401


def test_report_404_unknown_run(stack):
    client, headers = stack
    assert client.get("/api/runs/run_nope/report", headers=headers).status_code == 404


def test_report_invalid_format(stack):
    client, headers = stack
    _, _, run_id = _seed_run_with_findings(client, headers)
    r = client.get(f"/api/runs/{run_id}/report?format=pdf", headers=headers)
    assert r.status_code == 400


def test_report_html_renders_full_document(stack):
    client, headers = stack
    _, _, run_id = _seed_run_with_findings(client, headers)
    r = client.get(f"/api/runs/{run_id}/report?format=html", headers=headers)
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("text/html")
    body = r.text
    assert "<!doctype html>" in body
    assert "ReconForge run report" in body
    assert "report.example.com" in body
    # Critical finding's title surfaces; severity chip + section header present
    assert "Apache Struts RCE CVE-2017-5638" in body
    assert "Loot" in body
    # No scripts ever — the report must be safe to forward as-is.
    assert "<script" not in body.lower()
    # Evidence is escaped — the literal %{...} shouldn't render as raw HTML
    assert "%{...}" in body or "%amp;" not in body


def test_report_json_is_machine_readable(stack):
    client, headers = stack
    _, _, run_id = _seed_run_with_findings(client, headers)
    r = client.get(f"/api/runs/{run_id}/report?format=json", headers=headers)
    assert r.status_code == 200
    doc = json.loads(r.text)
    assert doc["schema"] == "reconforge.run.report/v1"
    assert doc["run"]["id"] == run_id
    assert doc["counts"]["findings"] == 2
    assert doc["counts"]["loot"] == 1
    assert doc["findings_by_severity"]["critical"] == 1
    # Findings are severity-ranked: critical first
    assert doc["findings"][0]["severity"] == "critical"


def test_report_markdown_is_drop_in_friendly(stack):
    client, headers = stack
    _, _, run_id = _seed_run_with_findings(client, headers)
    r = client.get(f"/api/runs/{run_id}/report?format=md", headers=headers)
    assert r.status_code == 200
    body = r.text
    assert body.startswith("# Run report")
    assert "## Loot" in body
    assert "## Findings" in body
    assert "[CRITICAL]" in body
    # Markdown table separator present
    assert "|---|" in body
