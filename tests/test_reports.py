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


# ----- Target (engagement-level) reports ---------------------------------

def test_target_report_anonymous_blocked(stack):
    client, _ = stack
    assert client.get("/api/targets/whatever/report").status_code == 401


def test_target_report_404_unknown(stack):
    client, headers = stack
    r = client.get("/api/targets/tgt_nope/report", headers=headers)
    assert r.status_code == 404


def test_target_report_invalid_format(stack):
    client, headers = stack
    _, target_id, _ = _seed_run_with_findings(client, headers)
    r = client.get(f"/api/targets/{target_id}/report?format=pdf", headers=headers)
    assert r.status_code == 400


def test_target_report_aggregates_runs(stack):
    """Two runs against one target — the engagement report should union both
    runs' findings and report 2 runs in the header counts."""
    client, headers = stack
    ws_id, target_id, run1 = _seed_run_with_findings(client, headers)
    # Second run + finding under the SAME target
    from app.db import engine
    from app.models import Finding, Run, RunStatus
    from sqlmodel import Session
    with Session(engine) as session:
        run2 = Run(workspace_id=ws_id, target_id=target_id, profile_id="web_quick",
                   status=RunStatus.completed)
        session.add(run2)
        session.commit()
        session.refresh(run2)
        session.add(Finding(workspace_id=ws_id, run_id=run2.id,
                            title="Open redirect in /next", severity="medium",
                            category="redirect", evidence="?next=evil",
                            tool_source="dalfox"))
        session.commit()

    body = client.get(f"/api/targets/{target_id}/report?format=json", headers=headers).json()
    assert body["schema"] == "reconforge.target.report/v1"
    assert body["counts"]["runs"] == 2
    # Originally seeded 2 + 1 we just added = 3
    assert body["counts"]["findings"] == 3
    # Findings severity-ranked across all runs: critical first, then medium, then info
    sevs = [f["severity"] for f in body["findings"]]
    assert sevs.index("critical") < sevs.index("medium") < sevs.index("info")


def test_target_report_html_self_contained(stack):
    client, headers = stack
    _, target_id, _ = _seed_run_with_findings(client, headers)
    r = client.get(f"/api/targets/{target_id}/report?format=html", headers=headers)
    assert r.status_code == 200
    body = r.text
    assert "<!doctype html>" in body
    assert "Engagement report" in body
    assert "report.example.com" in body
    # No scripts — safe to forward
    assert "<script" not in body.lower()


def test_target_report_md_has_engagement_header(stack):
    client, headers = stack
    _, target_id, _ = _seed_run_with_findings(client, headers)
    r = client.get(f"/api/targets/{target_id}/report?format=md", headers=headers)
    assert r.status_code == 200
    assert r.text.startswith("# Engagement report")
    assert "## Run history" in r.text


def test_target_report_dedupes_assets_across_runs(stack):
    """Same asset (type, value) seen in two runs surfaces once in the unique
    assets bucket. The engagement report is "what did we discover", not
    "every time we saw it"."""
    client, headers = stack
    ws_id, target_id, run1 = _seed_run_with_findings(client, headers)
    from app.db import engine
    from app.models import Asset, Run, RunStatus
    from sqlmodel import Session
    with Session(engine) as session:
        # Add the same domain asset to two runs
        session.add(Asset(workspace_id=ws_id, run_id=run1, type="domain",
                          value="api.report.example.com", source="subfinder"))
        run2 = Run(workspace_id=ws_id, target_id=target_id, profile_id="web_quick",
                   status=RunStatus.completed)
        session.add(run2)
        session.commit()
        session.refresh(run2)
        session.add(Asset(workspace_id=ws_id, run_id=run2.id, type="domain",
                          value="api.report.example.com", source="dnsx"))
        session.commit()

    body = client.get(f"/api/targets/{target_id}/report?format=json", headers=headers).json()
    domain_values = body["assets_by_type"].get("domain", [])
    assert domain_values.count("api.report.example.com") == 1, domain_values
