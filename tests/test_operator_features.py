"""Tests for the operator-quality-of-life endpoints:

  POST /api/targets/bulk           — paste-a-list bulk import + dedupe
  GET  /api/findings/export?fmt=…  — CSV / JSON / Markdown download
  POST /api/runs/{id}/rerun        — clone + re-queue an existing run
"""
from __future__ import annotations

import io
import csv
import json
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
API_DIR = REPO / "apps" / "api"
sys.path.insert(0, str(API_DIR))


@pytest.fixture
def stack(tmp_path, monkeypatch):
    db_path = tmp_path / "feat.db"
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


# ---------------------------------------------------------------------------
# Bulk target import
# ---------------------------------------------------------------------------


def _ws(client, headers):
    return client.get("/api/workspaces", headers=headers).json()[0]["id"]


def test_bulk_import_creates_unique_skips_blanks_and_comments(stack):
    client, headers = stack
    ws_id = _ws(client, headers)
    body = {
        "workspace_id": ws_id,
        "values": [
            "a.example.com",
            "  b.example.com  ",        # whitespace stripped
            "a.example.com",            # in-batch dupe
            "",                         # blank
            "# c.example.com is OOS",   # comment line
            "d.example.com",
        ],
    }
    r = client.post("/api/targets/bulk", headers=headers, json=body)
    assert r.status_code == 201, r.text
    payload = r.json()
    assert {t["value"] for t in payload["created"]} == {"a.example.com",
                                                          "b.example.com",
                                                          "d.example.com"}
    assert payload["skipped"] == []
    # listing now shows them
    rows = client.get(f"/api/targets?workspace_id={ws_id}", headers=headers).json()
    assert {"a.example.com", "b.example.com", "d.example.com"} <= {t["value"] for t in rows}


def test_bulk_import_dedupes_against_existing_workspace_targets(stack):
    client, headers = stack
    ws_id = _ws(client, headers)
    client.post("/api/targets/bulk", headers=headers,
                 json={"workspace_id": ws_id, "values": ["a.example.com", "b.example.com"]})
    r = client.post("/api/targets/bulk", headers=headers,
                     json={"workspace_id": ws_id, "values": ["a.example.com", "c.example.com"]})
    assert r.status_code == 201
    payload = r.json()
    assert [t["value"] for t in payload["created"]] == ["c.example.com"]
    assert payload["skipped"] == [{"value": "a.example.com", "reason": "duplicate"}]


def test_bulk_import_404_on_unknown_workspace(stack):
    client, headers = stack
    r = client.post("/api/targets/bulk", headers=headers,
                     json={"workspace_id": "ws_nope", "values": ["x.com"]})
    assert r.status_code == 404


def test_bulk_import_anonymous_blocked(stack):
    client, _ = stack
    ws_id = client.get("/api/workspaces", headers={"X-Test-User": "admin"}).json()[0]["id"]
    r = client.post("/api/targets/bulk", json={"workspace_id": ws_id, "values": ["x.com"]})
    assert r.status_code == 401


def test_bulk_import_emits_audit_row(stack):
    client, headers = stack
    ws_id = _ws(client, headers)
    client.post("/api/targets/bulk", headers=headers,
                 json={"workspace_id": ws_id, "values": ["audit.example.com"]})
    audit = client.get("/api/dashboard/detailed", headers=headers).json()["recent_audit"]
    assert any(row["action"] == "target.bulk_created" for row in audit)


# ---------------------------------------------------------------------------
# Findings export
# ---------------------------------------------------------------------------


def _seed_findings(stack, *, severities=("critical", "high", "low")):
    client, headers = stack
    ws_id = _ws(client, headers)
    target = client.post("/api/targets", headers=headers, json={
        "workspace_id": ws_id, "value": "expo.example.com", "type": "domain",
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
        raise AssertionError("run did not complete in 90s")

    from app.db import engine
    from app.models import Finding
    from sqlmodel import Session
    with Session(engine) as session:
        for sev in severities:
            session.add(Finding(workspace_id=ws_id, run_id=run["id"],
                                 title=f"sample {sev} finding",
                                 severity=sev, category="exposure",
                                 evidence=f"https://expo.example.com/{sev}",
                                 tool_source="nuclei"))
        session.commit()
    return ws_id


def test_findings_export_csv(stack):
    ws_id = _seed_findings(stack)
    client, headers = stack
    r = client.get(f"/api/findings/export?format=csv&workspace_id={ws_id}", headers=headers)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    rows = list(csv.reader(io.StringIO(r.text)))
    assert rows[0][:5] == ["id", "workspace_id", "run_id", "asset_id", "title"]
    titles = [row[4] for row in rows[1:]]
    assert any("critical" in t for t in titles)


def test_findings_export_json(stack):
    ws_id = _seed_findings(stack)
    client, headers = stack
    r = client.get(f"/api/findings/export?format=json&workspace_id={ws_id}", headers=headers)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    body = json.loads(r.text)
    assert isinstance(body, list)
    assert {"id", "title", "severity", "status"} <= set(body[0].keys())


def test_findings_export_markdown(stack):
    ws_id = _seed_findings(stack)
    client, headers = stack
    r = client.get(f"/api/findings/export?format=md&workspace_id={ws_id}", headers=headers)
    assert r.status_code == 200
    assert "text/markdown" in r.headers["content-type"]
    assert r.text.startswith("# Findings export")
    assert "| Severity | Status |" in r.text


def test_findings_export_filters_by_severity(stack):
    ws_id = _seed_findings(stack, severities=("critical", "high", "low"))
    client, headers = stack
    r = client.get(f"/api/findings/export?format=csv&workspace_id={ws_id}&severity=critical",
                    headers=headers)
    rows = list(csv.reader(io.StringIO(r.text)))[1:]   # drop header
    assert rows, "expected at least one critical row"
    assert all(row[5] == "critical" for row in rows)


def test_findings_export_invalid_format_400(stack):
    client, headers = stack
    r = client.get("/api/findings/export?format=xml", headers=headers)
    assert r.status_code == 400


def test_findings_export_anonymous_blocked(stack):
    client, _ = stack
    assert client.get("/api/findings/export?format=csv").status_code == 401


# ---------------------------------------------------------------------------
# Run rerun
# ---------------------------------------------------------------------------


def test_rerun_clones_target_and_profile(stack):
    client, headers = stack
    ws_id = _ws(client, headers)
    target = client.post("/api/targets", headers=headers, json={
        "workspace_id": ws_id, "value": "rerun.example.com", "type": "domain",
        "in_scope": True, "passive_allowed": True, "active_allowed": True,
    }).json()
    first = client.post("/api/runs", headers=headers, json={
        "workspace_id": ws_id, "target_id": target["id"], "profile_id": "passive_recon",
    }).json()

    r = client.post(f"/api/runs/{first['id']}/rerun", headers=headers)
    assert r.status_code == 201, r.text
    rerun = r.json()
    assert rerun["id"] != first["id"]
    assert rerun["target_id"] == first["target_id"]
    assert rerun["profile_id"] == first["profile_id"]
    assert rerun["config_snapshot"]["rerun_of"] == first["id"]


def test_rerun_404_on_unknown_run(stack):
    client, headers = stack
    assert client.post("/api/runs/run_missing/rerun", headers=headers).status_code == 404


def test_rerun_anonymous_blocked(stack):
    client, _ = stack
    assert client.post("/api/runs/run_x/rerun").status_code == 401


def test_rerun_audit_row(stack):
    client, headers = stack
    ws_id = _ws(client, headers)
    target = client.post("/api/targets", headers=headers, json={
        "workspace_id": ws_id, "value": "a.example.com", "type": "domain",
        "in_scope": True, "passive_allowed": True, "active_allowed": True,
    }).json()
    first = client.post("/api/runs", headers=headers, json={
        "workspace_id": ws_id, "target_id": target["id"], "profile_id": "passive_recon",
    }).json()
    client.post(f"/api/runs/{first['id']}/rerun", headers=headers)
    audit = client.get("/api/dashboard/detailed", headers=headers).json()["recent_audit"]
    assert any(row["action"] == "run.rerun" for row in audit)
