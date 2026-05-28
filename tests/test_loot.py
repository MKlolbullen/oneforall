"""Loot layer: classification, indexing, summary, manifest, and the /api/loot
surface (list, export, reindex + auth gates).

Loot is the curated high-signal slice of a run derived from Findings; see
apps/api/app/services/loot.py.
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
    db_path = tmp_path / "loot.db"
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


def _seed_findings(ws_id, run_id, specs):
    """Insert Finding rows directly. specs: list of (title, severity, tool, category)."""
    from app.db import engine
    from app.models import Finding
    from sqlmodel import Session
    ids = []
    with Session(engine) as session:
        for title, severity, tool, category in specs:
            f = Finding(
                workspace_id=ws_id, run_id=run_id, title=title, severity=severity,
                category=category, evidence=title, tool_source=tool,
            )
            session.add(f)
            session.commit()
            session.refresh(f)
            ids.append(f.id)
    return ids


def _seed_run(client, headers):
    """Create a workspace+target+run row set directly (no real execution)."""
    from app.db import engine
    from app.models import Run, RunStatus, Target
    from sqlmodel import Session
    ws_id = client.get("/api/workspaces", headers=headers).json()[0]["id"]
    with Session(engine) as session:
        target = Target(workspace_id=ws_id, value="loot.example.com", type="domain")
        session.add(target)
        session.commit()
        session.refresh(target)
        run = Run(workspace_id=ws_id, target_id=target.id, profile_id="passive_recon",
                  status=RunStatus.completed)
        session.add(run)
        session.commit()
        session.refresh(run)
        return ws_id, target.id, run.id


# ---------- pure classification (no DB) --------------------------------------


@pytest.mark.parametrize("title,severity,tool,category,expected_kind", [
    ("AWS secret key found in app.js", "info", "trufflehog", "secrets", "secret"),
    ("api_key=AKIA... leaked", "low", "secretfinder", "secrets", "secret"),
    ("Subdomain takeover possible on cdn.example.com", "high", "subzy", "takeover", "takeover"),
    ("Default credential admin:admin accepted", "medium", "nuclei", "auth", "credential"),
    ("Exposed .git/ directory", "medium", "nuclei", "exposure", "exposure"),
    ("Apache Struts RCE CVE-2017-5638", "critical", "nuclei", "rce", "vulnerability"),
    ("Reflected XSS in /search", "high", "dalfox", "xss", "vulnerability"),
])
def test_classify_positive(title, severity, tool, category, expected_kind):
    from app.models import Finding
    from app.services import loot
    f = Finding(workspace_id="ws_x", run_id="run_x", title=title,
                severity=severity, category=category, evidence=title, tool_source=tool)
    result = loot._classify(f)
    assert result is not None, f"expected {title!r} to be loot"
    assert result[0] == expected_kind


@pytest.mark.parametrize("title,severity,tool,category", [
    ("robots.txt discovered", "info", "httpx", "informational"),
    ("Server header: nginx/1.18", "low", "httpx", "fingerprint"),
    ("Open port 80/tcp", "info", "naabu", "port"),
])
def test_classify_negative(title, severity, tool, category):
    """Raw low/info scanner noise must NOT become loot."""
    from app.models import Finding
    from app.services import loot
    f = Finding(workspace_id="ws_x", run_id="run_x", title=title,
                severity=severity, category=category, evidence=title, tool_source=tool)
    assert loot._classify(f) is None


def test_secret_severity_floored_to_high():
    """An info-severity secret is high-signal: loot lifts it to >= high."""
    from app.models import Finding
    from app.services import loot
    f = Finding(workspace_id="ws_x", run_id="run_x",
                title="AWS secret key in bundle.js", severity="info",
                category="secrets", evidence="aws_secret=...", tool_source="trufflehog")
    kind, floor = loot._classify(f)
    assert loot._more_severe(f.severity, floor) == "high"


def test_summarize_loot_shape():
    from app.models import LootItem
    from app.services import loot
    items = [
        LootItem(workspace_id="w", kind="secret", label="a", severity="high"),
        LootItem(workspace_id="w", kind="secret", label="b", severity="critical"),
        LootItem(workspace_id="w", kind="vulnerability", label="c", severity="high"),
    ]
    summary = loot.summarize_loot(items)
    assert summary["total"] == 3
    assert summary["by_kind"] == {"secret": 2, "vulnerability": 1}
    assert summary["by_severity"] == {"high": 2, "critical": 1}
    # Top item is the most-severe (critical) one.
    assert summary["items"][0]["severity"] == "critical"


# ---------- index_run / record_from_finding (DB) -----------------------------


def test_index_run_creates_curated_loot(stack):
    client, headers = stack
    ws_id, _tid, run_id = _seed_run(client, headers)
    _seed_findings(ws_id, run_id, [
        ("AWS secret key in bundle.js", "info", "trufflehog", "secrets"),
        ("Subdomain takeover on cdn.example.com", "high", "subzy", "takeover"),
        ("Apache RCE CVE-2017-5638", "critical", "nuclei", "rce"),
        ("robots.txt discovered", "info", "httpx", "informational"),
        ("Server header nginx", "low", "httpx", "fingerprint"),
    ])
    from app.db import engine
    from app.services import loot
    from sqlmodel import Session
    with Session(engine) as session:
        items = loot.index_run(session, workspace_id=ws_id, run_id=run_id)
    # 3 of 5 findings are loot-worthy; the 2 info/low noise rows are excluded.
    assert len(items) == 3
    kinds = {i.kind for i in items}
    assert kinds == {"secret", "takeover", "vulnerability"}
    # Severity-ranked: critical first.
    assert items[0].severity == "critical"


def test_index_run_is_idempotent(stack):
    client, headers = stack
    ws_id, _tid, run_id = _seed_run(client, headers)
    _seed_findings(ws_id, run_id, [
        ("AWS secret key", "info", "trufflehog", "secrets"),
        ("RCE CVE-2017-5638", "critical", "nuclei", "rce"),
    ])
    from app.db import engine
    from app.services import loot
    from sqlmodel import Session
    with Session(engine) as session:
        first = loot.index_run(session, workspace_id=ws_id, run_id=run_id)
    with Session(engine) as session:
        second = loot.index_run(session, workspace_id=ws_id, run_id=run_id)
    assert len(first) == len(second) == 2
    assert {i.id for i in first} == {i.id for i in second}


def test_record_from_finding_respects_toggle(stack, monkeypatch):
    client, headers = stack
    ws_id, _tid, run_id = _seed_run(client, headers)
    fid = _seed_findings(ws_id, run_id, [("AWS secret key", "high", "trufflehog", "secrets")])[0]

    from app.db import engine
    from app.models import Finding, LootItem
    from app.services import loot
    from sqlmodel import Session, select

    # Toggle off -> passive hook is a no-op.
    monkeypatch.setattr(loot, "load_platform_config",
                        lambda: {"runtime": {"loot_enabled": False}})
    with Session(engine) as session:
        f = session.get(Finding, fid)
        assert loot.record_from_finding(session, f) is None
        assert session.exec(select(LootItem).where(LootItem.finding_id == fid)).first() is None

    # Toggle on -> a row is created.
    monkeypatch.setattr(loot, "load_platform_config",
                        lambda: {"runtime": {"loot_enabled": True}})
    with Session(engine) as session:
        f = session.get(Finding, fid)
        item = loot.record_from_finding(session, f)
        assert item is not None and item.kind == "secret"


def test_manifest_json_is_valid_document(stack):
    client, headers = stack
    ws_id, _tid, run_id = _seed_run(client, headers)
    _seed_findings(ws_id, run_id, [("RCE CVE-2017-5638", "critical", "nuclei", "rce")])
    from app.db import engine
    from app.services import loot
    from sqlmodel import Session
    with Session(engine) as session:
        loot.index_run(session, workspace_id=ws_id, run_id=run_id)
        manifest = loot.manifest_json(session, workspace_id=ws_id, run_id=run_id)
    doc = json.loads(manifest)
    assert doc["schema"] == "reconforge.loot.manifest/v1"
    assert doc["run_id"] == run_id
    assert doc["total"] == 1
    assert doc["loot"][0]["kind"] == "vulnerability"


# ---------- /api/loot surface -------------------------------------------------


def test_loot_anonymous_blocked(stack):
    client, _ = stack
    assert client.get("/api/loot").status_code == 401


def test_loot_list_and_facets_after_reindex(stack):
    client, headers = stack
    ws_id, _tid, run_id = _seed_run(client, headers)
    _seed_findings(ws_id, run_id, [
        ("AWS secret key", "info", "trufflehog", "secrets"),
        ("Subdomain takeover", "high", "subzy", "takeover"),
        ("RCE CVE-2017-5638", "critical", "nuclei", "rce"),
    ])
    r = client.post(f"/api/loot/runs/{run_id}/reindex", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["indexed"] == 3

    body = client.get(f"/api/loot?run_id={run_id}", headers=headers).json()
    assert body["total"] == 3
    assert set(body["facets"]["kinds"]) == {"secret", "takeover", "vulnerability"}
    # Severity-ranked: critical first.
    assert body["items"][0]["severity"] == "critical"

    only_secret = client.get(f"/api/loot?run_id={run_id}&kind=secret", headers=headers).json()
    assert len(only_secret["items"]) == 1
    assert only_secret["items"][0]["kind"] == "secret"


def test_loot_export_csv_and_json(stack):
    client, headers = stack
    ws_id, _tid, run_id = _seed_run(client, headers)
    _seed_findings(ws_id, run_id, [("RCE CVE-2017-5638", "critical", "nuclei", "rce")])
    client.post(f"/api/loot/runs/{run_id}/reindex", headers=headers)

    csv_resp = client.get(f"/api/loot/export?format=csv&run_id={run_id}", headers=headers)
    assert csv_resp.status_code == 200
    assert csv_resp.headers["content-type"].startswith("text/csv")
    assert "vulnerability" in csv_resp.text

    json_resp = client.get(f"/api/loot/export?format=json&run_id={run_id}", headers=headers)
    rows = json_resp.json()
    assert len(rows) == 1 and rows[0]["kind"] == "vulnerability"

    bad = client.get(f"/api/loot/export?format=xml&run_id={run_id}", headers=headers)
    assert bad.status_code == 400


def test_loot_reindex_404_unknown_run(stack):
    client, headers = stack
    assert client.post("/api/loot/runs/does-not-exist/reindex", headers=headers).status_code == 404


def test_loot_reindex_viewer_blocked(stack):
    client, headers = stack
    _ws_id, _tid, run_id = _seed_run(client, headers)
    admin_token = client.post("/api/auth/login",
                               json={"username": "admin",
                                      "password": "admin-passw0rd"}).json()["token"]
    client.post("/api/auth/users",
                headers={"Authorization": f"Bearer {admin_token}"},
                json={"username": "vw", "password": "viewer-p4ssword", "role": "viewer"})
    vt = client.post("/api/auth/login",
                     json={"username": "vw", "password": "viewer-p4ssword"}).json()["token"]
    r = client.post(f"/api/loot/runs/{run_id}/reindex",
                    headers={"Authorization": f"Bearer {vt}"})
    assert r.status_code == 403
