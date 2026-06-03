"""POST /api/scope/evaluate — preflight against the live ROE engine.

Verifies that the route is a faithful mirror of what the run-creation
guards decide. Tests cover:
  - no policy file → response decision == "no-engine"
  - policy loaded → allow / deny / require_approval surface correctly
  - 401 anonymous + 422 on missing target
"""
from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
API_DIR = REPO / "apps" / "api"
sys.path.insert(0, str(API_DIR))


def _write_policy(tmp_path: Path, yaml_text: str) -> Path:
    target = tmp_path / "roe.yaml"
    target.write_text(textwrap.dedent(yaml_text).lstrip(), encoding="utf-8")
    return target


@pytest.fixture
def stack(tmp_path, monkeypatch):
    db_path = tmp_path / "scope-eval.db"
    monkeypatch.setenv("TOOL_REGISTRY_DIR", str(REPO / "packages/tool-registry/tools"))
    monkeypatch.setenv("PROFILE_REGISTRY_DIR", str(REPO / "packages/tool-registry/profiles"))
    monkeypatch.setenv("PLATFORM_CONFIG_PATH",
                       str(REPO / "packages/platform-config/sniper-inspired.yaml"))
    monkeypatch.setenv("GREP_PATTERNS_PATH",
                       str(REPO / "packages/patterns/sniper-grep-patterns.yaml"))
    monkeypatch.setenv("WORDLISTS_DIR", str(REPO / "packages/wordlists"))
    monkeypatch.setenv("ROE_POLICY_PATH", str(tmp_path / "roe-disabled.yaml"))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("ARTIFACT_BACKEND", "local")
    monkeypatch.setenv("ARTIFACT_DIR", str(tmp_path / "artifacts"))
    monkeypatch.setenv("EXECUTION_MODE", "dry_run")
    monkeypatch.setenv("ALLOW_LIVE_EXECUTION", "false")
    monkeypatch.setenv("RUNNER_MODE", "in_process")
    monkeypatch.setenv("DRY_RUN_LINE_DELAY_SECONDS", "0")
    monkeypatch.setenv("RECONFORGE_BOOTSTRAP_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("RECONFORGE_BOOTSTRAP_ADMIN_PASSWORD", "admin-passw0rd")
    monkeypatch.setenv("RECONFORGE_TEST_AUTH_BYPASS", "1")

    from conftest import rebind_engine_to_database_url
    rebind_engine_to_database_url()
    from app.services.roe_guard import clear_engine_cache
    clear_engine_cache()

    from fastapi.testclient import TestClient
    from app.main import app
    headers = {"X-Test-User": "admin"}
    with TestClient(app) as client:
        yield client, headers, tmp_path
    from app.core.config import get_settings
    get_settings.cache_clear()
    clear_engine_cache()


def _activate_policy(monkeypatch, policy_path: Path) -> None:
    monkeypatch.setenv("ROE_POLICY_PATH", str(policy_path))
    from app.core.config import get_settings
    get_settings.cache_clear()
    from app.services.roe_guard import clear_engine_cache
    clear_engine_cache()


def test_anonymous_blocked(stack):
    client, _, _ = stack
    r = client.post("/api/scope/evaluate", json={"target": "example.com"})
    assert r.status_code == 401


def test_missing_target_422(stack):
    client, headers, _ = stack
    r = client.post("/api/scope/evaluate", headers=headers, json={"target": ""})
    assert r.status_code == 422


def test_no_engine_when_no_policy_file(stack):
    """Engine off → response advertises decision=no-engine. The frontend
    uses this to hide the preflight badge entirely."""
    client, headers, _ = stack
    r = client.post("/api/scope/evaluate", headers=headers, json={
        "target": "example.com", "risk": "passive",
    })
    assert r.status_code == 200
    assert r.json()["decision"] == "no-engine"


def test_engine_allow(stack, monkeypatch):
    client, headers, tmp_path = stack
    _activate_policy(monkeypatch, _write_policy(tmp_path, """
        allowed:
          domains:
            - example.com
            - "*.example.com"
    """))
    r = client.post("/api/scope/evaluate", headers=headers, json={
        "target": "api.example.com", "risk": "passive",
    })
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "allow"
    assert body["normalized_target"] == "api.example.com"


def test_engine_deny_carries_matched_rule(stack, monkeypatch):
    client, headers, tmp_path = stack
    _activate_policy(monkeypatch, _write_policy(tmp_path, """
        allowed:
          domains: ["*.example.com"]
        denied:
          domains: ["admin.example.com"]
    """))
    r = client.post("/api/scope/evaluate", headers=headers, json={
        "target": "admin.example.com", "risk": "passive",
    })
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "deny"
    assert body["matched_rule"] == "denied.domains"
    # Trace is helpful for UI tooltips ("why is this denied?")
    assert body["trace"]


def test_engine_require_approval_for_listed_tool(stack, monkeypatch):
    client, headers, tmp_path = stack
    _activate_policy(monkeypatch, _write_policy(tmp_path, """
        allowed:
          domains: ["*.example.com"]
        approval:
          require_for_tools: [subfinder]
    """))
    # subfinder is in the approval list; no manual_approval => prompt.
    r = client.post("/api/scope/evaluate", headers=headers, json={
        "target": "api.example.com", "risk": "passive", "tool_id": "subfinder",
    })
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "require_approval"

    # Same call with manual_approval=true clears.
    r = client.post("/api/scope/evaluate", headers=headers, json={
        "target": "api.example.com", "risk": "passive",
        "tool_id": "subfinder", "manual_approval": True,
    })
    assert r.json()["decision"] == "allow"


def test_engine_rate_limit_decision(stack, monkeypatch):
    """rate_limit is a non-fatal decision the UI surfaces as an amber
    warning — the run-creation guard treats it as allow because requested
    RPS isn't known yet, but the preflight surfaces it to the operator."""
    client, headers, tmp_path = stack
    _activate_policy(monkeypatch, _write_policy(tmp_path, """
        allowed:
          domains: ["*.example.com"]
        limits:
          max_rps: 5
    """))
    r = client.post("/api/scope/evaluate", headers=headers, json={
        "target": "api.example.com", "risk": "passive", "requested_rps": 50,
    })
    body = r.json()
    assert body["decision"] == "rate_limit"
    assert body["effective_limits"]["max_rps"] == 5
