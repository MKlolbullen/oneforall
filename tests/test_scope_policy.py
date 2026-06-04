"""GET/PUT /api/scope/policy — read and write the ROE policy from the UI.

Covers:
  - GET returns enabled=False + empty yaml when no policy file exists
  - GET returns parsed dict + yaml when a policy file is on disk
  - PUT (admin) writes the policy, the next preflight sees the new rules
  - PUT non-admin → 403
  - PUT invalid YAML → 422
  - PUT non-mapping YAML (a bare list) → 422
  - PUT empty body deletes the file → engine disables
  - Each write lands an audit row
"""
from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
API_DIR = REPO / "apps" / "api"
sys.path.insert(0, str(API_DIR))


@pytest.fixture
def stack(tmp_path, monkeypatch):
    db_path = tmp_path / "policy.db"
    monkeypatch.setenv("TOOL_REGISTRY_DIR", str(REPO / "packages/tool-registry/tools"))
    monkeypatch.setenv("PROFILE_REGISTRY_DIR", str(REPO / "packages/tool-registry/profiles"))
    monkeypatch.setenv("PLATFORM_CONFIG_PATH",
                       str(REPO / "packages/platform-config/sniper-inspired.yaml"))
    monkeypatch.setenv("GREP_PATTERNS_PATH",
                       str(REPO / "packages/patterns/sniper-grep-patterns.yaml"))
    monkeypatch.setenv("WORDLISTS_DIR", str(REPO / "packages/wordlists"))
    monkeypatch.setenv("ROE_POLICY_PATH", str(tmp_path / "roe.yaml"))
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


def test_get_policy_when_no_file_returns_disabled(stack):
    client, headers, _ = stack
    r = client.get("/api/scope/policy", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["enabled"] is False
    assert body["yaml"] == ""
    assert body["parsed"] == {}


def test_get_policy_returns_existing_file(stack):
    client, headers, tmp_path = stack
    policy = tmp_path / "roe.yaml"
    policy.write_text(textwrap.dedent("""
        allowed:
          domains: [example.com]
    """).lstrip(), encoding="utf-8")
    r = client.get("/api/scope/policy", headers=headers).json()
    assert r["enabled"] is True
    assert r["parsed"]["allowed"]["domains"] == ["example.com"]
    assert "allowed:" in r["yaml"]


def test_put_policy_writes_file_and_engages_engine(stack):
    """After a PUT, the next /scope/evaluate sees the new policy — proves
    the cache invalidation in PUT actually picks up the new rules."""
    client, headers, _ = stack
    # Before: engine off
    pre = client.post("/api/scope/evaluate", headers=headers, json={
        "target": "example.com", "risk": "passive",
    }).json()
    assert pre["decision"] == "no-engine"

    # Write a policy that explicitly denies admin.example.com
    new_yaml = textwrap.dedent("""
        allowed:
          domains: ["*.example.com", "example.com"]
        denied:
          domains: ["admin.example.com"]
    """).lstrip()
    r = client.put("/api/scope/policy", headers=headers, json={"yaml": new_yaml})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["enabled"] is True
    assert body["parsed"]["denied"]["domains"] == ["admin.example.com"]

    # The next evaluate uses the new policy.
    post = client.post("/api/scope/evaluate", headers=headers, json={
        "target": "admin.example.com", "risk": "passive",
    }).json()
    assert post["decision"] == "deny"
    assert post["matched_rule"] == "denied.domains"

    # Audit row recorded
    audit_body = client.get("/api/auth/audit", headers=headers).json()
    assert any(e["action"] == "scope.policy.updated" for e in audit_body["events"])


def test_put_invalid_yaml_returns_422(stack):
    client, headers, _ = stack
    r = client.put("/api/scope/policy", headers=headers, json={
        "yaml": "allowed: { domains: [unclosed",
    })
    assert r.status_code == 422
    assert "invalid YAML" in r.json()["detail"]


def test_put_non_mapping_returns_422(stack):
    """A bare list isn't a valid policy — refuse instead of silently
    accepting a structure the engine can't read."""
    client, headers, _ = stack
    r = client.put("/api/scope/policy", headers=headers, json={
        "yaml": "- example.com\n- admin.example.com\n",
    })
    assert r.status_code == 422
    assert "mapping" in r.json()["detail"]


def test_put_empty_body_disables_engine(stack):
    """Empty yaml body → file deleted → engine disabled. The next
    /scope/evaluate returns decision=no-engine."""
    client, headers, _ = stack
    # First write a valid policy
    client.put("/api/scope/policy", headers=headers, json={
        "yaml": "allowed:\n  domains: [example.com]\n",
    })
    # Confirm engine is on
    assert client.post("/api/scope/evaluate", headers=headers, json={
        "target": "example.com", "risk": "passive",
    }).json()["decision"] == "allow"
    # Empty body → delete
    r = client.put("/api/scope/policy", headers=headers, json={"yaml": ""})
    assert r.status_code == 200
    assert r.json()["enabled"] is False
    # Next evaluate → no engine
    assert client.post("/api/scope/evaluate", headers=headers, json={
        "target": "example.com", "risk": "passive",
    }).json()["decision"] == "no-engine"
    # Audit row for the delete
    audit_body = client.get("/api/auth/audit", headers=headers).json()
    assert any(e["action"] == "scope.policy.deleted" for e in audit_body["events"])


def test_put_policy_requires_admin(stack):
    """Operators can read the policy (it's not sensitive — it's on disk
    in the repo). Writing is admin-only."""
    client, _, _ = stack
    admin_token = client.post("/api/auth/login", json={
        "username": "admin", "password": "admin-passw0rd",
    }).json()["token"]
    client.post("/api/auth/users",
                headers={"Authorization": f"Bearer {admin_token}"},
                json={"username": "op", "password": "op-secret-1", "role": "operator"})
    op_token = client.post("/api/auth/login", json={
        "username": "op", "password": "op-secret-1",
    }).json()["token"]
    # Operator can read
    assert client.get("/api/scope/policy",
                      headers={"Authorization": f"Bearer {op_token}"}).status_code == 200
    # But cannot write
    r = client.put("/api/scope/policy",
                   headers={"Authorization": f"Bearer {op_token}"},
                   json={"yaml": "allowed:\n  domains: [a.com]\n"})
    assert r.status_code == 403


def test_get_policy_when_file_is_malformed(stack):
    """A malformed YAML file on disk should still be readable so the
    editor can show + fix it; enabled stays True (file exists) but
    parsed is empty."""
    client, headers, tmp_path = stack
    (tmp_path / "roe.yaml").write_text("allowed: { broken", encoding="utf-8")
    r = client.get("/api/scope/policy", headers=headers).json()
    assert r["enabled"] is True
    assert "broken" in r["yaml"]
    assert r["parsed"] == {}


def test_put_then_get_roundtrip(stack):
    """Round-trip: the YAML the operator typed comes back verbatim from
    GET — the editor doesn't see normalised/reformatted content."""
    client, headers, _ = stack
    custom = "# my carefully-formatted policy\nallowed:\n  domains: [example.com]\n"
    client.put("/api/scope/policy", headers=headers, json={"yaml": custom})
    r = client.get("/api/scope/policy", headers=headers).json()
    assert r["yaml"] == custom
