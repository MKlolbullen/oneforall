"""Auth + RBAC + signed audit log.

Covers:
  - password hashing round-trip + rejection of bad passwords
  - login issues a token; the token works on protected endpoints
  - viewer can read but not create runs/targets/workspaces
  - operator can create runs/targets but not workspaces or users
  - admin can do everything
  - audit chain remains intact across multiple events
  - tampering with one row is detected by verify_chain()
  - a configured HMAC key prevents post-hoc fabrication of rows
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
API_DIR = REPO / "apps" / "api"
sys.path.insert(0, str(API_DIR))


@pytest.fixture
def stack(tmp_path, monkeypatch):
    db_path = tmp_path / "auth.db"
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
    monkeypatch.setenv("RECONFORGE_AUDIT_HMAC_KEY", "test-hmac-key")

    from app.core.config import get_settings
    get_settings.cache_clear()
    import app.db as db_mod
    from sqlmodel import create_engine
    new_engine = create_engine(f"sqlite:///{db_path}", echo=False,
                                connect_args={"check_same_thread": False})
    db_mod.engine = new_engine
    import app.main as main_mod
    main_mod.engine = new_engine
    import app.api.routes.runs as runs_mod
    runs_mod.engine = new_engine

    from fastapi.testclient import TestClient
    with TestClient(main_mod.app) as client:
        yield client, new_engine
    get_settings.cache_clear()


# ---------------------------- Password primitives ----------------------------

def test_password_hash_roundtrip():
    from app.services.auth import hash_password, verify_password
    h = hash_password("hunter2")
    assert verify_password("hunter2", h)
    assert not verify_password("wrong", h)
    assert not verify_password("hunter2", "garbage")
    # Two hashes of the same password use different salts and differ
    h2 = hash_password("hunter2")
    assert h != h2 and verify_password("hunter2", h2)


def test_login_returns_token_and_token_works(stack):
    client, _ = stack
    r = client.post("/api/auth/login",
                    json={"username": "admin", "password": "admin-passw0rd"})
    assert r.status_code == 200, r.text
    body = r.json()
    token = body["token"]
    assert token.startswith("rcf_")

    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["username"] == "admin"
    assert me.json()["role"] == "admin"


def test_login_failure_does_not_leak_existence(stack):
    client, _ = stack
    bad_user = client.post("/api/auth/login", json={"username": "nope", "password": "x"})
    bad_pw = client.post("/api/auth/login", json={"username": "admin", "password": "x"})
    assert bad_user.status_code == 401
    assert bad_pw.status_code == 401
    # Same status, same message
    assert bad_user.json()["detail"] == bad_pw.json()["detail"] == "Invalid credentials"


# ---------------------------- Role enforcement ----------------------------

def _make_user(client, *, admin_token: str, username: str, password: str, role: str) -> str:
    r = client.post(
        "/api/auth/users",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"username": username, "password": password, "role": role},
    )
    assert r.status_code == 201, r.text
    login = client.post("/api/auth/login",
                        json={"username": username, "password": password})
    return login.json()["token"]


def _bootstrap_tokens(client) -> dict[str, str]:
    admin = client.post("/api/auth/login",
                        json={"username": "admin", "password": "admin-passw0rd"}).json()["token"]
    operator = _make_user(client, admin_token=admin, username="op",
                          password="opp4ssword", role="operator")
    viewer = _make_user(client, admin_token=admin, username="vw",
                        password="vwp4ssword", role="viewer")
    return {"admin": admin, "operator": operator, "viewer": viewer}


def test_anonymous_blocked_from_protected_endpoints(stack):
    client, _ = stack
    # No Authorization header -> 401
    assert client.get("/api/workspaces").status_code == 401
    assert client.get("/api/runs").status_code == 401
    # /health is unprotected
    assert client.get("/health").status_code == 200


def test_viewer_can_read_but_not_create(stack):
    client, _ = stack
    tok = _bootstrap_tokens(client)
    h = lambda role: {"Authorization": f"Bearer {tok[role]}"}

    # Viewer can list workspaces
    assert client.get("/api/workspaces", headers=h("viewer")).status_code == 200

    # Viewer cannot create a target
    r = client.post(
        "/api/targets",
        headers=h("viewer"),
        json={"workspace_id": "ws_x", "value": "lab.example.com", "type": "domain",
              "in_scope": True, "passive_allowed": True, "active_allowed": True},
    )
    assert r.status_code == 403
    # And cannot create a workspace
    r = client.post("/api/workspaces", headers=h("viewer"),
                    json={"name": "shouldntexist"})
    assert r.status_code == 403


def test_operator_can_create_targets_and_runs_but_not_workspaces(stack):
    client, _ = stack
    tok = _bootstrap_tokens(client)
    op_h = {"Authorization": f"Bearer {tok['operator']}"}

    # Read seeded workspace
    ws_id = client.get("/api/workspaces", headers=op_h).json()[0]["id"]

    # Operator may NOT create workspaces (admin-only)
    assert client.post("/api/workspaces", headers=op_h, json={"name": "x"}).status_code == 403

    # Operator may create a target
    target = client.post(
        "/api/targets",
        headers=op_h,
        json={"workspace_id": ws_id, "value": "lab.example.com", "type": "domain",
              "in_scope": True, "passive_allowed": True, "active_allowed": True},
    )
    assert target.status_code == 201, target.text

    # Operator may queue a run
    run = client.post(
        "/api/runs",
        headers=op_h,
        json={"workspace_id": ws_id, "target_id": target.json()["id"],
              "profile_id": "passive_recon"},
    )
    assert run.status_code == 201, run.text


def test_admin_can_create_users(stack):
    client, _ = stack
    admin_token = client.post("/api/auth/login",
                              json={"username": "admin", "password": "admin-passw0rd"}).json()["token"]
    r = client.post(
        "/api/auth/users",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"username": "newop", "password": "newp4ssword", "role": "operator"},
    )
    assert r.status_code == 201, r.text


# ---------------------------- API key revocation ----------------------------

def test_revoking_an_api_key_invalidates_it(stack):
    client, _ = stack
    admin_token = client.post("/api/auth/login",
                              json={"username": "admin", "password": "admin-passw0rd"}).json()["token"]
    h = {"Authorization": f"Bearer {admin_token}"}
    keys = client.get("/api/auth/api-keys", headers=h).json()
    key_id = keys[0]["id"]

    # Make a second key, log in via it, then revoke the first.
    new = client.post("/api/auth/api-keys", headers=h, json={"name": "ci"}).json()
    new_h = {"Authorization": f"Bearer {new['token']}"}
    assert client.get("/api/auth/me", headers=new_h).status_code == 200

    # Revoke the original admin login key
    assert client.delete(f"/api/auth/api-keys/{key_id}", headers=h).status_code == 204

    # The original key no longer authenticates
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {admin_token}"}).status_code == 401
    # The freshly-created key still works
    assert client.get("/api/auth/me", headers=new_h).status_code == 200


# ---------------------------- Audit chain ----------------------------

def test_audit_chain_grows_and_verifies(stack):
    client, engine = stack
    tok = _bootstrap_tokens(client)
    h = lambda role: {"Authorization": f"Bearer {tok[role]}"}

    ws_id = client.get("/api/workspaces", headers=h("operator")).json()[0]["id"]
    client.post("/api/targets", headers=h("operator"),
                json={"workspace_id": ws_id, "value": "lab.example.com", "type": "domain",
                      "in_scope": True, "passive_allowed": True, "active_allowed": True})

    audit = client.get("/api/auth/audit", headers=h("admin")).json()
    assert audit["ok"] is True
    seqs = [e["sequence"] for e in audit["events"]]
    assert seqs == sorted(seqs, reverse=True), "events ordered by sequence desc"
    actions = {e["action"] for e in audit["events"]}
    assert {"auth.login.success", "auth.user.created", "target.created"}.issubset(actions)


def test_audit_chain_detects_payload_tampering(stack):
    client, engine = stack
    # Generate a couple of events first
    client.post("/api/auth/login",
                json={"username": "admin", "password": "admin-passw0rd"})
    # Tamper with the most recent row's payload
    from sqlmodel import Session, select
    from app.models import AuditEvent
    with Session(engine) as session:
        last = session.exec(
            select(AuditEvent).order_by(AuditEvent.sequence.desc()).limit(1)
        ).first()
        last.payload = {**(last.payload or {}), "tampered": True}
        session.add(last)
        session.commit()

    from app.services.audit import verify_chain
    with Session(engine) as session:
        breaks = verify_chain(session)
    assert breaks, "tampered row must be detected"
    assert any("signature mismatch" in b.reason or "_hmac" in b.reason for b in breaks)


def test_audit_chain_detects_inserted_row(stack):
    client, engine = stack
    # Start the chain
    client.post("/api/auth/login",
                json={"username": "admin", "password": "admin-passw0rd"})

    from sqlmodel import Session, select
    from app.models import AuditEvent
    with Session(engine) as session:
        last = session.exec(
            select(AuditEvent).order_by(AuditEvent.sequence.desc()).limit(1)
        ).first()
        # Forge a row that pretends to be next in line, but with a wrong prev_signature
        forged = AuditEvent(
            sequence=last.sequence + 1,
            actor_id=None, actor_role=None,
            action="forged",
            target_kind=None, target_id=None,
            payload={"forged": True},
            prev_signature="0" * 64,
            signature="0" * 64,
        )
        session.add(forged)
        session.commit()

    from app.services.audit import verify_chain
    with Session(engine) as session:
        breaks = verify_chain(session)
    assert breaks
    assert any("prev_signature mismatch" in b.reason or "signature mismatch" in b.reason
               for b in breaks)
