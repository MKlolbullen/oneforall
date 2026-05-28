"""User admin endpoints: GET /api/auth/users + PATCH /api/auth/users/{id}.

Validates that the new admin-only roster + role/active toggles work, never
leak password hashes, and refuse to lock the acting admin out.
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
    db_path = tmp_path / "users.db"
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


def _admin_token(client):
    return client.post("/api/auth/login",
                       json={"username": "admin", "password": "admin-passw0rd"}).json()["token"]


def _seed_users(client, headers):
    admin_token = _admin_token(client)
    h = {"Authorization": f"Bearer {admin_token}"}
    client.post("/api/auth/users", headers=h,
                json={"username": "alice", "password": "alice-secret1", "role": "operator"})
    client.post("/api/auth/users", headers=h,
                json={"username": "bob", "password": "bob-secret-42", "role": "viewer"})


def test_list_users_admin_only(stack):
    client, headers = stack
    r = client.get("/api/auth/users", headers=headers)
    assert r.status_code == 200
    rows = r.json()
    # Bootstrap admin always present.
    usernames = {row["username"] for row in rows}
    assert "admin" in usernames
    # Password hash never leaks.
    assert all("password_hash" not in row for row in rows), rows


def test_list_users_viewer_forbidden(stack):
    client, _ = stack
    admin_token = _admin_token(client)
    client.post("/api/auth/users",
                headers={"Authorization": f"Bearer {admin_token}"},
                json={"username": "carol", "password": "carol-secret1", "role": "viewer"})
    carol = client.post("/api/auth/login",
                        json={"username": "carol", "password": "carol-secret1"}).json()["token"]
    r = client.get("/api/auth/users", headers={"Authorization": f"Bearer {carol}"})
    assert r.status_code == 403


def test_list_users_returns_seeded(stack):
    client, headers = stack
    _seed_users(client, headers)
    r = client.get("/api/auth/users", headers=headers)
    usernames = {row["username"] for row in r.json()}
    assert {"admin", "alice", "bob"}.issubset(usernames)
    roles = {row["username"]: row["role"] for row in r.json()}
    assert roles["alice"] == "operator"
    assert roles["bob"] == "viewer"


def test_patch_user_role_and_active(stack):
    client, headers = stack
    _seed_users(client, headers)
    users = client.get("/api/auth/users", headers=headers).json()
    bob = next(u for u in users if u["username"] == "bob")
    r = client.patch(f"/api/auth/users/{bob['id']}", headers=headers,
                     json={"role": "operator"})
    assert r.status_code == 200, r.text
    assert r.json()["role"] == "operator"

    r = client.patch(f"/api/auth/users/{bob['id']}", headers=headers,
                     json={"is_active": False})
    assert r.status_code == 200
    assert r.json()["is_active"] is False

    # Audit row exists for each mutation.
    audit = client.get("/api/auth/audit", headers=headers).json()
    actions = [e["action"] for e in audit["events"]]
    assert actions.count("auth.user.updated") >= 2


def test_patch_user_self_lockout_refused(stack):
    client, headers = stack
    me = client.get("/api/auth/me", headers=headers).json()
    # Deactivating self
    r = client.patch(f"/api/auth/users/{me['id']}", headers=headers,
                     json={"is_active": False})
    assert r.status_code == 400
    # Demoting self
    r = client.patch(f"/api/auth/users/{me['id']}", headers=headers,
                     json={"role": "viewer"})
    assert r.status_code == 400


def test_patch_unknown_user_404(stack):
    client, headers = stack
    r = client.patch("/api/auth/users/user_nope", headers=headers,
                     json={"role": "viewer"})
    assert r.status_code == 404


def test_patch_users_viewer_forbidden(stack):
    client, _ = stack
    admin_token = _admin_token(client)
    client.post("/api/auth/users",
                headers={"Authorization": f"Bearer {admin_token}"},
                json={"username": "view", "password": "view-secret1", "role": "viewer"})
    me_users = client.get("/api/auth/users",
                          headers={"Authorization": f"Bearer {admin_token}"}).json()
    bob = next(u for u in me_users if u["username"] == "view")
    vt = client.post("/api/auth/login",
                     json={"username": "view", "password": "view-secret1"}).json()["token"]
    r = client.patch(f"/api/auth/users/{bob['id']}",
                     headers={"Authorization": f"Bearer {vt}"},
                     json={"role": "admin"})
    assert r.status_code == 403
