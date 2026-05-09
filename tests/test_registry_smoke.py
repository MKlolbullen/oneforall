"""Cross-repo smoke: every tool/profile YAML loads against the real Pydantic schema,
the FastAPI app constructs cleanly, and the legacy oneforall wireup is present."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "apps" / "api"))


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    # Force a hermetic config so importing app.* doesn't hit a real DB / Redis.
    monkeypatch.setenv("TOOL_REGISTRY_DIR", str(REPO / "packages/tool-registry/tools"))
    monkeypatch.setenv("PROFILE_REGISTRY_DIR", str(REPO / "packages/tool-registry/profiles"))
    monkeypatch.setenv("PLATFORM_CONFIG_PATH",
                       str(REPO / "packages/platform-config/sniper-inspired.yaml"))
    monkeypatch.setenv("GREP_PATTERNS_PATH",
                       str(REPO / "packages/patterns/sniper-grep-patterns.yaml"))
    monkeypatch.setenv("WORDLISTS_DIR", str(REPO / "packages/wordlists"))
    monkeypatch.setenv("DATABASE_URL", "sqlite:///./reconforge-test.db")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("ARTIFACT_BACKEND", "local")
    monkeypatch.setenv("ARTIFACT_DIR", str(REPO / "artifacts"))
    monkeypatch.setenv("EXECUTION_MODE", "dry_run")
    monkeypatch.setenv("ALLOW_LIVE_EXECUTION", "false")
    monkeypatch.setenv("RUNNER_MODE", "in_process")
    # Clear cached settings between tests
    from app.core.config import get_settings
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_every_tool_yaml_validates():
    from app.services.tool_registry import ToolRegistry
    from app.core.config import get_settings
    s = get_settings()
    reg = ToolRegistry(s.tool_registry_dir, s.profile_registry_dir)
    tools = reg.list_tools()
    assert len(tools) >= 130, f"expected >=130 tools, got {len(tools)}"
    ids = {t.id for t in tools}
    assert "oneforall" in ids, "oneforall pipeline tool missing"
    for sid in ("s01_passive", "s02_active", "s03_techscan", "s04_crawl",
                "s05_secrets", "s06_fuzz", "s07_api", "s08_urlsort",
                "s09_vuln", "s10_report"):
        assert f"oneforall_{sid}" in ids, f"oneforall_{sid} stage tool missing"


def test_every_profile_resolves_its_steps():
    from app.services.tool_registry import ToolRegistry
    from app.core.config import get_settings
    s = get_settings()
    reg = ToolRegistry(s.tool_registry_dir, s.profile_registry_dir)
    profiles = reg.list_profiles()
    assert len(profiles) >= 24, f"expected >=24 profiles, got {len(profiles)}"
    assert any(p.get("id") == "oneforall_chain" for p in profiles), "oneforall_chain profile missing"
    for prof in profiles:
        for step in prof.get("steps", []):
            tool_id = step["tool"]
            reg.get_tool(tool_id)  # raises KeyError if missing


def test_app_constructs():
    from app.main import app
    assert app.title


def test_health_endpoint_returns_expected_keys():
    from app.main import app
    from fastapi.testclient import TestClient
    with TestClient(app) as client:
        r = client.get("/health")
        assert r.status_code == 200
        body = r.json()
        for k in ("status", "execution_mode", "live_execution_enabled",
                  "runner_mode", "artifact_backend"):
            assert k in body
