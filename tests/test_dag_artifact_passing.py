"""Tests for milestone #1: DAG artifact passing.

Each step should be able to read upstream step output via template variables in
its argv. The runner should record the rendered argv into RunStep.meta so we can
assert on what the next tool actually got."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "apps" / "api"))


@pytest.fixture(autouse=True)
def _env(monkeypatch, tmp_path):
    db_path = tmp_path / "rf.db"
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
    yield
    from app.core.config import get_settings
    get_settings.cache_clear()


def test_render_argv_resolves_nested_keys():
    from app.services.runner import render_argv
    params = {
        "target": "example.com",
        "steps": {
            "subfinder": {"stdout_path": "/tmp/01_subfinder.stdout.txt"},
        },
        "upstream": {
            "domain_list": {"merged_path": "/tmp/upstream_domain_list.txt"},
        },
        "previous": {"stdout_path": "/tmp/05_crtsh.stdout.txt"},
    }
    out = render_argv(
        ["dnsx", "-silent", "-l", "{{upstream.domain_list.merged_path}}",
         "--prev", "{{previous.stdout_path}}", "-d", "{{target}}"],
        params,
    )
    assert out == [
        "dnsx", "-silent", "-l", "/tmp/upstream_domain_list.txt",
        "--prev", "/tmp/05_crtsh.stdout.txt", "-d", "example.com",
    ]


def test_render_argv_unknown_token_left_unresolved():
    """Defensive: an unknown placeholder is left literal so failures are obvious
    rather than silently dropping argv elements."""
    from app.services.runner import render_argv
    out = render_argv(["dnsx", "{{nope.xxx}}"], {"target": "example.com"})
    assert out == ["dnsx", "{{nope.xxx}}"]


def test_argv_replace_overrides_tool_template():
    from app.services.runner import _resolve_step_argv
    from app.services.tool_registry import ToolRegistry
    from app.core.config import get_settings
    s = get_settings()
    reg = ToolRegistry(s.tool_registry_dir, s.profile_registry_dir)
    tool = reg.get_tool("dnsx")
    step = {
        "tool": "dnsx",
        "argv_replace": [
            "dnsx", "-silent", "-l", "{{upstream.domain_list.merged_path}}",
        ],
    }
    rendered = {"upstream": {"domain_list": {"merged_path": "/scratch/up.txt"}}}
    out = _resolve_step_argv(tool, step, rendered)
    assert out == ["dnsx", "-silent", "-l", "/scratch/up.txt"]


def test_argv_extra_appends_to_tool_template():
    from app.services.runner import _resolve_step_argv
    from app.services.tool_registry import ToolRegistry
    from app.core.config import get_settings
    s = get_settings()
    reg = ToolRegistry(s.tool_registry_dir, s.profile_registry_dir)
    tool = reg.get_tool("subfinder")
    step = {"tool": "subfinder", "argv_extra": ["-o", "/tmp/subs.txt"]}
    out = _resolve_step_argv(tool, step, {"target": "example.com"})
    assert out[:6] == ["subfinder", "-all", "-recursive", "-silent", "-d", "example.com"]
    assert out[-2:] == ["-o", "/tmp/subs.txt"]


def test_run_context_merges_domain_lists():
    from app.services.runner import RunContext
    from app.services.tool_registry import ToolRegistry
    from app.core.config import get_settings
    import tempfile
    s = get_settings()
    reg = ToolRegistry(s.tool_registry_dir, s.profile_registry_dir)

    with tempfile.TemporaryDirectory() as tmp:
        ctx = RunContext(run_id="r1", workspace_id="ws1", base_dir=Path(tmp))
        sub = reg.get_tool("subfinder")
        af = reg.get_tool("assetfinder")
        ctx.record_step(sub, ["api.example.com", "app.example.com"])
        ctx.record_step(af, ["app.example.com", "dev.example.com"])  # one overlap

        merged = ctx.upstream_merged.get("domain_list")
        assert merged is not None
        lines = merged.read_text().splitlines()
        # Order preserved by insertion, no duplicates
        assert lines == ["api.example.com", "app.example.com", "dev.example.com"]

        rendered = ctx.render_params({"target": "example.com"})
        assert rendered["upstream"]["domain_list"]["merged_path"] == str(merged)
        assert "subfinder" in rendered["steps"]
        assert "assetfinder" in rendered["steps"]
        assert rendered["previous"]["stdout_path"].endswith("02_assetfinder.stdout.txt")


def test_passive_recon_chains_subfinder_into_dnsx_into_httpx():
    """End-to-end: run passive_recon and assert the dnsx step's recorded argv contains
    a path to an upstream merged file that actually has subfinder's lines."""
    import time
    from fastapi.testclient import TestClient
    from app.main import app

    headers = {"X-Test-User": "admin"}
    with TestClient(app) as client:
        ws = client.get("/api/workspaces", headers=headers).json()[0]
        # Seed target has active_allowed=False; adding httpx made passive_recon
        # low_active. Create a fresh target authorized for active scanning.
        created = client.post(
            "/api/targets",
            json={"workspace_id": ws["id"], "value": "lab.example.com",
                  "type": "domain", "in_scope": True,
                  "passive_allowed": True, "active_allowed": True,
                  "notes": "DAG test target"},
            headers=headers,
        )
        assert created.status_code == 201, created.text
        target_id = created.json()["id"]
        run = client.post(
            "/api/runs",
            json={"workspace_id": ws["id"], "target_id": target_id,
                  "profile_id": "passive_recon", "requested_by": "dag-test"},
            headers=headers,
        )
        assert run.status_code == 201, run.text
        run_id = run.json()["id"]

        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            r = client.get(f"/api/runs/{run_id}", headers=headers)
            if r.json()["status"] == "completed":
                break
            time.sleep(0.3)
        else:
            raise AssertionError(
                f"run did not complete: {client.get(f'/api/runs/{run_id}', headers=headers).json()}"
            )

        steps = client.get(f"/api/runs/{run_id}/steps", headers=headers).json()
        by_tool = {s["tool_id"]: s for s in steps}
        assert "dnsx" in by_tool and "httpx" in by_tool

        dnsx_argv = by_tool["dnsx"]["meta"].get("argv", [])
        # The argv must contain the substituted upstream merged path
        assert "-l" in dnsx_argv, f"dnsx argv missing -l flag: {dnsx_argv}"
        l_index = dnsx_argv.index("-l")
        merged_path = Path(dnsx_argv[l_index + 1])
        assert merged_path.exists(), f"merged upstream path does not exist: {merged_path}"
        merged_content = merged_path.read_text()
        # subfinder's dry_run_output is app/api/dev.example.com — at least one must show up
        assert any(host in merged_content
                   for host in ("app.example.com", "api.example.com", "dev.example.com")), \
            f"merged file does not contain expected subdomains: {merged_content!r}"

        # httpx should also be wired to the same merged file (same chain)
        httpx_argv = by_tool["httpx"]["meta"].get("argv", [])
        assert "-l" in httpx_argv
        assert str(merged_path) == httpx_argv[httpx_argv.index("-l") + 1]
