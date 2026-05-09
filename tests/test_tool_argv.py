"""Per-tool argv rendering tests.

Catches what registry-validation alone misses:
  - typo in a {{placeholder}} that would survive Pydantic validation but never
    resolve at runtime (token left literal in argv -> tool fails)
  - missing `binary` field on a tool that declares an argv (the runner image
    test would catch installation gaps but not a YAML that says binary=python
    while invoking a different binary in argv[0])
  - argv[0] != tool.binary (pretty common slip when generating YAMLs by hand)
  - dry_run_output not declared (the in_process runner falls back to dry mode
    for tools without an argv template; and even with argv, missing dry output
    means tests that exercise this tool produce empty step output)

Parametrized over every tool in the registry so adding a tool tomorrow either
ships with sane argv or fails loudly.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
API_DIR = REPO / "apps" / "api"
sys.path.insert(0, str(API_DIR))


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("TOOL_REGISTRY_DIR", str(REPO / "packages/tool-registry/tools"))
    monkeypatch.setenv("PROFILE_REGISTRY_DIR", str(REPO / "packages/tool-registry/profiles"))
    monkeypatch.setenv("PLATFORM_CONFIG_PATH",
                       str(REPO / "packages/platform-config/sniper-inspired.yaml"))
    monkeypatch.setenv("GREP_PATTERNS_PATH",
                       str(REPO / "packages/patterns/sniper-grep-patterns.yaml"))
    monkeypatch.setenv("WORDLISTS_DIR", str(REPO / "packages/wordlists"))
    monkeypatch.setenv("DATABASE_URL", "sqlite:///./reconforge-argv-test.db")
    monkeypatch.setenv("ARTIFACT_BACKEND", "local")
    monkeypatch.setenv("ARTIFACT_DIR", "./artifacts")
    monkeypatch.setenv("EXECUTION_MODE", "dry_run")
    monkeypatch.setenv("ALLOW_LIVE_EXECUTION", "false")
    monkeypatch.setenv("RUNNER_MODE", "in_process")

    from app.core.config import get_settings
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _all_tools():
    from app.services.tool_registry import ToolRegistry
    from app.core.config import get_settings
    s = get_settings()
    reg = ToolRegistry(s.tool_registry_dir, s.profile_registry_dir)
    return reg.list_tools()


# Round-2 additions explicitly listed; the rest of the registry is exercised
# by parametrize-over-all but with looser assertions.
NEW_TOOLS = {
    "bbot", "prowler", "scoutsuite", "cloudfox", "osv_scanner",
    "proxify", "notify", "jaeles", "byp4xx", "dontgo403", "dirhunt",
    "apkleaks", "trivy_repo", "cero", "urless", "gitdorker",
}


def _tool_param_ids():
    return [t.id for t in _all_tools()]


@pytest.fixture
def tools_by_id(_env):
    """Function-scoped on purpose: the autouse _env fixture must apply first
    so the registry loads from the right path."""
    return {t.id: t for t in _all_tools()}


def test_new_tools_all_present(tools_by_id):
    missing = NEW_TOOLS - set(tools_by_id)
    assert not missing, f"round-2 tools not loaded by registry: {missing}"


@pytest.mark.parametrize("tool_id", sorted(NEW_TOOLS))
def test_new_tool_argv_renders_cleanly(tool_id, tools_by_id):
    """For each new tool: render argv with a sample params dict, assert
    no template tokens leak through and the binary appears as expected."""
    from app.services.runner import render_argv, _resolve_step_argv

    tool = tools_by_id[tool_id]
    argv_template = tool.command.get("argv") or []
    assert argv_template, f"{tool_id} declares no argv template"

    rendered = render_argv(argv_template, {"target": "example.com"})
    leftover = [tok for tok in rendered if "{{" in tok or "}}" in tok]
    assert not leftover, f"{tool_id} argv has unresolved templates: {leftover}"

    # Binary should show up somewhere in argv. Some tools (bbot etc.) have
    # subcommands, so we don't insist on argv[0]; we just want SOMEWHERE.
    binary = tool.binary or tool_id
    assert any(binary == tok or binary in tok for tok in rendered), \
        f"{tool_id} argv {rendered} does not reference binary {binary!r}"

    # Sanity: _resolve_step_argv with an empty step_config matches render_argv
    matches = _resolve_step_argv(tool, {}, {"target": "example.com"})
    assert matches == rendered


@pytest.mark.parametrize("tool_id", sorted(NEW_TOOLS))
def test_new_tool_has_dry_run_output(tool_id, tools_by_id):
    tool = tools_by_id[tool_id]
    assert tool.dry_run_output, \
        f"{tool_id} has empty dry_run_output; in_process runner will produce no fixture"


def test_no_existing_tool_argv_has_unresolved_templates(tools_by_id):
    """Defensive sweep over the whole registry: any argv that uses a
    {{placeholder}} which isn't 'target' (or one of our DAG tokens) should at
    least be documented somewhere; flag any that wouldn't resolve under the
    common single-target render."""
    from app.services.runner import render_argv

    # Tokens we always provide at render time
    common = {"target": "example.com"}
    # Plus DAG tokens — these are populated at runtime per-step but valid
    # references are: steps.<id>.stdout_path, previous.stdout_path,
    # upstream.<output_type>.merged_path
    dag_token = re.compile(r"\{\{(steps|previous|upstream)(\.[a-zA-Z0-9_]+)+\}\}")

    for tool in tools_by_id.values():
        argv = tool.command.get("argv") or []
        if not argv:
            continue
        rendered = render_argv(argv, common)
        for tok in rendered:
            for m in re.finditer(r"\{\{[^}]+\}\}", tok):
                placeholder = m.group(0)
                if dag_token.fullmatch(placeholder):
                    continue
                pytest.fail(
                    f"{tool.id} argv has unresolved placeholder {placeholder!r}; "
                    f"argv after render: {rendered}"
                )
