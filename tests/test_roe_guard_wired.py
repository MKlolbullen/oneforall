"""ROE engine wired into the run-creation paths.

The engine is opt-in: when `settings.roe_policy_path` doesn't exist the
guard no-ops and the platform behaves exactly as before. These tests
turn the engine on by writing a per-test policy file and pointing the
setting at it, then verify the new gates fire at every run-creation
endpoint:

  POST /api/runs            — named profile
  POST /api/runs/adhoc      — Workflow Builder canvas
  POST /api/runs/{id}/rerun — Re-run button
  POST /api/workflows/{id}/launch — saved workflow

Covers:
  - per-tool approval gate (V4 / V5 / V6's "engine-layer policy")
  - active scan time window (limits.active_scan_window)
  - default-disabled behaviour (no policy file → no engine intervention)
  - engine catches a target the legacy scope check would have allowed
    because the policy file declares stricter allowed.cidrs
"""
from __future__ import annotations

import sys
import textwrap
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
API_DIR = REPO / "apps" / "api"
sys.path.insert(0, str(API_DIR))


def _write_policy(tmp_path: Path, policy_yaml: str) -> Path:
    """Drop a per-test policy file in tmp and return its path. Uses
    textwrap.dedent so the test source can keep the YAML indented."""
    target = tmp_path / "roe.yaml"
    target.write_text(textwrap.dedent(policy_yaml).lstrip(), encoding="utf-8")
    return target


@pytest.fixture
def stack(tmp_path, monkeypatch):
    db_path = tmp_path / "roe.db"
    art_dir = tmp_path / "artifacts"
    art_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("TOOL_REGISTRY_DIR", str(REPO / "packages/tool-registry/tools"))
    monkeypatch.setenv("PROFILE_REGISTRY_DIR", str(REPO / "packages/tool-registry/profiles"))
    monkeypatch.setenv("PLATFORM_CONFIG_PATH",
                       str(REPO / "packages/platform-config/sniper-inspired.yaml"))
    monkeypatch.setenv("GREP_PATTERNS_PATH",
                       str(REPO / "packages/patterns/sniper-grep-patterns.yaml"))
    monkeypatch.setenv("WORDLISTS_DIR", str(REPO / "packages/wordlists"))
    # Default: engine OFF (file at this path won't exist). Per-test fixtures
    # can override by writing a file and setting ROE_POLICY_PATH below.
    monkeypatch.setenv("ROE_POLICY_PATH", str(tmp_path / "roe-disabled.yaml"))
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
    # Bust the engine cache so any prior test's load doesn't bleed in.
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


def _set_policy(monkeypatch, policy_path: Path) -> None:
    """Re-point ROE_POLICY_PATH at the test's policy file. Clears the
    cached engine + the settings cache so the next request reloads."""
    monkeypatch.setenv("ROE_POLICY_PATH", str(policy_path))
    from app.core.config import get_settings
    get_settings.cache_clear()
    from app.services.roe_guard import clear_engine_cache
    clear_engine_cache()


def _seed_workspace_target(client, headers, *, host="roe.example.com", active=True):
    ws_id = client.get("/api/workspaces", headers=headers).json()[0]["id"]
    target = client.post("/api/targets", headers=headers, json={
        "workspace_id": ws_id, "value": host, "type": "domain",
        "in_scope": True, "passive_allowed": True, "active_allowed": active,
    }).json()
    return ws_id, target


# ---------------------------------------------------------------------------
# Engine OFF by default — every run-creation path still works.
# ---------------------------------------------------------------------------

def test_no_policy_file_means_no_engine_intervention(stack):
    client, headers, _ = stack
    ws_id, target = _seed_workspace_target(client, headers)
    # passive_recon = passive risk, target is in scope, no policy file
    r = client.post("/api/runs", headers=headers, json={
        "workspace_id": ws_id, "target_id": target["id"],
        "profile_id": "passive_recon",
    })
    assert r.status_code == 201, r.text


# ---------------------------------------------------------------------------
# Per-tool approval gate — wires the engine's `approval.require_for_tools`.
# ---------------------------------------------------------------------------

def test_per_tool_approval_blocks_adhoc_run_with_listed_tool(stack, monkeypatch):
    """The engine's `approval.require_for_tools` is the new gate this
    commit adds. We pick `subfinder` (passive risk in the registry) so the
    legacy high-risk gate has nothing to fire — any 403 comes from the
    engine and only from the engine."""
    client, headers, tmp_path = stack
    policy = _write_policy(tmp_path, """
        allowed:
          domains: ["*.example.com", "example.com"]
        approval:
          require_for_tools:
            - subfinder
    """)
    _set_policy(monkeypatch, policy)

    ws_id, target = _seed_workspace_target(client, headers)

    # Without manual_approval: engine refuses.
    bad = client.post("/api/runs/adhoc", headers=headers, json={
        "workspace_id": ws_id, "target_id": target["id"],
        "name": "no consent",
        "steps": [{"tool": "subfinder"}],
    })
    assert bad.status_code == 403, bad.text
    detail = bad.json()["detail"]
    assert detail["decision"] == "require_approval"
    assert "approval" in (detail.get("matched_rule") or "")

    # Same workflow with manual_approval=true clears the engine.
    ok = client.post("/api/runs/adhoc", headers=headers, json={
        "workspace_id": ws_id, "target_id": target["id"],
        "name": "with consent",
        "steps": [{"tool": "subfinder"}],
        "params": {"manual_approval": True},
    })
    assert ok.status_code == 201, ok.text


def test_per_tool_approval_fires_on_workflow_launch(stack, monkeypatch):
    """Same gate on POST /api/workflows/{id}/launch — using `subfinder`
    so the legacy risk gate is silent and the 403 demonstrably comes
    from the engine."""
    client, headers, tmp_path = stack
    ws_id, target = _seed_workspace_target(client, headers)

    # Save the workflow first while the engine is off (no policy file yet).
    wf = client.post("/api/workflows", headers=headers, json={
        "workspace_id": ws_id, "name": "subfinder workflow",
        "body": {"steps": [{"tool": "subfinder"}]},
    }).json()

    policy = _write_policy(tmp_path, """
        allowed:
          domains: ["*.example.com", "example.com"]
        approval:
          require_for_tools:
            - subfinder
    """)
    _set_policy(monkeypatch, policy)

    r = client.post(f"/api/workflows/{wf['id']}/launch", headers=headers, json={
        "target_id": target["id"],
    })
    assert r.status_code == 403, r.text
    detail = r.json()["detail"]
    # The engine's structured decision body carries through the 403.
    assert detail["decision"] == "require_approval"
    assert "approval" in (detail.get("matched_rule") or "")


# ---------------------------------------------------------------------------
# Time-window enforcement — active scans only inside `limits.active_scan_window`.
# ---------------------------------------------------------------------------

def test_active_scan_outside_window_requires_approval(stack, monkeypatch):
    """The engine treats out-of-window active scans as require_approval.
    Setting a window of 00:00-00:00 with UTC reliably puts "now" outside it
    in CI regardless of the host's clock."""
    client, headers, tmp_path = stack
    policy = _write_policy(tmp_path, """
        allowed:
          domains: ["*.example.com", "example.com"]
        limits:
          active_scan_window:
            start: "00:00"
            end: "00:00"
            timezone: "UTC"
    """)
    _set_policy(monkeypatch, policy)

    ws_id, target = _seed_workspace_target(client, headers)
    # `crawler_url_intel` is low_active, so the legacy gate passes given
    # active_allowed=True; the engine's time-window is what should fire.
    r = client.post("/api/runs", headers=headers, json={
        "workspace_id": ws_id, "target_id": target["id"],
        "profile_id": "crawler_url_intel",
    })
    assert r.status_code == 403, r.text
    detail = r.json()["detail"]
    assert detail["decision"] == "require_approval"
    assert "active_scan_window" in (detail.get("matched_rule") or "")


# ---------------------------------------------------------------------------
# Engine catches what legacy misses — a target that's in scope per the
# Target row but outside the engine's allowed.domains.
# ---------------------------------------------------------------------------

def test_engine_denies_target_outside_allowed_domains(stack, monkeypatch):
    """Legacy gate passes (target.in_scope=true, active_allowed=true) but
    the engine refuses because the host isn't in the policy's allowed
    domains. Demonstrates defense in depth — the engine narrows scope
    independently of the Target row."""
    client, headers, tmp_path = stack
    policy = _write_policy(tmp_path, """
        allowed:
          domains:
            - "lab.example.com"
            - "*.lab.example.com"
    """)
    _set_policy(monkeypatch, policy)

    ws_id, target = _seed_workspace_target(client, headers, host="prod.example.com")
    r = client.post("/api/runs", headers=headers, json={
        "workspace_id": ws_id, "target_id": target["id"],
        "profile_id": "passive_recon",
    })
    assert r.status_code == 403, r.text
    detail = r.json()["detail"]
    assert detail["decision"] == "deny"
    assert "allowed.domains" in (detail.get("matched_rule") or "")


# ---------------------------------------------------------------------------
# Re-run path: tightening the policy AFTER the original run denies the rerun.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# V4 — argv extractor + engine: allowed.ports actually enforced.
# ---------------------------------------------------------------------------

def test_explicit_port_outside_allowlist_denies_adhoc_run(stack, monkeypatch):
    """An ad-hoc step that names port 22 via `-p 22` argv_extra is denied
    when the policy allowlists only 80/443. Demonstrates V4 enforcement
    at run-creation time without needing an HTTP-capture middleware."""
    client, headers, tmp_path = stack
    _set_policy(monkeypatch, _write_policy(tmp_path, """
        allowed:
          domains: ["*.example.com", "example.com"]
          ports: [80, 443]
    """))
    ws_id, target = _seed_workspace_target(client, headers)
    r = client.post("/api/runs/adhoc", headers=headers, json={
        "workspace_id": ws_id, "target_id": target["id"],
        "name": "port 22 attempt",
        "steps": [{"tool": "subfinder", "argv_extra": ["-p", "22"]}],
    })
    assert r.status_code == 403, r.text
    detail = r.json()["detail"]
    assert detail["decision"] == "deny"
    assert detail["matched_rule"] == "allowed.ports"


def test_explicit_port_in_allowlist_runs_clean(stack, monkeypatch):
    """Same policy + explicit port 443 → engine allows. Inverse of the
    previous test, so a regression that broke the parser would surface
    as both flipping."""
    client, headers, tmp_path = stack
    _set_policy(monkeypatch, _write_policy(tmp_path, """
        allowed:
          domains: ["*.example.com", "example.com"]
          ports: [80, 443]
    """))
    ws_id, target = _seed_workspace_target(client, headers)
    r = client.post("/api/runs/adhoc", headers=headers, json={
        "workspace_id": ws_id, "target_id": target["id"],
        "name": "port 443 OK",
        "steps": [{"tool": "subfinder", "argv_extra": ["-p", "443"]}],
    })
    assert r.status_code == 201, r.text


def test_broad_port_scan_denied_when_ports_allowlist_set(stack, monkeypatch):
    """A profile step using `--top-ports 1000` doesn't name specific
    ports; the parser flags it as a broad scan and the guard probes port
    22 against the policy. Operators that allowlist 80/443 see the broad
    scan refused — closes the V4 gap for tools whose defaults span SSH /
    RDP / etc."""
    client, headers, tmp_path = stack
    _set_policy(monkeypatch, _write_policy(tmp_path, """
        allowed:
          domains: ["*.example.com", "example.com"]
          ports: [80, 443]
    """))
    ws_id, target = _seed_workspace_target(client, headers)
    r = client.post("/api/runs/adhoc", headers=headers, json={
        "workspace_id": ws_id, "target_id": target["id"],
        "name": "broad scan",
        "steps": [{"tool": "subfinder", "argv_extra": ["--top-ports", "1000"]}],
    })
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["decision"] == "deny"


# ---------------------------------------------------------------------------
# V5 — argv extractor + engine: denied.methods actually enforced.
# ---------------------------------------------------------------------------

def test_denied_method_in_argv_denies_run(stack, monkeypatch):
    """`-X DELETE` in argv now sends `method=DELETE` to the engine; a
    policy that denies DELETE refuses the run at creation."""
    client, headers, tmp_path = stack
    _set_policy(monkeypatch, _write_policy(tmp_path, """
        allowed:
          domains: ["*.example.com", "example.com"]
        denied:
          methods: ["DELETE", "TRACE"]
    """))
    ws_id, target = _seed_workspace_target(client, headers)
    r = client.post("/api/runs/adhoc", headers=headers, json={
        "workspace_id": ws_id, "target_id": target["id"],
        "name": "DELETE attempt",
        "steps": [{"tool": "subfinder", "argv_extra": ["-X", "DELETE"]}],
    })
    assert r.status_code == 403, r.text
    detail = r.json()["detail"]
    assert detail["decision"] == "deny"
    assert detail["matched_rule"].startswith("denied.methods")


def test_safe_method_in_argv_runs_clean(stack, monkeypatch):
    """Same policy + a method NOT in the deny list → engine allows."""
    client, headers, tmp_path = stack
    _set_policy(monkeypatch, _write_policy(tmp_path, """
        allowed:
          domains: ["*.example.com", "example.com"]
        denied:
          methods: ["DELETE", "TRACE"]
    """))
    ws_id, target = _seed_workspace_target(client, headers)
    r = client.post("/api/runs/adhoc", headers=headers, json={
        "workspace_id": ws_id, "target_id": target["id"],
        "name": "GET is fine",
        "steps": [{"tool": "subfinder", "argv_extra": ["-X", "GET"]}],
    })
    assert r.status_code == 201, r.text


# ---------------------------------------------------------------------------
# V6 — argv extractor + engine: limits.max_rps actually enforced.
# ---------------------------------------------------------------------------

def test_argv_rps_over_max_denies_run(stack, monkeypatch):
    """`-rate-limit 50` in argv when max_rps=5 → 403. This is the one
    place the engine's rate_limit decision is elevated to a deny — the
    operator's argv explicitly asks for a rate the policy refuses."""
    client, headers, tmp_path = stack
    _set_policy(monkeypatch, _write_policy(tmp_path, """
        allowed:
          domains: ["*.example.com", "example.com"]
        limits:
          max_rps: 5
    """))
    ws_id, target = _seed_workspace_target(client, headers)
    r = client.post("/api/runs/adhoc", headers=headers, json={
        "workspace_id": ws_id, "target_id": target["id"],
        "name": "too fast",
        "steps": [{"tool": "subfinder", "argv_extra": ["-rate-limit", "50"]}],
    })
    assert r.status_code == 403, r.text
    detail = r.json()["detail"]
    assert detail["decision"] == "rate_limit"
    assert detail["matched_rule"] == "limits.max_rps"
    # effective_limits carries the configured ceiling so the operator
    # knows what to dial argv back to.
    assert detail["effective_limits"]["max_rps"] == 5


def test_argv_rps_within_max_runs_clean(stack, monkeypatch):
    """rate within the policy's limit clears the engine."""
    client, headers, tmp_path = stack
    _set_policy(monkeypatch, _write_policy(tmp_path, """
        allowed:
          domains: ["*.example.com", "example.com"]
        limits:
          max_rps: 50
    """))
    ws_id, target = _seed_workspace_target(client, headers)
    r = client.post("/api/runs/adhoc", headers=headers, json={
        "workspace_id": ws_id, "target_id": target["id"],
        "name": "polite rate",
        "steps": [{"tool": "subfinder", "argv_extra": ["-rate-limit", "5"]}],
    })
    assert r.status_code == 201, r.text


def test_named_profile_default_argv_evaluated(stack, monkeypatch):
    """The argv extractor also reads the tool registry's default argv,
    not just step overrides. `naabu` defaults to `-top-ports 1000` — if
    the policy allowlists only 80/443, the engine refuses the run even
    though the operator never explicitly named a port."""
    client, headers, tmp_path = stack
    _set_policy(monkeypatch, _write_policy(tmp_path, """
        allowed:
          domains: ["*.example.com", "example.com"]
          ports: [80, 443]
    """))
    ws_id, target = _seed_workspace_target(client, headers)
    r = client.post("/api/runs/adhoc", headers=headers, json={
        "workspace_id": ws_id, "target_id": target["id"],
        "name": "naabu defaults",
        "steps": [{"tool": "naabu"}],  # uses the tool's default -top-ports 1000
    })
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["decision"] == "deny"


def test_rerun_respects_policy_tightened_after_original_run(stack, monkeypatch):
    """An operator runs `passive_recon` against prod.example.com when no
    policy is active. The platform's policy is then tightened to lab-only.
    Hitting Re-run on the original run must 403 — the engine is re-evaluated
    on every rerun, so a tightened policy catches retries."""
    client, headers, tmp_path = stack
    ws_id, target = _seed_workspace_target(client, headers, host="prod.example.com")

    # 1) Engine off → create + run succeeds
    original = client.post("/api/runs", headers=headers, json={
        "workspace_id": ws_id, "target_id": target["id"],
        "profile_id": "passive_recon",
    })
    assert original.status_code == 201, original.text
    original_id = original.json()["id"]

    # wait for it to complete so the rerun's policy check is the only
    # delta vs the original
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if client.get(f"/api/runs/{original_id}", headers=headers).json()["status"] == "completed":
            break
        time.sleep(0.2)

    # 2) Tighten the policy: only *.lab.example.com is allowed now.
    policy = _write_policy(tmp_path, """
        allowed:
          domains:
            - "lab.example.com"
            - "*.lab.example.com"
    """)
    _set_policy(monkeypatch, policy)

    # 3) Rerun must fail.
    rerun = client.post(f"/api/runs/{original_id}/rerun", headers=headers)
    assert rerun.status_code == 403, rerun.text
    assert rerun.json()["detail"]["decision"] == "deny"
