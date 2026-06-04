"""Regression tests for ROE / scope-enforcement vulnerabilities.

These started as proofs-of-concept asserting the unsafe behaviour (PoC
mode); the same file has been re-tightened so each test now asserts the
SAFE behaviour after the V1 / V2 / V3 / V7 / V8 fixes shipped.

  - V1, V2, V3 fixes live in `apps/api/app/services/scope.py`.
  - V7, V8 fixes live in `apps/api/app/api/routes/runs.py:rerun_run`.

V4, V5, V6, V9 remain as documented gaps the ROE engine closes; their
tests still pass because they exercise the engine directly and don't
depend on the platform wiring it in.

See `docs/SECURITY_ADVISORY_ROE_SCOPE.md` for the written advisory and
fix references.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
API_DIR = REPO / "apps" / "api"
sys.path.insert(0, str(API_DIR))


# ============================================================================
# Pure scope-enforcement PoCs (no API client — direct call into the service).
# ============================================================================

@pytest.fixture
def _common_env(monkeypatch, tmp_path):
    """Minimal env so app.services.scope can import + run."""
    monkeypatch.setenv("TOOL_REGISTRY_DIR", str(REPO / "packages/tool-registry/tools"))
    monkeypatch.setenv("PROFILE_REGISTRY_DIR", str(REPO / "packages/tool-registry/profiles"))
    monkeypatch.setenv("PLATFORM_CONFIG_PATH",
                       str(REPO / "packages/platform-config/sniper-inspired.yaml"))
    monkeypatch.setenv("GREP_PATTERNS_PATH",
                       str(REPO / "packages/patterns/sniper-grep-patterns.yaml"))
    monkeypatch.setenv("WORDLISTS_DIR", str(REPO / "packages/wordlists"))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/scope-poc.db")
    monkeypatch.setenv("ARTIFACT_BACKEND", "local")
    monkeypatch.setenv("ARTIFACT_DIR", str(tmp_path / "artifacts"))
    from app.core.config import get_settings
    get_settings.cache_clear()


def test_poc_v1_block_private_ranges_is_a_silent_no_op(_common_env, monkeypatch):
    """V1 — `scope.block_private_ranges_by_default: true` is silently ignored.

    Severity: HIGH.

    Repro:
      - Platform config has `scope.block_private_ranges_by_default: true`.
      - Operator creates a target whose value is in RFC1918 space (e.g.
        10.10.50.5) with active_allowed=True.
      - The current scope code (`apps/api/app/services/scope.py:enforce_target_scope`)
        does NOT enforce any private-range policy: the field is never read
        anywhere in `apps/api/app/`.

    Impact:
      An operator who toggles "block private ranges" in the policy YAML
      believes internal networks are off-limits. The platform still allows
      runs against them. This is a "policy that does nothing" — exactly
      the kind of misconfiguration that breeds incidents.

    The ROE engine fixes this with `denied.cidrs`, but the field
    `block_private_ranges_by_default` needs to be either implemented or
    removed from the example config.
    """
    from app.models import RiskLevel, Target
    from app.services import scope as scope_mod

    # Patch platform config so the policy looks like an operator who toggled
    # the "block private ranges" intent on.
    monkeypatch.setattr(scope_mod, "load_platform_config", lambda: {
        "scope": {
            "enforce_out_of_scope_patterns": True,
            "default_out_of_scope": [],  # empty — only block_private would have applied
            "block_private_ranges_by_default": True,  # <-- operator's intent
            "require_active_authorization": True,
            "require_high_risk_manual_approval": True,
        }
    })

    target = Target(workspace_id="ws", value="10.10.50.5", type="ip",
                    in_scope=True, passive_allowed=True, active_allowed=True)

    # FIXED BEHAVIOUR — enforce_target_scope now reads
    # `block_private_ranges_by_default` and refuses RFC1918 / loopback /
    # link-local / ULA targets when it's enabled. Without the fix the test
    # was: `scope_mod.enforce_target_scope(target, RiskLevel.low_active)`
    # returning silently.
    with pytest.raises(scope_mod.ScopeError) as excinfo:
        scope_mod.enforce_target_scope(target, RiskLevel.low_active)
    assert "private" in str(excinfo.value).lower()

    # The ROE engine reaches the same conclusion via denied.cidrs.
    from app.services.scope_engine import ScopeAction, ScopeEngine
    engine = ScopeEngine({
        "allowed": {"cidrs": ["0.0.0.0/0"]},
        "denied": {"cidrs": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]},
    })
    decision = engine.evaluate_action(ScopeAction(target="10.10.50.5", risk="low_active"))
    assert decision.decision == "deny"
    assert "denied CIDR" in decision.reason


def test_poc_v2_cidr_pattern_in_out_of_scope_is_silently_ignored(_common_env, monkeypatch):
    """V2 — A CIDR pattern in `default_out_of_scope` does not deny IPs in the range.

    Severity: HIGH.

    Repro:
      - Operator writes `default_out_of_scope: ['10.10.50.0/24']` expecting
        CIDR semantics ("block this whole /24").
      - A target with value "10.10.50.5" is created.
      - `_matches_any` in scope.py treats the pattern as an fnmatch string;
        `fnmatch("10.10.50.5", "10.10.50.0/24")` is False, so the target
        passes scope.

    Impact:
      The platform pretends to honour a CIDR pattern. Operators who paste
      a CIDR into the deny list will not get the protection they expect.

    The ROE engine fixes this with a true CIDR matcher (`ipaddress.ip_network`).
    """
    from app.models import RiskLevel, Target
    from app.services import scope as scope_mod

    monkeypatch.setattr(scope_mod, "load_platform_config", lambda: {
        "scope": {
            "enforce_out_of_scope_patterns": True,
            # Operator intent: block any IP in this /24.
            "default_out_of_scope": ["10.10.50.0/24"],
            "require_active_authorization": True,
        }
    })

    target = Target(workspace_id="ws", value="10.10.50.5", type="ip",
                    in_scope=True, passive_allowed=True, active_allowed=True)

    # FIXED BEHAVIOUR — `_matches_any` now recognises CIDR-shaped patterns
    # and uses `ipaddress.ip_network` for matching. The IP target lands
    # inside the configured /24 deny block and scope refuses it.
    with pytest.raises(scope_mod.ScopeError) as excinfo:
        scope_mod.enforce_target_scope(target, RiskLevel.low_active)
    assert "10.10.50.0/24" in str(excinfo.value)

    # The ROE engine reaches the same decision via denied.cidrs.
    from app.services.scope_engine import ScopeAction, ScopeEngine
    engine = ScopeEngine({
        "allowed": {"cidrs": ["10.0.0.0/8"]},
        "denied": {"cidrs": ["10.10.50.0/24"]},
    })
    decision = engine.evaluate_action(ScopeAction(target="10.10.50.5", risk="low_active"))
    assert decision.decision == "deny"
    assert "denied CIDR" in decision.reason


def test_poc_v3_wildcard_only_matches_subdomain_not_apex(_common_env, monkeypatch):
    """V3 — A wildcard-only deny pattern (`*.corp.example.com`) lets the apex pass.

    Severity: MEDIUM (operator-intent gap, not a one-click bypass).

    Repro:
      - Operator writes `default_out_of_scope: ['*.corp.example.com']`.
      - A target with value "corp.example.com" (the apex) is created.
      - fnmatch("corp.example.com", "*.corp.example.com") is False because
        the apex itself does not have a left-hand label.

    Impact:
      Operators commonly believe a wildcard pattern denies the apex too.
      Writing both `corp.example.com` and `*.corp.example.com` is required
      to cover the whole zone, but only one of the two is intuitive.

    Recommended fix:
      Either change the matcher to treat `*.x.y` as covering `x.y` too,
      or document the requirement clearly in the policy schema. The
      ROE engine in this patch has the SAME issue and would need a similar
      fix; this PoC therefore demonstrates the gap but not a delta with
      the engine.
    """
    from app.models import RiskLevel, Target
    from app.services import scope as scope_mod

    monkeypatch.setattr(scope_mod, "load_platform_config", lambda: {
        "scope": {
            "enforce_out_of_scope_patterns": True,
            "default_out_of_scope": ["*.corp.example.com"],
            "require_active_authorization": True,
        }
    })

    target = Target(workspace_id="ws", value="corp.example.com", type="domain",
                    in_scope=True, passive_allowed=True, active_allowed=True)

    # FIXED BEHAVIOUR — the platform's `_matches_any` now treats a `*.x.y`
    # pattern as covering the apex `x.y`. Operators get the deny they
    # intuitively expected without having to list both forms.
    with pytest.raises(scope_mod.ScopeError) as excinfo:
        scope_mod.enforce_target_scope(target, RiskLevel.low_active)
    assert "*.corp.example.com" in str(excinfo.value)

    # The ROE engine's matcher still has the older behaviour; folding the
    # same apex rule into the engine is filed as a separate item in the
    # advisory but is non-blocking because the platform layer now denies.
    from app.services.scope_engine import ScopeAction, ScopeEngine
    engine = ScopeEngine({
        "allowed": {"domains": ["example.com", "*.example.com"]},
        "denied": {"domains": ["*.corp.example.com"]},
    })
    decision = engine.evaluate_action(ScopeAction(target="corp.example.com"))
    # Documentation of the remaining gap in the engine — when the engine
    # learns the same apex rule, this assertion should flip too.
    assert decision.decision != "deny"


def test_poc_v4_no_port_allowlist_at_scope_layer(_common_env, monkeypatch):
    """V4 — No platform-level port allowlist.

    Severity: MEDIUM (coverage gap).

    Repro:
      - Operator wants "only 80, 443, 8080 are in scope" — there is no
        knob in `scope.py` to express this.

    Impact:
      A misconfigured port-scan tool can hit SSH/RDP/SMB on in-scope
      hosts because scope policy can't restrict ports. The ROE engine
      closes this gap with `allowed.ports`.

    The "current behaviour" check is omission-based: scope.py never reads
    a `ports` key. The PoC demonstrates the proposed correct path.
    """
    from app.services.scope_engine import ScopeAction, ScopeEngine

    # ROE engine REJECTS port 22 against a scope.yaml that allowlists web
    # ports only. The platform's scope.py has no equivalent.
    engine = ScopeEngine({
        "allowed": {
            "domains": ["lab.example.com"],
            "ports": [80, 443, 8080],
        },
    })
    web = engine.evaluate_action(ScopeAction(target="lab.example.com", port=443))
    ssh = engine.evaluate_action(ScopeAction(target="lab.example.com", port=22))
    assert web.decision == "allow"
    assert ssh.decision == "deny"
    assert "Port 22" in ssh.reason


def test_poc_v5_no_method_or_path_denial_at_scope_layer(_common_env, monkeypatch):
    """V5 — No HTTP method or URL path denial.

    Severity: MEDIUM (coverage gap).

    Repro:
      - Operator wants `DELETE /users/{id}` and `/logout` to be off-limits.
        Scope policy can't express this; scope.py only looks at target.value.

    Impact:
      Active scanners like dalfox / sqlmap may issue DELETE or hit
      /logout endpoints during fuzz, breaking sessions or mutating
      production state. The ROE engine closes the gap with
      `denied.methods` + `denied.paths`.
    """
    from app.services.scope_engine import ScopeAction, ScopeEngine

    engine = ScopeEngine({
        "allowed": {"domains": ["lab.example.com"]},
        "denied": {"methods": ["DELETE", "TRACE"], "paths": ["/logout", "/delete"]},
    })
    safe = engine.evaluate_action(ScopeAction(target="lab.example.com", method="GET"))
    delete = engine.evaluate_action(ScopeAction(target="lab.example.com", method="DELETE"))
    logout = engine.evaluate_action(ScopeAction(target="https://lab.example.com/logout"))
    assert safe.decision == "allow"
    assert delete.decision == "deny"
    assert logout.decision == "deny"


def test_poc_v6_no_rate_limit_at_scope_layer(_common_env):
    """V6 — No `max_rps` cap at scope policy.

    Severity: MEDIUM (coverage gap — primary mitigations are per-tool).

    Repro:
      - Operator sets a policy "no scan above 5 RPS sitewide".
        scope.py has no key for this; rate caps must be configured per tool.

    Impact:
      A single mis-tuned profile can exceed the engagement's agreed RPS
      ceiling. The ROE engine catches this with `limits.max_rps`.
    """
    from app.services.scope_engine import ScopeAction, ScopeEngine
    engine = ScopeEngine({
        "allowed": {"domains": ["lab.example.com"]},
        "limits": {"max_rps": 5},
    })
    slow = engine.evaluate_action(ScopeAction(target="lab.example.com", requested_rps=3))
    fast = engine.evaluate_action(ScopeAction(target="lab.example.com", requested_rps=50))
    assert slow.decision == "allow"
    assert fast.decision == "rate_limit"


# ============================================================================
# Integration PoC — hits the live API with a TestClient.
# ============================================================================

@pytest.fixture
def stack(tmp_path, monkeypatch):
    db_path = tmp_path / "scope-poc.db"
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
    monkeypatch.setenv("DRY_RUN_LINE_DELAY_SECONDS", "0")
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


def _wait_completed(client, headers, run_id, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        body = client.get(f"/api/runs/{run_id}", headers=headers).json()
        if body["status"] in {"completed", "failed", "cancelled"}:
            return body
        time.sleep(0.25)
    raise AssertionError(f"run {run_id} did not complete in {timeout}s")


def test_poc_v7_rerun_inherits_stale_manual_approval(stack):
    """V7 — POST /api/runs/{id}/rerun copies stale manual_approval from the source.

    Severity: HIGH. This is the most impactful issue.

    Repro (against the live API):
      1. Admin/operator creates a high-risk run with
         `params={"manual_approval": true}` for a target that requires
         high-risk approval. The run is accepted (consent given THIS time).
      2. After the run completes, anyone with operator role calls
         POST /api/runs/{id}/rerun without providing `manual_approval`.
      3. `apps/api/app/api/routes/runs.py:rerun_run()` reads
         `params = source.config_snapshot.get("params") or {}` and uses
         the *source run's* manual_approval=True. enforce_target_scope
         is satisfied, the rerun is queued.

    Impact:
      Manual approval is the platform's per-run consent mechanism. The
      rerun endpoint silently extends a one-time approval to every
      subsequent rerun — including reruns by operators who were not
      the original approver. An incident reviewer reading the audit
      log would see a high-risk run with no fresh approval, but the
      platform did not enforce one.

    Recommended fix:
      `rerun_run` should NOT inherit `manual_approval` from
      `source.config_snapshot.params`; it should require the requester to
      re-supply it on the rerun request body (or admin role override),
      same as if they were calling POST /api/runs fresh.

    NOTE: this PoC currently passes (the rerun succeeds). After the fix,
    the rerun should fail with 403 unless the operator passes
    `{"params": {"manual_approval": true}}` in the rerun body — but the
    rerun endpoint doesn't currently accept a body at all, so the fix
    needs an API shape change too.
    """
    client, headers = stack
    ws_id = client.get("/api/workspaces", headers=headers).json()[0]["id"]

    # Setup: target authorised for active scans
    target = client.post("/api/targets", headers=headers, json={
        "workspace_id": ws_id, "value": "stale-consent.example.com", "type": "domain",
        "in_scope": True, "passive_allowed": True, "active_allowed": True,
        "notes": "PoC for stale-approval rerun",
    }).json()

    # Step 1: create the original high-risk run WITH manual_approval=true.
    # `high_risk_manual_approval` is a high_active YAML profile in the registry,
    # so the platform's existing high-risk gate fires. The original creation
    # passes only because the operator supplies fresh consent in `params`.
    original = client.post("/api/runs", headers=headers, json={
        "workspace_id": ws_id, "target_id": target["id"],
        "profile_id": "high_risk_manual_approval",
        "requested_by": "poc-original",
        "params": {"manual_approval": True},
    })
    assert original.status_code == 201, original.text
    original_id = original.json()["id"]
    _wait_completed(client, headers, original_id)

    # Step 2: rerun WITHOUT providing manual_approval. The rerun endpoint
    # now refuses high-risk reruns that don't re-supply consent. The
    # source run's manual_approval is no longer inherited.
    rerun_no_consent = client.post(f"/api/runs/{original_id}/rerun", headers=headers)
    assert rerun_no_consent.status_code == 403, (
        f"V7 regression — high-risk rerun without fresh manual_approval must 403. "
        f"Got: {rerun_no_consent.status_code} {rerun_no_consent.text}"
    )
    assert "manual_approval" in rerun_no_consent.text.lower()

    # Step 3: same rerun WITH fresh consent in the body succeeds.
    rerun_with_consent = client.post(
        f"/api/runs/{original_id}/rerun",
        headers=headers,
        json={"params": {"manual_approval": True}},
    )
    assert rerun_with_consent.status_code == 201, rerun_with_consent.text
    rerun_id = rerun_with_consent.json()["id"]
    _wait_completed(client, headers, rerun_id)
    final = client.get(f"/api/runs/{rerun_id}", headers=headers).json()
    assert final["status"] == "completed"


def test_poc_v8_rerun_breaks_for_adhoc_and_workflow_runs(stack):
    """V8 — POST /api/runs/{id}/rerun crashes for every ad-hoc run.

    Severity: MEDIUM (data-loss workflow bug; not auth-bypass).

    This PoC was discovered while writing V7: I tried to rerun an ad-hoc
    run and the rerun endpoint returned 404 "'Unknown profile: adhoc'".

    Repro:
      - Operator creates a run via POST /api/runs/adhoc (or POST
        /api/workflows/{id}/launch) — the resulting Run row has
        profile_id="adhoc".
      - Operator clicks "Re-run" in the UI (POST /api/runs/{id}/rerun).
      - `apps/api/app/api/routes/runs.py:rerun_run()` calls
        `registry.get_profile(source.profile_id)` → KeyError because
        there is no `packages/tool-registry/profiles/adhoc.yaml`.
      - The endpoint maps the KeyError to HTTP 404 "Unknown profile: adhoc".

    Impact:
      Workflow Builder runs and Tool Catalog quick-tests cannot be
      replayed. The "Re-run" button in the UI is broken for them.

    Recommended fix:
      `rerun_run` should mirror `create_adhoc_run` when source.profile_id
      == "adhoc": read source.config_snapshot["profile_inline"] and create
      a new run with the same inline profile body rather than looking up
      a YAML file.
    """
    client, headers = stack
    ws_id = client.get("/api/workspaces", headers=headers).json()[0]["id"]
    target = client.post("/api/targets", headers=headers, json={
        "workspace_id": ws_id, "value": "rerun-adhoc.example.com", "type": "domain",
        "in_scope": True, "passive_allowed": True, "active_allowed": True,
    }).json()
    original = client.post("/api/runs/adhoc", headers=headers, json={
        "workspace_id": ws_id, "target_id": target["id"],
        "name": "PoC: ad-hoc run", "steps": [{"tool": "subfinder"}],
    })
    assert original.status_code == 201, original.text
    original_id = original.json()["id"]
    _wait_completed(client, headers, original_id)

    # FIXED BEHAVIOUR — rerun_run honours `config_snapshot.profile_inline`
    # for ad-hoc replays. The Re-run button now works for Workflow Builder
    # runs, Tool Catalog quick-tests, and saved-workflow launches.
    rerun = client.post(f"/api/runs/{original_id}/rerun", headers=headers)
    assert rerun.status_code == 201, (
        f"V8 regression — ad-hoc rerun must succeed. "
        f"Got: {rerun.status_code} {rerun.text}"
    )
    fresh = rerun.json()
    assert fresh["profile_id"] == "adhoc"
    _wait_completed(client, headers, fresh["id"])
    final = client.get(f"/api/runs/{fresh['id']}", headers=headers).json()
    assert final["status"] == "completed"


def test_poc_v9_engine_decision_for_high_risk_without_approval_is_require_approval(_common_env):
    """V9 — Reference decision: ROE engine returns `require_approval` for
    high-risk actions without manual_approval.

    Documents the contract the rerun-path fix (V7) should honour at the
    policy layer. Not a vulnerability on its own.
    """
    from app.services.scope_engine import ScopeAction, ScopeEngine
    engine = ScopeEngine({
        "allowed": {"domains": ["lab.example.com"]},
        "approval": {"require_for_risk": ["high_active", "destructive"]},
    })
    no_consent = engine.evaluate_action(
        ScopeAction(target="lab.example.com", risk="high_active", manual_approval=False)
    )
    with_consent = engine.evaluate_action(
        ScopeAction(target="lab.example.com", risk="high_active", manual_approval=True)
    )
    assert no_consent.decision == "require_approval"
    assert with_consent.decision == "allow"
