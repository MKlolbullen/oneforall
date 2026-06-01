"""Proof-of-concept reproductions for ROE / scope-enforcement vulnerabilities.

Each test in this file documents one confirmed gap in the current scope
enforcement (apps/api/app/services/scope.py + how it's called in
apps/api/app/api/routes/runs.py). The test BODY itself is the PoC:

  1. It demonstrates the unsafe behaviour against the live code.
  2. It shows what the proposed ROE engine in apps/api/app/services/
     scope_engine.py would have decided instead.

Every PoC here passes today; after wiring `enforce_scope_before_run` from
`run_scope_guard.py` into runs.py, the "current behaviour" half of each test
should flip to denied / 403 — i.e. these PoCs become regression tests that
prove the fix.

See `docs/SECURITY_ADVISORY_ROE_SCOPE.md` for the written advisory.
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

    # CURRENT BEHAVIOUR — scope allows the action. This is the vulnerability.
    # No ScopeError is raised even though the operator expressed intent to
    # block private ranges in the policy.
    scope_mod.enforce_target_scope(target, RiskLevel.low_active)
    # (no exception == permissive == vuln)

    # WHAT THE ROE ENGINE WOULD HAVE DONE — deny via denied.cidrs.
    # An operator opting into "block private ranges" should land in a
    # policy like this one. The engine correctly denies.
    from app.services.scope_engine import ScopeAction, ScopeEngine
    engine = ScopeEngine({
        "allowed": {"cidrs": ["0.0.0.0/0"]},  # everything external
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

    # CURRENT BEHAVIOUR — vulnerable: scope permits the action.
    scope_mod.enforce_target_scope(target, RiskLevel.low_active)

    # WHAT THE ROE ENGINE WOULD HAVE DONE — explicit CIDR deny.
    from app.services.scope_engine import ScopeAction, ScopeEngine
    engine = ScopeEngine({
        "allowed": {"cidrs": ["10.0.0.0/8"]},  # lab range
        "denied": {"cidrs": ["10.10.50.0/24"]},  # production subnet
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

    # CURRENT BEHAVIOUR — apex slips past the wildcard, vulnerable.
    scope_mod.enforce_target_scope(target, RiskLevel.low_active)

    # Verifying the gap exists in the ROE engine too — useful so the fix
    # for both reaches the same matcher rules at the same time.
    from app.services.scope_engine import ScopeAction, ScopeEngine
    engine = ScopeEngine({
        "allowed": {"domains": ["example.com", "*.example.com"]},
        "denied": {"domains": ["*.corp.example.com"]},
    })
    decision = engine.evaluate_action(ScopeAction(target="corp.example.com"))
    # The ROE engine also lets the apex through (per its current matcher).
    # The proposed fix needs to recognise *.x.y as covering x.y.
    assert decision.decision != "deny", (
        "PoC stops being valid once the matcher is fixed in BOTH layers."
    )


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
    # does not accept a body at all, so an operator has no way to
    # express fresh consent. The platform allows it anyway — silently
    # inheriting the source run's manual_approval=True from
    # config_snapshot.params.
    rerun = client.post(f"/api/runs/{original_id}/rerun", headers=headers)

    # CURRENT BEHAVIOUR — vulnerable: a 201 is returned, the rerun is
    # queued. This is the bug.
    assert rerun.status_code == 201, (
        f"PoC stops reproducing once the platform starts requiring fresh "
        f"manual_approval on rerun. Got: {rerun.status_code} {rerun.text}"
    )
    # The rerun row carries the inherited consent into its
    # config_snapshot.params, persisting the stale approval in the audit
    # trail (the auditor sees a high-risk run with no contemporaneous
    # approval action, because there isn't one).
    rerun_id = rerun.json()["id"]
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

    # CURRENT BEHAVIOUR — vulnerable: rerun crashes with 404 because the
    # "adhoc" profile_id isn't an on-disk YAML.
    rerun = client.post(f"/api/runs/{original_id}/rerun", headers=headers)
    assert rerun.status_code == 404, (
        f"PoC stops reproducing once rerun_run learns to honour "
        f"config_snapshot.profile_inline for ad-hoc replays. "
        f"Got: {rerun.status_code} {rerun.text}"
    )
    assert "Unknown profile" in rerun.json()["detail"]


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
