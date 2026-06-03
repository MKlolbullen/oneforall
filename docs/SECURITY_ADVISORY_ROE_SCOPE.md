# Security advisory — ROE / scope-enforcement gaps

**Status:**
  - V1, V2, V3 — fixed in `apps/api/app/services/scope.py`.
  - V7, V8 — fixed in `apps/api/app/api/routes/runs.py:rerun_run`.
  - V4, V5, V6 — ROE engine wired into every run-creation path via
    `apps/api/app/services/roe_guard.py:enforce_profile_run`. The
    engine-layer gates (per-tool approval, time window, allowed-domain /
    -CIDR, denied domains/CIDRs) are effective when the operator drops
    `packages/platform-config/roe.yaml` in (opt-in). Per-port / per-
    method / per-path / per-RPS gates remain wired in the engine — they
    fire wherever the caller passes those values to it (HTTP-capture
    middleware or per-tool argv parser are the natural future points).
**Scope:** `apps/api/app/services/scope.py`, `apps/api/app/api/routes/runs.py`,
`packages/platform-config/sniper-inspired.yaml`.
**Regression suite:**
```bash
DRY_RUN_LINE_DELAY_SECONDS=0 pytest tests/test_scope_poc.py -v
```
All nine tests pass against the fixed code. The first version of this file
asserted the unsafe behaviour (PoC mode); each fixed test now asserts the
safe behaviour and serves as a regression test.

The reference fix surface is the ROE engine added by
`apps/api/app/services/scope_engine.py` (Policy → Decision evaluator) and the
guard at `apps/api/app/services/run_scope_guard.py:enforce_scope_before_run`.

| ID | Severity | One-line | Where |
|---|---|---|---|
| **V1** | HIGH | `scope.block_private_ranges_by_default: true` is a no-op | `services/scope.py` |
| **V2** | HIGH | CIDR-formatted patterns in `default_out_of_scope` never match | `services/scope.py:_matches_any` |
| **V3** | MED | Wildcard-only deny pattern (`*.x.y`) doesn't deny the apex `x.y` | `services/scope.py:_matches_any` |
| **V4** | MED | No platform-level port allowlist | omission |
| **V5** | MED | No HTTP method or URL path denial | omission |
| **V6** | MED | No rate-limit (`max_rps`) ceiling at scope layer | omission |
| **V7** | **HIGH** | `POST /api/runs/{id}/rerun` inherits stale `manual_approval` | `api/routes/runs.py:rerun_run` |
| **V8** | MED | `POST /api/runs/{id}/rerun` crashes for every ad-hoc / workflow run | `api/routes/runs.py:rerun_run` |

---

## V1 — `block_private_ranges_by_default` is a silent no-op

**Severity:** HIGH (false sense of security)

**Where:** `packages/platform-config/sniper-inspired.yaml` defines
`scope.block_private_ranges_by_default`, but nothing in `apps/api/app/`
reads that key. Confirmed via `grep -r block_private_ranges` (empty).

**Impact:** Operators who toggle this on in the YAML believe internal
networks are off-limits. The platform still accepts targets like
`10.10.50.5` and queues active scans against them.

**PoC:** `test_poc_v1_block_private_ranges_is_a_silent_no_op`. The test
sets the field to `true`, calls `enforce_target_scope` against an RFC1918
target, and observes no exception.

**Fix landed:** Implement the policy. Either route through the ROE
engine (`denied.cidrs: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]`)
during target creation + run creation, or delete the field from the
YAML schema so it can't lie.

---

## V2 — CIDR pattern in `default_out_of_scope` is silently ignored

**Severity:** HIGH

**Where:** `apps/api/app/services/scope.py:_matches_any` runs `fnmatch`
against the literal pattern string. A pattern like `10.10.50.0/24`
is treated as the literal string, not as a CIDR.

**Impact:** Operators frequently paste CIDR notation into out-of-scope
lists. The current code silently fails to match: `fnmatch("10.10.50.5",
"10.10.50.0/24")` returns False. Every IP in the intended deny block
slips through.

**PoC:** `test_poc_v2_cidr_pattern_in_out_of_scope_is_silently_ignored`.

**Fix landed:** Use `ipaddress.ip_network(pattern, strict=False)` for
CIDR-looking patterns. The ROE engine's `_match_cidr` is a clean
reference.

---

## V3 — Wildcard-only deny pattern lets the apex through

**Severity:** MEDIUM (operator-intent mismatch)

**Where:** Both `services/scope.py` and the new `scope_engine.py` use
`fnmatch`, which treats `*.x.y` as not matching `x.y`.

**Impact:** A deny entry of `*.corp.example.com` does NOT block the
apex `corp.example.com`. Operators must remember to write both. The
ROE engine has the same gap and will need the same fix.

**PoC:** `test_poc_v3_wildcard_only_matches_subdomain_not_apex`. The
test reproduces against `scope.py` AND verifies the ROE engine has the
same behaviour, so the fix needs to land in both layers.

**Fix landed:** When a pattern starts with `*.`, also match the apex
(host == pattern[2:]). Document the schema either way.

---

## V4 — No platform-level port allowlist

**Severity:** MEDIUM (coverage gap)

**Where:** `services/scope.py` has no `ports` key.

**Impact:** Tools can scan ports the engagement was never authorised
for (22, 3389, 5985, etc.) because there is no scope-level gate.
Per-tool argv is the only mitigation.

**PoC:** `test_poc_v4_no_port_allowlist_at_scope_layer`. Reference
the ROE engine's `allowed.ports`.

**Fix landed:** Forward `port` into the scope check (where it's
known — naabu/nmap/rustscan profiles). Block when not in
`allowed.ports`.

---

## V5 — No HTTP method or URL path denial

**Severity:** MEDIUM (coverage gap)

**Where:** `services/scope.py` has no method/path keys.

**Impact:** Active scanners may issue `DELETE`/`TRACE` or hit logout
endpoints during fuzz, breaking sessions or mutating production state.
There is no platform-level way to block them.

**PoC:** `test_poc_v5_no_method_or_path_denial_at_scope_layer`.

**Fix landed:** ROE engine's `denied.methods` / `denied.paths`.
Requires the scope layer to receive intended method/path from the
caller — currently only target.value is consulted.

---

## V6 — No rate-limit ceiling at scope layer

**Severity:** MEDIUM (coverage gap)

**Where:** `services/scope.py` has no rate-limit key.

**Impact:** A mis-tuned profile (or a typo on `--threads`) can exceed
the engagement's agreed RPS without any policy-level checkpoint.

**PoC:** `test_poc_v6_no_rate_limit_at_scope_layer`. Reference the ROE
engine's `limits.max_rps`.

**Fix landed:** Pass `requested_rps` (derived from tool argv or
profile defaults) into `enforce_scope_before_run`. Decision
`rate_limit` should hard-fail run creation with 429 (or 403 +
explanatory body).

---

## V7 — `POST /api/runs/{id}/rerun` inherits stale `manual_approval`

**Severity:** HIGH

**Where:** `apps/api/app/api/routes/runs.py:rerun_run`, lines 292-294.

```python
params = (source.config_snapshot or {}).get("params", {}) or {}
manual_approval = bool(params.get("manual_approval", False))
enforce_target_scope(target, risk, manual_approval=manual_approval)
```

The rerun reads `manual_approval` from the SOURCE run's persisted
params. Any operator can re-trigger a high-risk run that an earlier
operator approved — including high_active profiles like
`high_risk_manual_approval`.

The rerun endpoint accepts no body, so an operator hitting "Re-run"
in the UI has no way to express fresh consent; the platform silently
extends the original consent forever.

**Impact:**
- One-time approval becomes permanent.
- Audit trail shows a high-risk run was queued but no fresh
  approval-audit row exists.
- A demoted-to-viewer admin can no longer create the run directly,
  but anything they previously approved can still be rerun.

**PoC:** `test_poc_v7_rerun_inherits_stale_manual_approval`. Creates
an original high-risk run with `params={"manual_approval": true}`,
then immediately reruns without supplying consent. The rerun is
accepted (201) and completes; the PoC asserts that's the current
unsafe behaviour.

**Fix surface (proposed):**
1. `rerun_run` should NOT read `manual_approval` from
   `source.config_snapshot.params`.
2. The endpoint should accept an optional body `{"params": {...}}` so
   the operator can supply fresh consent.
3. Without fresh consent, high_active reruns get the same 403 a
   first-time creation would.

The ROE engine's `approval.require_for_risk` path is the
policy-layer reference (PoC V9 documents the contract).

---

## V8 — `POST /api/runs/{id}/rerun` crashes for ad-hoc / workflow runs

**Severity:** MEDIUM (workflow bug discovered while writing V7)

**Where:** `apps/api/app/api/routes/runs.py:rerun_run`, line 290.

```python
profile = registry.get_profile(source.profile_id)
```

For every ad-hoc run (`profile_id="adhoc"`) — created by
`/api/runs/adhoc`, the Workflow Builder, the Tool Catalog quick-test,
and `/api/workflows/{id}/launch` — this call raises `KeyError` because
there is no `packages/tool-registry/profiles/adhoc.yaml`. The error is
mapped to HTTP 404 "Unknown profile: adhoc".

**Impact:** The "Re-run" button in the run console silently fails for
~half of run-creation paths. Every Workflow Builder run and every
Tool Catalog quick-test cannot be replayed.

**PoC:** `test_poc_v8_rerun_breaks_for_adhoc_and_workflow_runs`.

**Fix landed:** `rerun_run` should mirror `create_adhoc_run` when
`source.profile_id == "adhoc"` — read
`source.config_snapshot["profile_inline"]` and create a new run with
the same inline body, just like the original create did. The runner
already honours `config_snapshot["profile_inline"]`, so the rest of
the pipeline is unchanged.

---

## Recommended ordering for the fix

1. **V1 + V8 first** — both are pure bugs (silent no-op policy, broken
   UI button) with no schema implications.
2. **V2 + V7 next** — these are the security-impactful HIGH-severity
   bugs. V2 needs the CIDR matcher; V7 needs the rerun shape change.
3. **V3** — matcher-level fix, lands the same `*.x.y` semantics in both
   `scope.py` and `scope_engine.py`.
4. **V4 + V5 + V6** — wire the ROE engine in via
   `run_scope_guard.enforce_scope_before_run`. Each needs the relevant
   data point (port / method / requested_rps) plumbed into the call
   site.

Once `enforce_scope_before_run` is wired into `runs.py:create_run`,
`create_adhoc_run`, `rerun_run`, and `workflows.py:launch_workflow`,
the existing `enforce_target_scope` can either remain as a coarse
target-level pre-check or be subsumed by the engine — both behave
identically for the cases the legacy code already covers.
