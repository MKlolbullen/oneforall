"""Claude advisor tests.

The Anthropic SDK is mocked end-to-end — we never hit the real API. We patch
`app.services.advisor._client` to return a fake whose `.messages.create()`
returns a canned response object that mimics the SDK's shape (content blocks,
usage counters, model field).

Coverage:
  - is_configured() reflects ANTHROPIC_API_KEY
  - 503 from POST /advisor/* when no key
  - 401 / 403 / 201 role gating
  - triage_run / suggest_profile / explain_finding / ask all persist Advice rows
  - Re-running replaces (not duplicates) keyed by (kind, ref_id)
  - Each call writes an audit row with the advisor.* action
  - The system prompt sent to the SDK uses cache_control on its catalogue block
  - Free-form ask honors run_id / target_id auto-context
"""
from __future__ import annotations

import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[1]
API_DIR = REPO / "apps" / "api"
sys.path.insert(0, str(API_DIR))


def _fake_response(text: str, *, model: str = "claude-opus-4-7",
                   input_tokens: int = 100, output_tokens: int = 50,
                   cache_read: int = 0):
    return SimpleNamespace(
        content=[SimpleNamespace(type="text", text=text)],
        stop_reason="end_turn",
        model=model,
        usage=SimpleNamespace(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_read_input_tokens=cache_read,
            cache_creation_input_tokens=0,
        ),
    )


class FakeMessages:
    def __init__(self, responder):
        self._responder = responder
        self.calls: list[dict] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return self._responder(**kwargs)


class FakeAnthropic:
    def __init__(self, responder=None):
        text = "Run had no critical findings. Suggest passive_recon next."
        self.messages = FakeMessages(responder or (lambda **_: _fake_response(text)))


@pytest.fixture
def stack(tmp_path, monkeypatch):
    db_path = tmp_path / "advisor.db"
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
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")
    # Auto-target-analysis is on by default in app.core.config, but most
    # advisor tests don't care about it firing as a side effect of run
    # completion. Specific auto-hook tests below opt back in.
    monkeypatch.setenv("AUTO_TARGET_ANALYSIS", "false")

    from conftest import rebind_engine_to_database_url
    rebind_engine_to_database_url()

    from fastapi.testclient import TestClient
    from app.main import app
    headers = {"X-Test-User": "admin"}

    fake = FakeAnthropic()
    import app.services.advisor as advisor_mod
    monkeypatch.setattr(advisor_mod, "_client", lambda: fake)

    with TestClient(app) as client:
        yield client, headers, fake, monkeypatch
    from app.core.config import get_settings
    get_settings.cache_clear()


def _seed_run(client, headers):
    """Create a workspace + active-allowed target + a completed dry-run."""
    ws_id = client.get("/api/workspaces", headers=headers).json()[0]["id"]
    target = client.post("/api/targets", headers=headers, json={
        "workspace_id": ws_id, "value": "lab.example.com", "type": "domain",
        "in_scope": True, "passive_allowed": True, "active_allowed": True,
    }).json()
    run = client.post("/api/runs", headers=headers, json={
        "workspace_id": ws_id, "target_id": target["id"], "profile_id": "passive_recon",
    }).json()
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        if client.get(f"/api/runs/{run['id']}", headers=headers).json()["status"] == "completed":
            break
        time.sleep(0.3)
    return ws_id, target, run


# ---------------------------- basics ----------------------------------------


def test_is_configured_reflects_env(monkeypatch):
    sys.path.insert(0, str(API_DIR))
    from app.services.advisor import is_configured
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert not is_configured()
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-foo")
    assert is_configured()


def test_503_when_no_api_key(stack):
    client, headers, _, mp = stack
    mp.delenv("ANTHROPIC_API_KEY", raising=False)
    ws_id, _t, run = _seed_run(client, headers)
    r = client.post(f"/api/advisor/runs/{run['id']}/triage", headers=headers)
    assert r.status_code == 503
    assert "ANTHROPIC_API_KEY" in r.json()["detail"]


# ---------------------------- role gating ----------------------------------


def test_invocations_require_operator(stack):
    client, headers, _, _ = stack
    ws_id = client.get("/api/workspaces", headers=headers).json()[0]["id"]
    # Create a viewer
    admin = client.post("/api/auth/login",
                        json={"username": "admin", "password": "admin-passw0rd"}).json()["token"]
    client.post("/api/auth/users",
                headers={"Authorization": f"Bearer {admin}"},
                json={"username": "vw", "password": "viewer-p4ssword", "role": "viewer"})
    vtoken = client.post("/api/auth/login",
                          json={"username": "vw", "password": "viewer-p4ssword"}).json()["token"]
    vh = {"Authorization": f"Bearer {vtoken}"}

    # Even with no run, the role check must come first → 403, not 404
    r = client.post("/api/advisor/runs/run_does_not_exist/triage", headers=vh)
    assert r.status_code == 403
    r = client.post("/api/advisor/ask", headers=vh,
                    json={"question": "hi", "workspace_id": ws_id})
    assert r.status_code == 403


def test_anonymous_blocked(stack):
    client, _, _, _ = stack
    assert client.post("/api/advisor/runs/x/triage").status_code == 401
    assert client.post("/api/advisor/ask",
                       json={"question": "x", "workspace_id": "x"}).status_code == 401
    assert client.get("/api/advisor/runs/x/triage").status_code == 401


# ---------------------------- triage_run ------------------------------------


def test_triage_run_persists_and_audits(stack):
    client, headers, fake, _ = stack
    ws_id, _t, run = _seed_run(client, headers)
    r = client.post(f"/api/advisor/runs/{run['id']}/triage", headers=headers)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["kind"] == "run_triage"
    assert body["ref_id"] == run["id"]
    assert body["model"] == "claude-opus-4-7"
    assert body["prompt_tokens"] > 0 and body["completion_tokens"] > 0
    assert "passive_recon" in body["summary"].lower() or body["summary"]

    # Exactly one SDK call
    assert len(fake.messages.calls) == 1
    call = fake.messages.calls[0]
    assert call["model"] == "claude-opus-4-7"
    assert call["thinking"] == {"type": "adaptive"}
    assert call["output_config"] == {"effort": "high"}
    # System prompt is a list of blocks; the catalogue block has cache_control
    sys_blocks = call["system"]
    assert isinstance(sys_blocks, list) and len(sys_blocks) >= 2
    catalogue = sys_blocks[-1]
    assert catalogue["cache_control"] == {"type": "ephemeral"}
    assert "Profile catalogue" in catalogue["text"]

    # Cached row is now retrievable via GET
    g = client.get(f"/api/advisor/runs/{run['id']}/triage", headers=headers)
    assert g.status_code == 200 and g.json()["id"] == body["id"]

    # Audit chain has the row
    audit = client.get("/api/auth/audit",
                        headers={"Authorization": f"Bearer {client.post('/api/auth/login', json={'username': 'admin', 'password': 'admin-passw0rd'}).json()['token']}"}).json()
    assert any(e["action"] == "advisor.run_triage" for e in audit["events"])
    assert audit["ok"] is True


def test_triage_rerun_replaces_keyed_by_ref(stack):
    """Two POSTs against the same run keep one Advice row, not two."""
    client, headers, fake, _ = stack
    _w, _t, run = _seed_run(client, headers)
    first = client.post(f"/api/advisor/runs/{run['id']}/triage", headers=headers).json()
    second = client.post(f"/api/advisor/runs/{run['id']}/triage", headers=headers).json()
    assert first["id"] == second["id"]
    assert len(fake.messages.calls) == 2  # both calls hit Anthropic


def test_get_triage_returns_204_equivalent_when_missing(stack):
    client, headers, _, _ = stack
    _w, _t, run = _seed_run(client, headers)
    g = client.get(f"/api/advisor/runs/{run['id']}/triage", headers=headers)
    assert g.status_code == 200
    assert g.json() is None


def test_triage_404_for_unknown_run(stack):
    client, headers, _, _ = stack
    r = client.post("/api/advisor/runs/nope/triage", headers=headers)
    assert r.status_code == 404


# ---------------------------- suggest_profile -------------------------------


def test_suggest_profile_persists(stack, monkeypatch):
    client, headers, fake, _ = stack
    _w, target, _r = _seed_run(client, headers)
    monkeypatch.setattr(fake.messages, "_responder",
                         lambda **_: _fake_response("Run web_quick next; reuses live hosts."))
    r = client.post(f"/api/advisor/targets/{target['id']}/suggest-profile",
                    headers=headers)
    assert r.status_code == 201, r.text
    assert "web_quick" in r.json()["summary"].lower() or r.json()["summary"]


# ---------------------------- explain_finding ------------------------------


def test_explain_finding_persists(stack, monkeypatch):
    client, headers, fake, _ = stack
    ws_id, _t, run = _seed_run(client, headers)
    # Insert a finding manually so we have a stable id
    from app.db import engine
    from app.models import Finding
    from sqlmodel import Session
    with Session(engine) as session:
        f = Finding(workspace_id=ws_id, run_id=run["id"],
                     title="Exposed .git/config", severity="high",
                     category="exposure", evidence="HTTP 200 at /.git/config",
                     tool_source="nuclei")
        session.add(f); session.commit(); session.refresh(f)
        finding_id = f.id

    monkeypatch.setattr(fake.messages, "_responder",
                         lambda **_: _fake_response("Public .git/config exposes branch + remote."))
    r = client.post(f"/api/advisor/findings/{finding_id}/explain", headers=headers)
    assert r.status_code == 201
    assert r.json()["kind"] == "finding_explain"
    assert r.json()["ref_id"] == finding_id


# ---------------------------- ask ------------------------------------------


def test_ask_includes_run_context_when_provided(stack):
    client, headers, fake, _ = stack
    ws_id, _t, run = _seed_run(client, headers)
    r = client.post("/api/advisor/ask", headers=headers,
                    json={"question": "what should we test next?",
                           "workspace_id": ws_id, "run_id": run["id"]})
    assert r.status_code == 201
    # Last SDK call's user message contains the run id and the literal question
    user_msg = fake.messages.calls[-1]["messages"][-1]["content"]
    assert run["id"] in user_msg
    assert "what should we test next?" in user_msg


def test_ask_without_refs_works(stack):
    client, headers, fake, _ = stack
    ws_id = client.get("/api/workspaces", headers=headers).json()[0]["id"]
    r = client.post("/api/advisor/ask", headers=headers,
                    json={"question": "what's a bug bounty triage workflow?",
                           "workspace_id": ws_id})
    assert r.status_code == 201
    user_msg = fake.messages.calls[-1]["messages"][-1]["content"]
    assert "Run context" not in user_msg  # no auto-attached context
    assert "Target context" not in user_msg


# ---------------------------- target analysis -----------------------------


_ANALYSIS_FIXTURE = """\
Target serves a fintech API with admin panel exposed. WAF appears absent.

```json
{
  "tech_stack": ["nginx", "react", "node"],
  "high_value_assets": [
    {"url": "https://admin.lab.example.com/login", "why": "no MFA, admin login"}
  ],
  "attack_surface": [
    "Admin login reachable without MFA",
    "Public Jenkins console with script execution"
  ],
  "recommended_profiles": ["web_quick", "secrets_supply_chain"],
  "payload_categories": ["xss", "ssrf"],
  "risk_level": "high",
  "one_line_next_step": "Probe /admin for authentication bypasses with dalfox + nuclei"
}
```
"""


def _analysis_responder(**kwargs):
    return _fake_response(_ANALYSIS_FIXTURE)


def test_target_analysis_persists_structured_json(stack):
    client, headers, fake, _ = stack
    fake.messages._responder = _analysis_responder
    ws_id, target, _run = _seed_run(client, headers)

    r = client.post(f"/api/advisor/targets/{target['id']}/analyze", headers=headers)
    assert r.status_code == 201, r.text
    advice = r.json()
    assert advice["kind"] == "target_analysis"
    assert advice["ref_id"] == target["id"]

    structured = advice["body"]["structured"]
    assert structured["risk_level"] == "high"
    assert structured["tech_stack"] == ["nginx", "react", "node"]
    assert structured["recommended_profiles"] == ["web_quick", "secrets_supply_chain"]
    assert structured["payload_categories"] == ["xss", "ssrf"]
    assert "admin.lab.example.com" in structured["high_value_assets"][0]["url"]


def test_target_analysis_cached_get_returns_same_row(stack):
    client, headers, fake, _ = stack
    fake.messages._responder = _analysis_responder
    _ws, target, _run = _seed_run(client, headers)
    first = client.post(f"/api/advisor/targets/{target['id']}/analyze", headers=headers).json()
    cached = client.get(f"/api/advisor/targets/{target['id']}/analyze", headers=headers).json()
    assert cached["id"] == first["id"]
    assert cached["body"]["structured"]["risk_level"] == "high"


def test_target_analysis_get_returns_null_when_absent(stack):
    client, headers, _, _ = stack
    _ws, target, _run = _seed_run(client, headers)
    r = client.get(f"/api/advisor/targets/{target['id']}/analyze", headers=headers)
    assert r.status_code == 200
    assert r.json() is None


def test_target_analysis_404_on_unknown_target(stack):
    client, headers, fake, _ = stack
    fake.messages._responder = _analysis_responder
    assert client.post("/api/advisor/targets/tgt_nope/analyze",
                       headers=headers).status_code == 404


def test_target_analysis_anonymous_blocked(stack):
    client, _, _, _ = stack
    assert client.post("/api/advisor/targets/tgt_x/analyze").status_code == 401


def test_target_analysis_503_without_api_key(stack):
    client, headers, _, mp = stack
    mp.delenv("ANTHROPIC_API_KEY", raising=False)
    _ws, target, _run = _seed_run(client, headers)
    r = client.post(f"/api/advisor/targets/{target['id']}/analyze", headers=headers)
    assert r.status_code == 503


def test_target_analysis_handles_malformed_json_block(stack):
    """If Claude returns an unparseable code fence we still persist the text
    and the body.structured falls back to an empty dict."""
    client, headers, fake, _ = stack
    fake.messages._responder = lambda **_: _fake_response(
        "Quick read.\n```json\n{not valid json,\n```"
    )
    _ws, target, _run = _seed_run(client, headers)
    r = client.post(f"/api/advisor/targets/{target['id']}/analyze", headers=headers)
    assert r.status_code == 201
    body = r.json()["body"]
    assert body["structured"] == {}
    assert "Quick read" in body["text"]


def test_target_analysis_emits_audit_row(stack):
    client, headers, fake, _ = stack
    fake.messages._responder = _analysis_responder
    _ws, target, _run = _seed_run(client, headers)
    client.post(f"/api/advisor/targets/{target['id']}/analyze", headers=headers)
    audit = client.get("/api/dashboard/detailed", headers=headers).json()["recent_audit"]
    assert any(row["action"] == "advisor.target_analysis" for row in audit)


# ---------------------------- finding pivot -----------------------------


_PIVOT_FIXTURE = """\
Likely chain: exposed admin -> SSRF probe via the /v1/users endpoint.

```json
{
  "pivots": [
    {
      "title": "Probe /v1/users for SSRF via url parameter",
      "tool": "nuclei",
      "command": "nuclei -u https://api.lab.example.com/v1/users -t ssrf/",
      "rationale": "The admin panel reachable from same host suggests the API may proxy URL params",
      "expected_severity": "high"
    },
    {
      "title": "Brute admin auth bypass on /login",
      "tool": "ffuf",
      "command": "ffuf -u https://admin.lab.example.com/FUZZ -w wordlist.txt",
      "rationale": "Admin login was reachable without MFA — try common bypass paths",
      "expected_severity": "high"
    }
  ],
  "related_findings": ["f_xyz123"],
  "confidence": "medium"
}
```
"""


def _pivot_responder(**kwargs):
    return _fake_response(_PIVOT_FIXTURE)


def _seed_finding(client, headers, *, evidence_url: str = "https://api.lab.example.com/v1/users"):
    """Create a run + insert a Finding pointing at evidence_url."""
    ws_id, _t, run = _seed_run(client, headers)
    from app.db import engine
    from app.models import Finding
    from sqlmodel import Session
    with Session(engine) as session:
        f = Finding(
            workspace_id=ws_id, run_id=run["id"],
            title="Reflected XSS on /v1/users", severity="high",
            category="xss", evidence=evidence_url,
            tool_source="dalfox",
        )
        session.add(f)
        session.commit()
        session.refresh(f)
        return ws_id, run, f.id


def test_finding_pivot_persists_structured_pivots(stack):
    client, headers, fake, _ = stack
    fake.messages._responder = _pivot_responder
    _ws, _run, fid = _seed_finding(client, headers)

    r = client.post(f"/api/advisor/findings/{fid}/pivot", headers=headers)
    assert r.status_code == 201, r.text
    advice = r.json()
    assert advice["kind"] == "finding_pivot"
    assert advice["ref_id"] == fid
    structured = advice["body"]["structured"]
    assert len(structured["pivots"]) == 2
    assert structured["pivots"][0]["tool"] == "nuclei"
    assert "nuclei -u https://api.lab.example.com" in structured["pivots"][0]["command"]
    assert structured["confidence"] == "medium"


def test_finding_pivot_cached_get_returns_same_row(stack):
    client, headers, fake, _ = stack
    fake.messages._responder = _pivot_responder
    _ws, _run, fid = _seed_finding(client, headers)
    first = client.post(f"/api/advisor/findings/{fid}/pivot", headers=headers).json()
    cached = client.get(f"/api/advisor/findings/{fid}/pivot", headers=headers).json()
    assert cached["id"] == first["id"]


def test_finding_pivot_404_on_unknown_id(stack):
    client, headers, fake, _ = stack
    fake.messages._responder = _pivot_responder
    assert client.post("/api/advisor/findings/f_nope/pivot",
                       headers=headers).status_code == 404


def test_finding_pivot_anonymous_blocked(stack):
    client, _, _, _ = stack
    assert client.post("/api/advisor/findings/f_x/pivot").status_code == 401


def test_finding_pivot_includes_sibling_assets_in_prompt(stack):
    """The prompt should reference sibling URLs/IPs on the same host so
    Claude can chain. We don't need to assert exactly which fields land,
    just that the host shows up in the user message body."""
    client, headers, fake, _ = stack
    fake.messages._responder = _pivot_responder
    _ws, _run, fid = _seed_finding(client, headers,
                                     evidence_url="https://api.lab.example.com/v1/users")
    client.post(f"/api/advisor/findings/{fid}/pivot", headers=headers)
    user_msg = fake.messages.calls[-1]["messages"][0]["content"]
    assert "api.lab.example.com" in user_msg
    assert "sibling_assets" in user_msg
    assert "sibling_findings" in user_msg


# ---------------------------- auto target-analysis hook --------------------


def test_auto_target_analysis_fires_after_run_complete(stack):
    """A run completion should trigger a fire-and-forget analyze_target
    call when auto_target_analysis is on + API key is set."""
    client, headers, fake, mp = stack
    mp.setenv("AUTO_TARGET_ANALYSIS", "true")
    from app.core.config import get_settings
    get_settings.cache_clear()
    fake.messages._responder = _analysis_responder
    _ws, target, _run = _seed_run(client, headers)

    cached = client.get(f"/api/advisor/targets/{target['id']}/analyze",
                        headers=headers).json()
    assert cached is not None, "expected auto-analysis to populate the cached row"
    assert cached["kind"] == "target_analysis"
    assert cached["ref_id"] == target["id"]
    assert cached["body"]["structured"]["risk_level"] == "high"


def test_auto_target_analysis_skipped_without_api_key(stack):
    client, headers, _, mp = stack
    mp.setenv("AUTO_TARGET_ANALYSIS", "true")
    mp.delenv("ANTHROPIC_API_KEY", raising=False)
    from app.core.config import get_settings
    get_settings.cache_clear()
    _ws, target, _run = _seed_run(client, headers)
    r = client.get(f"/api/advisor/targets/{target['id']}/analyze", headers=headers)
    assert r.status_code == 200
    assert r.json() is None


def test_auto_target_analysis_respects_cooldown(stack, monkeypatch):
    """A second run completing inside the cooldown window must not overwrite
    the existing target_analysis row."""
    client, headers, fake, mp = stack
    fake.messages._responder = _analysis_responder
    mp.setenv("AUTO_TARGET_ANALYSIS", "true")
    monkeypatch.setenv("AUTO_TARGET_ANALYSIS_COOLDOWN_SECONDS", "9999")
    from app.core.config import get_settings
    get_settings.cache_clear()

    # First run triggers analysis
    _ws_id, target, _run1 = _seed_run(client, headers)
    first = client.get(f"/api/advisor/targets/{target['id']}/analyze",
                        headers=headers).json()
    assert first is not None
    first_id = first["id"]
    first_calls = len(fake.messages.calls)

    # Second run completes — cooldown should prevent another Claude call
    run2 = client.post("/api/runs", headers=headers, json={
        "workspace_id": _ws_id, "target_id": target["id"],
        "profile_id": "passive_recon",
    }).json()
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        if client.get(f"/api/runs/{run2['id']}", headers=headers).json()["status"] == "completed":
            break
        time.sleep(0.3)

    cached = client.get(f"/api/advisor/targets/{target['id']}/analyze",
                        headers=headers).json()
    assert cached["id"] == first_id, "cooldown was supposed to keep the same row"
    assert len(fake.messages.calls) == first_calls, "no additional Claude call expected"
