"""Claude advisor.

Wraps the Anthropic SDK to provide four operator-facing flows:

  triage_run(run_id)           — summarise a completed run, prioritise findings
  suggest_profile(target_id)   — recommend the next profile to launch
  explain_finding(finding_id)  — interpret one finding (severity, exploit,
                                  remediation) past the template's noise
  ask(question, refs)          — free-form Q&A with auto-loaded context

Defaults follow the claude-api skill recommendations:
  - model: claude-opus-4-7
  - thinking: adaptive (intelligence-sensitive recon work)
  - effort: high
  - prompt caching on the static ReconForge schema preamble (it's ~1500 tokens
    of stable text + the profile catalogue, so cache hits dominate cost on the
    second invocation onward)

The Anthropic API key comes from ANTHROPIC_API_KEY. If it's not set,
`is_configured()` returns False and routes return 503 — the rest of the
control plane keeps working.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Any

import anthropic
from sqlmodel import Session, select

from app.models import Advice, Asset, Finding, Run, RunStep, Target, User
from app.services import audit
from app.services.tool_registry import get_registry

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "claude-opus-4-7"
DEFAULT_MAX_TOKENS = 16000
SYSTEM_PROMPT = """\
You are a senior offensive-security engineer advising an operator running a
recon / bug-bounty pipeline called ReconForge. The operator is running tools
against authorized targets only. You are precise, terse, and grounded in the
data you are given. You never invent CVE numbers, hostnames, or finding
details that aren't in the input.

# Domain model

ReconForge has these resources, in order:
  Workspace ⊃ Target ⊃ Run ⊃ RunStep ⊃ {Asset, Finding, Artifact}

A *Run* is one execution of a *Profile* (an ordered list of tool steps) against
one *Target*. Each step's stdout is captured. The platform also normalises
domain/url/ip lines into Assets, and parses nuclei/dalfox/etc. output into
Findings (severity-ranked: critical > high > medium > low > info).

# Profiles

Profiles in this registry include passive_recon, web_quick, web_deep,
projectdiscovery_asm, oneforall_chain (the legacy 10-stage pipeline),
cloud_audit, access_bypass, secrets_supply_chain, content_param_discovery,
and others. High-risk profiles (anything that actively probes auth or runs
fuzzing) require explicit target authorization (target.active_allowed=true).

# Risk levels

passive < low_active < medium_active < high_active. Anything above passive
needs explicit authorization on the target. Cloud-credentialed profiles are
high_active because a botched scan can pivot inside an AWS account.

# How to advise

When given a run, target, or finding:
  1. Lead with the *most actionable* observation — what should the operator do
     next, in one sentence.
  2. Then a brief justification grounded in the data (cite specific hosts,
     status codes, finding IDs).
  3. If the input is empty / boring, say so plainly. Don't pad.
  4. When suggesting a follow-up profile, name a real one from the list above
     and say *why* — don't recommend it just because it's next in a list.
  5. Be terse. The operator is running many of these.
"""


@dataclass
class AdviceResult:
    """Result of an advisor call. Persisted as an Advice row."""
    summary: str
    body: dict[str, Any]
    prompt_tokens: int
    completion_tokens: int
    cached_tokens: int
    model: str


def is_configured() -> bool:
    return bool(os.getenv("ANTHROPIC_API_KEY"))


def _client() -> anthropic.Anthropic:
    """Return a configured client. Tests can monkeypatch this to stub messages.create."""
    return anthropic.Anthropic()


def _stable_preamble() -> list[dict[str, Any]]:
    """The cacheable prefix: system prompt + tool/profile catalogue snapshot.

    cache_control on the last block instructs the API to cache everything up
    through it. Subsequent calls within the 5-minute TTL window read this back
    at ~10% of input cost.
    """
    reg = get_registry()
    profiles = reg.list_profiles()
    profile_lines = []
    for prof in profiles:
        steps = ", ".join(s["tool"] for s in prof.get("steps", [])[:8])
        profile_lines.append(
            f"  - {prof.get('id')} ({prof.get('risk', 'passive')}): "
            f"{prof.get('description', '').splitlines()[0][:140]}\n"
            f"    steps: {steps}"
        )

    catalogue = (
        "# Profile catalogue (live, from this control plane)\n\n"
        + "\n".join(profile_lines[:60])
    )

    return [
        {"type": "text", "text": SYSTEM_PROMPT},
        {"type": "text", "text": catalogue, "cache_control": {"type": "ephemeral"}},
    ]


def _call(user_payload: str) -> AdviceResult:
    """Single source of truth for hitting the model. All flows pass their
    shaped context as a JSON-fenced user message and read the model's plain-text
    reply back. We keep responses non-streaming because endpoints are
    request/response and the volume per call is well under the timeout."""
    client = _client()
    response = client.messages.create(
        model=DEFAULT_MODEL,
        max_tokens=DEFAULT_MAX_TOKENS,
        thinking={"type": "adaptive"},
        output_config={"effort": "high"},
        system=_stable_preamble(),
        messages=[{"role": "user", "content": user_payload}],
    )
    text = "\n".join(b.text for b in response.content if b.type == "text").strip()
    usage = response.usage
    return AdviceResult(
        summary=text,
        body={"text": text, "stop_reason": response.stop_reason},
        prompt_tokens=getattr(usage, "input_tokens", 0) or 0,
        completion_tokens=getattr(usage, "output_tokens", 0) or 0,
        cached_tokens=getattr(usage, "cache_read_input_tokens", 0) or 0,
        model=getattr(response, "model", DEFAULT_MODEL),
    )


# ---------- Context shaping ---------------------------------------------------

def _serialize_run_context(session: Session, run: Run) -> str:
    """Build a compact JSON block summarising one run for the advisor.

    Everything is bounded — no operator wants their advisor call to OOM because
    a chatty profile produced 50K events. Findings are severity-ranked and
    truncated; assets are typed and capped per type.
    """
    target = session.get(Target, run.target_id)
    steps = list(session.exec(
        select(RunStep).where(RunStep.run_id == run.id).order_by(RunStep.index)
    ).all())
    findings = list(session.exec(
        select(Finding).where(Finding.run_id == run.id)
    ).all())
    assets = list(session.exec(
        select(Asset).where(Asset.run_id == run.id)
    ).all())

    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: severity_rank.get(f.severity, 5))

    assets_by_type: dict[str, list[str]] = {}
    for a in assets:
        assets_by_type.setdefault(a.type, []).append(a.value)

    payload = {
        "run": {
            "id": run.id,
            "profile_id": run.profile_id,
            "status": run.status.value if hasattr(run.status, "value") else str(run.status),
            "risk": run.risk.value if hasattr(run.risk, "value") else str(run.risk),
            "created_at": run.created_at.isoformat() if run.created_at else None,
        },
        "target": (target.model_dump() if target else None),
        "steps": [
            {"index": s.index, "tool": s.tool_id, "status": s.status.value
                if hasattr(s.status, "value") else str(s.status), "error": s.error}
            for s in steps
        ],
        "findings_total": len(findings),
        "findings": [
            {"id": f.id, "title": f.title, "severity": f.severity, "category": f.category,
             "tool_source": f.tool_source, "evidence": (f.evidence or "")[:400]}
            for f in findings[:30]
        ],
        "assets_total": len(assets),
        "assets_by_type": {k: v[:25] for k, v in assets_by_type.items()},
    }
    return json.dumps(payload, indent=2, default=str)


def _serialize_target_context(session: Session, target: Target) -> str:
    runs = list(session.exec(
        select(Run).where(Run.target_id == target.id).order_by(Run.created_at.desc()).limit(20)
    ).all())
    findings = list(session.exec(
        select(Finding).where(Finding.run_id.in_([r.id for r in runs]))  # type: ignore[attr-defined]
    ).all()) if runs else []
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: severity_rank.get(f.severity, 5))
    payload = {
        "target": target.model_dump(),
        "recent_runs": [
            {"id": r.id, "profile_id": r.profile_id,
             "status": r.status.value if hasattr(r.status, "value") else str(r.status),
             "risk": r.risk.value if hasattr(r.risk, "value") else str(r.risk),
             "created_at": r.created_at.isoformat() if r.created_at else None}
            for r in runs
        ],
        "open_findings_total": len(findings),
        "open_findings_by_severity": {
            sev: sum(1 for f in findings if f.severity == sev)
            for sev in ("critical", "high", "medium", "low", "info")
        },
        "top_findings": [
            {"id": f.id, "title": f.title, "severity": f.severity, "tool_source": f.tool_source}
            for f in findings[:15]
        ],
    }
    return json.dumps(payload, indent=2, default=str)


def _serialize_target_analysis_context(session: Session, target: Target) -> str:
    """Richer context bundle for the deep target-analysis flow. We hand
    Claude the full passive-recon picture: every asset bucketed by type,
    HTTP-tech rollup (from httpx/wappalyzer/whatweb), and the latest 5
    runs. We deliberately cap each list so prompts stay <12k tokens even
    on a target with hundreds of subdomains."""
    runs = list(session.exec(
        select(Run).where(Run.target_id == target.id).order_by(Run.created_at.desc()).limit(20)
    ).all())
    run_ids = [r.id for r in runs]
    assets = list(session.exec(
        select(Asset).where(Asset.workspace_id == target.workspace_id)
    ).all()) if run_ids else []
    # Filter to assets produced by *this* target's runs OR matching the target value suffix.
    tgt = target.value.lower()
    def _belongs(a: Asset) -> bool:
        if a.run_id and a.run_id in run_ids:
            return True
        val = (a.value or "").lower()
        return val == tgt or val.endswith("." + tgt) or tgt in val
    assets = [a for a in assets if _belongs(a)]
    by_type: dict[str, list[Asset]] = {}
    for a in assets:
        by_type.setdefault(a.type, []).append(a)

    # Aggregate HTTP tech from `url` asset meta when available — that's where
    # the runner stashes the httpx json including detected webservers + tech.
    tech_hits: dict[str, int] = {}
    server_hits: dict[str, int] = {}
    status_hits: dict[str, int] = {}
    for u in by_type.get("url", []):
        meta_json = (u.meta or {}).get("json") if isinstance(u.meta, dict) else None
        if not isinstance(meta_json, dict):
            continue
        for t in meta_json.get("tech", []) or []:
            tech_hits[str(t)] = tech_hits.get(str(t), 0) + 1
        if meta_json.get("webserver"):
            server_hits[str(meta_json["webserver"])] = server_hits.get(str(meta_json["webserver"]), 0) + 1
        if meta_json.get("status_code"):
            status_hits[str(meta_json["status_code"])] = status_hits.get(str(meta_json["status_code"])
                                                                          , 0) + 1

    findings = list(session.exec(
        select(Finding).where(Finding.run_id.in_(run_ids))  # type: ignore[attr-defined]
    ).all()) if run_ids else []
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: severity_rank.get(f.severity, 5))

    payload = {
        "target": target.model_dump(),
        "scope": {
            "in_scope": target.in_scope,
            "passive_allowed": target.passive_allowed,
            "active_allowed": target.active_allowed,
        },
        "recent_runs": [
            {"id": r.id, "profile_id": r.profile_id,
             "status": r.status.value if hasattr(r.status, "value") else str(r.status),
             "risk": r.risk.value if hasattr(r.risk, "value") else str(r.risk)}
            for r in runs[:5]
        ],
        "asset_counts": {k: len(v) for k, v in by_type.items()},
        "sample_subdomains": [a.value for a in by_type.get("domain", [])[:30]],
        "sample_urls": [a.value for a in by_type.get("url", [])[:25]],
        "sample_ips": [a.value for a in by_type.get("ip", [])[:20]],
        "http_tech_top": sorted(tech_hits.items(), key=lambda kv: -kv[1])[:15],
        "webservers_top": sorted(server_hits.items(), key=lambda kv: -kv[1])[:10],
        "status_distribution": status_hits,
        "findings_by_severity": {
            sev: sum(1 for f in findings if f.severity == sev)
            for sev in ("critical", "high", "medium", "low", "info")
        },
        "top_findings": [
            {"id": f.id, "title": f.title, "severity": f.severity,
             "tool_source": f.tool_source}
            for f in findings[:15]
        ],
    }
    return json.dumps(payload, indent=2, default=str)


def _serialize_finding_pivot_context(session: Session, finding: Finding) -> str:
    """Bundle a finding + adjacent assets/findings on the same host so
    Claude can reason about which probe makes sense next. Adjacency is
    'same workspace + same host(name) suffix' which catches the realistic
    pivot points (sister subdomains, urls on the same IP)."""
    run = session.get(Run, finding.run_id) if finding.run_id else None
    target = session.get(Target, run.target_id) if run else None

    # Best-effort host extraction from evidence (often a URL)
    evidence = finding.evidence or ""
    host = ""
    for token in evidence.split():
        if "://" in token:
            from urllib.parse import urlparse
            try:
                host = urlparse(token).netloc.split(":", 1)[0].lower()
            except Exception:  # noqa: BLE001
                pass
            if host:
                break

    # Sibling assets — anything in the workspace touching the same host
    sibling_assets: list[dict[str, Any]] = []
    if host:
        rows = session.exec(
            select(Asset).where(Asset.workspace_id == finding.workspace_id)
        ).all()
        for a in rows:
            val = (a.value or "").lower()
            if a.type == "url" and host in val:
                sibling_assets.append({"type": a.type, "value": a.value,
                                        "source": a.source})
            elif a.type == "domain" and (val == host or val.endswith("." + host) or host.endswith("." + val)):
                sibling_assets.append({"type": a.type, "value": a.value,
                                        "source": a.source})
            elif a.type == "ip" and host in val:
                sibling_assets.append({"type": a.type, "value": a.value,
                                        "source": a.source})
        sibling_assets = sibling_assets[:25]

    # Sibling findings on the same host (skip the current one)
    sibling_findings: list[dict[str, Any]] = []
    if host:
        rows = session.exec(
            select(Finding).where(
                Finding.workspace_id == finding.workspace_id,
                Finding.id != finding.id,
            )
        ).all()
        for f in rows[:200]:
            if host in (f.evidence or ""):
                sibling_findings.append({"id": f.id, "title": f.title,
                                          "severity": f.severity,
                                          "tool_source": f.tool_source})
        sibling_findings = sibling_findings[:15]

    payload = {
        "finding": {
            "id": finding.id, "title": finding.title,
            "severity": finding.severity, "category": finding.category,
            "tool_source": finding.tool_source,
            "evidence": (finding.evidence or "")[:600],
        },
        "host": host or None,
        "target": (target.model_dump() if target else None),
        "run_profile": (run.profile_id if run else None),
        "sibling_assets": sibling_assets,
        "sibling_findings": sibling_findings,
    }
    return json.dumps(payload, indent=2, default=str)


def _serialize_finding_context(session: Session, finding: Finding) -> str:
    run = session.get(Run, finding.run_id) if finding.run_id else None
    target = session.get(Target, run.target_id) if run else None
    payload = {
        "finding": {
            "id": finding.id, "title": finding.title, "severity": finding.severity,
            "category": finding.category, "tool_source": finding.tool_source,
            "evidence": finding.evidence or "",
            "meta": finding.meta or {},
        },
        "target": (target.model_dump() if target else None),
        "run_profile": (run.profile_id if run else None),
    }
    return json.dumps(payload, indent=2, default=str)


# ---------- Persistence -------------------------------------------------------

def _store(
    session: Session,
    *,
    workspace_id: str,
    kind: str,
    ref_id: str | None,
    actor: User | None,
    result: AdviceResult,
) -> Advice:
    existing = session.exec(
        select(Advice).where(
            Advice.workspace_id == workspace_id,
            Advice.kind == kind,
            Advice.ref_id == ref_id,
        )
    ).first()
    if existing:
        existing.summary = result.summary
        existing.body = result.body
        existing.prompt_tokens = result.prompt_tokens
        existing.completion_tokens = result.completion_tokens
        existing.cached_tokens = result.cached_tokens
        existing.model = result.model
        existing.actor_id = actor.id if actor else None
        session.add(existing)
        session.commit()
        session.refresh(existing)
        return existing
    advice = Advice(
        workspace_id=workspace_id, kind=kind, ref_id=ref_id,
        actor_id=actor.id if actor else None, model=result.model,
        prompt_tokens=result.prompt_tokens, completion_tokens=result.completion_tokens,
        cached_tokens=result.cached_tokens, summary=result.summary, body=result.body,
    )
    session.add(advice)
    session.commit()
    session.refresh(advice)
    return advice


def _audit(session: Session, actor: User | None, kind: str, ref_id: str | None,
           result: AdviceResult) -> None:
    audit.record(session, actor=actor, action=f"advisor.{kind}",
                 target_kind="advice", target_id=ref_id,
                 payload={"model": result.model,
                           "prompt_tokens": result.prompt_tokens,
                           "completion_tokens": result.completion_tokens,
                           "cached_tokens": result.cached_tokens})


# ---------- Public flows ------------------------------------------------------

def triage_run(session: Session, run: Run, *, actor: User | None) -> Advice:
    ctx = _serialize_run_context(session, run)
    user = (
        "Triage this run. Lead with the single most useful next action for the "
        "operator. Then bullet the top 3-5 specific findings (cite IDs and "
        "severity). Then suggest one follow-up profile and say why.\n\n"
        f"```json\n{ctx}\n```"
    )
    result = _call(user)
    advice = _store(session, workspace_id=run.workspace_id, kind="run_triage",
                    ref_id=run.id, actor=actor, result=result)
    _audit(session, actor, "run_triage", run.id, result)
    session.commit()
    return advice


def suggest_profile(session: Session, target: Target, *, actor: User | None) -> Advice:
    ctx = _serialize_target_context(session, target)
    user = (
        "Recommend the next profile to run against this target. Name exactly "
        "one profile from the catalogue, give a one-sentence rationale, and a "
        "second sentence noting any pre-condition (e.g. 'requires "
        "active_allowed=true').\n\n"
        f"```json\n{ctx}\n```"
    )
    result = _call(user)
    advice = _store(session, workspace_id=target.workspace_id,
                    kind="target_suggest_profile", ref_id=target.id,
                    actor=actor, result=result)
    _audit(session, actor, "target_suggest_profile", target.id, result)
    session.commit()
    return advice


def analyze_target(session: Session, target: Target, *, actor: User | None) -> Advice:
    """Deep target analysis: attack-surface read of what we've collected
    so far. The structured prompt asks Claude to return JSON inside a
    fenced code block so the UI can render sections; we parse defensively
    and fall back to the prose summary if the JSON block is missing."""
    ctx = _serialize_target_analysis_context(session, target)
    user = (
        "Analyse the attack surface of this target using only the data below.\n\n"
        "Return TWO things, in this order:\n"
        " 1. A 1-2 sentence verdict that an operator can paste into a ticket.\n"
        " 2. A fenced ```json``` block with exactly these keys:\n"
        "    - tech_stack: list[str]                inferred from the HTTP probe data\n"
        "    - high_value_assets: list[{url, why}]  pivot points worth manual review\n"
        "    - attack_surface: list[str]            short bullets, prioritised\n"
        "    - recommended_profiles: list[str]      profile_ids from the catalogue\n"
        "    - payload_categories: list[str]        any of: xss, sqli, ssrf, lfi,\n"
        "                                            ssti, xxe, nosqli, redirect,\n"
        "                                            crlf, command-injection\n"
        "    - risk_level: 'low'|'medium'|'high'|'critical'\n"
        "    - one_line_next_step: str\n"
        "Don't invent assets, findings, or CVEs that aren't in the data.\n\n"
        f"```json\n{ctx}\n```"
    )
    result = _call(user)
    enriched = _enrich_with_structured(result)
    advice = _store(session, workspace_id=target.workspace_id,
                     kind="target_analysis", ref_id=target.id,
                     actor=actor, result=enriched)
    _audit(session, actor, "target_analysis", target.id, enriched)
    session.commit()
    return advice


def _enrich_with_structured(result: AdviceResult) -> AdviceResult:
    """If the body text contains a fenced ```json``` block, attach the
    parsed result under body.structured. Used by analyze_target +
    pivot_from_finding; flows whose output is pure prose pass through."""
    body_text = result.body.get("text", "") if isinstance(result.body, dict) else ""
    structured: dict[str, Any] = {}
    if "```json" in body_text:
        try:
            fence = body_text.split("```json", 1)[1].split("```", 1)[0]
            structured = json.loads(fence.strip())
        except (json.JSONDecodeError, IndexError, ValueError):
            structured = {}
    enriched_body = (
        {**result.body, "structured": structured}
        if isinstance(result.body, dict)
        else {"text": body_text, "structured": structured}
    )
    return AdviceResult(
        summary=result.summary, body=enriched_body,
        prompt_tokens=result.prompt_tokens,
        completion_tokens=result.completion_tokens,
        cached_tokens=result.cached_tokens, model=result.model,
    )


def maybe_auto_analyze_target(session: Session, target_id: str,
                                *, cooldown_seconds: int) -> Advice | None:
    """Called by the runner after a run completes. Skips silently when:
      * ANTHROPIC_API_KEY is unset
      * the target was deleted between run-complete and now
      * a target_analysis advice row exists newer than the cooldown
    Any error from Claude is swallowed; the operator can always click
    the Analyze button manually."""
    if not is_configured():
        return None
    target = session.get(Target, target_id)
    if not target:
        return None
    existing = session.exec(
        select(Advice).where(
            Advice.kind == "target_analysis",
            Advice.ref_id == target_id,
        )
    ).first()
    if existing and existing.created_at:
        from datetime import datetime, timezone, timedelta
        age = datetime.now(timezone.utc) - existing.created_at
        if age < timedelta(seconds=cooldown_seconds):
            logger.info("auto-target-analysis skipped for %s — cached row %.0fs old",
                         target_id, age.total_seconds())
            return None
    try:
        return analyze_target(session, target, actor=None)
    except Exception as exc:  # noqa: BLE001 — operator can always re-trigger
        logger.warning("auto-target-analysis failed for %s: %s", target_id, exc)
        return None


def pivot_from_finding(session: Session, finding: Finding, *,
                        actor: User | None) -> Advice:
    """Given a finding, suggest 2-3 concrete next probes to try. Each
    pivot includes the tool to use, a templated command, the rationale,
    and the severity of the asset the probe would prove. Output is the
    same {text, structured} shape analyze_target produces so the UI
    treats them identically."""
    ctx = _serialize_finding_pivot_context(session, finding)
    user = (
        "Suggest 2-3 specific *pivots* from this finding — what to probe next,\n"
        "given the sibling assets and findings on the same host.\n\n"
        "Return TWO things, in this order:\n"
        " 1. A 1-sentence summary the operator can paste into a ticket.\n"
        " 2. A fenced ```json``` block with exactly these keys:\n"
        "    - pivots: list[{title, tool, command, rationale, expected_severity}]\n"
        "                tool is a real binary name from the registry\n"
        "                  (nuclei, dalfox, ffuf, httpx, naabu, subfinder,\n"
        "                   xsstrike, dirsearch, ...).\n"
        "                command is a runnable shell command (no\n"
        "                  placeholders — fill in concrete URLs/hosts from\n"
        "                  the data).\n"
        "                expected_severity is 'low'|'medium'|'high'|'critical'.\n"
        "    - related_findings: list[finding_id]  IDs from sibling_findings\n"
        "                                            that this pivot would extend.\n"
        "    - confidence: 'low' | 'medium' | 'high'\n"
        "Don't invent CVEs, tools that aren't in the registry, or hosts that\n"
        "aren't in the sibling lists.\n\n"
        f"```json\n{ctx}\n```"
    )
    result = _call(user)
    advice = _store(session, workspace_id=finding.workspace_id,
                     kind="finding_pivot", ref_id=finding.id,
                     actor=actor, result=_enrich_with_structured(result))
    _audit(session, actor, "finding_pivot", finding.id, result)
    session.commit()
    return advice


def explain_finding(session: Session, finding: Finding, *, actor: User | None) -> Advice:
    ctx = _serialize_finding_context(session, finding)
    user = (
        "Explain this finding in 4-6 sentences. Cover: what it actually is "
        "(past the template noise), realistic exploitability (don't bluff), "
        "and the concrete next verification step.\n\n"
        f"```json\n{ctx}\n```"
    )
    result = _call(user)
    advice = _store(session, workspace_id=finding.workspace_id,
                    kind="finding_explain", ref_id=finding.id, actor=actor,
                    result=result)
    _audit(session, actor, "finding_explain", finding.id, result)
    session.commit()
    return advice


def ask(session: Session, *, workspace_id: str, question: str,
        run_id: str | None = None, target_id: str | None = None,
        actor: User | None = None) -> Advice:
    sections: list[str] = []
    if run_id:
        run = session.get(Run, run_id)
        if run:
            sections.append("## Run context\n```json\n" + _serialize_run_context(session, run) + "\n```")
    if target_id:
        target = session.get(Target, target_id)
        if target:
            sections.append("## Target context\n```json\n" + _serialize_target_context(session, target) + "\n```")
    user = "## Question\n" + question
    if sections:
        user += "\n\n" + "\n\n".join(sections)
    result = _call(user)
    advice = _store(session, workspace_id=workspace_id, kind="ask",
                    ref_id=run_id or target_id, actor=actor, result=result)
    _audit(session, actor, "ask", run_id or target_id, result)
    session.commit()
    return advice
