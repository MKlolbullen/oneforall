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

from app.models import Advice, Artifact, Asset, Finding, LootItem, Run, RunStep, Target, User
from app.services import audit, loot as loot_svc
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
Loot = curated high-signal rows (secrets, creds, critical vulns) derived from
findings; Artifacts = durable stdout/stderr/report bytes (fetch via API, never
inline megabytes into prompts).

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

    artifacts = list(session.exec(
        select(Artifact).where(Artifact.run_id == run.id).order_by(Artifact.created_at)
    ).all())
    loot_items = list(session.exec(
        select(LootItem).where(LootItem.run_id == run.id)
    ).all())
    if not loot_items and loot_svc.loot_enabled():
        loot_items = loot_svc.index_run(session, workspace_id=run.workspace_id, run_id=run.id)

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
        "artifacts": [
            {"id": a.id, "name": a.name, "type": a.type, "size_bytes": a.size_bytes,
             "sha256": a.sha256}
            for a in artifacts[:40]
        ],
        "loot": loot_svc.summarize_loot(loot_items),
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
