"""Secret extraction helpers.

When a tool's output contains a credential — AWS key, GitHub token, Slack
webhook, GCP service account key, JWT, etc. — we want three things to
happen:

1. A high-severity Finding so the operator sees it on the Results page.
2. A structured Artifact (`type=secret`) so the redacted match, its
   fingerprint, kind, and surrounding context survive past the run.
3. A consistent fingerprint so re-runs against the same source surface
   the same secret rather than counting it twice.

This module owns 1's classification logic and 2's serialization shape.
The runner / normalizer call into it. We deliberately don't store the
unredacted secret anywhere — the artifact holds the kind + fingerprint
+ a redacted preview, never the live credential.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

# Pattern catalogue. Kept tight on purpose — false positives are worse than
# missed-by-one rules because each match becomes a high-severity Finding.
# Order matters: more specific patterns first so e.g. an AWS access key
# matches "aws_access_key" rather than the generic "high_entropy" rule.
_PATTERNS: list[tuple[str, str, re.Pattern[str], str]] = [
    # (kind, severity, compiled regex, why-this-matters one-liner)
    ("aws_access_key", "critical", re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "AWS access key id — pair with secret key grants programmatic AWS access."),
    ("aws_secret_key", "critical", re.compile(r"(?i)aws(.{0,20})?(secret|sk)[^\s'\"]{0,3}[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        "AWS secret key candidate."),
    ("aws_session_token", "high", re.compile(r"\b(FQoGZ[A-Za-z0-9/+=]{50,})\b"),
        "AWS STS session token."),
    ("github_token", "critical", re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b"),
        "GitHub personal access / fine-grained token."),
    ("github_app_token", "high", re.compile(r"\b(ghs_[A-Za-z0-9_]{36,255})\b"),
        "GitHub App installation token."),
    ("gitlab_token", "high", re.compile(r"\b(glpat-[A-Za-z0-9_-]{20,})\b"),
        "GitLab personal access token."),
    ("slack_token", "critical", re.compile(r"\b(xox[abprs]-[A-Za-z0-9-]{10,})\b"),
        "Slack bot/user/refresh token."),
    ("slack_webhook", "high", re.compile(r"(https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,})"),
        "Slack incoming-webhook URL — anyone with this can post into a channel."),
    ("discord_webhook", "medium", re.compile(r"(https://(?:canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]{50,})"),
        "Discord webhook — usable for spoofed messages or persistence."),
    ("stripe_secret_key", "critical", re.compile(r"\b(sk_(?:live|test)_[A-Za-z0-9]{24,})\b"),
        "Stripe API key — live mode authorises charges."),
    ("gcp_service_account", "critical", re.compile(r'"type"\s*:\s*"service_account".{0,200}"private_key"\s*:\s*"-----BEGIN PRIVATE KEY'),
        "GCP service-account JSON with embedded private key."),
    ("gcp_api_key", "high", re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"),
        "Google API key."),
    ("anthropic_key", "critical", re.compile(r"\b(sk-ant-[A-Za-z0-9_-]{32,})\b"),
        "Anthropic API key."),
    ("openai_key", "critical", re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9_-]{32,})\b"),
        "OpenAI API key."),
    ("private_key_pem", "critical", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |PGP )?PRIVATE KEY-----"),
        "Embedded private key in PEM form."),
    ("jwt", "medium", re.compile(r"\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b"),
        "JSON Web Token — may carry session identity or signing context."),
    ("npm_token", "high", re.compile(r"\b(npm_[A-Za-z0-9]{36,})\b"),
        "npm publish token."),
    ("pypi_token", "high", re.compile(r"\b(pypi-AgEIcHlwaS5vcmcC[A-Za-z0-9_-]{50,})\b"),
        "PyPI upload token."),
    ("twilio_account_sid", "high", re.compile(r"\b(AC[a-f0-9]{32})\b"),
        "Twilio Account SID — usually paired with auth token."),
    ("sendgrid_key", "high", re.compile(r"\b(SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{40,})\b"),
        "SendGrid API key."),
    ("mailgun_key", "high", re.compile(r"\b(key-[a-f0-9]{32})\b"),
        "Mailgun API key."),
    ("generic_bearer", "low", re.compile(r"(?i)\b(?:authorization|bearer)\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.=]{32,})['\"]?"),
        "Bearer-style token — review for context."),
]


@dataclass(frozen=True)
class SecretMatch:
    kind: str
    severity: str
    rationale: str
    fingerprint: str
    redacted: str
    raw_offset: int
    context: str
    extra: dict[str, Any] = field(default_factory=dict)

    def as_payload(self) -> dict[str, Any]:
        """Shape we persist in Artifact.meta / dump into the secret artifact."""
        return {
            "kind": self.kind,
            "severity": self.severity,
            "rationale": self.rationale,
            "fingerprint": self.fingerprint,
            "redacted": self.redacted,
            "context": self.context,
            "extra": self.extra,
        }


def fingerprint_value(value: str) -> str:
    """Stable 12-char fingerprint that survives re-runs. We never log the
    raw value — only its hash — so the fingerprint is safe to put in
    Finding.title and Artifact.name."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def redact_value(value: str) -> str:
    """Keep just enough so the operator can tell two distinct secrets
    apart without seeing the credential."""
    if len(value) <= 8:
        return "***"
    return f"{value[:4]}***{value[-4:]} ({len(value)} chars)"


def _slice_context(text: str, start: int, end: int, window: int = 40) -> str:
    left = max(0, start - window)
    right = min(len(text), end + window)
    snippet = text[left:right].replace("\n", " ⏎ ")
    if left > 0:
        snippet = "…" + snippet
    if right < len(text):
        snippet = snippet + "…"
    return snippet


def extract_secrets_from_text(text: str, *, max_matches: int = 50) -> list[SecretMatch]:
    """Walk every pattern over `text` and collect matches.

    Bounded by `max_matches` to keep pathological inputs (a leaked
    keystore dumped into the stdout buffer) from generating thousands of
    findings. The runner calls this once per step on the aggregated
    stdout, not per line, so the limit is enforced per-step."""
    if not text:
        return []
    seen_fingerprints: set[str] = set()
    matches: list[SecretMatch] = []
    for kind, severity, pattern, rationale in _PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(1) if match.groups() else match.group(0)
            fp = fingerprint_value(value)
            if fp in seen_fingerprints:
                # Same secret matched twice (e.g. logged on stdout and
                # echoed back in stderr) — keep one record.
                continue
            seen_fingerprints.add(fp)
            matches.append(SecretMatch(
                kind=kind,
                severity=severity,
                rationale=rationale,
                fingerprint=fp,
                redacted=redact_value(value),
                raw_offset=match.start(),
                context=_slice_context(text, match.start(), match.end()),
            ))
            if len(matches) >= max_matches:
                return matches
    return matches


# ----------------------------------------------------------------------
# Tool-format adapters. Several scanners (trufflehog, gitleaks) emit a
# JSON-per-line shape; rather than re-derive their classifications from
# the raw match, we trust their detector name.
# ----------------------------------------------------------------------


def parse_trufflehog_json(record: dict[str, Any]) -> SecretMatch | None:
    detector = str(record.get("DetectorName") or record.get("detector_name") or "").strip()
    if not detector:
        return None
    raw = str(record.get("Raw") or record.get("raw") or "")
    fp = fingerprint_value(raw or detector + str(record.get("SourceID", "")))
    verified = bool(record.get("Verified") or record.get("verified"))
    source = record.get("SourceMetadata") or record.get("source_metadata") or {}
    return SecretMatch(
        kind=f"trufflehog:{detector.lower().replace(' ', '_')}",
        severity="critical" if verified else "high",
        rationale=f"TruffleHog flagged {detector}{' (verified)' if verified else ''}.",
        fingerprint=fp,
        redacted=redact_value(raw) if raw else f"{detector} match",
        raw_offset=0,
        context=str(source)[:240],
        extra={"verified": verified, "detector": detector},
    )


def parse_gitleaks_json(record: dict[str, Any]) -> SecretMatch | None:
    rule = str(record.get("RuleID") or record.get("Description") or "").strip()
    secret = str(record.get("Secret") or "")
    if not rule and not secret:
        return None
    fp = fingerprint_value(secret or rule + str(record.get("StartLine", "")))
    return SecretMatch(
        kind=f"gitleaks:{rule or 'unknown'}",
        severity="critical",
        rationale=f"gitleaks rule {rule!r} triggered.",
        fingerprint=fp,
        redacted=redact_value(secret) if secret else f"{rule} match",
        raw_offset=int(record.get("StartLine", 0) or 0),
        context=f"{record.get('File', '')}:{record.get('StartLine', '')}",
        extra={
            "rule": rule,
            "file": record.get("File"),
            "line": record.get("StartLine"),
            "commit": record.get("Commit"),
        },
    )


def parse_secretfinder_json(record: dict[str, Any]) -> SecretMatch | None:
    name = str(record.get("name") or record.get("type") or "").strip()
    match = str(record.get("match") or record.get("string") or "")
    if not name and not match:
        return None
    fp = fingerprint_value(match or name)
    return SecretMatch(
        kind=f"secretfinder:{name.lower().replace(' ', '_') or 'generic'}",
        severity="high",
        rationale=f"SecretFinder matched {name or 'pattern'}.",
        fingerprint=fp,
        redacted=redact_value(match) if match else f"{name} match",
        raw_offset=0,
        context=str(record.get("url") or record.get("source") or "")[:240],
        extra={"detector": name},
    )


def deduplicate(matches: Iterable[SecretMatch]) -> list[SecretMatch]:
    """Collapse matches by fingerprint, keeping the highest severity."""
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    best: dict[str, SecretMatch] = {}
    for match in matches:
        previous = best.get(match.fingerprint)
        if previous is None or severity_rank.get(match.severity, 0) > severity_rank.get(previous.severity, 0):
            best[match.fingerprint] = match
    return list(best.values())
