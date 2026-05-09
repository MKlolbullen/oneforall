"""Outbound notifications.

Subscribes to run-completion lifecycle and posts a structured message to a
webhook (Slack/Discord-compatible). Behaviour:

  - Disabled by default.
  - Enabled when platform_config.integrations.slack.enabled = true AND the
    env var named by `webhook_env` (default SLACK_WEBHOOK_URL) is set.
  - Webhook payload is the same JSON body that Slack and Discord both accept
    (`text`); fancier blocks live behind a flag we'll add later.
  - Failures are swallowed and logged — a busted webhook should never crash
    a run.

Why a separate service instead of a tool YAML invocation? The tool layer is
per-step and runs inside the worker container. Run-level events
(run.completed / run.failed / run.cancelled) come straight from the event
bus and need to fire once at the end of the chain, not as another step that
could itself fail and block the chain.
"""
from __future__ import annotations

import logging
import os
from typing import Any

import httpx

from app.services.platform_config import load_platform_config

logger = logging.getLogger(__name__)

WEBHOOK_TIMEOUT = 5.0


def _resolve_settings() -> tuple[bool, str | None]:
    """Return (enabled, webhook_url) from the merged platform config + env."""
    cfg = load_platform_config()
    integrations = (cfg or {}).get("integrations") or {}
    slack = integrations.get("slack") or {}
    enabled = bool(slack.get("enabled"))
    webhook_env = slack.get("webhook_env") or "SLACK_WEBHOOK_URL"
    webhook = os.getenv(webhook_env)
    return enabled, webhook


def is_configured() -> bool:
    enabled, webhook = _resolve_settings()
    return enabled and bool(webhook)


def _format(event_type: str, run_id: str, payload: dict[str, Any]) -> str:
    headline = {
        "run.completed": ":white_check_mark: Run completed",
        "run.failed": ":x: Run failed",
        "run.cancelled": ":warning: Run cancelled",
    }.get(event_type, f"Run event: {event_type}")
    target = payload.get("target_value") or payload.get("target_id") or "?"
    profile = payload.get("profile_id") or "?"
    runner_mode = payload.get("runner_mode") or ""
    extras = []
    if "error" in payload:
        extras.append(f"error: `{payload['error']}`")
    if runner_mode:
        extras.append(f"runner: `{runner_mode}`")
    extra_line = (" — " + ", ".join(extras)) if extras else ""
    return f"*{headline}* — `{run_id}` (`{profile}` on `{target}`){extra_line}"


async def notify_run_event(
    event_type: str,
    run_id: str,
    payload: dict[str, Any] | None = None,
) -> None:
    """Best-effort POST to the configured webhook. Returns silently on every
    failure mode (disabled, no webhook, network error, non-2xx)."""
    if event_type not in {"run.completed", "run.failed", "run.cancelled"}:
        return
    enabled, webhook = _resolve_settings()
    if not enabled or not webhook:
        return
    body = {"text": _format(event_type, run_id, payload or {})}
    try:
        async with httpx.AsyncClient(timeout=WEBHOOK_TIMEOUT) as client:
            r = await client.post(webhook, json=body)
            if r.status_code >= 300:
                logger.warning("webhook %s returned %s: %s",
                                webhook[:30] + "…", r.status_code, r.text[:200])
    except Exception as exc:  # noqa: BLE001 — webhook failures must never propagate
        logger.warning("webhook delivery failed: %s", exc)
