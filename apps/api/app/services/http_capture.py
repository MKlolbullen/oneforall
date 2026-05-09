"""Per-run HTTP traffic capture via proxify.

Architecture
------------
When a live run starts we spin up a per-run **proxify** sidecar pointing its
JSONL output at a per-run scratch file. Tool subprocesses inherit
`HTTP_PROXY` / `HTTPS_PROXY` env vars pointing at that proxify, so any tool
that respects proxy env (most Go-based PD tools do) routes through it. After
every step finishes we tail-read the JSONL, persist new lines as
HttpExchange rows tagged with the step that was running when the exchange
arrived, and update the per-run offset.

Dry runs do nothing (`start_for_run` returns None) — there's no real HTTP
traffic to capture and we don't want to launch proxify on every test.

The JSONL parser is pure (no subprocess, no DB). It accepts proxify's native
shape *and* a generic shape we control, so we can test without the proxify
binary present.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

from sqlmodel import Session

from app.models import HttpExchange, RunStep

logger = logging.getLogger(__name__)

MAX_BODY_BYTES = 64 * 1024
MAX_EXCHANGES_PER_RUN = 5000


# ---------- Pure parser ------------------------------------------------------


@dataclass
class ParsedExchange:
    method: str
    url: str
    host: str
    request_headers: dict[str, Any]
    request_body: str
    request_body_truncated: bool
    response_status: int | None
    response_headers: dict[str, Any]
    response_body: str
    response_body_truncated: bool
    response_size_bytes: int | None
    duration_ms: int | None
    error: str | None
    started_at: datetime


def _truncate(body: Any) -> tuple[str, bool, int | None]:
    """Coerce a body to text capped at MAX_BODY_BYTES.

    proxify can emit a string, base64-string, dict, or null. We coerce to
    string and cap. If we receive a dict/list we json.dumps it. If we receive
    bytes-shaped strings (base64) we leave them as-is — a UI hint can decide
    whether to render as hex / image / download.
    """
    if body is None:
        return "", False, None
    if isinstance(body, (dict, list)):
        s = json.dumps(body, separators=(",", ":"))
    else:
        s = str(body)
    raw_bytes = len(s.encode("utf-8", errors="replace"))
    if raw_bytes > MAX_BODY_BYTES:
        # Truncate at character boundary; the size we report is the original.
        return s[:MAX_BODY_BYTES], True, raw_bytes
    return s, False, raw_bytes


def _parse_started_at(value: Any) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        try:
            # ISO 8601 with optional trailing Z
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return datetime.now(timezone.utc)
    return datetime.now(timezone.utc)


def _line_to_exchange(raw: str) -> ParsedExchange | None:
    """Convert one JSONL line to a ParsedExchange, accepting two shapes:

    1) proxify native: top-level `request` + `response` sub-objects
    2) generic: flat keys (method, url, status, …)

    Returns None for unparseable lines so a single bad row can't kill an
    entire batch.
    """
    raw = raw.strip()
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None

    if "request" in data and isinstance(data["request"], dict):
        req = data["request"]
        resp = data.get("response") or {}
        if not isinstance(resp, dict):
            resp = {}
        method = req.get("method") or "GET"
        url = req.get("url") or req.get("uri") or ""
        req_headers = req.get("headers") or {}
        req_body = req.get("body")
        resp_headers = resp.get("headers") or {}
        resp_body = resp.get("body")
        resp_status = resp.get("status") or resp.get("status_code")
        duration_ms = data.get("duration_ms") or data.get("latency_ms")
        started_at = _parse_started_at(data.get("timestamp") or data.get("started_at"))
        error = data.get("error")
    else:
        method = data.get("method") or "GET"
        url = data.get("url") or ""
        req_headers = data.get("request_headers") or {}
        req_body = data.get("request_body")
        resp_headers = data.get("response_headers") or {}
        resp_body = data.get("response_body")
        resp_status = data.get("status") or data.get("response_status")
        duration_ms = data.get("duration_ms")
        started_at = _parse_started_at(data.get("started_at") or data.get("timestamp"))
        error = data.get("error")

    if not url:
        return None
    parsed = urlparse(url)
    host = parsed.netloc.split(":", 1)[0] or "?"

    req_text, req_trunc, _ = _truncate(req_body)
    resp_text, resp_trunc, resp_size = _truncate(resp_body)

    return ParsedExchange(
        method=method.upper()[:10],
        url=url[:2048],
        host=host[:255],
        request_headers=req_headers if isinstance(req_headers, dict) else {},
        request_body=req_text,
        request_body_truncated=req_trunc,
        response_status=int(resp_status) if isinstance(resp_status, (int, float, str)) and str(resp_status).isdigit() else None,
        response_headers=resp_headers if isinstance(resp_headers, dict) else {},
        response_body=resp_text,
        response_body_truncated=resp_trunc,
        response_size_bytes=resp_size,
        duration_ms=int(duration_ms) if isinstance(duration_ms, (int, float)) else None,
        error=str(error) if error else None,
        started_at=started_at,
    )


def parse_jsonl_chunk(chunk: str) -> list[ParsedExchange]:
    """Parse a chunk of JSONL into ParsedExchange objects. Bad lines are
    silently dropped so partial files (e.g. last line still being written)
    don't abort the whole batch."""
    return [ex for line in chunk.splitlines() if (ex := _line_to_exchange(line)) is not None]


# ---------- Persistence ------------------------------------------------------


def _step_index_for_timestamp(steps: list[RunStep], when: datetime) -> int | None:
    """Find the step that was running at `when`. Steps without started_at
    don't qualify. The first match wins; if multiple steps cover `when`
    (parallel — not currently a thing, but defensive), the earliest started
    one wins. Returns None if no step bracketed `when`."""
    candidates = []
    for s in steps:
        if not s.started_at:
            continue
        ended = s.finished_at or datetime.now(timezone.utc)
        if s.started_at <= when <= ended:
            candidates.append(s)
    if not candidates:
        return None
    candidates.sort(key=lambda s: s.started_at or datetime.now(timezone.utc))
    return candidates[0].index


def persist_exchanges(
    session: Session,
    *,
    run_id: str,
    workspace_id: str,
    parsed: Iterable[ParsedExchange],
    steps: list[RunStep] | None = None,
) -> int:
    """Insert ParsedExchange rows. Returns count actually inserted, capped
    at MAX_EXCHANGES_PER_RUN over the run's lifetime."""
    from sqlmodel import select, func

    existing = session.exec(
        select(func.count(HttpExchange.id)).where(HttpExchange.run_id == run_id)
    ).one() or 0
    remaining = MAX_EXCHANGES_PER_RUN - int(existing)
    if remaining <= 0:
        return 0

    inserted = 0
    steps = steps or []
    for ex in parsed:
        if inserted >= remaining:
            break
        # Match each exchange to a step on the basis of started_at falling
        # within that step's run window. Tools that retry across step
        # boundaries can produce ambiguous attribution; first-match is fine.
        step_idx = _step_index_for_timestamp(steps, ex.started_at)
        tool_id = next((s.tool_id for s in steps if s.index == step_idx), None) if step_idx else None

        row = HttpExchange(
            run_id=run_id,
            workspace_id=workspace_id,
            step_index=step_idx,
            tool_id=tool_id,
            method=ex.method,
            url=ex.url,
            host=ex.host,
            request_headers=ex.request_headers,
            request_body=ex.request_body,
            request_body_truncated=ex.request_body_truncated,
            response_status=ex.response_status,
            response_headers=ex.response_headers,
            response_body=ex.response_body,
            response_body_truncated=ex.response_body_truncated,
            response_size_bytes=ex.response_size_bytes,
            duration_ms=ex.duration_ms,
            error=ex.error,
            started_at=ex.started_at,
        )
        session.add(row)
        inserted += 1
    session.flush()
    return inserted


# ---------- Lifecycle (live mode only) ---------------------------------------


@dataclass
class CaptureContext:
    proxy_url: str           # e.g. http://127.0.0.1:8443
    jsonl_path: Path         # proxify writes here
    proc: subprocess.Popen
    offset: int = 0          # bytes already parsed


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def proxify_available() -> bool:
    return shutil.which("proxify") is not None


def start_for_run(run_id: str, base_dir: Path) -> CaptureContext | None:
    """Start a proxify sidecar for this run. Returns None if proxify isn't on
    PATH — capture is best-effort, never fatal."""
    if not proxify_available():
        logger.info("[%s] proxify not on PATH; HTTP capture disabled", run_id)
        return None
    port = _free_port()
    capture_dir = base_dir / "runs" / run_id / "http_capture"
    capture_dir.mkdir(parents=True, exist_ok=True)
    jsonl = capture_dir / "exchanges.jsonl"
    jsonl.touch()

    cmd = [
        "proxify", "-silent",
        "-listen-addr", f"127.0.0.1:{port}",
        "-output-jsonl", str(jsonl),
    ]
    logger.info("[%s] starting proxify on 127.0.0.1:%d -> %s", run_id, port, jsonl)
    proc = subprocess.Popen(
        cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    # Tiny wait for proxify to bind. If it crashed (e.g. flag mismatch on a
    # weird version), we surface that on the first parse attempt and disable.
    time.sleep(0.3)
    if proc.poll() is not None:
        logger.warning("[%s] proxify exited immediately (rc=%s); capture disabled",
                       run_id, proc.returncode)
        return None
    return CaptureContext(
        proxy_url=f"http://127.0.0.1:{port}",
        jsonl_path=jsonl,
        proc=proc,
    )


def proxy_env(ctx: CaptureContext | None) -> dict[str, str]:
    """Env vars for tool subprocesses so they route HTTP through proxify."""
    if ctx is None:
        return {}
    return {
        "HTTP_PROXY": ctx.proxy_url,
        "HTTPS_PROXY": ctx.proxy_url,
        "http_proxy": ctx.proxy_url,
        "https_proxy": ctx.proxy_url,
    }


def drain(
    ctx: CaptureContext,
    session: Session,
    *,
    run_id: str,
    workspace_id: str,
    steps: list[RunStep],
) -> int:
    """Read new bytes from the JSONL since the last drain, parse + persist.
    Returns the number of new exchanges inserted."""
    if not ctx.jsonl_path.exists():
        return 0
    size = ctx.jsonl_path.stat().st_size
    if size <= ctx.offset:
        return 0
    with ctx.jsonl_path.open("r") as f:
        f.seek(ctx.offset)
        chunk = f.read(size - ctx.offset)
    ctx.offset = size
    parsed = parse_jsonl_chunk(chunk)
    if not parsed:
        return 0
    return persist_exchanges(
        session,
        run_id=run_id,
        workspace_id=workspace_id,
        parsed=parsed,
        steps=steps,
    )


async def stop(ctx: CaptureContext) -> None:
    """SIGTERM proxify, then SIGKILL if it doesn't respect that."""
    proc = ctx.proc
    if proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), 15)
        for _ in range(20):
            if proc.poll() is not None:
                return
            await asyncio.sleep(0.1)
    except ProcessLookupError:
        return
    with contextlib.suppress(Exception):
        os.killpg(os.getpgid(proc.pid), 9)
