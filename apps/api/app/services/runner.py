from __future__ import annotations

import asyncio
import contextlib
import os
import shlex
import signal
import time
from typing import Any, Callable

from sqlmodel import Session, select

from app.core.config import get_settings
from app.models import Artifact, Run, RunStatus, RunStep, StepStatus, now_utc
from app.services.artifacts import ArtifactStore
from app.services.events import event_bus
from app.services.normalizer import normalize_tool_line
from app.services.queue import clear_run_cancel, is_run_cancel_requested
from app.services.tool_availability import check_tool_availability
from app.services.tool_registry import ToolRegistry

SessionFactory = Callable[[], Session]


class RunCancelled(RuntimeError):
    """Raised when the operator requested run cancellation."""


class StepTimedOut(RuntimeError):
    """Raised when a tool step exceeds its configured timeout."""


class StepExecutionFailed(RuntimeError):
    """Raised when a tool step fails after all retry attempts."""


def render_argv(template: list[str], params: dict[str, Any]) -> list[str]:
    argv: list[str] = []
    for token in template:
        rendered = token
        for key, value in params.items():
            rendered = rendered.replace("{{" + key + "}}", str(value))
        argv.append(rendered)
    return argv


def _coerce_int(value: Any, default: int, *, minimum: int = 0) -> int:
    try:
        coerced = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, coerced)


def _coerce_float(value: Any, default: float, *, minimum: float = 0.0) -> float:
    try:
        coerced = float(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, coerced)


def _step_policy(tool: Any, step_config: dict[str, Any]) -> dict[str, Any]:
    return {
        "timeout_seconds": _coerce_int(
            step_config.get("timeout_seconds"),
            int(getattr(tool, "default_timeout_seconds", 900)),
            minimum=1,
        ),
        "max_retries": _coerce_int(
            step_config.get("max_retries"),
            int(getattr(tool, "max_retries", 0)),
            minimum=0,
        ),
        "retry_backoff_seconds": _coerce_float(
            step_config.get("retry_backoff_seconds"),
            float(getattr(tool, "retry_backoff_seconds", 1.0)),
            minimum=0.0,
        ),
        "continue_on_error": bool(step_config.get("continue_on_error", getattr(tool, "continue_on_error", False))),
    }


def _refresh_run(session_factory: SessionFactory, run_id: str) -> Run | None:
    with session_factory() as session:
        return session.get(Run, run_id)


async def _cancel_requested(session_factory: SessionFactory, run_id: str) -> bool:
    if await is_run_cancel_requested(run_id):
        return True
    with session_factory() as session:
        run = session.get(Run, run_id)
        return bool(run and run.status == RunStatus.cancelled)


def _get_or_create_step(
    session: Session,
    *,
    run_id: str,
    workspace_id: str,
    index: int,
    tool_id: str,
    tool_name: str,
    policy: dict[str, Any],
) -> RunStep:
    step = session.exec(
        select(RunStep).where(RunStep.run_id == run_id, RunStep.index == index)
    ).first()
    if step:
        return step
    step = RunStep(
        run_id=run_id,
        workspace_id=workspace_id,
        index=index,
        tool_id=tool_id,
        tool_name=tool_name,
        timeout_seconds=policy["timeout_seconds"],
        max_retries=policy["max_retries"],
        continue_on_error=policy["continue_on_error"],
        meta={"retry_backoff_seconds": policy["retry_backoff_seconds"]},
    )
    session.add(step)
    session.commit()
    session.refresh(step)
    return step


def _update_step(
    session: Session,
    step_id: str,
    *,
    status: StepStatus | None = None,
    attempt: int | None = None,
    exit_code: int | None = None,
    error: str | None = None,
    started: bool = False,
    finished: bool = False,
    meta_patch: dict[str, Any] | None = None,
) -> RunStep | None:
    step = session.get(RunStep, step_id)
    if not step:
        return None
    if status is not None:
        step.status = status
    if attempt is not None:
        step.attempt = attempt
    if exit_code is not None:
        step.exit_code = exit_code
    if error is not None:
        step.error = error
    if started:
        step.started_at = now_utc()
        step.finished_at = None
        step.error = None
        step.exit_code = None
    if finished:
        step.finished_at = now_utc()
    if meta_patch:
        step.meta = {**(step.meta or {}), **meta_patch}
    session.add(step)
    session.commit()
    session.refresh(step)
    return step


async def execute_run(run_id: str, registry: ToolRegistry, session_factory: SessionFactory) -> None:
    settings = get_settings()

    with session_factory() as session:
        run = session.get(Run, run_id)
        if not run:
            return
        if run.status == RunStatus.cancelled or await is_run_cancel_requested(run_id):
            run.finished_at = now_utc()
            session.add(run)
            session.commit()
            await event_bus.publish(session, run.id, "run.cancelled", f"Run {run.id} was cancelled before start")
            return
        run.status = RunStatus.running
        run.started_at = now_utc()
        session.add(run)
        session.commit()
        workspace_id = run.workspace_id
        profile_id = run.profile_id
        config_snapshot = dict(run.config_snapshot or {})
        await event_bus.publish(
            session,
            run.id,
            "run.started",
            f"Run {run.id} started",
            payload={"runner_mode": settings.runner_mode, "execution_mode": settings.execution_mode},
        )

    try:
        profile = registry.get_profile(profile_id)
        params = dict(config_snapshot.get("params") or {})
        params.setdefault("target", config_snapshot.get("target_value"))

        for index, step_config in enumerate(profile.get("steps", []), start=1):
            if await _cancel_requested(session_factory, run_id):
                raise RunCancelled("operator requested cancellation")

            tool_id = step_config["tool"]
            tool = registry.get_tool(tool_id)
            policy = _step_policy(tool, step_config)

            with session_factory() as session:
                step = _get_or_create_step(
                    session,
                    run_id=run_id,
                    workspace_id=workspace_id,
                    index=index,
                    tool_id=tool_id,
                    tool_name=tool.name,
                    policy=policy,
                )
                step_id = step.id

            await _execute_step_with_retries(
                session_factory=session_factory,
                run_id=run_id,
                workspace_id=workspace_id,
                step_id=step_id,
                step_index=index,
                tool_id=tool_id,
                tool_name=tool.name,
                tool=tool,
                step_config=step_config,
                params=params,
                policy=policy,
            )

        with session_factory() as session:
            run = session.get(Run, run_id)
            if run:
                run.status = RunStatus.completed
                run.finished_at = now_utc()
                session.add(run)
                session.commit()
            await event_bus.publish(session, run_id, "run.completed", "Run completed")
            await clear_run_cancel(run_id)
    except RunCancelled as exc:
        with session_factory() as session:
            run = session.get(Run, run_id)
            if run:
                run.status = RunStatus.cancelled
                run.finished_at = now_utc()
                session.add(run)
                session.commit()
            await event_bus.publish(
                session,
                run_id,
                "run.cancelled",
                f"Run cancelled: {exc}",
                level="warning",
                payload={"error": str(exc)},
            )
    except Exception as exc:  # noqa: BLE001 - preserve crash reason in event stream
        with session_factory() as session:
            run = session.get(Run, run_id)
            if run and run.status != RunStatus.cancelled:
                run.status = RunStatus.failed
                run.finished_at = now_utc()
                session.add(run)
                session.commit()
            await event_bus.publish(
                session,
                run_id,
                "run.failed",
                f"Run failed: {exc}",
                level="error",
                payload={"error": repr(exc)},
            )


async def _execute_step_with_retries(
    *,
    session_factory: SessionFactory,
    run_id: str,
    workspace_id: str,
    step_id: str,
    step_index: int,
    tool_id: str,
    tool_name: str,
    tool: Any,
    step_config: dict[str, Any],
    params: dict[str, Any],
    policy: dict[str, Any],
) -> None:
    attempts_allowed = policy["max_retries"] + 1
    last_error: Exception | None = None

    for attempt in range(1, attempts_allowed + 1):
        if await _cancel_requested(session_factory, run_id):
            await _mark_step_cancelled(session_factory, run_id, step_id, tool_id, attempt, "cancelled before attempt")
            raise RunCancelled("operator requested cancellation")

        with session_factory() as session:
            _update_step(
                session,
                step_id,
                status=StepStatus.running,
                attempt=attempt,
                started=True,
                meta_patch={"step_config": step_config},
            )
            await event_bus.publish(
                session,
                run_id,
                "run.step.started",
                f"Starting {tool_name} (attempt {attempt}/{attempts_allowed})",
                payload={
                    "step_id": step_id,
                    "step_index": step_index,
                    "tool_id": tool_id,
                    "attempt": attempt,
                    "max_retries": policy["max_retries"],
                    "timeout_seconds": policy["timeout_seconds"],
                    "risk": str(tool.risk.value if hasattr(tool.risk, "value") else tool.risk),
                },
            )

        try:
            if get_settings().live_execution_enabled:
                availability = check_tool_availability(tool)
                if not availability.available:
                    raise RuntimeError(
                        f"{tool_id} is not runnable: {availability.status} - {availability.message}"
                    )
                argv_template = tool.command.get("argv", [])
                if not argv_template:
                    # Built-in/no-binary tools are allowed to emit deterministic structured output.
                    # External live tools must declare an argv template.
                    await _run_dry_tool(
                        session_factory,
                        run_id,
                        workspace_id,
                        tool_id,
                        tool.dry_run_output,
                        timeout_seconds=policy["timeout_seconds"],
                    )
                else:
                    argv = render_argv(argv_template, params)
                    await _run_live_tool(
                        session_factory,
                        run_id,
                        workspace_id,
                        tool_id,
                        argv,
                        timeout_seconds=policy["timeout_seconds"],
                    )
            else:
                await _run_dry_tool(
                    session_factory,
                    run_id,
                    workspace_id,
                    tool_id,
                    tool.dry_run_output,
                    timeout_seconds=policy["timeout_seconds"],
                )

            with session_factory() as session:
                _update_step(session, step_id, status=StepStatus.completed, exit_code=0, finished=True)
                await event_bus.publish(
                    session,
                    run_id,
                    "run.step.completed",
                    f"Completed {tool_name}",
                    payload={"step_id": step_id, "step_index": step_index, "tool_id": tool_id, "attempt": attempt},
                )
            return
        except RunCancelled:
            await _mark_step_cancelled(session_factory, run_id, step_id, tool_id, attempt, "operator requested cancellation")
            raise
        except StepTimedOut as exc:
            last_error = exc
            with session_factory() as session:
                _update_step(session, step_id, status=StepStatus.timed_out, error=str(exc), finished=True)
                await event_bus.publish(
                    session,
                    run_id,
                    "run.step.timed_out",
                    f"{tool_name} timed out after {policy['timeout_seconds']}s",
                    level="error",
                    payload={"step_id": step_id, "tool_id": tool_id, "attempt": attempt, "timeout_seconds": policy["timeout_seconds"]},
                )
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            with session_factory() as session:
                _update_step(session, step_id, status=StepStatus.failed, error=str(exc), finished=True)
                await event_bus.publish(
                    session,
                    run_id,
                    "run.step.failed",
                    f"{tool_name} failed: {exc}",
                    level="error",
                    payload={"step_id": step_id, "tool_id": tool_id, "attempt": attempt, "error": repr(exc)},
                )

        if attempt <= policy["max_retries"]:
            with session_factory() as session:
                _update_step(session, step_id, status=StepStatus.retrying)
                await event_bus.publish(
                    session,
                    run_id,
                    "run.step.retrying",
                    f"Retrying {tool_name} after {policy['retry_backoff_seconds']}s",
                    level="warning",
                    payload={"step_id": step_id, "tool_id": tool_id, "next_attempt": attempt + 1},
                )
            await asyncio.sleep(policy["retry_backoff_seconds"])
            continue

        if policy["continue_on_error"]:
            with session_factory() as session:
                await event_bus.publish(
                    session,
                    run_id,
                    "run.step.continued_after_error",
                    f"Continuing after failed optional step {tool_name}",
                    level="warning",
                    payload={"step_id": step_id, "tool_id": tool_id, "error": repr(last_error)},
                )
            return

        raise StepExecutionFailed(f"{tool_id} failed after {attempts_allowed} attempt(s): {last_error}")


async def _mark_step_cancelled(
    session_factory: SessionFactory,
    run_id: str,
    step_id: str,
    tool_id: str,
    attempt: int,
    reason: str,
) -> None:
    with session_factory() as session:
        _update_step(session, step_id, status=StepStatus.cancelled, attempt=attempt, error=reason, finished=True)
        await event_bus.publish(
            session,
            run_id,
            "run.step.cancelled",
            f"Step {tool_id} cancelled",
            level="warning",
            payload={"step_id": step_id, "tool_id": tool_id, "attempt": attempt, "reason": reason},
        )


async def _run_dry_tool(
    session_factory: SessionFactory,
    run_id: str,
    workspace_id: str,
    tool_id: str,
    lines: list[str],
    *,
    timeout_seconds: int,
) -> None:
    stdout_lines: list[str] = []
    started = time.monotonic()
    for line in lines:
        if await _cancel_requested(session_factory, run_id):
            raise RunCancelled("operator requested cancellation")
        if time.monotonic() - started > timeout_seconds:
            raise StepTimedOut(f"{tool_id} exceeded timeout of {timeout_seconds}s")
        await asyncio.sleep(0.25)
        stdout_lines.append(line)
        with session_factory() as session:
            await event_bus.publish(
                session,
                run_id,
                "run.step.output",
                line,
                payload={"tool_id": tool_id, "stream": "stdout"},
            )
            normalized = normalize_tool_line(
                session,
                workspace_id=workspace_id,
                run_id=run_id,
                tool_id=tool_id,
                line=line,
            )
            if normalized:
                await event_bus.publish(
                    session,
                    run_id,
                    "run.step.normalized",
                    f"Normalized {getattr(normalized, 'type', 'finding')}: {getattr(normalized, 'value', getattr(normalized, 'title', ''))}",
                    payload={"tool_id": tool_id, "entity_id": normalized.id},
                )

    await _write_artifact(
        session_factory,
        run_id,
        workspace_id,
        f"{tool_id}.stdout.txt",
        "\n".join(stdout_lines) + ("\n" if stdout_lines else ""),
    )


async def _run_live_tool(
    session_factory: SessionFactory,
    run_id: str,
    workspace_id: str,
    tool_id: str,
    argv: list[str],
    *,
    timeout_seconds: int,
) -> None:
    if not argv:
        raise RuntimeError(f"Tool {tool_id} has no argv template")

    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )

    stdout_lines: list[str] = []
    stderr_lines: list[str] = []

    async def consume_stream(stream: asyncio.StreamReader | None, stream_name: str, sink: list[str]) -> None:
        if stream is None:
            return
        async for raw in stream:
            line = raw.decode(errors="replace").rstrip("\n")
            sink.append(line)
            with session_factory() as session:
                await event_bus.publish(
                    session,
                    run_id,
                    "run.step.output",
                    line,
                    level="error" if stream_name == "stderr" else "info",
                    payload={"tool_id": tool_id, "stream": stream_name, "argv": shlex.join(argv)},
                )
                if stream_name == "stdout":
                    normalized = normalize_tool_line(
                        session,
                        workspace_id=workspace_id,
                        run_id=run_id,
                        tool_id=tool_id,
                        line=line,
                    )
                    if normalized:
                        await event_bus.publish(
                            session,
                            run_id,
                            "run.step.normalized",
                            f"Normalized {getattr(normalized, 'type', 'finding')}: {getattr(normalized, 'value', getattr(normalized, 'title', ''))}",
                            payload={"tool_id": tool_id, "entity_id": normalized.id},
                        )

    async def wait_for_cancel() -> None:
        while proc.returncode is None:
            if await _cancel_requested(session_factory, run_id):
                raise RunCancelled("operator requested cancellation")
            await asyncio.sleep(0.5)

    stdout_task = asyncio.create_task(consume_stream(proc.stdout, "stdout", stdout_lines))
    stderr_task = asyncio.create_task(consume_stream(proc.stderr, "stderr", stderr_lines))
    proc_task = asyncio.create_task(proc.wait())
    cancel_task = asyncio.create_task(wait_for_cancel())

    reason: Exception | None = None
    try:
        done, pending = await asyncio.wait(
            {proc_task, cancel_task},
            timeout=timeout_seconds,
            return_when=asyncio.FIRST_COMPLETED,
        )
        if not done:
            reason = StepTimedOut(f"{tool_id} exceeded timeout of {timeout_seconds}s")
            await _terminate_process_tree(proc)
        else:
            if cancel_task in done:
                exc = cancel_task.exception()
                if exc:
                    reason = exc
                    await _terminate_process_tree(proc)
            if reason is None:
                if not proc_task.done():
                    await proc_task
                code = proc_task.result()
                if code != 0:
                    reason = RuntimeError(f"{tool_id} exited with status {code}")
    finally:
        for task in (proc_task, cancel_task):
            if not task.done():
                task.cancel()
        await asyncio.gather(proc_task, cancel_task, return_exceptions=True)
        await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)

    await _write_artifact(
        session_factory,
        run_id,
        workspace_id,
        f"{tool_id}.stdout.txt",
        "\n".join(stdout_lines) + ("\n" if stdout_lines else ""),
    )
    if stderr_lines:
        await _write_artifact(
            session_factory,
            run_id,
            workspace_id,
            f"{tool_id}.stderr.txt",
            "\n".join(stderr_lines) + "\n",
        )

    if reason:
        raise reason


async def _terminate_process_tree(proc: asyncio.subprocess.Process) -> None:
    if proc.returncode is not None:
        return
    try:
        if proc.pid:
            os.killpg(proc.pid, signal.SIGTERM)
        else:
            proc.terminate()
        await asyncio.wait_for(proc.wait(), timeout=5)
    except Exception:  # noqa: BLE001
        with contextlib.suppress(Exception):
            if proc.pid:
                os.killpg(proc.pid, signal.SIGKILL)
            else:
                proc.kill()
        with contextlib.suppress(Exception):
            await proc.wait()


async def _write_artifact(
    session_factory: SessionFactory,
    run_id: str,
    workspace_id: str,
    name: str,
    content: str,
) -> None:
    stored = ArtifactStore().put_text(run_id=run_id, name=name, content=content)
    with session_factory() as session:
        artifact = Artifact(
            workspace_id=workspace_id,
            run_id=run_id,
            name=stored.name,
            type=stored.type,
            path=stored.path,
            size_bytes=stored.size_bytes,
            sha256=stored.sha256,
            storage_backend=stored.storage_backend,
            bucket=stored.bucket,
            object_key=stored.object_key,
            content_type=stored.content_type,
        )
        session.add(artifact)
        session.commit()
        session.refresh(artifact)
        await event_bus.publish(
            session,
            run_id,
            "run.step.artifact_created",
            f"Artifact created: {stored.name}",
            payload={
                "artifact_id": artifact.id,
                "name": stored.name,
                "sha256": stored.sha256,
                "storage_backend": stored.storage_backend,
                "path": stored.path,
            },
        )
