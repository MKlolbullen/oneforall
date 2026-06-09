from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from app.core.config import get_settings
from app.services.memory_transport import run_queue
from app.services.redis_client import get_redis


@dataclass(frozen=True)
class RunJob:
    run_id: str
    requested_at: str
    attempt: int = 1

    def as_json(self) -> str:
        return json.dumps(
            {"run_id": self.run_id, "requested_at": self.requested_at, "attempt": self.attempt},
            separators=(",", ":"),
        )

    def as_dict(self) -> dict[str, Any]:
        return {"run_id": self.run_id, "requested_at": self.requested_at, "attempt": self.attempt}


def _use_memory() -> bool:
    return get_settings().resolved_queue_backend == "memory"


def _cancel_key(run_id: str) -> str:
    return f"reconforge:runs:{run_id}:cancel"


async def enqueue_run(run_id: str, *, attempt: int = 1) -> None:
    job = RunJob(
        run_id=run_id,
        requested_at=datetime.now(timezone.utc).isoformat(),
        attempt=attempt,
    )
    if _use_memory():
        await run_queue.put(job.as_dict())
        return
    settings = get_settings()
    await get_redis().delete(_cancel_key(run_id))
    await get_redis().rpush(settings.run_queue_name, job.as_json())


async def dequeue_run(*, timeout_seconds: int = 5) -> dict[str, Any] | None:
    if _use_memory():
        return await run_queue.get(timeout_seconds=timeout_seconds)
    settings = get_settings()
    result = await get_redis().blpop(settings.run_queue_name, timeout=timeout_seconds)
    if not result:
        return None
    _, raw = result
    return json.loads(raw)


async def request_run_cancel(run_id: str, *, ttl_seconds: int = 86400) -> None:
    if _use_memory():
        run_queue.request_cancel(run_id)
        return
    try:
        await get_redis().set(_cancel_key(run_id), "1", ex=ttl_seconds)
    except Exception:  # noqa: BLE001 - the DB cancel flag is the durable signal; Redis is a fast-path
        return


async def is_run_cancel_requested(run_id: str) -> bool:
    if _use_memory():
        return run_queue.is_cancel_requested(run_id)
    try:
        return bool(await get_redis().exists(_cancel_key(run_id)))
    except Exception:  # noqa: BLE001 - DB status remains the fallback if Redis is unavailable
        return False


async def clear_run_cancel(run_id: str) -> None:
    if _use_memory():
        run_queue.clear_cancel(run_id)
        return
    try:
        await get_redis().delete(_cancel_key(run_id))
    except Exception:  # noqa: BLE001
        return
