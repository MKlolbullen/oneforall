from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from app.core.config import get_settings
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


def _cancel_key(run_id: str) -> str:
    return f"reconforge:runs:{run_id}:cancel"


async def enqueue_run(run_id: str, *, attempt: int = 1) -> None:
    settings = get_settings()
    job = RunJob(
        run_id=run_id,
        requested_at=datetime.now(timezone.utc).isoformat(),
        attempt=attempt,
    )
    await get_redis().delete(_cancel_key(run_id))
    await get_redis().rpush(settings.run_queue_name, job.as_json())


async def dequeue_run(*, timeout_seconds: int = 5) -> dict[str, Any] | None:
    settings = get_settings()
    result = await get_redis().blpop(settings.run_queue_name, timeout=timeout_seconds)
    if not result:
        return None
    _, raw = result
    return json.loads(raw)


async def request_run_cancel(run_id: str, *, ttl_seconds: int = 86400) -> None:
    await get_redis().set(_cancel_key(run_id), "1", ex=ttl_seconds)


async def is_run_cancel_requested(run_id: str) -> bool:
    try:
        return bool(await get_redis().exists(_cancel_key(run_id)))
    except Exception:  # noqa: BLE001 - DB status remains the fallback if Redis is unavailable
        return False


async def clear_run_cancel(run_id: str) -> None:
    try:
        await get_redis().delete(_cancel_key(run_id))
    except Exception:  # noqa: BLE001
        return
