from __future__ import annotations

import asyncio
import logging
import os
import signal
from contextlib import suppress

from sqlmodel import Session

from app.db import engine, init_db
from app.services.queue import dequeue_run
from app.services.runner import execute_run
from app.services.tool_registry import get_registry

logger = logging.getLogger(__name__)

_shutdown = asyncio.Event()


def session_factory() -> Session:
    return Session(engine)


def _request_shutdown(*_: object) -> None:
    _shutdown.set()


async def drain_queue(stop: asyncio.Event, *, label: str = "runner-1") -> None:
    """Consume run jobs until ``stop`` is set.

    Shared by the standalone worker process (queue mode) and the in-process
    embedded worker started from the API lifespan. A failure executing one run
    is logged and swallowed so the loop survives to drain the next job.
    """
    registry = get_registry()
    logger.info("[worker:%s] online", label)
    while not stop.is_set():
        job = await dequeue_run(timeout_seconds=3)
        if not job:
            continue
        run_id = job.get("run_id")
        if not run_id:
            logger.warning("[worker:%s] invalid job: %r", label, job)
            continue
        logger.info("[worker:%s] executing %s", label, run_id)
        try:
            await execute_run(run_id, registry, session_factory)
        except Exception:  # noqa: BLE001 - one bad run must not kill the worker loop
            logger.exception("[worker:%s] run %s crashed", label, run_id)
    logger.info("[worker:%s] shutdown complete", label)


async def worker_loop() -> None:
    init_db()
    await drain_queue(_shutdown, label=os.getenv("WORKER_NAME", "runner-1"))


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    for sig in (signal.SIGINT, signal.SIGTERM):
        with suppress(NotImplementedError):
            loop.add_signal_handler(sig, _request_shutdown)
    loop.run_until_complete(worker_loop())


if __name__ == "__main__":
    main()
