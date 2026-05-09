from __future__ import annotations

import asyncio
import os
import signal
from contextlib import suppress

from sqlmodel import Session

from app.db import engine, init_db
from app.services.queue import dequeue_run
from app.services.runner import execute_run
from app.services.tool_registry import get_registry

_shutdown = asyncio.Event()


def session_factory() -> Session:
    return Session(engine)


def _request_shutdown(*_: object) -> None:
    _shutdown.set()


async def worker_loop() -> None:
    init_db()
    registry = get_registry()
    worker_name = os.getenv("WORKER_NAME", "runner-1")
    print(f"[worker:{worker_name}] online")

    while not _shutdown.is_set():
        job = await dequeue_run(timeout_seconds=3)
        if not job:
            continue
        run_id = job.get("run_id")
        if not run_id:
            print(f"[worker:{worker_name}] invalid job: {job!r}")
            continue
        print(f"[worker:{worker_name}] executing {run_id}")
        await execute_run(run_id, registry, session_factory)

    print(f"[worker:{worker_name}] shutdown complete")


def main() -> None:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    for sig in (signal.SIGINT, signal.SIGTERM):
        with suppress(NotImplementedError):
            loop.add_signal_handler(sig, _request_shutdown)
    loop.run_until_complete(worker_loop())


if __name__ == "__main__":
    main()
