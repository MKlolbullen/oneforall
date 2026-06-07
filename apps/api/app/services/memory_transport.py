"""In-process transport for the live-event bus and the run queue.

When ``runner_mode=embedded`` (a packaged desktop build, or anyone who just
doesn't want a Redis dependency), the API and the runner share one process and
one asyncio loop. That makes Redis unnecessary: events can be fanned out
through in-memory queues and jobs handed off through an ``asyncio.Queue``.

These primitives are deliberately tiny and loop-agnostic — ``asyncio.Queue``
binds to the running loop on first use (Python 3.10+), so module-level
singletons are safe as long as first use happens inside a running loop.
"""
from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Any, AsyncIterator


class MemoryBroker:
    """Process-local pub/sub. Each subscriber gets its own bounded queue so a
    slow consumer can't block the publisher or other subscribers."""

    def __init__(self, *, maxsize: int = 1000) -> None:
        self._subscribers: dict[str, set[asyncio.Queue[dict[str, Any]]]] = defaultdict(set)
        self._maxsize = maxsize

    async def publish(self, channel: str, body: dict[str, Any]) -> None:
        for queue in list(self._subscribers.get(channel, ())):
            try:
                queue.put_nowait(body)
            except asyncio.QueueFull:
                # Drop on overflow rather than wedge the run. The DB remains the
                # source of truth; a reconnecting client replays history.
                pass

    async def subscribe(self, channel: str) -> AsyncIterator[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=self._maxsize)
        self._subscribers[channel].add(queue)
        try:
            while True:
                yield await queue.get()
        finally:
            self._subscribers[channel].discard(queue)
            if not self._subscribers[channel]:
                self._subscribers.pop(channel, None)

    def subscriber_count(self, channel: str) -> int:
        return len(self._subscribers.get(channel, ()))


class MemoryRunQueue:
    """FIFO job queue + cancellation registry for the embedded worker.

    The underlying ``asyncio.Queue`` binds to the loop that first touches it.
    A long-lived process has exactly one loop, but tests (and some servers)
    create fresh loops, so we rebind lazily if the running loop changes rather
    than raising "bound to a different event loop"."""

    def __init__(self) -> None:
        self._queue: asyncio.Queue[dict[str, Any]] | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._cancelled: set[str] = set()

    def _ensure_queue(self) -> asyncio.Queue[dict[str, Any]]:
        loop = asyncio.get_running_loop()
        if self._queue is None or self._loop is not loop:
            self._queue = asyncio.Queue()
            self._loop = loop
        return self._queue

    async def put(self, job: dict[str, Any]) -> None:
        # A fresh enqueue clears any stale cancel flag for that run id.
        self._cancelled.discard(str(job.get("run_id")))
        await self._ensure_queue().put(job)

    async def get(self, *, timeout_seconds: float) -> dict[str, Any] | None:
        try:
            return await asyncio.wait_for(self._ensure_queue().get(), timeout=timeout_seconds)
        except asyncio.TimeoutError:
            return None

    def request_cancel(self, run_id: str) -> None:
        self._cancelled.add(run_id)

    def is_cancel_requested(self, run_id: str) -> bool:
        return run_id in self._cancelled

    def clear_cancel(self, run_id: str) -> None:
        self._cancelled.discard(run_id)


# Module-level singletons shared by the event bus, the queue helpers, and the
# embedded worker. One process, one loop, one of each.
broker = MemoryBroker()
run_queue = MemoryRunQueue()
