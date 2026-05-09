from __future__ import annotations

import asyncio
import json
from collections import defaultdict
from typing import Any, AsyncIterator

from sqlalchemy import func
from sqlmodel import Session, select

from app.core.config import get_settings
from app.models import RunEvent
from app.services.redis_client import get_redis


class RunEventBus:
    """Persist run events and fan them out over Redis Pub/Sub.

    The first scaffold used process-local subscribers. That breaks as soon as the
    runner becomes a separate worker container. This bus keeps the database as
    source of truth and uses Redis only for live delivery.
    """

    def __init__(self) -> None:
        self._fallback_subscribers: dict[str, set[asyncio.Queue[dict[str, Any]]]] = defaultdict(set)

    def next_sequence(self, session: Session, run_id: str) -> int:
        last = session.exec(
            select(func.max(RunEvent.sequence)).where(RunEvent.run_id == run_id)
        ).one()
        return int(last or 0) + 1

    async def publish(
        self,
        session: Session,
        run_id: str,
        type_: str,
        message: str,
        *,
        level: str = "info",
        payload: dict[str, Any] | None = None,
    ) -> RunEvent:
        event = RunEvent(
            run_id=run_id,
            sequence=self.next_sequence(session, run_id),
            type=type_,
            level=level,
            message=message,
            payload=payload or {},
        )
        session.add(event)
        session.commit()
        session.refresh(event)

        body = self._event_to_body(event)
        raw = json.dumps(body, separators=(",", ":"), default=str)
        settings = get_settings()

        try:
            await get_redis().publish(settings.run_event_channel(run_id), raw)
        except Exception:  # noqa: BLE001 - Redis may be absent in local one-process dev mode
            for queue in list(self._fallback_subscribers[run_id]):
                await queue.put(body)

        return event

    async def subscribe(self, run_id: str) -> AsyncIterator[dict[str, Any]]:
        settings = get_settings()
        channel = settings.run_event_channel(run_id)
        try:
            pubsub = get_redis().pubsub()
            await pubsub.subscribe(channel)
            try:
                async for message in pubsub.listen():
                    if message.get("type") != "message":
                        continue
                    yield json.loads(message["data"])
            finally:
                await pubsub.unsubscribe(channel)
                await pubsub.close()
        except Exception:  # noqa: BLE001 - fallback keeps no-Redis local debugging usable
            queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=200)
            self._fallback_subscribers[run_id].add(queue)
            try:
                while True:
                    yield await queue.get()
            finally:
                self._fallback_subscribers[run_id].discard(queue)

    def history(self, session: Session, run_id: str) -> list[RunEvent]:
        return list(
            session.exec(
                select(RunEvent).where(RunEvent.run_id == run_id).order_by(RunEvent.sequence)
            ).all()
        )

    @staticmethod
    def _event_to_body(event: RunEvent) -> dict[str, Any]:
        return {
            "id": event.id,
            "run_id": event.run_id,
            "sequence": event.sequence,
            "type": event.type,
            "level": event.level,
            "message": event.message,
            "payload": event.payload,
            "created_at": event.created_at.isoformat(),
        }


event_bus = RunEventBus()
