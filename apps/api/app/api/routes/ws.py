from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlmodel import Session

from app.db import engine
from app.services.events import event_bus

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/runs/{run_id}")
async def run_socket(websocket: WebSocket, run_id: str):
    await websocket.accept()
    sent_ids: set[str] = set()

    # Send persisted history first so the UI can attach to a run after it has started
    # or even after it has completed. Redis is only live transport; Postgres is truth.
    with Session(engine) as session:
        for event in event_bus.history(session, run_id):
            body = event_bus._event_to_body(event)  # small internal conversion helper
            sent_ids.add(body["id"])
            await websocket.send_json(body)

    try:
        async for event in event_bus.subscribe(run_id):
            if event.get("id") in sent_ids:
                continue
            sent_ids.add(event.get("id"))
            await websocket.send_json(event)
    except WebSocketDisconnect:
        return
