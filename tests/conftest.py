"""Shared test plumbing.

Every test that boots the FastAPI app needs the engine bound to its own DB
file. Without this, an earlier test leaves `app.db.engine` pointing at a
torn-down SQLite path and subsequent tests fall over with `no such table: …`.

We can't pre-bind the engine because tests choose their own DATABASE_URL via
monkeypatch. Instead we provide an explicit helper that test fixtures call
once they've set DATABASE_URL.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "apps" / "api"))


def rebind_engine_to_database_url() -> None:
    """Patch every module-level `engine` reference so the lifespan hits the
    test's DB and any module that did `from app.db import engine` sees the new
    one."""
    from app.core.config import get_settings
    get_settings.cache_clear()
    settings = get_settings()
    from sqlmodel import create_engine
    new_engine = create_engine(
        settings.database_url,
        echo=False,
        connect_args={"check_same_thread": False} if settings.database_url.startswith("sqlite") else {},
    )
    import app.db as db_mod
    db_mod.engine = new_engine
    import app.main as main_mod
    main_mod.engine = new_engine
    import app.api.routes.runs as runs_mod
    runs_mod.engine = new_engine
    # Newer routes that bind the engine at import time (workflows launches
    # spawn execute_run with their own session_factory). Same trick.
    import app.api.routes.workflows as workflows_mod
    workflows_mod.engine = new_engine
    # The embedded worker (RUNNER_MODE=embedded) runs execute_run with its own
    # session_factory built from worker.engine, captured at import. Rebind it too
    # or the in-loop worker reads the wrong DB ("no such table: run").
    import app.worker as worker_mod
    worker_mod.engine = new_engine
    # The WebSocket route opens its own Session(engine) to replay event history.
    # Without rebinding, a second test's socket queries the first test's DB,
    # finds no history, sends nothing, and the client blocks forever.
    import app.api.routes.ws as ws_mod
    ws_mod.engine = new_engine
