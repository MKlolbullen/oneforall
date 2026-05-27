"""Validate that alembic migrations bring an empty DB up to a working schema
matching SQLModel metadata, and that init_db() runs them transparently."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect

REPO = Path(__file__).resolve().parents[1]
API_DIR = REPO / "apps" / "api"
sys.path.insert(0, str(API_DIR))


def _alembic_cfg(db_url: str):
    from alembic.config import Config
    cfg = Config(str(API_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(API_DIR / "alembic"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


def test_alembic_upgrade_head_creates_expected_tables(tmp_path):
    db_path = tmp_path / "alembic.db"
    db_url = f"sqlite:///{db_path}"
    from alembic import command
    command.upgrade(_alembic_cfg(db_url), "head")

    eng = create_engine(db_url)
    tables = set(inspect(eng).get_table_names())
    expected = {
        "workspace", "target", "run", "runevent", "runstep",
        "asset", "finding", "artifact", "lootitem", "alembic_version",
    }
    missing = expected - tables
    assert not missing, f"missing tables after upgrade head: {missing}"


def test_alembic_downgrade_to_base_drops_tables(tmp_path):
    db_path = tmp_path / "alembic.db"
    db_url = f"sqlite:///{db_path}"
    from alembic import command
    command.upgrade(_alembic_cfg(db_url), "head")
    command.downgrade(_alembic_cfg(db_url), "base")

    eng = create_engine(db_url)
    tables = set(inspect(eng).get_table_names())
    # Only alembic_version should remain (alembic itself keeps that table).
    assert tables - {"alembic_version"} == set(), \
        f"downgrade to base left non-alembic tables: {tables}"


def test_init_db_runs_migrations(tmp_path, monkeypatch):
    """init_db() should pick up DATABASE_URL via settings and apply migrations."""
    db_path = tmp_path / "init.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.delenv("RECONFORGE_SKIP_MIGRATIONS", raising=False)

    # Force a fresh settings object + a fresh engine bound to the new URL.
    from app.core.config import get_settings
    get_settings.cache_clear()
    import importlib
    import app.db as db_mod
    importlib.reload(db_mod)
    db_mod.init_db()

    eng = create_engine(f"sqlite:///{db_path}")
    tables = set(inspect(eng).get_table_names())
    assert {"workspace", "target", "run", "alembic_version"}.issubset(tables)
