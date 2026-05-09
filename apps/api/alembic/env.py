"""Alembic environment.

Wires the autogenerate metadata to SQLModel + uses DATABASE_URL from settings
so the same migrations work for the SQLite dev DB and production Postgres.
"""
from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool
from sqlmodel import SQLModel

# Importing app.models registers every table on SQLModel.metadata.
import app.models  # noqa: F401  (side-effect import)
from app.core.config import get_settings

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# URL precedence:
#   1. Whatever the caller already set on the alembic Config (programmatic use).
#   2. DATABASE_URL env var (docker-compose, CI).
#   3. Settings default (sqlite dev DB).
existing = config.get_main_option("sqlalchemy.url") or ""
default_url = "sqlite:///./reconforge.db"
if not existing or existing == default_url:
    config.set_main_option(
        "sqlalchemy.url",
        os.getenv("DATABASE_URL") or get_settings().database_url,
    )

target_metadata = SQLModel.metadata


def run_migrations_offline() -> None:
    """Run migrations without an engine — useful for SQL-script generation."""
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,  # SQLite-friendly ALTER TABLE handling
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=connection.dialect.name == "sqlite",
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
