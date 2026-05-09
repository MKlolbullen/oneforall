import logging
import os
from collections.abc import Generator
from pathlib import Path

from sqlmodel import SQLModel, Session, create_engine

from app.core.config import get_settings

logger = logging.getLogger(__name__)

settings = get_settings()
connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, echo=False, connect_args=connect_args, pool_pre_ping=True)


def _alembic_config() -> "alembic.config.Config":  # noqa: F821 - lazy import
    from alembic.config import Config
    here = Path(__file__).resolve().parent.parent  # apps/api
    cfg = Config(str(here / "alembic.ini"))
    cfg.set_main_option("script_location", str(here / "alembic"))
    # Resolve fresh each call so test fixtures that mutate DATABASE_URL after
    # this module was imported still take effect.
    cfg.set_main_option("sqlalchemy.url", get_settings().database_url)
    return cfg


def init_db() -> None:
    """Bring the schema up to head.

    Default: run alembic migrations. Set RECONFORGE_SKIP_MIGRATIONS=1 to fall
    back to SQLModel.metadata.create_all() — only useful in throwaway tests
    where no migration history exists.
    """
    if os.getenv("RECONFORGE_SKIP_MIGRATIONS"):
        logger.warning("RECONFORGE_SKIP_MIGRATIONS=1 -- creating schema via metadata, no version recorded")
        SQLModel.metadata.create_all(engine)
        return
    try:
        from alembic import command
        command.upgrade(_alembic_config(), "head")
    except Exception as exc:  # noqa: BLE001 - alembic should never block a dev container from booting
        logger.error("alembic upgrade head failed (%s); falling back to metadata.create_all", exc)
        SQLModel.metadata.create_all(engine)


def get_session() -> Generator[Session, None, None]:
    with Session(engine) as session:
        yield session
