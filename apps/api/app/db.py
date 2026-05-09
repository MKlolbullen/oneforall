from collections.abc import Generator
from sqlmodel import SQLModel, Session, create_engine
from app.core.config import get_settings

settings = get_settings()
connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, echo=False, connect_args=connect_args, pool_pre_ping=True)


def init_db() -> None:
    # For v1 starter: create tables directly. Replace with Alembic migrations before production.
    SQLModel.metadata.create_all(engine)


def get_session() -> Generator[Session, None, None]:
    with Session(engine) as session:
        yield session
