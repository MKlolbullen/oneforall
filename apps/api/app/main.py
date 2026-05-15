import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import Session, select

from app.api.routes import (
    advisor as advisor_routes,
    agent as agent_routes,
    assets,
    auth as auth_routes,
    config,
    dashboard,
    loot as loot_routes,
    network as network_routes,
    runs,
    targets,
    tools,
    workspaces,
    ws,
)
from app.core.config import get_settings
from app.db import engine, init_db
from app.models import Target, Workspace
from app.services.auth import ensure_admin

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    seed_dev_data()
    seed_default_admin()
    yield


settings = get_settings()
app = FastAPI(title=settings.app_name, version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_routes.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")
app.include_router(config.router, prefix="/api")
app.include_router(workspaces.router, prefix="/api")
app.include_router(targets.router, prefix="/api")
app.include_router(tools.router, prefix="/api")
app.include_router(runs.router, prefix="/api")
app.include_router(assets.router, prefix="/api")
app.include_router(advisor_routes.router, prefix="/api")
app.include_router(agent_routes.router, prefix="/api")
app.include_router(loot_routes.router, prefix="/api")
app.include_router(network_routes.router, prefix="/api")
app.include_router(graph_routes.router, prefix="/api")
app.include_router(ws.router)


@app.get("/health")
def health():
    return {
        "status": "ok",
        "app": settings.app_name,
        "environment": settings.environment,
        "execution_mode": settings.execution_mode,
        "live_execution_enabled": settings.live_execution_enabled,
        "runner_mode": settings.runner_mode,
        "artifact_backend": settings.artifact_backend,
        "run_queue_name": settings.run_queue_name,
        "block_live_runs_on_missing_tools": settings.block_live_runs_on_missing_tools,
        "tool_availability_cache_seconds": settings.tool_availability_cache_seconds,
        "platform_config_path": str(settings.platform_config_path),
        "grep_patterns_path": str(settings.grep_patterns_path),
    }


def seed_dev_data() -> None:
    with Session(engine) as session:
        existing = session.exec(select(Workspace)).first()
        if existing:
            return
        ws = Workspace(name="Demo Workspace", description="Authorized lab/demo workspace")
        session.add(ws)
        session.commit()
        session.refresh(ws)
        target = Target(
            workspace_id=ws.id,
            value="example.com",
            type="domain",
            in_scope=True,
            passive_allowed=True,
            active_allowed=False,
            notes="Dry-run demo target. Enable active scans only with explicit authorization.",
        )
        session.add(target)
        session.commit()


def seed_default_admin() -> None:
    """Bootstrap an admin user from env so the first /api/auth/login works.

    Lab default — RECONFORGE_BOOTSTRAP_ADMIN_USERNAME/PASSWORD. If both are
    set, the user is created (or its password reset) every boot. Production
    deployments should set them once via secret manager and rotate via the
    /api/auth/users endpoint.
    """
    username = os.getenv("RECONFORGE_BOOTSTRAP_ADMIN_USERNAME")
    password = os.getenv("RECONFORGE_BOOTSTRAP_ADMIN_PASSWORD")
    if not username or not password:
        logger.info("RECONFORGE_BOOTSTRAP_ADMIN_* unset — no admin seeded; "
                    "use ensure_admin() in a one-shot script if needed.")
        return
    with Session(engine) as session:
        ensure_admin(session, username=username, password=password)
        logger.info("Admin user %r ensured via bootstrap env.", username)
