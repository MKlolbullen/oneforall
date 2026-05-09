from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from sqlalchemy import Column, JSON
from sqlmodel import Field, SQLModel


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:16]}"


class RunStatus(str, Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class StepStatus(str, Enum):
    queued = "queued"
    running = "running"
    retrying = "retrying"
    completed = "completed"
    failed = "failed"
    timed_out = "timed_out"
    cancelled = "cancelled"


class RiskLevel(str, Enum):
    passive = "passive"
    low_active = "low_active"
    medium_active = "medium_active"
    high_active = "high_active"


class Workspace(SQLModel, table=True):
    id: str = Field(default_factory=lambda: new_id("ws"), primary_key=True)
    name: str = Field(index=True, min_length=1, max_length=120)
    description: str | None = None
    created_at: datetime = Field(default_factory=now_utc)


class Target(SQLModel, table=True):
    id: str = Field(default_factory=lambda: new_id("tgt"), primary_key=True)
    workspace_id: str = Field(index=True, foreign_key="workspace.id")
    value: str = Field(index=True, min_length=1, max_length=255)
    type: str = Field(default="domain", index=True)
    in_scope: bool = True
    passive_allowed: bool = True
    active_allowed: bool = False
    notes: str | None = None
    created_at: datetime = Field(default_factory=now_utc)


class Asset(SQLModel, table=True):
    id: str = Field(default_factory=lambda: new_id("asset"), primary_key=True)
    workspace_id: str = Field(index=True, foreign_key="workspace.id")
    run_id: str | None = Field(default=None, index=True, foreign_key="run.id")
    type: str = Field(index=True)
    value: str = Field(index=True)
    source: str = Field(default="unknown", index=True)
    confidence: float = 0.8
    meta: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    first_seen: datetime = Field(default_factory=now_utc)
    last_seen: datetime = Field(default_factory=now_utc)


class Finding(SQLModel, table=True):
    id: str = Field(default_factory=lambda: new_id("finding"), primary_key=True)
    workspace_id: str = Field(index=True, foreign_key="workspace.id")
    run_id: str | None = Field(default=None, index=True, foreign_key="run.id")
    asset_id: str | None = Field(default=None, index=True, foreign_key="asset.id")
    title: str = Field(index=True)
    severity: str = Field(default="info", index=True)
    confidence: str = Field(default="medium")
    category: str = Field(default="informational", index=True)
    status: str = Field(default="new", index=True)
    evidence: str | None = None
    tool_source: str | None = None
    meta: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=now_utc)
    updated_at: datetime = Field(default_factory=now_utc)


class Run(SQLModel, table=True):
    id: str = Field(default_factory=lambda: new_id("run"), primary_key=True)
    workspace_id: str = Field(index=True, foreign_key="workspace.id")
    target_id: str = Field(index=True, foreign_key="target.id")
    profile_id: str = Field(index=True)
    status: RunStatus = Field(default=RunStatus.queued, index=True)
    risk: RiskLevel = Field(default=RiskLevel.passive, index=True)
    requested_by: str = Field(default="local-dev")
    config_snapshot: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime = Field(default_factory=now_utc)


class RunStep(SQLModel, table=True):
    id: str = Field(default_factory=lambda: new_id("step"), primary_key=True)
    run_id: str = Field(index=True, foreign_key="run.id")
    workspace_id: str = Field(index=True, foreign_key="workspace.id")
    tool_id: str = Field(index=True)
    tool_name: str
    index: int = Field(index=True)
    status: StepStatus = Field(default=StepStatus.queued, index=True)
    attempt: int = Field(default=0)
    max_retries: int = Field(default=0)
    timeout_seconds: int = Field(default=900)
    continue_on_error: bool = False
    exit_code: int | None = None
    error: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    meta: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=now_utc)


class RunEvent(SQLModel, table=True):
    id: str = Field(default_factory=lambda: new_id("evt"), primary_key=True)
    run_id: str = Field(index=True, foreign_key="run.id")
    sequence: int = Field(index=True)
    type: str = Field(index=True)
    level: str = Field(default="info", index=True)
    message: str
    payload: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=now_utc)


class Artifact(SQLModel, table=True):
    id: str = Field(default_factory=lambda: new_id("art"), primary_key=True)
    workspace_id: str = Field(index=True, foreign_key="workspace.id")
    run_id: str = Field(index=True, foreign_key="run.id")
    name: str
    type: str = Field(default="text", index=True)
    path: str
    size_bytes: int = 0
    sha256: str | None = None
    storage_backend: str = Field(default="local", index=True)
    bucket: str | None = None
    object_key: str | None = None
    content_type: str = "application/octet-stream"
    meta: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=now_utc)
