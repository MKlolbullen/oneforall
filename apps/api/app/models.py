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


class Role(str, Enum):
    """Coarse-grained roles. Permissions are tested against role hierarchy."""
    viewer = "viewer"           # read-only on workspaces, runs, artifacts
    operator = "operator"       # may create targets and queue runs
    admin = "admin"             # may manage users, api keys, scope


ROLE_RANK = {Role.viewer: 0, Role.operator: 1, Role.admin: 2}


class User(SQLModel, table=True):
    id: str = Field(default_factory=lambda: new_id("user"), primary_key=True)
    username: str = Field(index=True, unique=True, min_length=1, max_length=120)
    password_hash: str  # PBKDF2 (salt + hash); see app.services.auth
    role: Role = Field(default=Role.viewer, index=True)
    is_active: bool = Field(default=True, index=True)
    created_at: datetime = Field(default_factory=now_utc)
    last_login_at: datetime | None = None


class APIKey(SQLModel, table=True):
    """A long-lived bearer token tied to a user.

    Only the prefix + sha256 of the token are stored; the plaintext is shown
    once at creation and never persisted.
    """
    id: str = Field(default_factory=lambda: new_id("ak"), primary_key=True)
    user_id: str = Field(index=True, foreign_key="user.id")
    name: str = Field(min_length=1, max_length=120)
    prefix: str = Field(index=True, max_length=12)
    token_sha256: str = Field(index=True, unique=True, max_length=64)
    created_at: datetime = Field(default_factory=now_utc)
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None


class HttpExchange(SQLModel, table=True):
    """One captured HTTP exchange — the proxify JSONL line for a single
    request/response pair. Bodies are capped at MAX_BODY_BYTES (64KB) and
    flagged truncated; stash the full body separately if the use case ever
    demands it.

    `step_index` is the run-step that was running when the exchange was
    observed, derived from timestamp at parse time. It can be None if the
    exchange landed before any step started or after the last step finished.
    """
    id: str = Field(default_factory=lambda: new_id("ex"), primary_key=True)
    run_id: str = Field(index=True, foreign_key="run.id")
    workspace_id: str = Field(index=True, foreign_key="workspace.id")
    step_index: int | None = Field(default=None, index=True)
    tool_id: str | None = Field(default=None, index=True, max_length=64)
    method: str = Field(index=True, max_length=10)
    url: str = Field(max_length=2048)
    host: str = Field(index=True, max_length=255)
    request_headers: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    request_body: str = ""
    request_body_truncated: bool = False
    response_status: int | None = Field(default=None, index=True)
    response_headers: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    response_body: str = ""
    response_body_truncated: bool = False
    response_size_bytes: int | None = None
    duration_ms: int | None = None
    error: str | None = None
    started_at: datetime = Field(default_factory=now_utc, index=True)


class LootItem(SQLModel, table=True):
    """High-signal recon output: secrets, credentials, tokens, paths, payloads.

    Loot is derived from Findings and tool output — not a second copy of every
    scanner line. Operators and agents use it as the curated 'what to steal
    attention' layer; raw evidence stays on the Finding / Artifact.
    """
    id: str = Field(default_factory=lambda: new_id("loot"), primary_key=True)
    workspace_id: str = Field(index=True, foreign_key="workspace.id")
    run_id: str | None = Field(default=None, index=True, foreign_key="run.id")
    finding_id: str | None = Field(default=None, index=True, foreign_key="finding.id")
    artifact_id: str | None = Field(default=None, index=True, foreign_key="artifact.id")
    kind: str = Field(index=True, max_length=32)
    label: str = Field(index=True, max_length=255)
    value_preview: str = Field(default="", max_length=512)
    severity: str = Field(default="info", index=True)
    source_tool: str | None = Field(default=None, index=True, max_length=64)
    host: str | None = Field(default=None, index=True, max_length=255)
    meta: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=now_utc)


class Workflow(SQLModel, table=True):
    """A saved Workflow Builder graph.

    `body` holds the canonical execution shape (steps[]) plus the visual graph
    (nodes/edges) so the canvas can rehydrate. The execution body matches the
    AdHocRunCreate shape so launches go through the same /api/runs/adhoc code
    path — workflows are just persistent ad-hoc workflows.
    """
    id: str = Field(default_factory=lambda: new_id("wf"), primary_key=True)
    workspace_id: str = Field(index=True, foreign_key="workspace.id")
    name: str = Field(index=True, min_length=1, max_length=120)
    description: str | None = None
    body: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    created_by: str | None = Field(default=None, index=True, foreign_key="user.id")
    created_at: datetime = Field(default_factory=now_utc)
    updated_at: datetime = Field(default_factory=now_utc)


class Advice(SQLModel, table=True):
    """A stored Claude advisor response.

    `kind` is one of:
        run_triage                — analyse a completed run, prioritise findings
        target_suggest_profile    — recommend the next profile for a target
        finding_explain           — interpret one finding (severity, exploit,
                                     remediation), bypassing template noise
        ask                       — free-form Q&A; ref_id may be None
    Re-running an advisor call replaces the row keyed by (workspace, kind, ref).
    """
    id: str = Field(default_factory=lambda: new_id("adv"), primary_key=True)
    workspace_id: str = Field(index=True, foreign_key="workspace.id")
    kind: str = Field(index=True, max_length=64)
    ref_id: str | None = Field(default=None, index=True, max_length=64)
    actor_id: str | None = Field(default=None, index=True)
    model: str = Field(default="claude-opus-4-7", max_length=64)
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cached_tokens: int = 0
    summary: str = Field(default="")
    body: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=now_utc)


class AuditEvent(SQLModel, table=True):
    """Append-only, hash-chained audit trail.

    Each row's signature = sha256(prev_signature || canonical_json(payload)).
    The chain is rooted at the empty string; verification re-walks rows by
    sequence and checks each signature.
    """
    id: str = Field(default_factory=lambda: new_id("aud"), primary_key=True)
    sequence: int = Field(index=True, unique=True)
    actor_id: str | None = Field(default=None, index=True)
    actor_role: str | None = None
    action: str = Field(index=True, max_length=64)
    target_kind: str | None = Field(default=None, index=True, max_length=32)
    target_id: str | None = Field(default=None, index=True)
    payload: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    prev_signature: str = Field(default="", max_length=64)
    signature: str = Field(index=True, max_length=64)
    created_at: datetime = Field(default_factory=now_utc)
