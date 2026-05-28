from typing import Any
from pydantic import BaseModel, Field
from app.models import RiskLevel, RunStatus, StepStatus


class WorkspaceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str | None = None


class TargetCreate(BaseModel):
    workspace_id: str
    value: str = Field(min_length=1, max_length=255)
    type: str = "domain"
    in_scope: bool = True
    passive_allowed: bool = True
    active_allowed: bool = False
    notes: str | None = None


class BulkTargetCreate(BaseModel):
    """Paste-a-list shape used by the Targets page bulk-import textarea."""
    workspace_id: str
    values: list[str] = Field(min_length=1, max_length=500)
    type: str = "domain"
    in_scope: bool = True
    passive_allowed: bool = True
    active_allowed: bool = False
    notes: str | None = None


class BulkTargetResult(BaseModel):
    created: list[Any] = Field(default_factory=list)        # list[Target] post-serialize
    skipped: list[dict[str, str]] = Field(default_factory=list)
    workspace_id: str


class RunCreate(BaseModel):
    workspace_id: str
    target_id: str
    profile_id: str = "passive_recon"
    requested_by: str = "local-dev"
    params: dict[str, Any] = Field(default_factory=dict)


class AdHocStep(BaseModel):
    """One step inside an ad-hoc workflow.

    Mirrors the YAML profile-step shape the registry already supports, but as
    a typed Pydantic body so the Workflow Builder can POST a JSON DAG without
    writing a temporary YAML file. argv_replace/argv_extra accept the same
    `{{steps.<id>.stdout_path}}` / `{{upstream.<type>.merged_path}}` templates
    the YAML profiles use.
    """
    tool: str = Field(min_length=1, max_length=64)
    argv_replace: list[str] | None = None
    argv_extra: list[str] | None = None
    timeout_seconds: int | None = Field(default=None, ge=1, le=86400)
    max_retries: int | None = Field(default=None, ge=0, le=10)
    retry_backoff_seconds: float | None = Field(default=None, ge=0, le=300)
    continue_on_error: bool | None = None


class AdHocRunCreate(BaseModel):
    """Body for POST /api/runs/adhoc. The Workflow Builder topologically sorts
    its canvas, then submits the resulting linear step list here."""
    workspace_id: str
    target_id: str
    name: str = Field(default="Ad-hoc workflow", min_length=1, max_length=120)
    steps: list[AdHocStep] = Field(min_length=1, max_length=50)
    requested_by: str = "local-dev"
    params: dict[str, Any] = Field(default_factory=dict)


class ToolInput(BaseModel):
    name: str
    type: str
    required: bool = True


class ToolOutput(BaseModel):
    name: str
    type: str


class ToolDefinition(BaseModel):
    id: str
    name: str
    category: str
    description: str = ""
    binary: str | None = None
    risk: RiskLevel = RiskLevel.passive
    requires_authorization: bool = False
    inputs: list[ToolInput] = Field(default_factory=list)
    outputs: list[ToolOutput] = Field(default_factory=list)
    command: dict[str, Any] = Field(default_factory=dict)
    parser: dict[str, Any] = Field(default_factory=dict)
    default_timeout_seconds: int = Field(default=900, ge=1, le=86400)
    max_retries: int = Field(default=0, ge=0, le=10)
    retry_backoff_seconds: float = Field(default=1.0, ge=0, le=300)
    continue_on_error: bool = False
    tags: list[str] = Field(default_factory=list)
    install: dict[str, Any] = Field(default_factory=dict)
    dry_run_output: list[str] = Field(default_factory=list)




class ToolAvailability(BaseModel):
    tool_id: str
    name: str
    category: str
    risk: RiskLevel
    requires_authorization: bool
    binary: str | None = None
    available: bool
    status: str
    path: str | None = None
    version: str | None = None
    message: str | None = None
    install: dict[str, Any] = Field(default_factory=dict)


class ProfileAvailability(BaseModel):
    profile_id: str
    name: str
    runnable: bool
    total_tools: int
    available_tools: int
    missing_tools: list[str] = Field(default_factory=list)
    tools: list[ToolAvailability] = Field(default_factory=list)


class RunRead(BaseModel):
    id: str
    workspace_id: str
    target_id: str
    profile_id: str
    status: RunStatus
    risk: RiskLevel


class DashboardStats(BaseModel):
    workspaces: int
    targets: int
    runs: int
    assets: int
    findings: int
    open_findings: int


class RunCancelResponse(BaseModel):
    run_id: str
    status: RunStatus
    message: str


class RunStepRead(BaseModel):
    id: str
    run_id: str
    workspace_id: str
    tool_id: str
    tool_name: str
    index: int
    status: StepStatus
    attempt: int
    max_retries: int
    timeout_seconds: int
    continue_on_error: bool
    exit_code: int | None = None
    error: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    meta: dict[str, Any] = Field(default_factory=dict)
