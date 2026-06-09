from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "ReconForge"
    environment: str = "dev"
    database_url: str = "sqlite:///./reconforge.db"
    redis_url: str = "redis://localhost:6379/0"
    # app://reconforge is the origin of the Electron desktop shell's renderer
    # (Phase 3); kept in the defaults so a freshly-spawned sidecar can talk to
    # the bundled UI with no extra configuration.
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173,app://reconforge"

    tool_registry_dir: Path = Field(default=Path("../../packages/tool-registry/tools"))
    profile_registry_dir: Path = Field(default=Path("../../packages/tool-registry/profiles"))
    platform_config_path: Path = Field(default=Path("../../packages/platform-config/sniper-inspired.yaml"))
    grep_patterns_path: Path = Field(default=Path("../../packages/patterns/sniper-grep-patterns.yaml"))
    wordlists_dir: Path = Field(default=Path("../../packages/wordlists"))
    # ROE engine policy. If the file doesn't exist the engine guard
    # no-ops, leaving the legacy target-level scope check as the only
    # gate. Operators opt in by creating the file.
    roe_policy_path: Path = Field(default=Path("../../packages/platform-config/roe.yaml"))

    tool_availability_cache_seconds: float = 15.0
    tool_availability_probe_timeout_seconds: float = 1.5
    block_live_runs_on_missing_tools: bool = True

    # Safe-by-default execution. Live mode requires both EXECUTION_MODE=live
    # and ALLOW_LIVE_EXECUTION=true so one typo cannot accidentally fire real
    # tools. Keep this default unless you are inside an explicitly authorized lab.
    execution_mode: str = "dry_run"
    allow_live_execution: bool = False

    # Dry-run simulator pacing. Keep non-zero for readable demos; set to 0 in
    # CI when you want fast deterministic tests.
    dry_run_line_delay_seconds: float = 0.05

    # queue    = external worker drains a Redis queue (multi-process, prod).
    # embedded = worker runs in the API's own asyncio loop, backed by an
    #            in-process queue + pub/sub. No Redis, no second process —
    #            this is the mode a packaged desktop (Electron) build uses.
    # in_process = fire-and-forget asyncio task per run inside the request
    #            handler. Handy for local debugging.
    runner_mode: str = "queue"
    run_queue_name: str = "reconforge:runs:queue"
    redis_event_channel_prefix: str = "reconforge:runs"

    # Live-event bus + job-queue transport. "auto" derives the right backend
    # from runner_mode (memory for embedded/in_process, redis for queue) so a
    # single RUNNER_MODE flip is enough; override explicitly to mix and match.
    event_transport: str = "auto"  # auto | redis | memory
    queue_backend: str = "auto"  # auto | redis | memory

    # local or s3. Compose uses MinIO-backed S3 by default.
    artifact_backend: str = "local"
    artifact_dir: Path = Field(default=Path("./artifacts"))
    minio_endpoint: str = "http://localhost:9000"
    minio_access_key: str = "reconforge"
    minio_secret_key: str = "reconforge-secret"
    minio_bucket: str = "artifacts"
    s3_region: str = "us-east-1"

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def live_execution_enabled(self) -> bool:
        return self.execution_mode == "live" and self.allow_live_execution

    @property
    def queued_runner_enabled(self) -> bool:
        # Both queue and embedded push jobs onto a queue; they differ only in
        # who drains it (external process vs. in-loop task). in_process skips
        # the queue and spawns the run directly.
        return self.runner_mode in {"queue", "embedded"}

    @property
    def embedded_runner_enabled(self) -> bool:
        return self.runner_mode == "embedded"

    @property
    def resolved_event_transport(self) -> str:
        if self.event_transport != "auto":
            return self.event_transport
        return "memory" if self.runner_mode in {"embedded", "in_process"} else "redis"

    @property
    def resolved_queue_backend(self) -> str:
        if self.queue_backend != "auto":
            return self.queue_backend
        return "memory" if self.runner_mode == "embedded" else "redis"

    def run_event_channel(self, run_id: str) -> str:
        return f"{self.redis_event_channel_prefix}:{run_id}:events"


@lru_cache
def get_settings() -> Settings:
    return Settings()
