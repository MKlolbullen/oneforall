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
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

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

    # queue = external worker via Redis. in_process remains useful for local debugging.
    runner_mode: str = "queue"
    run_queue_name: str = "reconforge:runs:queue"
    redis_event_channel_prefix: str = "reconforge:runs"

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
        return self.runner_mode == "queue"

    def run_event_channel(self, run_id: str) -> str:
        return f"{self.redis_event_channel_prefix}:{run_id}:events"


@lru_cache
def get_settings() -> Settings:
    return Settings()
