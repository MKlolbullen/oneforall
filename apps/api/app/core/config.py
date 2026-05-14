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

    tool_availability_cache_seconds: float = 15.0
    tool_availability_probe_timeout_seconds: float = 1.5
    block_live_runs_on_missing_tools: bool = True

    # Lab-mode default for this branch — live execution is on. Production
    # deployments outside an authorized lab MUST flip both back to dry_run
    # / false in the .env. live_execution_enabled requires both flags so
    # a single env-var typo can't accidentally fire real tools.
    execution_mode: str = "live"
    allow_live_execution: bool = True

    # Auto-target-analysis: after every successful run, fire-and-forget a
    # Claude target-analysis call so the operator sees the panel populated
    # the moment they open Target detail. No-op when ANTHROPIC_API_KEY is
    # unset. The cooldown keeps a chatty workspace from spamming the API:
    # if the latest target_analysis for this target is younger than the
    # cooldown window, we skip.
    auto_target_analysis: bool = True
    auto_target_analysis_cooldown_seconds: int = 300

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
