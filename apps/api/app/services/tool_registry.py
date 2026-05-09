from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import TypeAdapter

from app.core.config import get_settings
from app.models import RiskLevel
from app.schemas import ToolDefinition


class ToolRegistry:
    def __init__(self, tools_dir: Path, profiles_dir: Path) -> None:
        self.tools_dir = tools_dir
        self.profiles_dir = profiles_dir
        self._tool_adapter = TypeAdapter(ToolDefinition)

    def list_tools(self) -> list[ToolDefinition]:
        tools: list[ToolDefinition] = []
        if not self.tools_dir.exists():
            return tools
        for path in sorted(self.tools_dir.glob("*.yaml")):
            tools.append(self.get_tool(path.stem))
        return tools

    def get_tool(self, tool_id: str) -> ToolDefinition:
        path = self.tools_dir / f"{tool_id}.yaml"
        if not path.exists():
            raise KeyError(f"Unknown tool: {tool_id}")
        with path.open("r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        return self._tool_adapter.validate_python(raw)

    def list_profiles(self) -> list[dict[str, Any]]:
        profiles: list[dict[str, Any]] = []
        if not self.profiles_dir.exists():
            return profiles
        for path in sorted(self.profiles_dir.glob("*.yaml")):
            with path.open("r", encoding="utf-8") as f:
                profiles.append(yaml.safe_load(f) or {})
        return profiles

    def get_profile(self, profile_id: str) -> dict[str, Any]:
        path = self.profiles_dir / f"{profile_id}.yaml"
        if not path.exists():
            raise KeyError(f"Unknown profile: {profile_id}")
        with path.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    def profile_risk(self, profile: dict[str, Any]) -> RiskLevel:
        max_rank = 0
        ranked = {
            RiskLevel.passive: 0,
            RiskLevel.low_active: 1,
            RiskLevel.medium_active: 2,
            RiskLevel.high_active: 3,
        }
        for step in profile.get("steps", []):
            tool = self.get_tool(step["tool"])
            max_rank = max(max_rank, ranked[tool.risk])
        for risk, rank in ranked.items():
            if rank == max_rank:
                return risk
        return RiskLevel.passive


def get_registry() -> ToolRegistry:
    settings = get_settings()
    return ToolRegistry(settings.tool_registry_dir, settings.profile_registry_dir)
