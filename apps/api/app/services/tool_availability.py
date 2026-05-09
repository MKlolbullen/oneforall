from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from typing import Any

from app.core.config import get_settings
from app.schemas import ProfileAvailability, ToolAvailability, ToolDefinition
from app.services.tool_registry import ToolRegistry

_CACHE: dict[str, tuple[float, ToolAvailability]] = {}
_MODULE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")


def _tool_binary(tool: ToolDefinition) -> str | None:
    if tool.binary:
        return tool.binary
    argv = tool.command.get("argv") if isinstance(tool.command, dict) else None
    if isinstance(argv, list) and argv:
        first = argv[0]
        return str(first) if first else None
    return None


def _argv(tool: ToolDefinition) -> list[str]:
    raw = tool.command.get("argv") if isinstance(tool.command, dict) else None
    if not isinstance(raw, list):
        return []
    return [str(item) for item in raw]


def _python_module_from_argv(argv: list[str]) -> str | None:
    for idx, token in enumerate(argv[:-1]):
        if token == "-m":
            module = argv[idx + 1]
            if _MODULE_RE.match(module):
                return module
            return None
    return None



def _missing_required_env(tool: ToolDefinition) -> list[str]:
    raw = tool.install.get("env") if isinstance(tool.install, dict) else None
    if not isinstance(raw, list):
        return []
    return [str(name) for name in raw if not os.getenv(str(name))]

def _run_probe(args: list[str], timeout_seconds: float) -> tuple[int | None, str]:
    try:
        completed = subprocess.run(
            args,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return None, "probe timed out"
    except OSError as exc:
        return None, str(exc)
    output = "\n".join(part.strip() for part in (completed.stdout, completed.stderr) if part and part.strip())
    return completed.returncode, output[:1200]


def _probe_version(binary_path: str, timeout_seconds: float) -> tuple[str | None, str | None]:
    # Most recon tools support --version; a few only support -version or version.
    # We intentionally keep this shallow and time-bounded; availability must be cheap.
    for args in ([binary_path, "--version"], [binary_path, "-version"], [binary_path, "version"]):
        code, output = _run_probe(args, timeout_seconds)
        if code == 0 and output:
            first_line = output.splitlines()[0].strip()
            return first_line[:300], None
    return None, "version probe unavailable"


def check_tool_availability(tool: ToolDefinition, *, force: bool = False) -> ToolAvailability:
    settings = get_settings()
    binary = _tool_binary(tool)
    argv = _argv(tool)
    cache_key = f"{tool.id}:{binary}:{' '.join(argv[:3])}"
    now = time.monotonic()

    if not force:
        cached = _CACHE.get(cache_key)
        if cached and cached[0] > now:
            return cached[1]

    missing_env = _missing_required_env(tool)

    if not binary:
        result = ToolAvailability(
            tool_id=tool.id,
            name=tool.name,
            category=tool.category,
            risk=tool.risk,
            requires_authorization=tool.requires_authorization,
            binary=None,
            available=not missing_env,
            status="missing_env" if missing_env else "not_required",
            path=None,
            version=None,
            message=(
                f"Missing required environment variables: {', '.join(missing_env)}"
                if missing_env
                else "No external binary declared."
            ),
            install=tool.install,
        )
        _CACHE[cache_key] = (now + settings.tool_availability_cache_seconds, result)
        return result

    path = shutil.which(binary)
    if not path:
        result = ToolAvailability(
            tool_id=tool.id,
            name=tool.name,
            category=tool.category,
            risk=tool.risk,
            requires_authorization=tool.requires_authorization,
            binary=binary,
            available=False,
            status="missing",
            path=None,
            version=None,
            message=f"Missing executable on PATH: {binary}",
            install=tool.install,
        )
        _CACHE[cache_key] = (now + settings.tool_availability_cache_seconds, result)
        return result

    if missing_env:
        result = ToolAvailability(
            tool_id=tool.id,
            name=tool.name,
            category=tool.category,
            risk=tool.risk,
            requires_authorization=tool.requires_authorization,
            binary=binary,
            available=False,
            status="missing_env",
            path=path,
            version=None,
            message=f"Missing required environment variables: {', '.join(missing_env)}",
            install=tool.install,
        )
        _CACHE[cache_key] = (now + settings.tool_availability_cache_seconds, result)
        return result

    module = _python_module_from_argv(argv)
    if module:
        code, output = _run_probe(
            [path, "-c", f"import importlib.util; raise SystemExit(0 if importlib.util.find_spec({module!r}) else 2)"],
            settings.tool_availability_probe_timeout_seconds,
        )
        if code != 0:
            result = ToolAvailability(
                tool_id=tool.id,
                name=tool.name,
                category=tool.category,
                risk=tool.risk,
                requires_authorization=tool.requires_authorization,
                binary=binary,
                available=False,
                status="broken",
                path=path,
                version=None,
                message=f"Binary exists, but Python module is unavailable: {module}. {output}".strip(),
                install=tool.install,
            )
            _CACHE[cache_key] = (now + settings.tool_availability_cache_seconds, result)
            return result

    version, version_error = _probe_version(path, settings.tool_availability_probe_timeout_seconds)
    result = ToolAvailability(
        tool_id=tool.id,
        name=tool.name,
        category=tool.category,
        risk=tool.risk,
        requires_authorization=tool.requires_authorization,
        binary=binary,
        available=True,
        status="available",
        path=path,
        version=version,
        message=version_error or "Executable found.",
        install=tool.install,
    )
    _CACHE[cache_key] = (now + settings.tool_availability_cache_seconds, result)
    return result


def list_tool_availability(registry: ToolRegistry, *, force: bool = False) -> list[ToolAvailability]:
    return [check_tool_availability(tool, force=force) for tool in registry.list_tools()]


def profile_availability(registry: ToolRegistry, profile_id: str, *, force: bool = False) -> ProfileAvailability:
    profile = registry.get_profile(profile_id)
    checks: list[ToolAvailability] = []
    missing: list[str] = []
    for step in profile.get("steps", []):
        tool = registry.get_tool(step["tool"])
        check = check_tool_availability(tool, force=force)
        checks.append(check)
        if not check.available:
            missing.append(tool.id)

    return ProfileAvailability(
        profile_id=profile_id,
        name=str(profile.get("name", profile_id)),
        runnable=not missing,
        total_tools=len(checks),
        available_tools=sum(1 for check in checks if check.available),
        missing_tools=missing,
        tools=checks,
    )


def unavailable_profile_tools(registry: ToolRegistry, profile_id: str, *, force: bool = False) -> list[ToolAvailability]:
    profile = registry.get_profile(profile_id)
    missing: list[ToolAvailability] = []
    seen: set[str] = set()
    for step in profile.get("steps", []):
        tool_id = step["tool"]
        if tool_id in seen:
            continue
        seen.add(tool_id)
        tool = registry.get_tool(tool_id)
        check = check_tool_availability(tool, force=force)
        if not check.available:
            missing.append(check)
    return missing
