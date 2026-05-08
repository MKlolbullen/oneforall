"""External tool wrappers, dedup helpers, tool detection."""
from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def require(tools: list[str]) -> list[str]:
    """Return the subset of `tools` actually present on PATH."""
    available = [t for t in tools if have(t)]
    missing = [t for t in tools if not have(t)]
    if missing:
        logger.warning("Tools not on PATH (skipping): %s", ", ".join(missing))
    return available


def run(cmd: str, log_file: Path | None = None, env: dict | None = None,
        timeout: int | None = None, check: bool = False) -> tuple[int, str]:
    """Run a shell command. Returns (returncode, combined_output).

    Logs to `log_file` if given. Never raises unless check=True.
    """
    logger.info("$ %s", cmd)
    try:
        proc = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            env=env, timeout=timeout, check=check,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        if log_file:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            with log_file.open("a") as f:
                f.write(f"\n$ {cmd}\n{out}\n")
        return proc.returncode, out
    except subprocess.TimeoutExpired as e:
        msg = f"timeout after {timeout}s: {cmd}"
        logger.error(msg)
        if log_file:
            with log_file.open("a") as f:
                f.write(f"\n$ {cmd}\n[TIMEOUT]\n")
        return 124, msg
    except Exception as e:
        logger.error("command failed: %s -- %s", cmd, e)
        return 1, str(e)


def anew(lines: list[str], path: Path) -> int:
    """Append unique lines to file, return number newly added (anew-style)."""
    existing = set()
    if path.exists():
        existing = {l.strip() for l in path.read_text().splitlines() if l.strip()}
    new = [l for l in (s.strip() for s in lines) if l and l not in existing]
    if new:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as f:
            f.write("\n".join(new) + "\n")
    return len(new)


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [l.strip() for l in path.read_text().splitlines() if l.strip()]
