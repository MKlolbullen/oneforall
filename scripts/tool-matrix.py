#!/usr/bin/env python3
"""Render the declarative tool registry as a compact Markdown table.

This intentionally uses only the Python stdlib so it can run before the API
virtualenv is installed. It is a lightweight inventory helper, not a YAML
validator.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = ROOT / "packages" / "tool-registry" / "tools"


def scalar(lines: list[str], key: str, default: str = "") -> str:
    prefix = f"{key}:"
    for line in lines:
        if line.startswith(prefix):
            return line.split(":", 1)[1].strip().strip("'\"")
    return default


def parse(path: Path) -> dict[str, str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return {
        "id": scalar(lines, "id", path.stem),
        "name": scalar(lines, "name", path.stem),
        "category": scalar(lines, "category", "unknown"),
        "binary": scalar(lines, "binary", ""),
        "risk": scalar(lines, "risk", "unknown"),
        "auth": scalar(lines, "requires_authorization", "false"),
    }


def main() -> int:
    tools = sorted((parse(path) for path in TOOLS_DIR.glob("*.yaml")), key=lambda t: (t["category"], t["id"]))
    print(f"# Tool Matrix\n\nTotal tools: **{len(tools)}**\n")
    print("| Tool | Category | Binary | Risk | Auth |")
    print("|---|---|---|---|---|")
    for tool in tools:
        auth = "yes" if tool["auth"].lower() == "true" else "no"
        print(f"| `{tool['id']}` | {tool['category']} | `{tool['binary']}` | {tool['risk']} | {auth} |")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
