"""Validate the runner Dockerfile structurally.

We can't invoke `docker build` from this test harness in every environment, but
we can guarantee that the pin matrix covers the tools that our default
profiles depend on, and that the Dockerfile syntax is at least parseable.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
RUNNER_DOCKERFILE = REPO / "apps" / "api" / "Dockerfile.runner"
TOOLS_DIR = REPO / "packages" / "tool-registry" / "tools"
PROFILES_DIR = REPO / "packages" / "tool-registry" / "profiles"

# Profiles whose tools MUST all have a pinned install entry in Dockerfile.runner.
# These are the ones a fresh `docker compose up` user is likely to launch.
CRITICAL_PROFILES = {"passive_recon"}


def test_runner_dockerfile_exists():
    assert RUNNER_DOCKERFILE.exists(), "Dockerfile.runner is missing"


def test_runner_dockerfile_pins_versions_for_critical_tools():
    body = RUNNER_DOCKERFILE.read_text()
    # Every go install line must include a tag/version (no @latest)
    bad = re.findall(r'go install "?[^"\n]*?@latest"?', body)
    assert not bad, f"Dockerfile.runner uses @latest pins (bump to a tagged version): {bad}"

    # Every ARG that names a *_VERSION must be referenced in a go install line
    arg_versions = re.findall(r"^ARG\s+([A-Z0-9_]+_VERSION)=", body, flags=re.M)
    referenced = re.findall(r"\$\{([A-Z0-9_]+_VERSION)\}", body)
    unused = set(arg_versions) - set(referenced)
    assert not unused, f"unused version ARGs: {unused}"


def test_runner_image_covers_passive_recon_tool_chain():
    body = RUNNER_DOCKERFILE.read_text()
    for prof_id in CRITICAL_PROFILES:
        prof = yaml.safe_load((PROFILES_DIR / f"{prof_id}.yaml").read_text())
        for step in prof["steps"]:
            tool_id = step["tool"]
            tool = yaml.safe_load((TOOLS_DIR / f"{tool_id}.yaml").read_text())
            install = (tool.get("install") or {})
            method = install.get("method")
            package = install.get("package", "")

            if method == "go_install":
                # Strip @version from registered package; we expect the image to
                # have a pinned go install for it (binary == tool.binary).
                bin_name = tool.get("binary") or tool_id
                # Match either a pinned `go install <package>@${X_VERSION}` line
                # or apt-installed binaries like nmap.
                assert (
                    re.search(rf'go install "[^"]+\b{re.escape(bin_name)}\b[^"]*"', body)
                    or re.search(rf'go install "[^"]+/{re.escape(bin_name)}@', body)
                ), f"runner image does not install go binary for {tool_id} (binary={bin_name})"
            elif method == "apt":
                assert re.search(rf"apt-get install[^\n]*\b{re.escape(package)}\b", body), \
                    f"runner image apt-install missing for {tool_id}: {package}"
            elif method == "manual":
                # crtsh/github_search/etc. are HTTP-only or built-in; nothing to install.
                continue
            elif method in {"pip_install", "pipx"}:
                # Either is fine; we install pipx-based tools in the image.
                continue
            else:
                raise AssertionError(f"unknown install method for {tool_id}: {method!r}")


def test_runner_dockerfile_installs_legacy_oneforall_package():
    body = RUNNER_DOCKERFILE.read_text()
    assert "/app/legacy" in body, "runner image must include the legacy package"
    assert "pip install" in body and "/app/legacy" in body, \
        "runner image must `pip install -e /app/legacy`"
