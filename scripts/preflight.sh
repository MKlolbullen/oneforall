#!/usr/bin/env bash
# ReconForge preflight: cheap checks before a demo, CI run, or live lab.
# It intentionally defaults to dry-run-safe checks. Pass --live to require the
# runner toolchain to be present and to print explicit live-mode warnings.
set -euo pipefail

LIVE=0
SKIP_WEB=0
QUICK=0
for arg in "$@"; do
  case "$arg" in
    --live) LIVE=1 ;;
    --skip-web) SKIP_WEB=1 ;;
    --quick) QUICK=1 ;;
    -h|--help)
      cat <<'EOF'
Usage: scripts/preflight.sh [--quick] [--live] [--skip-web]

Checks:
  - Python import smoke for the API
  - registry/profile load
  - pytest suite with safe dry-run env
  - --quick limits pytest to fast smoke/regression tests
  - optional frontend build
  - optional live tool availability matrix
EOF
      exit 0
      ;;
    *) echo "unknown arg: $arg" >&2; exit 2 ;;
  esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT/apps/api:${PYTHONPATH:-}"

log() { printf '\033[1;36m[preflight]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[preflight]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[1;31m[preflight]\033[0m %s\n' "$*" >&2; exit 1; }

export TOOL_REGISTRY_DIR="${TOOL_REGISTRY_DIR:-$ROOT/packages/tool-registry/tools}"
export PROFILE_REGISTRY_DIR="${PROFILE_REGISTRY_DIR:-$ROOT/packages/tool-registry/profiles}"
export PLATFORM_CONFIG_PATH="${PLATFORM_CONFIG_PATH:-$ROOT/packages/platform-config/sniper-inspired.yaml}"
export GREP_PATTERNS_PATH="${GREP_PATTERNS_PATH:-$ROOT/packages/patterns/sniper-grep-patterns.yaml}"
export WORDLISTS_DIR="${WORDLISTS_DIR:-$ROOT/packages/wordlists}"
export DATABASE_URL="${DATABASE_URL:-sqlite:///$ROOT/.preflight-reconforge.db}"
export ARTIFACT_BACKEND="${ARTIFACT_BACKEND:-local}"
export ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT/.preflight-artifacts}"
export EXECUTION_MODE="${EXECUTION_MODE:-dry_run}"
export ALLOW_LIVE_EXECUTION="${ALLOW_LIVE_EXECUTION:-false}"
export RUNNER_MODE="${RUNNER_MODE:-in_process}"
export DRY_RUN_LINE_DELAY_SECONDS="${DRY_RUN_LINE_DELAY_SECONDS:-0}"
export RECONFORGE_BOOTSTRAP_ADMIN_USERNAME="${RECONFORGE_BOOTSTRAP_ADMIN_USERNAME:-admin}"
export RECONFORGE_BOOTSTRAP_ADMIN_PASSWORD="${RECONFORGE_BOOTSTRAP_ADMIN_PASSWORD:-admin-passw0rd}"
export RECONFORGE_TEST_AUTH_BYPASS=1

if [[ "$LIVE" -eq 1 ]]; then
  warn "--live selected. Only use this in an explicitly authorized lab/engagement."
  if [[ "${EXECUTION_MODE}" != "live" || "${ALLOW_LIVE_EXECUTION}" != "true" ]]; then
    warn "Live requested but env is not live/live-allowed; tool matrix will run, execution tests stay dry."
  fi
fi

log "Python import smoke"
python - <<'PY'
from pathlib import Path
from app.core.config import get_settings
from app.services.tool_registry import get_registry
s = get_settings()
r = get_registry()
tools = r.list_tools()
profiles = r.list_profiles()
assert tools, "no tools loaded"
assert profiles, "no profiles loaded"
print({
    "execution_mode": s.execution_mode,
    "live_execution_enabled": s.live_execution_enabled,
    "tools": len(tools),
    "profiles": len(profiles),
})
PY

if [[ "$QUICK" -eq 1 ]]; then
  log "pytest quick safe dry-run smoke"
  python -m pytest \
    tests/test_target_validation.py \
    tests/test_registry_smoke.py \
    tests/test_dag_artifact_passing.py \
    tests/test_e2e_dry_run.py \
    -q
else
  log "pytest full safe dry-run suite"
  python -m pytest tests/ -q
fi

if [[ "$SKIP_WEB" -eq 0 ]]; then
  if command -v npm >/dev/null; then
    log "frontend type-check/build"
    (cd apps/web && npm run build)
  else
    warn "npm not found; skipping frontend build"
  fi
fi

if [[ "$LIVE" -eq 1 ]]; then
  log "live tool matrix"
  ./scripts/check-tools.sh || fail "live tool check failed"
fi

log "preflight OK"
