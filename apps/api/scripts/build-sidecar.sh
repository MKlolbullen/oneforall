#!/usr/bin/env bash
# Build the ReconForge sidecar binary for the Electron desktop shell.
#
# Run from apps/api (the package this script lives in). The output is
# dist/reconforge-sidecar (or .exe on Windows), ready for electron-builder
# or scripts/copy-sidecar.sh to drop into the desktop app's resources/.
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v pyinstaller >/dev/null 2>&1; then
  echo "error: pyinstaller not found on PATH" >&2
  echo "       install with:  pip install pyinstaller" >&2
  exit 1
fi

# --clean wipes the cached build state so a `pip install -e .` change is
# actually reflected. Without it, PyInstaller happily ships a stale graph.
pyinstaller --clean --noconfirm reconforge_sidecar.spec

bin="dist/reconforge-sidecar"
[[ "${OS:-}" == "Windows_NT" ]] && bin="dist/reconforge-sidecar.exe"

echo
echo "built: ${bin}"
ls -lh "${bin}" 2>/dev/null || true
