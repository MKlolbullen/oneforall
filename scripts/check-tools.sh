#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS_DIR="${TOOLS_DIR:-$ROOT/packages/tool-registry/tools}"
API="${API:-}"

if [[ -n "$API" ]]; then
  echo "[+] API availability checks from $API"
  curl -fsS "$API/api/tools/availability?force=true" \
    | jq -r '.[] | [.status, .tool_id, (.binary // "-"), (.path // .message // "-")] | @tsv' \
    | column -t -s $'\t'
  exit 0
fi

python3 - <<'PY' "$TOOLS_DIR"
import shutil, sys
from pathlib import Path
import yaml

tools_dir=Path(sys.argv[1])
rows=[]
for path in sorted(tools_dir.glob('*.yaml')):
    raw=yaml.safe_load(path.read_text()) or {}
    tool_id=raw.get('id', path.stem)
    binary=raw.get('binary') or ((raw.get('command') or {}).get('argv') or [None])[0]
    found=shutil.which(binary) if binary else 'built-in'
    rows.append((tool_id, binary or '-', 'ok' if found else 'missing', found or '-'))

print(f"{'TOOL':28} {'BINARY':22} {'STATUS':10} PATH")
for tool_id, binary, status, found in rows:
    print(f"{tool_id:28} {binary:22} {status:10} {found}")
missing=sum(1 for _,_,status,_ in rows if status!='ok')
print(f"\n{len(rows)} tools checked, {missing} missing/broken according to PATH")
PY
