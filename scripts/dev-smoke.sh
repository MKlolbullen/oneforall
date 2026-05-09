#!/usr/bin/env bash
set -euo pipefail

API="${API:-http://localhost:8000}"

curl -fsS "$API/health" | jq .
curl -fsS "$API/api/tools" | jq '.[].id'
curl -fsS "$API/api/tools/profiles" | jq '.[].id'
curl -fsS "$API/api/tools/availability" | jq 'map(select(.available == false)) | length as $missing | {checked:length, missing:$missing}'
curl -fsS "$API/api/tools/profiles/passive_recon/availability" | jq '{profile_id, runnable, available_tools, total_tools, missing_tools}'
curl -fsS "$API/api/config/effective" | jq '{id, runtime: .runtime, scope: .scope}'
curl -fsS "$API/api/config/plugin-matrix" | jq '{plugins: length, enabled: map(select(.enabled == true)) | length}'
curl -fsS "$API/api/config/grep-patterns" | jq '{id, patterns: (.patterns | keys)}'
curl -fsS "$API/api/config/wordlists" | jq 'map({name, entries})'
workspace_id="$(curl -fsS "$API/api/workspaces" | jq -r '.[0].id')"
target_id="$(curl -fsS "$API/api/targets?workspace_id=${workspace_id}" | jq -r '.[0].id')"
run_id="$(curl -fsS -X POST "$API/api/runs" \
  -H 'Content-Type: application/json' \
  -d "{\"workspace_id\":\"${workspace_id}\",\"target_id\":\"${target_id}\",\"profile_id\":\"passive_recon\"}" | jq -r '.id')"

echo "queued run: ${run_id}"
echo "events:    $API/api/runs/${run_id}/events"
echo "steps:     $API/api/runs/${run_id}/steps"
echo "artifacts: $API/api/runs/${run_id}/artifacts"
