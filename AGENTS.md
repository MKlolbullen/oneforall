# Agents & automation

How an external agent (a Claude-driven operator, a CI bot, your own script)
talks to the ReconForge control plane. Everything here is a normal authenticated
REST/WebSocket call against the FastAPI control plane — there is no separate
agent protocol.

The golden rule: **read the curated layers first (brief → loot → findings),
fetch raw artifact bytes only when you need the full evidence.** Briefs and loot
are bounded; artifacts are not.

## Authentication

Every `/api/*` route requires a bearer token (`/health` is open). Mint one with
a username/password, then send it on every request:

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H 'content-type: application/json' \
  -d '{"username":"admin","password":"…"}' | jq -r .token)

curl -s http://localhost:8000/api/agent/runs/$RUN_ID/brief \
  -H "Authorization: Bearer $TOKEN" | jq .
```

The token is shown once; only its prefix and `sha256(token)` are stored. Roles:
`viewer` (read), `operator` (create targets / queue runs / reindex loot),
`admin` (users + keys). See the "Auth & audit" section of the main
[README](./README.md).

## Structured run brief — `GET /api/agent/runs/{id}/brief`

The single best entry point for an agent. A bounded, deterministic snapshot of
one run — no LLM in the loop, so it is cheap and reproducible:

```jsonc
{
  "run":    { "id", "profile_id", "status", "risk", "created_at", … },
  "target": { "id", "value", "type", "active_allowed", … },
  "counts": { "steps", "findings", "assets", "artifacts", "loot" },
  "findings_by_severity": { "critical": 2, "high": 5, … },
  "steps":    [ { "index", "tool", "status", "error" } ],
  "findings": [ { "id", "title", "severity", "category", "tool_source",
                  "evidence_excerpt" } ],   // severity-ranked, capped at 50
  "assets_by_type": { "domain": [...], "url": [...] },  // capped per type
  "artifacts": [ { "id", "name", "type", "size_bytes", "sha256",
                   "content_url" } ],
  "loot": { "total", "by_kind", "by_severity", "items": [...] }
}
```

Findings are severity-ranked (critical → info) and truncated; assets are capped
per type; artifacts carry a `content_url` you can `GET` directly. If loot has
not been indexed yet it is computed on the fly (when the loot toggle is on).

## Loot — curated high-signal output

Loot is the "what deserves attention" layer: secrets, credentials, subdomain
takeovers, exposed sensitive files, and critical/high vulnerabilities. It is
*derived from Findings*, not a second copy of every scanner line — raw evidence
stays on the Finding / Artifact.

`kind` is one of: `secret`, `credential`, `takeover`, `exposure`,
`vulnerability`. Inherently high-signal kinds (secrets, takeovers, creds) are
floored to at least `high` severity even when the source tool tagged them lower.

```text
GET  /api/loot?workspace_id=&run_id=&kind=&severity=&host=&limit=&offset=
GET  /api/loot/export?format=csv|json|md&…       # same filters
POST /api/loot/runs/{run_id}/reindex             # operator; idempotent
```

`GET /api/loot` returns a severity-ranked page plus `facets` (`kinds`,
`severities`) so a UI/agent can build filters in one round trip. At run
completion the worker also writes a `loot.manifest.json` artifact —
`schema: reconforge.loot.manifest/v1` — containing the full loot list and a
summary. Reindex is idempotent (keyed on `finding_id`); re-running never
duplicates rows.

## Claude advisor — `GET|POST /api/advisor/...`

When an agent wants ReconForge's own Claude advisor to interpret data (rather
than reading it raw), use the advisor endpoints. `POST` runs the model and
caches the result; `GET` returns the cached `Advice` (or `204` if none yet).
Requires `ANTHROPIC_API_KEY` on the server, else `503`.

```text
GET|POST /api/advisor/runs/{run_id}/triage
GET|POST /api/advisor/targets/{target_id}/suggest-profile
GET|POST /api/advisor/findings/{finding_id}/explain
POST     /api/advisor/ask            # {question, workspace_id, run_id?, target_id?}
```

Advisor responses are grounded in the same serialized run/target/finding
context an agent could fetch itself — including the loot summary.

## Live run events — `WS /ws/runs/{run_id}`

Connect a WebSocket to stream a run's events. The socket first replays the
persisted history (Postgres is the source of truth), then tails live events via
Redis Pub/Sub — so attaching mid-run or post-run still yields the full timeline:

```text
run.queued → run.started
  run.step.started → run.step.completed (per step)
  run.step.artifact_created            (carries artifact_id in payload)
run.completed | run.failed | run.cancelled
```

For a non-streaming poll, use `GET /api/runs/{run_id}/events` and
`GET /api/runs/{run_id}/steps`.

## Fetching artifacts

Artifact metadata lives in Postgres; bytes live in MinIO/S3 or local disk.
Never inline large artifacts into a prompt — fetch on demand:

```text
GET /api/artifacts/{artifact_id}            # metadata
GET /api/artifacts/{artifact_id}/content    # raw bytes (Range supported)
```

The brief's `artifacts[].content_url` already points at the `/content` route.

## Findings

The raw, full finding list (with substring search, facets, and CSV/JSON/MD
export) lives alongside loot:

```text
GET /api/findings?workspace_id=&severity=&status=&tool=&target_id=&q=&limit=&offset=
GET /api/findings/export?format=csv|json|md&…
PATCH /api/findings/{id}    # {status} — operator; triage workflow
```

## A typical agent loop

1. `POST /api/runs` to queue a run (operator), or watch an existing one.
2. `WS /ws/runs/{id}` (or poll `/events`) until `run.completed`.
3. `GET /api/agent/runs/{id}/brief` for the bounded snapshot.
4. Triage `loot` first; pull individual `findings` and fetch artifact
   `content_url`s only for the items that matter.
5. Optionally `POST /api/advisor/runs/{id}/triage` for a Claude-written summary,
   or `POST /api/advisor/ask` with `run_id` for free-form questions.
