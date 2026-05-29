# ReconForge hardening checklist

ReconForge can launch real recon/scanning tools. Treat it as an operator control plane, not a toy web app.

## Default stance

Fresh checkouts are safe-by-default:

```env
EXECUTION_MODE=dry_run
ALLOW_LIVE_EXECUTION=false
BLOCK_LIVE_RUNS_ON_MISSING_TOOLS=true
```

Live execution should only be enabled inside an explicitly authorized lab, customer engagement, or bug-bounty scope.

## Before live mode

1. Set a real admin password; never keep `change-me-now` or `admin-passw0rd`.
2. Configure `RECONFORGE_AUDIT_HMAC_KEY` with at least 32 random bytes.
3. Run `scripts/preflight.sh --live` inside the same container/host that will execute tools.
4. Confirm each target has correct `in_scope`, `passive_allowed`, and `active_allowed` flags.
5. Keep `BLOCK_LIVE_RUNS_ON_MISSING_TOOLS=true` unless you are debugging the runner image.
6. Put the API behind TLS, authentication, rate limits, and a private network boundary.
7. Keep artifacts out of the database; use MinIO/S3 with retention and access policies.
8. Export and archive audit logs after each engagement.

## Never expose a raw runner

Do not expose the API or worker directly to the internet. The worker can spawn subprocesses and handle sensitive artifacts, so it belongs in an isolated network segment.

Minimum production-grade shape:

```text
browser -> reverse proxy/TLS/WAF -> API -> Redis/Postgres/MinIO
                                      -> isolated worker network -> tool runner
```

## Scope model

Target creation validates syntax and canonicalizes values. It intentionally allows private, loopback, and RFC1918 ranges because internal labs, AD/Entra hybrid environments, and Kubernetes assessments need them.

Actual authorization happens at run creation:

- out-of-scope pattern match blocks the run,
- passive runs require `passive_allowed=true`,
- active runs require `active_allowed=true`,
- high-risk profiles require `manual_approval=true` when enabled by config.

## Operator preflight

```bash
scripts/preflight.sh --quick  # fast dry-run-safe smoke + optional web build
scripts/preflight.sh          # full dry-run-safe tests + optional web build
scripts/preflight.sh --live   # adds live tool matrix checks
scripts/preflight.sh --skip-web
```

Set `DRY_RUN_LINE_DELAY_SECONDS=0` for fast CI, or keep `0.05` for readable demos.
