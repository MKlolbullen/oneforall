# ReconForge enhancement roadmap

This roadmap assumes the current codebase: FastAPI control plane, React/Vite UI, YAML tool registry, worker execution, artifacts, auth/audit, target detail pages, loot, advisor, and graph views.

## Phase 1 — safer v1 operator loop

- Keep dry-run as the immutable default in templates, docs, and backend defaults.
- Add target normalization and invalid-row reporting for bulk imports. Done.
- Add `scripts/preflight.sh` for import smoke, tests, frontend build, and live tool matrix. Done.
- Add a UI auth flow instead of relying on manually supplied bearer tokens.
- Add workspace-level scope policy editing in the Settings Pack page.
- Add run launch drawer with explicit risk, profile steps, required tools, and approval toggles.

## Phase 2 — execution engine maturity

- Replace ad-hoc in-process queue mode with Redis/worker as the only production path.
- Add per-step resource limits: CPU, memory, max output bytes, max artifact bytes.
- Add signed run manifests: profile hash, target snapshot, argv, env allow-list, artifact hashes.
- Add optional containerized per-run sandboxes.
- Add workflow graph persistence for user-authored DAGs, not just registry profiles.

## Phase 3 — intelligence model

- Introduce first-class entities: service, technology, endpoint, parameter, identity, credential, cloud resource, Kubernetes object.
- Add provenance edges for every entity: source tool, run, artifact, parser confidence.
- Add confidence decay and staleness scoring.
- Add finding correlation/deduplication by asset + evidence fingerprint.
- Add asset graph filters: type, severity, source tool, run, first/last seen, internet/internal boundary.

## Phase 4 — AI sidekick without chaos

- Keep advisor calls read-only by default.
- Make agent outputs structured JSON with schema validation before anything reaches the runner.
- Add a planner approval queue: recommended action, expected inputs, risk, cost, and rollback/stop condition.
- Add provider router support for OpenAI/Anthropic/Gemini/Ollama with cost accounting.
- Add redaction before prompts: tokens, secrets, credentials, customer names when required.

## Phase 5 — reporting

- Add report builder with findings triage, evidence selection, screenshots, remediation, and scope appendix.
- Export Markdown, DOCX, and PDF.
- Generate one report per target and one executive roll-up per workspace.
- Include an attestation appendix: target list, profile list, exact run times, tool versions, audit-chain verification result.

## Strong opinion

Do not turn this into a giant Bash wrapper with a pretty face. The value is typed entities, provenance, repeatability, approval gates, and evidence quality. Tool spam is easy; trustworthy automation is the hard part.
