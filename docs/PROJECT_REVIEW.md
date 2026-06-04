# ReconForge project review

## What is already strong

- Clean split between React UI, FastAPI API, worker, registry, artifacts, and legacy CLI.
- YAML registry is the right direction; it keeps tool behavior declarative.
- Scope checks exist before run creation.
- Commands are argv arrays instead of shell strings.
- Auth/RBAC and tamper-evident audit logs are present.
- Artifact model and run-step tracking are already useful for real operator workflows.
- The graph/loot/advisor layers give the project a clear path beyond "run tools and dump text".

## Biggest risks

1. **Live-mode drift** — defaults and documentation must never accidentally encourage real tool execution.
2. **Runner isolation** — live subprocess execution needs container or host-level limits before shared deployment.
3. **Entity quality** — normalizers should become stricter and richer; otherwise the graph becomes pretty garbage.
4. **Auth UX** — backend auth exists, but the frontend still needs a first-class login/session experience.
5. **Workflow persistence** — the visual builder should persist typed DAGs and compile them into run plans.

## Best next engineering moves

1. Build the run launch drawer with preflight profile availability, risk summary, and manual approval toggles.
2. Add signed run manifests and artifact-hash verification.
3. Add workspace-scoped ROE configuration in the UI.
4. Add finding deduplication/fingerprinting.
5. Add provider-agnostic AI advisor routing, but keep it read-only until schema-validated approval flows exist.
