# Techniques catalog

Maps MITRE ATT&CK techniques to the platform's tools, payloads, and
chain profiles. The catalog is read-only metadata — the runner doesn't
need it, but the UI uses it to:

* tag a Finding with the techniques the source tool / payload implies
* answer the question "which tools cover initial-access?" without
  re-deriving from the tool registry
* show an attack-flow diagram from initial recon → exploit → post-ex
  given a workspace's findings.

## Files

* `attack_techniques.yaml` — the catalog itself, indexed by MITRE
  technique id (`T#####` or `T#####.###`).
* `tactics.yaml` — the MITRE tactic axis (initial_access,
  execution, persistence, privilege_escalation, defense_evasion,
  credential_access, discovery, lateral_movement, collection,
  exfiltration, c2, impact). Tools / techniques key off these IDs.

## Adding a technique

Each entry needs at minimum:

```yaml
- id: T1190
  name: Exploit Public-Facing Application
  tactic: initial_access
  tools: [nuclei, sqlmap_crawl, dalfox]
  payloads: [xss, sqli, ssti, ssrf]
  chains: [bug_bounty_full_v2, web_deep]
```

References are optional but encouraged.

## Source

Catalog entries are aligned with MITRE ATT&CK v15 (April 2024). For the
canonical text of each technique see https://attack.mitre.org/.
