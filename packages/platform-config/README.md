# Platform Configuration Packs

This directory contains ReconForge policy/config packs. The default `sniper-inspired.yaml` is a clean-room translation of the kind of knobs exposed by Sn1per CE-style Bash settings into structured YAML.

It covers:

- runtime limits such as `max_hosts`, `threads`, and `max_javascript_files`
- out-of-scope defaults and active/high-risk approval requirements
- scanner integrations: Burp, ZAP, OpenVAS/GVM, Nessus, Metasploit import
- external intelligence API env var names
- Slack notification toggles
- web brute-force stages and wordlists
- Nmap quick/default/full port profiles
- plugin groups for recon, OSINT, passive web, active web, network, email, and DAST

API endpoints:

```text
GET  /api/config/effective
GET  /api/config/plugin-matrix
POST /api/config/reload
```

The config is intentionally separated from the tool registry. The registry says what a tool is and how it runs; the platform config says which operational knobs are enabled by default.
