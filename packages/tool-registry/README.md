# ReconForge Tool Registry

The registry is declarative on purpose: every tool is a YAML file that describes inputs, outputs, risk level, authorization requirements, command argv, parser hints, retry/timeout policy, tags, install hints and dry-run output.

Current inventory:

- **137 tools**
- **24 profiles**
- Passive, low-active, medium-active and high-active risk classes
- Active tools require target authorization before run creation; high-risk profiles also require manual approval when the platform config requires it

## Categories

```text
reconnaissance          passive subdomain and OSINT collection
external-intel          Shodan/Censys/provider-backed external inventory
network-intel           ASN/CIDR/IP mapping
resolution              DNS resolution and DNS record checks
permutation             candidate subdomain generation
brand-intel             typo-squatting / lookalike discovery
probing                 HTTP/HTTPS liveness probing
fingerprinting          web/CDN/WAF/tech/favicons/CSP analysis
screenshots             visual reconnaissance
url-discovery           historical URL gathering
crawling                live crawling/spidering
javascript-analysis     JS endpoints and client-side surface extraction
url-normalization       dedupe/canonicalization/extraction utilities
content-discovery       files/directories/vhosts/params
vulnerability-scanning  nuclei/nikto/template-style validation
injection-testing       SQLi/command/CRLF helpers; approval-gated
xss-testing             XSS-focused validation
api-security            API, GraphQL, JWT and route discovery
secrets                 JS/repo/artifact secret discovery
supply-chain            client-side dependency checks
cloud-security          buckets/cloud inventory/exposure checks
port-scanning           TCP/service inventory
OOB-testing             callback-based validation support
```

## Profiles added in this expansion

```text
enterprise_passive_asm
web_surface_fingerprint
crawler_url_intel
content_param_discovery
web_validation_safe
api_security_recon
secrets_supply_chain
cloud_takeover_exposure
ports_services_deep
dns_permutation_resolution
high_risk_manual_approval
sniper_ce_osint_plus
sniper_ce_recon_plugins
sniper_ce_web_plugins
sniper_ce_network_plugins
scanner_integrations_manual
legacy_high_risk_manual_only
```

## Helper commands

```bash
./scripts/tool-matrix.py
./scripts/check-tools.sh
./scripts/install-tools.sh
```

Dry-run mode does not require binaries to be installed. Live mode does.
