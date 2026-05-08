# OneForAll v2

10-stage bug bounty / pentest automation, driven either from the CLI or from a Claude Code subagent (`.claude/agents/recon.md`).

Each stage emits structured JSON into `workspace/<target>/findings.json` plus raw tool output under `workspace/<target>/raw/sNN/...`, so the next stage (or Claude) can read what the previous stage found and decide what to do next.

## The 10 stages

| # | Stage | What it does |
|---|---|---|
| 1 | Passive DNS recon | crt.sh, Shodan, Censys, FOFA, BeVigil, ipinfo |
| 2 | Active DNS recon | subfinder, assetfinder, chaos-client, amass, nextnet + httpx liveness |
| 3 | Tech stack & ports | naabu → nmap -sV → whatweb / wappalyzer |
| 4 | Crawling | urlfinder, katana, photon, x8, arjun |
| 5 | Secrets | cariddi, gf (json/secrets), jsubfinder, local regex fallback |
| 6 | Content fuzzing | feroxbuster / ffuf / gobuster + hakrawler |
| 7 | **API testing** *(gated)* | OpenAPI/Swagger probe, replay, method confusion, fake-bearer |
| 8 | URL sorting | gf + heuristic classification into xss/ssrf/ssti/rce/sqli/lfi/redirect/idor |
| 9 | **Vulnerability scanning** *(gated)* | xsstrike, dalfox, nuclei (severity + tag-based) |
| 10 | Reporting | Markdown + HTML from findings.json |

Stages **7 and 9 are gated**: they refuse to run without both `--i-have-authorization` and a populated `scope.yaml`.

## Install

```bash
git clone https://github.com/MKlolbullen/oneforall.git
cd oneforall
chmod +x setup.sh && ./setup.sh
source oneforall-env/bin/activate
```

Optional API keys (export to your shell to enable extra passive sources):

```bash
export SHODAN_API_KEY=...
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
export FOFA_EMAIL=...
export FOFA_KEY=...
export BEVIGIL_API_KEY=...
export IPINFO_TOKEN=...
export CHAOS_CLIENT_KEY=...
```

Stages skip any source whose key is missing.

## Usage

```bash
# Full safe pipeline (no active probes)
python -m oneforall run -d example.com --stages 1,2,3,4,5,6,8,10

# Per stage
python -m oneforall s01_passive -d example.com
python -m oneforall s2 -d example.com           # short alias
cat workspace/example.com/findings.json | jq '.subdomains | length'

# Active stages — authorization required
python -m oneforall init-scope -d example.com   # edit workspace/example.com/scope.yaml
python -m oneforall run -d example.com --stages 7,9 --i-have-authorization

# Final report
python -m oneforall s10_report -d example.com
open workspace/example.com/report/report.html
```

## Driving it from Claude Code

The bundled subagent (`.claude/agents/recon.md`) teaches Claude how to chain the stages, read `findings.json` between them, and refuse to run active stages without authorization.

```
> Use the recon subagent to do passive recon on example.com
```

The subagent will:
1. Lay out `workspace/example.com/`.
2. Run s01 → s02 → s03 → s04 → s05 → s06 → s08 → s10.
3. Stop before s07 / s09 unless you explicitly authorize active probes.
4. Surface the path to `report.html` plus the top findings.

## Workspace layout

```
workspace/example.com/
├── findings.json        # canonical structured state
├── scope.yaml           # required for s07 / s09
├── raw/sNN/...          # raw tool output per stage
├── logs/sNN.log         # one log per stage
└── report/report.{md,html}
```

## Authorization & responsible use

- Only run this against assets you own or have explicit written permission to test (bug bounty scope, a signed engagement, your own lab).
- `scope.yaml` is the source of truth for what gets actively probed in stages 7 and 9; out-of-scope hosts are filtered before any request is sent.
- Stages 1–6, 8, 10 are passive or read-only enough that they're fine on any target you have a legitimate reason to research.

## Project layout

```
oneforall/
├── oneforall/                 # the package
│   ├── cli.py runner.py workspace.py tools.py auth.py schema.py
│   └── stages/s01_*.py … s10_*.py
├── templates/report.html.j2
├── .claude/agents/recon.md    # the subagent
└── setup.sh
```

## License

MIT.
