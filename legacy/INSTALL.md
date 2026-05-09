# OneForAll v2 — Installation

## Requirements

- Linux (Ubuntu/Debian recommended); macOS works for everything except a few Linux-only tools (naabu installs fine).
- Python 3.10+
- Go 1.20+ (for ProjectDiscovery / tomnomnom tools)
- `nmap`, `curl`, `git`, `jq`

## Quick start

```bash
git clone https://github.com/MKlolbullen/oneforall.git
cd oneforall
chmod +x setup.sh
./setup.sh
source oneforall-env/bin/activate
python -m oneforall --help
```

## What `setup.sh` installs

System packages: `python3 python3-venv git curl jq nmap build-essential`

Go-installed tools (one `go install` each):

- `subfinder`, `chaos-client`, `naabu`, `katana`, `urlfinder`, `nuclei`, `httpx` (ProjectDiscovery)
- `assetfinder`, `gau`, `gf`, `qsreplace`, `anew`, `unfurl` (tomnomnom)
- `dalfox`, `hakrawler`, `subjack`, `cariddi`, `jsubfinder`

Pip-installed: `arjun`, `xsstrike`, `wappalyzer`, `uro`, `photon` (where pip-installable)

Optional / manual:

- **amass** — `snap install amass` or download release binary
- **feroxbuster** — `cargo install feroxbuster` or grab a release
- **x8** — `cargo install x8`
- **ffuf** — `go install github.com/ffuf/ffuf/v2@latest`
- **whatweb** — `apt install whatweb` (Ubuntu) or `gem install whatweb`
- **nextnet** — go install or release binary
- **SecLists** — `git clone https://github.com/danielmiessler/SecLists /usr/share/seclists` (used by stage 6 for wordlists)

If a tool isn't on PATH, the corresponding stage logs a warning and skips it — installation is therefore incremental.

## API keys

Export these in your shell (or `~/.bashrc`) to enable extra passive sources:

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

## Verify the install

```bash
python -m oneforall --help
python -m oneforall init-scope -d example.com
python -m oneforall s01_passive -d example.com
cat workspace/example.com/findings.json | jq '.subdomains | length'
```

## Troubleshooting

- **`command not found: subfinder`** — make sure `~/go/bin` is on PATH.
- **`naabu` needs root for SYN scan** — run with `sudo -E` or use `-scan-type connect`.
- **Stage skipped a tool you have installed** — check the stage log under `workspace/<target>/logs/sNN.log`; the actual command run is recorded.
