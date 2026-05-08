#!/usr/bin/env bash
# OneForAll v2 setup — installs Go + Python + recon tools.
# Designed to be idempotent: re-running is safe.

set -euo pipefail

echo "[*] OneForAll v2 setup"

command_exists() { command -v "$1" >/dev/null 2>&1; }

# 1. System packages
if command_exists apt; then
  echo "[*] Installing system packages (apt)"
  sudo apt update
  sudo apt install -y python3 python3-pip python3-venv git curl jq nmap build-essential whatweb
fi

# 2. Go
if ! command_exists go; then
  echo "[*] Installing Go 1.21"
  curl -fsSL https://go.dev/dl/go1.21.5.linux-amd64.tar.gz -o /tmp/go.tgz
  sudo tar -C /usr/local -xzf /tmp/go.tgz
  rm /tmp/go.tgz
fi
export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"
grep -q '/usr/local/go/bin' ~/.bashrc 2>/dev/null || echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc

# 3. Go-installed tools
echo "[*] Installing Go tools"
GO_TOOLS=(
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "github.com/projectdiscovery/chaos-client/cmd/chaos-client@latest"
  "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  "github.com/projectdiscovery/katana/cmd/katana@latest"
  "github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest"
  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "github.com/tomnomnom/assetfinder@latest"
  "github.com/lc/gau/v2/cmd/gau@latest"
  "github.com/tomnomnom/gf@latest"
  "github.com/tomnomnom/qsreplace@latest"
  "github.com/tomnomnom/anew@latest"
  "github.com/tomnomnom/unfurl@latest"
  "github.com/hahwul/dalfox/v2@latest"
  "github.com/hakluke/hakrawler@latest"
  "github.com/haccer/subjack@latest"
  "github.com/edoardottt/cariddi/cmd/cariddi@latest"
  "github.com/ThreatUnkown/jsubfinder@latest"
  "github.com/ffuf/ffuf/v2@latest"
)
for t in "${GO_TOOLS[@]}"; do
  echo "  go install $t"
  go install "$t" || echo "    !! failed: $t (skipping)"
done

# gf patterns (gf-patterns repo)
if [ ! -d "$HOME/.gf" ]; then
  git clone --quiet https://github.com/1ndianl33t/Gf-Patterns.git "$HOME/.gf"
  cp -r "$HOME/.gf"/*.json "$HOME/.gf"/ 2>/dev/null || true
fi

# 4. SecLists for wordlists
if [ ! -d /usr/share/seclists ]; then
  echo "[*] Cloning SecLists"
  sudo git clone --depth 1 https://github.com/danielmiessler/SecLists /usr/share/seclists || true
fi

# 5. Python venv + the package itself
echo "[*] Creating Python virtualenv"
python3 -m venv oneforall-env
# shellcheck disable=SC1091
source oneforall-env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .

# 6. Optional pip tools
echo "[*] Installing optional Python tools"
pip install arjun xsstrike-cli wappalyzer-python uro photon || true

# 7. API keys prompt
read -r -p "Enter your Chaos API key (or empty to skip): " chaos_key
read -r -p "Enter your Shodan API key (or empty to skip): " shodan_key
{
  [ -n "$chaos_key" ]  && echo "export CHAOS_CLIENT_KEY=\"$chaos_key\""
  [ -n "$shodan_key" ] && echo "export SHODAN_API_KEY=\"$shodan_key\""
} >> ~/.bashrc

cat <<'EOF'

[*] Setup complete.

Next steps:
  source oneforall-env/bin/activate
  python -m oneforall --help
  python -m oneforall init-scope -d example.com
  python -m oneforall s01_passive -d example.com

Optional manual installs (not on Go/pip):
  amass:        snap install amass / release binary
  feroxbuster:  cargo install feroxbuster
  x8:           cargo install x8
  nextnet:      go install / release binary
EOF
