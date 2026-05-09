#!/usr/bin/env bash
set -euo pipefail

# ReconForge optional tool bootstrapper.
# Dry-run mode does not require any of these tools. Live mode does.
# Run only inside an authorized lab/runner image where live execution is intended.

GO_BIN="${GO_BIN:-$(command -v go || true)}"
APT_GET="${APT_GET:-$(command -v apt-get || true)}"
NPM_BIN="${NPM_BIN:-$(command -v npm || true)}"
PIPX_BIN="${PIPX_BIN:-$(command -v pipx || true)}"

log() { printf '[*] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }

need_go() {
  if [[ -z "${GO_BIN}" ]]; then
    warn "go is not installed; skipping Go-based tools"
    return 1
  fi
}

go_install() {
  local pkg="$1"
  need_go || return 0
  log "go install ${pkg}"
  "${GO_BIN}" install "${pkg}" || warn "failed: go install ${pkg}"
}

apt_install() {
  local pkg="$1"
  if [[ -z "${APT_GET}" ]]; then
    warn "apt-get unavailable; skipping ${pkg}"
    return 0
  fi
  log "apt-get install ${pkg}"
  sudo apt-get install -y "${pkg}" || warn "failed: apt install ${pkg}"
}

pipx_install() {
  local pkg="$1"
  if [[ -z "${PIPX_BIN}" ]]; then
    warn "pipx unavailable; skipping ${pkg}"
    return 0
  fi
  log "pipx install ${pkg}"
  "${PIPX_BIN}" install "${pkg}" || warn "failed: pipx install ${pkg}"
}

npm_install_g() {
  local pkg="$1"
  if [[ -z "${NPM_BIN}" ]]; then
    warn "npm unavailable; skipping ${pkg}"
    return 0
  fi
  log "npm install -g ${pkg}"
  "${NPM_BIN}" install -g "${pkg}" || warn "failed: npm install -g ${pkg}"
}

if [[ -n "${APT_GET}" ]]; then
  log "Refreshing apt package index"
  sudo apt-get update || warn "apt update failed; continuing with best effort"
fi

log "Installing baseline OS tools"
for pkg in \
  curl git jq dnsutils nmap masscan rustscan gobuster nikto whatweb wafw00f sslscan testssl.sh dnstwist dnsrecon sqlmap whois finger smbclient nfs-common rpcbind smtp-user-enum cutycapt; do
  apt_install "$pkg"
done

log "Installing ProjectDiscovery/core Go tooling"
go_install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go_install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go_install github.com/projectdiscovery/httpx/cmd/httpx@latest
go_install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go_install github.com/projectdiscovery/katana/cmd/katana@latest
go_install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go_install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go_install github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go_install github.com/projectdiscovery/uncover/cmd/uncover@latest
go_install github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest
go_install github.com/projectdiscovery/asnmap/cmd/asnmap@latest
go_install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
go_install github.com/projectdiscovery/alterx/cmd/alterx@latest
go_install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go_install github.com/projectdiscovery/cloudlist/cmd/cloudlist@latest
go_install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

log "Installing recon/crawler/content Go tools"
go_install github.com/tomnomnom/assetfinder@latest
go_install github.com/tomnomnom/httprobe@latest
go_install github.com/tomnomnom/anew@latest
go_install github.com/tomnomnom/unfurl@latest
go_install github.com/tomnomnom/qsreplace@latest
go_install github.com/tomnomnom/gf@latest
go_install github.com/cgboal/sonarsearch/crobat@latest
go_install github.com/lc/gau/v2/cmd/gau@latest
go_install github.com/bp0lr/gauplus@latest
go_install github.com/hakluke/hakrawler@latest
go_install github.com/jaeles-project/gospider@latest
go_install github.com/ffuf/ffuf/v2@latest
go_install github.com/sensepost/gowitness@latest
go_install github.com/hahwul/dalfox/v2@latest
go_install github.com/edoardottt/cariddi/cmd/cariddi@latest
go_install github.com/d3mondev/puredns/v2@latest
go_install github.com/trufflesecurity/trufflehog/v3@latest
go_install github.com/gitleaks/gitleaks/v8@latest
go_install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest
go_install github.com/LukaSikic/subzy@latest
go_install github.com/haccer/subjack@latest
go_install github.com/Ice3man543/SubOver@latest

log "Installing Python/pipx tools where available"
pipx_install arjun
pipx_install uro
pipx_install waymore
pipx_install xnLinkFinder
pipx_install graphw00f
pipx_install dnsgen
pipx_install s3scanner
pipx_install theHarvester
pipx_install metagoofil
pipx_install h8mail
pipx_install ssh-audit
pipx_install webtech
pipx_install altdns

log "Installing npm tools where available"
npm_install_g retire

warn "Manual/runner-image tools still recommended: Amass v4, Findomain, Feroxbuster, WPScan, Kiterunner, EyeWitness, XSStrike, Corsy, SecretFinder, LinkFinder, cloud_enum, Commix, jwt_tool, Aquatone, Burp/ZAP/OpenVAS/Nessus integrations, JexBoss, Shocker, Smuggler."
warn "Some package names vary by distro. Treat this as a bootstrapper, not a reproducible pinned runner image."
log "Done. Ensure GOPATH/bin is in PATH, usually: export PATH=\"$HOME/go/bin:$PATH\""
log "Run ./scripts/check-tools.sh to see what is actually available on this host."
