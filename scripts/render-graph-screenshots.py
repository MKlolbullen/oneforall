"""Render three time-slices of the same engagement against acme-bank.com:

  T+0    passive-recon only — subdomains discovered, urls probed, no findings
  T+15   active scan finds web-tier vulns (the original "attack" snapshot)
  T+45   internal pivot — netexec + impacket land creds, lateral movement
         hops onto two internal /16 hosts, more critical findings appear

Same color palette + edge kinds + centrality-driven sizing as the production
graph endpoint, so the three frames are directly comparable.

Outputs live under docs/screenshots/. Run with:

    python scripts/render-graph-screenshots.py
"""
from __future__ import annotations

import math
from pathlib import Path

import matplotlib.pyplot as plt
import networkx as nx
from matplotlib.lines import Line2D

REPO = Path(__file__).resolve().parents[1]
OUT_DIR = REPO / "docs" / "screenshots"
OUT_DIR.mkdir(parents=True, exist_ok=True)

KIND_COLORS = {
    "target":  "#22d3ee",
    "domain":  "#a78bfa",
    "url":     "#34d399",
    "ip":      "#f59e0b",
    "host":    "#fb923c",   # internal Windows host (separate kind so it stands out)
    "cred":    "#fbbf24",   # captured credential
    "finding": "#f472b6",
}
SEV_COLORS = {
    "critical": "#ef4444",
    "high":     "#f97316",
    "medium":   "#eab308",
    "low":      "#22c55e",
    "info":     "#64748b",
}
RING_RADIUS = {
    "target":  0,
    "domain":  3.6,
    "url":     6.4,
    "ip":      8.6,
    "host":    9.8,
    "cred":    10.6,
    "finding": 11.4,
}

target = "acme-bank.com"

DOMAINS = [
    "acme-bank.com", "www.acme-bank.com", "api.acme-bank.com",
    "admin.acme-bank.com", "auth.acme-bank.com", "dev.acme-bank.com",
    "staging.acme-bank.com", "vpn.acme-bank.com", "mail.acme-bank.com",
    "files.acme-bank.com", "internal.acme-bank.com", "jenkins.acme-bank.com",
]

URLS = [
    ("https://api.acme-bank.com/v1/users/{id}",  "api.acme-bank.com",     "10.0.4.21"),
    ("https://api.acme-bank.com/v1/transfer",     "api.acme-bank.com",     "10.0.4.21"),
    ("https://admin.acme-bank.com/login",         "admin.acme-bank.com",   "10.0.4.22"),
    ("https://admin.acme-bank.com/console",       "admin.acme-bank.com",   "10.0.4.22"),
    ("https://auth.acme-bank.com/oauth/token",    "auth.acme-bank.com",    "10.0.4.21"),
    ("https://dev.acme-bank.com/.git/config",     "dev.acme-bank.com",     "10.0.4.30"),
    ("https://staging.acme-bank.com/debug",       "staging.acme-bank.com", "10.0.4.30"),
    ("https://files.acme-bank.com/uploads/",      "files.acme-bank.com",   "10.0.4.40"),
    ("https://jenkins.acme-bank.com/script",      "jenkins.acme-bank.com", "10.0.4.41"),
    ("https://internal.acme-bank.com/wp-admin/",  "internal.acme-bank.com","10.0.4.42"),
]

# T+15 — web-tier findings (same set as the previous render)
FINDINGS_T15 = [
    ("Exposed .git repository",       "critical", "dev.acme-bank.com"),
    ("Jenkins script console RCE",    "critical", "jenkins.acme-bank.com"),
    ("WordPress admin reachable",     "high",     "internal.acme-bank.com"),
    ("Admin panel without MFA",       "high",     "admin.acme-bank.com"),
    ("Reflected XSS on /v1/users",    "high",     "api.acme-bank.com"),
    ("Verbose stacktrace on /debug",  "medium",   "staging.acme-bank.com"),
    ("Open S3 bucket (files/)",       "medium",   "files.acme-bank.com"),
    ("Mixed-content on /oauth/token", "low",      "auth.acme-bank.com"),
    ("subfinder + dnsx asset growth", "info",     "acme-bank.com"),
]

# T+45 — internal pivot adds two internal Windows hosts, captured credentials,
# and lateral-movement findings. These hang off the bridge IP that the
# Jenkins RCE gave us a foothold on (10.0.4.41).
INTERNAL_HOSTS = [
    ("DC01.acme.local",   "10.10.20.5"),
    ("FILES01.acme.local","10.10.20.18"),
    ("WS-FINANCE-07",     "10.10.20.42"),
]
CREDS = [
    ("svc_jenkins:S3cret!",    "10.0.4.41"),     # captured on jenkins host
    ("ACME\\administrator (NTLM)", "DC01.acme.local"),  # post-secretsdump
]
FINDINGS_T45 = FINDINGS_T15 + [
    ("Jenkins -> svc_jenkins creds",   "high",     "jenkins.acme-bank.com"),
    ("netexec smb -> SMB signing off", "medium",   "FILES01.acme.local"),
    ("impacket-secretsdump on DC01",   "critical", "DC01.acme.local"),
    ("Pass-the-hash WS-FINANCE-07",    "critical", "WS-FINANCE-07"),
    ("Open SMB share \\\\FILES01\\HR$",  "high",     "FILES01.acme.local"),
    ("GetUserSPNs -> 4 kerberoastable","high",     "DC01.acme.local"),
]


def build_graph(stage: str):
    """stage in {'passive','attack','lateral'}."""
    G = nx.Graph()
    kind = {}

    def add(nid, k):
        G.add_node(nid)
        kind[nid] = k

    t = f"target:{target}"
    add(t, "target")
    for d in DOMAINS:
        add(f"domain:{d}", "domain")
        G.add_edge(t, f"domain:{d}", kind="owns")
    for url, host, ip in URLS:
        uid = f"url:{url}"
        iid = f"ip:{ip}"
        add(uid, "url")
        if iid not in kind:
            add(iid, "ip")
        G.add_edge(f"domain:{host}", uid, kind="hosts")
        G.add_edge(uid, iid, kind="resolves_to")

    if stage == "passive":
        return G, kind, []   # no findings yet

    findings = list(FINDINGS_T15) if stage == "attack" else list(FINDINGS_T45)

    for i, (title, sev, host) in enumerate(findings):
        fid = f"finding:{i}"
        add(fid, "finding")
        G.add_edge(t, fid, kind="finds")
        # link the finding to whichever asset it's about
        candidate = f"domain:{host}"
        if candidate in kind:
            G.add_edge(candidate, fid, kind="finds")
        candidate = f"host:{host}"
        if candidate in kind:
            G.add_edge(candidate, fid, kind="finds")

    if stage == "lateral":
        # bridge IP we pivoted from (jenkins host)
        bridge = "ip:10.0.4.41"
        for name, ip in INTERNAL_HOSTS:
            hid = f"host:{name}"
            iid = f"ip:{ip}"
            add(hid, "host")
            if iid not in kind:
                add(iid, "ip")
            # internal host is reached *from* the bridge
            G.add_edge(bridge, iid, kind="pivots_to")
            G.add_edge(iid, hid, kind="resolves_to")
        for cred, source in CREDS:
            cid = f"cred:{cred}"
            add(cid, "cred")
            src_candidates = [f"host:{source}", f"ip:{source}"]
            for s in src_candidates:
                if s in kind:
                    G.add_edge(s, cid, kind="captures")
                    break
        # rewire the new findings to point at the right host nodes
        for i, (title, sev, host) in enumerate(findings):
            fid = f"finding:{i}"
            target_nid = f"host:{host}"
            if target_nid in kind and not G.has_edge(target_nid, fid):
                G.add_edge(target_nid, fid, kind="finds")

    return G, kind, findings


def layout(G, kind):
    cent = nx.betweenness_centrality(G)
    groups = {}
    for n, k in kind.items():
        groups.setdefault(k, []).append(n)
    for items in groups.values():
        items.sort(key=lambda n: (-cent[n], n))
    pos = {}
    offsets = {"domain": 0.0, "url": 0.18, "ip": 0.05,
               "host": 0.12, "cred": 0.0, "finding": 0.32}
    for k, items in groups.items():
        r = RING_RADIUS[k]
        if r == 0:
            for nid in items:
                pos[nid] = (0.0, 0.0)
            continue
        n = max(len(items), 1)
        for i, nid in enumerate(items):
            angle = 2 * math.pi * i / n + offsets.get(k, 0)
            pos[nid] = (math.cos(angle) * r, math.sin(angle) * r)
    return pos, cent


EDGE_STYLE = {
    "owns":        ("#475569", 0.9, 0.45),
    "hosts":       ("#475569", 0.9, 0.45),
    "resolves_to": ("#475569", 0.9, 0.45),
    "finds":       ("#f472b6", 1.6, 0.78),
    "pivots_to":   ("#fb923c", 2.0, 0.95),   # the dramatic edge
    "captures":    ("#fbbf24", 1.6, 0.85),
}


def draw(stage, ax, title, subtitle, kpi_line):
    G, kind, findings = build_graph(stage)
    pos, cent = layout(G, kind)
    finding_sev = {f"finding:{i}": sev for i, (_, sev, _) in enumerate(findings)}

    ax.set_facecolor("#060a12")
    ax.set_aspect("equal")
    ax.set_axis_off()
    ax.set_xlim(-14, 14)
    ax.set_ylim(-14, 14)

    for u, v, attrs in G.edges(data=True):
        c, lw, a = EDGE_STYLE.get(attrs.get("kind", ""), ("#475569", 0.9, 0.4))
        x0, y0 = pos[u]; x1, y1 = pos[v]
        ax.plot([x0, x1], [y0, y1], color=c, linewidth=lw, alpha=a, zorder=1)

    for nid, (x, y) in pos.items():
        k = kind[nid]
        base = KIND_COLORS[k]
        edge = SEV_COLORS[finding_sev[nid]] if k == "finding" else base
        size = 220 + cent[nid] * 4200
        if k == "target":
            size = max(size, 1500)
        if k in ("host", "cred"):
            size = max(size, 480)
        ax.scatter([x], [y], s=size, c=base, edgecolors=edge, linewidths=2.4,
                   zorder=3, alpha=0.95)

    def label_for(nid):
        k = kind[nid]
        val = nid.split(":", 1)[1]
        if k == "url":
            return val.split("/", 3)[-1][:18]
        if k == "domain":
            return val.split(".", 1)[0] if val.count(".") > 1 else val
        if k == "host":
            return val.split(".")[0]
        if k == "cred":
            return val[:24]
        if k == "finding":
            idx = int(val); title, sev, _ = findings[idx]
            return f"{sev[:1].upper()}: {title[:24]}"
        return val

    for nid, (x, y) in pos.items():
        k = kind[nid]
        if k == "target":
            ax.text(x, y, target, fontsize=10, fontweight="bold", color="#0f172a",
                    ha="center", va="center", zorder=4)
            continue
        r = math.hypot(x, y) or 1
        ox, oy = x + x / r * 0.55, y + y / r * 0.55
        if k == "finding":
            color = SEV_COLORS[finding_sev[nid]]; weight = "bold"
        elif k == "host":
            color = "#fdba74"; weight = "bold"
        elif k == "cred":
            color = "#fde047"; weight = "bold"
        else:
            color = "#cbd5e1"; weight = "normal"
        ax.text(ox, oy, label_for(nid), fontsize=7.5, color=color, weight=weight,
                ha="center", va="center", zorder=5,
                bbox=dict(facecolor="#0d1117", edgecolor="#1f2937",
                           boxstyle="round,pad=0.18", alpha=0.85))

    ax.text(-13.5, 13, title, color="#22d3ee", fontsize=15, fontweight="bold")
    ax.text(-13.5, 12.1, subtitle, color="#94a3b8", fontsize=9)
    ax.text(-13.5, 11.3, kpi_line, color="#fda4af", fontsize=9)


def render_single(stage, title, subtitle, kpi, out_name):
    fig, ax = plt.subplots(figsize=(13, 11), facecolor="#060a12")
    draw(stage, ax, title, subtitle, kpi)
    legend = [
        Line2D([0], [0], marker="o", linestyle="", color=KIND_COLORS["target"],  markersize=10, label="target"),
        Line2D([0], [0], marker="o", linestyle="", color=KIND_COLORS["domain"],  markersize=9,  label="domain"),
        Line2D([0], [0], marker="o", linestyle="", color=KIND_COLORS["url"],     markersize=8,  label="url"),
        Line2D([0], [0], marker="o", linestyle="", color=KIND_COLORS["ip"],      markersize=8,  label="ip"),
        Line2D([0], [0], marker="o", linestyle="", color=KIND_COLORS["host"],    markersize=9,  label="internal host"),
        Line2D([0], [0], marker="o", linestyle="", color=KIND_COLORS["cred"],    markersize=9,  label="captured cred"),
        Line2D([0], [0], marker="o", linestyle="", color=KIND_COLORS["finding"], markersize=9,  label="finding"),
        Line2D([0], [0], color="#fb923c", linewidth=2, label="pivots_to"),
        Line2D([0], [0], color="#fbbf24", linewidth=2, label="captures"),
        Line2D([0], [0], color="#f472b6", linewidth=2, label="finds"),
        Line2D([0], [0], color="#475569", linewidth=1.5, label="owns / hosts / resolves_to"),
    ]
    ax.legend(handles=legend, loc="lower right", facecolor="#0d1117",
              edgecolor="#1f2937", labelcolor="#cbd5e1", fontsize=8)
    plt.tight_layout()
    out = OUT_DIR / out_name
    plt.savefig(out, dpi=140, facecolor="#060a12", bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {out}")


def render_triptych(out_name):
    fig, axes = plt.subplots(1, 3, figsize=(34, 12), facecolor="#060a12")
    draw("passive", axes[0],
         "T+0   Passive recon",
         "subfinder + dnsx + httpx complete · no findings yet",
         "0 findings · 30 nodes / 31 edges")
    draw("attack", axes[1],
         "T+15   Active scan",
         "nuclei + dalfox + arjun running · web-tier findings landing",
         "9 findings (2 critical · 3 high) · 39 nodes / 49 edges")
    draw("lateral", axes[2],
         "T+45   Internal pivot",
         "jenkins RCE -> netexec + impacket on 10.10.20.0/24",
         "15 findings (4 critical · 6 high) · 49 nodes / 67 edges")
    plt.tight_layout()
    out = OUT_DIR / out_name
    plt.savefig(out, dpi=140, facecolor="#060a12", bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {out}")


if __name__ == "__main__":
    render_single("passive", "ReconForge — Network Graph",
                  "Workspace: redteam · Target: acme-bank.com · passive only",
                  "0 findings · subdomains + urls + ips wired up",
                  "network-graph-passive.png")
    render_single("attack", "ReconForge — Network Graph",
                  "Workspace: redteam · Target: acme-bank.com · web-tier scan",
                  "9 findings · 2 critical · 3 high · nuclei + dalfox active",
                  "network-graph-attack.png")
    render_single("lateral", "ReconForge — Network Graph",
                  "Workspace: redteam · Target: acme-bank.com · post-pivot",
                  "15 findings · 4 critical · 6 high · pivoted to internal /16",
                  "network-graph-lateral.png")
    render_triptych("network-graph-timeline.png")
