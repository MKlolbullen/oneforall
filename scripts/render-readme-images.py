"""Render the marketing/UI imagery embedded in the top-level README.

Produces (under docs/screenshots/):

  banner.png            Hero banner: title, tagline, accent strokes
  workflow.png          Passive recon → active scan → internal pivot flow
  ui-dashboard.png      Simulated dashboard panel
  ui-run-console.png    Simulated live run console with event stream
  ui-tool-catalog.png   Simulated tool catalog grid

Same dark palette as the live UI's "Classic" theme + the existing graph
screenshots, so everything reads as one product. Re-run after touching the
palette to keep README art in sync:

    python scripts/render-readme-images.py
"""
from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Circle, Rectangle

REPO = Path(__file__).resolve().parents[1]
OUT_DIR = REPO / "docs" / "screenshots"
OUT_DIR.mkdir(parents=True, exist_ok=True)

BG          = "#0b1220"
PANEL       = "#111a2e"
PANEL_DEEP  = "#0d1426"
BORDER      = "#1f2a44"
TEXT        = "#e2e8f0"
MUTED       = "#94a3b8"
DIM         = "#64748b"
CYAN        = "#22d3ee"
PURPLE      = "#a78bfa"
GREEN       = "#34d399"
ORANGE      = "#f59e0b"
ORANGE_HOT  = "#fb923c"
PINK        = "#f472b6"
PINK_HOT    = "#ec4899"
RED         = "#ef4444"
YELLOW      = "#eab308"

SEV = {
    "critical": "#ef4444",
    "high":     "#f97316",
    "medium":   "#eab308",
    "low":      "#22c55e",
    "info":     "#64748b",
}


def new_canvas(w_in: float, h_in: float, dpi: int = 140):
    fig, ax = plt.subplots(figsize=(w_in, h_in), dpi=dpi)
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)
    ax.set_xlim(0, w_in * 100)
    ax.set_ylim(0, h_in * 100)
    ax.set_aspect("equal")
    ax.axis("off")
    return fig, ax


def panel(ax, x, y, w, h, *, fc=PANEL, ec=BORDER, lw=1.2, radius=0.6):
    box = FancyBboxPatch(
        (x, y), w, h,
        boxstyle=f"round,pad=0.0,rounding_size={radius}",
        linewidth=lw, edgecolor=ec, facecolor=fc,
    )
    ax.add_patch(box)
    return box


def chip(ax, x, y, text, *, fc=PANEL_DEEP, ec=BORDER, color=MUTED, fs=8):
    t = ax.text(
        x, y, text,
        fontsize=fs, color=color, ha="left", va="center",
        family="monospace",
        bbox=dict(
            boxstyle="round,pad=0.35",
            facecolor=fc, edgecolor=ec, linewidth=0.8,
        ),
    )
    return t


# ---------------------------------------------------------------------------
# 1. Hero banner
# ---------------------------------------------------------------------------
def render_banner():
    fig, ax = new_canvas(16, 5)

    # left accent bar
    ax.add_patch(Rectangle((0, 0), 6, 500, facecolor=CYAN, alpha=0.0))
    for i, c in enumerate([CYAN, PINK_HOT, PURPLE]):
        ax.add_patch(Rectangle((40 + i * 6, 60), 3, 380, facecolor=c, alpha=0.85))

    # title
    ax.text(80, 360, "ReconForge",
            fontsize=72, color=TEXT, weight="bold",
            family="sans-serif", ha="left", va="center")
    ax.text(82, 295, "multi-panel web GUI · recon · ASM · bug-bounty workflows",
            fontsize=18, color=MUTED, family="monospace",
            ha="left", va="center")

    # underline gradient strokes
    ax.plot([80, 380], [255, 255], color=CYAN, lw=2.2)
    ax.plot([390, 540], [255, 255], color=PINK_HOT, lw=2.2)
    ax.plot([550, 640], [255, 255], color=PURPLE, lw=2.2)

    # capability chips
    chips = [
        ("FastAPI control plane",   CYAN),
        ("Redis run queue",         PINK_HOT),
        ("MinIO artifacts",         PURPLE),
        ("137 tools · 24 profiles", GREEN),
        ("dry-run by default",      ORANGE),
    ]
    x = 80
    for label, color in chips:
        chip(ax, x, 175, label, fc=PANEL_DEEP, ec=color, color=color, fs=11)
        # monospace fs=11 ≈ 11-12 px per char; pad generously to avoid overlap
        x += len(label) * 12 + 36

    # right-side abstract graph motif (target -> domains -> findings)
    cx, cy = 1320, 250
    ax.add_patch(Circle((cx, cy), 22, facecolor=CYAN, edgecolor=BG, lw=2, zorder=3))
    ring_nodes = []
    import math
    for i in range(10):
        a = math.tau * i / 10 + 0.2
        rx = cx + 120 * math.cos(a)
        ry = cy + 120 * math.sin(a)
        ring_nodes.append((rx, ry))
        ax.plot([cx, rx], [cy, ry], color=BORDER, lw=0.8, zorder=1)
        ax.add_patch(Circle((rx, ry), 9, facecolor=PURPLE, edgecolor=BG, lw=1.4, zorder=3))
    # outer findings ring
    for i in range(6):
        a = math.tau * i / 6 + 0.6
        rx = cx + 200 * math.cos(a)
        ry = cy + 200 * math.sin(a)
        anchor = ring_nodes[i % len(ring_nodes)]
        ax.plot([anchor[0], rx], [anchor[1], ry], color=PINK, lw=0.9, alpha=0.7, zorder=1)
        sev = ["critical", "high", "medium", "high", "low", "critical"][i]
        ax.add_patch(Circle((rx, ry), 7, facecolor=SEV[sev], edgecolor=BG, lw=1.2, zorder=3))

    # footer tagline
    ax.text(80, 70, "passive recon → active scan → internal pivot",
            fontsize=12, color=DIM, family="monospace", ha="left", va="center")

    out = OUT_DIR / "banner.png"
    fig.savefig(out, facecolor=BG, bbox_inches="tight", pad_inches=0.1)
    plt.close(fig)
    print(f"wrote {out.relative_to(REPO)}")


# ---------------------------------------------------------------------------
# 2. Workflow illustration
# ---------------------------------------------------------------------------
def render_workflow():
    fig, ax = new_canvas(16, 7)

    ax.text(60, 640, "Engagement flow",
            fontsize=22, color=TEXT, weight="bold", family="sans-serif")
    ax.text(60, 605, "every step persists assets, findings, and artifacts as it runs",
            fontsize=12, color=MUTED, family="monospace")

    stages = [
        {
            "title": "Passive recon",
            "color": CYAN,
            "x": 60,
            "tools": ["subfinder", "crt.sh", "chaos", "dnsx", "httpx"],
            "outputs": ["domains: 142", "live urls: 87", "ips: 31"],
            "tag": "T+0",
        },
        {
            "title": "Active scan",
            "color": PINK_HOT,
            "x": 555,
            "tools": ["nuclei", "dalfox", "arjun", "ffuf", "gowitness"],
            "outputs": ["findings: 9", "critical: 2", "screenshots: 87"],
            "tag": "T+15",
        },
        {
            "title": "Internal pivot",
            "color": ORANGE_HOT,
            "x": 1050,
            "tools": ["netexec", "impacket", "kerbrute", "responder"],
            "outputs": ["hosts: 3", "creds: 2", "findings: 15"],
            "tag": "T+45",
        },
    ]

    for s in stages:
        x = s["x"]
        panel(ax, x, 200, 430, 360, fc=PANEL, ec=BORDER, radius=1.2)
        # left accent stripe
        ax.add_patch(Rectangle((x, 200), 6, 360, facecolor=s["color"]))
        # tag
        chip(ax, x + 22, 525, s["tag"], fc=PANEL_DEEP, ec=s["color"], color=s["color"], fs=10)
        # title
        ax.text(x + 22, 490, s["title"],
                fontsize=20, color=TEXT, weight="bold",
                family="sans-serif", ha="left", va="center")
        # tools
        ax.text(x + 22, 450, "tools",
                fontsize=10, color=DIM, family="monospace", ha="left", va="center")
        ty = 425
        for t in s["tools"]:
            ax.text(x + 22, ty, "· " + t,
                    fontsize=12, color=TEXT, family="monospace", ha="left", va="center")
            ty -= 22
        # divider
        ax.plot([x + 22, x + 408], [305, 305], color=BORDER, lw=0.8)
        # outputs
        ax.text(x + 22, 285, "yields",
                fontsize=10, color=DIM, family="monospace", ha="left", va="center")
        oy = 260
        for o in s["outputs"]:
            ax.text(x + 22, oy, "→ " + o,
                    fontsize=12, color=s["color"], family="monospace",
                    ha="left", va="center")
            oy -= 22

    # arrows between stages
    for x_from, x_to in [(490, 555), (985, 1050)]:
        arr = FancyArrowPatch(
            (x_from, 380), (x_to, 380),
            arrowstyle="-|>", mutation_scale=20,
            color=MUTED, lw=2.0,
        )
        ax.add_patch(arr)

    # bottom legend bar
    panel(ax, 60, 60, 1490, 90, fc=PANEL_DEEP, ec=BORDER, radius=1.0)
    legend = [
        ("scope-gated",   CYAN,    "active tools gated on authorization"),
        ("DAG artifacts", PURPLE,  "steps read upstream merged outputs"),
        ("live events",   PINK,    "Redis pub/sub → WebSocket → UI"),
        ("audit chain",   ORANGE,  "hash-chained, optional HMAC"),
    ]
    col_w = 1490 / len(legend)
    for i, (label, color, desc) in enumerate(legend):
        cx = 60 + i * col_w + 20
        ax.add_patch(Circle((cx, 115), 6, facecolor=color, edgecolor=BG, lw=1.2))
        ax.text(cx + 16, 117, label,
                fontsize=11, color=TEXT, weight="bold",
                family="monospace", ha="left", va="center")
        ax.text(cx + 16, 92, desc,
                fontsize=9, color=MUTED, family="monospace",
                ha="left", va="center")

    out = OUT_DIR / "workflow.png"
    fig.savefig(out, facecolor=BG, bbox_inches="tight", pad_inches=0.1)
    plt.close(fig)
    print(f"wrote {out.relative_to(REPO)}")


# ---------------------------------------------------------------------------
# helpers for UI mockups
# ---------------------------------------------------------------------------
def app_chrome(ax, w, h, *, active_tab="Dashboard"):
    # top bar
    panel(ax, 0, h - 50, w, 50, fc=PANEL_DEEP, ec=BORDER, radius=0.0)
    # traffic lights
    for i, c in enumerate(["#ef4444", "#eab308", "#22c55e"]):
        ax.add_patch(Circle((22 + i * 16, h - 25), 5, facecolor=c, edgecolor=BG, lw=0.6))
    # logo + title
    ax.add_patch(Rectangle((80, h - 32), 3, 14, facecolor=CYAN))
    ax.add_patch(Rectangle((86, h - 32), 3, 14, facecolor=PINK_HOT))
    ax.add_patch(Rectangle((92, h - 32), 3, 14, facecolor=PURPLE))
    ax.text(105, h - 25, "ReconForge",
            fontsize=12, color=TEXT, weight="bold",
            family="sans-serif", va="center")
    # nav tabs
    tabs = ["Dashboard", "Targets", "Runs", "Tools", "Graph", "Settings"]
    x = 290
    for t in tabs:
        is_active = t == active_tab
        color = CYAN if is_active else MUTED
        chip(ax, x, h - 25, t,
             fc=PANEL if is_active else PANEL_DEEP,
             ec=CYAN if is_active else BORDER,
             color=color, fs=9)
        x += len(t) * 10 + 40

    # right side: mode + user
    chip(ax, w - 280, h - 25, "MODE: dry_run",
         fc=PANEL_DEEP, ec=ORANGE, color=ORANGE, fs=9)
    chip(ax, w - 130, h - 25, "operator",
         fc=PANEL_DEEP, ec=BORDER, color=MUTED, fs=9)

    # left sidebar
    panel(ax, 0, 0, 60, h - 50, fc=PANEL_DEEP, ec=BORDER, radius=0.0)
    icons = [("◉", CYAN), ("⊞", MUTED), ("▶", MUTED), ("⚙", MUTED), ("◈", MUTED), ("≡", MUTED)]
    for i, (sym, c) in enumerate(icons):
        ax.text(30, h - 90 - i * 40, sym,
                fontsize=14, color=c, ha="center", va="center")


def render_ui_dashboard():
    W, H = 1600, 900
    fig, ax = new_canvas(16, 9)
    app_chrome(ax, W, H, active_tab="Dashboard")

    # main heading
    ax.text(85, H - 90, "Workspace · acme-bank engagement",
            fontsize=18, color=TEXT, weight="bold",
            family="sans-serif", va="center")
    ax.text(85, H - 115, "last run · 2 min ago · passive_recon · finished",
            fontsize=10, color=MUTED, family="monospace", va="center")

    # KPI cards
    cards = [
        ("Targets",   "12",  "+3 this week",       CYAN),
        ("Live runs", "2",   "queue depth 4",      PINK),
        ("Findings",  "47",  "9 critical · 14 high", ORANGE),
        ("Artifacts", "1.4k","384 MB stored",      PURPLE),
    ]
    card_y = H - 280
    card_h = 130
    card_w = 350
    x = 85
    for title, value, sub, color in cards:
        panel(ax, x, card_y, card_w, card_h, fc=PANEL, ec=BORDER, radius=1.0)
        ax.add_patch(Rectangle((x, card_y), 6, card_h, facecolor=color))
        ax.text(x + 24, card_y + card_h - 30, title,
                fontsize=11, color=MUTED, family="monospace", va="center")
        ax.text(x + 24, card_y + card_h - 75, value,
                fontsize=36, color=TEXT, weight="bold",
                family="sans-serif", va="center")
        ax.text(x + 24, card_y + 22, sub,
                fontsize=10, color=color, family="monospace", va="center")
        x += card_w + 14

    # left big panel: severity by target
    panel(ax, 85, 80, 720, 470, fc=PANEL, ec=BORDER, radius=1.0)
    ax.text(110, 510, "Findings by target",
            fontsize=14, color=TEXT, weight="bold",
            family="sans-serif", va="center")
    ax.text(110, 485, "stacked by severity · last 30 days",
            fontsize=9, color=MUTED, family="monospace", va="center")

    targets = ["acme-bank.com", "api.acme-bank.com", "admin.acme-bank.com",
               "jenkins.acme-bank.com", "internal.acme-bank.com",
               "files.acme-bank.com", "auth.acme-bank.com"]
    counts = [
        (2, 3, 4, 5, 1),
        (1, 2, 3, 4, 2),
        (1, 1, 2, 3, 1),
        (2, 1, 1, 2, 0),
        (0, 2, 3, 2, 2),
        (0, 1, 1, 2, 1),
        (0, 0, 2, 3, 1),
    ]
    sev_keys = ["critical", "high", "medium", "low", "info"]
    bar_x = 250
    bar_w = 540
    row_h = 36
    for i, (t, row) in enumerate(zip(targets, counts)):
        y = 460 - 30 - i * (row_h + 16)
        ax.text(240, y + row_h / 2, t,
                fontsize=10, color=TEXT, family="monospace",
                ha="right", va="center")
        cum = 0
        total = sum(row)
        for k, v in zip(sev_keys, row):
            if v == 0:
                continue
            seg_w = bar_w * (v / 18.0)
            ax.add_patch(Rectangle((bar_x + cum, y), seg_w, row_h, facecolor=SEV[k]))
            cum += seg_w
        ax.text(bar_x + cum + 8, y + row_h / 2, str(total),
                fontsize=10, color=MUTED, family="monospace", va="center")

    # right panel: recent runs
    panel(ax, 825, 80, 690, 470, fc=PANEL, ec=BORDER, radius=1.0)
    ax.text(850, 510, "Recent runs",
            fontsize=14, color=TEXT, weight="bold",
            family="sans-serif", va="center")
    ax.text(850, 485, "click to inspect events, findings, artifacts",
            fontsize=9, color=MUTED, family="monospace", va="center")

    runs = [
        ("R-2841", "passive_recon",     "acme-bank.com",          "finished", GREEN,  "2m"),
        ("R-2840", "web_quick",         "api.acme-bank.com",      "running",  CYAN,   "0:42"),
        ("R-2839", "attack_surface",    "admin.acme-bank.com",    "finished", GREEN,  "11m"),
        ("R-2838", "internal_pivot",    "jenkins.acme-bank.com",  "failed",   RED,    "3m"),
        ("R-2837", "param_discovery",   "files.acme-bank.com",    "queued",   MUTED,  "—"),
        ("R-2836", "secrets_scan",      "dev.acme-bank.com",      "finished", GREEN,  "8m"),
        ("R-2835", "takeover_check",    "auth.acme-bank.com",     "finished", GREEN,  "1m"),
    ]
    col_xs = [855, 940, 1100, 1290, 1430]
    headers = ["run", "profile", "target", "status", "elapsed"]
    for cx, hd in zip(col_xs, headers):
        ax.text(cx, 450, hd,
                fontsize=9, color=DIM, family="monospace",
                ha="left", va="center")
    ax.plot([850, 1500], [435, 435], color=BORDER, lw=0.8)
    for i, r in enumerate(runs):
        y = 410 - i * 48
        ax.text(col_xs[0], y, r[0],
                fontsize=10, color=TEXT, family="monospace", va="center")
        ax.text(col_xs[1], y, r[1],
                fontsize=10, color=PURPLE, family="monospace", va="center")
        ax.text(col_xs[2], y, r[2],
                fontsize=10, color=TEXT, family="monospace", va="center")
        chip(ax, col_xs[3], y, r[3], fc=PANEL_DEEP, ec=r[4], color=r[4], fs=9)
        ax.text(col_xs[4], y, r[5],
                fontsize=10, color=MUTED, family="monospace", va="center")

    out = OUT_DIR / "ui-dashboard.png"
    fig.savefig(out, facecolor=BG, bbox_inches="tight", pad_inches=0.0)
    plt.close(fig)
    print(f"wrote {out.relative_to(REPO)}")


def render_ui_run_console():
    W, H = 1600, 900
    fig, ax = new_canvas(16, 9)
    app_chrome(ax, W, H, active_tab="Runs")

    # header
    ax.text(85, H - 90, "Run R-2840 · web_quick · api.acme-bank.com",
            fontsize=18, color=TEXT, weight="bold",
            family="sans-serif", va="center")
    chip(ax, 85, H - 120, "running", fc=PANEL_DEEP, ec=CYAN, color=CYAN, fs=10)
    chip(ax, 165, H - 120, "step 4 / 7", fc=PANEL_DEEP, ec=PURPLE, color=PURPLE, fs=10)
    chip(ax, 260, H - 120, "elapsed 0:42", fc=PANEL_DEEP, ec=MUTED, color=MUTED, fs=10)
    chip(ax, 365, H - 120, "live · wss://", fc=PANEL_DEEP, ec=PINK, color=PINK, fs=10)

    # left: step DAG
    panel(ax, 85, 90, 420, 640, fc=PANEL, ec=BORDER, radius=1.0)
    ax.text(110, 700, "Profile steps",
            fontsize=13, color=TEXT, weight="bold",
            family="sans-serif", va="center")
    steps = [
        ("01", "subfinder",   "done",     GREEN, "12s"),
        ("02", "crt.sh",      "done",     GREEN, "8s"),
        ("03", "dnsx",        "done",     GREEN, "14s"),
        ("04", "httpx",       "running",  CYAN,  "0:08"),
        ("05", "katana",      "pending",  DIM,   "—"),
        ("06", "nuclei",      "pending",  DIM,   "—"),
        ("07", "normalize",   "pending",  DIM,   "—"),
    ]
    for i, (n, tool, status, color, t) in enumerate(steps):
        y = 660 - i * 78
        # connector
        if i > 0:
            ax.plot([135, 135], [y + 48, y + 30], color=BORDER, lw=1.2)
        ax.add_patch(Circle((135, y + 10), 12, facecolor=color, edgecolor=BG, lw=1.5, zorder=3))
        ax.text(135, y + 10, n, fontsize=8, color=BG, weight="bold",
                ha="center", va="center", zorder=4)
        ax.text(165, y + 20, tool, fontsize=12, color=TEXT,
                family="monospace", va="center")
        ax.text(165, y, f"{status} · {t}", fontsize=9, color=color,
                family="monospace", va="center")

    # right top: event stream
    panel(ax, 525, 380, 990, 350, fc=PANEL, ec=BORDER, radius=1.0)
    ax.text(550, 700, "Live event stream",
            fontsize=13, color=TEXT, weight="bold",
            family="sans-serif", va="center")
    ax.text(550, 680, "Redis pub/sub → WebSocket → ArtifactExplorer",
            fontsize=9, color=MUTED, family="monospace", va="center")
    events = [
        ("00:00:00", "run.queued",      "profile=web_quick params={...}",                MUTED),
        ("00:00:01", "step.started",    "01 subfinder argv=['subfinder','-d','...']",    CYAN),
        ("00:00:13", "asset.discovered","domain · api.acme-bank.com (subfinder)",        PURPLE),
        ("00:00:13", "step.finished",   "01 subfinder · 47 domains · exit=0",            GREEN),
        ("00:00:14", "step.started",    "02 crt.sh",                                     CYAN),
        ("00:00:22", "step.finished",   "02 crt.sh · 12 new domains · exit=0",           GREEN),
        ("00:00:23", "step.started",    "03 dnsx",                                       CYAN),
        ("00:00:37", "asset.discovered","ip · 10.0.4.21 (dnsx)",                         PURPLE),
        ("00:00:37", "step.finished",   "03 dnsx · 31 ips · exit=0",                     GREEN),
        ("00:00:38", "step.started",    "04 httpx · -l merged_domain_list.txt",          CYAN),
        ("00:00:46", "asset.discovered","url · https://api.acme-bank.com/v1 (httpx)",    PURPLE),
    ]
    for i, (ts, kind, msg, color) in enumerate(events):
        y = 655 - i * 24
        ax.text(550, y, ts, fontsize=9, color=DIM, family="monospace", va="center")
        ax.text(635, y, kind, fontsize=9, color=color, family="monospace", va="center")
        ax.text(805, y, msg, fontsize=9, color=TEXT, family="monospace", va="center")

    # right bottom: findings + artifacts
    panel(ax, 525, 90, 485, 270, fc=PANEL, ec=BORDER, radius=1.0)
    ax.text(550, 330, "Findings so far",
            fontsize=13, color=TEXT, weight="bold",
            family="sans-serif", va="center")
    findings = [
        ("critical", "Exposed .git on dev subdomain"),
        ("high",     "Jenkins console authn weak"),
        ("medium",   "Verbose error on /v1/transfer"),
        ("medium",   "Missing HSTS on auth host"),
        ("low",      "X-Powered-By header leak"),
    ]
    for i, (sev, msg) in enumerate(findings):
        y = 300 - i * 35
        chip(ax, 550, y, sev.upper(), fc=PANEL_DEEP, ec=SEV[sev], color=SEV[sev], fs=8)
        ax.text(640, y, msg, fontsize=10, color=TEXT, family="monospace", va="center")

    panel(ax, 1030, 90, 485, 270, fc=PANEL, ec=BORDER, radius=1.0)
    ax.text(1055, 330, "Artifacts",
            fontsize=13, color=TEXT, weight="bold",
            family="sans-serif", va="center")
    artifacts = [
        ("TXT",  "01_subfinder.stdout.txt", "4.2 KB",  "text",  GREEN),
        ("TXT",  "02_crtsh.stdout.txt",     "2.1 KB",  "text",  GREEN),
        ("JSON", "03_dnsx.json",            "11 KB",   "json",  CYAN),
        ("JSON", "04_httpx.jsonl",          "running", "jsonl", CYAN),
        ("PNG",  "screenshot.api.host.png", "84 KB",   "image", PINK),
    ]
    for i, (icon, name, size, kind, icon_color) in enumerate(artifacts):
        y = 300 - i * 35
        chip(ax, 1055, y, icon, fc=PANEL_DEEP, ec=icon_color, color=icon_color, fs=8)
        ax.text(1110, y, name, fontsize=10, color=TEXT, family="monospace", va="center")
        ax.text(1380, y, size, fontsize=9, color=MUTED, family="monospace",
                ha="right", va="center")
        chip(ax, 1400, y, kind, fc=PANEL_DEEP, ec=PURPLE, color=PURPLE, fs=8)

    out = OUT_DIR / "ui-run-console.png"
    fig.savefig(out, facecolor=BG, bbox_inches="tight", pad_inches=0.0)
    plt.close(fig)
    print(f"wrote {out.relative_to(REPO)}")


def render_ui_tool_catalog():
    W, H = 1600, 900
    fig, ax = new_canvas(16, 9)
    app_chrome(ax, W, H, active_tab="Tools")

    ax.text(85, H - 90, "Tool catalog · 137 tools · 24 profiles",
            fontsize=18, color=TEXT, weight="bold",
            family="sans-serif", va="center")
    ax.text(85, H - 115, "filter by category · live availability check against the runner image",
            fontsize=10, color=MUTED, family="monospace", va="center")

    # category filters
    cats = [
        ("recon", CYAN, True),
        ("network-intel", MUTED, False),
        ("probing", MUTED, False),
        ("fingerprinting", MUTED, False),
        ("crawling", MUTED, False),
        ("content-discovery", MUTED, False),
        ("vuln-scan", MUTED, False),
        ("secrets", MUTED, False),
        ("takeover", MUTED, False),
        ("cloud", MUTED, False),
    ]
    x = 85
    for name, color, active in cats:
        chip(ax, x, H - 155, name,
             fc=PANEL if active else PANEL_DEEP,
             ec=color, color=color, fs=10)
        x += len(name) * 11 + 32

    # tool grid
    # tool grid — list sized exactly to cols × rows below so nothing is dropped
    tools = [
        ("subfinder",   "recon",         "passive subdomain enum",       "ok",      GREEN),
        ("amass",       "recon",         "deep ASM enumeration",          "ok",      GREEN),
        ("chaos",       "recon",         "ProjectDiscovery PD dataset",   "ok",      GREEN),
        ("crt.sh",      "external-intel","certificate transparency",      "ok",      GREEN),
        ("dnsx",        "resolution",    "fast DNS resolver",             "ok",      GREEN),
        ("puredns",     "resolution",    "validated bruteforce",          "missing", RED),
        ("httpx",       "probing",       "HTTP toolkit · tech detect",    "ok",      GREEN),
        ("tlsx",        "tls-security",  "TLS data collection",           "ok",      GREEN),
        ("katana",      "crawling",      "modern next-gen crawler",       "ok",      GREEN),
        ("gau",         "url-discovery", "URLs from archives",            "ok",      GREEN),
        ("waybackurls", "url-discovery", "wayback URL mining",            "ok",      GREEN),
        ("ffuf",        "content-disc.", "fast web fuzzer",               "ok",      GREEN),
        ("arjun",       "parameter-disc","HTTP parameter discovery",      "ok",      GREEN),
        ("nuclei",      "vuln-scan",     "templated vuln scanner",        "ok",      GREEN),
        ("dalfox",      "xss-testing",   "XSS scanner",                   "ok",      GREEN),
        ("sqlmap",      "injection",     "SQL injection",                 "ok",      GREEN),
        ("trufflehog",  "secrets",       "git / fs secrets scan",         "ok",      GREEN),
        ("gitleaks",    "secrets",       "git secrets scan",              "ok",      GREEN),
        ("subzy",       "takeover",      "subdomain takeover check",      "warn",    YELLOW),
        ("cloud_enum",  "cloud",         "multi-cloud asset enum",        "ok",      GREEN),
    ]

    cols = 4
    rows = 5
    assert len(tools) == cols * rows, "tools list must match grid size"
    card_w = 360
    card_h = 110
    gap = 20
    start_x = 85
    start_y = H - 290
    for i, (name, cat, desc, status, color) in enumerate(tools):
        cx = start_x + (i % cols) * (card_w + gap)
        cy = start_y - (i // cols) * (card_h + gap)
        panel(ax, cx, cy - card_h, card_w, card_h, fc=PANEL, ec=BORDER, radius=0.8)
        # status pill on top-right
        chip(ax, cx + card_w - 70, cy - 20, status,
             fc=PANEL_DEEP, ec=color, color=color, fs=9)
        # name + cat
        ax.text(cx + 18, cy - 25, name,
                fontsize=14, color=TEXT, weight="bold",
                family="monospace", va="center")
        ax.text(cx + 18, cy - 50, cat,
                fontsize=9, color=PURPLE, family="monospace", va="center")
        # divider
        ax.plot([cx + 18, cx + card_w - 18], [cy - 65, cy - 65], color=BORDER, lw=0.6)
        # description
        ax.text(cx + 18, cy - 88, desc,
                fontsize=10, color=MUTED, family="monospace", va="center")

    out = OUT_DIR / "ui-tool-catalog.png"
    fig.savefig(out, facecolor=BG, bbox_inches="tight", pad_inches=0.0)
    plt.close(fig)
    print(f"wrote {out.relative_to(REPO)}")


def render_deployment_modes():
    """Three side-by-side panels: docker compose, hybrid dev, desktop.

    Encodes the same architectural choice the README's "How to run it" section
    documents — same palette so it reads as part of the rest of the imagery.
    """
    fig, ax = new_canvas(16, 8)

    ax.text(60, 740, "How to run it",
            fontsize=22, color=TEXT, weight="bold", family="sans-serif")
    ax.text(60, 705, "three deployment topologies share the same FastAPI + React stack",
            fontsize=12, color=MUTED, family="monospace")

    cards = [
        {
            "title": "Docker compose",
            "subtitle": "full prod-shaped stack",
            "color": CYAN,
            "x": 60,
            "tag": "RUNNER_MODE=queue",
            "boxes": [
                ("React UI", PURPLE),
                ("FastAPI", CYAN),
                ("Worker", PINK_HOT),
                ("Postgres", GREEN),
                ("Redis", ORANGE),
                ("MinIO/S3", PURPLE),
            ],
            "footer": "docker compose up\n→ closest to real deploy",
        },
        {
            "title": "Hybrid local",
            "subtitle": "infra in compose, app on host",
            "color": PINK_HOT,
            "x": 555,
            "tag": "RUNNER_MODE=queue",
            "boxes": [
                ("Vite dev (host)", PURPLE),
                ("uvicorn (host)", CYAN),
                ("python -m app.worker", PINK_HOT),
                ("Postgres (compose)", GREEN),
                ("Redis (compose)", ORANGE),
                ("local artifacts", PURPLE),
            ],
            "footer": "docker compose up postgres redis minio\n+ uvicorn --reload + npm run dev",
        },
        {
            "title": "Desktop app",
            "subtitle": "single process, no Docker",
            "color": GREEN,
            "x": 1050,
            "tag": "RUNNER_MODE=embedded",
            "boxes": [
                ("Electron main", PURPLE),
                ("React renderer (app://)", PURPLE),
                ("FastAPI + worker", CYAN),
                ("(no Postgres)", DIM),
                ("(no Redis)", DIM),
                ("SQLite + ~/.reconforge", GREEN),
            ],
            "footer": "cd apps/desktop && npm run dev\n→ Phases 1–3 (PRs #11, #16, #19)",
        },
    ]

    for c in cards:
        x = c["x"]
        panel(ax, x, 130, 430, 540, fc=PANEL, ec=BORDER, radius=1.2)
        ax.add_patch(Rectangle((x, 130), 6, 540, facecolor=c["color"]))
        chip(ax, x + 22, 640, c["tag"], fc=PANEL_DEEP, ec=c["color"],
             color=c["color"], fs=10)
        ax.text(x + 22, 600, c["title"],
                fontsize=20, color=TEXT, weight="bold",
                family="sans-serif", va="center")
        ax.text(x + 22, 575, c["subtitle"],
                fontsize=10, color=MUTED, family="monospace", va="center")
        # component stack
        ty = 535
        for label, color in c["boxes"]:
            panel(ax, x + 22, ty - 25, 386, 38, fc=PANEL_DEEP, ec=BORDER, radius=0.5)
            ax.add_patch(Rectangle((x + 22, ty - 25), 4, 38, facecolor=color))
            ax.text(x + 36, ty - 6, label,
                    fontsize=11, color=TEXT, family="monospace", va="center")
            ty -= 50
        # footer command
        ax.text(x + 22, 175, c["footer"],
                fontsize=9, color=MUTED, family="monospace", va="bottom")

    # arrows between cards to imply progression
    for x_from, x_to in [(490, 555), (985, 1050)]:
        arr = FancyArrowPatch(
            (x_from, 400), (x_to, 400),
            arrowstyle="-|>", mutation_scale=18,
            color=DIM, lw=1.4,
        )
        ax.add_patch(arr)

    # legend / outcome bar
    panel(ax, 60, 50, 1490, 50, fc=PANEL_DEEP, ec=BORDER, radius=0.8)
    ax.text(85, 75, "All three modes share the same code path; flipping RUNNER_MODE "
                    "and EVENT_TRANSPORT picks Redis vs. in-process.",
            fontsize=10, color=MUTED, family="monospace", va="center")

    out = OUT_DIR / "deployment-modes.png"
    fig.savefig(out, facecolor=BG, bbox_inches="tight", pad_inches=0.1)
    plt.close(fig)
    print(f"wrote {out.relative_to(REPO)}")


def main():
    render_banner()
    render_workflow()
    render_ui_dashboard()
    render_ui_run_console()
    render_ui_tool_catalog()
    render_deployment_modes()


if __name__ == "__main__":
    main()
