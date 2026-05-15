# ReconForge agent squad

Five Claude Code subagents covering the full lifecycle of a recon /
pentest engagement. One **leader** (Commander) orchestrates four
specialists who each own one phase of the work.

![Agent squad](./agents-squad.png)

| Agent | Role | Phase | Active tools |
|---|---|---|---|
| **commander** | Leader — delegates, gates, synthesises | all | none (uses `Task` to delegate) |
| **scout** | Passive recon, OSINT, scope validation | T+0 | subfinder, crt.sh, gau, WebFetch |
| **prober** | Active web-tier scanning + finding triage | T+15 | httpx, nuclei, dalfox, ffuf, katana |
| **pivot** | Internal AD / lateral movement | T+45 (gated) | netexec, impacket suite |
| **scribe** | Reporting, evidence packaging | end | MD + HTML render, exports |

## Engagement flow

```mermaid
flowchart LR
    user(["Operator"])
    user -->|"recon acme-bank.com"| C

    subgraph squad ["Agent squad"]
        C{{"<b>commander</b><br/>reads state, gates,<br/>synthesises"}}
        S[/"<b>scout</b><br/>passive · OSINT"/]
        P[/"<b>prober</b><br/>active · web-tier"/]
        V[/"<b>pivot</b><br/>internal · lateral"/]
        R[/"<b>scribe</b><br/>report · export"/]
    end

    subgraph platform ["ReconForge"]
        API["FastAPI<br/>/api/runs<br/>/api/findings<br/>/api/advisor/*"]
        ADV["Claude advisor<br/>(opus-4-7,<br/>adaptive thinking)"]
        DB[("workspace<br/>state")]
    end

    %% Leader delegation
    C -.-> |"Task: scout"| S
    C -.-> |"Task: prober"| P
    C -.-> |"Task: pivot<br/>(needs manual_approval)"| V
    C -.-> |"Task: scribe"| R

    %% Each specialist drives the platform
    S -->|"passive_recon<br/>enterprise_passive_asm"| API
    P -->|"web_quick<br/>web_deep"| API
    V -->|"internal_pivot<br/>(active_allowed + scope.yaml)"| API
    R -->|"GET /findings/export<br/>POST /advisor/findings/.../explain"| API

    API -->|reads/writes| DB
    API -->|"triage / suggest /<br/>analyze / pivot / explain"| ADV
    ADV -.->|structured advice| API

    %% Pivot gating
    P -->|"foothold landed<br/>handoff to commander"| C
    C -->|"approve internal scope?"| user
    user -->|yes| C

    classDef leader fill:#1a2e1a,stroke:#86efac,color:#bbf7d0
    classDef spec   fill:#0f1f2e,stroke:#22d3ee,color:#67e8f9
    classDef plat   fill:#1a1a2e,stroke:#c5a3ff,color:#e9d5ff
    classDef store  fill:#2e1a1a,stroke:#fca5a5,color:#fecaca
    class C leader
    class S,P,V,R spec
    class API,ADV plat
    class DB store
```

## Spawning

Each agent file in `.claude/agents/` is invokable two ways:

1. **Direct** — operator types `Use the prober subagent to run web_quick
   against api.acme-bank.com`.
2. **Via commander** — operator types `Recon acme-bank.com end to end`
   and Commander delegates via the `Task` tool, returning a single
   synthesized report.

## Hard gates (every agent honours these)

* `target.active_allowed === true` before any active probe (prober +
  pivot).
* A populated `scope.yaml` before pivot fires.
* `scope.require_high_risk_manual_approval === true` → Commander stops
  and asks before delegating to pivot.
* Anything in `packages/platform-config/sniper-inspired.yaml`
  `scope.default_out_of_scope` is always refused.
