import { useMemo, useState } from "react";
import type { Decision, RoeDecision } from "./types";

export function RoeDecisionTimeline({ decisions }: { decisions: RoeDecision[] }) {
  const [decision, setDecision] = useState<Decision | "all">("all");
  const [query, setQuery] = useState("");

  const filtered = useMemo(() => decisions.filter((d) => {
    const decisionOk = decision === "all" || d.decision === decision;
    const haystack = `${d.target} ${d.toolId} ${d.reason} ${d.matchedRule ?? ""}`.toLowerCase();
    return decisionOk && (!query || haystack.includes(query.toLowerCase()));
  }), [decisions, decision, query]);

  return (
    <section className="occ-stack">
      <div className="occ-card">
        <h2>ROE Decision Timeline</h2>
        <p>Every active action should leave a scope decision trace.</p>
        <div className="occ-row">
          <select value={decision} onChange={(e) => setDecision(e.target.value as Decision | "all")}>
            <option value="all">all decisions</option>
            <option value="allow">allow</option>
            <option value="deny">deny</option>
            <option value="require_approval">require approval</option>
            <option value="rate_limit">rate limit</option>
          </select>
          <input placeholder="Filter target, tool, reason..." value={query} onChange={(e) => setQuery(e.target.value)} />
        </div>
      </div>
      <div className="occ-timeline">
        {filtered.map((d) => (
          <article key={d.id} className="occ-timeline-item">
            <span className={`occ-dot ${d.decision}`} />
            <div className="occ-card">
              <div className="occ-card-title">
                <h3>{d.target}</h3>
                <span className={`occ-pill ${d.decision}`}>{d.decision}</span>
              </div>
              <p>{d.reason}</p>
              <div className="occ-metrics">
                <span>{d.toolId}</span>
                <span>{d.risk}</span>
                <span>{d.matchedRule || "no rule"}</span>
                <span>{new Date(d.createdAt).toLocaleString()}</span>
              </div>
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}
