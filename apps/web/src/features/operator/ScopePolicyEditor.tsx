import { useState } from "react";
import type { RoeDecision, ScopePolicy } from "./types";

export function ScopePolicyEditor({
  policy,
  onSave,
  onEvaluate,
}: {
  policy: ScopePolicy;
  onSave: (yaml: string) => Promise<ScopePolicy>;
  onEvaluate: (payload: Record<string, unknown>) => Promise<RoeDecision>;
}) {
  const [yaml, setYaml] = useState(policy.yaml);
  const [target, setTarget] = useState("api.example.com");
  const [toolId, setToolId] = useState("nuclei");
  const [risk, setRisk] = useState("high_active");
  const [result, setResult] = useState<RoeDecision | null>(null);

  return (
    <section className="occ-grid-2">
      <div className="occ-card">
        <h2>Scope Policy Editor</h2>
        <p>Backend ROE policy. Do not trust browser-only validation.</p>
        <textarea className="mono tall" value={yaml} onChange={(e) => setYaml(e.target.value)} />
        <button onClick={async () => setYaml((await onSave(yaml)).yaml)}>Save policy</button>
      </div>
      <div className="occ-card">
        <h3>Evaluate action</h3>
        <input value={target} onChange={(e) => setTarget(e.target.value)} />
        <input value={toolId} onChange={(e) => setToolId(e.target.value)} />
        <input value={risk} onChange={(e) => setRisk(e.target.value)} />
        <button onClick={async () => setResult(await onEvaluate({ target, toolId, risk }))}>Evaluate</button>
        {result && (
          <div className="occ-result">
            <span className={`occ-pill ${result.decision}`}>{result.decision}</span>
            <p>{result.reason}</p>
            <code>{result.matchedRule}</code>
          </div>
        )}
      </div>
    </section>
  );
}
