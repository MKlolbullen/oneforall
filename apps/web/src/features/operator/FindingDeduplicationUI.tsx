import type { FindingGroup, FindingStatus } from "./types";

const statuses: FindingStatus[] = ["new", "duplicate", "reopened", "accepted_risk", "false_positive", "fixed"];

export function FindingDeduplicationUI({
  groups,
  onStatus,
  onMerge,
}: {
  groups: FindingGroup[];
  onStatus: (fingerprint: string, status: FindingStatus) => Promise<unknown>;
  onMerge: (fingerprint: string) => Promise<unknown>;
}) {
  return (
    <section className="occ-stack">
      <div className="occ-card">
        <h2>Finding Deduplication</h2>
        <p>Group repeated findings by stable fingerprint and keep reports clean.</p>
      </div>
      {groups.map((g) => (
        <article key={g.fingerprint} className="occ-card">
          <div className="occ-card-title">
            <h3>{g.title}</h3>
            <span className={`occ-pill sev-${g.severity}`}>{g.severity}</span>
          </div>
          <code>{g.fingerprint}</code>
          <p>{g.items.length} related finding(s). Canonical: {g.canonicalId}</p>
          <div className="occ-row wrap">
            {statuses.map((s) => <button key={s} onClick={() => void onStatus(g.fingerprint, s)}>{s}</button>)}
            <button className="danger" onClick={() => void onMerge(g.fingerprint)}>Merge duplicates</button>
          </div>
          <div className="occ-nested">
            {g.items.map((i) => (
              <div key={i.id} className="occ-list-row">
                <strong>{i.title}</strong>
                <span>{i.asset}</span>
                <span>{i.status}</span>
              </div>
            ))}
          </div>
        </article>
      ))}
    </section>
  );
}
