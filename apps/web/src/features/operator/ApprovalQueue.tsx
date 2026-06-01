import { useState } from "react";
import type { ApprovalRequest } from "./types";

export function ApprovalQueue({
  approvals,
  onApprove,
  onReject,
}: {
  approvals: ApprovalRequest[];
  onApprove: (id: string, reason: string) => Promise<unknown>;
  onReject: (id: string, reason: string) => Promise<unknown>;
}) {
  const [reason, setReason] = useState("Approved under current ROE.");

  return (
    <section className="occ-stack">
      <div className="occ-card">
        <h2>Approval Queue</h2>
        <p>High-risk tools and out-of-window actions must be approved before execution.</p>
        <textarea value={reason} onChange={(e) => setReason(e.target.value)} />
      </div>
      {approvals.map((a) => (
        <article key={a.id} className="occ-card">
          <div className="occ-card-title">
            <h3>{a.toolId} → {a.target}</h3>
            <span className={`occ-pill ${a.status}`}>{a.status}</span>
          </div>
          <p>{a.reason}</p>
          <div className="occ-metrics">
            <span>{a.risk}</span>
            <span>{a.requestedBy}</span>
            <span>{new Date(a.createdAt).toLocaleString()}</span>
          </div>
          {a.status === "pending" && (
            <div className="occ-row">
              <button onClick={() => void onApprove(a.id, reason)}>Approve</button>
              <button className="danger" onClick={() => void onReject(a.id, reason)}>Reject</button>
            </div>
          )}
        </article>
      ))}
    </section>
  );
}
