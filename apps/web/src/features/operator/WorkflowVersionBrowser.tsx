import { useMemo, useState } from "react";
import type { WorkflowTemplate, WorkflowVersion } from "./types";

export function WorkflowVersionBrowser({ workflows }: { workflows: WorkflowTemplate[] }) {
  const [workflowId, setWorkflowId] = useState(workflows[0]?.id || "");
  const workflow = workflows.find((w) => w.id === workflowId) || workflows[0];
  const [left, setLeft] = useState("");
  const [right, setRight] = useState("");

  const versions = workflow?.versions || [];
  const active = versions.find((v) => v.status === "active");

  const selected = useMemo(() => ({
    l: versions.find((v) => v.id === left),
    r: versions.find((v) => v.id === right),
  }), [versions, left, right]);

  if (!workflow) return <section className="occ-card">No workflows found.</section>;

  return (
    <section className="occ-stack">
      <div className="occ-card">
        <h2>Workflow Version Browser</h2>
        <p>Track saved React Flow DAG versions, compare changes, and identify the active executable version.</p>
        <select value={workflow.id} onChange={(e) => setWorkflowId(e.target.value)}>
          {workflows.map((w) => <option key={w.id} value={w.id}>{w.name}</option>)}
        </select>
      </div>

      <div className="occ-grid">
        {versions.map((v) => <VersionCard key={v.id} version={v} active={active?.id === v.id} />)}
      </div>

      <div className="occ-card">
        <h3>Compare versions</h3>
        <div className="occ-row">
          <select value={left} onChange={(e) => setLeft(e.target.value)}>
            <option value="">Left version</option>
            {versions.map((v) => <option key={v.id} value={v.id}>v{v.version}</option>)}
          </select>
          <select value={right} onChange={(e) => setRight(e.target.value)}>
            <option value="">Right version</option>
            {versions.map((v) => <option key={v.id} value={v.id}>v{v.version}</option>)}
          </select>
        </div>
        {selected.l && selected.r && (
          <div className="occ-compare">
            <span>Nodes: {selected.l.nodes} → {selected.r.nodes}</span>
            <span>Edges: {selected.l.edges} → {selected.r.edges}</span>
            <span>{selected.r.changeSummary}</span>
          </div>
        )}
      </div>
    </section>
  );
}

function VersionCard({ version, active }: { version: WorkflowVersion; active: boolean }) {
  return (
    <article className="occ-card">
      <div className="occ-card-title">
        <h3>v{version.version}</h3>
        <span className={`occ-pill ${active ? "ok" : version.status}`}>{active ? "active" : version.status}</span>
      </div>
      <p>{version.changeSummary}</p>
      <div className="occ-metrics">
        <span>{version.nodes} nodes</span>
        <span>{version.edges} edges</span>
        <span>{version.createdBy}</span>
      </div>
    </article>
  );
}
