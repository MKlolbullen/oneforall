import { useEffect, useState } from "react";
import "./operator.css";
import { operatorApi } from "./api";
import { ApprovalQueue } from "./ApprovalQueue";
import { EvidenceToReportMapper } from "./EvidenceToReportMapper";
import { FindingDeduplicationUI } from "./FindingDeduplicationUI";
import { ReportBuilderEditor } from "./ReportBuilderEditor";
import { RoeDecisionTimeline } from "./RoeDecisionTimeline";
import { ScopePolicyEditor } from "./ScopePolicyEditor";
import { WorkerHealthDashboard } from "./WorkerHealthDashboard";
import { WorkflowVersionBrowser } from "./WorkflowVersionBrowser";
import type {
  ApprovalRequest,
  EvidenceItem,
  FindingGroup,
  ReportDraft,
  RoeDecision,
  ScopePolicy,
  WorkerHealth,
  WorkflowTemplate,
} from "./types";

type Tab = "workflows" | "roe" | "reports" | "dedup" | "approvals" | "workers" | "scope" | "evidence";

const tabs: Array<{ id: Tab; label: string }> = [
  { id: "workflows", label: "Workflow Versions" },
  { id: "roe", label: "ROE Timeline" },
  { id: "reports", label: "Report Builder" },
  { id: "dedup", label: "Deduplication" },
  { id: "approvals", label: "Approvals" },
  { id: "workers", label: "Workers" },
  { id: "scope", label: "Scope Policy" },
  { id: "evidence", label: "Evidence Mapping" },
];

export function OperatorControlCenter() {
  const [tab, setTab] = useState<Tab>("workflows");
  const [workflows, setWorkflows] = useState<WorkflowTemplate[]>([]);
  const [roe, setRoe] = useState<RoeDecision[]>([]);
  const [reports, setReports] = useState<ReportDraft[]>([]);
  const [findingGroups, setFindingGroups] = useState<FindingGroup[]>([]);
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [workers, setWorkers] = useState<WorkerHealth[]>([]);
  const [scope, setScope] = useState<ScopePolicy | null>(null);
  const [evidence, setEvidence] = useState<EvidenceItem[]>([]);
  const [error, setError] = useState<string | null>(null);

  async function refresh() {
    try {
      setError(null);
      const [wf, rd, rp, fg, ap, wk, sp, ev] = await Promise.all([
        operatorApi.workflows(),
        operatorApi.roeDecisions(),
        operatorApi.reports(),
        operatorApi.findingGroups(),
        operatorApi.approvals(),
        operatorApi.workers(),
        operatorApi.scopePolicy(),
        operatorApi.evidence(),
      ]);
      setWorkflows(wf);
      setRoe(rd);
      setReports(rp);
      setFindingGroups(fg);
      setApprovals(ap);
      setWorkers(wk);
      setScope(sp);
      setEvidence(ev);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  useEffect(() => {
    void refresh();
  }, []);

  const pendingApprovals = approvals.filter((a) => a.status === "pending").length;
  const criticalGroups = findingGroups.filter((g) => g.severity === "critical").length;
  const denied = roe.filter((r) => r.decision === "deny").length;

  return (
    <div className="occ-shell">
      <header className="occ-header">
        <div>
          <p className="occ-kicker">ReconForge</p>
          <h1>Operator Control Center</h1>
        </div>
        <div className="occ-header-stats">
          <span>{pendingApprovals} approvals</span>
          <span>{criticalGroups} critical groups</span>
          <span>{denied} denied actions</span>
          <button onClick={() => void refresh()}>Refresh</button>
        </div>
      </header>

      {error && <div className="occ-error">{error}</div>}

      <div className="occ-layout">
        <nav className="occ-tabs" aria-label="Operator control center sections">
          {tabs.map((t) => (
            <button key={t.id} className={tab === t.id ? "active" : ""} onClick={() => setTab(t.id)}>
              {t.label}
            </button>
          ))}
        </nav>

        <main className="occ-main">
          {tab === "workflows" && <WorkflowVersionBrowser workflows={workflows} />}
          {tab === "roe" && <RoeDecisionTimeline decisions={roe} />}
          {tab === "reports" && <ReportBuilderEditor reports={reports} evidence={evidence} onSave={operatorApi.updateReport} onExport={operatorApi.exportReport} />}
          {tab === "dedup" && <FindingDeduplicationUI groups={findingGroups} onStatus={operatorApi.markFindingStatus} onMerge={operatorApi.mergeFindingGroup} />}
          {tab === "approvals" && <ApprovalQueue approvals={approvals} onApprove={operatorApi.approve} onReject={operatorApi.reject} />}
          {tab === "workers" && <WorkerHealthDashboard workers={workers} />}
          {tab === "scope" && scope && <ScopePolicyEditor policy={scope} onSave={operatorApi.saveScopePolicy} onEvaluate={operatorApi.evaluateScope} />}
          {tab === "evidence" && <EvidenceToReportMapper evidence={evidence} reports={reports} onMap={operatorApi.mapEvidence} />}
        </main>
      </div>
    </div>
  );
}
