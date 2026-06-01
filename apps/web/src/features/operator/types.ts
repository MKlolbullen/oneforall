export type Decision = "allow" | "deny" | "require_approval" | "rate_limit";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type FindingStatus = "new" | "duplicate" | "reopened" | "accepted_risk" | "false_positive" | "fixed";
export type ApprovalStatus = "pending" | "approved" | "rejected";

export interface WorkflowVersion {
  id: string;
  version: number;
  createdAt: string;
  createdBy: string;
  nodes: number;
  edges: number;
  status: "draft" | "active" | "archived";
  changeSummary: string;
}

export interface WorkflowTemplate {
  id: string;
  name: string;
  description: string;
  versions: WorkflowVersion[];
}

export interface RoeDecision {
  id: string;
  createdAt: string;
  target: string;
  toolId: string;
  decision: Decision;
  reason: string;
  matchedRule?: string;
  risk: string;
  actor: string;
}

export interface ReportSection {
  id: string;
  title: string;
  body: string;
  evidenceIds: string[];
}

export interface ReportDraft {
  id: string;
  title: string;
  target: string;
  status: "draft" | "ready" | "exported";
  sections: ReportSection[];
  updatedAt: string;
}

export interface FindingItem {
  id: string;
  title: string;
  severity: Severity;
  asset: string;
  status: FindingStatus;
  firstSeenRun: string;
  lastSeenRun: string;
}

export interface FindingGroup {
  fingerprint: string;
  title: string;
  severity: Severity;
  canonicalId: string;
  status: FindingStatus;
  items: FindingItem[];
}

export interface ApprovalRequest {
  id: string;
  createdAt: string;
  target: string;
  toolId: string;
  risk: string;
  reason: string;
  requestedBy: string;
  status: ApprovalStatus;
}

export interface WorkerHealth {
  id: string;
  hostname: string;
  status: "healthy" | "degraded" | "offline";
  queueDepth: number;
  activeRuns: number;
  lastHeartbeatSeconds: number;
  toolsAvailable: number;
  toolsMissing: number;
}

export interface ScopePolicy {
  yaml: string;
  updatedAt: string;
  updatedBy: string;
}

export interface EvidenceItem {
  id: string;
  type: "artifact" | "finding" | "screenshot" | "http_exchange" | "loot";
  title: string;
  source: string;
  severity?: Severity;
  preview: string;
  mappedSectionIds: string[];
}
