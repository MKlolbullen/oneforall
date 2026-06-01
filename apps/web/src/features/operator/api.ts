import { getApiBaseUrl } from "../../lib/runtimeConfig";
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

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${getApiBaseUrl()}${path}`, {
    ...init,
    headers: {
      "content-type": "application/json",
      ...(init?.headers || {}),
    },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}: ${await res.text()}`);
  return res.json() as Promise<T>;
}

export const operatorApi = {
  workflows: () => request<WorkflowTemplate[]>("/api/operator/workflows"),
  roeDecisions: () => request<RoeDecision[]>("/api/operator/roe-decisions"),
  reports: () => request<ReportDraft[]>("/api/operator/reports/drafts"),
  updateReport: (draft: ReportDraft) => request<ReportDraft>(`/api/operator/reports/drafts/${draft.id}`, { method: "PATCH", body: JSON.stringify(draft) }),
  exportReport: (id: string, format: "md" | "html" | "pdf" | "json") => request<{ url: string }>(`/api/operator/reports/drafts/${id}/export`, { method: "POST", body: JSON.stringify({ format }) }),
  findingGroups: () => request<FindingGroup[]>("/api/operator/findings/groups"),
  markFindingStatus: (fingerprint: string, status: string) => request(`/api/operator/findings/groups/${fingerprint}/status`, { method: "PATCH", body: JSON.stringify({ status }) }),
  mergeFindingGroup: (fingerprint: string) => request(`/api/operator/findings/groups/${fingerprint}/merge`, { method: "POST" }),
  approvals: () => request<ApprovalRequest[]>("/api/operator/approvals"),
  approve: (id: string, reason: string) => request(`/api/operator/approvals/${id}/approve`, { method: "POST", body: JSON.stringify({ reason }) }),
  reject: (id: string, reason: string) => request(`/api/operator/approvals/${id}/reject`, { method: "POST", body: JSON.stringify({ reason }) }),
  workers: () => request<WorkerHealth[]>("/api/operator/workers"),
  scopePolicy: () => request<ScopePolicy>("/api/operator/scope-policy"),
  saveScopePolicy: (yaml: string) => request<ScopePolicy>("/api/operator/scope-policy", { method: "PUT", body: JSON.stringify({ yaml }) }),
  evaluateScope: (payload: Record<string, unknown>) => request<RoeDecision>("/api/operator/scope-policy/evaluate", { method: "POST", body: JSON.stringify(payload) }),
  evidence: () => request<EvidenceItem[]>("/api/operator/evidence"),
  mapEvidence: (evidenceId: string, sectionId: string) => request(`/api/operator/evidence/map`, { method: "POST", body: JSON.stringify({ evidenceId, sectionId }) }),
};
