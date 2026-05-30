import type { AdHocRunCreate, Advice, APIKeyPublic, Artifact, Asset, AuditPage, CreatedAPIKey, DashboardDetailed, DashboardStats, Finding, FindingPage, GraphPayload, GrepPatternPack, HttpExchangeDetail, LootPage, NetworkPage, PlatformConfig, PluginToggle, Profile, ProfileAvailability, Run, RunBrief, RunEvent, RunStep, SavedWorkflow, SearchResults, Target, TargetSummary, TargetTech, Tool, ToolAvailability, UserPublic, Webhook, WebhookCreate, WebhookTestResult, WebhookUpdate, WhoAmI, WordlistInfo, WorkflowCreate, WorkflowUpdate, Workspace } from '../types';

import { getApiBaseUrl, getWsBaseUrl } from './runtimeConfig';

// Resolve at module load; the helpers honour window-injected config first
// (useful for an Electron shell that picks the sidecar URL at app start) and
// fall back to Vite's build-time env, then to localhost defaults.
const API_BASE_URL = getApiBaseUrl();
const WS_BASE_URL = getWsBaseUrl();

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
    ...init,
  });
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`${response.status} ${response.statusText}: ${body}`);
  }
  return response.json() as Promise<T>;
}

// 204 No Content + DELETE-style endpoints can't be JSON-parsed; request<T>
// would throw on response.json(). Use this helper for void endpoints.
async function requestVoid(path: string, init?: RequestInit): Promise<void> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
    ...init,
  });
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`${response.status} ${response.statusText}: ${body}`);
  }
}

export const api = {
  health: () => request<Record<string, unknown>>('/health'),
  stats: () => request<DashboardStats>('/api/dashboard/stats'),
  dashboardDetailed: () => request<DashboardDetailed>('/api/dashboard/detailed'),
  findings: (opts: {
    workspace_id?: string;
    severity?: string;
    status?: string;
    tool?: string;
    target_id?: string;
    q?: string;
    limit?: number;
    offset?: number;
  } = {}) => {
    const p = new URLSearchParams();
    for (const [k, v] of Object.entries(opts)) {
      if (v != null && v !== '') p.set(k, String(v));
    }
    const qs = p.toString();
    return request<FindingPage>(`/api/findings${qs ? `?${qs}` : ''}`);
  },
  updateFindingStatus: (findingId: string, status: string) =>
    request<Finding>(`/api/findings/${findingId}`, {
      method: 'PATCH', body: JSON.stringify({ status }),
    }),
  finding: (findingId: string) => request<Finding>(`/api/findings/${findingId}`),
  workspaces: () => request<Workspace[]>('/api/workspaces'),
  createWorkspace: (payload: { name: string; description?: string }) =>
    request<Workspace>('/api/workspaces', { method: 'POST', body: JSON.stringify(payload) }),
  targets: (workspaceId?: string) =>
    request<Target[]>(`/api/targets${workspaceId ? `?workspace_id=${workspaceId}` : ''}`),
  createTarget: (payload: Partial<Target>) =>
    request<Target>('/api/targets', { method: 'POST', body: JSON.stringify(payload) }),
  target: (id: string) => request<Target>(`/api/targets/${id}`),
  targetRuns: (id: string) => request<Run[]>(`/api/targets/${id}/runs`),
  targetAssets: (id: string, type?: string) =>
    request<Asset[]>(`/api/targets/${id}/assets${type ? `?type=${encodeURIComponent(type)}` : ''}`),
  targetFindings: (id: string) => request<Finding[]>(`/api/targets/${id}/findings`),
  targetSummary: (id: string) => request<TargetSummary>(`/api/targets/${id}/summary`),
  targetTech: (id: string) => request<TargetTech>(`/api/targets/${id}/tech`),
  runs: () => request<Run[]>('/api/runs'),
  createRun: (payload: { workspace_id: string; target_id: string; profile_id: string }) =>
    request<Run>('/api/runs', { method: 'POST', body: JSON.stringify(payload) }),
  createAdhocRun: (payload: AdHocRunCreate) =>
    request<Run>('/api/runs/adhoc', { method: 'POST', body: JSON.stringify(payload) }),
  tool: (toolId: string) => request<Tool>(`/api/tools/${toolId}`),
  cancelRun: (runId: string) => request<Run>(`/api/runs/${runId}/cancel`, { method: 'POST' }),
  runEvents: (runId: string) => request<RunEvent[]>(`/api/runs/${runId}/events`),
  runSteps: (runId: string) => request<RunStep[]>(`/api/runs/${runId}/steps`),
  runArtifacts: (runId: string) => request<Artifact[]>(`/api/runs/${runId}/artifacts`),
  artifactContentUrl: (artifactId: string) => `${API_BASE_URL}/api/artifacts/${artifactId}/content`,
  tools: () => request<Tool[]>('/api/tools'),
  toolAvailability: (force = false) => request<ToolAvailability[]>(`/api/tools/availability${force ? '?force=true' : ''}`),
  profileAvailability: (profileId: string, force = false) => request<ProfileAvailability>(`/api/tools/profiles/${profileId}/availability${force ? '?force=true' : ''}`),
  profiles: () => request<Profile[]>('/api/tools/profiles'),
  effectiveConfig: () => request<PlatformConfig>('/api/config/effective'),
  grepPatterns: () => request<GrepPatternPack>('/api/config/grep-patterns'),
  wordlists: () => request<WordlistInfo[]>('/api/config/wordlists'),
  pluginMatrix: () => request<PluginToggle[]>('/api/config/plugin-matrix'),
  reloadConfig: () => request<{ status: string }>('/api/config/reload', { method: 'POST' }),
  wsUrl: (runId: string) => `${WS_BASE_URL}/ws/runs/${runId}`,

  // Advisor — Claude-backed analysis. POSTs hit the model and persist; GETs
  // read back the cached row (200 with body or null when none yet).
  getRunTriage: (runId: string) =>
    request<Advice | null>(`/api/advisor/runs/${runId}/triage`),
  triageRun: (runId: string) =>
    request<Advice>(`/api/advisor/runs/${runId}/triage`, { method: 'POST' }),
  getTargetSuggestion: (targetId: string) =>
    request<Advice | null>(`/api/advisor/targets/${targetId}/suggest-profile`),
  suggestProfile: (targetId: string) =>
    request<Advice>(`/api/advisor/targets/${targetId}/suggest-profile`, { method: 'POST' }),
  getFindingExplain: (findingId: string) =>
    request<Advice | null>(`/api/advisor/findings/${findingId}/explain`),
  explainFinding: (findingId: string) =>
    request<Advice>(`/api/advisor/findings/${findingId}/explain`, { method: 'POST' }),
  askAdvisor: (payload: {
    question: string;
    workspace_id: string;
    run_id?: string;
    target_id?: string;
  }) =>
    request<Advice>('/api/advisor/ask', { method: 'POST', body: JSON.stringify(payload) }),

  runNetwork: (runId: string, opts: {
    host?: string;
    method?: string;
    status?: number;
    step?: number;
    limit?: number;
    offset?: number;
  } = {}) => {
    const params = new URLSearchParams();
    if (opts.host) params.set('host', opts.host);
    if (opts.method) params.set('method', opts.method);
    if (opts.status != null) params.set('status', String(opts.status));
    if (opts.step != null) params.set('step', String(opts.step));
    if (opts.limit != null) params.set('limit', String(opts.limit));
    if (opts.offset != null) params.set('offset', String(opts.offset));
    const qs = params.toString();
    return request<NetworkPage>(`/api/runs/${runId}/network${qs ? `?${qs}` : ''}`);
  },
  runExchange: (runId: string, exchangeId: string) =>
    request<HttpExchangeDetail>(`/api/runs/${runId}/network/${exchangeId}`),

  workspaceGraph: (workspaceId: string, maxNodes?: number) => {
    const qs = maxNodes != null ? `?max_nodes=${maxNodes}` : '';
    return request<GraphPayload>(`/api/workspaces/${workspaceId}/graph${qs}`);
  },

  // Build a download URL the browser can hit directly (anchor with href).
  // Browser sends cookies for same-origin; for the dev cross-origin case the
  // /api/findings/export response includes the bearer auth via the API
  // session cookie or is opened in a tab where the cookie is set. If you
  // need bearer-only export, switch this to a fetch+blob helper.
  findingsExportUrl: (opts: {
    workspace_id?: string;
    severity?: string;
    status?: string;
    tool?: string;
    target_id?: string;
    q?: string;
    format?: 'csv' | 'json' | 'md';
  } = {}) => {
    const p = new URLSearchParams();
    for (const [k, v] of Object.entries(opts)) {
      if (v != null && v !== '') p.set(k, String(v));
    }
    return `${API_BASE_URL}/api/findings/export${p.toString() ? `?${p}` : ''}`;
  },

  bulkTargets: (payload: {
    workspace_id: string;
    values: string[];
    type?: string;
    in_scope?: boolean;
    passive_allowed?: boolean;
    active_allowed?: boolean;
    notes?: string;
  }) => request<{
    created: Target[];
    skipped: { value: string; reason: string }[];
    workspace_id: string;
  }>('/api/targets/bulk', { method: 'POST', body: JSON.stringify(payload) }),

  rerun: (runId: string) => request<Run>(`/api/runs/${runId}/rerun`, { method: 'POST' }),

  // Loot — curated high-signal layer (secrets, takeovers, critical/high vulns).
  // See AGENTS.md and apps/api/app/services/loot.py.
  loot: (opts: {
    workspace_id?: string;
    run_id?: string;
    kind?: string;
    severity?: string;
    host?: string;
    limit?: number;
    offset?: number;
  } = {}) => {
    const p = new URLSearchParams();
    for (const [k, v] of Object.entries(opts)) {
      if (v != null && v !== '') p.set(k, String(v));
    }
    const qs = p.toString();
    return request<LootPage>(`/api/loot${qs ? `?${qs}` : ''}`);
  },
  lootExportUrl: (opts: {
    workspace_id?: string;
    run_id?: string;
    kind?: string;
    severity?: string;
    host?: string;
    format?: 'csv' | 'json' | 'md';
  } = {}) => {
    const p = new URLSearchParams();
    for (const [k, v] of Object.entries(opts)) {
      if (v != null && v !== '') p.set(k, String(v));
    }
    return `${API_BASE_URL}/api/loot/export${p.toString() ? `?${p}` : ''}`;
  },
  reindexRunLoot: (runId: string) =>
    request<{ run_id: string; indexed: number }>(`/api/loot/runs/${runId}/reindex`, { method: 'POST' }),

  // Agent — machine-facing structured run brief; cheaper than the advisor
  // because no LLM is involved.
  runBrief: (runId: string) => request<RunBrief>(`/api/agent/runs/${runId}/brief`),

  // Run report — html/json/md document with full findings + loot + assets.
  // Returns the absolute URL so the operator can click a real <a download>
  // and the browser handles the file dialog; the same URL works in a new tab.
  runReportUrl: (runId: string, format: 'html' | 'json' | 'md' = 'html') =>
    `${API_BASE_URL}/api/runs/${runId}/report?format=${format}`,
  targetReportUrl: (targetId: string, format: 'html' | 'json' | 'md' = 'html') =>
    `${API_BASE_URL}/api/targets/${targetId}/report?format=${format}`,

  // Identity + audit. /auth/audit is admin-only — non-admins get 403.
  me: () => request<WhoAmI>('/api/auth/me'),
  audit: (limit = 100) => request<AuditPage>(`/api/auth/audit?limit=${limit}`),

  // User admin (admin-only roster + role/active toggles).
  listUsers: () => request<UserPublic[]>('/api/auth/users'),
  createUser: (payload: { username: string; password: string; role: string }) =>
    request<WhoAmI>('/api/auth/users', { method: 'POST', body: JSON.stringify(payload) }),
  updateUser: (userId: string, payload: { role?: string; is_active?: boolean }) =>
    request<UserPublic>(`/api/auth/users/${userId}`, {
      method: 'PATCH', body: JSON.stringify(payload),
    }),

  // Per-user API keys. List + create + revoke. The token is only returned by
  // POST /api/auth/api-keys; it must be shown to the operator once and never
  // re-fetched (only its sha256 + prefix are persisted).
  listApiKeys: () => request<APIKeyPublic[]>('/api/auth/api-keys'),
  createApiKey: (name: string) =>
    request<CreatedAPIKey>('/api/auth/api-keys', {
      method: 'POST', body: JSON.stringify({ name }),
    }),
  revokeApiKey: (apiKeyId: string) =>
    requestVoid(`/api/auth/api-keys/${apiKeyId}`, { method: 'DELETE' }),

  // Saved Workflow Builder graphs (DB-backed). Body holds the steps[] used
  // at launch + a "graph" with the React Flow nodes/edges for the canvas.
  workflows: (workspaceId?: string) =>
    request<SavedWorkflow[]>(`/api/workflows${workspaceId ? `?workspace_id=${workspaceId}` : ''}`),
  workflow: (workflowId: string) =>
    request<SavedWorkflow>(`/api/workflows/${workflowId}`),
  createWorkflow: (payload: WorkflowCreate) =>
    request<SavedWorkflow>('/api/workflows', { method: 'POST', body: JSON.stringify(payload) }),
  updateWorkflow: (workflowId: string, payload: WorkflowUpdate) =>
    request<SavedWorkflow>(`/api/workflows/${workflowId}`, {
      method: 'PUT', body: JSON.stringify(payload),
    }),
  deleteWorkflow: (workflowId: string) =>
    requestVoid(`/api/workflows/${workflowId}`, { method: 'DELETE' }),
  launchWorkflow: (workflowId: string, payload: { target_id: string; params?: Record<string, unknown> }) =>
    request<Run>(`/api/workflows/${workflowId}/launch`, {
      method: 'POST', body: JSON.stringify(payload),
    }),
  workflowExportUrl: (workflowId: string, format: 'yaml' | 'json' = 'yaml') =>
    `${API_BASE_URL}/api/workflows/${workflowId}/export?format=${format}`,
  importWorkflow: (payload: { workspace_id: string; yaml: string; name?: string; description?: string }) =>
    request<SavedWorkflow>('/api/workflows/import', {
      method: 'POST', body: JSON.stringify(payload),
    }),

  // Outbound webhooks (Slack / Discord / generic JSON). DB-backed and
  // workspace-scoped — different engagements can route to different channels.
  webhooks: (workspaceId?: string) =>
    request<Webhook[]>(`/api/webhooks${workspaceId ? `?workspace_id=${workspaceId}` : ''}`),
  webhook: (webhookId: string) => request<Webhook>(`/api/webhooks/${webhookId}`),
  createWebhook: (payload: WebhookCreate) =>
    request<Webhook>('/api/webhooks', { method: 'POST', body: JSON.stringify(payload) }),
  updateWebhook: (webhookId: string, payload: WebhookUpdate) =>
    request<Webhook>(`/api/webhooks/${webhookId}`, {
      method: 'PUT', body: JSON.stringify(payload),
    }),
  deleteWebhook: (webhookId: string) =>
    requestVoid(`/api/webhooks/${webhookId}`, { method: 'DELETE' }),
  testWebhook: (webhookId: string) =>
    request<WebhookTestResult>(`/api/webhooks/${webhookId}/test`, { method: 'POST' }),

  // Cross-entity palette search. workspaceId is optional; when set, DB
  // results narrow to that scope (registry tools/profiles stay global).
  search: (q: string, opts: { workspaceId?: string; limit?: number } = {}) => {
    const p = new URLSearchParams({ q });
    if (opts.workspaceId) p.set('workspace_id', opts.workspaceId);
    if (opts.limit) p.set('limit', String(opts.limit));
    return request<SearchResults>(`/api/search?${p.toString()}`);
  },
};
