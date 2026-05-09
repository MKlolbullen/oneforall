import type { Advice, Artifact, Asset, DashboardStats, Finding, GrepPatternPack, PlatformConfig, PluginToggle, Profile, ProfileAvailability, Run, RunEvent, RunStep, Target, TargetSummary, TargetTech, Tool, ToolAvailability, WordlistInfo, Workspace } from '../types';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000';
const WS_BASE_URL = import.meta.env.VITE_WS_BASE_URL ?? 'ws://localhost:8000';

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

export const api = {
  health: () => request<Record<string, unknown>>('/health'),
  stats: () => request<DashboardStats>('/api/dashboard/stats'),
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
};
