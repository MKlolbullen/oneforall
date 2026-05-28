export type Workspace = {
  id: string;
  name: string;
  description?: string | null;
  created_at: string;
};

export type Target = {
  id: string;
  workspace_id: string;
  value: string;
  type: string;
  in_scope: boolean;
  passive_allowed: boolean;
  active_allowed: boolean;
  notes?: string | null;
  created_at: string;
};

export type Run = {
  id: string;
  workspace_id: string;
  target_id: string;
  profile_id: string;
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
  risk: 'passive' | 'low_active' | 'medium_active' | 'high_active';
  created_at: string;
};

export type RunEvent = {
  id: string;
  run_id: string;
  sequence: number;
  type: string;
  level: string;
  message: string;
  payload: Record<string, unknown>;
  created_at: string;
};

export type ToolIO = {
  name: string;
  type: string;
  required?: boolean;
};

export type Tool = {
  id: string;
  name: string;
  category: string;
  description: string;
  binary?: string | null;
  risk: string;
  requires_authorization: boolean;
  inputs?: ToolIO[];
  outputs?: ToolIO[];
  default_timeout_seconds?: number;
  max_retries?: number;
  retry_backoff_seconds?: number;
  continue_on_error?: boolean;
  command?: { argv?: string[]; [k: string]: unknown };
  tags?: string[];
};

export type AdHocStep = {
  tool: string;
  argv_replace?: string[];
  argv_extra?: string[];
  timeout_seconds?: number;
  max_retries?: number;
  retry_backoff_seconds?: number;
  continue_on_error?: boolean;
};

export type AdHocRunCreate = {
  workspace_id: string;
  target_id: string;
  name: string;
  steps: AdHocStep[];
  params?: Record<string, unknown>;
};

export type Profile = {
  id: string;
  name: string;
  risk: string;
  description: string;
  steps: { tool: string }[];
};

export type DashboardStats = {
  workspaces: number;
  targets: number;
  runs: number;
  assets: number;
  findings: number;
  open_findings: number;
};

export type DashboardRunBrief = {
  id: string;
  profile_id: string;
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled' | string;
  risk: string;
  target_id: string;
  workspace_id: string;
  created_at: string | null;
  started_at: string | null;
  finished_at: string | null;
};

export type DashboardFindingBrief = {
  id: string;
  title: string;
  severity: string;
  category: string;
  status: string;
  run_id: string | null;
  tool_source: string | null;
  created_at: string;
};

export type DashboardTopTarget = {
  id: string;
  value: string;
  workspace_id: string;
  run_count: number;
};

export type DashboardTopTool = {
  tool_id: string;
  run_count: number;
};

export type DashboardAuditEntry = {
  sequence: number;
  action: string;
  target_kind: string | null;
  target_id: string | null;
  actor_role: string | null;
  created_at: string;
};

export type DashboardDetailed = {
  kpis: DashboardStats;
  runs_by_status: Record<string, number>;
  findings_by_severity: Record<string, number>;
  active_runs: DashboardRunBrief[];
  recent_runs: DashboardRunBrief[];
  recent_findings: DashboardFindingBrief[];
  top_targets: DashboardTopTarget[];
  top_tools: DashboardTopTool[];
  recent_audit: DashboardAuditEntry[];
};

export type FindingPage = {
  total: number;
  items: Finding[];
  facets: { severities: string[]; statuses: string[]; tools: string[] };
};

export type Artifact = {
  id: string;
  workspace_id: string;
  run_id: string;
  name: string;
  type: string;
  path: string;
  size_bytes: number;
  sha256?: string | null;
  storage_backend: 'local' | 's3' | string;
  bucket?: string | null;
  object_key?: string | null;
  content_type: string;
  created_at: string;
};


export type RunStep = {
  id: string;
  run_id: string;
  workspace_id: string;
  tool_id: string;
  tool_name: string;
  index: number;
  status: 'queued' | 'running' | 'retrying' | 'completed' | 'failed' | 'timed_out' | 'cancelled';
  attempt: number;
  max_retries: number;
  timeout_seconds: number;
  continue_on_error: boolean;
  exit_code?: number | null;
  error?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
  meta: Record<string, unknown>;
};


export type ToolAvailability = {
  tool_id: string;
  name: string;
  category: string;
  risk: string;
  requires_authorization: boolean;
  binary?: string | null;
  available: boolean;
  status: 'available' | 'missing' | 'broken' | 'not_required' | string;
  path?: string | null;
  version?: string | null;
  message?: string | null;
  install: Record<string, unknown>;
};

export type ProfileAvailability = {
  profile_id: string;
  name: string;
  runnable: boolean;
  total_tools: number;
  available_tools: number;
  missing_tools: string[];
  tools: ToolAvailability[];
};

export type PlatformConfig = Record<string, any>;

export type GrepPatternPack = {
  id?: string;
  name?: string;
  version?: string;
  settings?: Record<string, unknown>;
  patterns: Record<string, string>;
};

export type WordlistInfo = {
  name: string;
  path: string;
  entries: number;
  size_bytes: number;
  sample: string[];
};

export type PluginToggle = {
  group: string;
  plugin: string;
  enabled: boolean;
};

export type Asset = {
  id: string;
  workspace_id: string;
  run_id?: string | null;
  type: string;
  value: string;
  source: string;
  confidence: number;
  meta?: Record<string, unknown>;
  first_seen: string;
  last_seen: string;
};

export type Finding = {
  id: string;
  workspace_id: string;
  run_id?: string | null;
  asset_id?: string | null;
  title: string;
  severity: string;
  confidence: string;
  category: string;
  status: string;
  evidence?: string | null;
  tool_source?: string | null;
  meta?: Record<string, unknown>;
  created_at: string;
  updated_at: string;
};

export type TargetSummary = {
  target: Target;
  runs_total: number;
  runs_by_status: Record<string, number>;
  last_run_at: string | null;
  assets_total: number;
  assets_by_type: Record<string, number>;
  findings_total: number;
  findings_by_severity: Record<string, number>;
};

export type TargetTechRow = {
  url: string;
  title: string | null;
  status_code: number | null;
  tech: string[];
  server: string | null;
};

export type TargetTech = {
  tech: Record<string, number>;
  servers: Record<string, number>;
  by_url: TargetTechRow[];
};

export type HttpExchangeSummary = {
  id: string;
  started_at: string;
  method: string;
  url: string;
  host: string;
  response_status: number | null;
  response_size_bytes: number | null;
  duration_ms: number | null;
  step_index: number | null;
  tool_id: string | null;
  error: string | null;
};

export type HttpExchangeDetail = HttpExchangeSummary & {
  request_headers: Record<string, unknown>;
  request_body: string;
  request_body_truncated: boolean;
  response_headers: Record<string, unknown>;
  response_body: string;
  response_body_truncated: boolean;
};

export type NetworkPage = {
  total: number;
  items: HttpExchangeSummary[];
  hosts: string[];
  methods: string[];
  statuses: number[];
};

export type GraphNode = {
  id: string;
  kind: 'target' | 'domain' | 'ip' | 'url' | 'finding' | string;
  label: string;
  severity?: string | null;
  centrality: number;
  ref_id?: string | null;
};

export type GraphEdge = {
  source: string;
  target: string;
  kind: 'owns' | 'resolves_to' | 'hosts' | 'finds' | string;
};

export type GraphPayload = {
  nodes: GraphNode[];
  edges: GraphEdge[];
  stats: { by_kind?: Record<string, number>; node_count?: number; edge_count?: number; max_nodes?: number };
  truncated: boolean;
};

export type Advice = {
  id: string;
  workspace_id: string;
  kind: 'run_triage' | 'target_suggest_profile' | 'finding_explain' | 'ask' | string;
  ref_id: string | null;
  actor_id: string | null;
  model: string;
  prompt_tokens: number;
  completion_tokens: number;
  cached_tokens: number;
  summary: string;
  body: Record<string, unknown>;
};

export type WhoAmI = {
  id: string;
  username: string;
  role: 'viewer' | 'operator' | 'admin' | string;
  is_active: boolean;
  last_login_at: string | null;
};

export type AuditEvent = {
  sequence: number;
  actor_id: string | null;
  actor_role: 'viewer' | 'operator' | 'admin' | string | null;
  action: string;
  target_kind: string | null;
  target_id: string | null;
  payload: Record<string, unknown>;
  prev_signature: string | null;
  signature: string;
  created_at: string;
};

export type AuditBreak = { sequence: number; reason: string };

export type AuditPage = {
  ok: boolean;
  breaks: AuditBreak[];
  events: AuditEvent[];
};

export type LootItem = {
  id: string;
  workspace_id: string;
  run_id: string | null;
  finding_id: string | null;
  artifact_id: string | null;
  kind: 'secret' | 'credential' | 'takeover' | 'exposure' | 'vulnerability' | string;
  label: string;
  value_preview: string;
  severity: string;
  source_tool: string | null;
  host: string | null;
  meta: Record<string, unknown>;
  created_at: string;
};

export type LootPage = {
  total: number;
  items: LootItem[];
  facets: { kinds: string[]; severities: string[] };
};

export type LootSummary = {
  total: number;
  by_kind: Record<string, number>;
  by_severity: Record<string, number>;
  items: { id: string; kind: string; label: string; severity: string; source_tool: string | null; host: string | null }[];
};

export type RunBriefStep = { index: number; tool: string; status: string; error: string | null };
export type RunBriefFinding = {
  id: string;
  title: string;
  severity: string;
  category: string;
  tool_source: string | null;
  status: string;
  evidence_excerpt: string;
};
export type RunBriefArtifact = {
  id: string;
  name: string;
  type: string;
  size_bytes: number;
  sha256: string | null;
  content_url: string;
};

export type RunBrief = {
  run: {
    id: string;
    workspace_id: string;
    target_id: string;
    profile_id: string;
    status: string;
    risk: string;
    created_at: string | null;
    started_at: string | null;
    finished_at: string | null;
  };
  target: {
    id: string;
    value: string;
    type: string;
    in_scope: boolean;
    passive_allowed: boolean;
    active_allowed: boolean;
  } | null;
  counts: { steps: number; findings: number; assets: number; artifacts: number; loot: number };
  findings_by_severity: Record<string, number>;
  steps: RunBriefStep[];
  findings: RunBriefFinding[];
  assets_by_type: Record<string, string[]>;
  artifacts: RunBriefArtifact[];
  loot: LootSummary;
};
