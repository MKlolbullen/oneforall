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

export type Tool = {
  id: string;
  name: string;
  category: string;
  description: string;
  binary?: string | null;
  risk: string;
  requires_authorization: boolean;
  tags?: string[];
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
