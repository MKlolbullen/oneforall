import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { Activity, Boxes, Crosshair, LayoutDashboard, Network, RefreshCw, Settings as SettingsIcon, ShieldAlert, TerminalSquare, Wrench } from 'lucide-react';
import { ReactFlow, Background, Controls, Handle, Position } from '@xyflow/react';
import { api } from './lib/api';
import { ArtifactExplorer } from './lib/ArtifactExplorer';
import { classifyArtifact } from './lib/artifactKind';
import { TargetDetail } from './lib/TargetDetail';
import { applyTheme, loadTheme, persistTheme, THEMES, type Theme } from './lib/theme';
import type { Artifact, DashboardStats, GrepPatternPack, PlatformConfig, PluginToggle, Profile, ProfileAvailability, Run, RunEvent, RunStep, Target, Tool, ToolAvailability, WordlistInfo, Workspace } from './types';

type Page = 'dashboard' | 'targets' | 'runs' | 'tools' | 'workflow' | 'settings';

const pages: { id: Page; label: string; icon: ReactNode }[] = [
  { id: 'dashboard', label: 'Dashboard', icon: <LayoutDashboard size={16} /> },
  { id: 'targets', label: 'Targets', icon: <Crosshair size={16} /> },
  { id: 'runs', label: 'Runs', icon: <TerminalSquare size={16} /> },
  { id: 'tools', label: 'Tool Catalog', icon: <Wrench size={16} /> },
  { id: 'workflow', label: 'Workflow Builder', icon: <Network size={16} /> },
  { id: 'settings', label: 'Settings Pack', icon: <SettingsIcon size={16} /> },
];

function availabilityClass(check?: ToolAvailability | ProfileAvailability) {
  if (!check) return 'badge passive';
  const ok = 'runnable' in check ? check.runnable : check.available;
  return ok ? 'badge ok' : 'badge bad';
}

function availabilityLabel(check?: ToolAvailability) {
  if (!check) return 'unknown';
  if (check.status === 'not_required') return 'built-in';
  return check.status;
}

export function App() {
  const [page, setPage] = useState<Page>('dashboard');
  const [health, setHealth] = useState<Record<string, unknown>>({});
  const [theme, setTheme] = useState<Theme>(() => loadTheme());

  useEffect(() => {
    api.health().then(setHealth).catch(console.error);
  }, []);

  useEffect(() => {
    applyTheme(theme);
    persistTheme(theme);
  }, [theme]);

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand"><span className="brand-mark">RF</span><span>ReconForge</span></div>
        <nav className="nav">
          {pages.map((item) => (
            <button key={item.id} className={page === item.id ? 'active' : ''} onClick={() => setPage(item.id)}>
              <span className="row">{item.icon}{item.label}</span>
            </button>
          ))}
        </nav>
      </aside>
      <main className="main">
        <div className="topbar">
          <div className="row"><ShieldAlert size={18} color="#22d3ee" /> Authorized Security Control Plane</div>
          <div className="row">
            <span className="badge passive">{String(health.execution_mode ?? 'unknown')} mode</span>
            {health.live_execution_enabled === true ? <span className="badge active">live execution</span> : <span className="badge passive">dry-run safe</span>}
            <label className="theme-toggle muted" title="Switch UI theme">
              theme
              <select value={theme} onChange={(e) => setTheme(e.target.value as Theme)}>
                {THEMES.map((t) => <option key={t.id} value={t.id}>{t.label}</option>)}
              </select>
            </label>
          </div>
        </div>
        <div className="content">
          {page === 'dashboard' && <Dashboard />}
          {page === 'targets' && <Targets />}
          {page === 'runs' && <Runs />}
          {page === 'tools' && <Tools />}
          {page === 'workflow' && <Workflow />}
          {page === 'settings' && <SettingsPack />}
        </div>
      </main>
    </div>
  );
}

function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [runs, setRuns] = useState<Run[]>([]);

  useEffect(() => {
    api.stats().then(setStats).catch(console.error);
    api.runs().then(setRuns).catch(console.error);
  }, []);

  return (
    <div className="grid">
      <div className="grid cols-3">
        <Metric title="Targets" value={stats?.targets ?? 0} icon={<Crosshair />} />
        <Metric title="Assets" value={stats?.assets ?? 0} icon={<Boxes />} />
        <Metric title="Open Findings" value={stats?.open_findings ?? 0} icon={<ShieldAlert />} />
      </div>
      <div className="card">
        <div className="row space"><h3>Recent runs</h3><span className="muted">Control plane event history</span></div>
        <RunTable runs={runs} />
      </div>
    </div>
  );
}

function Metric({ title, value, icon }: { title: string; value: number; icon: ReactNode }) {
  return <div className="card"><div className="row space"><span className="muted">{title}</span>{icon}</div><div className="metric">{value}</div></div>;
}

function Targets() {
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [profileAvailability, setProfileAvailability] = useState<Record<string, ProfileAvailability>>({});
  const [health, setHealth] = useState<Record<string, unknown>>({});
  const [workspaceId, setWorkspaceId] = useState('');
  const [value, setValue] = useState('');
  const [activeAllowed, setActiveAllowed] = useState(false);
  const [selected, setSelected] = useState<Target | null>(null);

  const liveEnabled = health.live_execution_enabled === true;

  const reload = async () => {
    const [ws, tgts, prof, h] = await Promise.all([api.workspaces(), api.targets(), api.profiles(), api.health()]);
    setWorkspaces(ws); setTargets(tgts); setProfiles(prof); setHealth(h);
    if (!workspaceId && ws[0]) setWorkspaceId(ws[0].id);
    const checks = await Promise.all(prof.map((profile) => api.profileAvailability(profile.id).catch(() => null)));
    setProfileAvailability(Object.fromEntries(checks.filter(Boolean).map((check) => [check!.profile_id, check!])));
  };

  useEffect(() => { reload().catch(console.error); }, []);

  const createTarget = async () => {
    if (!workspaceId || !value) return;
    await api.createTarget({ workspace_id: workspaceId, value, type: 'domain', active_allowed: activeAllowed, passive_allowed: true, in_scope: true });
    setValue(''); setActiveAllowed(false); await reload();
  };

  const launch = async (target: Target, profileId: string) => {
    const check = profileAvailability[profileId];
    if (liveEnabled && check && !check.runnable) {
      alert(`Live run blocked locally: missing tools for ${check.name}: ${check.missing_tools.join(', ')}`);
      return;
    }
    try {
      const run = await api.createRun({ workspace_id: target.workspace_id, target_id: target.id, profile_id: profileId });
      alert(`Run queued: ${run.id}`);
    } catch (error) {
      alert(error instanceof Error ? error.message : String(error));
    }
  };

  if (selected) {
    return <TargetDetail target={selected} onClose={() => setSelected(null)} />;
  }

  return (
    <div className="grid cols-2">
      <div className="card">
        <h3>Add target</h3>
        <div className="grid">
          <select className="input" value={workspaceId} onChange={(e) => setWorkspaceId(e.target.value)}>
            {workspaces.map((w) => <option key={w.id} value={w.id}>{w.name}</option>)}
          </select>
          <input className="input" placeholder="example.com" value={value} onChange={(e) => setValue(e.target.value)} />
          <label className="row muted"><input type="checkbox" checked={activeAllowed} onChange={(e) => setActiveAllowed(e.target.checked)} /> Active scan authorization</label>
          <button className="btn" onClick={createTarget}>Create target</button>
        </div>
      </div>
      <div className="card">
        <h3>Launch guardrails</h3>
        <p className="muted">Dry-run mode ignores missing binaries and uses registry fixtures. Live mode blocks profiles with missing or broken tools before a worker can faceplant.</p>
        <div className="row"><span className="badge passive">mode</span><span>{liveEnabled ? 'live' : 'dry_run'}</span></div>
      </div>
      <div className="card" style={{ gridColumn: '1 / -1' }}>
        <h3>Targets</h3>
        <table className="table"><thead><tr><th>Value</th><th>Type</th><th>Scope</th><th>Active</th><th>Launch</th></tr></thead><tbody>
          {targets.map((t) => <tr key={t.id}><td><button className="link" onClick={() => setSelected(t)} type="button">{t.value}</button></td><td>{t.type}</td><td>{t.in_scope ? <span className="badge ok">in scope</span> : <span className="badge bad">out</span>}</td><td>{t.active_allowed ? <span className="badge active">authorized</span> : <span className="badge">blocked</span>}</td><td><div className="launch-grid">{profiles.map((p) => {
            const check = profileAvailability[p.id];
            const blocked = liveEnabled && check && !check.runnable;
            return <button key={p.id} className={blocked ? 'btn disabledish' : 'btn'} disabled={Boolean(blocked)} title={blocked ? `Missing: ${check?.missing_tools.join(', ')}` : 'Runnable'} onClick={() => launch(t, p.id)}>
              <span>{p.name}</span>
              <span className={availabilityClass(check)}>{check ? `${check.available_tools}/${check.total_tools}` : '?'}</span>
            </button>;
          })}</div></td></tr>)}
        </tbody></table>
      </div>
    </div>
  );
}

function Runs() {
  const [runs, setRuns] = useState<Run[]>([]);
  const [selected, setSelected] = useState<Run | null>(null);

  const reload = () => api.runs().then((loaded) => {
    setRuns(loaded);
    setSelected((current) => current ? loaded.find((run) => run.id === current.id) ?? current : current);
  }).catch(console.error);

  useEffect(() => { reload(); const timer = window.setInterval(reload, 3000); return () => window.clearInterval(timer); }, []);

  return <div className="grid cols-2">
    <div className="card"><h3>Runs</h3><RunTable runs={runs} onSelect={setSelected} /></div>
    <div className="card"><h3>Live console</h3>{selected ? <RunConsole run={selected} onChanged={reload} /> : <p className="muted">Select a run to attach to its event stream.</p>}</div>
  </div>;
}

function RunTable({ runs, onSelect }: { runs: Run[]; onSelect?: (run: Run) => void }) {
  return <table className="table"><thead><tr><th>ID</th><th>Profile</th><th>Status</th><th>Risk</th></tr></thead><tbody>
    {runs.map((r) => <tr key={r.id} onClick={() => onSelect?.(r)}><td>{r.id}</td><td>{r.profile_id}</td><td><span className={`badge ${r.status === 'completed' ? 'ok' : r.status === 'failed' ? 'bad' : 'passive'}`}>{r.status}</span></td><td>{r.risk}</td></tr>)}
  </tbody></table>;
}

function RunConsole({ run, onChanged }: { run: Run; onChanged?: () => void }) {
  const [events, setEvents] = useState<RunEvent[]>([]);
  const [artifacts, setArtifacts] = useState<Artifact[]>([]);
  const [steps, setSteps] = useState<RunStep[]>([]);
  const [selected, setSelected] = useState<Artifact | null>(null);

  const reloadArtifacts = () => api.runArtifacts(run.id).then(setArtifacts).catch(console.error);
  const reloadSteps = () => api.runSteps(run.id).then(setSteps).catch(console.error);

  const cancel = async () => {
    await api.cancelRun(run.id);
    await reloadSteps();
    onChanged?.();
  };

  useEffect(() => {
    setEvents([]);
    setSelected(null);
    reloadArtifacts();
    reloadSteps();
    api.runEvents(run.id).then(setEvents).catch(console.error);
    const socket = new WebSocket(api.wsUrl(run.id));
    socket.onmessage = (message) => {
      const event = JSON.parse(message.data) as RunEvent;
      setEvents((prev) => prev.some((item) => item.id === event.id) ? prev : [...prev, event]);
      if (event.type === 'run.step.artifact_created') reloadArtifacts();
      if (event.type.startsWith('run.step.') || event.type === 'run.cancel_requested') reloadSteps();
      if (event.type === 'run.completed' || event.type === 'run.failed' || event.type === 'run.cancelled') onChanged?.();
    };
    return () => socket.close();
  }, [run.id]);

  const canCancel = run.status === 'queued' || run.status === 'running';

  return <div className="grid">
    <div className="row space">
      <span className={`badge ${run.status === 'completed' ? 'ok' : run.status === 'failed' || run.status === 'cancelled' ? 'bad' : 'passive'}`}>{run.status}</span>
      <button className="btn danger" disabled={!canCancel} onClick={cancel}>Cancel run</button>
    </div>
    <div>
      <div className="row space"><strong>Steps</strong><span className="muted">timeout / retry policy</span></div>
      <table className="table compact"><thead><tr><th>#</th><th>Tool</th><th>Status</th><th>Try</th><th>Timeout</th></tr></thead><tbody>
        {steps.map((step) => <tr key={step.id}><td>{step.index}</td><td>{step.tool_name}</td><td><span className={`badge ${step.status === 'completed' ? 'ok' : step.status === 'failed' || step.status === 'timed_out' || step.status === 'cancelled' ? 'bad' : 'passive'}`}>{step.status}</span></td><td>{step.attempt}/{step.max_retries + 1}</td><td>{step.timeout_seconds}s</td></tr>)}
      </tbody></table>
    </div>
    <div className="console">{events.map((e) => <div key={e.id} className={`console-line ${e.level}`}>[{e.sequence.toString().padStart(3, '0')}] {e.type}: {e.message}</div>)}</div>
    <div>
      <div className="row space"><strong>Artifacts</strong><span className="muted">{artifacts.length} files · click to preview</span></div>
      <div className="artifact-list">{artifacts.map((artifact) => {
        const kind = classifyArtifact(artifact);
        const isSelected = selected?.id === artifact.id;
        return (
          <button
            key={artifact.id}
            className={`artifact ${isSelected ? 'selected' : ''}`}
            onClick={() => setSelected(isSelected ? null : artifact)}
            type="button"
          >
            <span className="row">
              <span className="badge passive">{kind}</span>
              <span className="mono">{artifact.name}</span>
            </span>
            <small>{artifact.storage_backend} · {(artifact.size_bytes / 1024).toFixed(1)} KB</small>
          </button>
        );
      })}</div>
      {selected && <ArtifactExplorer artifact={selected} onClose={() => setSelected(null)} />}
    </div>
  </div>;
}

function Tools() {
  const [tools, setTools] = useState<Tool[]>([]);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [availability, setAvailability] = useState<ToolAvailability[]>([]);
  const [profileChecks, setProfileChecks] = useState<Record<string, ProfileAvailability>>({});
  const [query, setQuery] = useState('');
  const [category, setCategory] = useState('all');
  const [risk, setRisk] = useState('all');
  const [availabilityFilter, setAvailabilityFilter] = useState('all');

  const reload = async (force = false) => {
    const [loadedTools, loadedProfiles, loadedAvailability] = await Promise.all([api.tools(), api.profiles(), api.toolAvailability(force)]);
    setTools(loadedTools); setProfiles(loadedProfiles); setAvailability(loadedAvailability);
    const checks = await Promise.all(loadedProfiles.map((profile) => api.profileAvailability(profile.id, force).catch(() => null)));
    setProfileChecks(Object.fromEntries(checks.filter(Boolean).map((check) => [check!.profile_id, check!])));
  };

  useEffect(() => { reload().catch(console.error); }, []);

  const availabilityByTool = useMemo(() => Object.fromEntries(availability.map((item) => [item.tool_id, item])), [availability]);
  const availableCount = availability.filter((item) => item.available).length;
  const missingCount = availability.filter((item) => !item.available).length;
  const categories = useMemo(() => ['all', ...Array.from(new Set(tools.map((t) => t.category))).sort()], [tools]);
  const riskCounts = useMemo(() => tools.reduce<Record<string, number>>((acc, tool) => {
    acc[tool.risk] = (acc[tool.risk] ?? 0) + 1;
    return acc;
  }, {}), [tools]);
  const categoryCounts = useMemo(() => tools.reduce<Record<string, number>>((acc, tool) => {
    acc[tool.category] = (acc[tool.category] ?? 0) + 1;
    return acc;
  }, {}), [tools]);

  const filtered = tools.filter((tool) => {
    const check = availabilityByTool[tool.id];
    const haystack = `${tool.name} ${tool.id} ${tool.category} ${tool.description} ${(tool.tags ?? []).join(' ')}`.toLowerCase();
    return (category === 'all' || tool.category === category)
      && (risk === 'all' || tool.risk === risk)
      && (availabilityFilter === 'all' || (availabilityFilter === 'available' ? check?.available : check && !check.available))
      && (!query || haystack.includes(query.toLowerCase()));
  });

  return <div className="grid">
    <div className="grid cols-3">
      <Metric title="Registered Tools" value={tools.length} icon={<Wrench />} />
      <Metric title="Available Tools" value={availableCount} icon={<Activity />} />
      <Metric title="Missing/Broken" value={missingCount} icon={<ShieldAlert />} />
    </div>
    <div className="grid cols-2">
      <div className="card">
        <div className="row space"><h3>Tool registry</h3><button className="btn small" onClick={() => reload(true).catch(console.error)}><RefreshCw size={14} /> Refresh checks</button></div>
        <div className="row space"><span className="muted">{filtered.length}/{tools.length} shown</span><span className="muted">Active-gated: {tools.filter((t) => t.requires_authorization).length}</span></div>
        <div className="toolbar availability-toolbar">
          <input className="input" placeholder="Search tools, tags, categories..." value={query} onChange={(e) => setQuery(e.target.value)} />
          <select className="input" value={category} onChange={(e) => setCategory(e.target.value)}>
            {categories.map((item) => <option key={item} value={item}>{item === 'all' ? 'All categories' : `${item} (${categoryCounts[item] ?? 0})`}</option>)}
          </select>
          <select className="input" value={risk} onChange={(e) => setRisk(e.target.value)}>
            <option value="all">All risks</option>
            {['passive', 'low_active', 'medium_active', 'high_active'].map((item) => <option key={item} value={item}>{item} ({riskCounts[item] ?? 0})</option>)}
          </select>
          <select className="input" value={availabilityFilter} onChange={(e) => setAvailabilityFilter(e.target.value)}>
            <option value="all">All availability</option>
            <option value="available">Available</option>
            <option value="missing">Missing/broken</option>
          </select>
        </div>
        <table className="table"><thead><tr><th>Tool</th><th>Availability</th><th>Category</th><th>Risk</th><th>Auth</th><th>Tags</th></tr></thead><tbody>{filtered.map((t) => {
          const check = availabilityByTool[t.id];
          return <tr key={t.id}>
            <td><strong>{t.name}</strong><br /><span className="muted mono">{t.id}{t.binary ? ` · ${t.binary}` : ''}</span></td>
            <td><span className={availabilityClass(check)} title={check?.message ?? ''}>{availabilityLabel(check)}</span><br /><span className="muted mono">{check?.path ?? check?.message ?? 'not checked'}</span></td>
            <td>{t.category}</td>
            <td><span className={t.risk === 'passive' ? 'badge passive' : t.risk === 'high_active' ? 'badge bad' : 'badge active'}>{t.risk}</span></td>
            <td>{t.requires_authorization ? <span className="badge active">required</span> : <span className="badge passive">no</span>}</td>
            <td><div className="tag-list">{(t.tags ?? []).slice(0, 4).map((tag) => <span key={tag} className="tag">{tag}</span>)}</div></td>
          </tr>;
        })}</tbody></table>
      </div>
      <div className="card"><h3>Profiles</h3>{profiles.map((p) => {
        const check = profileChecks[p.id];
        return <div key={p.id} className="card profile-card"><div className="row space"><strong>{p.name}</strong><span className={availabilityClass(check)}>{check ? `${check.available_tools}/${check.total_tools}` : 'unchecked'}</span></div><p className="muted">{p.description}</p>{check && !check.runnable && <p className="warning-text">Missing: {check.missing_tools.join(', ')}</p>}<code>{p.steps.map((s) => s.tool).join(' -> ')}</code></div>;
      })}</div>
    </div>
  </div>;
}


function SettingsPack() {
  const [config, setConfig] = useState<PlatformConfig | null>(null);
  const [patterns, setPatterns] = useState<GrepPatternPack | null>(null);
  const [wordlists, setWordlists] = useState<WordlistInfo[]>([]);
  const [plugins, setPlugins] = useState<PluginToggle[]>([]);

  const reload = async () => {
    const [cfg, pats, words, plugs] = await Promise.all([
      api.effectiveConfig(),
      api.grepPatterns(),
      api.wordlists(),
      api.pluginMatrix(),
    ]);
    setConfig(cfg); setPatterns(pats); setWordlists(words); setPlugins(plugs);
  };

  useEffect(() => { reload().catch(console.error); }, []);

  const runtime = config?.runtime ?? {};
  const scope = config?.scope ?? {};
  const integrations = config?.integrations ?? {};
  const webBrute = config?.web_bruteforce ?? {};
  const nmap = config?.nmap ?? {};
  const enabledPlugins = plugins.filter((item) => item.enabled).length;
  const pluginGroups = Array.from(new Set(plugins.map((item) => item.group))).sort();

  return <div className="grid">
    <div className="grid cols-3">
      <Metric title="Enabled Plugins" value={enabledPlugins} icon={<Activity />} />
      <Metric title="Wordlists" value={wordlists.length} icon={<Boxes />} />
      <Metric title="Grep Patterns" value={Object.keys(patterns?.patterns ?? {}).length} icon={<ShieldAlert />} />
    </div>

    <div className="card">
      <div className="row space"><h3>Sn1per-style settings pack</h3><button className="btn small" onClick={() => api.reloadConfig().then(() => reload()).catch(console.error)}><RefreshCw size={14} /> Reload</button></div>
      <p className="muted">Clean-room Sn1per CE-inspired operational toggles translated into ReconForge policy/config. This layer controls integrations, scan stages, wordlists, Nmap ports, grep patterns and safety limits.</p>
    </div>

    <div className="grid cols-2">
      <div className="card">
        <h3>Runtime guardrails</h3>
        <KeyValue label="Max hosts" value={runtime.max_hosts} />
        <KeyValue label="Threads" value={runtime.threads} />
        <KeyValue label="Max JavaScript files" value={runtime.max_javascript_files} />
        <KeyValue label="Reports" value={runtime.report_enabled ? 'enabled' : 'disabled'} />
        <KeyValue label="Loot/artifacts" value={runtime.loot_enabled ? 'enabled' : 'disabled'} />
        <KeyValue label="High-risk approval" value={scope.require_high_risk_manual_approval ? 'required' : 'not required'} />
        <KeyValue label="Active auth" value={scope.require_active_authorization ? 'required' : 'not required'} />
      </div>
      <div className="card">
        <h3>Dynamic scanner integrations</h3>
        {Object.entries(integrations).filter(([, value]) => typeof value === 'object' && value !== null).slice(0, 8).map(([name, value]) => {
          const record = value as Record<string, unknown>;
          return <div key={name} className="integration-row"><strong>{name}</strong><span className={record.enabled ? 'badge active' : 'badge passive'}>{record.enabled ? 'enabled' : 'disabled'}</span><small className="muted">{String(record.host ?? record.service ?? record.webhook_env ?? '')}</small></div>;
        })}
      </div>
      <div className="card">
        <h3>Web brute-force stages</h3>
        <KeyValue label="Stealth" value={webBrute.stealth_scan ? 'on' : 'off'} />
        <KeyValue label="Common" value={webBrute.common_scan ? 'on' : 'off'} />
        <KeyValue label="Full" value={webBrute.full_scan ? 'on' : 'off'} />
        <KeyValue label="Exploit paths" value={webBrute.exploit_scan ? 'on' : 'off'} />
        <KeyValue label="Extensions" value={webBrute.extensions} />
        <KeyValue label="Exclude codes" value={(webBrute.exclude_status_codes ?? []).join(', ')} />
      </div>
      <div className="card">
        <h3>Nmap profiles</h3>
        <KeyValue label="Quick ports" value={nmap.quick_ports} />
        <KeyValue label="Default ports" value={nmap.default_ports} />
        <KeyValue label="Full ports" value={nmap.full_ports} />
        <KeyValue label="Options" value={nmap.options} />
      </div>
    </div>

    <div className="grid cols-2">
      <div className="card">
        <h3>Plugin matrix</h3>
        {pluginGroups.map((group) => <div key={group} className="plugin-group">
          <div className="row space"><strong>{group}</strong><span className="muted">{plugins.filter((item) => item.group === group && item.enabled).length}/{plugins.filter((item) => item.group === group).length}</span></div>
          <div className="tag-list">{plugins.filter((item) => item.group === group).map((item) => <span key={`${item.group}:${item.plugin}`} className={item.enabled ? 'tag enabled' : 'tag'}>{item.plugin}</span>)}</div>
        </div>)}
      </div>
      <div className="card">
        <h3>Pattern pack</h3>
        <p className="muted">{patterns?.name ?? 'No pattern pack loaded'}</p>
        <div className="pattern-list">{Object.entries(patterns?.patterns ?? {}).map(([name, value]) => <details key={name}><summary>{name}</summary><code>{value}</code></details>)}</div>
      </div>
    </div>

    <div className="card">
      <h3>Wordlists</h3>
      <table className="table"><thead><tr><th>Name</th><th>Entries</th><th>Sample</th></tr></thead><tbody>
        {wordlists.map((wordlist) => <tr key={wordlist.name}><td><strong>{wordlist.name}</strong><br /><span className="muted mono">{wordlist.path}</span></td><td>{wordlist.entries}</td><td><span className="muted">{wordlist.sample.join(', ')}</span></td></tr>)}
      </tbody></table>
    </div>
  </div>;
}

function KeyValue({ label, value }: { label: string; value: unknown }) {
  return <div className="kv"><span className="muted">{label}</span><strong>{String(value ?? '—')}</strong></div>;
}

function Workflow() {
  const nodeTypes = useMemo(() => ({ rfNode: RFNode }), []);
  const nodes = useMemo(() => [
    { id: 'target', type: 'rfNode', position: { x: 0, y: 160 }, data: { title: 'Target Domain', sub: 'example.com' } },
    { id: 'subfinder', type: 'rfNode', position: { x: 240, y: 70 }, data: { title: 'subfinder', sub: 'passive subdomains' } },
    { id: 'crtsh', type: 'rfNode', position: { x: 240, y: 250 }, data: { title: 'crt.sh', sub: 'certificate transparency' } },
    { id: 'dnsx', type: 'rfNode', position: { x: 500, y: 160 }, data: { title: 'dnsx', sub: 'resolve/validate' } },
    { id: 'httpx', type: 'rfNode', position: { x: 760, y: 160 }, data: { title: 'httpx', sub: 'probe + tech detect' } },
    { id: 'nuclei', type: 'rfNode', position: { x: 1020, y: 160 }, data: { title: 'nuclei', sub: 'findings' } },
  ], []);
  const edges = useMemo(() => [
    { id: 'e1', source: 'target', target: 'subfinder' },
    { id: 'e2', source: 'target', target: 'crtsh' },
    { id: 'e3', source: 'subfinder', target: 'dnsx' },
    { id: 'e4', source: 'crtsh', target: 'dnsx' },
    { id: 'e5', source: 'dnsx', target: 'httpx' },
    { id: 'e6', source: 'httpx', target: 'nuclei' },
  ], []);
  return <div className="card"><div className="row space"><h3>Workflow Builder</h3><span className="muted">React Flow skeleton: typed sockets come next</span></div><div className="flow-pane"><ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView><Background /><Controls /></ReactFlow></div></div>;
}

function RFNode({ data }: { data: { title: string; sub: string } }) {
  return <div className="node-card"><Handle type="target" position={Position.Left} /><div className="title">{data.title}</div><div className="sub">{data.sub}</div><Handle type="source" position={Position.Right} /></div>;
}
