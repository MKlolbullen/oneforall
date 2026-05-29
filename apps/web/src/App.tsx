import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Activity, Bell, Boxes, Coins, Crosshair, FileSearch, FileText, History, LayoutDashboard, MessageSquare, Network, RefreshCw, Settings as SettingsIcon, Share2, ShieldAlert, TerminalSquare, Users as UsersIcon, Wrench } from 'lucide-react';
import { api } from './lib/api';
import { ArtifactExplorer } from './lib/ArtifactExplorer';
import { classifyArtifact } from './lib/artifactKind';
import { TargetDetail } from './lib/TargetDetail';
import { AdvicePanel } from './lib/AdvicePanel';
import { AdvisorChat } from './lib/AdvisorChat';
import { AdvisorProvider, AdvisorScopeBinder } from './lib/advisorContext';
import { AuditLog } from './lib/AuditLog';
import { Loot } from './lib/Loot';
import { Templates } from './lib/Templates';
import { ToolDetailModal } from './lib/ToolDetailModal';
import { Users as UsersPage } from './lib/Users';
import { Webhooks as WebhooksPage } from './lib/Webhooks';
import { WorkflowBuilder } from './lib/WorkflowBuilder';
import { Workspaces as WorkspacesPage } from './lib/Workspaces';
import { useNav, type Page } from './lib/nav';
import { NetworkTab } from './lib/NetworkTab';
import { CopyButton } from './lib/CopyButton';
import { EmptyState } from './lib/EmptyState';
import { Dashboard } from './lib/Dashboard';
import { NetworkGraph } from './lib/NetworkGraph';
import { Results } from './lib/Results';
import { PendingGHint, ShortcutsCheatsheet, useShortcuts } from './lib/Shortcuts';
import { useToast } from './lib/Toast';
import { useConfirm } from './lib/Confirm';
import { applyTheme, loadTheme, persistTheme, THEMES, type Theme } from './lib/theme';
import type { Artifact, GrepPatternPack, LootItem, PlatformConfig, PluginToggle, Profile, ProfileAvailability, Run, RunEvent, RunStep, Target, Tool, ToolAvailability, WordlistInfo, Workspace } from './types';

const pages: { id: Page; label: string; icon: ReactNode }[] = [
  { id: 'dashboard', label: 'Dashboard', icon: <LayoutDashboard size={16} /> },
  { id: 'workspaces', label: 'Workspaces', icon: <Boxes size={16} /> },
  { id: 'targets', label: 'Targets', icon: <Crosshair size={16} /> },
  { id: 'templates', label: 'Templates', icon: <FileText size={16} /> },
  { id: 'runs', label: 'Runs', icon: <TerminalSquare size={16} /> },
  { id: 'results', label: 'Results', icon: <FileSearch size={16} /> },
  { id: 'loot', label: 'Loot', icon: <Coins size={16} /> },
  { id: 'network', label: 'Network Graph', icon: <Share2 size={16} /> },
  { id: 'tools', label: 'Tool Catalog', icon: <Wrench size={16} /> },
  { id: 'workflow', label: 'Workflow Builder', icon: <Network size={16} /> },
  { id: 'users', label: 'Users', icon: <UsersIcon size={16} /> },
  { id: 'webhooks', label: 'Webhooks', icon: <Bell size={16} /> },
  { id: 'audit', label: 'Audit Log', icon: <History size={16} /> },
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
  const { page, navigate } = useNav();
  const [health, setHealth] = useState<Record<string, unknown>>({});
  const [theme, setTheme] = useState<Theme>(() => loadTheme());
  const [activeRuns, setActiveRuns] = useState(0);

  // Shortcuts expects (page: string) => void; cast through Page since our nav
  // accepts NavParams too but the shortcuts only need page-by-name.
  const navForShortcuts = useCallback((target: string) => {
    if (pages.some((p) => p.id === target)) navigate(target as Page);
  }, [navigate]);
  const { showCheat, setShowCheat, pendingG } = useShortcuts(navForShortcuts);

  useEffect(() => {
    api.health().then(setHealth).catch(console.error);
  }, []);

  // Active-runs pulse — polls every 5s so the sidebar reflects what's
  // happening even when the operator is reading a different page.
  useEffect(() => {
    let cancelled = false;
    const poll = () => {
      api.runs().then((rows) => {
        if (cancelled) return;
        setActiveRuns(rows.filter((r) =>
          r.status === 'running' || r.status === 'queued').length);
      }).catch(() => { /* sidebar pulse is decorative — silent failure is fine */ });
    };
    poll();
    const t = window.setInterval(poll, 5000);
    return () => { cancelled = true; window.clearInterval(t); };
  }, []);

  useEffect(() => {
    applyTheme(theme);
    persistTheme(theme);
  }, [theme]);

  return (
    <AdvisorProvider>
    <div className="shell">
      <aside className="sidebar">
        <div className="brand"><span className="brand-mark">RF</span><span>ReconForge</span></div>
        <nav className="nav">
          {pages.map((item) => (
            <button key={item.id} className={page === item.id ? 'active' : ''} onClick={() => navigate(item.id)}>
              <span className="row">
                {item.icon}
                {item.label}
                {item.id === 'runs' && activeRuns > 0 && (
                  <span className="nav-badge active" title={`${activeRuns} active run(s)`}>
                    {activeRuns}
                  </span>
                )}
                {item.id === 'runs' && activeRuns === 0 && page !== 'runs' && (
                  /* keep the row stable by reserving width — but invisible */
                  <span style={{ marginLeft: 'auto' }} />
                )}
              </span>
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
            <button
              type="button"
              className="btn small advisor-topbar-btn"
              title="Open AI advisor chat"
              onClick={() => window.dispatchEvent(new CustomEvent('reconforge:advisor-open'))}
            >
              <MessageSquare size={14} /> Advisor
            </button>
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
          {page === 'workspaces' && <WorkspacesPage />}
          {page === 'targets' && <Targets />}
          {page === 'templates' && <Templates />}
          {page === 'runs' && <Runs />}
          {page === 'results' && <Results />}
          {page === 'loot' && <Loot />}
          {page === 'network' && <NetworkGraph />}
          {page === 'tools' && <Tools />}
          {page === 'workflow' && <WorkflowBuilder />}
          {page === 'users' && <UsersPage />}
          {page === 'webhooks' && <WebhooksPage />}
          {page === 'audit' && <AuditLog />}
          {page === 'settings' && <SettingsPack />}
        </div>
      </main>
      <ShortcutsCheatsheet open={showCheat} onClose={() => setShowCheat(false)} />
      <PendingGHint visible={pendingG} />
    </div>
      <AdvisorChat />
    </AdvisorProvider>
  );
}


function Metric({ title, value, icon }: { title: string; value: number; icon: ReactNode }) {
  return <div className="card"><div className="row space"><span className="muted">{title}</span>{icon}</div><div className="metric">{value}</div></div>;
}

function Targets() {
  const toast = useToast();
  const { consume } = useNav();
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [profileAvailability, setProfileAvailability] = useState<Record<string, ProfileAvailability>>({});
  const [health, setHealth] = useState<Record<string, unknown>>({});
  const [workspaceId, setWorkspaceId] = useState('');
  // List filter — distinct from the create form's workspaceId so an operator
  // can review one workspace while the form is queued to drop into another.
  // Deeplinks from the Workspaces page seed it.
  const [filterWsId, setFilterWsId] = useState<string>('');
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

  useEffect(() => {
    // Consume the workspace deeplink once on mount and snap both the filter
    // and the create form to it so the user lands somewhere coherent.
    const params = consume();
    if (params.workspaceId) {
      setFilterWsId(params.workspaceId);
      setWorkspaceId(params.workspaceId);
    }
    reload().catch(console.error);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const visibleTargets = filterWsId ? targets.filter((t) => t.workspace_id === filterWsId) : targets;

  const createTarget = async () => {
    if (!workspaceId || !value) return;
    await api.createTarget({ workspace_id: workspaceId, value, type: 'domain', active_allowed: activeAllowed, passive_allowed: true, in_scope: true });
    setValue(''); setActiveAllowed(false); await reload();
  };

  const launch = async (target: Target, profileId: string) => {
    const check = profileAvailability[profileId];
    if (liveEnabled && check && !check.runnable) {
      toast.warn(`Live run blocked: ${check.name}`,
                 `Missing tools: ${check.missing_tools.join(', ')}`);
      return;
    }
    try {
      const run = await api.createRun({ workspace_id: target.workspace_id, target_id: target.id, profile_id: profileId });
      toast.success('Run queued', run.id);
    } catch (error) {
      toast.fromError(error, 'Run launch failed');
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
      <BulkImport
        workspaceId={workspaceId}
        defaultActiveAllowed={activeAllowed}
        onImported={() => reload().catch(console.error)}
      />
      <div className="card" style={{ gridColumn: '1 / -1' }}>
        <div className="row space">
          <h3>Targets</h3>
          <div className="row" style={{ gap: 8 }}>
            <span className="muted small">{visibleTargets.length} of {targets.length}</span>
            <select
              className="input"
              style={{ maxWidth: 220 }}
              value={filterWsId}
              onChange={(e) => setFilterWsId(e.target.value)}
              title="Filter the list by workspace"
            >
              <option value="">All workspaces</option>
              {workspaces.map((w) => <option key={w.id} value={w.id}>{w.name}</option>)}
            </select>
          </div>
        </div>
        {visibleTargets.length === 0 ? (
          <EmptyState
            icon={<Crosshair size={28} />}
            title={targets.length === 0 ? 'No targets yet' : 'No targets in this workspace'}
            body={targets.length === 0
              ? 'Add one with the form above, or paste a list into the bulk-import card to seed many at once.'
              : 'Clear the workspace filter to see other targets, or add one to this workspace.'}
          />
        ) : (
        <table className="table"><thead><tr><th>Value</th><th>Type</th><th>Scope</th><th>Active</th><th>Launch</th></tr></thead><tbody>
          {visibleTargets.map((t) => <tr key={t.id}><td><button className="link" onClick={() => setSelected(t)} type="button">{t.value}</button></td><td>{t.type}</td><td>{t.in_scope ? <span className="badge ok">in scope</span> : <span className="badge bad">out</span>}</td><td>{t.active_allowed ? <span className="badge active">authorized</span> : <span className="badge">blocked</span>}</td><td><div className="launch-grid">{profiles.map((p) => {
            const check = profileAvailability[p.id];
            const blocked = liveEnabled && check && !check.runnable;
            return <button key={p.id} className={blocked ? 'btn disabledish' : 'btn'} disabled={Boolean(blocked)} title={blocked ? `Missing: ${check?.missing_tools.join(', ')}` : 'Runnable'} onClick={() => launch(t, p.id)}>
              <span>{p.name}</span>
              <span className={availabilityClass(check)}>{check ? `${check.available_tools}/${check.total_tools}` : '?'}</span>
            </button>;
          })}</div></td></tr>)}
        </tbody></table>)}
      </div>
    </div>
  );
}

function BulkImport({ workspaceId, defaultActiveAllowed, onImported }:
  { workspaceId: string; defaultActiveAllowed: boolean; onImported: () => void }) {
  const toast = useToast();
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setBusy(true);
    try {
      const values = text.split(/[\r\n,]+/).map((s) => s.trim()).filter(Boolean);
      if (!values.length) { toast.warn('Nothing to import', 'Paste at least one domain.'); return; }
      if (!workspaceId)   { toast.warn('No workspace', 'Pick a workspace first.'); return; }
      const r = await api.bulkTargets({
        workspace_id: workspaceId,
        values,
        active_allowed: defaultActiveAllowed,
      });
      const detail = r.skipped.length
        ? `Created ${r.created.length}, skipped ${r.skipped.length} duplicate${r.skipped.length === 1 ? '' : 's'}.`
        : `Created ${r.created.length} target${r.created.length === 1 ? '' : 's'}.`;
      if (r.created.length) {
        toast.success('Bulk import complete', detail);
        setText('');
      } else {
        toast.info('Nothing new added', detail);
      }
      onImported();
    } catch (e: unknown) {
      toast.fromError(e, 'Bulk import failed');
    } finally { setBusy(false); }
  };

  return (
    <div className="card">
      <h3>Bulk import</h3>
      <p className="muted">Paste one domain per line (commas also work). Lines starting with <code>#</code> are skipped, dupes inside the workspace are reported.</p>
      <textarea
        className="input"
        rows={5}
        placeholder={"a.example.com\nb.example.com\n# c.example.com is out of scope"}
        value={text}
        onChange={(e) => setText(e.target.value)}
        style={{ fontFamily: 'ui-monospace, monospace' }}
      />
      <div className="row space" style={{ marginTop: 8 }}>
        <span className="muted">{busy ? 'Importing…' : ''}</span>
        <button className="btn" onClick={submit} disabled={busy || !text.trim()}>
          {busy ? 'Importing…' : 'Import'}
        </button>
      </div>
    </div>
  );
}

function Runs() {
  const { consume } = useNav();
  const [runs, setRuns] = useState<Run[]>([]);
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [filterWsId, setFilterWsId] = useState<string>('');
  const [selected, setSelected] = useState<Run | null>(null);
  // Pending deeplink — held in a ref so the setInterval's closure always sees
  // the current value (useState would still be null in the first tick because
  // setters are async).
  const pendingRunIdRef = useRef<string | null>(null);

  const reload = () => api.runs().then((loaded) => {
    setRuns(loaded);
    setSelected((current) => {
      const pending = pendingRunIdRef.current;
      if (pending) {
        const match = loaded.find((r) => r.id === pending);
        if (match) { pendingRunIdRef.current = null; return match; }
      }
      return current ? loaded.find((run) => run.id === current.id) ?? current : current;
    });
  }).catch(console.error);

  useEffect(() => {
    const params = consume();
    if (params.runId) pendingRunIdRef.current = params.runId;
    if (params.workspaceId) setFilterWsId(params.workspaceId);
    api.workspaces().then(setWorkspaces).catch(() => { /* sidebar list — silent */ });
    reload();
    const timer = window.setInterval(reload, 3000);
    return () => window.clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const visibleRuns = filterWsId ? runs.filter((r) => r.workspace_id === filterWsId) : runs;

  return <div className="grid cols-2">
    <div className="card">
      <div className="row space">
        <h3>Runs</h3>
        <div className="row" style={{ gap: 8 }}>
          <span className="muted small">{visibleRuns.length} of {runs.length}</span>
          <select
            className="input"
            style={{ maxWidth: 200 }}
            value={filterWsId}
            onChange={(e) => setFilterWsId(e.target.value)}
            title="Filter runs by workspace"
          >
            <option value="">All workspaces</option>
            {workspaces.map((w) => <option key={w.id} value={w.id}>{w.name}</option>)}
          </select>
        </div>
      </div>
      <RunTable runs={visibleRuns} onSelect={setSelected} selectedId={selected?.id ?? null} />
    </div>
    <div className="card"><h3>Live console</h3>{selected ? <RunConsole run={selected} onChanged={reload} /> : <p className="muted">Select a run to attach to its event stream.</p>}</div>
  </div>;
}

function RunTable({ runs, onSelect, selectedId }: { runs: Run[]; onSelect?: (run: Run) => void; selectedId?: string | null }) {
  return <table className="table"><thead><tr><th>ID</th><th>Profile</th><th>Status</th><th>Risk</th></tr></thead><tbody>
    {runs.map((r) => (
      <tr key={r.id} onClick={() => onSelect?.(r)}
          className={selectedId === r.id ? 'row-selected' : undefined}
          style={{ cursor: 'pointer' }}>
        <td className="mono small">{r.id.slice(0, 16)}…</td>
        <td>{r.profile_id}</td>
        <td><span className={`badge ${r.status === 'completed' ? 'ok' : r.status === 'failed' || r.status === 'cancelled' ? 'bad' : r.status === 'running' ? 'active' : 'passive'}`}>{r.status}</span></td>
        <td>{r.risk}</td>
      </tr>
    ))}
  </tbody></table>;
}

type RunTab = 'console' | 'steps' | 'network' | 'artifacts' | 'loot' | 'advisor';

function RunConsole({ run, onChanged }: { run: Run; onChanged?: () => void }) {
  return (
    <>
      <AdvisorScopeBinder
        workspaceId={run.workspace_id}
        runId={run.id}
        runLabel={run.profile_id}
        targetId={run.target_id}
      />
      <RunConsoleInner run={run} onChanged={onChanged} />
    </>
  );
}

function RunConsoleInner({ run, onChanged }: { run: Run; onChanged?: () => void }) {
  const toast = useToast();
  const confirm = useConfirm();
  const { navigate } = useNav();
  const [events, setEvents] = useState<RunEvent[]>([]);
  const [artifacts, setArtifacts] = useState<Artifact[]>([]);
  const [steps, setSteps] = useState<RunStep[]>([]);
  const [loot, setLoot] = useState<LootItem[]>([]);
  const [selected, setSelected] = useState<Artifact | null>(null);
  const [tab, setTab] = useState<RunTab>('console');

  const reloadArtifacts = () => api.runArtifacts(run.id).then(setArtifacts).catch(console.error);
  const reloadSteps = () => api.runSteps(run.id).then(setSteps).catch(console.error);
  const reloadLoot = () => api.loot({ run_id: run.id, limit: 500 })
    .then((p) => setLoot(p.items))
    .catch(console.error);

  const reindexLoot = async () => {
    try {
      const r = await api.reindexRunLoot(run.id);
      toast.success('Loot reindexed', `${r.indexed} item${r.indexed === 1 ? '' : 's'} for this run.`);
      reloadLoot();
    } catch (e) {
      toast.fromError(e, 'Reindex failed');
    }
  };

  const cancel = async () => {
    const ok = await confirm({
      title: `Cancel run ${run.id}?`,
      body: "Any tools still in flight will be interrupted at their next checkpoint. Already-collected assets and findings stay in place.",
      confirmLabel: 'Cancel run',
      cancelLabel: 'Keep running',
      destructive: true,
    });
    if (!ok) return;
    try {
      await api.cancelRun(run.id);
      await reloadSteps();
      onChanged?.();
      toast.info('Cancellation requested', run.id);
    } catch (e) {
      toast.fromError(e, 'Cancel failed');
    }
  };

  const rerun = async () => {
    try {
      const fresh = await api.rerun(run.id);
      onChanged?.();
      toast.success('Re-run queued', fresh.id);
    } catch (error) {
      toast.fromError(error, 'Re-run failed');
    }
  };

  useEffect(() => {
    setEvents([]);
    setSelected(null);
    setLoot([]);
    reloadArtifacts();
    reloadSteps();
    reloadLoot();
    api.runEvents(run.id).then(setEvents).catch(console.error);
    const socket = new WebSocket(api.wsUrl(run.id));
    socket.onmessage = (message) => {
      const event = JSON.parse(message.data) as RunEvent;
      setEvents((prev) => prev.some((item) => item.id === event.id) ? prev : [...prev, event]);
      if (event.type === 'run.step.artifact_created') reloadArtifacts();
      if (event.type.startsWith('run.step.') || event.type === 'run.cancel_requested') reloadSteps();
      if (event.type === 'run.completed') reloadLoot();
      if (event.type === 'run.completed' || event.type === 'run.failed' || event.type === 'run.cancelled') onChanged?.();
    };
    return () => socket.close();
  }, [run.id]);

  const canCancel = run.status === 'queued' || run.status === 'running';

  const tabs: { id: RunTab; label: string; badge?: string | number }[] = [
    { id: 'console', label: 'Console' },
    { id: 'steps', label: 'Steps', badge: steps.length },
    { id: 'network', label: 'Network' },
    { id: 'artifacts', label: 'Artifacts', badge: artifacts.length },
    { id: 'loot', label: 'Loot', badge: loot.length },
    { id: 'advisor', label: 'Advisor' },
  ];

  return <div className="grid">
    <div className="row space">
      <div className="row">
        <span className={`badge ${run.status === 'completed' ? 'ok' : run.status === 'failed' || run.status === 'cancelled' ? 'bad' : 'passive'}`}>{run.status}</span>
        <span className="mono muted" style={{ fontSize: 12 }}>
          {run.id}
          <CopyButton value={run.id} title="Copy run ID" />
        </span>
      </div>
      <div className="row">
        {/* Report links open in a new tab — HTML is self-contained, JSON/md
            are useful for tickets / agents. No JS-side state needed because
            the backend renders on demand. */}
        <a
          className="btn small"
          href={api.runReportUrl(run.id, 'html')}
          target="_blank"
          rel="noreferrer"
          title="Open the HTML report in a new tab"
        >
          Report
        </a>
        <a className="btn small" href={api.runReportUrl(run.id, 'json')} target="_blank" rel="noreferrer" title="JSON report" download>JSON</a>
        <a className="btn small" href={api.runReportUrl(run.id, 'md')} target="_blank" rel="noreferrer" title="Markdown report" download>MD</a>
        <button className="btn small" onClick={rerun} title="Queue a new run with the same target + profile + params">
          Re-run
        </button>
        <button className="btn danger" disabled={!canCancel} onClick={cancel}>Cancel run</button>
      </div>
    </div>
    <div className="row" role="tablist">
      {tabs.map((t) => (
        <button
          key={t.id}
          type="button"
          role="tab"
          aria-selected={tab === t.id}
          className={`btn small ${tab === t.id ? '' : 'disabledish'}`}
          onClick={() => setTab(t.id)}
        >
          {t.label}{t.badge !== undefined && <span className="badge passive" style={{ marginLeft: 6 }}>{t.badge}</span>}
        </button>
      ))}
    </div>
    {tab === 'console' && (
      <div className="console">{events.map((e) => <div key={e.id} className={`console-line ${e.level}`}>[{e.sequence.toString().padStart(3, '0')}] {e.type}: {e.message}</div>)}</div>
    )}
    {tab === 'steps' && (
      <div>
        <div className="row space"><strong>Steps</strong><span className="muted">timeout / retry policy</span></div>
        <table className="table compact"><thead><tr><th>#</th><th>Tool</th><th>Status</th><th>Try</th><th>Timeout</th></tr></thead><tbody>
          {steps.map((step) => <tr key={step.id}><td>{step.index}</td><td>{step.tool_name}</td><td><span className={`badge ${step.status === 'completed' ? 'ok' : step.status === 'failed' || step.status === 'timed_out' || step.status === 'cancelled' ? 'bad' : 'passive'}`}>{step.status}</span></td><td>{step.attempt}/{step.max_retries + 1}</td><td>{step.timeout_seconds}s</td></tr>)}
        </tbody></table>
      </div>
    )}
    {tab === 'network' && <NetworkTab runId={run.id} />}
    {tab === 'artifacts' && (
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
    )}
    {tab === 'loot' && (
      <div className="grid">
        <div className="row space">
          <strong>Loot</strong>
          <div className="row">
            <button className="btn small" onClick={reindexLoot} title="Re-derive loot from this run's current findings"><RefreshCw size={14} /> Reindex</button>
            <button className="btn small" onClick={() => navigate('loot', { runId: run.id, workspaceId: run.workspace_id })} title="Open the full Loot page filtered to this run">
              Open in Loot page
            </button>
          </div>
        </div>
        {loot.length === 0 ? (
          <EmptyState
            icon={<Coins size={24} />}
            title="No loot for this run"
            body="Either no findings here qualified as loot, or loot indexing has not yet run. Click Reindex above to derive it from the current findings."
          />
        ) : (
          <table className="table compact">
            <thead><tr><th>Severity</th><th>Kind</th><th>Label</th><th>Host</th><th>Tool</th></tr></thead>
            <tbody>
              {loot.map((it) => (
                <tr key={it.id}>
                  <td><span className={`badge ${it.severity === 'critical' || it.severity === 'high' ? 'bad' : it.severity === 'medium' ? 'active' : 'passive'}`}>{it.severity}</span></td>
                  <td>{it.kind}</td>
                  <td>{it.label}</td>
                  <td><span className="mono">{it.host ?? '—'}</span></td>
                  <td>{it.source_tool ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    )}
    {tab === 'advisor' && (
      <div className="grid">
        <div className="row space">
          <p className="muted">One-shot triage below, or use the global chat for back-and-forth Q&amp;A.</p>
          <button
            type="button"
            className="btn small"
            onClick={() => window.dispatchEvent(new CustomEvent('reconforge:advisor-open'))}
          >
            <MessageSquare size={14} /> Open chat
          </button>
        </div>
        <AdvicePanel
          label="Triage with Claude"
          refKey={run.id}
          fetchCached={() => api.getRunTriage(run.id)}
          invoke={() => api.triageRun(run.id)}
        />
      </div>
    )}
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
  const [selectedTool, setSelectedTool] = useState<Tool | null>(null);

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
          return <tr key={t.id} onClick={() => setSelectedTool(t)} style={{ cursor: 'pointer' }} title="Click for detail + quick-launch">
            <td><strong>{t.name}</strong><br /><span className="muted mono">{t.id}{t.binary ? ` · ${t.binary}` : ''}</span></td>
            <td><span className={availabilityClass(check)} title={check?.message ?? ''}>{availabilityLabel(check)}</span><br /><span className="muted mono">{check?.path ?? check?.message ?? 'not checked'}</span></td>
            <td>{t.category}</td>
            <td><span className={t.risk === 'passive' ? 'badge passive' : t.risk === 'high_active' ? 'badge bad' : 'badge active'}>{t.risk}</span></td>
            <td>{t.requires_authorization ? <span className="badge active">required</span> : <span className="badge passive">no</span>}</td>
            <td><div className="tag-list">{(t.tags ?? []).slice(0, 4).map((tag) => <span key={tag} className="tag">{tag}</span>)}</div></td>
          </tr>;
        })}</tbody></table>
      </div>
      {selectedTool && <ToolDetailModal tool={selectedTool} onClose={() => setSelectedTool(null)} />}
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
  const [theme, setTheme] = useState<Theme>(() => loadTheme());

  const onThemeChange = (next: Theme) => {
    setTheme(next);
    applyTheme(next);
    persistTheme(next);
  };

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
    <div className="card">
      <div className="row space"><h3>Appearance</h3><span className="muted">Choose how the UI should look. Persisted in localStorage.</span></div>
      <div className="theme-grid">
        {THEMES.map((t) => (
          <button
            key={t.id}
            type="button"
            className={`theme-swatch ${theme === t.id ? 'selected' : ''}`}
            onClick={() => onThemeChange(t.id)}
            aria-pressed={theme === t.id}
          >
            <div className={`theme-swatch-preview theme-preview-${t.id}`}>
              <div className="theme-preview-bar" />
              <div className="theme-preview-card">
                <div className="theme-preview-line w60" />
                <div className="theme-preview-line w40" />
                <div className="theme-preview-line w80" />
              </div>
              <div className="theme-preview-pills">
                <span className="theme-preview-pill ok">passed</span>
                <span className="theme-preview-pill warn">warning</span>
                <span className="theme-preview-pill bad">critical</span>
              </div>
            </div>
            <div className="theme-swatch-meta">
              <strong>{t.label}</strong>
              <small className="muted">{t.description}</small>
              {theme === t.id && <span className="badge ok">active</span>}
            </div>
          </button>
        ))}
      </div>
    </div>
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

