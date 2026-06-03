import { useEffect, useMemo, useState } from 'react';
import { CheckCircle2, ChevronRight, Crosshair, Edit3, FileText, Network, Rocket, Search, ShieldAlert, X } from 'lucide-react';
import { api } from './api';
import { EmptyState } from './EmptyState';
import { useNav } from './nav';
import { ScopePreflight, useScopePreflight } from './ScopePreflight';
import { useToast } from './Toast';
import type { Profile, ProfileAvailability, SavedWorkflow, Target, Workspace } from '../types';

const RISK_LABEL: Record<string, string> = {
  passive: 'Passive',
  low_active: 'Low active',
  medium_active: 'Medium active',
  high_active: 'High active',
};

function riskBadge(risk: string) {
  if (risk === 'passive') return 'passive';
  if (risk === 'high_active') return 'bad';
  return 'active';
}

/**
 * Templates — a card-grid launchpad for scan profiles. Different audience
 * from the Tool Catalog: this view is for picking a workflow and firing it
 * at a target, not for inspecting individual binaries.
 */
export function Templates() {
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [availability, setAvailability] = useState<Record<string, ProfileAvailability>>({});
  const [workflows, setWorkflows] = useState<SavedWorkflow[]>([]);
  const [query, setQuery] = useState('');
  const [risk, setRisk] = useState('all');
  const [health, setHealth] = useState<Record<string, unknown>>({});
  const [picking, setPicking] = useState<Profile | null>(null);
  const [pickingWf, setPickingWf] = useState<SavedWorkflow | null>(null);

  const reload = async () => {
    const [loaded, h, wfs] = await Promise.all([
      api.profiles(),
      api.health(),
      api.workflows().catch(() => []),
    ]);
    setProfiles(loaded);
    setHealth(h);
    setWorkflows(wfs);
    const checks = await Promise.all(loaded.map((p) => api.profileAvailability(p.id).catch(() => null)));
    setAvailability(Object.fromEntries(checks.filter(Boolean).map((c) => [c!.profile_id, c!])));
  };
  useEffect(() => { reload().catch(console.error); }, []);

  const liveEnabled = health.live_execution_enabled === true;

  const riskCounts = useMemo(() => profiles.reduce<Record<string, number>>((acc, p) => {
    acc[p.risk] = (acc[p.risk] ?? 0) + 1;
    return acc;
  }, {}), [profiles]);

  const filtered = profiles.filter((p) => {
    if (risk !== 'all' && p.risk !== risk) return false;
    if (!query) return true;
    const hay = `${p.id} ${p.name} ${p.description}`.toLowerCase();
    return hay.includes(query.toLowerCase());
  });

  return (
    <div className="grid">
      <div className="card">
        <div className="row space">
          <h3><FileText size={18} style={{ verticalAlign: 'middle', marginRight: 6 }} /> Scan templates</h3>
          <span className="muted">
            Predefined recon + ASM workflows. Pick a template and a target — the worker handles the rest.
            {liveEnabled ? <> Live execution is enabled; templates with missing tools are disabled.</> : <> Dry-run mode: missing tools are tolerated.</>}
          </span>
        </div>
        <div className="toolbar availability-toolbar">
          <div className="row" style={{ flex: 1, position: 'relative' }}>
            <Search size={14} style={{ position: 'absolute', left: 8, opacity: 0.5 }} />
            <input
              className="input"
              style={{ paddingLeft: 28 }}
              placeholder="Search templates by name, description, ID…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </div>
          <select className="input" value={risk} onChange={(e) => setRisk(e.target.value)}>
            <option value="all">All risks ({profiles.length})</option>
            {['passive', 'low_active', 'medium_active', 'high_active'].map((r) =>
              <option key={r} value={r}>{RISK_LABEL[r]} ({riskCounts[r] ?? 0})</option>
            )}
          </select>
        </div>
      </div>

      {workflows.length > 0 && (
        <>
          <div className="card">
            <div className="row space">
              <strong><Network size={14} style={{ verticalAlign: 'middle', marginRight: 4 }} /> Saved workflows</strong>
              <span className="muted small">{workflows.length} workflow{workflows.length === 1 ? '' : 's'} · built in the canvas, launchable from here</span>
            </div>
          </div>
          <div className="templates-grid">
            {workflows.map((wf) => (
              <WorkflowCard key={wf.id} workflow={wf} onLaunch={() => setPickingWf(wf)} />
            ))}
          </div>
        </>
      )}

      {workflows.length > 0 && (
        <div className="card">
          <strong>System profiles</strong>
        </div>
      )}

      {filtered.length === 0 ? (
        <EmptyState
          icon={<FileText size={28} />}
          title={profiles.length === 0 ? 'No templates registered' : 'No templates match'}
          body={profiles.length === 0
            ? 'The tool registry has no profiles. Add profile YAMLs under packages/tool-registry/profiles/.'
            : 'Try clearing the search box or widening the risk filter.'}
        />
      ) : (
        <div className="templates-grid">
          {filtered.map((p) => (
            <TemplateCard
              key={p.id}
              profile={p}
              check={availability[p.id]}
              liveEnabled={liveEnabled}
              onLaunch={() => setPicking(p)}
            />
          ))}
        </div>
      )}

      {picking && (
        <LaunchPicker
          profile={picking}
          check={availability[picking.id]}
          liveEnabled={liveEnabled}
          onClose={() => setPicking(null)}
        />
      )}
      {pickingWf && (
        <WorkflowLaunchPicker workflow={pickingWf} onClose={() => setPickingWf(null)} />
      )}
    </div>
  );
}

function TemplateCard({
  profile, check, liveEnabled, onLaunch,
}: {
  profile: Profile;
  check?: ProfileAvailability;
  liveEnabled: boolean;
  onLaunch: () => void;
}) {
  const { navigate } = useNav();
  const blocked = liveEnabled && check && !check.runnable;
  const stepNames = profile.steps.map((s) => s.tool);
  const visibleSteps = stepNames.slice(0, 8);
  const hiddenSteps = stepNames.length - visibleSteps.length;

  return (
    <div className={`template-card ${blocked ? 'blocked' : ''}`}>
      <div className="row space">
        <strong className="template-title">{profile.name}</strong>
        <span className={`badge ${riskBadge(profile.risk)}`}>{RISK_LABEL[profile.risk] ?? profile.risk}</span>
      </div>
      <p className="muted template-desc">{profile.description || '—'}</p>
      <div className="template-meta">
        <span className="row" title="Tools needed for this template">
          <CheckCircle2 size={14} color={check?.runnable ? '#22d3ee' : '#fca5a5'} />
          {check ? `${check.available_tools}/${check.total_tools} tools` : 'unchecked'}
        </span>
        <span className="muted">{profile.steps.length} step{profile.steps.length === 1 ? '' : 's'}</span>
      </div>
      <div className="template-steps">
        {visibleSteps.map((tool, i) => (
          <span key={`${tool}-${i}`} className="template-step">
            {tool}
            {i < visibleSteps.length - 1 && <ChevronRight size={12} className="muted" />}
          </span>
        ))}
        {hiddenSteps > 0 && <span className="muted">… +{hiddenSteps}</span>}
      </div>
      {blocked && check && (
        <p className="warning-text" style={{ marginTop: 6 }}>
          <ShieldAlert size={12} /> Missing in live mode: {check.missing_tools.slice(0, 5).join(', ')}
          {check.missing_tools.length > 5 ? ` (+${check.missing_tools.length - 5})` : ''}
        </p>
      )}
      <div className="row space" style={{ marginTop: 8 }}>
        <span className="muted mono small">{profile.id}</span>
        <div className="row" style={{ gap: 6 }}>
          <button
            className="btn small"
            type="button"
            title="Open this profile's steps in the Workflow Builder for editing"
            onClick={() => navigate('workflow', { fromProfile: profile.id })}
          >
            <Edit3 size={12} /> Customize
          </button>
          <button className="btn" disabled={Boolean(blocked)} onClick={onLaunch}>
            <Rocket size={14} /> Launch
          </button>
        </div>
      </div>
    </div>
  );
}

function LaunchPicker({
  profile, check, liveEnabled, onClose,
}: {
  profile: Profile;
  check?: ProfileAvailability;
  liveEnabled: boolean;
  onClose: () => void;
}) {
  const toast = useToast();
  const { navigate } = useNav();
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [workspaceId, setWorkspaceId] = useState('');
  const [targetId, setTargetId] = useState('');
  const [filter, setFilter] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    Promise.all([api.workspaces(), api.targets()])
      .then(([ws, ts]) => {
        setWorkspaces(ws);
        setTargets(ts);
        if (ws[0]) setWorkspaceId(ws[0].id);
      })
      .catch((e) => toast.fromError(e, 'Failed to load workspaces'));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const filteredTargets = useMemo(() => {
    return targets.filter((t) => {
      if (workspaceId && t.workspace_id !== workspaceId) return false;
      if (!filter) return true;
      return t.value.toLowerCase().includes(filter.toLowerCase());
    });
  }, [targets, workspaceId, filter]);

  // High-risk profiles need active_allowed on the target.
  const needsActive = profile.risk !== 'passive';
  const selected = targets.find((t) => t.id === targetId) ?? null;
  const targetReady = selected != null && (!needsActive || selected.active_allowed);

  // Use a stable param string for the preflight call so flipping
  // unrelated state doesn't refire the debounced fetch.
  const preflight = useScopePreflight(selected ? {
    target: selected.value,
    risk: profile.risk,
    tool_id: profile.id,
  } : null);

  const launch = async (extraParams: Record<string, unknown> = {}) => {
    if (!selected || !targetReady) return;
    setBusy(true);
    try {
      const run = await api.createRun({
        workspace_id: selected.workspace_id,
        target_id: selected.id,
        profile_id: profile.id,
      });
      toast.success('Run queued', `${profile.name} → ${selected.value}`);
      onClose();
      navigate('runs', { runId: run.id });
    } catch (e) {
      toast.fromError(e, 'Run launch failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal launch-modal" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
        <div className="modal-header">
          <span className="row">
            <Rocket size={16} color="#22d3ee" />
            <strong>Launch <span className="mono">{profile.id}</span></strong>
            <span className={`badge ${riskBadge(profile.risk)}`}>{RISK_LABEL[profile.risk] ?? profile.risk}</span>
          </span>
          <button className="icon-btn" onClick={onClose} type="button" aria-label="Close"><X size={14} /></button>
        </div>
        <p className="muted">{profile.description}</p>
        <div className="grid">
          <select className="input" value={workspaceId} onChange={(e) => { setWorkspaceId(e.target.value); setTargetId(''); }}>
            {workspaces.map((w) => <option key={w.id} value={w.id}>{w.name}</option>)}
          </select>
          <input
            className="input"
            placeholder="Filter targets by host…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
          <div className="launch-target-list">
            {filteredTargets.length === 0 && <p className="muted">No targets match. Add one on the Targets page.</p>}
            {filteredTargets.map((t) => {
              const ok = !needsActive || t.active_allowed;
              return (
                <button
                  key={t.id}
                  type="button"
                  className={`launch-target ${targetId === t.id ? 'selected' : ''} ${!ok ? 'disabledish' : ''}`}
                  onClick={() => setTargetId(t.id)}
                  disabled={!ok}
                  title={ok ? '' : 'Active scan authorization required for this profile risk'}
                >
                  <span className="row">
                    <Crosshair size={14} />
                    <span className="mono">{t.value}</span>
                  </span>
                  <span className="row">
                    {t.active_allowed ? <span className="badge active">active OK</span> : <span className="badge">passive only</span>}
                    {!t.in_scope && <span className="badge bad">out of scope</span>}
                  </span>
                </button>
              );
            })}
          </div>
          {selected && !targetReady && (
            <p className="warning-text">
              <ShieldAlert size={12} /> {selected.value} has no active-scan authorization, but {profile.name} is {RISK_LABEL[profile.risk]?.toLowerCase() ?? profile.risk}.
              Open the Targets page to authorize it first.
            </p>
          )}
          {liveEnabled && check && !check.runnable && (
            <p className="warning-text">
              <ShieldAlert size={12} /> Live mode: missing {check.missing_tools.slice(0, 3).join(', ')}{check.missing_tools.length > 3 ? '…' : ''}
            </p>
          )}
          {selected && preflight.state && preflight.state.decision !== 'no-engine' && (
            <div className="row" style={{ gap: 6, alignItems: 'center', marginTop: 4 }}>
              <span className="muted small">ROE preflight:</span>
              <ScopePreflight action={selected ? {
                target: selected.value, risk: profile.risk, tool_id: profile.id,
              } : null} />
              {preflight.state.decision === 'deny' && preflight.state.reason && (
                <small className="warning-text">— {preflight.state.reason}</small>
              )}
            </div>
          )}
        </div>
        <div className="modal-actions">
          <button className="btn small" onClick={onClose} type="button">Cancel</button>
          <button
            className="btn"
            onClick={() => launch()}
            type="button"
            disabled={!targetReady || busy || preflight.blocked}
            title={preflight.blocked ? `Blocked by ROE policy: ${preflight.state?.reason ?? ''}` : ''}
          >
            {busy ? 'Queueing…' : preflight.blocked ? (
              <><Rocket size={14} /> Blocked by ROE</>
            ) : (
              <><Rocket size={14} /> Launch run</>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}

/* ============================================================================
 * Saved workflow card + launch picker
 * ========================================================================== */

function WorkflowCard({ workflow, onLaunch }: { workflow: SavedWorkflow; onLaunch: () => void }) {
  const { navigate } = useNav();
  const steps = workflow.body?.steps ?? [];
  const visible = steps.slice(0, 8);
  const hidden = steps.length - visible.length;

  return (
    <div className="template-card">
      <div className="row space">
        <strong className="template-title">{workflow.name}</strong>
        <span className="badge ok">workflow</span>
      </div>
      <p className="muted template-desc">{workflow.description || 'Saved Workflow Builder graph.'}</p>
      <div className="template-meta">
        <span className="muted small">{steps.length} step{steps.length === 1 ? '' : 's'}</span>
        <span className="muted small" title={`Updated ${new Date(workflow.updated_at).toLocaleString()}`}>
          updated {new Date(workflow.updated_at).toLocaleDateString()}
        </span>
      </div>
      <div className="template-steps">
        {visible.map((s, i) => (
          <span key={`${s.tool}-${i}`} className="template-step">
            {s.tool}
            {i < visible.length - 1 && <ChevronRight size={12} className="muted" />}
          </span>
        ))}
        {hidden > 0 && <span className="muted">… +{hidden}</span>}
      </div>
      <div className="row space" style={{ marginTop: 8 }}>
        <button
          className="btn small"
          type="button"
          onClick={() => navigate('workflow', { workflowId: workflow.id })}
          title="Open this workflow in the canvas editor"
        >
          <Edit3 size={12} /> Edit
        </button>
        <button className="btn" type="button" onClick={onLaunch}>
          <Rocket size={14} /> Launch
        </button>
      </div>
    </div>
  );
}

function WorkflowLaunchPicker({ workflow, onClose }: { workflow: SavedWorkflow; onClose: () => void }) {
  const toast = useToast();
  const { navigate } = useNav();
  const [targets, setTargets] = useState<Target[]>([]);
  const [filter, setFilter] = useState('');
  const [targetId, setTargetId] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.targets().then((all) => {
      // Workflow is workspace-scoped; show only targets in that workspace.
      setTargets(all.filter((t) => t.workspace_id === workflow.workspace_id));
    }).catch((e) => toast.fromError(e, 'Failed to load targets'));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const filteredTargets = useMemo(
    () => targets.filter((t) => !filter || t.value.toLowerCase().includes(filter.toLowerCase())),
    [targets, filter],
  );
  const selected = targets.find((t) => t.id === targetId) ?? null;
  // Use the first tool from the workflow's saved body as the preflight tool
  // id — surfaces per-tool approval gates if any step's tool is listed.
  const firstTool = (workflow.body?.steps ?? [])[0]?.tool;
  const preflight = useScopePreflight(selected ? {
    target: selected.value,
    risk: 'low_active',  // workflows don't carry an explicit risk; use a midpoint
    tool_id: firstTool,
  } : null);

  const launch = async () => {
    if (!selected) return;
    setBusy(true);
    try {
      const run = await api.launchWorkflow(workflow.id, { target_id: selected.id });
      toast.success('Run queued', `${workflow.name} → ${selected.value}`);
      onClose();
      navigate('runs', { runId: run.id });
    } catch (e) {
      toast.fromError(e, 'Launch failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal launch-modal" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
        <div className="modal-header">
          <span className="row">
            <Rocket size={16} color="#22d3ee" />
            <strong>Launch workflow <span className="mono">{workflow.name}</span></strong>
            <span className="badge ok">workflow</span>
          </span>
          <button className="icon-btn" onClick={onClose} type="button" aria-label="Close"><X size={14} /></button>
        </div>
        {workflow.description && <p className="muted">{workflow.description}</p>}
        <p className="muted small">
          Scoped to its saved workspace. Target list is filtered to that workspace.
        </p>
        <div className="grid">
          <input
            className="input"
            placeholder="Filter targets by host…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
          <div className="launch-target-list">
            {filteredTargets.length === 0 && <p className="muted">No targets in this workspace. Open Targets to add one.</p>}
            {filteredTargets.map((t) => (
              <button
                key={t.id}
                type="button"
                className={`launch-target ${targetId === t.id ? 'selected' : ''}`}
                onClick={() => setTargetId(t.id)}
              >
                <span className="row">
                  <Crosshair size={14} />
                  <span className="mono">{t.value}</span>
                </span>
                <span className="row">
                  {t.active_allowed ? <span className="badge active">active OK</span> : <span className="badge">passive only</span>}
                  {!t.in_scope && <span className="badge bad">out of scope</span>}
                </span>
              </button>
            ))}
          </div>
          {selected && preflight.state && preflight.state.decision !== 'no-engine' && (
            <div className="row" style={{ gap: 6, alignItems: 'center', marginTop: 4 }}>
              <span className="muted small">ROE preflight:</span>
              <ScopePreflight action={{
                target: selected.value, risk: 'low_active', tool_id: firstTool,
              }} />
              {preflight.state.decision === 'deny' && preflight.state.reason && (
                <small className="warning-text">— {preflight.state.reason}</small>
              )}
            </div>
          )}
        </div>
        <div className="modal-actions">
          <button className="btn small" onClick={onClose} type="button">Cancel</button>
          <button
            className="btn"
            onClick={launch}
            type="button"
            disabled={!selected || busy || preflight.blocked}
            title={preflight.blocked ? `Blocked by ROE policy: ${preflight.state?.reason ?? ''}` : ''}
          >
            {busy ? 'Queueing…' : preflight.blocked ? (
              <><Rocket size={14} /> Blocked by ROE</>
            ) : (
              <><Rocket size={14} /> Launch run</>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
