import { useEffect, useMemo, useState } from 'react';
import { CheckCircle2, ChevronRight, Crosshair, FileText, Rocket, Search, ShieldAlert, X } from 'lucide-react';
import { api } from './api';
import { EmptyState } from './EmptyState';
import { useNav } from './nav';
import { useToast } from './Toast';
import type { Profile, ProfileAvailability, Target, Workspace } from '../types';

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
  const [query, setQuery] = useState('');
  const [risk, setRisk] = useState('all');
  const [health, setHealth] = useState<Record<string, unknown>>({});
  const [picking, setPicking] = useState<Profile | null>(null);

  const reload = async () => {
    const [loaded, h] = await Promise.all([api.profiles(), api.health()]);
    setProfiles(loaded);
    setHealth(h);
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
        <button className="btn" disabled={Boolean(blocked)} onClick={onLaunch}>
          <Rocket size={14} /> Launch
        </button>
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

  const launch = async () => {
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
        </div>
        <div className="modal-actions">
          <button className="btn small" onClick={onClose} type="button">Cancel</button>
          <button className="btn" onClick={launch} type="button" disabled={!targetReady || busy}>
            {busy ? 'Queueing…' : <><Rocket size={14} /> Launch run</>}
          </button>
        </div>
      </div>
    </div>
  );
}
