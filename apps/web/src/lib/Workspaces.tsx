import { useEffect, useMemo, useState } from 'react';
import { Boxes, Coins, Crosshair, FolderPlus, Lock, ShieldAlert, TerminalSquare } from 'lucide-react';
import { api } from './api';
import { EmptyState } from './EmptyState';
import { useNav } from './nav';
import { useToast } from './Toast';
import type { Run, Target, WhoAmI, Workspace } from '../types';

function relTime(iso?: string | null): string {
  if (!iso) return '—';
  const ms = Date.now() - new Date(iso).getTime();
  if (ms < 60_000) return `${Math.max(1, Math.floor(ms / 1000))}s ago`;
  if (ms < 3_600_000) return `${Math.floor(ms / 60_000)}m ago`;
  if (ms < 86_400_000) return `${Math.floor(ms / 3_600_000)}h ago`;
  return `${Math.floor(ms / 86_400_000)}d ago`;
}

export function Workspaces() {
  const toast = useToast();
  const { navigate } = useNav();
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [runs, setRuns] = useState<Run[]>([]);
  const [me, setMe] = useState<WhoAmI | null>(null);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reload = async () => {
    try {
      const [ws, ts, rs] = await Promise.all([api.workspaces(), api.targets(), api.runs()]);
      setWorkspaces(ws);
      setTargets(ts);
      setRuns(rs);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  useEffect(() => {
    reload().catch(console.error);
    // /me may 401 in test mode without bypass headers — swallow rather than error.
    api.me().then(setMe).catch(() => setMe(null));
  }, []);

  const isAdmin = me?.role === 'admin';

  // Roll up targets / runs per workspace in one pass so each card has counts.
  const stats = useMemo(() => {
    const byWs: Record<string, { targets: number; runs: number; activeRuns: number; lastRun: string | null }> = {};
    for (const t of targets) {
      byWs[t.workspace_id] ??= { targets: 0, runs: 0, activeRuns: 0, lastRun: null };
      byWs[t.workspace_id].targets += 1;
    }
    for (const r of runs) {
      byWs[r.workspace_id] ??= { targets: 0, runs: 0, activeRuns: 0, lastRun: null };
      byWs[r.workspace_id].runs += 1;
      if (r.status === 'running' || r.status === 'queued') byWs[r.workspace_id].activeRuns += 1;
      if (!byWs[r.workspace_id].lastRun || r.created_at > (byWs[r.workspace_id].lastRun ?? '')) {
        byWs[r.workspace_id].lastRun = r.created_at;
      }
    }
    return byWs;
  }, [targets, runs]);

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    setCreating(true);
    try {
      const ws = await api.createWorkspace({
        name: name.trim(),
        description: description.trim() || undefined,
      });
      toast.success('Workspace created', ws.name);
      setName('');
      setDescription('');
      reload();
    } catch (err) {
      toast.fromError(err, 'Create failed');
    } finally {
      setCreating(false);
    }
  };

  return (
    <div className="grid">
      <div className="card">
        <div className="row space">
          <h3><Boxes size={18} style={{ verticalAlign: 'middle', marginRight: 6 }} /> Workspaces</h3>
          <span className="muted">
            One workspace per engagement. Targets, runs, findings, and loot are scoped to their workspace.
          </span>
        </div>
      </div>

      {/* Create form — admin only; gracefully hidden otherwise */}
      {isAdmin ? (
        <form className="card" onSubmit={create}>
          <div className="row space"><strong><FolderPlus size={14} style={{ verticalAlign: 'middle', marginRight: 6 }} />Create workspace</strong></div>
          <div className="grid cols-2" style={{ alignItems: 'end' }}>
            <input
              className="input"
              placeholder="Workspace name (required)"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              maxLength={120}
            />
            <input
              className="input"
              placeholder="Short description (optional)"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              maxLength={500}
            />
          </div>
          <div className="row space" style={{ marginTop: 8 }}>
            <span className="muted">{creating ? 'Creating…' : 'Stored in Postgres; targets/runs created later attach via workspace_id.'}</span>
            <button className="btn" type="submit" disabled={creating || !name.trim()}>
              <FolderPlus size={14} /> {creating ? 'Creating…' : 'Create'}
            </button>
          </div>
        </form>
      ) : (
        <div className="card admin-only-card">
          <div className="row">
            <Lock size={14} color="#94a3b8" />
            <span className="muted">Workspace creation is admin-only. {me ? `Signed in as ${me.role}.` : ''}</span>
          </div>
        </div>
      )}

      {error && (
        <div className="card">
          <p className="advice-error"><ShieldAlert size={14} /> {error}</p>
        </div>
      )}

      {workspaces.length === 0 && !error && (
        <EmptyState
          icon={<Boxes size={28} />}
          title="No workspaces"
          body={isAdmin
            ? 'Create one above to start scoping targets and runs.'
            : 'No workspaces exist yet. Ask an admin to create one.'}
        />
      )}

      <div className="workspaces-grid">
        {workspaces.map((ws) => {
          const s = stats[ws.id] ?? { targets: 0, runs: 0, activeRuns: 0, lastRun: null };
          return (
            <div key={ws.id} className="card workspace-card">
              <div className="row space">
                <strong className="workspace-name">{ws.name}</strong>
                {s.activeRuns > 0 && (
                  <span className="badge active" title={`${s.activeRuns} active run(s)`}><span className="dot-blink" /> {s.activeRuns} active</span>
                )}
              </div>
              <p className="muted workspace-desc">{ws.description || '—'}</p>
              <div className="workspace-stats">
                <div className="workspace-stat"><Crosshair size={12} /><span>{s.targets}</span><small className="muted">targets</small></div>
                <div className="workspace-stat"><TerminalSquare size={12} /><span>{s.runs}</span><small className="muted">runs</small></div>
                <div className="workspace-stat"><Coins size={12} /><small className="muted">loot</small></div>
              </div>
              <div className="row space" style={{ marginTop: 8 }}>
                <span className="muted small">Last run: {relTime(s.lastRun)}</span>
                <span className="mono small muted" title={ws.id}>{ws.id.slice(0, 14)}…</span>
              </div>
              <div className="row" style={{ marginTop: 10, flexWrap: 'wrap', gap: 6 }}>
                <button className="btn small" onClick={() => navigate('targets')} title="Open the Targets page">
                  Targets
                </button>
                <button className="btn small" onClick={() => navigate('runs')} title="Open the Runs page">
                  Runs
                </button>
                <button className="btn small" onClick={() => navigate('loot', { workspaceId: ws.id })} title="Open Loot filtered to this workspace">
                  Loot
                </button>
                <button className="btn small" onClick={() => navigate('templates')} title="Launch a scan template">
                  Launch
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
