import { useEffect, useMemo, useState } from 'react';
import { Crosshair, Package, Rocket, ShieldAlert, Tag, Terminal, X } from 'lucide-react';
import { api } from './api';
import { useNav } from './nav';
import { useToast } from './Toast';
import type { Target, Tool, Workspace } from '../types';

/**
 * Side modal for inspecting a registry tool — full IO types, default argv,
 * install info, plus a "Quick launch" CTA that builds a 1-step ad-hoc
 * workflow and queues it. This makes the Tool Catalog actionable instead of
 * purely informational.
 */
export function ToolDetailModal({ tool, onClose }: { tool: Tool; onClose: () => void }) {
  const toast = useToast();
  const { navigate } = useNav();
  const [showLaunch, setShowLaunch] = useState(false);
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [workspaceId, setWorkspaceId] = useState('');
  const [targetId, setTargetId] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    Promise.all([api.workspaces(), api.targets()])
      .then(([ws, ts]) => {
        setWorkspaces(ws); setTargets(ts);
        if (ws[0]) setWorkspaceId(ws[0].id);
      })
      .catch((e) => toast.fromError(e, 'Failed to load workspaces'));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const workspaceTargets = useMemo(
    () => targets.filter((t) => !workspaceId || t.workspace_id === workspaceId),
    [targets, workspaceId],
  );
  const selected = targets.find((t) => t.id === targetId) ?? null;
  const needsActive = tool.risk !== 'passive';
  const targetReady = selected != null && (!needsActive || selected.active_allowed);

  const quickLaunch = async () => {
    if (!selected || !targetReady) return;
    setBusy(true);
    try {
      const run = await api.createAdhocRun({
        workspace_id: selected.workspace_id,
        target_id: selected.id,
        name: `Quick: ${tool.name}`,
        steps: [{ tool: tool.id }],
      });
      toast.success('Quick run queued', `${tool.name} → ${selected.value}`);
      onClose();
      navigate('runs', { runId: run.id });
    } catch (e) {
      toast.fromError(e, 'Quick launch failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal tool-modal" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
        <div className="modal-header">
          <span className="row">
            <Terminal size={16} color="#22d3ee" />
            <strong>{tool.name}</strong>
            <span className="muted mono small">{tool.id}</span>
          </span>
          <button className="icon-btn" onClick={onClose} type="button" aria-label="Close"><X size={14} /></button>
        </div>

        <p className="muted">{tool.description || '(no description)'}</p>

        <div className="row" style={{ flexWrap: 'wrap', gap: 4 }}>
          <span className="badge passive">{tool.category}</span>
          <span className={`badge ${tool.risk === 'passive' ? 'passive' : tool.risk === 'high_active' ? 'bad' : 'active'}`}>{tool.risk}</span>
          {tool.requires_authorization && <span className="badge active">auth required</span>}
          {tool.binary && <span className="muted mono small">binary: {tool.binary}</span>}
        </div>

        <div className="tool-section">
          <strong>Inputs</strong>
          {(tool.inputs ?? []).length === 0 ? (
            <p className="muted small">None declared.</p>
          ) : (
            <div className="tool-io-row">
              {(tool.inputs ?? []).map((io) => (
                <span key={io.name} className="wf-io-pill in">
                  ◂ {io.name} <small className="muted">· {io.type}</small>
                  {io.required && <small style={{ color: '#fca5a5', marginLeft: 4 }}>required</small>}
                </span>
              ))}
            </div>
          )}
        </div>

        <div className="tool-section">
          <strong>Outputs</strong>
          {(tool.outputs ?? []).length === 0 ? (
            <p className="muted small">None declared.</p>
          ) : (
            <div className="tool-io-row">
              {(tool.outputs ?? []).map((io) => (
                <span key={io.name} className="wf-io-pill out">
                  {io.name} <small className="muted">· {io.type}</small> ▸
                </span>
              ))}
            </div>
          )}
        </div>

        {tool.command?.argv && (
          <div className="tool-section">
            <strong>Default command</strong>
            <pre className="mono wf-argv">{tool.command.argv.join(' ')}</pre>
            <small className="muted">
              Placeholders like <code>{'{{target}}'}</code> are replaced at run time.
              Drop this tool into the Workflow Builder canvas to override argv.
            </small>
          </div>
        )}

        {tool.tags && tool.tags.length > 0 && (
          <div className="tool-section">
            <strong><Tag size={12} style={{ verticalAlign: 'middle', marginRight: 4 }} /> Tags</strong>
            <div className="tag-list">
              {tool.tags.map((t) => <span key={t} className="tag">{t}</span>)}
            </div>
          </div>
        )}

        <div className="tool-section">
          <strong>Run policy defaults</strong>
          <div className="row" style={{ flexWrap: 'wrap', gap: 12 }}>
            <span className="muted small">timeout: <strong>{tool.default_timeout_seconds ?? 900}s</strong></span>
            <span className="muted small">retries: <strong>{tool.max_retries ?? 0}</strong></span>
            <span className="muted small">backoff: <strong>{tool.retry_backoff_seconds ?? 1.0}s</strong></span>
            <span className="muted small">continue_on_error: <strong>{String(tool.continue_on_error ?? false)}</strong></span>
          </div>
        </div>

        <div className="modal-actions">
          {!showLaunch ? (
            <button
              className="btn"
              onClick={() => setShowLaunch(true)}
              type="button"
              title="Build a 1-step ad-hoc workflow with this tool and queue it"
            >
              <Rocket size={14} /> Quick run on a target…
            </button>
          ) : (
            <div className="grid" style={{ flex: 1, gap: 8 }}>
              <p className="muted small">
                Quick-launch creates a 1-step ad-hoc workflow with the tool's
                default argv. Use the Workflow Builder if you need to override
                argv, chain steps, or save it as a workflow.
              </p>
              <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
                <select className="input" style={{ maxWidth: 200 }} value={workspaceId}
                        onChange={(e) => { setWorkspaceId(e.target.value); setTargetId(''); }}>
                  {workspaces.map((w) => <option key={w.id} value={w.id}>{w.name}</option>)}
                </select>
                <select className="input" style={{ minWidth: 240 }} value={targetId}
                        onChange={(e) => setTargetId(e.target.value)}>
                  <option value="">— Target —</option>
                  {workspaceTargets.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.value}{needsActive && !t.active_allowed ? ' (passive only — blocked)' : ''}
                    </option>
                  ))}
                </select>
              </div>
              {selected && !targetReady && (
                <p className="warning-text" style={{ margin: 0, fontSize: 12 }}>
                  <ShieldAlert size={12} /> {selected.value} has no active-scan authorization, but {tool.name} is {tool.risk}. Open Targets to authorize.
                </p>
              )}
              <div className="row" style={{ gap: 8 }}>
                <button className="btn small" type="button" onClick={() => setShowLaunch(false)}>Cancel</button>
                <button className="btn" type="button" onClick={quickLaunch} disabled={!targetReady || busy}>
                  <Rocket size={14} /> {busy ? 'Queueing…' : 'Queue run'}
                </button>
              </div>
            </div>
          )}
          {tool.install && Object.keys(tool.install).length > 0 && (
            <details style={{ marginTop: 8 }}>
              <summary className="muted small"><Package size={12} style={{ verticalAlign: 'middle', marginRight: 4 }} /> Install</summary>
              <pre className="mono wf-argv">{JSON.stringify(tool.install, null, 2)}</pre>
            </details>
          )}
        </div>
      </div>
    </div>
  );
}
