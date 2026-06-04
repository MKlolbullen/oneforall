import { useCallback, useEffect, useMemo, useState } from 'react';
import { AlertTriangle, Bell, CheckCircle2, Plus, RefreshCw, Send, Trash2, X } from 'lucide-react';
import { api } from './api';
import { EmptyState } from './EmptyState';
import { useConfirm } from './Confirm';
import { useToast } from './Toast';
import { useWorkspace } from './WorkspaceContext';
import type { Webhook } from '../types';

/** Operator-friendly UI for DB-backed outbound webhooks. Workspace-scoped:
 *  every engagement can wire its own Slack / Discord / generic JSON receiver
 *  without touching the platform YAML. */
const KNOWN_EVENTS = ['run.completed', 'run.failed', 'run.cancelled'] as const;
type WebhookEvent = (typeof KNOWN_EVENTS)[number];

function relTime(iso: string | null | undefined): string {
  if (!iso) return 'never';
  const ms = Date.now() - new Date(iso).getTime();
  if (ms < 60_000) return `${Math.max(1, Math.floor(ms / 1000))}s ago`;
  if (ms < 3_600_000) return `${Math.floor(ms / 60_000)}m ago`;
  if (ms < 86_400_000) return `${Math.floor(ms / 3_600_000)}h ago`;
  return `${Math.floor(ms / 86_400_000)}d ago`;
}

export function Webhooks() {
  const toast = useToast();
  const confirm = useConfirm();
  // Workspace comes from the global topbar selector; the create form
  // posts to whichever workspace the operator has active. `null` means
  // "All workspaces" and the create form falls back to the first one.
  const { workspaces, activeWorkspaceId } = useWorkspace();
  const [hooks, setHooks] = useState<Webhook[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [testing, setTesting] = useState<string | null>(null);

  // Create form
  const [name, setName] = useState('');
  const [url, setUrl] = useState('');
  const [events, setEvents] = useState<WebhookEvent[]>(['run.completed', 'run.failed']);
  const [creating, setCreating] = useState(false);

  const reload = useCallback(async () => {
    try {
      const rows = await api.webhooks(activeWorkspaceId ?? undefined);
      setHooks(rows);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [activeWorkspaceId]);

  useEffect(() => {
    // No-op — workspaces are loaded by the context provider.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => { reload(); }, [reload]);

  const toggleEvent = (event: WebhookEvent) => {
    setEvents((prev) =>
      prev.includes(event) ? prev.filter((e) => e !== event) : [...prev, event]
    );
  };

  // The webhook is created in the workspace the topbar has active.
  // If the operator chose "All workspaces" we fall back to the first
  // workspace so the form can still post; ambiguity here would mean
  // creating without scope, which the backend rejects with 404.
  const createInWorkspaceId = activeWorkspaceId ?? workspaces[0]?.id ?? null;

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!createInWorkspaceId) {
      toast.warn('No workspace', 'Open the Workspaces page and create one first.');
      return;
    }
    if (events.length === 0) {
      toast.warn('Pick at least one event', 'Otherwise the webhook will never fire.');
      return;
    }
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      toast.warn('Invalid URL', 'URL must start with http:// or https://.');
      return;
    }
    setCreating(true);
    try {
      await api.createWebhook({
        workspace_id: createInWorkspaceId, name: name.trim(), url: url.trim(),
        events, is_active: true,
      });
      toast.success('Webhook created', `${name} → ${events.length} event${events.length === 1 ? '' : 's'}`);
      setName(''); setUrl('');
      setEvents(['run.completed', 'run.failed']);
      reload();
    } catch (err) {
      toast.fromError(err, 'Create failed');
    } finally {
      setCreating(false);
    }
  };

  const toggleActive = async (wh: Webhook) => {
    try {
      await api.updateWebhook(wh.id, { is_active: !wh.is_active });
      reload();
    } catch (err) { toast.fromError(err, 'Update failed'); }
  };

  const test = async (wh: Webhook) => {
    setTesting(wh.id);
    try {
      const result = await api.testWebhook(wh.id);
      if (result.delivered) {
        toast.success('Webhook delivered', `${wh.name} (HTTP ${result.status})`);
      } else {
        toast.warn('Webhook test failed', result.error ?? 'unknown error');
      }
      reload();
    } catch (err) {
      toast.fromError(err, 'Test failed');
    } finally {
      setTesting(null);
    }
  };

  const remove = async (wh: Webhook) => {
    const ok = await confirm({
      title: `Delete webhook "${wh.name}"?`,
      body: `This stops all event delivery to ${wh.url.slice(0, 60)}${wh.url.length > 60 ? '…' : ''}.`,
      confirmLabel: 'Delete',
      cancelLabel: 'Keep',
      destructive: true,
    });
    if (!ok) return;
    try {
      await api.deleteWebhook(wh.id);
      toast.success('Webhook deleted', wh.name);
      reload();
    } catch (err) { toast.fromError(err, 'Delete failed'); }
  };

  const counts = useMemo(() => {
    const active = hooks.filter((h) => h.is_active).length;
    const failing = hooks.filter((h) => h.last_status != null && h.last_status >= 300).length;
    const ok = hooks.filter((h) => h.last_status != null && h.last_status < 300).length;
    return { active, failing, ok };
  }, [hooks]);

  return (
    <div className="grid">
      <div className="card">
        <div className="row space">
          <h3><Bell size={18} style={{ verticalAlign: 'middle', marginRight: 6 }} /> Webhooks</h3>
          <span className="muted">
            Outbound HTTP notifications fired on run lifecycle events. Slack / Discord / generic JSON — anything that accepts a <code>{`{ "text": "…" }`}</code> POST.
          </span>
        </div>
        <div className="toolbar availability-toolbar">
          <span className="muted small">
            scope: <strong>{activeWorkspaceId ? (workspaces.find((w) => w.id === activeWorkspaceId)?.name ?? '—') : 'all workspaces'}</strong>
            <span className="muted" style={{ marginLeft: 4 }}>(change in the topbar)</span>
          </span>
          <button className="btn small" type="button" onClick={() => reload()} title="Refresh"><RefreshCw size={14} /> Refresh</button>
          <span className="muted small" style={{ marginLeft: 'auto' }}>
            {hooks.length} total · {counts.active} active · {counts.ok} healthy · {counts.failing} failing
          </span>
        </div>
      </div>

      <form className="card" onSubmit={create}>
        <div className="row space"><strong><Plus size={14} style={{ verticalAlign: 'middle', marginRight: 4 }} />Add webhook</strong></div>
        <div className="grid cols-2" style={{ alignItems: 'end' }}>
          <input className="input" placeholder="Name (e.g. ops-slack)"
                 value={name} onChange={(e) => setName(e.target.value)}
                 required maxLength={120} />
          <input className="input" placeholder="https://hooks.slack.com/services/T…/B…/X…"
                 value={url} onChange={(e) => setUrl(e.target.value)}
                 required maxLength={2048} />
        </div>
        <div className="row" style={{ gap: 12, flexWrap: 'wrap', marginTop: 8 }}>
          <span className="muted small">Fire on:</span>
          {KNOWN_EVENTS.map((event) => (
            <label key={event} className="row muted small" style={{ gap: 4 }}>
              <input
                type="checkbox"
                checked={events.includes(event)}
                onChange={() => toggleEvent(event)}
              />
              <code>{event}</code>
            </label>
          ))}
        </div>
        <div className="row space" style={{ marginTop: 8 }}>
          <span className="muted small">
            The receiver gets a single <code>{`{ "text": "…" }`}</code> POST with the run id, profile, target, and (on failure) the error.
          </span>
          <button className="btn" type="submit" disabled={creating || !name.trim() || !url.trim() || !createInWorkspaceId}>
            <Plus size={14} /> {creating ? 'Creating…' : 'Add webhook'}
          </button>
        </div>
      </form>

      {error && (
        <div className="card">
          <p className="advice-error"><AlertTriangle size={14} /> {error}</p>
        </div>
      )}

      {hooks.length === 0 && !error ? (
        <EmptyState
          icon={<Bell size={28} />}
          title="No webhooks in this workspace"
          body="Add one above to push run completion / failure / cancellation events to a chat channel or generic JSON receiver."
        />
      ) : (
        <div className="card">
          <table className="table">
            <thead><tr><th>Name</th><th>URL</th><th>Events</th><th>Status</th><th>Last delivery</th><th /></tr></thead>
            <tbody>
              {hooks.map((wh) => (
                <tr key={wh.id}>
                  <td>
                    <strong>{wh.name}</strong>
                    <br /><span className="muted mono small">{wh.id}</span>
                  </td>
                  <td>
                    <span className="mono small" title={wh.url}>
                      {wh.url.length > 50 ? wh.url.slice(0, 50) + '…' : wh.url}
                    </span>
                  </td>
                  <td>
                    <div className="tag-list">
                      {(wh.events ?? []).map((e) => <span key={e} className="tag">{e}</span>)}
                    </div>
                  </td>
                  <td>
                    <span className={wh.is_active ? 'badge ok' : 'badge'}>
                      {wh.is_active ? 'active' : 'paused'}
                    </span>
                    {wh.last_status != null && (
                      <>
                        <br />
                        <span className={`badge ${wh.last_status < 300 ? 'ok' : 'bad'}`} style={{ marginTop: 4 }}>
                          HTTP {wh.last_status}
                        </span>
                      </>
                    )}
                    {wh.last_error && wh.last_status == null && (
                      <>
                        <br />
                        <span className="badge bad" style={{ marginTop: 4 }} title={wh.last_error}>
                          network error
                        </span>
                      </>
                    )}
                  </td>
                  <td className="muted small" title={wh.last_used_at ?? 'never'}>
                    {relTime(wh.last_used_at)}
                    {wh.last_error && (
                      <>
                        <br />
                        <span className="muted small" style={{ color: '#fca5a5' }} title={wh.last_error}>
                          {wh.last_error.length > 50 ? wh.last_error.slice(0, 50) + '…' : wh.last_error}
                        </span>
                      </>
                    )}
                  </td>
                  <td>
                    <div className="row" style={{ gap: 4 }}>
                      <button
                        className="btn small"
                        type="button"
                        onClick={() => test(wh)}
                        disabled={testing === wh.id}
                        title="Send a synthetic message to verify the URL"
                      >
                        <Send size={12} /> {testing === wh.id ? 'Testing…' : 'Test'}
                      </button>
                      <button
                        className="btn small"
                        type="button"
                        onClick={() => toggleActive(wh)}
                        title={wh.is_active ? 'Pause delivery' : 'Resume delivery'}
                      >
                        {wh.is_active ? 'Pause' : 'Resume'}
                      </button>
                      <button
                        className="icon-btn danger"
                        type="button"
                        onClick={() => remove(wh)}
                        aria-label="Delete"
                        title="Delete this webhook"
                      >
                        <Trash2 size={12} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {hooks.some((h) => h.is_active && h.last_status != null && h.last_status < 300) && (
            <p className="muted small" style={{ marginTop: 8 }}>
              <CheckCircle2 size={12} color="#22c55e" /> Healthy hooks have shipped a successful delivery in the past.
              Use Test to verify after URL changes.
            </p>
          )}
        </div>
      )}
    </div>
  );
}
