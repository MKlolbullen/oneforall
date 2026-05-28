import { useEffect, useMemo, useState } from 'react';
import { CheckCircle2, FileText, Lock, RefreshCw, Search, ShieldAlert, X } from 'lucide-react';
import { api } from './api';
import { CopyButton } from './CopyButton';
import { EmptyState } from './EmptyState';
import type { AuditEvent, AuditPage } from '../types';

function relTime(iso?: string | null): string {
  if (!iso) return '—';
  const ms = Date.now() - new Date(iso).getTime();
  if (ms < 60_000) return `${Math.max(1, Math.floor(ms / 1000))}s ago`;
  if (ms < 3_600_000) return `${Math.floor(ms / 60_000)}m ago`;
  if (ms < 86_400_000) return `${Math.floor(ms / 3_600_000)}h ago`;
  return `${Math.floor(ms / 86_400_000)}d ago`;
}

const LIMITS = [50, 100, 250, 500];

export function AuditLog() {
  const [data, setData] = useState<AuditPage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [limit, setLimit] = useState(100);
  const [q, setQ] = useState('');
  const [actor, setActor] = useState('');
  const [kind, setKind] = useState('');
  const [selected, setSelected] = useState<AuditEvent | null>(null);

  const reload = async (nextLimit = limit) => {
    setLoading(true);
    setError(null);
    try {
      const page = await api.audit(nextLimit);
      setData(page);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { reload(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, []);

  const events = data?.events ?? [];
  const actors = useMemo(
    () => Array.from(new Set(events.map((e) => e.actor_role).filter((x): x is string => Boolean(x)))).sort(),
    [events],
  );
  const kinds = useMemo(
    () => Array.from(new Set(events.map((e) => e.target_kind).filter((x): x is string => Boolean(x)))).sort(),
    [events],
  );
  const filtered = useMemo(() => events.filter((e) => {
    if (actor && e.actor_role !== actor) return false;
    if (kind && e.target_kind !== kind) return false;
    if (q) {
      const needle = q.toLowerCase();
      const hay = `${e.action} ${e.target_id ?? ''} ${e.actor_id ?? ''}`.toLowerCase();
      if (!hay.includes(needle)) return false;
    }
    return true;
  }), [events, actor, kind, q]);

  // Permission-denied + general error handling. /api/auth/audit requires admin.
  if (error) {
    const isForbidden = /403|forbid/i.test(error);
    return (
      <div className="card">
        <div className="row space"><h3>Audit log</h3>{!isForbidden && <button className="btn small" onClick={() => reload()}><RefreshCw size={14} /></button>}</div>
        {isForbidden ? (
          <EmptyState
            icon={<Lock size={28} />}
            title="Admin-only"
            body="The audit log is only visible to admin users. Sign in as an admin to view the append-only, hash-chained record of platform actions."
          />
        ) : (
          <p className="advice-error"><ShieldAlert size={14} /> {error}</p>
        )}
      </div>
    );
  }

  return (
    <div className="grid">
      <div className="card">
        <div className="row space">
          <h3><FileText size={18} style={{ verticalAlign: 'middle', marginRight: 6 }} /> Audit log</h3>
          <span className="muted">
            Append-only, hash-chained record. Every login, run, target, key and workspace mutation lands here.
          </span>
        </div>
        <div className="toolbar availability-toolbar">
          <div className="row" style={{ flex: 1, position: 'relative' }}>
            <Search size={14} style={{ position: 'absolute', left: 8, opacity: 0.5 }} />
            <input
              className="input"
              style={{ paddingLeft: 28 }}
              placeholder="Filter by action, target id, actor id…"
              value={q}
              onChange={(e) => setQ(e.target.value)}
            />
          </div>
          <select className="input" value={actor} onChange={(e) => setActor(e.target.value)}>
            <option value="">All actor roles</option>
            {actors.map((a) => <option key={a} value={a}>{a}</option>)}
          </select>
          <select className="input" value={kind} onChange={(e) => setKind(e.target.value)}>
            <option value="">All target kinds</option>
            {kinds.map((k) => <option key={k} value={k}>{k}</option>)}
          </select>
          <select className="input" value={limit} onChange={(e) => { const n = Number(e.target.value); setLimit(n); reload(n); }}>
            {LIMITS.map((l) => <option key={l} value={l}>Last {l}</option>)}
          </select>
          <button className="btn small" onClick={() => reload()} disabled={loading}>
            <RefreshCw size={14} className={loading ? 'spin' : ''} /> Refresh
          </button>
        </div>
      </div>

      {/* Chain verification banner — green pill or breaks listed */}
      {data && (
        data.ok ? (
          <div className="card chain-banner ok">
            <div className="row"><CheckCircle2 size={16} color="#22c55e" /><strong>Hash chain verified.</strong>
              <span className="muted">All {events.length} events form a contiguous, signed chain.</span>
            </div>
          </div>
        ) : (
          <div className="card chain-banner bad">
            <div className="row"><ShieldAlert size={16} color="#fca5a5" /><strong>Hash chain broken</strong></div>
            <ul className="muted">
              {data.breaks.map((b) => <li key={b.sequence}>seq #{b.sequence}: {b.reason}</li>)}
            </ul>
          </div>
        )
      )}

      <div className="card">
        {filtered.length === 0 && events.length > 0 && (
          <p className="muted">No events match the current filters.</p>
        )}
        {events.length === 0 && (
          <EmptyState icon={<FileText size={28} />} title="No audit events" body="Login or create a workspace to generate the first audit row." />
        )}
        {filtered.length > 0 && (
          <table className="table compact">
            <thead><tr><th>#</th><th>Action</th><th>Role</th><th>Target</th><th>When</th><th /></tr></thead>
            <tbody>
              {filtered.map((e) => (
                <tr key={e.sequence} onClick={() => setSelected(e)} style={{ cursor: 'pointer' }}>
                  <td className="mono small">#{e.sequence}</td>
                  <td><span className="badge passive">{e.action}</span></td>
                  <td><span className="muted small">{e.actor_role ?? '—'}</span></td>
                  <td>
                    {e.target_kind ? <span className="muted small">{e.target_kind}:</span> : ''}
                    <span className="mono small"> {e.target_id ? e.target_id.slice(0, 24) + (e.target_id.length > 24 ? '…' : '') : '—'}</span>
                  </td>
                  <td className="muted small" title={e.created_at}>{relTime(e.created_at)}</td>
                  <td><Search size={12} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <p className="muted small" style={{ marginTop: 8 }}>
          Showing {filtered.length}{filtered.length !== events.length ? ` of ${events.length}` : ''} events.
        </p>
      </div>

      {selected && <AuditEventModal event={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}

function AuditEventModal({ event, onClose }: { event: AuditEvent; onClose: () => void }) {
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal audit-modal" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
        <div className="modal-header">
          <span className="row">
            <FileText size={14} />
            <strong>Audit event #{event.sequence}</strong>
            <span className="badge passive">{event.action}</span>
          </span>
          <button className="icon-btn" onClick={onClose} type="button" aria-label="Close"><X size={14} /></button>
        </div>
        <div className="grid">
          <KV label="When" value={event.created_at} />
          <KV label="Actor role" value={event.actor_role ?? '—'} />
          <KV label="Actor ID" value={<span className="mono">{event.actor_id ?? '—'}</span>} />
          <KV label="Target" value={
            <span className="mono">{event.target_kind ? `${event.target_kind}:` : ''}{event.target_id ?? '—'}</span>
          } />
          <div>
            <div className="row space"><span className="muted">Payload</span><CopyButton value={JSON.stringify(event.payload)} title="Copy payload JSON" /></div>
            <pre className="mono audit-payload">{JSON.stringify(event.payload, null, 2)}</pre>
          </div>
          <div>
            <div className="row space"><span className="muted">Chain</span><CopyButton value={event.signature} title="Copy signature" /></div>
            <KV label="prev_signature" value={<span className="mono small">{event.prev_signature ? event.prev_signature.slice(0, 32) + '…' : '(genesis)'}</span>} />
            <KV label="signature" value={<span className="mono small">{event.signature.slice(0, 32)}…</span>} />
          </div>
        </div>
      </div>
    </div>
  );
}

function KV({ label, value }: { label: string; value: React.ReactNode }) {
  return <div className="kv"><span className="muted">{label}</span><strong>{value}</strong></div>;
}
