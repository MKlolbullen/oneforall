import { useEffect, useMemo, useState } from 'react';
import { ChevronDown, ChevronRight, RefreshCw } from 'lucide-react';
import { api } from './api';
import type { HttpExchangeDetail, HttpExchangeSummary, NetworkPage } from '../types';

type Props = { runId: string };

function statusClass(s: number | null | undefined): string {
  if (s == null) return 'badge';
  if (s >= 500) return 'badge bad';
  if (s >= 400) return 'badge active';
  if (s >= 300) return 'badge passive';
  if (s >= 200) return 'badge ok';
  return 'badge';
}

function fmtBytes(n: number | null | undefined): string {
  if (n == null) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function fmtDuration(ms: number | null | undefined): string {
  if (ms == null) return '—';
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

export function NetworkTab({ runId }: Props) {
  const [page, setPage] = useState<NetworkPage | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [host, setHost] = useState<string>('');
  const [method, setMethod] = useState<string>('');
  const [status, setStatus] = useState<string>('');
  const [pageOffset, setPageOffset] = useState(0);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<HttpExchangeDetail | null>(null);

  const limit = 100;

  const reload = async () => {
    setLoading(true); setError(null);
    try {
      const opts: Parameters<typeof api.runNetwork>[1] = { limit, offset: pageOffset };
      if (host) opts.host = host;
      if (method) opts.method = method;
      if (status) opts.status = Number(status);
      const p = await api.runNetwork(runId, opts);
      setPage(p);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally { setLoading(false); }
  };

  // Reload when run changes or filters/page change
  useEffect(() => { reload(); /* eslint-disable-next-line */ }, [runId, host, method, status, pageOffset]);

  // Load detail panel when an exchange is picked
  useEffect(() => {
    if (!selectedId) { setDetail(null); return; }
    let cancelled = false;
    api.runExchange(runId, selectedId)
      .then((d) => { if (!cancelled) setDetail(d); })
      .catch(() => { if (!cancelled) setDetail(null); });
    return () => { cancelled = true; };
  }, [runId, selectedId]);

  const totalPages = page ? Math.max(1, Math.ceil(page.total / limit)) : 1;
  const currentPage = Math.floor(pageOffset / limit) + 1;
  const items = page?.items ?? [];

  const distinctHosts = useMemo(() => page?.hosts ?? [], [page]);
  const distinctMethods = useMemo(() => page?.methods ?? [], [page]);
  const distinctStatuses = useMemo(() => page?.statuses ?? [], [page]);

  return (
    <div className="grid network-tab">
      <div className="row space network-toolbar">
        <div className="row">
          <select className="input" value={host} onChange={(e) => { setHost(e.target.value); setPageOffset(0); }}>
            <option value="">all hosts</option>
            {distinctHosts.map((h) => <option key={h} value={h}>{h}</option>)}
          </select>
          <select className="input" value={method} onChange={(e) => { setMethod(e.target.value); setPageOffset(0); }}>
            <option value="">all methods</option>
            {distinctMethods.map((m) => <option key={m} value={m}>{m}</option>)}
          </select>
          <select className="input" value={status} onChange={(e) => { setStatus(e.target.value); setPageOffset(0); }}>
            <option value="">all status</option>
            {distinctStatuses.map((s) => <option key={s} value={String(s)}>{s}</option>)}
          </select>
        </div>
        <div className="row">
          <span className="muted">{page ? `${page.total} requests` : '...'}</span>
          <button className="btn small" type="button" onClick={() => reload()} disabled={loading}>
            <RefreshCw size={13} className={loading ? 'spin' : ''} /> Refresh
          </button>
        </div>
      </div>
      {error && <p className="advice-error">{error}</p>}
      <table className="table compact network-table">
        <thead><tr>
          <th style={{ width: 18 }}></th>
          <th>Method</th>
          <th>URL</th>
          <th>Status</th>
          <th>Size</th>
          <th>Time</th>
          <th>Step</th>
        </tr></thead>
        <tbody>
          {items.map((row) => (
            <NetworkRow
              key={row.id}
              row={row}
              selected={selectedId === row.id}
              detail={selectedId === row.id ? detail : null}
              onToggle={() => setSelectedId(selectedId === row.id ? null : row.id)}
            />
          ))}
          {items.length === 0 && !loading && (
            <tr><td colSpan={7} className="muted" style={{ padding: 16 }}>
              No HTTP traffic captured. Capture only runs in live mode and requires <code>proxify</code> on the worker's PATH.
            </td></tr>
          )}
        </tbody>
      </table>
      {totalPages > 1 && (
        <div className="row space">
          <span className="muted">page {currentPage} / {totalPages}</span>
          <div className="row">
            <button className="btn small" type="button" disabled={pageOffset === 0}
                    onClick={() => setPageOffset(Math.max(0, pageOffset - limit))}>Prev</button>
            <button className="btn small" type="button" disabled={currentPage >= totalPages}
                    onClick={() => setPageOffset(pageOffset + limit)}>Next</button>
          </div>
        </div>
      )}
    </div>
  );
}

function NetworkRow({
  row, selected, detail, onToggle,
}: {
  row: HttpExchangeSummary;
  selected: boolean;
  detail: HttpExchangeDetail | null;
  onToggle: () => void;
}) {
  return (
    <>
      <tr className={`network-row ${selected ? 'selected' : ''}`} onClick={onToggle}>
        <td>{selected ? <ChevronDown size={12} /> : <ChevronRight size={12} />}</td>
        <td><span className="badge passive mono">{row.method}</span></td>
        <td className="mono"><div className="ellipsis-cell" title={row.url}>{row.url}</div></td>
        <td><span className={statusClass(row.response_status)}>{row.response_status ?? '—'}</span></td>
        <td>{fmtBytes(row.response_size_bytes)}</td>
        <td>{fmtDuration(row.duration_ms)}</td>
        <td>{row.step_index != null ? `#${row.step_index} ${row.tool_id ?? ''}` : '—'}</td>
      </tr>
      {selected && (
        <tr className="network-detail-row">
          <td colSpan={7}>
            {!detail && <p className="muted">Loading…</p>}
            {detail && <ExchangeDetail d={detail} />}
          </td>
        </tr>
      )}
    </>
  );
}

function ExchangeDetail({ d }: { d: HttpExchangeDetail }) {
  return (
    <div className="grid cols-2 network-detail">
      <div>
        <div className="row space"><strong>Request</strong>{d.request_body_truncated && <span className="badge bad">body truncated</span>}</div>
        <pre className="exchange-block">
{`${d.method} ${d.url}\n` + Object.entries(d.request_headers ?? {}).map(([k,v]) => `${k}: ${v}`).join('\n')}
        </pre>
        {d.request_body && <pre className="exchange-body">{d.request_body}</pre>}
      </div>
      <div>
        <div className="row space"><strong>Response</strong>{d.response_body_truncated && <span className="badge bad">body truncated</span>}</div>
        <pre className="exchange-block">
{`HTTP ${d.response_status ?? '???'}\n` + Object.entries(d.response_headers ?? {}).map(([k,v]) => `${k}: ${v}`).join('\n')}
        </pre>
        {d.response_body && <pre className="exchange-body">{d.response_body}</pre>}
      </div>
    </div>
  );
}
