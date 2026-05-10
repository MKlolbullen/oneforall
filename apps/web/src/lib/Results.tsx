import { useEffect, useMemo, useState } from 'react';
import { ChevronDown, ChevronRight, Filter, RefreshCw, Search, ShieldAlert } from 'lucide-react';
import { api } from './api';
import { AdvicePanel } from './AdvicePanel';
import type { Finding, FindingPage, Workspace } from '../types';

const SEVERITY_RANK: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5,
};
const STATUS_OPTIONS = ['new', 'triaged', 'false_positive', 'fixed', 'closed'] as const;

function severityBadgeClass(sev: string): string {
  if (sev === 'critical' || sev === 'high') return 'badge bad';
  if (sev === 'medium') return 'badge active';
  if (sev === 'low') return 'badge passive';
  return 'badge';
}

function statusBadgeClass(s: string): string {
  if (s === 'fixed' || s === 'closed') return 'badge ok';
  if (s === 'false_positive') return 'badge passive';
  if (s === 'triaged') return 'badge active';
  return 'badge';
}

export function Results() {
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [workspaceId, setWorkspaceId] = useState('');
  const [page, setPage] = useState<FindingPage | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [severity, setSeverity] = useState('');
  const [status, setStatus] = useState('');
  const [tool, setTool] = useState('');
  const [q, setQ] = useState('');
  const [offset, setOffset] = useState(0);

  // Selection
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const limit = 50;

  // Initial: load workspaces, default to the first one.
  useEffect(() => {
    api.workspaces().then((ws) => {
      setWorkspaces(ws);
      if (ws[0]) setWorkspaceId(ws[0].id);
    }).catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);

  const reload = async () => {
    if (!workspaceId) return;
    setLoading(true); setError(null);
    try {
      const result = await api.findings({
        workspace_id: workspaceId,
        severity: severity || undefined,
        status: status || undefined,
        tool: tool || undefined,
        q: q || undefined,
        limit, offset,
      });
      setPage(result);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally { setLoading(false); }
  };

  // Reload on filter / page / workspace change
  useEffect(() => { reload(); /* eslint-disable-next-line */ },
    [workspaceId, severity, status, tool, q, offset]);

  const totalPages = page ? Math.max(1, Math.ceil(page.total / limit)) : 1;
  const currentPage = Math.floor(offset / limit) + 1;
  const items = page?.items ?? [];

  // Distribution for the headline severity bar
  const dist = useMemo(() => {
    const out: Record<string, number> = {};
    for (const f of items) out[f.severity] = (out[f.severity] ?? 0) + 1;
    return out;
  }, [items]);

  const onPatchStatus = async (finding: Finding, next: string) => {
    try {
      await api.updateFindingStatus(finding.id, next);
      await reload();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <div className="grid">
      <div className="row space">
        <div className="row">
          <ShieldAlert size={16} color="#22d3ee" />
          <strong>Results</strong>
          <span className="muted">workspace-wide findings</span>
        </div>
        <button className="btn small" onClick={() => reload()} disabled={loading} type="button">
          <RefreshCw size={13} className={loading ? 'spin' : ''} /> Refresh
        </button>
      </div>

      <div className="card">
        <div className="row space">
          <div className="row"><Filter size={14} color="#22d3ee" /><strong>Filters</strong></div>
          <span className="muted">{page ? `${page.total} matches` : '—'}</span>
        </div>
        <div className="results-filter-grid">
          <select className="input" value={workspaceId} onChange={(e) => { setWorkspaceId(e.target.value); setOffset(0); }}>
            {workspaces.map((w) => <option key={w.id} value={w.id}>{w.name}</option>)}
          </select>
          <select className="input" value={severity} onChange={(e) => { setSeverity(e.target.value); setOffset(0); }}>
            <option value="">all severities</option>
            {(page?.facets?.severities ?? []).map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <select className="input" value={status} onChange={(e) => { setStatus(e.target.value); setOffset(0); }}>
            <option value="">all statuses</option>
            {(page?.facets?.statuses ?? STATUS_OPTIONS).map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <select className="input" value={tool} onChange={(e) => { setTool(e.target.value); setOffset(0); }}>
            <option value="">all tools</option>
            {(page?.facets?.tools ?? []).map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
          <div className="row" style={{ position: 'relative', flex: 1 }}>
            <Search size={13} className="search-icon" />
            <input className="input search-input"
                    placeholder="search title or evidence…"
                    value={q}
                    onChange={(e) => { setQ(e.target.value); setOffset(0); }} />
          </div>
        </div>
      </div>

      {error && <div className="card"><p className="advice-error">{error}</p></div>}

      <div className="card">
        <div className="row space"><strong>Findings</strong>
          {Object.keys(dist).length > 0 && (
            <div className="row">
              {(['critical', 'high', 'medium', 'low', 'info'] as const).map((sev) => dist[sev] && (
                <span key={sev} className={severityBadgeClass(sev)}>{sev}: {dist[sev]}</span>
              ))}
            </div>
          )}
        </div>
        <table className="table compact results-table">
          <thead><tr>
            <th style={{ width: 18 }}></th>
            <th>Severity</th>
            <th>Title</th>
            <th>Tool</th>
            <th>Status</th>
            <th>Created</th>
          </tr></thead>
          <tbody>
            {items.length === 0 && !loading && (
              <tr><td colSpan={6} className="muted" style={{ padding: 16 }}>
                No findings match these filters.
              </td></tr>
            )}
            {items.map((f) => (
              <ResultsRow
                key={f.id}
                finding={f}
                expanded={selectedId === f.id}
                onToggle={() => setSelectedId(selectedId === f.id ? null : f.id)}
                onStatusChange={(next) => onPatchStatus(f, next)}
              />
            ))}
          </tbody>
        </table>
        {totalPages > 1 && (
          <div className="row space" style={{ marginTop: 10 }}>
            <span className="muted">page {currentPage} / {totalPages} · {page?.total} total</span>
            <div className="row">
              <button className="btn small" type="button" disabled={offset === 0}
                      onClick={() => setOffset(Math.max(0, offset - limit))}>Prev</button>
              <button className="btn small" type="button" disabled={currentPage >= totalPages}
                      onClick={() => setOffset(offset + limit)}>Next</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function ResultsRow({
  finding, expanded, onToggle, onStatusChange,
}: {
  finding: Finding;
  expanded: boolean;
  onToggle: () => void;
  onStatusChange: (next: string) => void;
}) {
  return (
    <>
      <tr className={`results-row ${expanded ? 'selected' : ''}`} onClick={onToggle}>
        <td>{expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}</td>
        <td><span className={severityBadgeClass(finding.severity)}>{finding.severity}</span></td>
        <td><div className="ellipsis-cell" title={finding.title}>{finding.title}</div></td>
        <td className="mono small">{finding.tool_source ?? '—'}</td>
        <td><span className={statusBadgeClass(finding.status)}>{finding.status}</span></td>
        <td className="muted small">{new Date(finding.created_at).toLocaleString()}</td>
      </tr>
      {expanded && (
        <tr className="results-detail-row">
          <td colSpan={6}>
            <div className="grid">
              <div className="row space">
                <div className="row">
                  <span className="muted">status</span>
                  <select className="input" style={{ maxWidth: 200 }}
                          value={finding.status}
                          onClick={(e) => e.stopPropagation()}
                          onChange={(e) => { e.stopPropagation(); onStatusChange(e.target.value); }}>
                    {(['new', 'triaged', 'false_positive', 'fixed', 'closed'] as const).map((s) => (
                      <option key={s} value={s}>{s}</option>
                    ))}
                  </select>
                </div>
                <div className="row muted small">
                  <span>category: <strong>{finding.category}</strong></span>
                  <span>confidence: <strong>{finding.confidence}</strong></span>
                </div>
              </div>
              {finding.evidence && <pre className="finding-evidence">{finding.evidence}</pre>}
              <AdvicePanel
                label="Explain with Claude"
                refKey={finding.id}
                fetchCached={() => api.getFindingExplain(finding.id)}
                invoke={() => api.explainFinding(finding.id)}
              />
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
