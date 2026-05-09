import { useEffect, useMemo, useState } from 'react';
import { ArrowLeft, Boxes, Globe, ShieldAlert, TerminalSquare, Wrench } from 'lucide-react';
import { api } from './api';
import { AdvicePanel } from './AdvicePanel';
import type { Asset, Finding, Run, Target, TargetSummary, TargetTech } from '../types';

type Props = {
  target: Target;
  onClose: () => void;
};

type Tab = 'overview' | 'assets' | 'findings' | 'runs' | 'tech';

const SEVERITY_RANK: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
  unknown: 5,
};

function severityBadge(sev: string): string {
  switch (sev) {
    case 'critical':
    case 'high':
      return 'badge bad';
    case 'medium':
      return 'badge active';
    case 'low':
      return 'badge passive';
    default:
      return 'badge';
  }
}

export function TargetDetail({ target, onClose }: Props) {
  const [tab, setTab] = useState<Tab>('overview');
  const [summary, setSummary] = useState<TargetSummary | null>(null);
  const [runs, setRuns] = useState<Run[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [tech, setTech] = useState<TargetTech | null>(null);
  const [assetType, setAssetType] = useState<string>('');
  const [findingFilter, setFindingFilter] = useState<string>('all');

  useEffect(() => {
    let cancelled = false;
    Promise.all([
      api.targetSummary(target.id),
      api.targetRuns(target.id),
      api.targetAssets(target.id),
      api.targetFindings(target.id),
      api.targetTech(target.id),
    ])
      .then(([s, r, a, f, t]) => {
        if (cancelled) return;
        setSummary(s);
        setRuns(r);
        setAssets(a);
        setFindings(f);
        setTech(t);
      })
      .catch(console.error);
    return () => {
      cancelled = true;
    };
  }, [target.id]);

  const filteredAssets = useMemo(
    () => (assetType ? assets.filter((a) => a.type === assetType) : assets),
    [assets, assetType],
  );
  const filteredFindings = useMemo(
    () => (findingFilter === 'all' ? findings : findings.filter((f) => f.severity === findingFilter)),
    [findings, findingFilter],
  );
  const assetTypes = useMemo(() => {
    const types = new Set(assets.map((a) => a.type));
    return [''].concat(Array.from(types).sort());
  }, [assets]);
  const severityKeys = useMemo(
    () => ['all', ...Object.keys(SEVERITY_RANK).filter((s) => findings.some((f) => f.severity === s))],
    [findings],
  );

  return (
    <div className="grid">
      <div className="row space">
        <button className="btn small" onClick={onClose} type="button">
          <ArrowLeft size={14} /> Back to targets
        </button>
        <div className="row">
          <Globe size={16} color="#22d3ee" />
          <strong className="mono">{target.value}</strong>
          <span className="badge passive">{target.type}</span>
          {target.in_scope ? <span className="badge ok">in scope</span> : <span className="badge bad">out</span>}
          {target.active_allowed ? <span className="badge active">active OK</span> : <span className="badge">passive only</span>}
        </div>
      </div>

      <div className="card">
        <div className="row" role="tablist">
          {(['overview', 'assets', 'findings', 'runs', 'tech'] as Tab[]).map((t) => (
            <button
              key={t}
              className={`btn small ${tab === t ? '' : 'disabledish'}`}
              onClick={() => setTab(t)}
              type="button"
              role="tab"
              aria-selected={tab === t}
            >
              {t}
            </button>
          ))}
        </div>
      </div>

      {tab === 'overview' && summary && (
        <Overview summary={summary} />
      )}
      {tab === 'overview' && !summary && <p className="muted">Loading…</p>}

      {tab === 'assets' && (
        <div className="card">
          <div className="row space">
            <h3>Assets ({filteredAssets.length})</h3>
            <select className="input" style={{ maxWidth: 220 }} value={assetType} onChange={(e) => setAssetType(e.target.value)}>
              {assetTypes.map((t) => (
                <option key={t || 'all'} value={t}>
                  {t || 'all types'}
                </option>
              ))}
            </select>
          </div>
          <table className="table compact">
            <thead><tr><th>Type</th><th>Value</th><th>Source</th><th>First seen</th><th>Last seen</th></tr></thead>
            <tbody>
              {filteredAssets.map((a) => (
                <tr key={a.id}>
                  <td><span className="badge passive">{a.type}</span></td>
                  <td className="mono">{a.value}</td>
                  <td>{a.source}</td>
                  <td className="muted">{new Date(a.first_seen).toLocaleString()}</td>
                  <td className="muted">{new Date(a.last_seen).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === 'findings' && (
        <div className="card">
          <div className="row space">
            <h3>Findings ({filteredFindings.length})</h3>
            <select className="input" style={{ maxWidth: 220 }} value={findingFilter} onChange={(e) => setFindingFilter(e.target.value)}>
              {severityKeys.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>
          {filteredFindings.length === 0 && <p className="muted">No findings yet for this filter.</p>}
          <div className="grid">
            {filteredFindings.map((f) => (
              <details key={f.id} className="finding-row">
                <summary className="row space">
                  <span className="row">
                    <span className={severityBadge(f.severity)}>{f.severity}</span>
                    <strong>{f.title}</strong>
                  </span>
                  <span className="muted">{f.tool_source ?? f.category}</span>
                </summary>
                <div className="finding-body">
                  <div className="kv"><span className="muted">Status</span><strong>{f.status}</strong></div>
                  <div className="kv"><span className="muted">Confidence</span><strong>{f.confidence}</strong></div>
                  <div className="kv"><span className="muted">Created</span><strong>{new Date(f.created_at).toLocaleString()}</strong></div>
                  {f.evidence && <pre className="finding-evidence">{f.evidence}</pre>}
                  <AdvicePanel
                    label="Explain with Claude"
                    refKey={f.id}
                    fetchCached={() => api.getFindingExplain(f.id)}
                    invoke={() => api.explainFinding(f.id)}
                  />
                </div>
              </details>
            ))}
          </div>
        </div>
      )}

      {tab === 'runs' && (
        <div className="card">
          <h3>Runs ({runs.length})</h3>
          <table className="table compact">
            <thead><tr><th>ID</th><th>Profile</th><th>Status</th><th>Risk</th><th>Started</th></tr></thead>
            <tbody>
              {runs.map((r) => (
                <tr key={r.id}>
                  <td className="mono">{r.id}</td>
                  <td>{r.profile_id}</td>
                  <td><span className={`badge ${r.status === 'completed' ? 'ok' : r.status === 'failed' || r.status === 'cancelled' ? 'bad' : 'passive'}`}>{r.status}</span></td>
                  <td>{r.risk}</td>
                  <td className="muted">{new Date(r.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === 'tech' && tech && (
        <div className="grid cols-2">
          <div className="card">
            <h3>Tech stack</h3>
            {Object.keys(tech.tech).length === 0 && <p className="muted">No tech fingerprints yet.</p>}
            <div className="tag-list">
              {Object.entries(tech.tech).map(([name, count]) => (
                <span key={name} className="tag enabled" title={`Seen on ${count} URL(s)`}>
                  {name} <small className="muted">×{count}</small>
                </span>
              ))}
            </div>
            <h3 style={{ marginTop: 16 }}>Servers</h3>
            <div className="tag-list">
              {Object.entries(tech.servers).map(([name, count]) => (
                <span key={name} className="tag" title={`${count} URL(s)`}>
                  {name} <small className="muted">×{count}</small>
                </span>
              ))}
            </div>
          </div>
          <div className="card" style={{ overflow: 'hidden' }}>
            <h3>Per-URL fingerprints</h3>
            <table className="table compact">
              <thead><tr><th>URL</th><th>Status</th><th>Title</th><th>Tech</th></tr></thead>
              <tbody>
                {tech.by_url.map((row) => (
                  <tr key={row.url}>
                    <td className="mono">{row.url}</td>
                    <td>{row.status_code ?? '—'}</td>
                    <td className="muted">{row.title ?? ''}</td>
                    <td>
                      <div className="tag-list">
                        {row.tech.map((t) => <span key={t} className="tag">{t}</span>)}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

function Overview({ summary }: { summary: TargetSummary }) {
  return (
    <div className="grid">
      <div className="grid cols-3">
        <Card label="Runs" value={summary.runs_total} icon={<TerminalSquare />} />
        <Card label="Assets" value={summary.assets_total} icon={<Boxes />} />
        <Card label="Findings" value={summary.findings_total} icon={<ShieldAlert />} />
      </div>
      <div className="grid cols-2">
        <div className="card">
          <h3>Findings by severity</h3>
          <div className="grid">
            {Object.entries(summary.findings_by_severity).sort(([a], [b]) => SEVERITY_RANK[a] - SEVERITY_RANK[b]).map(([sev, count]) => (
              <div key={sev} className="kv">
                <span className={severityBadge(sev)}>{sev}</span>
                <strong>{count}</strong>
              </div>
            ))}
            {Object.keys(summary.findings_by_severity).length === 0 && <p className="muted">No findings yet.</p>}
          </div>
        </div>
        <div className="card">
          <h3>Assets by type</h3>
          <div className="grid">
            {Object.entries(summary.assets_by_type).map(([type, count]) => (
              <div key={type} className="kv">
                <span className="badge passive">{type}</span>
                <strong>{count}</strong>
              </div>
            ))}
            {Object.keys(summary.assets_by_type).length === 0 && <p className="muted">No assets discovered yet.</p>}
          </div>
        </div>
        <div className="card">
          <h3>Run status</h3>
          <div className="grid">
            {Object.entries(summary.runs_by_status).map(([status, count]) => (
              <div key={status} className="kv">
                <span className={`badge ${status === 'completed' ? 'ok' : status === 'failed' || status === 'cancelled' ? 'bad' : 'passive'}`}>{status}</span>
                <strong>{count}</strong>
              </div>
            ))}
            {Object.keys(summary.runs_by_status).length === 0 && <p className="muted">No runs yet.</p>}
          </div>
          <div className="kv"><span className="muted">Last run</span><strong>{summary.last_run_at ? new Date(summary.last_run_at).toLocaleString() : '—'}</strong></div>
        </div>
        <div className="card">
          <h3>Authorization</h3>
          <div className="kv"><span className="muted">In scope</span><strong>{summary.target.in_scope ? 'yes' : 'no'}</strong></div>
          <div className="kv"><span className="muted">Passive allowed</span><strong>{summary.target.passive_allowed ? 'yes' : 'no'}</strong></div>
          <div className="kv"><span className="muted">Active allowed</span><strong>{summary.target.active_allowed ? 'yes' : 'no'}</strong></div>
          <div className="kv"><span className="muted">Notes</span><strong>{summary.target.notes ?? '—'}</strong></div>
        </div>
      </div>
    </div>
  );
}

function Card({ label, value, icon }: { label: string; value: number; icon: React.ReactNode }) {
  return (
    <div className="card">
      <div className="row space"><span className="muted">{label}</span><span style={{ color: '#22d3ee' }}>{icon}</span></div>
      <div className="metric">{value}</div>
    </div>
  );
}
