import { useEffect, useState } from 'react';
import { ArrowRight, Download, ExternalLink, Sparkles, X } from 'lucide-react';
import { api } from './api';
import { useNav } from './nav';
import type { RunBrief } from '../types';

/**
 * Run Brief modal — renders `GET /api/agent/runs/{id}/brief`.
 *
 * The brief is the cheapest way to scan everything about a run in one shot:
 * counts, severity-ranked findings, assets-by-type, artifact fetch URLs, and
 * the loot summary — no LLM in the loop. Use it from any page where the
 * operator wants "what happened in this run" without leaving the screen.
 */
export function RunBriefView({
  runId,
  onClose,
}: {
  runId: string;
  onClose: () => void;
}) {
  const { navigate } = useNav();
  const [brief, setBrief] = useState<RunBrief | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setError(null);
    setBrief(null);
    api.runBrief(runId)
      .then((b) => { if (!cancelled) setBrief(b); })
      .catch((e) => { if (!cancelled) setError(e instanceof Error ? e.message : String(e)); });
    return () => { cancelled = true; };
  }, [runId]);

  return (
    <div className="modal-backdrop" onClick={onClose} role="presentation">
      <div className="modal brief-modal" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true" aria-label="Run brief">
        <div className="modal-header">
          <span className="row">
            <Sparkles size={16} color="#22d3ee" />
            <strong>Run brief</strong>
            <span className="mono small muted">{runId}</span>
          </span>
          <button className="icon-btn" onClick={onClose} type="button" aria-label="Close brief"><X size={14} /></button>
        </div>

        {error && <p className="advice-error">Failed to load brief: {error}</p>}
        {!error && !brief && <p className="muted">Loading…</p>}

        {brief && (
          <div className="brief-body grid">
            <div className="row space">
              <div className="row">
                <span className="badge passive">{brief.run.profile_id}</span>
                <span className={`badge ${brief.run.status === 'completed' ? 'ok' : brief.run.status === 'failed' || brief.run.status === 'cancelled' ? 'bad' : 'passive'}`}>{brief.run.status}</span>
                <span className="badge passive">{brief.run.risk}</span>
                {brief.target && <span className="mono small">{brief.target.value}</span>}
              </div>
              <div className="row">
                <button className="btn small" type="button" onClick={() => { onClose(); navigate('runs', { runId }); }}>
                  <ExternalLink size={12} /> Open in Runs
                </button>
                <button className="btn small" type="button" onClick={() => { onClose(); navigate('loot', { runId, workspaceId: brief.run.workspace_id }); }}>
                  <ExternalLink size={12} /> Open loot
                </button>
              </div>
            </div>

            <div className="brief-counts">
              <BriefStat label="Steps" value={brief.counts.steps} />
              <BriefStat label="Findings" value={brief.counts.findings} />
              <BriefStat label="Assets" value={brief.counts.assets} />
              <BriefStat label="Artifacts" value={brief.counts.artifacts} />
              <BriefStat label="Loot" value={brief.counts.loot} highlight={brief.counts.loot > 0} />
            </div>

            {brief.counts.findings > 0 && (
              <div className="card brief-section">
                <div className="row space"><strong>Findings by severity</strong></div>
                <div className="row" style={{ flexWrap: 'wrap' }}>
                  {(['critical', 'high', 'medium', 'low', 'info'] as const).map((sev) => {
                    const n = brief.findings_by_severity[sev] ?? 0;
                    if (n === 0) return null;
                    return (
                      <span
                        key={sev}
                        className={`badge ${sev === 'critical' || sev === 'high' ? 'bad' : sev === 'medium' ? 'active' : 'passive'}`}
                      >
                        {sev}: {n}
                      </span>
                    );
                  })}
                </div>
                <table className="table compact" style={{ marginTop: 8 }}>
                  <thead><tr><th>Severity</th><th>Title</th><th>Tool</th></tr></thead>
                  <tbody>
                    {brief.findings.slice(0, 12).map((f) => (
                      <tr key={f.id}>
                        <td><span className={`badge ${f.severity === 'critical' || f.severity === 'high' ? 'bad' : f.severity === 'medium' ? 'active' : 'passive'}`}>{f.severity}</span></td>
                        <td title={f.evidence_excerpt}>{f.title}</td>
                        <td className="mono small">{f.tool_source ?? '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {brief.findings.length > 12 && (
                  <p className="muted small">…+{brief.findings.length - 12} more</p>
                )}
              </div>
            )}

            {brief.loot.total > 0 && (
              <div className="card brief-section">
                <div className="row space">
                  <strong>Loot</strong>
                  <button className="link" type="button" onClick={() => { onClose(); navigate('loot', { runId, workspaceId: brief.run.workspace_id }); }}>
                    Open full loot <ArrowRight size={12} />
                  </button>
                </div>
                <div className="row" style={{ flexWrap: 'wrap' }}>
                  {Object.entries(brief.loot.by_kind).map(([k, n]) => (
                    <span key={k} className="badge active">{k}: {n}</span>
                  ))}
                </div>
                <table className="table compact" style={{ marginTop: 8 }}>
                  <thead><tr><th>Severity</th><th>Kind</th><th>Label</th><th>Host</th></tr></thead>
                  <tbody>
                    {brief.loot.items.slice(0, 8).map((it) => (
                      <tr key={it.id}>
                        <td><span className={`badge ${it.severity === 'critical' || it.severity === 'high' ? 'bad' : it.severity === 'medium' ? 'active' : 'passive'}`}>{it.severity}</span></td>
                        <td>{it.kind}</td>
                        <td>{it.label}</td>
                        <td><span className="mono small">{it.host ?? '—'}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {Object.keys(brief.assets_by_type).length > 0 && (
              <div className="card brief-section">
                <strong>Assets by type</strong>
                <div className="brief-assets">
                  {Object.entries(brief.assets_by_type).map(([type, values]) => (
                    <div key={type} className="brief-asset-bucket">
                      <div className="row space"><span className="badge passive">{type}</span><span className="muted small">{values.length}</span></div>
                      <ul className="brief-asset-list">
                        {values.slice(0, 8).map((v) => <li key={v} className="mono small">{v}</li>)}
                        {values.length > 8 && <li className="muted small">…+{values.length - 8}</li>}
                      </ul>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {brief.artifacts.length > 0 && (
              <div className="card brief-section">
                <strong>Artifacts</strong>
                <table className="table compact">
                  <thead><tr><th>Name</th><th>Type</th><th>Size</th><th /></tr></thead>
                  <tbody>
                    {brief.artifacts.map((a) => (
                      <tr key={a.id}>
                        <td className="mono small">{a.name}</td>
                        <td>{a.type}</td>
                        <td className="muted">{(a.size_bytes / 1024).toFixed(1)} KB</td>
                        <td>
                          <a className="link" href={a.content_url} target="_blank" rel="noreferrer" title="Download / open content"><Download size={12} /></a>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function BriefStat({ label, value, highlight }: { label: string; value: number; highlight?: boolean }) {
  return (
    <div className={`brief-stat ${highlight ? 'highlight' : ''}`}>
      <span className="muted small">{label}</span>
      <strong>{value}</strong>
    </div>
  );
}
