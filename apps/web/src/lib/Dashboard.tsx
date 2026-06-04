import { useEffect, useState } from 'react';
import { Activity, AlertTriangle, Boxes, Crosshair, FileText, History, RefreshCw, ShieldAlert, Sparkles, TerminalSquare, Wrench } from 'lucide-react';
import { api } from './api';
import { RunBriefView } from './RunBriefView';
import { RoePolicyCard, WebhookHealthCard } from './DashboardCards';
import type { DashboardDetailed, DashboardFindingBrief, DashboardRunBrief } from '../types';

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const;

function statusBadgeClass(status: string): string {
  if (status === 'completed') return 'badge ok';
  if (status === 'failed' || status === 'cancelled') return 'badge bad';
  if (status === 'running') return 'badge active';
  return 'badge passive';
}

function severityBadgeClass(sev: string): string {
  if (sev === 'critical' || sev === 'high') return 'badge bad';
  if (sev === 'medium') return 'badge active';
  if (sev === 'low') return 'badge passive';
  return 'badge';
}

function relativeTime(iso: string | null | undefined): string {
  if (!iso) return '';
  const ms = Date.now() - new Date(iso).getTime();
  if (ms < 60_000) return `${Math.max(1, Math.floor(ms / 1000))}s ago`;
  if (ms < 3_600_000) return `${Math.floor(ms / 60_000)}m ago`;
  if (ms < 86_400_000) return `${Math.floor(ms / 3_600_000)}h ago`;
  return `${Math.floor(ms / 86_400_000)}d ago`;
}

export function Dashboard() {
  const [data, setData] = useState<DashboardDetailed | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Set to a run id when the operator opens a brief from a recent-run row;
  // unset clears the modal.
  const [briefRunId, setBriefRunId] = useState<string | null>(null);

  const reload = async () => {
    setLoading(true); setError(null);
    try { setData(await api.dashboardDetailed()); }
    catch (e: unknown) { setError(e instanceof Error ? e.message : String(e)); }
    finally { setLoading(false); }
  };

  // Initial load + 10-second refresh so active runs / counts move on their own.
  useEffect(() => {
    reload();
    const t = window.setInterval(reload, 10_000);
    return () => window.clearInterval(t);
  }, []);

  if (error) return <div className="card"><p className="advice-error">Failed to load dashboard: {error}</p></div>;
  if (!data) return <div className="card"><p className="muted">Loading…</p></div>;

  const { kpis, runs_by_status, findings_by_severity, active_runs, recent_runs,
          recent_findings, top_targets, top_tools, recent_audit } = data;

  const findingsTotal = SEVERITY_ORDER.reduce((acc, s) => acc + (findings_by_severity[s] ?? 0), 0);

  return (
    <div className="grid">
      {/* Header strip with reload */}
      <div className="row space">
        <div className="row">
          <Activity size={16} color="#22d3ee" />
          <strong>Operations overview</strong>
          <span className="muted">live · refreshes every 10s</span>
        </div>
        <button className="btn small" type="button" onClick={() => reload()} disabled={loading}>
          <RefreshCw size={13} className={loading ? 'spin' : ''} /> Refresh
        </button>
      </div>

      {/* KPI strip — 6 cards */}
      <div className="kpi-grid">
        <KpiCard label="Workspaces" value={kpis.workspaces} icon={<Boxes />} />
        <KpiCard label="Targets" value={kpis.targets} icon={<Crosshair />} />
        <KpiCard label="Runs" value={kpis.runs} icon={<TerminalSquare />} />
        <KpiCard label="Assets" value={kpis.assets} icon={<Boxes />} />
        <KpiCard label="Findings" value={kpis.findings} icon={<ShieldAlert />} />
        <KpiCard label="Open" value={kpis.open_findings} icon={<AlertTriangle />} highlight />
      </div>

      {/* Platform health strip: ROE policy + webhook health */}
      <div className="grid cols-2 dashboard-platform-row">
        <RoePolicyCard />
        <WebhookHealthCard />
      </div>

      {/* Two-column row: severity breakdown + run status */}
      <div className="grid cols-2">
        <div className="card">
          <div className="row space"><h3>Findings by severity</h3><span className="muted">{findingsTotal} total</span></div>
          {findingsTotal === 0 && <p className="muted">No findings yet.</p>}
          {findingsTotal > 0 && (
            <>
              <SeverityBar buckets={findings_by_severity} total={findingsTotal} />
              <div className="severity-rows">
                {SEVERITY_ORDER.map((sev) => {
                  const count = findings_by_severity[sev] ?? 0;
                  return (
                    <div key={sev} className="row space severity-row">
                      <span className={severityBadgeClass(sev)}>{sev}</span>
                      <span className="mono"><strong>{count}</strong>{findingsTotal > 0 && (
                        <span className="muted"> · {Math.round((count / findingsTotal) * 100)}%</span>
                      )}</span>
                    </div>
                  );
                })}
              </div>
            </>
          )}
        </div>

        <div className="card">
          <div className="row space"><h3>Run status</h3><span className="muted">all-time</span></div>
          <div className="severity-rows">
            {Object.entries(runs_by_status).map(([s, n]) => (
              <div key={s} className="row space severity-row">
                <span className={statusBadgeClass(s)}>{s}</span>
                <strong className="mono">{n}</strong>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Active runs banner */}
      {active_runs.length > 0 && (
        <div className="card active-runs">
          <div className="row space">
            <h3><span className="dot-blink" /> Active runs</h3>
            <span className="muted">{active_runs.length} in flight</span>
          </div>
          <table className="table compact">
            <thead><tr><th>ID</th><th>Profile</th><th>Status</th><th>Started</th></tr></thead>
            <tbody>{active_runs.map((r) => <RunRow key={r.id} r={r} />)}</tbody>
          </table>
        </div>
      )}

      {/* Three-column row: recent runs / findings / audit */}
      <div className="grid cols-3 dashboard-feeds">
        <div className="card">
          <div className="row space"><h3>Recent runs</h3><History size={14} /></div>
          {recent_runs.length === 0 && <p className="muted">No runs yet.</p>}
          <table className="table compact"><tbody>
            {recent_runs.map((r) => (
              <tr key={r.id}>
                <td><span className="mono small">{r.profile_id}</span></td>
                <td><span className={statusBadgeClass(r.status)}>{r.status}</span></td>
                <td className="muted">{relativeTime(r.created_at)}</td>
                <td>
                  <button
                    type="button"
                    className="btn small"
                    onClick={() => setBriefRunId(r.id)}
                    title="Open the structured run brief"
                  >
                    <Sparkles size={11} /> Brief
                  </button>
                </td>
              </tr>
            ))}
          </tbody></table>
        </div>

        <div className="card">
          <div className="row space"><h3>Recent findings</h3><ShieldAlert size={14} /></div>
          {recent_findings.length === 0 && <p className="muted">No findings yet.</p>}
          <ul className="feed">
            {recent_findings.map((f) => <FindingFeedRow key={f.id} f={f} />)}
          </ul>
        </div>

        <div className="card">
          <div className="row space"><h3>Audit feed</h3><FileText size={14} /></div>
          {recent_audit.length === 0 && <p className="muted">No audit events yet.</p>}
          <ul className="feed">
            {recent_audit.map((e) => (
              <li key={e.sequence} className="feed-row">
                <span className="mono small">#{e.sequence}</span>
                <span className="badge passive">{e.action}</span>
                {e.actor_role && <span className="muted small">by {e.actor_role}</span>}
                <span className="muted small">{relativeTime(e.created_at)}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      {/* Two-column row: top targets / top tools */}
      <div className="grid cols-2">
        <div className="card">
          <div className="row space"><h3>Top targets</h3><span className="muted">last 30 days</span></div>
          {top_targets.length === 0 && <p className="muted">No runs in the last 30 days.</p>}
          {top_targets.length > 0 && (
            <table className="table compact"><thead><tr><th>Target</th><th>Runs</th></tr></thead>
              <tbody>{top_targets.map((t) => (
                <tr key={t.id}>
                  <td className="mono">{t.value}</td>
                  <td><strong className="mono">{t.run_count}</strong></td>
                </tr>
              ))}</tbody>
            </table>
          )}
        </div>

        <div className="card">
          <div className="row space"><h3>Most-used tools</h3><Wrench size={14} /></div>
          {top_tools.length === 0 && <p className="muted">No tool steps recorded yet.</p>}
          {top_tools.length > 0 && (
            <div className="grid">
              {top_tools.map((t) => {
                const max = Math.max(...top_tools.map((tt) => tt.run_count));
                const pct = (t.run_count / max) * 100;
                return (
                  <div key={t.tool_id} className="row space tool-bar-row">
                    <span className="mono small">{t.tool_id}</span>
                    <div className="tool-bar-track">
                      <div className="tool-bar-fill" style={{ width: `${pct}%` }} />
                    </div>
                    <strong className="mono small">{t.run_count}</strong>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
      {briefRunId && <RunBriefView runId={briefRunId} onClose={() => setBriefRunId(null)} />}
    </div>
  );
}

function KpiCard({ label, value, icon, highlight }:
  { label: string; value: number; icon: React.ReactNode; highlight?: boolean }) {
  return (
    <div className={`card kpi-card ${highlight ? 'highlight' : ''}`}>
      <div className="row space">
        <span className="muted">{label}</span>
        <span style={{ color: highlight ? '#fca5a5' : '#22d3ee' }}>{icon}</span>
      </div>
      <div className="metric">{value.toLocaleString()}</div>
    </div>
  );
}

function SeverityBar({ buckets, total }: { buckets: Record<string, number>; total: number }) {
  const segs = SEVERITY_ORDER.map((s) => ({ sev: s, count: buckets[s] ?? 0 })).filter((s) => s.count > 0);
  return (
    <div className="severity-bar">
      {segs.map(({ sev, count }) => (
        <div key={sev} className={`severity-seg ${sev}`} style={{ flex: count }}
             title={`${sev}: ${count} (${Math.round((count / total) * 100)}%)`} />
      ))}
    </div>
  );
}

function RunRow({ r }: { r: DashboardRunBrief }) {
  return (
    <tr>
      <td className="mono small">{r.id.slice(0, 14)}…</td>
      <td className="mono small">{r.profile_id}</td>
      <td><span className={statusBadgeClass(r.status)}>{r.status}</span></td>
      <td className="muted">{relativeTime(r.created_at)}</td>
    </tr>
  );
}

function FindingFeedRow({ f }: { f: DashboardFindingBrief }) {
  return (
    <li className="feed-row">
      <span className={severityBadgeClass(f.severity)}>{f.severity}</span>
      <span className="ellipsis-cell" title={f.title}>{f.title}</span>
      <span className="muted small">{relativeTime(f.created_at)}</span>
    </li>
  );
}
