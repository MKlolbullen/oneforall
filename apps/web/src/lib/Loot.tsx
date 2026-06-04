import { useCallback, useEffect, useMemo, useState } from 'react';
import { ArrowRight, Coins, Download, RefreshCw, ShieldAlert } from 'lucide-react';
import { AdvicePanel } from './AdvicePanel';
import { api } from './api';
import { CopyButton } from './CopyButton';
import { EmptyState } from './EmptyState';
import { useNav } from './nav';
import { useWorkspace } from './WorkspaceContext';
import { useToast } from './Toast';
import type { Finding, LootItem, LootPage, Run } from '../types';

type ExportFormat = 'csv' | 'json' | 'md';

const SEVERITY_RANK: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5,
};

const KIND_LABEL: Record<string, string> = {
  secret: 'Secret',
  credential: 'Credential',
  takeover: 'Subdomain takeover',
  exposure: 'Exposure',
  vulnerability: 'Vulnerability',
};

function severityBadge(sev: string) {
  if (sev === 'critical') return 'bad';
  if (sev === 'high') return 'bad';
  if (sev === 'medium') return 'active';
  return 'passive';
}

export function Loot() {
  const toast = useToast();
  const { consume, navigate } = useNav();
  // The workspace lives in the global topbar context now. A deeplink with
  // workspaceId (e.g. from a Workspaces card click) sets the global
  // selector — same code path as the operator picking it manually.
  const { workspaces, activeWorkspaceId, setActiveWorkspaceId } = useWorkspace();
  const [runs, setRuns] = useState<Run[]>([]);
  const [runId, setRunId] = useState('');
  const [kind, setKind] = useState('');
  const [severity, setSeverity] = useState('');
  const [host, setHost] = useState('');
  const [page, setPage] = useState<LootPage | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [reindexing, setReindexing] = useState(false);

  // One-time deeplink consume on mount.
  useEffect(() => {
    const params = consume();
    if (params.workspaceId) setActiveWorkspaceId(params.workspaceId);
    if (params.runId) setRunId(params.runId);
    if (params.lootKind) setKind(params.lootKind);
    if (params.lootSeverity) setSeverity(params.lootSeverity);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    api.runs()
      .then(setRuns)
      .catch((e) => setError(String(e)));
  }, []);

  const reload = useCallback(() => {
    setLoading(true);
    setError(null);
    api.loot({
      workspace_id: activeWorkspaceId ?? undefined,
      run_id: runId || undefined,
      kind: kind || undefined,
      severity: severity || undefined,
      host: host || undefined,
      limit: 500,
    })
      .then(setPage)
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, [activeWorkspaceId, runId, kind, severity, host]);

  useEffect(() => { reload(); }, [reload]);

  const reindex = async () => {
    if (!runId) {
      toast.warn('No run selected', 'Pick a run to reindex its loot.');
      return;
    }
    setReindexing(true);
    try {
      const r = await api.reindexRunLoot(runId);
      toast.success('Loot reindexed', `${r.indexed} item${r.indexed === 1 ? '' : 's'} for this run.`);
      reload();
    } catch (e) {
      toast.fromError(e, 'Reindex failed');
    } finally {
      setReindexing(false);
    }
  };

  const exportLink = (format: ExportFormat) =>
    api.lootExportUrl({
      workspace_id: activeWorkspaceId ?? undefined,
      run_id: runId || undefined,
      kind: kind || undefined,
      severity: severity || undefined,
      host: host || undefined,
      format,
    });

  // Workspace-scoped run options so the dropdown doesn't show foreign runs.
  const runOptions = useMemo(
    () => runs.filter((r) => !activeWorkspaceId || r.workspace_id === activeWorkspaceId),
    [runs, activeWorkspaceId],
  );

  const activeWorkspace = workspaces.find((w) => w.id === activeWorkspaceId) ?? null;

  const kindFacets = page?.facets.kinds ?? [];
  const sevFacets = (page?.facets.severities ?? []).slice().sort(
    (a, b) => (SEVERITY_RANK[a] ?? 9) - (SEVERITY_RANK[b] ?? 9),
  );

  const items = page?.items ?? [];
  const summary = useMemo(() => {
    const byKind: Record<string, number> = {};
    const bySeverity: Record<string, number> = {};
    for (const it of items) {
      byKind[it.kind] = (byKind[it.kind] ?? 0) + 1;
      bySeverity[it.severity] = (bySeverity[it.severity] ?? 0) + 1;
    }
    return { byKind, bySeverity };
  }, [items]);

  return (
    <div className="grid">
      <div className="card">
        <div className="row space">
          <h3><Coins size={18} style={{ verticalAlign: 'middle', marginRight: 6 }} /> Loot</h3>
          <span className="muted">
            {activeWorkspace ? `Workspace: ${activeWorkspace.name}` : 'All workspaces'} ·
            Curated high-signal output derived from findings. Secrets, takeovers, critical vulns — not raw scanner noise.
          </span>
        </div>
        <div className="toolbar availability-toolbar">
          <select className="input" value={runId} onChange={(e) => setRunId(e.target.value)}>
            <option value="">All runs</option>
            {runOptions.map((r) => <option key={r.id} value={r.id}>{r.profile_id} · {r.id.slice(0, 14)}</option>)}
          </select>
          <select className="input" value={kind} onChange={(e) => setKind(e.target.value)}>
            <option value="">All kinds</option>
            {kindFacets.map((k) => <option key={k} value={k}>{KIND_LABEL[k] ?? k}</option>)}
          </select>
          <select className="input" value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="">All severities</option>
            {sevFacets.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <input
            className="input"
            placeholder="Host (exact)"
            value={host}
            onChange={(e) => setHost(e.target.value)}
          />
          <button className="btn small" onClick={reload} disabled={loading} title="Refresh loot list">
            <RefreshCw size={14} /> {loading ? '…' : 'Refresh'}
          </button>
          <button
            className="btn small"
            onClick={reindex}
            disabled={reindexing || !runId}
            title={runId ? 'Re-derive loot from current findings of the selected run' : 'Pick a run first'}
          >
            <ShieldAlert size={14} /> {reindexing ? 'Reindexing…' : 'Reindex run'}
          </button>
          <a className="btn small" href={exportLink('csv')} download title="Export filtered loot as CSV"><Download size={14} /> CSV</a>
          <a className="btn small" href={exportLink('json')} download title="Export filtered loot as JSON">JSON</a>
          <a className="btn small" href={exportLink('md')} download title="Export filtered loot as Markdown">MD</a>
        </div>
      </div>

      <div className="grid cols-3">
        <SummaryCard title="Loot items" value={page?.total ?? 0} icon={<Coins size={16} />} />
        <BreakdownCard title="By kind" counts={summary.byKind} labelMap={KIND_LABEL} />
        <BreakdownCard title="By severity" counts={summary.bySeverity} order={Object.keys(SEVERITY_RANK)} />
      </div>

      <div className="card">
        {error && <p className="warning-text">{error}</p>}
        {!error && items.length === 0 && (
          <EmptyState
            icon={<Coins size={28} />}
            title="No loot in scope"
            body={runId
              ? 'No loot indexed for this run yet. Click "Reindex run" to derive loot from its current findings.'
              : 'Pick a workspace or run, or run a scan that produces secrets / takeovers / critical vulns.'}
          />
        )}
        {items.length > 0 && (
          <table className="table">
            <thead>
              <tr>
                <th style={{ width: 90 }}>Severity</th>
                <th style={{ width: 130 }}>Kind</th>
                <th>Label</th>
                <th>Host</th>
                <th>Tool</th>
                <th style={{ width: 110 }}>Run</th>
                <th style={{ width: 40 }} />
              </tr>
            </thead>
            <tbody>
              {items.map((it) => (
                <LootRow
                  key={it.id}
                  item={it}
                  expanded={expandedId === it.id}
                  onToggle={() => setExpandedId(expandedId === it.id ? null : it.id)}
                  onOpenRun={() => navigate('runs', { runId: it.run_id ?? undefined })}
                />
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function SummaryCard({ title, value, icon }: { title: string; value: number; icon: React.ReactNode }) {
  return (
    <div className="card">
      <div className="row space"><span className="muted">{title}</span>{icon}</div>
      <div className="metric">{value}</div>
    </div>
  );
}

function BreakdownCard({
  title, counts, labelMap, order,
}: {
  title: string;
  counts: Record<string, number>;
  labelMap?: Record<string, string>;
  order?: string[];
}) {
  const keys = order
    ? order.filter((k) => counts[k])
    : Object.keys(counts).sort((a, b) => (counts[b] ?? 0) - (counts[a] ?? 0));
  return (
    <div className="card">
      <div className="row space"><span className="muted">{title}</span></div>
      {keys.length === 0
        ? <p className="muted">—</p>
        : keys.map((k) => (
          <div key={k} className="row space" style={{ padding: '4px 0' }}>
            <span>{labelMap?.[k] ?? k}</span>
            <strong>{counts[k] ?? 0}</strong>
          </div>
        ))}
    </div>
  );
}

function LootRow({
  item, expanded, onToggle, onOpenRun,
}: {
  item: LootItem;
  expanded: boolean;
  onToggle: () => void;
  onOpenRun: () => void;
}) {
  // Lazy-load the linked finding so closed rows don't issue requests. The
  // fetch happens once per (item, expanded) transition; subsequent toggles
  // are free because state persists.
  const [finding, setFinding] = useState<Finding | null>(null);
  const [findingError, setFindingError] = useState<string | null>(null);

  useEffect(() => {
    if (!expanded || !item.finding_id) return;
    if (finding && finding.id === item.finding_id) return;
    let cancelled = false;
    api.finding(item.finding_id)
      .then((f) => { if (!cancelled) { setFinding(f); setFindingError(null); } })
      .catch((e) => { if (!cancelled) setFindingError(e instanceof Error ? e.message : String(e)); });
    return () => { cancelled = true; };
  }, [expanded, item.finding_id, finding]);

  return (
    <>
      <tr onClick={onToggle} style={{ cursor: 'pointer' }}>
        <td><span className={`badge ${severityBadge(item.severity)}`}>{item.severity}</span></td>
        <td>{KIND_LABEL[item.kind] ?? item.kind}</td>
        <td><strong>{item.label}</strong></td>
        <td><span className="mono">{item.host ?? '—'}</span></td>
        <td>{item.source_tool ?? '—'}</td>
        <td>
          {item.run_id ? (
            <button
              type="button"
              className="link"
              onClick={(e) => { e.stopPropagation(); onOpenRun(); }}
              title="Open this loot's run"
            >
              {item.run_id.slice(0, 12)}…
            </button>
          ) : '—'}
        </td>
        <td><ArrowRight size={14} style={{ transform: expanded ? 'rotate(90deg)' : undefined, transition: 'transform 120ms' }} /></td>
      </tr>
      {expanded && (
        <tr className="loot-detail-row">
          <td colSpan={7}>
            <div className="grid cols-2">
              <div>
                <div className="row space"><span className="muted">Value preview</span><CopyButton value={item.value_preview} title="Copy preview" /></div>
                <pre className="mono loot-preview">{item.value_preview || '(empty)'}</pre>
                {finding && finding.evidence && finding.evidence !== item.value_preview && (
                  <>
                    <div className="row space" style={{ marginTop: 8 }}>
                      <span className="muted">Full finding evidence</span>
                      <CopyButton value={finding.evidence} title="Copy evidence" />
                    </div>
                    <pre className="mono loot-preview">{finding.evidence}</pre>
                  </>
                )}
              </div>
              <div>
                <KV label="Loot ID" value={<span className="mono">{item.id}</span>} />
                <KV label="Finding" value={item.finding_id ? <span className="mono">{item.finding_id}</span> : '—'} />
                <KV label="Artifact" value={item.artifact_id ? <span className="mono">{item.artifact_id}</span> : '—'} />
                <KV label="Created" value={item.created_at} />
                {finding && (
                  <>
                    <KV label="Status" value={<span className="badge passive">{finding.status}</span>} />
                    <KV label="Category" value={finding.category} />
                    <KV label="Confidence" value={finding.confidence} />
                  </>
                )}
                {findingError && (
                  <p className="advice-error" style={{ margin: 0, fontSize: 12 }}>
                    Could not load finding: {findingError}
                  </p>
                )}
                {Object.keys(item.meta ?? {}).length > 0 && (
                  <details>
                    <summary className="muted">meta</summary>
                    <pre className="mono">{JSON.stringify(item.meta, null, 2)}</pre>
                  </details>
                )}
              </div>
            </div>
            {finding && (
              <div style={{ marginTop: 10 }}>
                <AdvicePanel
                  label="Explain this finding with Claude"
                  refKey={finding.id}
                  fetchCached={() => api.getFindingExplain(finding.id)}
                  invoke={() => api.explainFinding(finding.id)}
                />
              </div>
            )}
          </td>
        </tr>
      )}
    </>
  );
}

function KV({ label, value }: { label: string; value: React.ReactNode }) {
  return <div className="kv"><span className="muted">{label}</span><strong>{value}</strong></div>;
}
