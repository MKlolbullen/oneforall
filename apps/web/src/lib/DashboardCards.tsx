import { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, Bell, CheckCircle2, ExternalLink, ShieldAlert, ShieldCheck } from 'lucide-react';
import { api } from './api';
import { useNav } from './nav';
import { useWorkspace } from './WorkspaceContext';
import type { ScopePolicyResponse, Webhook } from '../types';

/* ============================================================================
 * ROE policy status card
 * ========================================================================== */

export function RoePolicyCard() {
  const { navigate } = useNav();
  const [policy, setPolicy] = useState<ScopePolicyResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.scopePolicy()
      .then(setPolicy)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, []);

  const sectionCounts = useMemo(() => {
    if (!policy || !policy.enabled) return null;
    const parsed = policy.parsed ?? {};
    const allowed = (parsed.allowed as Record<string, unknown> | undefined) ?? {};
    const denied = (parsed.denied as Record<string, unknown> | undefined) ?? {};
    const approval = (parsed.approval as Record<string, unknown> | undefined) ?? {};
    return {
      allowedDomains: Array.isArray(allowed.domains) ? allowed.domains.length : 0,
      allowedCidrs: Array.isArray(allowed.cidrs) ? allowed.cidrs.length : 0,
      allowedPorts: Array.isArray(allowed.ports) ? allowed.ports.length : 0,
      deniedDomains: Array.isArray(denied.domains) ? denied.domains.length : 0,
      deniedMethods: Array.isArray(denied.methods) ? denied.methods.length : 0,
      requireForTools: Array.isArray(approval.require_for_tools) ? approval.require_for_tools.length : 0,
    };
  }, [policy]);

  return (
    <div className="card dashboard-roe-card">
      <div className="row space">
        <h3><ShieldAlert size={16} style={{ verticalAlign: 'middle', marginRight: 4 }} /> ROE policy</h3>
        <button className="btn small" type="button" onClick={() => navigate('scope')} title="Open the Scope page">
          <ExternalLink size={12} /> Edit
        </button>
      </div>

      {error && <p className="advice-error small">{error}</p>}

      {!error && (
        policy?.enabled ? (
          <>
            <div className="row" style={{ marginBottom: 6 }}>
              <ShieldCheck size={13} color="#22c55e" />
              <strong>Engine on</strong>
              <span className="muted small">path: {policy.path.split('/').slice(-2).join('/')}</span>
            </div>
            {sectionCounts && (
              <div className="dashboard-roe-grid">
                <CountTile label="allowed.domains" value={sectionCounts.allowedDomains} />
                <CountTile label="allowed.cidrs" value={sectionCounts.allowedCidrs} />
                <CountTile label="allowed.ports" value={sectionCounts.allowedPorts} />
                <CountTile label="denied.domains" value={sectionCounts.deniedDomains} />
                <CountTile label="denied.methods" value={sectionCounts.deniedMethods} />
                <CountTile label="approval.tools" value={sectionCounts.requireForTools} />
              </div>
            )}
            <small className="muted">
              Enforced at every run-creation. Per-tool argv (ports / methods /
              rate-limit) is also evaluated.
            </small>
          </>
        ) : (
          <>
            <div className="row" style={{ marginBottom: 6 }}>
              <ShieldAlert size={13} color="#94a3b8" />
              <strong className="muted">Engine off — no policy file</strong>
            </div>
            <p className="muted small">
              The platform falls back to the legacy target-level scope check
              (target.in_scope + active_allowed + default_out_of_scope).
              Open the Scope page to write a policy and enable defence-in-depth.
            </p>
          </>
        )
      )}
    </div>
  );
}


/* ============================================================================
 * Webhook health card — per-workspace totals + recent failures
 * ========================================================================== */

export function WebhookHealthCard() {
  const { navigate } = useNav();
  const { activeWorkspaceId, activeWorkspace } = useWorkspace();
  const [hooks, setHooks] = useState<Webhook[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.webhooks(activeWorkspaceId ?? undefined)
      .then(setHooks)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, [activeWorkspaceId]);

  const counts = useMemo(() => {
    let active = 0, healthy = 0, failing = 0, never = 0;
    for (const h of hooks) {
      if (!h.is_active) continue;
      active += 1;
      if (h.last_status == null && !h.last_error) {
        never += 1;
      } else if (h.last_status != null && h.last_status < 300) {
        healthy += 1;
      } else {
        failing += 1;
      }
    }
    return { total: hooks.length, active, healthy, failing, never };
  }, [hooks]);

  const failingHooks = useMemo(() =>
    hooks
      .filter((h) => h.is_active && (h.last_status != null && h.last_status >= 300 || h.last_error))
      .slice(0, 3),
    [hooks],
  );

  return (
    <div className="card dashboard-webhook-card">
      <div className="row space">
        <h3><Bell size={16} style={{ verticalAlign: 'middle', marginRight: 4 }} /> Webhook health</h3>
        <button className="btn small" type="button" onClick={() => navigate('webhooks')} title="Open the Webhooks page">
          <ExternalLink size={12} /> Manage
        </button>
      </div>

      <small className="muted" style={{ display: 'block', marginBottom: 6 }}>
        {activeWorkspace ? `Workspace: ${activeWorkspace.name}` : 'All workspaces'}
      </small>

      {error && <p className="advice-error small">{error}</p>}

      {!error && (counts.total === 0 ? (
        <p className="muted small">
          No webhooks configured. Open the Webhooks page to attach a Slack /
          Discord / generic JSON receiver to run lifecycle events.
        </p>
      ) : (
        <>
          <div className="dashboard-webhook-grid">
            <CountTile label="active" value={counts.active} tone="ok" />
            <CountTile label="healthy" value={counts.healthy} tone="ok" />
            <CountTile label="failing" value={counts.failing} tone={counts.failing > 0 ? 'bad' : undefined} />
            <CountTile label="untested" value={counts.never} />
          </div>

          {failingHooks.length > 0 && (
            <div className="dashboard-failing-hooks">
              <strong className="muted small">
                <AlertTriangle size={11} color="#fca5a5" style={{ verticalAlign: 'middle', marginRight: 2 }} />
                Failing
              </strong>
              {failingHooks.map((h) => (
                <div key={h.id} className="dashboard-failing-row">
                  <span className="mono small ellipsis-cell" title={h.url}>{h.name}</span>
                  <span className="badge bad">
                    {h.last_status != null ? `HTTP ${h.last_status}` : 'network'}
                  </span>
                </div>
              ))}
            </div>
          )}

          {failingHooks.length === 0 && counts.active > 0 && (
            <p className="muted small">
              <CheckCircle2 size={11} color="#22c55e" style={{ verticalAlign: 'middle', marginRight: 2 }} />
              All active webhooks healthy.
            </p>
          )}
        </>
      ))}
    </div>
  );
}


/* ============================================================================
 * Shared bits
 * ========================================================================== */

function CountTile({ label, value, tone }: { label: string; value: number; tone?: 'ok' | 'bad' }) {
  return (
    <div className={`dashboard-count-tile ${tone ?? ''}`}>
      <strong>{value}</strong>
      <span className="muted small">{label}</span>
    </div>
  );
}
