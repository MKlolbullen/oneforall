import { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, CheckCircle2, FileText, Lock, RefreshCw, Save, ShieldAlert, ShieldCheck, ShieldX, Trash2 } from 'lucide-react';
import { api } from './api';
import { useConfirm } from './Confirm';
import { useNav } from './nav';
import { useScopePreflight } from './ScopePreflight';
import { useToast } from './Toast';
import type { ScopePolicyResponse, WhoAmI } from '../types';

/**
 * ROE policy editor + live preflight tester.
 *
 * Tier-1 design: YAML textarea editor backed by GET/PUT /api/scope/policy.
 * Operators paste / type the policy, hit Save, and the engine cache busts
 * so the next run-creation sees the new rules. A live preflight widget
 * on the right shows what the current draft decides for a sample target —
 * try-before-you-save.
 *
 * A structured form editor (lists with add/remove rows per section) is
 * the natural follow-up; the route already accepts the same YAML either
 * way, so swapping in a richer editor is a pure frontend change.
 */

const SAMPLE_POLICY = `# ReconForge ROE policy — tier-1 sample.
# Drop sections you don't need; the engine treats absence as "any".
# After saving, runs queued via /api/runs, /api/runs/adhoc,
# /api/runs/{id}/rerun, and /api/workflows/{id}/launch are evaluated
# against these rules + per-step argv (ports / methods / rate-limit).

allowed:
  domains:
    - example.com
    - "*.example.com"
  # Optional CIDR allowlist; targets outside both lists are denied.
  # cidrs:
  #   - "10.10.0.0/16"
  # Optional explicit port allowlist; a tool's argv (-p 22, --top-ports 1000)
  # is parsed and checked against this.
  # ports: [80, 443, 8080]

denied:
  # domains:
  #   - admin.example.com
  # cidrs:
  #   - "10.10.50.0/24"
  # methods: ["DELETE", "TRACE"]
  # paths: ["/logout", "/delete"]

# limits:
#   max_rps: 5
#   active_scan_window:
#     start: "22:00"
#     end: "05:00"
#     timezone: "Europe/Stockholm"

approval:
  require_for_risk:
    - high_active
  # Tools that always require fresh consent regardless of profile risk.
  # require_for_tools:
  #   - sqlmap_crawl
  #   - commix
`;

export function Scope() {
  const toast = useToast();
  const confirm = useConfirm();
  const { navigate } = useNav();
  const [me, setMe] = useState<WhoAmI | null>(null);
  const [policy, setPolicy] = useState<ScopePolicyResponse | null>(null);
  const [draft, setDraft] = useState<string>('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Preflight tester state
  const [testTarget, setTestTarget] = useState<string>('api.example.com');
  const [testRisk, setTestRisk] = useState<string>('low_active');
  const [testTool, setTestTool] = useState<string>('');
  const [testApproval, setTestApproval] = useState<boolean>(false);
  const preflight = useScopePreflight(testTarget ? {
    target: testTarget, risk: testRisk,
    tool_id: testTool || undefined,
    manual_approval: testApproval,
  } : null);

  const isAdmin = me?.role === 'admin';
  const dirty = policy ? draft !== policy.yaml : draft.length > 0;

  const reload = async () => {
    try {
      const [whoami, current] = await Promise.all([
        api.me().catch(() => null),
        api.scopePolicy(),
      ]);
      setMe(whoami);
      setPolicy(current);
      setDraft(current.yaml);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  useEffect(() => { reload().catch(console.error); }, []);

  const save = async () => {
    if (!isAdmin) {
      toast.warn('Admin required', 'Only admins can write the ROE policy.');
      return;
    }
    setSaving(true);
    try {
      const next = await api.scopePolicyWrite(draft);
      setPolicy(next);
      setDraft(next.yaml);
      toast.success('Policy saved', next.enabled ? 'Engine reloaded.' : 'Engine disabled (empty body).');
    } catch (err) {
      toast.fromError(err, 'Save failed');
    } finally {
      setSaving(false);
    }
  };

  const wipe = async () => {
    if (!isAdmin) return;
    const ok = await confirm({
      title: 'Disable the ROE engine?',
      body: 'This deletes the policy file. The platform falls back to the legacy target-level scope check until a new policy is written.',
      confirmLabel: 'Delete policy',
      cancelLabel: 'Keep',
      destructive: true,
    });
    if (!ok) return;
    setSaving(true);
    try {
      const next = await api.scopePolicyWrite('');
      setPolicy(next);
      setDraft('');
      toast.info('Policy deleted', 'Engine disabled.');
    } catch (err) {
      toast.fromError(err, 'Delete failed');
    } finally {
      setSaving(false);
    }
  };

  const insertSample = () => {
    setDraft(SAMPLE_POLICY);
  };

  // Render-time YAML "linting" — surface obvious mistakes inline before
  // the backend's 422. Cheap heuristics, NOT a real YAML parser.
  const localHints = useMemo<string[]>(() => {
    const hints: string[] = [];
    if (!draft.trim()) return hints;
    if (!/^(allowed|denied|limits|approval):/m.test(draft)) {
      hints.push('No top-level allowed / denied / limits / approval section found.');
    }
    if (/\t/.test(draft)) {
      hints.push('Tabs detected — YAML requires spaces for indentation.');
    }
    return hints;
  }, [draft]);

  return (
    <div className="grid">
      <div className="card">
        <div className="row space">
          <h3><ShieldCheck size={18} style={{ verticalAlign: 'middle', marginRight: 6 }} /> ROE / scope policy</h3>
          <span className="muted">
            Edit the policy the engine evaluates on every run-creation. After
            saving, the cache busts and the next run sees the new rules.
          </span>
        </div>
        <div className="toolbar availability-toolbar">
          <span className={policy?.enabled ? 'badge ok' : 'badge passive'}>
            {policy?.enabled ? <><CheckCircle2 size={11} /> engine on</> : <><ShieldAlert size={11} /> engine off</>}
          </span>
          {policy?.path && (
            <span className="muted small mono" title={policy.path}>
              path: {policy.path.length > 70 ? `…${policy.path.slice(-70)}` : policy.path}
            </span>
          )}
          <span style={{ marginLeft: 'auto' }} />
          <button className="btn small" type="button" onClick={() => reload()} title="Reload from disk">
            <RefreshCw size={13} /> Reload
          </button>
          {policy && policy.yaml.length === 0 && (
            <button className="btn small" type="button" onClick={insertSample} title="Insert a starter policy">
              <FileText size={13} /> Insert sample
            </button>
          )}
          <button
            className="btn small"
            type="button"
            onClick={wipe}
            disabled={!isAdmin || !policy?.enabled || saving}
            title={!isAdmin ? 'Admin only' : 'Delete the policy file (engine off)'}
          >
            <Trash2 size={13} /> Delete
          </button>
          <button
            className="btn"
            type="button"
            onClick={save}
            disabled={!isAdmin || saving || !dirty}
            title={!isAdmin ? 'Admin only' : !dirty ? 'No changes' : 'Save & reload engine'}
          >
            <Save size={13} /> {saving ? 'Saving…' : 'Save policy'}
          </button>
        </div>
        {!isAdmin && (
          <div className="row" style={{ marginTop: 6 }}>
            <Lock size={12} color="#94a3b8" />
            <span className="muted small">
              Read-only view. Operators can read the policy but only admins can write it. {me ? `Signed in as ${me.role}.` : ''}
            </span>
          </div>
        )}
      </div>

      {error && (
        <div className="card">
          <p className="advice-error"><AlertTriangle size={14} /> {error}</p>
        </div>
      )}

      <div className="grid cols-2">
        {/* Left: editor */}
        <div className="card">
          <div className="row space">
            <strong>Policy YAML</strong>
            {localHints.length > 0 && (
              <span className="muted small">{localHints.length} hint{localHints.length === 1 ? '' : 's'}</span>
            )}
          </div>
          <textarea
            className="input scope-policy-editor"
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            placeholder={SAMPLE_POLICY}
            spellCheck={false}
            rows={26}
            disabled={!isAdmin}
          />
          {localHints.length > 0 && (
            <ul className="scope-hints">
              {localHints.map((h, i) => (
                <li key={i}><AlertTriangle size={11} /> {h}</li>
              ))}
            </ul>
          )}
          <small className="muted">
            Sections allowed / denied / limits / approval. See <code>roe.yaml.example</code> in
            packages/platform-config/ for the full reference.
          </small>
        </div>

        {/* Right: live tester */}
        <div className="card">
          <div className="row space">
            <strong>Live preflight</strong>
            <span className="muted small">Evaluates against the SAVED policy</span>
          </div>
          <div className="grid" style={{ gap: 8 }}>
            <label className="muted small">Target
              <input
                className="input"
                value={testTarget}
                onChange={(e) => setTestTarget(e.target.value)}
                placeholder="api.example.com"
              />
            </label>
            <label className="muted small">Risk
              <select className="input" value={testRisk} onChange={(e) => setTestRisk(e.target.value)}>
                <option value="passive">passive</option>
                <option value="low_active">low_active</option>
                <option value="medium_active">medium_active</option>
                <option value="high_active">high_active</option>
                <option value="destructive">destructive</option>
              </select>
            </label>
            <label className="muted small">Tool ID (optional)
              <input
                className="input"
                value={testTool}
                onChange={(e) => setTestTool(e.target.value)}
                placeholder="subfinder"
              />
            </label>
            <label className="row muted small" style={{ gap: 4 }}>
              <input type="checkbox" checked={testApproval} onChange={(e) => setTestApproval(e.target.checked)} />
              manual_approval=true
            </label>
            <div className="scope-tester-result">
              <strong className="muted small">Decision</strong>
              <PreflightResult state={preflight.state} />
            </div>
          </div>
        </div>
      </div>

      {/* Quick "did it land" check — last X audit rows mentioning scope.policy.* */}
      <div className="card">
        <div className="row space">
          <strong>Recent policy changes</strong>
          <button className="btn small" type="button" onClick={() => navigate('audit')}>
            Open audit log
          </button>
        </div>
        <small className="muted">
          Every PUT (save / delete) writes one of <code>scope.policy.updated</code>
          or <code>scope.policy.deleted</code> into the audit chain. Use the
          Audit Log page to filter by action.
        </small>
      </div>
    </div>
  );
}


function PreflightResult({ state }: { state: ReturnType<typeof useScopePreflight>['state'] }) {
  if (!state) {
    return <p className="muted small">Enter a target above.</p>;
  }
  if (state.decision === 'pending') {
    return <p className="muted small">Evaluating…</p>;
  }
  if (state.decision === 'no-engine') {
    return (
      <p className="muted small">
        <ShieldAlert size={11} /> Engine is OFF — no policy file is loaded. Save a policy on the left to activate.
      </p>
    );
  }
  const icon = state.decision === 'allow' ? <ShieldCheck size={13} color="#22c55e" />
             : state.decision === 'deny' ? <ShieldX size={13} color="#fca5a5" />
             : <AlertTriangle size={13} color="#fbbf24" />;
  const cls = state.decision === 'allow' ? 'ok'
            : state.decision === 'deny' ? 'bad' : 'active';
  return (
    <div className="grid" style={{ gap: 4 }}>
      <div className="row">
        {icon}
        <strong>{state.decision}</strong>
        <span className={`badge ${cls}`}>{state.decision}</span>
      </div>
      {state.reason && <small className="muted">reason: {state.reason}</small>}
      {state.matched_rule && (
        <small className="muted">rule: <code>{state.matched_rule}</code></small>
      )}
      {state.normalized_target && (
        <small className="muted">normalized: <span className="mono">{state.normalized_target}</span></small>
      )}
      {state.trace && state.trace.length > 0 && (
        <details style={{ marginTop: 4 }}>
          <summary className="muted small">trace ({state.trace.length})</summary>
          <ul className="scope-trace">
            {state.trace.map((line, i) => <li key={i} className="mono small">{line}</li>)}
          </ul>
        </details>
      )}
    </div>
  );
}
