import { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, CheckCircle2, ClipboardList, FileText, Lock, Plus, RefreshCw, Save, ShieldAlert, ShieldCheck, ShieldX, Sparkles, Trash2, X } from 'lucide-react';
import { api } from './api';
import { useConfirm } from './Confirm';
import { useNav } from './nav';
import { useScopePreflight } from './ScopePreflight';
import { useToast } from './Toast';
import type { ScopePolicyResponse, ScopePolicyStructured, WhoAmI } from '../types';

/**
 * ROE policy editor + live preflight tester.
 *
 * Two view modes share one underlying engine:
 *   - Form: structured editor (4 sections, chip-list inputs).
 *   - YAML: raw textarea editor.
 *
 * The server-side `_serialise_policy` is the single source of truth for
 * Form→YAML conversion (via POST /api/scope/policy/render), so the client
 * never has to know how to format YAML. Switching from YAML back to Form
 * loses comments and field ordering — that's the cost of the round-trip
 * and we surface it via a warning when the operator toggles.
 */

const SAMPLE_POLICY = `# ReconForge ROE policy — tier-1 sample.
# Drop sections you don't need; the engine treats absence as "any".

allowed:
  domains:
    - example.com
    - "*.example.com"

approval:
  require_for_risk:
    - high_active
`;

const RISK_LEVELS = ['passive', 'low_active', 'medium_active', 'high_active', 'destructive'] as const;
const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'TRACE', 'OPTIONS', 'CONNECT', 'HEAD'] as const;


export function Scope() {
  const toast = useToast();
  const confirm = useConfirm();
  const { navigate } = useNav();
  const [me, setMe] = useState<WhoAmI | null>(null);
  const [policy, setPolicy] = useState<ScopePolicyResponse | null>(null);
  const [yamlDraft, setYamlDraft] = useState<string>('');
  const [structuredDraft, setStructuredDraft] = useState<ScopePolicyStructured>({});
  const [mode, setMode] = useState<'form' | 'yaml'>('form');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Preflight tester
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

  const reload = async () => {
    try {
      const [whoami, current] = await Promise.all([
        api.me().catch(() => null),
        api.scopePolicy(),
      ]);
      setMe(whoami);
      setPolicy(current);
      setYamlDraft(current.yaml);
      setStructuredDraft(structuredFromParsed(current.parsed));
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  useEffect(() => { reload().catch(console.error); }, []);

  // When the operator switches from Form to YAML, render the structured
  // draft to YAML via the backend so what they see in the textarea
  // matches what the structured PUT would write.
  const switchToYaml = async () => {
    try {
      const { yaml: rendered } = await api.scopePolicyRender(structuredDraft);
      setYamlDraft(rendered);
      setMode('yaml');
    } catch (e) {
      toast.fromError(e, 'Could not render YAML');
    }
  };

  // Switching YAML→Form drops anything the form can't model (comments,
  // custom keys, fields outside the known schema). Surface that risk via
  // confirm before we replace the structured state.
  const switchToForm = async () => {
    const cleanedDraft = yamlDraft.replace(/^\s*#.*$/gm, '').trim();
    const looksDifferent = cleanedDraft.length > 0 && structuredToYamlPreview(structuredDraft).trim() !== cleanedDraft;
    if (looksDifferent) {
      const ok = await confirm({
        title: 'Switch to form view?',
        body: 'The structured form covers the standard fields only. Comments and any unsupported keys in your YAML draft will be lost.',
        confirmLabel: 'Switch anyway',
        cancelLabel: 'Stay in YAML',
        destructive: true,
      });
      if (!ok) return;
    }
    // Parse the YAML via a GET to /api/scope/policy that already returns
    // `parsed`. We don't have a YAML→form server endpoint; instead, we
    // save first (only if YAML is valid) then reload. Simpler approach
    // for tier 1: just re-init structured from the last GET response's
    // parsed shape.
    setStructuredDraft(policy ? structuredFromParsed(policy.parsed) : {});
    setMode('form');
  };

  const saveYaml = async () => {
    if (!isAdmin) {
      toast.warn('Admin required', 'Only admins can write the ROE policy.');
      return;
    }
    setSaving(true);
    try {
      const next = await api.scopePolicyWrite(yamlDraft);
      setPolicy(next);
      setYamlDraft(next.yaml);
      setStructuredDraft(structuredFromParsed(next.parsed));
      toast.success('Policy saved', next.enabled ? 'Engine reloaded.' : 'Engine disabled.');
    } catch (err) {
      toast.fromError(err, 'Save failed');
    } finally {
      setSaving(false);
    }
  };

  const saveStructured = async () => {
    if (!isAdmin) {
      toast.warn('Admin required', 'Only admins can write the ROE policy.');
      return;
    }
    setSaving(true);
    try {
      const next = await api.scopePolicyWriteStructured(structuredDraft);
      setPolicy(next);
      setYamlDraft(next.yaml);
      setStructuredDraft(structuredFromParsed(next.parsed));
      toast.success('Policy saved', next.enabled ? 'Engine reloaded.' : 'Engine disabled.');
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
      setYamlDraft('');
      setStructuredDraft({});
      toast.info('Policy deleted', 'Engine disabled.');
    } catch (err) {
      toast.fromError(err, 'Delete failed');
    } finally {
      setSaving(false);
    }
  };

  const insertSample = () => {
    setYamlDraft(SAMPLE_POLICY);
    setStructuredDraft({
      allowed: { domains: ['example.com', '*.example.com'] },
      approval: { require_for_risk: ['high_active'] },
    });
  };

  const localHints = useMemo<string[]>(() => {
    if (mode !== 'yaml') return [];
    const hints: string[] = [];
    if (!yamlDraft.trim()) return hints;
    if (!/^(allowed|denied|limits|approval):/m.test(yamlDraft)) {
      hints.push('No top-level allowed / denied / limits / approval section found.');
    }
    if (/\t/.test(yamlDraft)) {
      hints.push('Tabs detected — YAML requires spaces for indentation.');
    }
    return hints;
  }, [yamlDraft, mode]);

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
              path: {policy.path.length > 60 ? `…${policy.path.slice(-60)}` : policy.path}
            </span>
          )}
          <div className="scope-mode-toggle" role="group" aria-label="Editor mode">
            <button
              type="button"
              className={`btn small ${mode === 'form' ? '' : 'disabledish'}`}
              onClick={() => mode === 'yaml' ? switchToForm() : null}
              aria-pressed={mode === 'form'}
            >
              <ClipboardList size={12} /> Form
            </button>
            <button
              type="button"
              className={`btn small ${mode === 'yaml' ? '' : 'disabledish'}`}
              onClick={() => mode === 'form' ? switchToYaml() : null}
              aria-pressed={mode === 'yaml'}
            >
              <FileText size={12} /> YAML
            </button>
          </div>
          <span style={{ marginLeft: 'auto' }} />
          <button className="btn small" type="button" onClick={() => reload()} title="Reload from disk">
            <RefreshCw size={13} /> Reload
          </button>
          {(!policy?.enabled || (mode === 'yaml' && yamlDraft.length === 0)) && (
            <button className="btn small" type="button" onClick={insertSample} title="Insert a starter policy">
              <Sparkles size={13} /> Sample
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
            onClick={mode === 'yaml' ? saveYaml : saveStructured}
            disabled={!isAdmin || saving}
            title={!isAdmin ? 'Admin only' : 'Save & reload engine'}
          >
            <Save size={13} /> {saving ? 'Saving…' : 'Save policy'}
          </button>
        </div>
        {!isAdmin && (
          <div className="row" style={{ marginTop: 6 }}>
            <Lock size={12} color="#94a3b8" />
            <span className="muted small">
              Read-only view. Operators can read; only admins can write. {me ? `Signed in as ${me.role}.` : ''}
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
        {/* Left: editor — form or YAML */}
        <div className="grid">
          {mode === 'form' ? (
            <FormEditor draft={structuredDraft} setDraft={setStructuredDraft} disabled={!isAdmin} />
          ) : (
            <div className="card">
              <div className="row space">
                <strong>Policy YAML</strong>
                {localHints.length > 0 && (
                  <span className="muted small">{localHints.length} hint{localHints.length === 1 ? '' : 's'}</span>
                )}
              </div>
              <textarea
                className="input scope-policy-editor"
                value={yamlDraft}
                onChange={(e) => setYamlDraft(e.target.value)}
                placeholder={SAMPLE_POLICY}
                spellCheck={false}
                rows={26}
                disabled={!isAdmin}
              />
              {localHints.length > 0 && (
                <ul className="scope-hints">
                  {localHints.map((h, i) => <li key={i}><AlertTriangle size={11} /> {h}</li>)}
                </ul>
              )}
              <small className="muted">
                Sections allowed / denied / limits / approval. See <code>roe.yaml.example</code> for
                the full reference. Switch to Form view for a guided editor.
              </small>
            </div>
          )}
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
                {RISK_LEVELS.map((r) => <option key={r} value={r}>{r}</option>)}
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

      <div className="card">
        <div className="row space">
          <strong>Recent policy changes</strong>
          <button className="btn small" type="button" onClick={() => navigate('audit')}>
            Open audit log
          </button>
        </div>
        <small className="muted">
          Every save / delete writes one of <code>scope.policy.updated</code>
          or <code>scope.policy.deleted</code> into the audit chain.
        </small>
      </div>
    </div>
  );
}


/* ============================================================================
 * Form editor — structured, chip-list inputs per section
 * ========================================================================== */

function FormEditor({
  draft, setDraft, disabled,
}: {
  draft: ScopePolicyStructured;
  setDraft: (next: ScopePolicyStructured) => void;
  disabled: boolean;
}) {
  // Helpers — copy-shallow-update for nested sections; React state setter
  // closes over the latest draft via the parent.
  const setAllowed = (next: ScopePolicyStructured['allowed']) =>
    setDraft({ ...draft, allowed: next });
  const setDenied = (next: ScopePolicyStructured['denied']) =>
    setDraft({ ...draft, denied: next });
  const setApproval = (next: ScopePolicyStructured['approval']) =>
    setDraft({ ...draft, approval: next });
  const setLimits = (next: ScopePolicyStructured['limits']) =>
    setDraft({ ...draft, limits: next });

  const allowed = draft.allowed ?? {};
  const denied = draft.denied ?? {};
  const approval = draft.approval ?? {};
  const limits = draft.limits ?? null;

  return (
    <div className="grid" style={{ gap: 10 }}>
      <SectionCard title="Allowed" subtitle="Anything not matched here is denied">
        <ChipListInput
          label="Domains"
          values={allowed.domains ?? []}
          onChange={(v) => setAllowed({ ...allowed, domains: v })}
          placeholder="example.com or *.example.com"
          disabled={disabled}
        />
        <ChipListInput
          label="CIDRs"
          values={allowed.cidrs ?? []}
          onChange={(v) => setAllowed({ ...allowed, cidrs: v })}
          placeholder="10.10.0.0/16"
          disabled={disabled}
        />
        <ChipListInput
          label="Ports"
          values={(allowed.ports ?? []).map(String)}
          onChange={(v) => setAllowed({ ...allowed, ports: v.map((p) => Number(p)).filter((n) => Number.isFinite(n) && n >= 0 && n <= 65535) })}
          placeholder="80"
          numeric
          disabled={disabled}
        />
      </SectionCard>

      <SectionCard title="Denied" subtitle="Wins over allowed for the same value">
        <ChipListInput
          label="Domains"
          values={denied.domains ?? []}
          onChange={(v) => setDenied({ ...denied, domains: v })}
          placeholder="admin.example.com"
          disabled={disabled}
        />
        <ChipListInput
          label="CIDRs"
          values={denied.cidrs ?? []}
          onChange={(v) => setDenied({ ...denied, cidrs: v })}
          placeholder="10.10.50.0/24"
          disabled={disabled}
        />
        <ChipListInput
          label="HTTP methods"
          values={denied.methods ?? []}
          onChange={(v) => setDenied({ ...denied, methods: v.map((m) => m.toUpperCase()) })}
          placeholder="DELETE"
          presets={[...HTTP_METHODS]}
          disabled={disabled}
        />
        <ChipListInput
          label="URL paths"
          values={denied.paths ?? []}
          onChange={(v) => setDenied({ ...denied, paths: v })}
          placeholder="/logout"
          disabled={disabled}
        />
      </SectionCard>

      <SectionCard title="Limits" subtitle="Rate ceiling + optional active-scan window">
        <label className="muted small">Max RPS (per step)
          <input
            className="input"
            type="number"
            min={0}
            step={0.5}
            value={limits?.max_rps ?? ''}
            disabled={disabled}
            onChange={(e) => {
              const next = e.target.value === '' ? null : Number(e.target.value);
              setLimits({ ...(limits ?? {}), max_rps: next });
            }}
            placeholder="e.g. 5"
          />
        </label>
        <div className="grid cols-3" style={{ gap: 6 }}>
          <label className="muted small">Window start
            <input
              className="input"
              type="time"
              value={limits?.active_scan_window?.start ?? ''}
              disabled={disabled}
              onChange={(e) => setLimits({
                ...(limits ?? {}),
                active_scan_window: {
                  start: e.target.value,
                  end: limits?.active_scan_window?.end ?? '00:00',
                  timezone: limits?.active_scan_window?.timezone ?? 'UTC',
                },
              })}
            />
          </label>
          <label className="muted small">Window end
            <input
              className="input"
              type="time"
              value={limits?.active_scan_window?.end ?? ''}
              disabled={disabled}
              onChange={(e) => setLimits({
                ...(limits ?? {}),
                active_scan_window: {
                  start: limits?.active_scan_window?.start ?? '00:00',
                  end: e.target.value,
                  timezone: limits?.active_scan_window?.timezone ?? 'UTC',
                },
              })}
            />
          </label>
          <label className="muted small">Timezone
            <input
              className="input"
              type="text"
              placeholder="UTC"
              value={limits?.active_scan_window?.timezone ?? ''}
              disabled={disabled}
              onChange={(e) => setLimits({
                ...(limits ?? {}),
                active_scan_window: {
                  start: limits?.active_scan_window?.start ?? '00:00',
                  end: limits?.active_scan_window?.end ?? '00:00',
                  timezone: e.target.value,
                },
              })}
            />
          </label>
        </div>
        {limits?.active_scan_window && (
          <button
            type="button"
            className="btn small"
            style={{ marginTop: 4 }}
            onClick={() => setLimits({ ...(limits ?? {}), active_scan_window: null })}
            disabled={disabled}
          >
            <X size={11} /> Clear window
          </button>
        )}
      </SectionCard>

      <SectionCard title="Approval" subtitle="Force manual_approval for matching risks / tools">
        <ChipListInput
          label="Required for risk"
          values={approval.require_for_risk ?? []}
          onChange={(v) => setApproval({ ...approval, require_for_risk: v })}
          placeholder="high_active"
          presets={[...RISK_LEVELS]}
          disabled={disabled}
        />
        <ChipListInput
          label="Required for tools"
          values={approval.require_for_tools ?? []}
          onChange={(v) => setApproval({ ...approval, require_for_tools: v })}
          placeholder="sqlmap_crawl"
          disabled={disabled}
        />
      </SectionCard>
    </div>
  );
}


function SectionCard({
  title, subtitle, children,
}: {
  title: string;
  subtitle: string;
  children: React.ReactNode;
}) {
  return (
    <div className="card scope-section-card">
      <div className="row space">
        <strong>{title}</strong>
        <span className="muted small">{subtitle}</span>
      </div>
      <div className="grid" style={{ gap: 8 }}>
        {children}
      </div>
    </div>
  );
}


/** Add / remove items from a list. Optional presets render as quick-add
 *  chips below the input. `numeric` constrains the type-in input to digits
 *  (used for the ports list). */
function ChipListInput({
  label, values, onChange, placeholder, presets, numeric, disabled,
}: {
  label: string;
  values: string[];
  onChange: (next: string[]) => void;
  placeholder?: string;
  presets?: string[];
  numeric?: boolean;
  disabled?: boolean;
}) {
  const [draft, setDraft] = useState<string>('');

  const add = (raw: string) => {
    const clean = raw.trim();
    if (!clean) return;
    if (values.includes(clean)) {
      setDraft('');
      return;
    }
    onChange([...values, clean]);
    setDraft('');
  };

  const remove = (value: string) => {
    onChange(values.filter((v) => v !== value));
  };

  return (
    <div className="scope-chip-input">
      <label className="muted small">{label}</label>
      <div className="row" style={{ gap: 4 }}>
        <input
          className="input"
          type={numeric ? 'number' : 'text'}
          inputMode={numeric ? 'numeric' : undefined}
          placeholder={placeholder}
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') { e.preventDefault(); add(draft); }
            else if (e.key === ',' && !numeric) {
              // Comma also acts as a separator for paste-style entry.
              e.preventDefault();
              add(draft);
            }
          }}
          disabled={disabled}
        />
        <button type="button" className="btn small" onClick={() => add(draft)} disabled={disabled || !draft.trim()}>
          <Plus size={11} />
        </button>
      </div>
      {presets && presets.length > 0 && (
        <div className="scope-chip-presets">
          {presets.map((p) => (
            <button
              key={p}
              type="button"
              className="scope-chip-preset"
              disabled={disabled || values.includes(p)}
              onClick={() => add(p)}
              title={values.includes(p) ? 'Already added' : 'Add preset'}
            >
              + {p}
            </button>
          ))}
        </div>
      )}
      {values.length > 0 && (
        <div className="scope-chip-list">
          {values.map((value) => (
            <span key={value} className="scope-chip">
              {value}
              <button
                type="button"
                className="scope-chip-remove"
                onClick={() => remove(value)}
                aria-label={`Remove ${value}`}
                disabled={disabled}
              >
                <X size={10} />
              </button>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}


/** Convert the engine's parsed dict shape into the form's state shape. The
 *  parsed dict comes straight from yaml.safe_load — fields may be missing
 *  or have unexpected types. Be defensive. */
function structuredFromParsed(parsed: Record<string, unknown>): ScopePolicyStructured {
  const asStrings = (x: unknown): string[] =>
    Array.isArray(x) ? x.filter((v): v is string => typeof v === 'string') : [];
  const asNumbers = (x: unknown): number[] =>
    Array.isArray(x) ? x.filter((v): v is number => typeof v === 'number') : [];

  const allowed = (parsed.allowed as Record<string, unknown> | undefined) ?? {};
  const denied = (parsed.denied as Record<string, unknown> | undefined) ?? {};
  const limitsRaw = (parsed.limits as Record<string, unknown> | undefined) ?? undefined;
  const approval = (parsed.approval as Record<string, unknown> | undefined) ?? {};

  const limits: ScopePolicyStructured['limits'] = limitsRaw ? {
    max_rps: typeof limitsRaw.max_rps === 'number' ? limitsRaw.max_rps : null,
    max_hosts: typeof limitsRaw.max_hosts === 'number' ? limitsRaw.max_hosts : null,
    active_scan_window: (limitsRaw.active_scan_window && typeof limitsRaw.active_scan_window === 'object') ? {
      start: String((limitsRaw.active_scan_window as Record<string, unknown>).start ?? ''),
      end: String((limitsRaw.active_scan_window as Record<string, unknown>).end ?? ''),
      timezone: String((limitsRaw.active_scan_window as Record<string, unknown>).timezone ?? 'UTC'),
    } : null,
  } : null;

  return {
    allowed: {
      domains: asStrings(allowed.domains),
      cidrs: asStrings(allowed.cidrs),
      ports: asNumbers(allowed.ports),
    },
    denied: {
      domains: asStrings(denied.domains),
      cidrs: asStrings(denied.cidrs),
      methods: asStrings(denied.methods),
      paths: asStrings(denied.paths),
    },
    limits,
    approval: {
      require_for_risk: asStrings(approval.require_for_risk),
      require_for_tools: asStrings(approval.require_for_tools),
    },
  };
}


/** Very small synchronous YAML stub used only to detect "did the operator
 *  edit the YAML draft beyond what the structured form would render". This
 *  is the cheap heuristic that decides whether to show the destructive
 *  confirm when switching YAML→Form. NOT used for actual saves — the
 *  server's _serialise_policy is the source of truth for that. */
function structuredToYamlPreview(draft: ScopePolicyStructured): string {
  const lines: string[] = [];
  const allowed = draft.allowed ?? {};
  if (allowed.domains?.length || allowed.cidrs?.length || allowed.ports?.length) {
    lines.push('allowed:');
    if (allowed.domains?.length) { lines.push('  domains:'); allowed.domains.forEach((d) => lines.push(`    - ${d}`)); }
    if (allowed.cidrs?.length) { lines.push('  cidrs:'); allowed.cidrs.forEach((d) => lines.push(`    - ${d}`)); }
    if (allowed.ports?.length) { lines.push('  ports:'); allowed.ports.forEach((p) => lines.push(`    - ${p}`)); }
  }
  return lines.join('\n');
}


function PreflightResult({ state }: { state: ReturnType<typeof useScopePreflight>['state'] }) {
  if (!state) return <p className="muted small">Enter a target above.</p>;
  if (state.decision === 'pending') return <p className="muted small">Evaluating…</p>;
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
