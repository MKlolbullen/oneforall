import { useEffect, useState } from 'react';
import { AlertTriangle, CheckCircle2, Loader2, ShieldAlert, ShieldCheck, ShieldX } from 'lucide-react';
import { api } from './api';
import type { ScopeDecision, ScopeEvaluateRequest, ScopeEvaluateResponse } from '../types';

/**
 * Live ROE preflight badge.
 *
 * Wraps `/api/scope/evaluate` so any launch UI can mount a badge that
 * shows the engine's verdict before the operator clicks Launch. The
 * parent component reads the `decision` via the `onDecision` callback
 * and uses it to decide whether to:
 *   - allow the Launch button (allow)
 *   - prompt for manual_approval before retrying (require_approval)
 *   - disable Launch entirely with the reason (deny)
 *   - show an amber warning but keep Launch enabled (rate_limit)
 *   - hide the badge — the engine isn't configured (no-engine)
 *
 * Debounced 200ms so editing the action context (target, tool, etc.)
 * doesn't hammer the backend.
 */

// A union with the pending-loading state. The optional fields are listed
// so callers can read `state.reason` without TypeScript narrowing each
// time — they'll be `undefined` while the request is in flight.
export type DecisionState = ScopeEvaluateResponse | { decision: 'pending'; reason?: undefined; matched_rule?: undefined } | null;

export function isLaunchBlocked(state: DecisionState): boolean {
  if (!state || state.decision === 'pending') return false;
  return state.decision === 'deny';
}

export function needsApproval(state: DecisionState): boolean {
  if (!state || state.decision === 'pending') return false;
  return state.decision === 'require_approval';
}

const DECISION_META: Record<ScopeDecision, { cls: string; icon: React.ReactNode; label: string }> = {
  allow: { cls: 'badge ok', icon: <ShieldCheck size={11} />, label: 'scope clear' },
  deny: { cls: 'badge bad', icon: <ShieldX size={11} />, label: 'scope deny' },
  require_approval: { cls: 'badge active', icon: <AlertTriangle size={11} />, label: 'needs approval' },
  rate_limit: { cls: 'badge active', icon: <AlertTriangle size={11} />, label: 'rate-limited' },
  'no-engine': { cls: 'badge passive', icon: <ShieldAlert size={11} />, label: 'no policy' },
};

export function ScopePreflight({
  action,
  onDecision,
  hidden,
}: {
  // Request payload; pass `null` to skip the call entirely (e.g. when the
  // operator hasn't picked a target yet).
  action: ScopeEvaluateRequest | null;
  onDecision?: (state: DecisionState) => void;
  // Optional override — caller can render its own badge and just consume
  // the decision via onDecision.
  hidden?: boolean;
}) {
  const [state, setState] = useState<DecisionState>(null);

  useEffect(() => {
    if (!action || !action.target) {
      setState(null);
      onDecision?.(null);
      return;
    }
    setState({ decision: 'pending' });
    let cancelled = false;
    const timer = window.setTimeout(() => {
      api.scopeEvaluate(action)
        .then((response) => {
          if (cancelled) return;
          setState(response);
          onDecision?.(response);
        })
        .catch((error) => {
          if (cancelled) return;
          // Don't block the operator on a preflight failure; the run
          // creation endpoint will still enforce policy authoritatively.
          // Surface the failure as no-engine so the UI stays out of the way.
          const fallback: ScopeEvaluateResponse = {
            decision: 'no-engine',
            reason: error instanceof Error ? error.message : String(error),
          };
          setState(fallback);
          onDecision?.(fallback);
        });
    }, 200);
    return () => { cancelled = true; window.clearTimeout(timer); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [JSON.stringify(action)]);

  if (hidden || !state || state.decision === 'no-engine') return null;
  if (state.decision === 'pending') {
    return (
      <span className="badge passive" title="Evaluating scope policy…">
        <Loader2 size={11} className="spin" /> preflight
      </span>
    );
  }
  const meta = DECISION_META[state.decision as ScopeDecision] ?? DECISION_META.allow;
  const reason = state.decision !== 'allow' && state.reason ? state.reason : null;
  return (
    <span className={meta.cls} title={reason ?? `Decision: ${state.decision}`}>
      {meta.icon} {meta.label}
      {reason && <small className="muted" style={{ marginLeft: 4 }}>· {reason.slice(0, 60)}{reason.length > 60 ? '…' : ''}</small>}
    </span>
  );
}


/** Re-exported convenience for callers that want to render their own UI
 *  instead of the badge component. Returns the latest decision. */
export function useScopePreflight(action: ScopeEvaluateRequest | null): {
  state: DecisionState;
  blocked: boolean;
  needsApproval: boolean;
} {
  const [state, setState] = useState<DecisionState>(null);
  useEffect(() => {
    if (!action || !action.target) { setState(null); return; }
    setState({ decision: 'pending' });
    let cancelled = false;
    const timer = window.setTimeout(() => {
      api.scopeEvaluate(action)
        .then((response) => { if (!cancelled) setState(response); })
        .catch(() => { if (!cancelled) setState({ decision: 'no-engine' }); });
    }, 200);
    return () => { cancelled = true; window.clearTimeout(timer); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [JSON.stringify(action)]);
  return {
    state,
    blocked: isLaunchBlocked(state),
    needsApproval: needsApproval(state),
  };
}

// CSS spinner for the pending state — small enough to inline here so the
// component is self-contained. styles.css carries the rest of the badge
// classes (badge.ok / .bad / .active / .passive) the parent already uses.
const SPIN_STYLE = `
@keyframes rf-spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
.spin { animation: rf-spin 0.9s linear infinite; }
`;
if (typeof document !== 'undefined' && !document.getElementById('rf-spin-style')) {
  const el = document.createElement('style');
  el.id = 'rf-spin-style';
  el.textContent = SPIN_STYLE;
  document.head.appendChild(el);
}
