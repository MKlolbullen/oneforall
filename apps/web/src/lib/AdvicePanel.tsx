import { useEffect, useState } from 'react';
import { Bot, Loader2, RefreshCw } from 'lucide-react';
import type { Advice } from '../types';

type Props = {
  /** Static label rendered in the header. */
  label: string;
  /** Returns the cached advice (or null if none yet). */
  fetchCached: () => Promise<Advice | null>;
  /** Hits the model. Returns the new advice. */
  invoke: () => Promise<Advice>;
  /** Forces a re-fetch when this changes (e.g. when the run/finding ID changes). */
  refKey: string;
};

/**
 * Reusable Claude-advisor panel. Loads cached advice via fetchCached on mount;
 * a single button kicks off a fresh call via invoke. The component intentionally
 * has no opinions about WHAT it's advising on — every mode (run triage, finding
 * explain, profile suggest) feeds it the same shape.
 */
export function AdvicePanel({ label, fetchCached, invoke, refKey }: Props) {
  const [advice, setAdvice] = useState<Advice | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchCached()
      .then((a) => { if (!cancelled) setAdvice(a); })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      });
    return () => { cancelled = true; };
  }, [refKey, fetchCached]);

  const run = async () => {
    setLoading(true); setError(null);
    try {
      const a = await invoke();
      setAdvice(a);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="advice-panel">
      <div className="row space">
        <div className="row">
          <Bot size={14} color="#22d3ee" />
          <strong>{label}</strong>
          {advice && <span className="badge passive">{advice.model}</span>}
        </div>
        <button className="btn small" onClick={run} disabled={loading} type="button">
          {loading ? <Loader2 size={13} className="spin" /> : <RefreshCw size={13} />}
          {advice ? 'Re-run' : 'Ask Claude'}
        </button>
      </div>
      {error && <p className="advice-error">{error}</p>}
      {!advice && !loading && !error && (
        <p className="muted">Click <em>Ask Claude</em> for an analysis.</p>
      )}
      {advice && (
        <>
          <div className="advice-summary">{advice.summary}</div>
          <div className="row muted advice-meta">
            <span>tokens in: {advice.prompt_tokens}</span>
            <span>· out: {advice.completion_tokens}</span>
            {advice.cached_tokens > 0 && <span>· cached: {advice.cached_tokens}</span>}
          </div>
        </>
      )}
    </div>
  );
}
