import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';

/**
 * Tracks "what is the operator looking at right now" so the global advisor
 * chat can ground its questions in the current run / target. Pages mount
 * `<AdvisorScopeBinder …>` to declare their scope; the chat reads it via
 * `useAdvisorScope()`.
 */
export type AdvisorScope = {
  workspaceId: string | null;
  runId: string | null;
  runLabel: string | null;
  targetId: string | null;
  targetLabel: string | null;
};

const EMPTY_SCOPE: AdvisorScope = {
  workspaceId: null,
  runId: null,
  runLabel: null,
  targetId: null,
  targetLabel: null,
};

type Ctx = {
  scope: AdvisorScope;
  setScope: (next: Partial<AdvisorScope>) => void;
  clear: () => void;
};

const AdvisorContext = createContext<Ctx | null>(null);

export function AdvisorProvider({ children }: { children: ReactNode }) {
  const [scope, setScopeState] = useState<AdvisorScope>(EMPTY_SCOPE);

  const setScope = useCallback((next: Partial<AdvisorScope>) => {
    setScopeState((prev) => ({ ...prev, ...next }));
  }, []);
  const clear = useCallback(() => setScopeState(EMPTY_SCOPE), []);

  const value = useMemo(() => ({ scope, setScope, clear }), [scope, setScope, clear]);
  return <AdvisorContext.Provider value={value}>{children}</AdvisorContext.Provider>;
}

export function useAdvisorScope(): Ctx {
  const ctx = useContext(AdvisorContext);
  if (!ctx) throw new Error('useAdvisorScope must be used inside <AdvisorProvider>');
  return ctx;
}

/**
 * Mount this inside a run / target view to declare the advisor scope. Unmounts
 * clear the scope back to empty so the chat doesn't stay anchored to a stale
 * run after the user navigates away.
 */
export function AdvisorScopeBinder({
  workspaceId,
  runId,
  runLabel,
  targetId,
  targetLabel,
}: {
  workspaceId: string;
  runId?: string;
  runLabel?: string;
  targetId?: string;
  targetLabel?: string;
}) {
  const { setScope, clear } = useAdvisorScope();
  useEffect(() => {
    setScope({
      workspaceId,
      runId: runId ?? null,
      runLabel: runLabel ?? null,
      targetId: targetId ?? null,
      targetLabel: targetLabel ?? null,
    });
    return clear;
  }, [workspaceId, runId, runLabel, targetId, targetLabel, setScope, clear]);
  return null;
}
