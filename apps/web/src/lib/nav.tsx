import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react';

/**
 * Cross-page deeplinks. Pages call `navigate('loot', { runId })` to switch
 * pages and pre-seed filters; pages read `useNavParams()` once per page mount
 * to consume any pending params (then clear them so a re-render doesn't loop).
 */
export type Page =
  | 'dashboard' | 'workspaces' | 'targets' | 'runs' | 'results' | 'network'
  | 'tools' | 'templates' | 'workflow' | 'loot' | 'users' | 'audit' | 'settings';

export type NavParams = {
  runId?: string;
  findingId?: string;
  targetId?: string;
  workspaceId?: string;
  lootKind?: string;
  lootSeverity?: string;
};

type Ctx = {
  page: Page;
  params: NavParams;
  navigate: (page: Page, params?: NavParams) => void;
  consume: () => NavParams;
};

const NavContext = createContext<Ctx | null>(null);

export function NavProvider({ children }: { children: ReactNode }) {
  const [page, setPage] = useState<Page>('dashboard');
  const [params, setParams] = useState<NavParams>({});

  const navigate = useCallback((next: Page, p?: NavParams) => {
    setPage(next);
    setParams(p ?? {});
  }, []);

  // Pages call consume() once on mount to read + clear params. The cleared
  // params prevent stale deeplinks from re-firing on subsequent re-renders.
  const consume = useCallback(() => {
    const taken = params;
    setParams({});
    return taken;
  }, [params]);

  const value = useMemo(() => ({ page, params, navigate, consume }), [page, params, navigate, consume]);
  return <NavContext.Provider value={value}>{children}</NavContext.Provider>;
}

export function useNav(): Ctx {
  const ctx = useContext(NavContext);
  if (!ctx) throw new Error('useNav must be used inside <NavProvider>');
  return ctx;
}
