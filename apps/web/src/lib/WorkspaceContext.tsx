import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { api } from './api';
import type { Workspace } from '../types';

/**
 * Cross-page "currently focused workspace" state.
 *
 * Most list pages (Loot, Webhooks, Results, Targets, Runs) used to mount
 * their own workspace dropdown + local state, so an operator who picked
 * "Acme" on Loot would land on Webhooks and see "All workspaces" again.
 * This context lifts the choice up: pages read `activeWorkspaceId` from
 * the hook and never need to mount their own dropdown — the topbar owns
 * the selection.
 *
 * `activeWorkspaceId === null` means "all workspaces" — pages must treat
 * that as "do not filter" rather than as a missing value.
 *
 * Persisted to localStorage so a browser refresh keeps the operator on
 * the same workspace.
 */
const STORAGE_KEY = 'reconforge:active-workspace:v1';

type Ctx = {
  workspaces: Workspace[];
  activeWorkspaceId: string | null;
  setActiveWorkspaceId: (id: string | null) => void;
  activeWorkspace: Workspace | null;
  loading: boolean;
  refresh: () => Promise<void>;
};

const WorkspaceContext = createContext<Ctx | null>(null);

export function WorkspaceProvider({ children }: { children: ReactNode }) {
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [activeWorkspaceId, setActiveWorkspaceIdRaw] = useState<string | null>(() => {
    try {
      return localStorage.getItem(STORAGE_KEY);
    } catch {
      return null;
    }
  });
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const list = await api.workspaces();
      setWorkspaces(list);
      // If the stored workspace was deleted out from under us, fall back
      // to "all" rather than show a stale id the backend will 404 on.
      setActiveWorkspaceIdRaw((prev) => {
        if (prev && !list.some((w) => w.id === prev)) return null;
        return prev;
      });
    } catch {
      // Auth not set up / network failure — leave the cached id alone so
      // a transient 401 doesn't reset the operator's choice.
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { refresh().catch(console.error); }, [refresh]);

  const setActiveWorkspaceId = useCallback((id: string | null) => {
    setActiveWorkspaceIdRaw(id);
    try {
      if (id) localStorage.setItem(STORAGE_KEY, id);
      else localStorage.removeItem(STORAGE_KEY);
    } catch {
      /* quota — non-fatal */
    }
  }, []);

  const activeWorkspace = useMemo(
    () => workspaces.find((w) => w.id === activeWorkspaceId) ?? null,
    [workspaces, activeWorkspaceId],
  );

  const value = useMemo<Ctx>(() => ({
    workspaces, activeWorkspaceId, setActiveWorkspaceId,
    activeWorkspace, loading, refresh,
  }), [workspaces, activeWorkspaceId, setActiveWorkspaceId, activeWorkspace, loading, refresh]);

  return <WorkspaceContext.Provider value={value}>{children}</WorkspaceContext.Provider>;
}

export function useWorkspace(): Ctx {
  const ctx = useContext(WorkspaceContext);
  if (!ctx) throw new Error('useWorkspace must be used inside <WorkspaceProvider>');
  return ctx;
}
