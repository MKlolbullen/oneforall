import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { CheckCircle2, Info, X, XCircle, AlertTriangle } from 'lucide-react';

export type ToastKind = 'info' | 'success' | 'error' | 'warning';

type Toast = {
  id: number;
  kind: ToastKind;
  title: string;
  body?: string;
  // ms; 0 = sticky
  duration: number;
};

type ToastInput = Omit<Toast, 'id' | 'duration'> & { duration?: number };

type ToastApi = {
  push: (t: ToastInput) => number;
  dismiss: (id: number) => void;
  // sugar — use these instead of alert()
  info: (title: string, body?: string) => void;
  success: (title: string, body?: string) => void;
  warn: (title: string, body?: string) => void;
  error: (title: string, body?: string) => void;
  fromError: (e: unknown, fallback?: string) => void;
};

const ToastContext = createContext<ToastApi | null>(null);

const DEFAULT_DURATION: Record<ToastKind, number> = {
  info: 4000,
  success: 4000,
  warning: 6000,
  error: 8000,   // errors stick around longer so the operator actually reads them
};

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const counter = useRef(0);
  const timers = useRef<Map<number, number>>(new Map());

  const dismiss = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
    const handle = timers.current.get(id);
    if (handle) {
      window.clearTimeout(handle);
      timers.current.delete(id);
    }
  }, []);

  const push = useCallback((input: ToastInput) => {
    const id = ++counter.current;
    const duration = input.duration ?? DEFAULT_DURATION[input.kind];
    const toast: Toast = { id, ...input, duration };
    setToasts((prev) => [...prev, toast]);
    if (duration > 0) {
      const handle = window.setTimeout(() => dismiss(id), duration);
      timers.current.set(id, handle);
    }
    return id;
  }, [dismiss]);

  const api = useMemo<ToastApi>(() => ({
    push,
    dismiss,
    info:    (title, body) => { push({ kind: 'info', title, body }); },
    success: (title, body) => { push({ kind: 'success', title, body }); },
    warn:    (title, body) => { push({ kind: 'warning', title, body }); },
    error:   (title, body) => { push({ kind: 'error', title, body }); },
    fromError: (e, fallback = 'Something went wrong') => {
      const msg = e instanceof Error ? e.message : typeof e === 'string' ? e : fallback;
      push({ kind: 'error', title: fallback, body: msg });
    },
  }), [push, dismiss]);

  // pause auto-dismiss while the cursor is over the stack so an operator can
  // actually read a long error
  const pauseAll = () => {
    timers.current.forEach((handle) => window.clearTimeout(handle));
    timers.current.clear();
  };
  const resumeAll = () => {
    setToasts((prev) => {
      prev.forEach((t) => {
        if (t.duration > 0 && !timers.current.has(t.id)) {
          timers.current.set(t.id, window.setTimeout(() => dismiss(t.id), t.duration));
        }
      });
      return prev;
    });
  };

  useEffect(() => () => {
    timers.current.forEach((h) => window.clearTimeout(h));
    timers.current.clear();
  }, []);

  return (
    <ToastContext.Provider value={api}>
      {children}
      <div
        className="toast-stack"
        role="region"
        aria-label="Notifications"
        onMouseEnter={pauseAll}
        onMouseLeave={resumeAll}
      >
        {toasts.map((t) => <ToastCard key={t.id} toast={t} onDismiss={() => dismiss(t.id)} />)}
      </div>
    </ToastContext.Provider>
  );
}

function ToastCard({ toast, onDismiss }: { toast: Toast; onDismiss: () => void }) {
  const Icon = toast.kind === 'success' ? CheckCircle2
              : toast.kind === 'error' ? XCircle
              : toast.kind === 'warning' ? AlertTriangle
              : Info;
  return (
    <div className={`toast toast-${toast.kind}`} role="status">
      <Icon size={18} />
      <div className="toast-body">
        <strong>{toast.title}</strong>
        {toast.body && <span className="toast-detail">{toast.body}</span>}
      </div>
      <button className="toast-dismiss" onClick={onDismiss} aria-label="Dismiss" type="button">
        <X size={14} />
      </button>
    </div>
  );
}

export function useToast(): ToastApi {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be used inside <ToastProvider>');
  return ctx;
}
