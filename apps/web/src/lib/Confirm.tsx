import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react';
import { AlertTriangle, X } from 'lucide-react';

type ConfirmOptions = {
  title: string;
  body?: string;
  confirmLabel?: string;
  cancelLabel?: string;
  destructive?: boolean;
};

type ConfirmApi = (opts: ConfirmOptions) => Promise<boolean>;

const ConfirmContext = createContext<ConfirmApi | null>(null);

type Pending = ConfirmOptions & { resolve: (value: boolean) => void };

export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [pending, setPending] = useState<Pending | null>(null);

  const confirm = useCallback<ConfirmApi>((opts) => {
    return new Promise<boolean>((resolve) => setPending({ ...opts, resolve }));
  }, []);

  const finish = (ok: boolean) => {
    if (!pending) return;
    pending.resolve(ok);
    setPending(null);
  };

  // ESC cancels, Enter confirms — standard modal etiquette
  useEffect(() => {
    if (!pending) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { e.preventDefault(); finish(false); }
      if (e.key === 'Enter')  { e.preventDefault(); finish(true);  }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pending]);

  return (
    <ConfirmContext.Provider value={confirm}>
      {children}
      {pending && (
        <div className="modal-backdrop" onClick={() => finish(false)} role="presentation">
          <div className="modal" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true" aria-labelledby="confirm-title">
            <div className="modal-header">
              <span className="row">
                {pending.destructive && <AlertTriangle size={18} color="#fca5a5" />}
                <strong id="confirm-title">{pending.title}</strong>
              </span>
              <button className="icon-btn" onClick={() => finish(false)} aria-label="Close" type="button"><X size={14} /></button>
            </div>
            {pending.body && <p className="muted modal-body">{pending.body}</p>}
            <div className="modal-actions">
              <button className="btn small" onClick={() => finish(false)} type="button">
                {pending.cancelLabel ?? 'Cancel'}
              </button>
              <button
                className={`btn small ${pending.destructive ? 'danger' : ''}`}
                onClick={() => finish(true)}
                type="button"
                autoFocus
              >
                {pending.confirmLabel ?? 'Confirm'}
              </button>
            </div>
          </div>
        </div>
      )}
    </ConfirmContext.Provider>
  );
}

export function useConfirm(): ConfirmApi {
  const ctx = useContext(ConfirmContext);
  if (!ctx) throw new Error('useConfirm must be used inside <ConfirmProvider>');
  return ctx;
}
