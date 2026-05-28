import { useEffect, useState } from 'react';
import { Keyboard, X } from 'lucide-react';

// Page IDs we navigate to via `g <key>`. Kept loose (string) so App.tsx can
// pass any superset; unknown keys are no-ops.
type Nav = (page: string) => void;

const NAV_KEYS: Record<string, string> = {
  d: 'dashboard',
  k: 'workspaces',
  t: 'targets',
  e: 'templates',
  r: 'runs',
  o: 'results',
  l: 'loot',
  n: 'network',
  c: 'tools',
  w: 'workflow',
  a: 'audit',
  s: 'settings',
};

const SHORTCUTS = [
  { keys: ['/'],     label: 'Focus search' },
  { keys: ['?'],     label: 'Show this cheatsheet' },
  { keys: ['Esc'],   label: 'Close dialog / unfocus' },
  { keys: ['g d'],   label: 'Go to Dashboard' },
  { keys: ['g k'],   label: 'Go to Workspaces' },
  { keys: ['g t'],   label: 'Go to Targets' },
  { keys: ['g e'],   label: 'Go to Templates' },
  { keys: ['g r'],   label: 'Go to Runs' },
  { keys: ['g o'],   label: 'Go to Results' },
  { keys: ['g l'],   label: 'Go to Loot' },
  { keys: ['g n'],   label: 'Go to Network Graph' },
  { keys: ['g c'],   label: 'Go to Tool Catalog' },
  { keys: ['g w'],   label: 'Go to Workflow Builder' },
  { keys: ['g a'],   label: 'Go to Audit Log' },
  { keys: ['g s'],   label: 'Go to Settings' },
];

function isTypingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName;
  return tag === 'INPUT' || tag === 'TEXTAREA' || target.isContentEditable;
}

export function useShortcuts(navigate: Nav) {
  const [showCheat, setShowCheat] = useState(false);
  const [pendingG, setPendingG] = useState(false);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      // Inside an input we treat only Esc as global; everything else is theirs.
      if (isTypingTarget(e.target)) {
        if (e.key === 'Escape' && e.target instanceof HTMLElement) {
          e.target.blur();
        }
        return;
      }
      if (e.metaKey || e.ctrlKey || e.altKey) return;

      if (e.key === '?') {
        setShowCheat((v) => !v);
        e.preventDefault();
        return;
      }
      if (e.key === 'Escape') {
        setShowCheat(false);
        setPendingG(false);
        return;
      }
      if (e.key === '/') {
        const search = document.querySelector<HTMLInputElement>('[data-shortcut-target="search"]');
        if (search) { search.focus(); search.select(); e.preventDefault(); }
        return;
      }
      if (e.key === 'g' && !pendingG) {
        setPendingG(true);
        // 1.2s window to hit the second key
        window.setTimeout(() => setPendingG(false), 1200);
        return;
      }
      if (pendingG) {
        const target = NAV_KEYS[e.key];
        if (target) {
          navigate(target);
          e.preventDefault();
        }
        setPendingG(false);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [navigate, pendingG]);

  return { showCheat, setShowCheat, pendingG };
}

export function ShortcutsCheatsheet({ open, onClose }:
  { open: boolean; onClose: () => void }) {
  if (!open) return null;
  return (
    <div className="modal-backdrop" onClick={onClose} role="presentation">
      <div className="modal" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true">
        <div className="modal-header">
          <span className="row"><Keyboard size={18} /><strong>Keyboard shortcuts</strong></span>
          <button className="icon-btn" onClick={onClose} aria-label="Close" type="button"><X size={14} /></button>
        </div>
        <table className="table compact shortcut-table">
          <tbody>
            {SHORTCUTS.map((s) => (
              <tr key={s.label}>
                <td style={{ width: '40%' }}>
                  {s.keys.map((k, i) => (
                    <span key={i}>
                      {k.split(' ').map((part, j) => (
                        <kbd key={j} className="kbd">{part}</kbd>
                      )).reduce((acc, el, j) => j === 0 ? [el] : [...acc, ' ', el], [] as React.ReactNode[])}
                      {i < s.keys.length - 1 && ' / '}
                    </span>
                  ))}
                </td>
                <td>{s.label}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="muted" style={{ marginTop: 10, fontSize: 12 }}>
          Tip: shortcuts ignore key presses while you're typing in a field.
        </p>
      </div>
    </div>
  );
}

export function PendingGHint({ visible }: { visible: boolean }) {
  if (!visible) return null;
  return <div className="kbd-hint"><kbd className="kbd">g</kbd> &hellip; waiting for second key</div>;
}
