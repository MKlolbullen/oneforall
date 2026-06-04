import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Bell, Coins, Crosshair, FileText, Network, Search, ShieldAlert, TerminalSquare, Wrench, X } from 'lucide-react';
import { api } from './api';
import { useNav, type NavParams, type Page } from './nav';
import type { SearchResults } from '../types';

/**
 * Global search palette. Open with `/` or Cmd/Ctrl+K from anywhere in the
 * app. Results are categorised by entity type; arrow keys move the selection,
 * Enter activates the highlighted row, Esc closes.
 *
 * Each row resolves to a deeplink: Targets / Runs (preselected) / Results
 * page filtered to the finding's workspace / Loot filtered by run / etc.
 * The backend `/api/search` endpoint caps results per category so the
 * palette never has to scroll past a wall of weak matches.
 */
const OPEN_EVENT = 'reconforge:search-open';

type Item = {
  page: Page;
  params?: NavParams;
  icon: React.ReactNode;
  label: string;
  sub?: string;
  badge?: { text: string; cls: string };
  key: string;
};

const SEVERITY_BADGE: Record<string, string> = {
  critical: 'bad', high: 'bad', medium: 'active', low: 'passive', info: 'passive',
};

function isTypingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName;
  return tag === 'INPUT' || tag === 'TEXTAREA' || target.isContentEditable;
}

export function SearchPalette() {
  const { navigate } = useNav();
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState('');
  const [results, setResults] = useState<SearchResults | null>(null);
  const [busy, setBusy] = useState(false);
  const [selectedIdx, setSelectedIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement | null>(null);

  // Open via `/` (when not typing AND no page-local search input is mounted —
  // e.g. Results uses `/` for its own filter box) or Cmd/Ctrl+K (always).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && (e.key === 'k' || e.key === 'K')) {
        e.preventDefault();
        setOpen(true);
        return;
      }
      if (e.key === '/' && !isTypingTarget(e.target) && !open) {
        // Defer to page-local search inputs when present so a `/` on Results
        // keeps focusing the filter row instead of stealing it to the palette.
        const pageLocal = document.querySelector('[data-shortcut-target="search"]');
        if (pageLocal) return;
        e.preventDefault();
        setOpen(true);
      } else if (e.key === 'Escape' && open) {
        e.preventDefault();
        setOpen(false);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open]);

  // External callers (topbar button etc.) can dispatch this event to open the
  // palette without knowing the component's internal state.
  useEffect(() => {
    const onOpen = () => setOpen(true);
    window.addEventListener(OPEN_EVENT, onOpen as EventListener);
    return () => window.removeEventListener(OPEN_EVENT, onOpen as EventListener);
  }, []);

  // Reset on open
  useEffect(() => {
    if (open) {
      setQ('');
      setResults(null);
      setSelectedIdx(0);
      // Wait for the modal to mount before grabbing focus.
      setTimeout(() => inputRef.current?.focus(), 30);
    }
  }, [open]);

  // Debounced search. 200ms feels snappy at typing speed without hammering
  // the backend on each keystroke.
  useEffect(() => {
    if (!open) return;
    const needle = q.trim();
    if (!needle) { setResults(null); setBusy(false); return; }
    setBusy(true);
    const timer = window.setTimeout(() => {
      api.search(needle, { limit: 6 })
        .then((r) => { setResults(r); setSelectedIdx(0); })
        .catch(() => setResults(null))
        .finally(() => setBusy(false));
    }, 200);
    return () => window.clearTimeout(timer);
  }, [q, open]);

  // Build a flat, ordered list of selectable items. The arrow keys move
  // through this list; section headers don't count.
  const items: Item[] = useMemo(() => {
    if (!results) return [];
    const out: Item[] = [];
    for (const t of results.targets) {
      out.push({
        page: 'targets', params: { workspaceId: t.workspace_id },
        icon: <Crosshair size={14} />,
        label: t.value, sub: `target · ${t.type}${t.active_allowed ? '' : ' · passive only'}`,
        key: `target:${t.id}`,
      });
    }
    for (const r of results.runs) {
      out.push({
        page: 'runs', params: { runId: r.id, workspaceId: r.workspace_id },
        icon: <TerminalSquare size={14} />,
        label: `${r.profile_id}`,
        sub: `run · ${r.id.slice(0, 14)}… · ${r.status}`,
        badge: { text: r.status, cls: r.status === 'completed' ? 'ok' : r.status === 'failed' || r.status === 'cancelled' ? 'bad' : 'passive' },
        key: `run:${r.id}`,
      });
    }
    for (const f of results.findings) {
      out.push({
        page: 'results', params: { workspaceId: f.workspace_id },
        icon: <ShieldAlert size={14} />,
        label: f.title, sub: `finding · ${f.tool_source ?? 'unknown'} · ${f.category}`,
        badge: { text: f.severity, cls: SEVERITY_BADGE[f.severity] ?? 'passive' },
        key: `finding:${f.id}`,
      });
    }
    for (const l of results.loot) {
      out.push({
        page: 'loot', params: { workspaceId: l.workspace_id, runId: l.run_id ?? undefined },
        icon: <Coins size={14} />,
        label: l.label, sub: `loot · ${l.kind}${l.host ? ` · ${l.host}` : ''}`,
        badge: { text: l.severity, cls: SEVERITY_BADGE[l.severity] ?? 'passive' },
        key: `loot:${l.id}`,
      });
    }
    for (const wf of results.workflows) {
      out.push({
        page: 'workflow', params: { workflowId: wf.id },
        icon: <Network size={14} />,
        label: wf.name, sub: `workflow · ${wf.step_count} step${wf.step_count === 1 ? '' : 's'}`,
        key: `workflow:${wf.id}`,
      });
    }
    for (const w of results.workspaces) {
      out.push({
        page: 'workspaces', params: { workspaceId: w.id },
        icon: <FileText size={14} />,
        label: w.name, sub: `workspace · ${w.description || 'no description'}`,
        key: `workspace:${w.id}`,
      });
    }
    for (const wh of results.webhooks) {
      out.push({
        page: 'webhooks',
        icon: <Bell size={14} />,
        label: wh.name, sub: `webhook · ${wh.is_active ? 'active' : 'paused'}`,
        key: `webhook:${wh.id}`,
      });
    }
    for (const t of results.tools) {
      out.push({
        page: 'tools',
        icon: <Wrench size={14} />,
        label: t.name, sub: `tool · ${t.category} · ${t.description.slice(0, 80)}`,
        badge: { text: t.risk, cls: t.risk === 'passive' ? 'passive' : t.risk === 'high_active' ? 'bad' : 'active' },
        key: `tool:${t.id}`,
      });
    }
    for (const p of results.profiles) {
      out.push({
        page: 'templates',
        icon: <FileText size={14} />,
        label: p.name, sub: `profile · ${p.step_count} steps · ${p.description.slice(0, 70)}`,
        badge: { text: p.risk, cls: p.risk === 'passive' ? 'passive' : p.risk === 'high_active' ? 'bad' : 'active' },
        key: `profile:${p.id}`,
      });
    }
    return out;
  }, [results]);

  const activate = useCallback((item: Item) => {
    setOpen(false);
    navigate(item.page, item.params);
  }, [navigate]);

  // Arrow-key navigation through the flat list
  const handleInputKey = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIdx((i) => Math.min(items.length - 1, i + 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIdx((i) => Math.max(0, i - 1));
    } else if (e.key === 'Enter' && items[selectedIdx]) {
      e.preventDefault();
      activate(items[selectedIdx]);
    }
  };

  if (!open) return null;

  const grouped: Record<string, Item[]> = {};
  for (const item of items) {
    const cat = item.key.split(':', 1)[0];
    (grouped[cat] = grouped[cat] ?? []).push(item);
  }
  const CATEGORY_LABEL: Record<string, string> = {
    target: 'Targets', run: 'Runs', finding: 'Findings', loot: 'Loot',
    workflow: 'Workflows', workspace: 'Workspaces', webhook: 'Webhooks',
    tool: 'Tools', profile: 'Scan profiles',
  };
  const CATEGORY_ORDER = ['target', 'run', 'finding', 'loot', 'workflow', 'workspace', 'webhook', 'tool', 'profile'];

  // Build the flat index for highlight lookup
  let flatIdx = 0;

  return (
    <div className="modal-backdrop" onClick={() => setOpen(false)} role="presentation">
      <div className="search-palette" onClick={(e) => e.stopPropagation()} role="dialog" aria-label="Search">
        <div className="search-palette-input-row">
          <Search size={16} color="#22d3ee" />
          <input
            ref={inputRef}
            className="search-palette-input"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={handleInputKey}
            placeholder="Search targets, runs, findings, loot, workflows, tools…"
            autoComplete="off"
            spellCheck={false}
          />
          <span className="muted small">↑↓ navigate · ↵ open · esc close</span>
          <button className="icon-btn" onClick={() => setOpen(false)} type="button" aria-label="Close"><X size={14} /></button>
        </div>
        <div className="search-palette-results">
          {!q.trim() && (
            <p className="muted small" style={{ padding: '12px 14px', margin: 0 }}>
              Search across targets, runs, findings, loot, workflows, webhooks, tools, and scan profiles. Press <kbd>/</kbd> or <kbd>⌘K</kbd> from anywhere to reopen.
            </p>
          )}
          {q.trim() && busy && items.length === 0 && (
            <p className="muted small" style={{ padding: '12px 14px', margin: 0 }}>Searching…</p>
          )}
          {q.trim() && !busy && items.length === 0 && results && (
            <p className="muted small" style={{ padding: '12px 14px', margin: 0 }}>No matches.</p>
          )}
          {CATEGORY_ORDER.map((cat) => {
            const rows = grouped[cat];
            if (!rows || rows.length === 0) return null;
            return (
              <div key={cat} className="search-palette-group">
                <div className="search-palette-group-header">{CATEGORY_LABEL[cat]}</div>
                {rows.map((item) => {
                  const myIdx = flatIdx++;
                  const selected = myIdx === selectedIdx;
                  return (
                    <button
                      key={item.key}
                      type="button"
                      className={`search-palette-row ${selected ? 'selected' : ''}`}
                      onClick={() => activate(item)}
                      onMouseEnter={() => setSelectedIdx(myIdx)}
                    >
                      <span className="search-palette-row-icon">{item.icon}</span>
                      <span className="search-palette-row-text">
                        <strong>{item.label}</strong>
                        {item.sub && <small className="muted">{item.sub}</small>}
                      </span>
                      {item.badge && (
                        <span className={`badge ${item.badge.cls}`}>{item.badge.text}</span>
                      )}
                    </button>
                  );
                })}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
