import { useCallback, useEffect, useRef, useState } from 'react';
import { MessageSquare, Send, Sparkles, X } from 'lucide-react';
import { api } from './api';
import { useAdvisorScope } from './advisorContext';
import { useToast } from './Toast';

type Message = {
  id: string;
  role: 'user' | 'assistant';
  text: string;
  meta?: { model?: string; cached_tokens?: number; prompt_tokens?: number; completion_tokens?: number };
};

const STORAGE_KEY = 'reconforge:advisor-chat:v1';
const OPEN_EVENT = 'reconforge:advisor-open';

function newId() {
  return `msg_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
}

/**
 * Floating Claude advisor chat. Hidden by default; opens on the
 * `reconforge:advisor-open` CustomEvent (dispatched by topbar/run-console
 * buttons). Grounds each question in the current AdvisorScope so the model
 * has the active run / target as context without the operator typing IDs.
 */
export function AdvisorChat() {
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<Message[]>([]);
  const [draft, setDraft] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { scope } = useAdvisorScope();
  const toast = useToast();
  const scrollRef = useRef<HTMLDivElement | null>(null);

  // Restore messages from localStorage so closing/reopening keeps history.
  useEffect(() => {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) setMessages(JSON.parse(raw) as Message[]);
    } catch {
      /* malformed history — start fresh */
    }
  }, []);
  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(messages.slice(-50)));
    } catch {
      /* quota — non-fatal */
    }
  }, [messages]);

  // External open trigger via CustomEvent — topbar/run-console buttons dispatch it.
  useEffect(() => {
    const onOpen = () => setOpen(true);
    window.addEventListener(OPEN_EVENT, onOpen as EventListener);
    return () => window.removeEventListener(OPEN_EVENT, onOpen as EventListener);
  }, []);

  // Auto-scroll on new message.
  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [messages, busy]);

  const ask = useCallback(async (override?: string) => {
    const text = (override ?? draft).trim();
    if (!text || busy) return;
    if (!scope.workspaceId) {
      toast.warn('No workspace context', 'Open a target or run first so the advisor has something to ground in.');
      return;
    }
    setBusy(true);
    setError(null);
    const userMsg: Message = { id: newId(), role: 'user', text };
    setMessages((prev) => [...prev, userMsg]);
    if (!override) setDraft('');
    try {
      const advice = await api.askAdvisor({
        question: text,
        workspace_id: scope.workspaceId,
        run_id: scope.runId ?? undefined,
        target_id: scope.targetId ?? undefined,
      });
      setMessages((prev) => [
        ...prev,
        {
          id: newId(),
          role: 'assistant',
          text: advice.summary || '(no reply)',
          meta: {
            model: advice.model,
            cached_tokens: advice.cached_tokens,
            prompt_tokens: advice.prompt_tokens,
            completion_tokens: advice.completion_tokens,
          },
        },
      ]);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setError(msg);
      toast.fromError(e, 'Advisor call failed');
    } finally {
      setBusy(false);
    }
  }, [draft, busy, scope.workspaceId, scope.runId, scope.targetId, toast]);

  const triageCurrentRun = useCallback(async () => {
    if (!scope.runId) {
      toast.warn('No run selected', 'Pick a run first to triage it.');
      return;
    }
    setBusy(true);
    setError(null);
    setMessages((prev) => [
      ...prev,
      { id: newId(), role: 'user', text: `Triage run ${scope.runLabel ?? scope.runId}.` },
    ]);
    try {
      const advice = await api.triageRun(scope.runId);
      setMessages((prev) => [
        ...prev,
        {
          id: newId(),
          role: 'assistant',
          text: advice.summary || '(no reply)',
          meta: {
            model: advice.model,
            cached_tokens: advice.cached_tokens,
            prompt_tokens: advice.prompt_tokens,
            completion_tokens: advice.completion_tokens,
          },
        },
      ]);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      toast.fromError(e, 'Triage failed');
    } finally {
      setBusy(false);
    }
  }, [scope.runId, scope.runLabel, toast]);

  const clearHistory = () => {
    setMessages([]);
    setError(null);
    try { localStorage.removeItem(STORAGE_KEY); } catch { /* ignore */ }
  };

  return (
    <>
      {!open && (
        <button
          type="button"
          className="advisor-fab"
          title="Open advisor chat"
          onClick={() => setOpen(true)}
        >
          <MessageSquare size={16} />
          <span className="advisor-fab-label">Advisor</span>
        </button>
      )}
      {open && (
        <div className="advisor-chat floating" role="dialog" aria-label="Claude advisor chat">
          <div className="advisor-chat-header">
            <div className="row">
              <MessageSquare size={16} color="#22d3ee" />
              <strong>Advisor</strong>
            </div>
            <div className="row">
              <button className="btn small" onClick={clearHistory} type="button" title="Clear chat history">Clear</button>
              <button className="icon-btn" onClick={() => setOpen(false)} type="button" aria-label="Close advisor">
                <X size={14} />
              </button>
            </div>
          </div>
          <div className="advisor-context-bar muted">
            <span>Context:</span>
            {scope.runLabel && <span className="badge passive">run · {scope.runLabel}</span>}
            {scope.targetLabel && <span className="badge passive">target · {scope.targetLabel}</span>}
            {!scope.runLabel && !scope.targetLabel && (
              <span className="muted">no run/target — open one to ground the advisor</span>
            )}
          </div>
          <div className="advisor-quick-actions">
            <button
              type="button"
              className="btn small"
              onClick={triageCurrentRun}
              disabled={!scope.runId || busy}
              title={scope.runId ? 'Triage the current run with Claude' : 'Open a run to enable triage'}
            >
              <Sparkles size={12} /> Triage this run
            </button>
            <button
              type="button"
              className="btn small"
              onClick={() => ask('What should I do next?')}
              disabled={!scope.workspaceId || busy}
              title="Ask the advisor what to do next given the current scope"
            >
              What next?
            </button>
          </div>
          <div className="advisor-chat-messages" ref={scrollRef}>
            {messages.length === 0 && (
              <p className="muted">
                Ask the advisor anything about the current scope.
                {scope.runLabel && ` Context: run ${scope.runLabel}.`}
              </p>
            )}
            {messages.map((m) => (
              <div key={m.id} className={`advisor-bubble ${m.role}`}>
                <div className="advisor-bubble-text">{m.text}</div>
                {m.meta?.model && (
                  <div className="advisor-bubble-meta muted row">
                    <span>{m.meta.model}</span>
                    <span>· in {m.meta.prompt_tokens}t</span>
                    <span>· out {m.meta.completion_tokens}t</span>
                    {m.meta.cached_tokens ? <span>· cached {m.meta.cached_tokens}t</span> : null}
                  </div>
                )}
              </div>
            ))}
            {busy && <div className="advisor-bubble assistant typing"><div className="advisor-bubble-text">Thinking…</div></div>}
          </div>
          {error && <p className="advisor-chat-error">{error}</p>}
          <form
            className="advisor-chat-compose"
            onSubmit={(e) => { e.preventDefault(); ask(); }}
          >
            <textarea
              className="input advisor-chat-input"
              rows={2}
              placeholder={scope.workspaceId ? 'Ask a question (⌘/Ctrl+Enter to send)…' : 'Open a target or run to ground the advisor first.'}
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
                  e.preventDefault();
                  ask();
                }
              }}
              disabled={busy}
            />
            <button className="btn advisor-send" type="submit" disabled={busy || !draft.trim()}>
              <Send size={14} /> Send
            </button>
          </form>
        </div>
      )}
    </>
  );
}
