import { useEffect, useMemo, useState } from 'react';
import { Beaker, Download, FlaskConical, RefreshCw } from 'lucide-react';
import { api } from './api';
import { CopyButton } from './CopyButton';
import { EmptyState } from './EmptyState';
import { useToast } from './Toast';
import type { PayloadEncoding, PayloadFileMeta, PayloadIndex, PayloadResponse } from '../types';

const ENCODING_HELP: Record<PayloadEncoding, string> = {
  raw:     'no transform',
  url:     'percent-encode every byte (single)',
  url2:    'percent-encode twice — slips past one decode layer',
  base64:  'base64 of the UTF-8 bytes',
  hex:     'lowercase hex of the UTF-8 bytes',
  html:    'HTML entity escape (text-context safe)',
  unicode: '\\uXXXX form, JS-safe',
};

const CATEGORY_HINT: Record<string, string> = {
  xss: 'Cross-site scripting',
  sqli: 'SQL injection',
  ssrf: 'Server-side request forgery',
  lfi: 'Local file inclusion / path traversal',
  ssti: 'Server-side template injection',
  xxe: 'XML external entity',
  nosqli: 'NoSQL injection',
  redirect: 'Open redirect',
  crlf: 'CR/LF header injection',
  'command-injection': 'OS command injection',
};

export function Payloads() {
  const toast = useToast();
  const [index, setIndex] = useState<PayloadIndex | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const [selected, setSelected] = useState<{ category: string; name: string } | null>(null);
  const [encoding, setEncoding] = useState<PayloadEncoding>('raw');
  const [body, setBody] = useState<PayloadResponse | null>(null);
  const [bodyLoading, setBodyLoading] = useState(false);
  const [filter, setFilter] = useState('');

  const reload = async () => {
    setLoading(true); setError(null);
    try {
      const idx = await api.payloadIndex();
      setIndex(idx);
      if (!selected && idx.files[0]) {
        setSelected({ category: idx.files[0].category, name: idx.files[0].name });
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      setError(msg);
      toast.error('Failed to load payload index', msg);
    } finally { setLoading(false); }
  };

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { reload(); }, []);

  // Load the picked file whenever the selection or encoding changes.
  useEffect(() => {
    if (!selected) { setBody(null); return; }
    let cancelled = false;
    setBodyLoading(true);
    api.payload(selected.category, selected.name, encoding)
      .then((res) => { if (!cancelled) setBody(res); })
      .catch((e) => {
        if (cancelled) return;
        toast.fromError(e, 'Failed to load payload');
      })
      .finally(() => { if (!cancelled) setBodyLoading(false); });
    return () => { cancelled = true; };
  }, [selected, encoding, toast]);

  const groups = useMemo(() => {
    if (!index) return new Map<string, PayloadFileMeta[]>();
    const f = filter.trim().toLowerCase();
    const map = new Map<string, PayloadFileMeta[]>();
    for (const file of index.files) {
      const hay = `${file.category} ${file.name} ${file.description}`.toLowerCase();
      if (f && !hay.includes(f)) continue;
      if (!map.has(file.category)) map.set(file.category, []);
      map.get(file.category)!.push(file);
    }
    return map;
  }, [index, filter]);

  const totalShown = useMemo(() =>
    Array.from(groups.values()).reduce((acc, files) => acc + files.length, 0),
    [groups]);

  const copyAll = async () => {
    if (!body) return;
    const text = body.payloads.join('\n') + '\n';
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        const ta = document.createElement('textarea');
        ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
        document.body.appendChild(ta); ta.select();
        document.execCommand('copy'); document.body.removeChild(ta);
      }
      toast.success('Copied', `${body.payload_count} payloads on clipboard.`);
    } catch (e) {
      toast.fromError(e, 'Copy failed');
    }
  };

  return (
    <div className="grid">
      <div className="row space">
        <div className="row">
          <FlaskConical size={16} color="#22d3ee" />
          <strong>Payload library</strong>
          <span className="muted">authorized testing only</span>
        </div>
        <button className="btn small" onClick={reload} disabled={loading} type="button">
          <RefreshCw size={13} className={loading ? 'spin' : ''} /> Reload
        </button>
      </div>

      {error && <div className="card"><p className="advice-error">{error}</p></div>}

      <div className="payload-shell">
        <aside className="card payload-tree">
          <input
            className="input"
            placeholder={`filter ${index?.files.length ?? 0} files…`}
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            data-shortcut-target="search"
          />
          {totalShown === 0 ? (
            <EmptyState
              title="Nothing matches"
              body={index ? 'Clear the filter to see all categories.' : 'Loading…'}
            />
          ) : (
            <div className="payload-categories">
              {Array.from(groups.entries()).map(([cat, files]) => (
                <div key={cat} className="payload-category">
                  <div className="payload-category-header">
                    <Beaker size={12} />
                    <strong>{cat}</strong>
                    <span className="muted" style={{ fontSize: 11 }}>{files.length}</span>
                  </div>
                  {CATEGORY_HINT[cat] && (
                    <p className="muted" style={{ fontSize: 11, margin: '0 0 4px 18px' }}>
                      {CATEGORY_HINT[cat]}
                    </p>
                  )}
                  <ul className="payload-files">
                    {files.map((f) => {
                      const active = selected?.category === f.category && selected?.name === f.name;
                      return (
                        <li key={`${f.category}/${f.name}`}>
                          <button
                            type="button"
                            className={`payload-file ${active ? 'selected' : ''}`}
                            onClick={() => setSelected({ category: f.category, name: f.name })}
                          >
                            <span>{f.name}</span>
                            <span className="badge passive">{f.payload_count}</span>
                          </button>
                        </li>
                      );
                    })}
                  </ul>
                </div>
              ))}
            </div>
          )}
        </aside>

        <section className="card payload-detail">
          {!selected && (
            <EmptyState
              icon={<FlaskConical size={28} />}
              title="Pick a payload set"
              body="Pick any list on the left, choose an encoding, copy or download."
            />
          )}
          {selected && (
            <>
              <div className="row space">
                <div>
                  <strong>{selected.category} / {selected.name}</strong>
                  <div className="muted" style={{ fontSize: 12, marginTop: 2 }}>
                    {body?.description || ' '}
                  </div>
                </div>
                <div className="row">
                  <a
                    className="btn small"
                    href={api.payloadDownloadUrl(selected.category, selected.name, encoding)}
                    title="Download as text"
                  >
                    <Download size={13} /> .txt
                  </a>
                  <button className="btn small" onClick={copyAll} type="button">
                    Copy all
                  </button>
                </div>
              </div>

              <div className="encoding-bar">
                {(['raw','url','url2','base64','hex','html','unicode'] as PayloadEncoding[]).map((e) => (
                  <button
                    key={e}
                    type="button"
                    className={`encoding-chip ${encoding === e ? 'selected' : ''}`}
                    onClick={() => setEncoding(e)}
                    title={ENCODING_HELP[e]}
                  >
                    {e}
                  </button>
                ))}
              </div>

              {bodyLoading && <p className="muted">Encoding…</p>}
              {body && (
                <div className="payload-list">
                  {body.payloads.length === 0 && (
                    <EmptyState title="Empty list" body="This file has no payloads." />
                  )}
                  {body.payloads.map((p, i) => (
                    <div key={i} className="payload-row">
                      <code className="mono payload-text">{p}</code>
                      <CopyButton value={p} title="Copy this payload" />
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </section>
      </div>
    </div>
  );
}
