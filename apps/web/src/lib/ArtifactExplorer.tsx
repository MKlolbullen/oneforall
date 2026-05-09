import { useEffect, useMemo, useState } from 'react';
import { Download, FileJson, FileText, Image as ImageIcon, Loader2, Maximize2, Minimize2 } from 'lucide-react';
import { api } from './api';
import { classifyArtifact, fetchSizeCap, prettyJsonl, type ArtifactKind } from './artifactKind';
import type { Artifact } from '../types';

type Props = {
  artifact: Artifact;
  onClose?: () => void;
};

const KIND_ICON: Record<ArtifactKind, React.ReactNode> = {
  text: <FileText size={14} />,
  json: <FileJson size={14} />,
  jsonl: <FileJson size={14} />,
  html: <FileText size={14} />,
  image: <ImageIcon size={14} />,
  binary: <Download size={14} />,
};

export function ArtifactExplorer({ artifact, onClose }: Props) {
  const kind = useMemo(() => classifyArtifact(artifact), [artifact]);
  const [expanded, setExpanded] = useState(false);
  const [body, setBody] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState('');

  const contentUrl = api.artifactContentUrl(artifact.id);
  const cap = fetchSizeCap(kind);
  const truncated = cap !== null && artifact.size_bytes > cap;

  useEffect(() => {
    setBody(null);
    setError(null);
    setFilter('');
    if (kind === 'image' || kind === 'binary') return;

    setLoading(true);
    const headers: Record<string, string> = {};
    if (cap !== null && truncated) headers.Range = `bytes=0-${cap}`;
    fetch(contentUrl, { headers })
      .then(async (r) => {
        if (!r.ok && r.status !== 206) throw new Error(`${r.status} ${r.statusText}`);
        return r.text();
      })
      .then(setBody)
      .catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false));
  }, [artifact.id, kind, contentUrl, cap, truncated]);

  return (
    <div className={`artifact-explorer ${expanded ? 'expanded' : ''}`}>
      <header className="artifact-explorer-header">
        <div className="row">
          {KIND_ICON[kind]}
          <strong className="mono">{artifact.name}</strong>
          <span className="badge passive">{kind}</span>
          <span className="muted">
            {(artifact.size_bytes / 1024).toFixed(1)} KB · {artifact.storage_backend}
          </span>
          {truncated && <span className="badge bad" title={`Showing first ${cap} bytes`}>truncated</span>}
        </div>
        <div className="row">
          <a className="btn small" href={contentUrl} target="_blank" rel="noreferrer">
            <Download size={14} /> Raw
          </a>
          <button className="btn small" onClick={() => setExpanded((v) => !v)}>
            {expanded ? <Minimize2 size={14} /> : <Maximize2 size={14} />}
          </button>
          {onClose && (
            <button className="btn small" onClick={onClose} aria-label="Close artifact preview">
              ✕
            </button>
          )}
        </div>
      </header>

      {loading && (
        <div className="artifact-loading row muted">
          <Loader2 className="spin" size={14} /> Loading…
        </div>
      )}

      {error && <div className="artifact-error">Failed to load: {error}</div>}

      {!loading && !error && (
        <>
          {kind === 'text' && body !== null && <TextRender body={body} filter={filter} setFilter={setFilter} />}
          {kind === 'json' && body !== null && <JsonRender body={body} />}
          {kind === 'jsonl' && body !== null && <JsonlRender body={body} filter={filter} setFilter={setFilter} />}
          {kind === 'html' && body !== null && <HtmlRender body={body} />}
          {kind === 'image' && <img className="artifact-image" src={contentUrl} alt={artifact.name} />}
          {kind === 'binary' && <BinaryRender artifact={artifact} contentUrl={contentUrl} />}
        </>
      )}
    </div>
  );
}

function TextRender({ body, filter, setFilter }: { body: string; filter: string; setFilter: (v: string) => void }) {
  const lines = body.split('\n');
  const filtered = filter
    ? lines.map((l, i) => ({ i: i + 1, l })).filter((row) => row.l.toLowerCase().includes(filter.toLowerCase()))
    : lines.map((l, i) => ({ i: i + 1, l }));
  return (
    <div className="artifact-text">
      <input
        className="input"
        placeholder="Filter lines (case-insensitive)…"
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
      />
      <pre>
        {filtered.map(({ i, l }) => (
          <div key={i} className="text-line">
            <span className="lineno">{String(i).padStart(4, ' ')}</span>
            <span>{l}</span>
          </div>
        ))}
      </pre>
    </div>
  );
}

function JsonRender({ body }: { body: string }) {
  let pretty = body;
  let parsed: unknown = null;
  try {
    parsed = JSON.parse(body);
    pretty = JSON.stringify(parsed, null, 2);
  } catch {
    // keep raw body; show parse warning
    return (
      <div className="artifact-text">
        <div className="warning-text">JSON parse failed — showing raw text.</div>
        <pre>{body}</pre>
      </div>
    );
  }
  return <pre className="artifact-json">{pretty}</pre>;
}

function JsonlRender({ body, filter, setFilter }: { body: string; filter: string; setFilter: (v: string) => void }) {
  const pretty = useMemo(() => prettyJsonl(body), [body]);
  return <TextRender body={pretty} filter={filter} setFilter={setFilter} />;
}

function HtmlRender({ body }: { body: string }) {
  // Sandbox the iframe so the artifact HTML can't run scripts in our origin or
  // talk back to our cookies. Drop both allow-scripts and allow-same-origin.
  return (
    <iframe
      className="artifact-html"
      sandbox=""
      srcDoc={body}
      title="artifact preview"
    />
  );
}

function BinaryRender({ artifact, contentUrl }: { artifact: Artifact; contentUrl: string }) {
  return (
    <div className="artifact-binary">
      <p className="muted">No inline preview for this content type ({artifact.content_type}).</p>
      <a className="btn" href={contentUrl} target="_blank" rel="noreferrer">
        <Download size={14} /> Download {artifact.name}
      </a>
    </div>
  );
}
