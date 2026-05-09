import type { Artifact } from '../types';

export type ArtifactKind = 'text' | 'json' | 'jsonl' | 'html' | 'image' | 'binary';

const TEXT_EXTS = new Set([
  '.txt', '.log', '.csv', '.tsv', '.md', '.yaml', '.yml', '.xml',
  '.stdout.txt', '.stderr.txt',
]);
const JSON_EXTS = new Set(['.json']);
const JSONL_EXTS = new Set(['.jsonl', '.ndjson']);
const HTML_EXTS = new Set(['.html', '.htm']);
const IMAGE_EXTS = new Set(['.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.bmp']);

function lowerName(name: string): string {
  return name.toLowerCase();
}

function endsWithAny(name: string, exts: Set<string>): boolean {
  for (const ext of exts) if (name.endsWith(ext)) return true;
  return false;
}

/**
 * Decide which renderer to use for an artifact. Content-Type is consulted first
 * (the source of truth) and falls back to the filename extension. Extension wins
 * over a generic application/octet-stream.
 */
export function classifyArtifact(artifact: Pick<Artifact, 'name' | 'content_type'>): ArtifactKind {
  const name = lowerName(artifact.name);
  const ct = (artifact.content_type ?? '').toLowerCase();

  // Strong signals from extension
  if (endsWithAny(name, JSONL_EXTS)) return 'jsonl';
  if (endsWithAny(name, JSON_EXTS)) return 'json';
  if (endsWithAny(name, HTML_EXTS)) return 'html';
  if (endsWithAny(name, IMAGE_EXTS)) return 'image';
  if (endsWithAny(name, TEXT_EXTS) || name.endsWith('.stdout.txt') || name.endsWith('.stderr.txt')) {
    return 'text';
  }

  // Content-type hints
  if (ct.startsWith('image/')) return 'image';
  if (ct === 'application/json' || ct === 'text/json') return 'json';
  if (ct === 'application/x-ndjson' || ct === 'application/jsonl') return 'jsonl';
  if (ct === 'text/html' || ct === 'application/xhtml+xml') return 'html';
  if (ct.startsWith('text/')) return 'text';

  return 'binary';
}

/**
 * For very large artifacts (logs, multi-MB JSON dumps) we want to fetch a
 * head + tail rather than the whole file. Returns null when the full content
 * should be fetched.
 */
export function fetchSizeCap(kind: ArtifactKind): number | null {
  switch (kind) {
    case 'text':
    case 'jsonl':
      return 2 * 1024 * 1024;   // 2 MiB head
    case 'json':
    case 'html':
      return 5 * 1024 * 1024;   // 5 MiB
    case 'image':
    case 'binary':
      return null;               // image src tags fetch directly
  }
}

/**
 * Pretty-print a JSONL blob. Each line is parsed independently — malformed lines
 * are passed through verbatim with a "[unparsed]" prefix so a single bad line
 * doesn't kill the whole render.
 */
export function prettyJsonl(blob: string): string {
  return blob
    .split('\n')
    .filter((line) => line.trim().length > 0)
    .map((line) => {
      try {
        return JSON.stringify(JSON.parse(line), null, 2);
      } catch {
        return `[unparsed] ${line}`;
      }
    })
    .join('\n\n');
}
