// Runtime config resolution. Vite bakes import.meta.env at build time, which
// is fine for the docker-compose web container but useless for an Electron
// shell that needs to point at a sidecar URL chosen at app start. Resolution
// order, highest precedence first:
//
//   1. window.__RECONFORGE_CONFIG__ — injected by an Electron preload script
//      (or a server-rendered <script> tag) before the React bundle loads.
//   2. import.meta.env.VITE_API_BASE_URL / VITE_WS_BASE_URL — build-time env,
//      used by the docker-compose web image and `npm run dev`.
//   3. Hardcoded localhost defaults for a developer running `vite` against a
//      local uvicorn.

export interface ReconForgeRuntimeConfig {
  apiBaseUrl?: string;
  wsBaseUrl?: string;
}

const DEFAULT_API = 'http://localhost:8000';
const DEFAULT_WS = 'ws://localhost:8000';

function fromWindow(): ReconForgeRuntimeConfig {
  if (typeof window === 'undefined') return {};
  return window.__RECONFORGE_CONFIG__ ?? {};
}

export function getApiBaseUrl(): string {
  return (
    fromWindow().apiBaseUrl ??
    import.meta.env.VITE_API_BASE_URL ??
    DEFAULT_API
  );
}

export function getWsBaseUrl(): string {
  return (
    fromWindow().wsBaseUrl ??
    import.meta.env.VITE_WS_BASE_URL ??
    DEFAULT_WS
  );
}
