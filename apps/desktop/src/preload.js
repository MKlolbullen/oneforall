'use strict';
// Preload runs in an isolated context before the renderer scripts load. The
// sidecar URL is chosen at runtime by main.js (free-port pick), so we receive
// it through `additionalArguments` rather than env vars (which would leak into
// any child processes the renderer spawned).
//
// The frontend's apps/web/src/lib/runtimeConfig.ts reads
// `window.__RECONFORGE_CONFIG__` first, falling back to the Vite build-time
// envs, then to localhost — exposing the value here is all that's needed.
const { contextBridge } = require('electron');

const PREFIX = '--reconforge-config=';

function loadConfig() {
  const arg = process.argv.find((a) => a.startsWith(PREFIX));
  if (!arg) return {};
  try {
    const json = Buffer.from(arg.slice(PREFIX.length), 'base64').toString('utf8');
    return JSON.parse(json);
  } catch {
    // Malformed config arg: fall back to localhost defaults rather than crash.
    return {};
  }
}

contextBridge.exposeInMainWorld('__RECONFORGE_CONFIG__', loadConfig());
