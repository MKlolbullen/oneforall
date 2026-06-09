'use strict';
// `app://reconforge/` custom protocol handler.
//
// Loading the Vite build via file:// gives the page a "null" origin which the
// API would have to wildcard-allow in CORS, and breaks SecureContext-only
// browser APIs. A registered custom scheme gives the renderer a stable origin
// (`app://reconforge`) that we can add to the API's CORS allowlist cleanly.
const { protocol, net } = require('electron');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

// Must run BEFORE app.whenReady() — Electron requires this for privileged
// schemes. The flags grant the standard same-origin policy, secure-context,
// fetch API, and CORS plumbing the React app expects.
function registerSchemes() {
  protocol.registerSchemesAsPrivileged([
    {
      scheme: 'app',
      privileges: {
        standard: true,
        secure: true,
        supportFetchAPI: true,
        corsEnabled: true,
        stream: true,
      },
    },
  ]);
}

// Maps app://reconforge/<path> -> <webDistDir>/<path>. Resolves "/" to
// index.html so a bare app://reconforge/ load works. Rejects path traversal
// attempts and requests for other app:// hosts.
function registerHandler(webDistDir) {
  const root = path.resolve(webDistDir);
  protocol.handle('app', async (request) => {
    const url = new URL(request.url);
    if (url.host !== 'reconforge') {
      return new Response('Unknown app host', { status: 404 });
    }
    let pathname;
    try {
      pathname = decodeURIComponent(url.pathname);
    } catch {
      // Malformed percent-encoding — return a controlled 400 rather than
      // letting the URIError bubble out of the handler.
      return new Response('Bad Request', { status: 400 });
    }
    if (!pathname || pathname === '/') pathname = '/index.html';
    const resolved = path.normalize(path.join(root, pathname));
    // Defence in depth: refuse anything that escaped the dist root.
    if (resolved !== root && !resolved.startsWith(root + path.sep)) {
      return new Response('Forbidden', { status: 403 });
    }
    return net.fetch(pathToFileURL(resolved).toString());
  });
}

module.exports = { registerSchemes, registerHandler };
