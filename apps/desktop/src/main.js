'use strict';
// Electron main process for the ReconForge desktop shell.
//
//   1. Pick a free localhost port.
//   2. Spawn the Python sidecar (dev: uvicorn from apps/api; prod: PyInstaller
//      binary in resources/sidecar) on that port, in embedded runner mode.
//   3. Poll /health until the API answers (sidecar may run migrations on boot).
//   4. Open a BrowserWindow that loads either the Vite dev server (dev) or
//      `app://reconforge/index.html` from the bundled web build (prod). The
//      preload exposes the sidecar URL as window.__RECONFORGE_CONFIG__ so the
//      React app routes API/WS calls at the right port.
//   5. On window-all-closed / SIGTERM, kill the sidecar before exiting.
const { app, BrowserWindow } = require('electron');
const path = require('node:path');

const {
  pickFreePort,
  spawnSidecar,
  waitForHealth,
  killSidecar,
} = require('./sidecar.js');
const { registerSchemes, registerHandler } = require('./protocol.js');

const IS_DEV = process.env.RECONFORGE_DESKTOP_DEV === '1';

// Repo paths (apps/desktop/src/main.js → ../../api, ../../web/dist).
const API_DIR = path.resolve(__dirname, '..', '..', 'api');
const WEB_DIST_DIR = path.resolve(__dirname, '..', '..', 'web', 'dist');

// Privileged scheme registration MUST happen before app.whenReady.
registerSchemes();

let sidecarProc = null;
let mainWindow = null;
let isQuitting = false;

function encodeConfig(port) {
  const config = {
    apiBaseUrl: `http://127.0.0.1:${port}`,
    wsBaseUrl: `ws://127.0.0.1:${port}`,
  };
  return '--reconforge-config=' + Buffer.from(JSON.stringify(config)).toString('base64');
}

async function createWindow(port) {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    show: false,
    backgroundColor: '#0b1220',
    title: 'ReconForge',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false,
      additionalArguments: [encodeConfig(port)],
    },
  });

  const startUrl = IS_DEV
    ? 'http://localhost:5173'
    : 'app://reconforge/index.html';
  await mainWindow.loadURL(startUrl);
  mainWindow.show();
  mainWindow.on('closed', () => { mainWindow = null; });
}

async function bootstrap() {
  const port = await pickFreePort();
  console.log(`[reconforge-desktop] starting sidecar on 127.0.0.1:${port} (mode=${IS_DEV ? 'dev' : 'prod'})`);

  sidecarProc = spawnSidecar({
    port,
    mode: IS_DEV ? 'dev' : 'prod',
    apiDir: API_DIR,
    resourcesPath: process.resourcesPath,
  });

  // If the sidecar dies, take the UI down with it — a stale window with a
  // dead backend is worse than a quit.
  sidecarProc.on('exit', (code, signal) => {
    console.error(`[reconforge-desktop] sidecar exited code=${code} signal=${signal}`);
    if (!isQuitting) {
      isQuitting = true;
      app.exit(code ?? 1);
    }
  });

  console.log('[reconforge-desktop] waiting for sidecar /health...');
  await waitForHealth(port);
  console.log('[reconforge-desktop] sidecar ready');

  // In dev we point the renderer at vite-dev; the app:// handler is only used
  // for the prod bundle that ships with the Electron app.
  if (!IS_DEV) registerHandler(WEB_DIST_DIR);

  await createWindow(port);
}

app.whenReady().then(bootstrap).catch((e) => {
  console.error('[reconforge-desktop] startup failed:', e);
  isQuitting = true;
  app.exit(1);
});

app.on('window-all-closed', async () => {
  isQuitting = true;
  await killSidecar(sidecarProc);
  app.quit();
});

app.on('before-quit', async (event) => {
  if (!sidecarProc || sidecarProc.exitCode !== null) return;
  // Hold quit until the sidecar exits cleanly.
  event.preventDefault();
  isQuitting = true;
  await killSidecar(sidecarProc);
  app.exit(0);
});

for (const sig of ['SIGTERM', 'SIGINT']) {
  process.on(sig, () => {
    isQuitting = true;
    app.quit();
  });
}
