'use strict';
// Python sidecar lifecycle for the Electron shell.
//
// Picks a free port, spawns the API, waits for /health to confirm boot, and
// terminates it cleanly on app quit. The API is started in embedded runner
// mode (Phase 2) so it has no Redis dependency and runs as a single Python
// process.
const { spawn } = require('node:child_process');
const net = require('node:net');
const http = require('node:http');
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');

async function pickFreePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

function reconforgeHome() {
  // ~/.reconforge for the desktop install. Override with RECONFORGE_HOME for
  // tests / portable builds.
  return process.env.RECONFORGE_HOME || path.join(os.homedir(), '.reconforge');
}

function buildEnv(home) {
  fs.mkdirSync(path.join(home, 'artifacts'), { recursive: true });
  return {
    ...process.env,
    // Phase 2: in-process worker, no Redis, no second process.
    RUNNER_MODE: 'embedded',
    // SQLite + local artifacts under the user's home — survives reinstalls.
    // SQLAlchemy URLs require forward slashes; path.join uses backslashes on
    // Windows, which would produce an invalid `sqlite:///C:\Users\...` URL.
    DATABASE_URL: `sqlite:///${path.join(home, 'reconforge.db').replace(/\\/g, '/')}`,
    ARTIFACT_BACKEND: 'local',
    ARTIFACT_DIR: path.join(home, 'artifacts'),
    EXECUTION_MODE: 'dry_run',
    ALLOW_LIVE_EXECUTION: 'false',
    // CORS: deliberately NOT set here. The API default in
    // apps/api/app/core/config.py already includes `app://reconforge` plus the
    // vite-dev origins, so leaving CORS_ORIGINS unset lets that single source
    // of truth win. Anyone overriding it via .env still takes precedence.
  };
}

function spawnSidecar({ port, mode, apiDir, resourcesPath }) {
  const home = reconforgeHome();
  const env = buildEnv(home);
  let cmd;
  let args;
  let cwd;

  if (mode === 'dev') {
    // Dev: requires the API package installed in the active Python env. The
    // contributor either uses a venv (RECONFORGE_PYTHON=./apps/api/.venv/bin/python)
    // or has it on PATH.
    cmd = process.env.RECONFORGE_PYTHON || 'python';
    args = ['-m', 'uvicorn', 'app.main:app',
            '--host', '127.0.0.1', '--port', String(port),
            '--log-level', 'info'];
    cwd = apiDir;
  } else {
    // Prod: PyInstaller binary bundled into the app's resources directory.
    const binName = process.platform === 'win32'
      ? 'reconforge-sidecar.exe'
      : 'reconforge-sidecar';
    cmd = path.join(resourcesPath, 'sidecar', binName);
    args = ['--host', '127.0.0.1', '--port', String(port)];
    cwd = path.dirname(cmd);
  }

  const proc = spawn(cmd, args, {
    env,
    cwd,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  // Surface sidecar logs to Electron's stdout for crash diagnosis.
  proc.stdout?.on('data', (d) => process.stdout.write(`[sidecar] ${d}`));
  proc.stderr?.on('data', (d) => process.stderr.write(`[sidecar] ${d}`));
  return proc;
}

async function waitForHealth(port, { timeoutMs = 30000, intervalMs = 250 } = {}) {
  const deadline = Date.now() + timeoutMs;
  let lastErr;
  while (Date.now() < deadline) {
    try {
      await probeOnce(port);
      return;
    } catch (e) {
      lastErr = e;
      await new Promise((r) => setTimeout(r, intervalMs));
    }
  }
  throw new Error(
    `sidecar /health did not respond within ${timeoutMs}ms (last error: ${lastErr?.message ?? 'unknown'})`,
  );
}

function probeOnce(port) {
  return new Promise((resolve, reject) => {
    const req = http.get(
      { host: '127.0.0.1', port, path: '/health', timeout: 1500 },
      (res) => {
        // Drain so the socket can be returned to the pool, regardless of status.
        res.resume();
        if (res.statusCode === 200) resolve();
        else reject(new Error(`status ${res.statusCode}`));
      },
    );
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('timeout'));
    });
  });
}

async function killSidecar(proc, { graceMs = 5000 } = {}) {
  if (!proc || proc.exitCode !== null || proc.signalCode !== null) return;
  return new Promise((resolve) => {
    const finished = () => {
      clearTimeout(forceTimer);
      resolve();
    };
    proc.once('exit', finished);
    const forceTimer = setTimeout(() => {
      try { proc.kill('SIGKILL'); } catch { /* already gone */ }
      finished();
    }, graceMs);
    try { proc.kill('SIGTERM'); } catch { finished(); }
  });
}

module.exports = {
  pickFreePort,
  spawnSidecar,
  waitForHealth,
  killSidecar,
  reconforgeHome,
};
