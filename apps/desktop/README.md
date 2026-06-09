# reconforge-desktop

Electron shell that wraps the React UI and a Python API sidecar into a single
desktop application — no Docker, no Redis, no Postgres.

This is Phase 3 of the desktop track. The previous phases land the pieces it
depends on:

- **Phase 1** (PR #11): `apps/web/src/lib/runtimeConfig.ts` resolves the API
  and WebSocket URLs at runtime via `window.__RECONFORGE_CONFIG__`, so the
  sidecar's chosen port can be injected after the bundle is built.
- **Phase 2** (PR #16): `RUNNER_MODE=embedded` runs the worker inside the API's
  own asyncio loop, with in-memory event/queue transports. The sidecar is one
  Python process.

## Architecture

```
┌───────────────────────────────┐         ┌──────────────────────────┐
│  Electron main (Node)          │ spawn   │  reconforge-sidecar       │
│   - pick free localhost port   │────────▶│  (PyInstaller binary OR   │
│   - spawn sidecar              │         │   `python -m uvicorn`)    │
│   - poll /health               │◀────────│   FastAPI · embedded      │
│   - register app:// scheme     │  health │   runner · sqlite + local │
│   - BrowserWindow + preload    │         │   artifacts under ~/.recon│
└──────────────┬────────────────┘         └──────────────────────────┘
               │ loads
               ▼
        app://reconforge/index.html
        (preload injects __RECONFORGE_CONFIG__ with the sidecar URL)
```

## Dev mode

You need three things on your machine:

1. Node ≥ 18 (Electron 32 ships with Chromium 128).
2. A Python environment with the API installed: `cd apps/api && pip install -e .`
3. The React frontend's dev server, running separately.

Then, in three terminals:

```bash
# 1. Frontend dev server (Vite, port 5173)
cd apps/web && npm install && npm run dev

# 2. Electron shell — spawns the Python sidecar automatically
cd apps/desktop && npm install && npm run dev
```

`npm run dev` passes `--dev` to Electron (cross-shell, works in `cmd.exe`/PowerShell as well as bash/zsh), which:

- Spawns `python -m uvicorn app.main:app` from `apps/api` instead of looking for
  the bundled binary. Set `RECONFORGE_PYTHON=/path/to/venv/bin/python` if your
  API isn't installed in the default `python` on PATH.
- Loads the BrowserWindow from `http://localhost:5173` (Vite dev) so HMR works.

The sidecar is started with:

- `RUNNER_MODE=embedded` — single-process worker, no Redis.
- `DATABASE_URL=sqlite:///~/.reconforge/reconforge.db` — per-user state.
- `ARTIFACT_BACKEND=local`, `ARTIFACT_DIR=~/.reconforge/artifacts`.
- `EXECUTION_MODE=dry_run`, `ALLOW_LIVE_EXECUTION=false` — safe defaults.
- CORS is **not** overridden — the API's default in `apps/api/app/core/config.py`
  already includes `app://reconforge` plus the vite-dev origins. A `.env`
  override still wins if you set one.

Override the home directory with `RECONFORGE_HOME=/some/path` if you want
isolation (e.g. for tests).

## Prod build

Two halves: the React bundle and the Python sidecar binary. Both need to exist
before Electron is packaged.

```bash
# 1. Web bundle with relative asset URLs (so app:// can serve them)
cd apps/desktop && npm run build:web

# 2. PyInstaller binary
cd apps/desktop && npm run build:sidecar
# (or directly: cd apps/api && ./scripts/build-sidecar.sh)
```

The sidecar binary lands at `apps/api/dist/reconforge-sidecar`. An
electron-builder config (Phase 4) will copy it into `resources/sidecar/` of the
installer; today, copy it manually if you want to test a prod-mode run:

```bash
mkdir -p apps/desktop/resources/sidecar
cp apps/api/dist/reconforge-sidecar apps/desktop/resources/sidecar/
cd apps/desktop && npm start
```

In prod mode, the main process:

- Spawns the binary from `process.resourcesPath/sidecar/`.
- Registers the `app://reconforge/` scheme and serves the bundled web assets
  from `apps/web/dist/`.

## File map

```
apps/desktop/
├── package.json              # Electron deps + npm scripts
├── README.md                 # this file
└── src/
    ├── main.js               # process orchestration, BrowserWindow, lifecycle
    ├── preload.js            # exposes window.__RECONFORGE_CONFIG__
    ├── protocol.js           # app://reconforge/ scheme + file handler
    └── sidecar.js            # spawn + health-check + kill

apps/api/
├── reconforge_sidecar.spec   # PyInstaller spec (--clean reproducible build)
└── scripts/
    ├── sidecar_entry.py      # binary entry point — invokes uvicorn as a lib
    └── build-sidecar.sh      # wrapper around `pyinstaller`
```

## What's not here

- **electron-builder** packaging (DMG/NSIS/AppImage) — Phase 4. The current
  setup runs unpackaged via `electron .` for development and manual testing.
- **Code signing / notarization** — Phase 4. Required for distribution on
  macOS and Windows.
- **Auto-update** — Phase 4. Probably `electron-updater` against a release
  channel.
- **Real tools (subfinder, nuclei, ...)** — these still need to be on the
  user's `PATH` for live runs. Dry-run mode (the default) is unaffected.
