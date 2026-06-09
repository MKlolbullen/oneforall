# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the ReconForge desktop sidecar.

Builds a self-contained ``reconforge-sidecar`` binary that the Electron shell
spawns. From ``apps/api``:

    pyinstaller --clean --noconfirm reconforge_sidecar.spec

The output ``dist/reconforge-sidecar`` (``.exe`` on Windows) is what
``electron-builder`` (or ``scripts/build-sidecar.sh``) copies into the desktop
app's ``resources/sidecar/`` directory.
"""
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules


API_DIR = Path(SPECPATH).resolve()  # apps/api  # noqa: F821 - SPECPATH provided by PyInstaller

datas = []

# Alembic migration tree — read at runtime from the on-disk versions/
# directory. PyInstaller needs them as data files, not pure modules.
alembic_dir = API_DIR / "alembic"
if alembic_dir.exists():
    datas += [(str(alembic_dir / "versions"), "alembic/versions")]
    datas += [(str(alembic_dir / "env.py"), "alembic")]
    datas += [(str(alembic_dir / "script.py.mako"), "alembic")]
    datas += [(str(API_DIR / "alembic.ini"), ".")]

# Anything `app` imports as data (templates, yaml fixtures…).
datas += collect_data_files("app")

hiddenimports = [
    # uvicorn picks loop/http/ws backends via runtime import; PyInstaller's
    # static analysis misses these.
    "uvicorn.loops.asyncio",
    "uvicorn.protocols.http.h11_impl",
    "uvicorn.protocols.websockets.wsproto_impl",
    "uvicorn.lifespan.on",
    # Alembic env.py is invoked through importlib.
    "alembic.runtime.migration",
    "alembic.runtime.environment",
    # The desktop build uses SQLite; bundle the dialect even if installed
    # SQLAlchemy can resolve it itself.
    "sqlalchemy.dialects.sqlite",
]
# Every `app.*` submodule, so routes/services aren't dropped.
hiddenimports += collect_submodules("app")

a = Analysis(  # noqa: F821 - Analysis provided by PyInstaller
    [str(API_DIR / "scripts" / "sidecar_entry.py")],
    pathex=[str(API_DIR)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
)
pyz = PYZ(a.pure)  # noqa: F821
exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="reconforge-sidecar",
    console=True,           # surface logs so Electron's stdio pipe sees them
    strip=False,
    upx=False,
    debug=False,
)
