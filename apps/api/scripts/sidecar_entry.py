"""Sidecar entry point for the PyInstaller-bundled binary.

`python -m uvicorn app.main:app` doesn't survive PyInstaller's import analysis
cleanly because the `-m` flow re-executes the interpreter. Invoking uvicorn as
a library is the supported path. Accepts ``--host``/``--port`` from argv so
Electron can hand the sidecar a free port chosen at app start.
"""
from __future__ import annotations

import argparse
import sys


def main() -> int:
    parser = argparse.ArgumentParser(prog="reconforge-sidecar")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    # Import lazily so --help works without paying for the full app graph.
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=args.host,
        port=args.port,
        log_level="info",
        access_log=False,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
