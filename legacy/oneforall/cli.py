"""CLI entrypoint. Subcommands: run | s01 .. s10 | report | init-scope."""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from oneforall import STAGES
from oneforall.runner import normalize_stage_selector, run_pipeline, run_stage
from oneforall.workspace import Workspace


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="oneforall", description=__doc__)
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    # run: full pipeline
    pr = sub.add_parser("run", help="Run the 10-stage pipeline (or a subset)")
    pr.add_argument("-d", "--domain", required=True)
    pr.add_argument("--stages", help="comma-separated stage numbers or names, e.g. '1,2,3' or 's04_crawl'")
    pr.add_argument("--workspace", help="workspace base dir (default: ./workspace)")
    pr.add_argument("--i-have-authorization", action="store_true",
                    help="required to run active stages (s07_api, s09_vuln)")

    # init-scope: scaffold a scope.yaml
    pi = sub.add_parser("init-scope", help="Create an empty scope.yaml in the workspace")
    pi.add_argument("-d", "--domain", required=True)
    pi.add_argument("--workspace")

    # per-stage subcommands (s01_passive, s02_active, ...)
    for sid in STAGES:
        sp = sub.add_parser(sid, help=f"Run stage {sid}")
        sp.add_argument("-d", "--domain", required=True)
        sp.add_argument("--workspace")
        sp.add_argument("--i-have-authorization", action="store_true")

    # alias: short forms s1..s10 -> sNN_*
    for n, sid in enumerate(STAGES, start=1):
        short = f"s{n}"
        sp = sub.add_parser(short, help=f"Alias for {sid}")
        sp.add_argument("-d", "--domain", required=True)
        sp.add_argument("--workspace")
        sp.add_argument("--i-have-authorization", action="store_true")

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(args.verbose)

    base = Path(args.workspace) if getattr(args, "workspace", None) else None

    if args.cmd == "init-scope":
        ws = Workspace.for_target(args.domain, base=base)
        if ws.scope_path.exists():
            print(f"scope.yaml already exists at {ws.scope_path}")
            return 0
        ws.scope_path.write_text(
            "# Authorize targets you are permitted to test.\n"
            "# Required for stages s07_api and s09_vuln.\n"
            f"in:\n  - \"{args.domain}\"\n  - \"*.{args.domain}\"\nout: []\n"
        )
        print(f"created {ws.scope_path}")
        return 0

    ws = Workspace.for_target(args.domain, base=base)

    if args.cmd == "run":
        stages = normalize_stage_selector(args.stages)
        run_pipeline(ws, stages, authorized=args.i_have_authorization)
        return 0

    # individual stage
    if args.cmd in STAGES:
        run_stage(args.cmd, ws, authorized=args.i_have_authorization)
        return 0

    # short aliases s1..s10
    if args.cmd.startswith("s") and args.cmd[1:].isdigit():
        n = int(args.cmd[1:])
        run_stage(STAGES[n - 1], ws, authorized=args.i_have_authorization)
        return 0

    parser.error(f"unknown command: {args.cmd}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
