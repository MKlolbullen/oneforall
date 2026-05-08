"""Pipeline orchestrator: runs stages in order against a workspace."""
from __future__ import annotations

import importlib
import logging
import time

from oneforall import STAGES, GATED_STAGES
from oneforall.workspace import Workspace

logger = logging.getLogger(__name__)


def run_stage(stage_id: str, ws: Workspace, authorized: bool = False) -> None:
    """Dispatch to oneforall.stages.<stage_id>.run(ws, authorized)."""
    module = importlib.import_module(f"oneforall.stages.{stage_id}")
    t0 = time.time()
    logger.info("=== [%s] start ===", stage_id)
    module.run(ws, authorized=authorized)
    ws.mark_stage_done(stage_id)
    logger.info("=== [%s] done in %.1fs ===", stage_id, time.time() - t0)


def run_pipeline(ws: Workspace, stages: list[str], authorized: bool = False) -> None:
    for sid in stages:
        if sid in GATED_STAGES and not authorized:
            logger.warning("[%s] skipped (active stage; pass --i-have-authorization to enable)", sid)
            continue
        try:
            run_stage(sid, ws, authorized=authorized)
        except SystemExit:
            raise
        except Exception as e:
            logger.exception("[%s] failed: %s", sid, e)


def normalize_stage_selector(sel: str | None) -> list[str]:
    """`1,2,3` -> ['s01_passive', 's02_active', 's03_techscan']. None -> all."""
    if not sel:
        return list(STAGES)
    out = []
    for tok in sel.split(","):
        tok = tok.strip()
        if not tok:
            continue
        if tok.isdigit():
            n = int(tok)
            if not 1 <= n <= 10:
                raise ValueError(f"stage number out of range: {tok}")
            out.append(STAGES[n - 1])
        elif tok in STAGES:
            out.append(tok)
        else:
            # Allow shorthand like 's1' or 'passive'
            match = next((s for s in STAGES if s == tok or s.startswith(tok + "_")
                          or s.split("_", 1)[1] == tok), None)
            if not match:
                raise ValueError(f"unknown stage: {tok}")
            out.append(match)
    return out
