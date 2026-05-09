"""Authorization gate for active-probe stages (s07_api, s09_vuln)."""
from __future__ import annotations

import logging
import sys

from oneforall.workspace import Workspace

logger = logging.getLogger(__name__)

REFUSAL_MSG = (
    "REFUSED: this stage performs active probes against the target. "
    "Re-run with --i-have-authorization AND ensure scope.yaml exists in the workspace "
    "listing the in-scope hosts/IPs you are authorized to test."
)


def require_authorization(ws: Workspace, authorized: bool, stage_id: str) -> None:
    """Exit non-zero unless the user passed --i-have-authorization and a scope file exists."""
    scope = ws.load_scope()
    if not authorized or scope is None or not scope.get("in"):
        logger.error("[%s] %s", stage_id, REFUSAL_MSG)
        sys.exit(2)
    logger.info("[%s] authorization OK; in-scope: %s", stage_id, scope["in"])
