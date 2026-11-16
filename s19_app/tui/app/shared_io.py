"""s19_app.tui.app.shared_io — shared helpers that read the D1 seam (moved verbatim from s19_app/tui/app.py at 4f721985)."""
from __future__ import annotations

from typing import Optional
from ..services.project_gather_service import PLAN_ACTION_KEEP, PLAN_ACTION_NEW, SavePlanRow
from ..workspace import PlacementResult
from . import deps


def _plan_row_mismatch(row: SavePlanRow, placed: PlacementResult) -> Optional[str]:
    """
    Summary:
        Check one landed placement against its plan row (LLR-163.7,
        LLR-167.6): a different path, or a reuse the plan did not predict
        (or the reverse), is an error naming both paths — never silent.

    Args:
        row (SavePlanRow): The planned row.
        placed (PlacementResult): Where the placement landed.

    Returns:
        Optional[str]: The refusal line, or ``None`` when they agree.
    """
    same_path = deps.os.path.normcase(str(placed.path)) == deps.os.path.normcase(
        str(row.landing)
    )
    if same_path and placed.reused == (row.action == PLAN_ACTION_KEEP):
        return None
    landed_action = PLAN_ACTION_KEEP if placed.reused else PLAN_ACTION_NEW
    return (
        f"Project NOT saved: the plan named {row.landing} ({row.action}) "
        f"but the file landed at {placed.path} ({landed_action}) — save again."
    )
