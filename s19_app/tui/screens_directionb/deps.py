"""s19_app.tui.screens_directionb.deps — test seam (D1) (moved verbatim from s19_app/tui/screens_directionb.py at 4f721985)."""
from __future__ import annotations

from datetime import datetime


def _json_clock() -> str:
    """The time a JSON view repaint is stamped with (D4; the tests' seam)."""
    return datetime.now().strftime("%H:%M:%S")
