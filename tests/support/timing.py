"""Timing bounds for wall-clock assertions (batch-100 Inc 8b E5 corrective
pass 1, LED .80).

The requirements state their time bounds for the local machine (1 s). Shared
CI runners are slower and noisier: Inc 7 and Inc 8a "< 1 s" nodes failed on
Linux CI only. ``timing_bound`` keeps the requirement's number locally and
doubles it when the ``CI`` environment variable is truthy, so a CI run checks
the same order of magnitude without flaking on runner load.
"""
from __future__ import annotations

import os

#: The factor a CI run applies to a requirement's local time bound.
CI_TIMING_FACTOR = 2


def timing_bound(seconds: float) -> float:
    """``seconds`` locally; ``seconds * CI_TIMING_FACTOR`` when env ``CI`` is
    truthy (set, and not "", "0", "false" or "no", any case)."""
    value = os.environ.get("CI", "").strip().lower()
    if value in ("", "0", "false", "no"):
        return seconds
    return seconds * CI_TIMING_FACTOR
