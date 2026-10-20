"""Batch-97 shared probes (design-proposal §5.1).

Inc-1 adds the open-folder chip helpers; the screen predicates
(``focus_method``, ``clipped_overflow``, ``span_colours`` …) arrive with Inc-3.
Every probe reads the shipped surface: the chip widget itself and the app's
status line (``S19TuiApp.log_lines``, the buffer ``#status_log`` paints).
"""
from __future__ import annotations

from typing import Optional

from s19_app.tui.open_folder_chip import OpenFolderChip

#: The terminal the chip tests run at: wide enough that a status line naming a
#: full ``tmp_path`` target is not clipped by the status cap (``app.py``
#: ``_append_log_line`` keeps ``max(50, width)`` cells).
CHIP_TEST_SIZE = (220, 60)


async def settle(pilot, rounds: int = 4) -> None:
    """Pump the event loop so a press or a mount has run its handlers."""
    for _ in range(rounds):
        await pilot.pause()


async def mount_chip(
    app, pilot, family: str, *, id_suffix: Optional[str] = None
) -> OpenFolderChip:
    """Mount a chip of ``family`` on the active screen and let it refresh.

    Used for the families no screen header carries yet (``flows`` and
    ``session`` land in the headers at Inc-5 / Inc-6) and for the
    ``id_suffix`` mechanism; the chip runs its own ``on_mount`` refresh.
    """
    if id_suffix is None:
        chip = OpenFolderChip(family)
    else:
        chip = OpenFolderChip(family, id_suffix=id_suffix)
    await app.screen.mount(chip)
    await settle(pilot)
    return chip


def last_status(app) -> str:
    """The newest status line the app painted."""
    return app.log_lines[-1] if app.log_lines else ""


def chip_label(chip: OpenFolderChip) -> str:
    """The chip's painted label as plain text."""
    return str(chip.label)
