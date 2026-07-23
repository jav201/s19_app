"""Batch 1 (N6 + N7) — user-test polish fixes, black-box acceptance tests.

N6: pressing ``?`` a SECOND time must hide Textual's built-in ``HelpPanel``
(the stock ``show_help_panel`` action only mounts it, leaving no keyboard way to
dismiss it — so ``?`` was show-only, not a toggle).

N7: loading an A2L via the standalone ``load_a2l_from_path`` path must refresh
the top Workspace "Loaded" panel so the A2L filename appears WITHOUT a screen
switch (the merge path already refreshed; this orphaned path did not).

Both are driven through the real app surface (Textual ``Pilot``) over the public
``examples/case_01_basic_valid`` trio — asserting the observable result a user
sees, not an internal flag.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from textual.widgets import HelpPanel

from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens_directionb import LoadedArtifactsPanel

_CASE_01 = Path(__file__).resolve().parent.parent / "examples" / "case_01_basic_valid"
_CASE_01_S19 = _CASE_01 / "firmware.s19"
_CASE_01_A2L = _CASE_01 / "firmware.a2l"


# ---------------------------------------------------------------------------
# N6 — AC-N6-2: pressing `?` twice toggles the HelpPanel back off.
# (AC-N6-1 — first press mounts exactly one — is already pinned by
# test_discoverability.py::test_ac2_question_mark_opens_help_panel.)
# ---------------------------------------------------------------------------


def test_help_panel_toggle_hides_on_second_press(tmp_path: Path) -> None:
    """Press `?` -> one HelpPanel; press `?` again -> zero. RED pre-N6 (the
    stock show-only action left the panel mounted on the second press)."""

    async def _drive() -> tuple[int, int, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            start = len(app.query(HelpPanel))
            await pilot.press("question_mark")
            await pilot.pause()
            after_open = len(app.query(HelpPanel))
            await pilot.press("question_mark")
            await pilot.pause()
            after_toggle = len(app.query(HelpPanel))
            return start, after_open, after_toggle

    start, after_open, after_toggle = asyncio.run(_drive())
    assert start == 0, "no help panel before any `?`"
    assert after_open == 1, "first `?` must mount exactly one HelpPanel"
    assert after_toggle == 0, "second `?` must hide the HelpPanel (true toggle)"


# ---------------------------------------------------------------------------
# N7 — AC-N7-1: standalone A2L load shows the filename in the Loaded panel
# with NO screen switch.
# ---------------------------------------------------------------------------


def _a2l_slot_text(app: S19TuiApp) -> str:
    """The A2L slot readout of the mounted Loaded panel (``_SLOTS`` order is
    ``[primary, mac, a2l]`` — index 2). Reads the through-surface ``.loaded-detail``
    cell a user sees, not the underlying ``LoadedFile`` field."""
    panel = app.query_one("#loaded_panel", LoadedArtifactsPanel)
    cells = list(panel.query(".loaded-detail"))
    content = cells[2].render()
    return getattr(content, "plain", str(content))


def test_a2l_load_refreshes_loaded_panel_without_screen_switch(tmp_path: Path) -> None:
    """Load an S19 image, then load the A2L through the standalone
    ``load_a2l_from_path`` path, and assert the Loaded panel's A2L slot shows the
    filename with NO ``action_show_screen`` in between. RED pre-N7 (the slot
    stayed ``(none)`` until a screen switch refreshed the panel)."""

    async def _drive() -> tuple[str, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.load_selected_file(_CASE_01_S19)  # image only; no A2L merge
            await pilot.pause()
            before = _a2l_slot_text(app)
            app.load_a2l_from_path(_CASE_01_A2L)  # the orphaned load path
            await pilot.pause()
            after = _a2l_slot_text(app)
            return before, after

    before, after = asyncio.run(_drive())
    assert before == "(none)", "A2L slot must be empty before the A2L is loaded"
    assert after.startswith("firmware.a2l"), (
        "A2L slot must show the filename immediately after load_a2l_from_path, "
        f"with no screen switch; got {after!r}"
    )
