"""Discoverability affordances (prior-backlog field-audit gap).

The app had 24 of 27 bindings footer-invisible and no help surface. This batch
adds two additive affordances:
- `?` opens Textual's built-in help panel, which lists EVERY active binding, so
  the many `show=False` keys become learnable from the UI.
- the A2L screen gains the on-screen `Legend` button that MAC and Issues already
  have (parity), routed to the shared `action_show_legend`.
"""

import asyncio
from pathlib import Path

from textual.binding import Binding
from textual.widgets import Button, HelpPanel

from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens import LegendScreen


# ---------------------------------------------------------------------------
# AC-1 — a footer-visible `?` -> show_help_panel binding exists.
# ---------------------------------------------------------------------------


def test_ac1_help_binding_is_present_and_visible() -> None:
    help_bindings = [
        b
        for b in S19TuiApp.BINDINGS
        if isinstance(b, Binding) and b.action == "show_help_panel"
    ]

    assert help_bindings, "no binding routes to Textual's built-in help panel"
    binding = help_bindings[0]
    assert binding.key == "question_mark", f"help must be on '?'; got {binding.key!r}"
    assert binding.show is True, "the help binding must be Footer-visible (show=True)"
    assert binding.description == "Help"


# ---------------------------------------------------------------------------
# AC-2 — pressing `?` mounts the built-in HelpPanel (all bindings listed).
# ---------------------------------------------------------------------------


def test_ac2_question_mark_opens_help_panel(tmp_path: Path) -> None:
    async def _drive() -> "tuple[int, int]":
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            before = len(app.query(HelpPanel))
            await pilot.press("question_mark")
            await pilot.pause()
            after = len(app.query(HelpPanel))
            return before, after

    before, after = asyncio.run(_drive())
    assert before == 0, "help panel must not be mounted before '?'"
    assert after == 1, "pressing '?' must mount Textual's HelpPanel (lists all bindings)"


# ---------------------------------------------------------------------------
# AC-3 — the A2L screen has a Legend button that opens the LegendScreen.
# ---------------------------------------------------------------------------


def test_ac3_a2l_has_legend_button_that_opens_legend(tmp_path: Path) -> None:
    async def _drive() -> "tuple[bool, bool]":
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("a2l")
            await pilot.pause()
            buttons = app.query("#a2l_legend_button")
            present = len(buttons) == 1
            if present:
                buttons.first(Button).press()
                await pilot.pause()
            pushed = isinstance(app.screen, LegendScreen)
            return present, pushed

    present, pushed = asyncio.run(_drive())
    assert present, "the A2L screen must render #a2l_legend_button (parity with MAC/Issues)"
    assert pushed, "pressing the A2L Legend button must push LegendScreen"
