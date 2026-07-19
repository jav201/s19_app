"""Discoverability affordances (prior-backlog field-audit gap).

The app had 24 of 27 bindings footer-invisible and no help surface. This batch
adds a footer-visible `?` binding that opens Textual's built-in help panel, which
lists EVERY active binding — so the many `show=False` keys (rails, save/load
project, dump-JSON, before/after report, undo/redo, paging) become learnable from
the UI at every terminal width.

(An A2L on-screen Legend button was considered for MAC/Issues parity but dropped:
it clips off-screen at 80 cols — the deliberate C-13 decision, see
`test_tui_legend.py::test_at023e_c13_geometry_at_80_cols` — and is redundant, as
the A2L legend is already reachable via the footer-visible `k` key, which the help
panel now surfaces at all widths.)
"""

import asyncio
from pathlib import Path

from textual.binding import Binding
from textual.widgets import HelpPanel

from s19_app.tui.app import S19TuiApp


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
