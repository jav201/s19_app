"""Inc 1b E5 WinCI round 2 (P-002): the A2L filter refresh after teardown.

R-COPY.26/1. WinCI run 43460552606 failed three clipboard nodes
intermittently: a paste or copy in ``#a2l_tags_filter_input`` changes its
value, the change schedules the 0.15 s filter debounce, and the debounce
came due while ``run_test`` was closing the app, so
``update_a2l_tags_view`` raised ``NoMatches '#a2l_tags_list'``.

The test takes the timing out: it captures the debounce callback that the
real input change schedules, lets the app close, and only then runs it.
"""

from __future__ import annotations

import asyncio

import pytest
from textual.css.query import NoMatches
from textual.widgets import DataTable, Input, Label

from s19_app.tui.app import S19TuiApp


def _capture_filter_debounce(app, monkeypatch) -> list:
    captured: list = []
    original = app.set_timer

    def spy(delay, callback=None, *args, **kwargs):
        if getattr(callback, "__name__", "") == "_apply_filter":
            captured.append(callback)
            return None
        return original(delay, callback, *args, **kwargs)

    monkeypatch.setattr(app, "set_timer", spy)
    return captured


def test_r_copy_26_1_filter_refresh_due_after_teardown_is_dropped(
    tmp_path, monkeypatch
) -> None:
    """R-COPY.26/1: a filter refresh due after the app closed raises nothing."""

    async def drive():
        app = S19TuiApp(base_dir=tmp_path)
        captured = _capture_filter_debounce(app, monkeypatch)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            app.action_show_screen("a2l")
            for _ in range(4):
                await pilot.pause()
            app.query_one("#a2l_tags_filter_input", Input).value = "KEEP"
            await pilot.pause()
            assert len(captured) == 1, "the input change did not schedule the filter debounce"
            captured[0]()
            await pilot.pause()
            live = str(app.query_one("#a2l_tags_summary", Label).render())
        return app, captured, live

    app, captured, live = asyncio.run(drive())
    # Positive arm: while the app runs, the same callback still refreshes.
    assert live == "No A2L tags match 'KEEP'.", live
    # The state of the WinCI failure: the app stopped and the table is gone.
    assert app.is_running is False
    with pytest.raises(NoMatches):
        app.query_one("#a2l_tags_list", DataTable)
    captured[0]()
