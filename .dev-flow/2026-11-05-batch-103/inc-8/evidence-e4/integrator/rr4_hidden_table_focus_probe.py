"""Inc 8 E4 integrator probe for ruling RR-4: can the hidden picker table (R-PE-DEF.2) take focus?

    pytest -p no:cacheprovider -q -s .dev-flow/2026-11-05-batch-103/inc-8/evidence-e4/integrator/rr4_hidden_table_focus_probe.py

Prints `RR4.*` lines: whether `#patch_param_table` is displayed, in the screen's focus chain (what Tab
reaches), and focused after a programmatic `.focus()` (what tc_b102_pe_02 / r011 do).
"""
from __future__ import annotations

import asyncio

from s19_app.tui.app import S19TuiApp


def test_rr4_hidden_picker_table_focus(tmp_path):
    async def drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(118, 54)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            for _ in range(6):
                await pilot.pause()
            table = app.screen.query_one("#patch_param_table")
            displayed = table.display
            in_chain = table in app.screen.focus_chain
            table.focus()
            for _ in range(3):
                await pilot.pause()
            focused = app.focused is table
            tabbed = []
            for _ in range(40):
                await pilot.press("tab")
                tabbed.append(getattr(app.focused, "id", None))
            return displayed, in_chain, focused, "patch_param_table" in tabbed

    displayed, in_chain, focused, reached = asyncio.run(drive())
    print(f"RR4.table.display = {displayed}")
    print(f"RR4.table.in_focus_chain = {in_chain}")
    print(f"RR4.table.focused_after_programmatic_focus = {focused}")
    print(f"RR4.table.reached_by_40_tabs = {reached}")
