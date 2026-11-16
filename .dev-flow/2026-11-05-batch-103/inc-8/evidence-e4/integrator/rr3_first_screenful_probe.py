"""Inc 8 E4 integrator probe for ruling RR-3 (`test_at064b`): what the first screenful shows at 120x30.

    pytest -p no:cacheprovider -q -s .dev-flow/2026-11-05-batch-103/inc-8/evidence-e4/integrator/rr3_first_screenful_probe.py

Prints `RR3.*` lines: the panel's visible content rows at scroll 0, and each region's top/bottom row
(R-TUI-063.1 order) relative to the panel's content top, with the Inspector tab shown. Measurements only.
"""
from __future__ import annotations

import asyncio

from s19_app.tui.app import S19TuiApp

REGIONS = (
    "patch_filter_row",
    "patch_sheet_win",
    "patch_inspector",
    "patch_doc_file_row",
    "patch_doc_controls",
    "patch_legend",
    "patch_doc_entry_buttons",
)


def test_rr3_first_screenful_at_120x30(tmp_path):
    async def drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            for _ in range(6):
                await pilot.pause()
            panel = app.query_one("#patch_editor_panel")
            app.query_one("#patch_tab_inspector").press()
            for _ in range(3):
                await pilot.pause()
            top = panel.content_region.y
            out = {"panel.visible_rows": panel.content_region.height, "panel.max_scroll_y": panel.max_scroll_y}
            for rid in REGIONS:
                region = app.query_one(f"#{rid}").region
                out[rid] = (region.y - top, region.bottom - top)
            return out

    for key, value in asyncio.run(drive()).items():
        print(f"RR3.120x30.{key} = {value}")
