"""Inc 8 E4 integrator probe for rulings RR-1/RR-2: the landing pane's measured geometry.

    pytest -p no:cacheprovider -q -s .dev-flow/2026-11-05-batch-103/inc-8/evidence-e4/integrator/landing_geometry_probe.py

Prints `GEO.*` lines per terminal size: the LANDS IN height (R-PE-DEF.1.1), its content width, the
strip's bytes per row (D5 f, derived from that width), the Inspector pane's visible content rows and
its scroll extent, the ledger table's height. Measurements only; no assertion.
"""
from __future__ import annotations

import asyncio

import pytest
from textual.widgets import Button, Input

from s19_app.tui.app import S19TuiApp
from tests.b97_fixtures import calib_hotfix, load_change_file, open_patch_editor
from tests.b97_probes import settle


@pytest.mark.parametrize("size", [(80, 24), (118, 53), (118, 54), (220, 60)])
def test_landing_geometry(tmp_path, size):
    async def drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            panel = await open_patch_editor(app, pilot)
            await load_change_file(app, pilot, panel, calib_hotfix(tmp_path))
            landing = panel.query_one("#patch_inspector")
            table = panel.query_one("#patch_doc_entries_table")
            out = {
                "landing.h": landing.region.height,
                "landing.content": tuple(landing.content_region.size),
                "table.h": table.region.height,
                "table.rows": table.row_count,
                "chips.h": panel.query_one("#patch_tab_script").region.height,
            }
            panel.query_one("#patch_tab_inspector").press()
            await settle(pilot, 3)
            pane = panel.query_one("#patch_pane_inspector")
            out["strip_bytes"] = panel._widths().strip_bytes
            out["pane.content"] = tuple(pane.content_region.size)
            out["pane.max_scroll_y"] = pane.max_scroll_y
            panel.query_one("#patch_entry_address_input", Input).value = "0xEB14"
            panel.query_one("#patch_entry_bytes_input", Input).value = " ".join(["5A"] * 256)
            panel.query_one("#patch_entry_add_button", Button).press()
            await settle(pilot, 4)
            pane.scroll_home(animate=False)
            await settle(pilot, 3)
            out["capped.card.h"] = panel.query_one("#patch_before_after_card").region.height
            out["capped.pane.max_scroll_y"] = pane.max_scroll_y
            top = pane.content_region.y
            out["capped.children"] = [
                (c.id, c.region.y - top, c.outer_size.height) for c in pane.children
            ]
            return out

    for key, value in asyncio.run(drive()).items():
        print(f"GEO.{size[0]}x{size[1]}.{key} = {value}")
