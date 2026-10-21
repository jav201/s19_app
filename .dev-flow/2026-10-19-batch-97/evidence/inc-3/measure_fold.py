"""Inc-3 gate fold: measure the Fields pane budget and paint the card (headless)."""
import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path.cwd()))
from s19_app.tui.app import S19TuiApp  # noqa: E402
from tests.b97_fixtures import DEMO_A2L, open_check_editor  # noqa: E402
from tests.b97_probes import blank_panel_rows, painted_rows, settle  # noqa: E402


async def measure(size, scenario):
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        app = S19TuiApp(base_dir=Path(tmp))
        async with app.run_test(size=size) as pilot:
            panel = await open_check_editor(app, pilot, a2l=DEMO_A2L)
            if scenario == "ce_A":
                panel.load_spec(
                    [{"address": a, "size": s} for a, s in ((0xEB10, 4), (0xEB40, 4), (0xED00, 2), (0xFCB0, 2))],
                    "baseline.chk.json",
                )
                await settle(pilot, 2)
                table = panel.query_one("#check_param_table")
                for row in (1, 4):
                    table.move_cursor(row=row)
                    await settle(pilot, 1)
                    panel.query_one("#check_param_include_button").press()
                    await settle(pilot, 2)
            await settle(pilot, 3)
            pane = panel.query_one("#check_pane_fields")
            used = pane.virtual_size.height
            rows = painted_rows(app, pane)
            last = max(i for i, r in enumerate(rows) if r.strip())
            empty_below = len(rows) - 1 - last
            blanks = blank_panel_rows(app, panel, outside=panel.query_one("#check_param_table"))
            full = painted_rows(app, panel.query_one("#check_full_name_line"))[0].strip()
            status = painted_rows(app, panel.query_one("#check_status"))[0].strip()
            print(f"== {size} {scenario}: panel H {panel.region.height}, switcher {panel.query_one('#check_card_switcher').region.height}, "
                  f"empty rows under the status line {empty_below}, full-width blank panel rows {blanks}")
            print(f"   full-name line: {full!r}  (content width {panel.query_one('#check_full_name_line').content_region.width}, layout {panel._layout.full_name})")
            print(f"   status: {status!r} width {panel.query_one('#check_status').content_region.width}")
            if size == (118, 54):
                for r in rows[: last + 1]:
                    print("   |" + r)


async def main():
    for size in ((118, 54), (118, 53), (220, 60), (220, 59)):
        for scenario in ("ce_A", "empty"):
            await measure(size, scenario)


asyncio.run(main())
