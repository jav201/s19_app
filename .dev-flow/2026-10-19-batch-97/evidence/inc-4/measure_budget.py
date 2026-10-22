"""Inc-4 PC-24: the Patch Editor's vertical budget, measured on the real tree.

Run from the repo root:  python measure_budget.py > budget.txt
At 118x54, 118x53, 220x60 and 220x59, with prg.s19 + calib_hotfix.json loaded
and ledger row #3 highlighted (the design §3 scenario), prints each region's
painted height and the empty rows at the foot of the Inspector pane; then the
JSON tab's view / paste heights, plain and with the save-back prompt and the
before/after report offered (Apply, then Write file).
"""
import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path.cwd()))

from s19_app.tui.app import S19TuiApp  # noqa: E402
from tests.b97_fixtures import calib_hotfix, load_change_file, open_patch_editor  # noqa: E402
from tests.b97_probes import painted_rows, settle  # noqa: E402


async def measure(size):
    tmp = Path(tempfile.mkdtemp())
    app = S19TuiApp(base_dir=tmp)
    async with app.run_test(size=size) as pilot:
        panel = await open_patch_editor(app, pilot)
        await load_change_file(app, pilot, panel, calib_hotfix(tmp))
        table = panel.query_one("#patch_doc_entries_table")
        table.move_cursor(row=2)
        await settle(pilot, 4)
        q = lambda i: panel.query_one(f"#{i}").region  # noqa: E731
        pane = panel.query_one("#patch_pane_inspector")
        rows = painted_rows(app, pane)
        used = max((i for i, r in enumerate(rows) if r.strip()), default=-1) + 1
        print(f"== {size[0]}x{size[1]}  panel H {panel.region.height}")
        for wid in ("patch_identity_ribbon", "patch_main", "patch_doc_entries_table",
                    "patch_tab_switcher", "patch_before_after_card", "patch_doc_entry_inputs",
                    "patch_doc_entry_buttons", "patch_doc_tally", "patch_doc_file_row",
                    "patch_doc_controls", "patch_legend"):
            r = q(wid)
            print(f"   {wid:26s} y={r.y:3d} h={r.height}")
        print(f"   Inspector pane: {pane.region.height} rows, {used} used, {pane.region.height - used} empty at the foot")
        panel.query_one("#patch_tab_json").press()
        await settle(pilot, 3)
        print(f"   JSON tab: view {q('patch_json_view').height} · paste text {q('patch_paste_text').height}")
        panel.query_one("#patch_doc_apply_button").press()
        await settle(pilot, 6)
        panel.query_one("#patch_saveback_confirm_button").press()
        await settle(pilot, 6)
        panel.query_one("#patch_doc_apply_button").press()
        await settle(pilot, 6)
        offered = (not panel.query_one("#patch_saveback_row").has_class("hidden"),
                   not panel.query_one("#patch_before_after_row").has_class("hidden"))
        json_tab = panel.query_one("#patch_win_json")
        print(f"   JSON tab with save-back + report offered {offered}: view {q('patch_json_view').height}"
              f" · paste text {q('patch_paste_text').height} · tab scroll max {json_tab.max_scroll_y}")


async def main():
    for size in ((118, 54), (118, 53), (220, 60), (220, 59)):
        await measure(size)


asyncio.run(main())
