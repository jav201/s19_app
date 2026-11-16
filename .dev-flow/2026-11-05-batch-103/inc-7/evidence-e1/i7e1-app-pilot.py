"""i7e1-app-pilot.py -- batch-103 Inc 7 E1: the real app on case 08, headless (throwaway; evidence).

Boots S19TuiApp (b103-inc7 = 2dbd7d5a) in run_test, loads case 08's firmware.s19 then firmware.a2l
through the shipped handlers, shows the A2L Explorer ("2") and prints, at 118x54 and 220x60:

  1  the column labels of the tag table and the text-mode cells of the 9 names of the G2 list that
     case 08 holds (the shipped cell builder), plus each tag's char_type / section / in_memory
  2  how many of the 462 tags each filter mode keeps, with no filter text
  3  the pane widths, the hex view's widest painted line after a jump to MAP_0003, and whether a hex
     line wraps today (PLAN backlog 5)
  4  what the filter box holds after a two-line text is typed into it as one value (no paste route)

No clipboard is read or written; HOME and XDG are isolated by the runner script.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(sys.argv[1]).resolve()
OUT = Path(sys.argv[2]).resolve()
sys.path.insert(0, str(REPO))

import s19_app  # noqa: E402

print("s19_app.__file__ =", s19_app.__file__)
print("repo HEAD =", subprocess.run(["git", "-C", str(REPO), "rev-parse", "--short=8", "HEAD"],
                                    capture_output=True, text=True).stdout.strip())

from textual.widgets import DataTable, Input  # noqa: E402

from tests.support import b100_projects as projects  # noqa: E402
from tests.support.b100_workers import settle_workers  # noqa: E402
from tests.support.timing import wait_until  # noqa: E402

CASE = OUT / "case08"
LIST9 = ["VALUE_0002", "CURVE_0001", "MAP_0003", "MEASUREMENT_0005", "VALUE_0042", "CURVE_0017",
         "MAP_0001", "MEASUREMENT_0012", "VALUE_0118"]


async def settle(pilot, n: int = 10) -> None:
    for _ in range(n):
        await pilot.pause()


def make_scenario(size):
    async def scenario(app, pilot, log):
        print(f"\n######## size {size[0]}x{size[1]}")
        app.load_selected_file(CASE / "firmware.s19")
        await wait_until(pilot, lambda: app.current_file is not None, "image load")
        app.load_a2l_from_path(CASE / "firmware.a2l")
        await settle_workers(pilot)
        await settle(pilot)
        app.set_focus(None)
        await pilot.press("2")
        await wait_until(pilot, lambda: app._active_screen_key == "a2l", "A2L Explorer")
        await settle(pilot)
        table = app.query_one("#a2l_tags_list", DataTable)
        print("=== 1. columns =", [str(c.label) for c in table.ordered_columns])
        print("   fixed_columns =", table.fixed_columns, "enriched tags =", len(app._a2l_enriched_tags),
              "a2l_view_generation =", app._a2l_view_generation)
        by_name = {t.get("name"): t for t in app._a2l_enriched_tags}
        for n in LIST9:
            t = by_name.get(n)
            cells = [c.plain for c in app._build_a2l_table_cells(t, None)]
            print(f"   {n}: char_type={t.get('char_type')!r} section={t.get('section')!r} "
                  f"in_memory={t.get('in_memory')!r} schema_ok={t.get('schema_ok', True)!r}")
            print(f"      cells = {cells[:9]}")
        print("=== 2. mode counts (no text)")
        saved = app.a2l_tags_filter_text
        app.a2l_tags_filter_text = ""
        for mode in ("all", "invalid", "inmem"):
            app.a2l_tags_filter_mode = mode
            print(f"   {mode}: {len(app._filter_a2l_tags(app._a2l_enriched_tags))}")
        app.a2l_tags_filter_mode = "all"
        app.a2l_tags_filter_text = saved
        print("=== 3. panes")
        for wid in ("#a2l_panes", "#a2l_tags_pane", "#a2l_hex_pane", "#a2l_detail_card", "#alt_hex_scroll",
                    "#alt_hex_view", "#a2l_tags_filters"):
            w = app.query_one(wid)
            print(f"   {wid}: region={tuple(w.region)} content={tuple(w.content_region)}")
        app._jump_to_tag_by_data(by_name["MAP_0003"])
        await settle(pilot)
        hexv = app.query_one("#alt_hex_view")
        painted = [strip.text for strip in hexv.render_lines(hexv.region.reset_offset)] if hexv.region.width else []
        widest = max((len(p.rstrip()) for p in painted), default=0)
        print(f"   hex view width = {hexv.content_region.width}; painted lines = {len(painted)}; widest = {widest}")
        for p in painted[:6]:
            print("   |" + p.rstrip())
        print("=== 4. filter box value after a two-line value is set")
        box = app.query_one("#a2l_tags_filter_input", Input)
        box.value = "VALUE_0002\nCURVE_0001"
        await settle(pilot)
        print("   value =", repr(box.value))
        return None
    return scenario


for size in ((118, 54), (220, 60)):
    base = OUT / f"app_{size[0]}"
    base.mkdir(parents=True, exist_ok=True)
    projects.run_app(base, make_scenario(size), size=size)
