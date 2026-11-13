"""i7e3r1-layout-pilot.py -- batch-103 Inc 7 E3R1: the A2L Explorer's vertical budget on base (throwaway; evidence).

Boots S19TuiApp (b103-inc7 at the E3 rulings, product tree = 2dbd7d5a) in run_test, loads case 08's
firmware.s19 then firmware.a2l, shows the A2L Explorer ("2") and prints, at 80x24, 120x30, 80x54, 118x54
and 160x40 (the sizes of E3A-10 and of the tc019 / tc016s tests):

  1  the region of #a2l_panes, #a2l_tags_pane and #a2l_hex_pane (the body the D-2 layout divides)
  2  every child of #a2l_tags_pane with its region height (the fixed lines above and below the table)
  3  the tag table's region height and how many body rows it shows (height - header)

The numbers size the E3A-10 fallback rows (R-A2L-LIST.088, .089). No clipboard is read or written;
HOME and XDG are isolated by the runner script.
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

from textual.widgets import DataTable  # noqa: E402

from tests.support import b100_projects as projects  # noqa: E402
from tests.support.b100_workers import settle_workers  # noqa: E402
from tests.support.timing import wait_until  # noqa: E402

CASE = OUT / "case08"
gen = subprocess.run([sys.executable, str(REPO / "tools/synth/make_release_case.py"), "--out", str(CASE),
                      "--seed", "20260001"], capture_output=True, text=True)
print("make_release_case rc =", gen.returncode)


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
        print("=== 1. body")
        for wid in ("#a2l_panes", "#a2l_tags_pane", "#a2l_hex_pane", "#a2l_detail_card", "#alt_hex_scroll"):
            w = app.query_one(wid)
            print(f"   {wid}: region={tuple(w.region)}")
        print("=== 2. children of #a2l_tags_pane (id, class, region height)")
        pane = app.query_one("#a2l_tags_pane")
        fixed = 0
        for child in pane.children:
            h = child.outer_size.height if child.display else 0
            print(f"   {child.id or '-'} {type(child).__name__} display={child.display} outer_h={h}")
            if not isinstance(child, DataTable):
                fixed += h
        print(f"   fixed lines (non-table children, outer) = {fixed}; pane outer height = {pane.outer_size.height}")
        table = app.query_one("#a2l_tags_list", DataTable)
        header = table.header_height if table.show_header else 0
        print("=== 3. table")
        print(f"   region={tuple(table.region)} header={header} body rows shown={max(0, table.region.height - header)}"
              f" row_count={table.row_count}")
        return None
    return scenario


for size in ((80, 24), (120, 30), (80, 54), (118, 54), (160, 40)):
    base = OUT / f"lay_{size[0]}x{size[1]}"
    base.mkdir(parents=True, exist_ok=True)
    projects.run_app(base, make_scenario(size), size=size)
