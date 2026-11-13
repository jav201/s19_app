"""i7e3r2-layout-pilot.py -- batch-103 Inc 7 E3R2: R-A2L-LIST.083's table rows with option (a) of E3A-R1 (throwaway; evidence).

No Inc 7 code exists yet, so this builds the pinned tags pane at run time in the real app (b103-inc7, product tree =
2dbd7d5a), changing no file: after the A2L Explorer is shown it mounts, as `_compose_screen_a2l` pins them after E3R2,

  - into the base filter row `#a2l_tags_filters` (which keeps the find box and its three buttons, option (a)):
    the mode tag Label (`FILTER` / `LIST`) before the filter box and the `Paste list…  alt+p` Button after it;
  - under that row: a Static `#a2l_list_chips` with the rows' texts (list mode: counts line, order line, mode line;
    text mode: the TEXT line and the mode line) and a Static `#a2l_list_missing` (list mode only).

At 118x54 the stacked body's rules of [Config] are applied inline (`#a2l_panes` vertical, tags pane 100% x 1fr,
hex pane 100% x 14). The chips Static is measured two ways: `wrap` (a Static's default: long lines wrap at the pane
width) and `clip` (one screen line per text line: height = the line count, overflow hidden). It prints the tag
table's body rows for each size, mode and way. HOME and XDG are isolated by the runner script; no clipboard.
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

from textual.widgets import Button, DataTable, Label, Static  # noqa: E402

from tests.support import b100_projects as projects  # noqa: E402
from tests.support.b100_workers import settle_workers  # noqa: E402
from tests.support.timing import wait_until  # noqa: E402

CASE = OUT / "case08"
if not (CASE / "firmware.a2l").exists():
    gen = subprocess.run([sys.executable, str(REPO / "tools/synth/make_release_case.py"), "--out", str(CASE),
                          "--seed", "20260001"], capture_output=True, text=True)
    print("make_release_case rc =", gen.returncode)

LIST_CHIPS = [
    " LIST   12 pasted  ·  ● 9 found  ·  ✗ 2 missing  ·  = 1 duplicate",
    "order ● ● ● ● ● ● ✗ ● ● = ✗ ●    field ignored in LIST mode · esc back to text filter · alt+p edit the list",
    "mode All · no tag hidden by mode (462 tags)",
]
TEXT_CHIPS = [
    " TEXT   no text filter  ·  showing 462 of 462   paste several names, or alt+p, to filter by a LIST",
    "mode All · no tag hidden by mode (462 tags)",
]
MISSING = "Missing 2 ▸ #7 MAP_0024 · #11 CURVE_0071    Duplicates 1 ▸ #10 VALUE_0002 (= #1)"


async def settle(pilot, n: int = 10) -> None:
    for _ in range(n):
        await pilot.pause()


def make_scenario(size, stacked):
    async def scenario(app, pilot, log):
        print(f"\n######## size {size[0]}x{size[1]} ({'stacked [Config] inline' if stacked else 'base split'})")
        app.load_selected_file(CASE / "firmware.s19")
        await wait_until(pilot, lambda: app.current_file is not None, "image load")
        app.load_a2l_from_path(CASE / "firmware.a2l")
        await settle_workers(pilot)
        await settle(pilot)
        app.set_focus(None)
        await pilot.press("2")
        await wait_until(pilot, lambda: app._active_screen_key == "a2l", "A2L Explorer")
        await settle(pilot)
        if stacked:
            app.query_one("#a2l_panes").styles.layout = "vertical"
            tags_pane = app.query_one("#a2l_tags_pane")
            tags_pane.styles.width = "100%"
            tags_pane.styles.height = "1fr"
            hex_pane = app.query_one("#a2l_hex_pane")
            hex_pane.styles.width = "100%"
            hex_pane.styles.height = 14
        filters = app.query_one("#a2l_tags_filters")
        box = app.query_one("#a2l_tags_filter_input")
        await filters.mount(Label("FILTER", id="zq_mode_tag"), before=box)
        await filters.mount(Button("Paste list…  alt+p", id="zq_paste_list"), after=box)
        chips = Static("", id="zq_list_chips", markup=False)
        missing = Static(MISSING, id="zq_list_missing", markup=False)
        await app.query_one("#a2l_tags_pane").mount(chips, missing, after=filters)
        await settle(pilot)
        for c in ("#a2l_panes", "#a2l_tags_pane", "#a2l_hex_pane"):
            print(f"   {c}: region={tuple(app.query_one(c).region)}")
        print(f"   #a2l_tags_filters outer_h={filters.outer_size.height} (find box and buttons kept in it: "
              f"{app.query_one('#a2l_tag_find_input').parent is filters})")
        table = app.query_one("#a2l_tags_list", DataTable)
        for mode, lines in (("list", LIST_CHIPS), ("text", TEXT_CHIPS)):
            for way in ("wrap", "clip"):
                chips.update("\n".join(lines))
                if way == "clip":
                    chips.styles.height = len(lines)
                    chips.styles.overflow_x = "hidden"
                    chips.styles.overflow_y = "hidden"
                    chips.styles.text_wrap = "nowrap"
                else:
                    chips.styles.height = "auto"
                    chips.styles.text_wrap = "wrap"
                missing.display = mode == "list"
                missing.styles.height = 1 if way == "clip" else "auto"
                await settle(pilot)
                header = table.header_height if table.show_header else 0
                fixed = sum(ch.outer_size.height for ch in app.query_one("#a2l_tags_pane").children
                            if ch.display and ch is not table)
                print(f"   {mode:4} {way}: chips_h={chips.outer_size.height} missing_h="
                      f"{missing.outer_size.height if missing.display else 0} fixed={fixed} "
                      f"table_region_h={table.region.height} body rows shown={max(0, table.region.height - header)}")
        return None
    return scenario


for size, stacked in (((120, 30), False), ((160, 40), False), ((118, 54), True)):
    base = OUT / f"lay2_{size[0]}x{size[1]}"
    base.mkdir(parents=True, exist_ok=True)
    projects.run_app(base, make_scenario(size, stacked), size=size)
