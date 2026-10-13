"""Throwaway probe (inc-003): smoke-test the map spec sheet + measure the
80x24 floor budget. Deleted after the measurements are taken."""

from __future__ import annotations

import asyncio
from pathlib import Path

from rich.cells import cell_len
from textual.widgets import Static

from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens import LegendScreen


async def _probe(size, base: Path, out) -> None:
    app = S19TuiApp(base_dir=base)
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        app.action_show_screen("map")
        await pilot.pause()
        app.action_show_legend()
        await pilot.pause()
        assert isinstance(app.screen, LegendScreen)
        legend = app.screen
        dialog = legend.query_one("#legend_dialog")
        body = legend.query_one("#legend_body")
        print(f"== {size}: dialog {dialog.region.width}x{dialog.region.height}, "
              f"body {body.region.width}x{body.region.height}", file=out)
        for box in legend.query(".legend-sheet-box"):
            title = box.border_title
            over = cell_len(title) > box.region.width
            print(f"  box {title!r}: box_w={box.region.width} title_cells={cell_len(title)}{' OVER' if over else ''}", file=out)
            for line in box.query(Static):
                plain = line.render().plain
                w = line.region.width
                h = line.region.height
                flag = ""
                if cell_len(plain) > w or h != 1:
                    flag = f"  <<< WRAP cells={cell_len(plain)} h={h}"
                print(f"    [{h}] ({cell_len(plain):>3} vs {w:>3}) {plain!r}{flag}", file=out)
        # Esc dismissal
        await pilot.press("escape")
        await pilot.pause()
        print("  after Esc:", type(app.screen).__name__, file=out)


def main() -> None:
    base = Path(".dev-flow/2026-10-11-batch-93/evidence/inc003_probe_base")
    base.mkdir(parents=True, exist_ok=True)
    dest = Path(".dev-flow/2026-10-11-batch-93/evidence/inc003_sheet_probe.out.txt")
    with dest.open("w", encoding="utf-8") as out:
        asyncio.run(_probe((120, 36), base, out))
        asyncio.run(_probe((80, 24), base, out))
    print("written", dest)


if __name__ == "__main__":
    main()
