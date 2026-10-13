# Boundary + resize probe for batch-93 inc-002 (HLR-131 arms).
# (a) regime at terminals 95/96/97/98 (panel 83/84/85/86): exactly-at vs
#     one-below/one-above the recorded _MAP_STACK_MIN_WIDTH=86.
# (b) a live resize across the boundary AND across the microbar threshold:
#     rows/peek/bar must re-apportion to the then-measured width (0 stale).
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from rich.cells import cell_len

from s19_app.tui.app import S19TuiApp
from s19_app.tui.models import LoadedFile
from s19_app.tui.screens_directionb import (
    BandSegment,
    _MAP_STACK_MIN_WIDTH,
)
from s19_app.tui.services.entropy_service import compute_entropy


def _lcg_bytes(seed, n):
    out, state = [], seed
    for _ in range(n):
        state = (state * 1103515245 + 12345) & 0x7FFFFFFF
        out.append((state >> 16) & 0xFF)
    return out


def fixture():
    mem = {}

    def put(addr, data):
        for i, v in enumerate(data):
            mem[addr + i] = v

    put(0x00000000, [(0x08, 0x00, 0x10 + (i % 8), 0x00)[i % 4] for i in range(0x100)])
    put(0x08000000, [(i // 4) & 0xFF for i in range(0x800)])
    put(0x08001000, _lcg_bytes(0xC0FFEE, 0x600))
    put(0x08002000, [0xFF] * 0x400)
    put(0x1FFF0000, [(0x30 + (i * 7) % 60) for i in range(0x200)])
    ranges = [
        (0x00000000, 0x00000100),
        (0x08000000, 0x08000800),
        (0x08001000, 0x08001600),
        (0x08002000, 0x08002400),
        (0x1FFF0000, 0x1FFF0200),
    ]
    return LoadedFile(
        path=Path("ecu_fw_v3.s19"), file_type="s19", mem_map=mem,
        row_bases=sorted({a - a % 16 for a in mem}), ranges=ranges,
        range_validity=[True] * len(ranges), errors=[],
        a2l_path=None, a2l_data=None, entropy_windows=compute_entropy(mem),
    )


def regime_facts(app, panel):
    grid = app.query_one("#map_grid")
    detail = app.query_one("#map_detail")
    rows = [c for c in app.query_one(".map-region-list").children]
    first = str(rows[0].render()) if rows else ""
    body = app.query_one("#map_detail_body").render().plain
    peek_rows = 0
    lines = body.splitlines()
    if "Peek" in lines:
        peek_rows = len(lines) - lines.index("Peek") - 1
    bar = app.query_one(".map-band-bar")
    seg_over = []
    for seg in bar.query(BandSegment):
        w = seg.region.width
        cells = cell_len(str(seg.render()))
        if w > 0 and cells > w:
            seg_over.append((cells, w))
    return {
        "panel_w": panel.size.width,
        "stacked": panel.has_class("width-narrow"),
        "side_by_side": detail.region.y == grid.region.y
        and detail.region.x > grid.region.x,
        "row_cells": cell_len(first),
        "row_widget": rows[0].region.width if rows else -1,
        "peek_rows": peek_rows,
        "bar_w": bar.region.width,
        "seg_overflow": seg_over,
    }


async def boundary(width, height=30):
    app = S19TuiApp()
    async with app.run_test(size=(width, height)) as pilot:
        await pilot.pause()
        app.current_file = fixture()
        app.action_show_screen("map")
        await pilot.pause()
        app.update_memory_map()
        for _ in range(5):
            await pilot.pause()
        panel = app.query_one("#memory_map_panel")
        f = regime_facts(app, panel)
        verdict = "STACKED" if f["stacked"] else "SIDE-BY-SIDE"
        ok = f["stacked"] == (f["panel_w"] < _MAP_STACK_MIN_WIDTH)
        print(f"term={width:3d} panel={f['panel_w']:3d} -> {verdict:12s} "
              f"sbs={f['side_by_side']} row={f['row_cells']}c/{f['row_widget']}w "
              f"peek={f['peek_rows']} bar={f['bar_w']} over={f['seg_overflow']} "
              f"LAW={'OK' if ok else 'VIOLATED'}")


async def resize_drive():
    app = S19TuiApp()
    async with app.run_test(size=(160, 48)) as pilot:
        await pilot.pause()
        app.current_file = fixture()
        app.action_show_screen("map")
        await pilot.pause()
        app.update_memory_map()
        for _ in range(5):
            await pilot.pause()
        panel = app.query_one("#memory_map_panel")
        before = regime_facts(app, panel)
        print(f"BEFORE 160x48: {before}")
        # Cross BOTH the stack threshold and the microbar threshold downward.
        await pilot.resize_terminal(120, 36)
        for _ in range(6):
            await pilot.pause()
        mid = regime_facts(app, panel)
        print(f"AFTER  ->120x36: {mid}")
        # And back up across the stack threshold.
        await pilot.resize_terminal(96, 30)
        for _ in range(6):
            await pilot.pause()
        low = regime_facts(app, panel)
        print(f"AFTER  -> 96x30: {low}")
        await pilot.resize_terminal(160, 48)
        for _ in range(6):
            await pilot.pause()
        high = regime_facts(app, panel)
        print(f"AFTER  ->160x48: {high}")


print("--- boundary arms (threshold 86; term = panel + 12) ---")
for w in (95, 96, 97, 98):
    asyncio.run(boundary(w))
print("--- live resize across the thresholds ---")
asyncio.run(resize_drive())
