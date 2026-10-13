# P3 render check for batch-93 increment 001 — drives the shipped map screen
# at the charter geometries and reports the cockpit layout facts (pane chrome,
# left-pane stack, row offsets, peek rows, stats form). Throwaway evidence
# tooling; not part of the suite.
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from s19_app.tui import app as app_mod
from s19_app.tui.app import S19TuiApp
from s19_app.tui.models import LoadedFile
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


async def one(size):
    app = S19TuiApp()
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        app.current_file = fixture()
        await pilot.press("4")
        await pilot.pause()
        app.update_memory_map()
        for _ in range(4):
            await pilot.pause()
        grid = app.query_one("#map_grid")
        detail = app.query_one("#map_detail")
        print(f"=== {size[0]}x{size[1]}")
        print(f"  map pane   : title={grid.border_title!r} sub={grid.border_subtitle!r} "
              f"region={grid.region}")
        print(f"  inspector  : title={detail.border_title!r} sub={detail.border_subtitle!r} "
              f"region={detail.region}")
        kids = [type(c).__name__ for c in grid.children]
        print(f"  left stack : {kids}")
        scroll = app.query_one(".map-region-scroll")
        rows = scroll.query(".map-region-list RegionRow") if False else \
            [c for c in app.query_one(".map-region-list").children]
        print(f"  rows       : {len(rows)}  scroll_viewport={scroll.region} "
              f"scrollable={scroll.is_scrollable}")
        for r in rows[:3]:
            print(f"    row {r.region_start:08X}: {str(r.render())!r}")
        chips = app.query_one(".map-glance-chips")
        print(f"  chips      : {[str(c.render()) for c in chips.children]}")
        body = app.query_one("#map_detail_body").render().plain
        print("  inspector body:")
        for ln in body.splitlines():
            print(f"    |{ln}")
        stats = app.query_one("#map_stats_body").render().plain
        print(f"  stats({len(stats)} cells): {stats!r}")
        sw = app.query_one("#map_stats_body").region.width
        print(f"  stats widget width={sw}")
        panel = app.query_one("#memory_map_panel")
        print(f"  panel size={panel.size}  rows avail -> "
              f"{panel.size.width - 51} (inset 51)")


for size in [(100, 30), (120, 36), (160, 48)]:
    asyncio.run(one(size))
