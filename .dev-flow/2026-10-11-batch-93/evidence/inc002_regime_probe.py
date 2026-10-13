# Panel-width vs terminal-width mapping probe (inc-002, HLR-131 threshold
# re-measurement, C-29 executed not copied). Reports the panel's measured width
# across the terminals around the candidate stack threshold, plus the stacked
# regime's row-widget inset at several stacked geometries.
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

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


async def one(width, height=30):
    app = S19TuiApp()
    async with app.run_test(size=(width, height)) as pilot:
        await pilot.pause()
        app.current_file = fixture()
        app.action_show_screen("map")
        await pilot.pause()
        app.update_memory_map()
        for _ in range(4):
            await pilot.pause()
        panel = app.query_one("#memory_map_panel")
        grid = app.query_one("#map_grid")
        rows = [c for c in app.query_one(".map-region-list").children]
        row_w = rows[0].region.width if rows else -1
        narrow = "width-narrow" in app.query_one("#workspace_body").classes
        print(f"term={width:3d}  panel={panel.size.width:3d}  "
              f"panel_h={panel.size.height:3d}  grid_content={grid.content_region.width:3d}  "
              f"row_widget={row_w:3d}  ws_narrow={narrow}")


print("--- around the candidate threshold (terminals 84..120) ---")
for w in list(range(84, 105, 2)) + [110, 113, 114, 115, 116, 117, 118, 119, 120]:
    asyncio.run(one(w))
print("--- stacked inset at stacked geometries ---")
for wh in [(80, 24), (80, 30), (90, 30), (94, 40), (60, 24)]:
    asyncio.run(one(*wh))
