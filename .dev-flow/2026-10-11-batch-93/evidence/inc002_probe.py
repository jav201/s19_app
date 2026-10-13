# P3 probe for batch-93 increment 002 -- the wrap audit's first pass + the
# regime measurements. Drives the shipped map screen at the contract's
# geometries, walks every authored Text surface, and reports any line whose
# cell width exceeds its widget's measured width (the wrap defect class), plus
# the panel/pane widths the HLR-131 threshold re-derivation needs. Throwaway
# evidence tooling; not part of the suite.
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from rich.cells import cell_len

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


def audit_panel(panel):
    """Walk every authored Text widget under the panel; report overflowing lines.

    Returns [(label, line_no, line, line_cells, widget_width), ...].
    """
    from textual.widgets import Label
    from textual.widget import Widget

    overflows = []
    surfaces = [
        w for w in panel.query(Widget)
        if type(w) in (Label,) or type(w).__name__ == "Static"
    ]
    for w in surfaces:
        try:
            text = w.render()
        except Exception:
            continue
        width = w.region.width
        plain = text.plain
        for i, line in enumerate(plain.splitlines() or [""]):
            cells = cell_len(line)
            if cells > width:
                overflows.append(
                    (f"{type(w).__name__}#{w.id or '-'} .{'.'.join(w.classes)}",
                     i, line, cells, width)
                )
    return overflows


async def one(size, tags=None):
    app = S19TuiApp()
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        app.current_file = fixture()
        if tags is not None and tags != "HINT":
            app._a2l_enriched_tags = tags
        app.action_show_screen("map")
        await pilot.pause()
        app.update_memory_map()
        for _ in range(6):
            await pilot.pause()
        if tags == "HINT":
            # Force the pre-selection state: the hint is what paints before
            # the deferred auto-selection (and whenever selection is cleared).
            app.query_one("#memory_map_panel")._reset_detail()
        panel = app.query_one("#memory_map_panel")
        grid = app.query_one("#map_grid")
        detail = app.query_one("#map_detail")
        body = app.query_one("#workspace_body")
        scroll = app.query_one(".map-region-scroll")
        rows = [c for c in app.query_one(".map-region-list").children]
        print(f"=== {size[0]}x{size[1]}")
        print(f"  workspace narrow : {'width-narrow' in body.classes}")
        print(f"  panel size       : {panel.size}  content={panel.content_region.width}")
        print(f"  grid region      : {grid.region.width}  content={grid.content_region.width}")
        print(f"  detail region    : {detail.region.width}  content={detail.content_region.width}")
        print(f"  detail body w    : {app.query_one('#map_detail_body').region.width}")
        print(f"  stats body w     : {app.query_one('#map_stats_body').region.width}")
        print(f"  scroll viewport  : {scroll.region.width}")
        for r in rows[:2]:
            line = str(r.render())
            print(f"  row {r.region_start:08X}: {cell_len(line)} cells in w={r.region.width} :: {line!r}")
        over = audit_panel(panel)
        print(f"  WRAP DEFECTS     : {len(over)}")
        for label, i, line, cells, width in over:
            print(f"    !! {label} line{i}: {cells} cells > {width} :: {line!r}")
        body_text = app.query_one("#map_detail_body").render().plain
        print("  inspector body:")
        for ln in body_text.splitlines():
            print(f"    |{ln}")


LONG_TAGS = [
    {"name": "A_VERY_LONG_SYMBOL_NAME_THAT_WILL_NOT_FIT_INSIDE_THE_INSPECTOR_PANE_WIDTH_AT_ALL",
     "address": 0x00000020, "byte_size": 4},
    {"name": "x" * 200, "address": 0x00000040},
]

print("########## demo fixture, no tags")
for size in [(80, 24), (100, 30), (120, 36), (140, 40), (160, 48)]:
    asyncio.run(one(size))
print("########## with a hostile long A2L symbol name (120x36 + 80x24)")
asyncio.run(one((120, 36), tags=LONG_TAGS))
asyncio.run(one((80, 24), tags=LONG_TAGS))
print("########## the pre-selection HINT state (120x36)")
asyncio.run(one((120, 36), tags="HINT"))
