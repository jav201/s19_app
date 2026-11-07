"""Inc 11 E3 architect (batch-103): the A2L Explorer tag table at 5 widths with cell_padding 0 (e07fb00) and 1
(R-TUI-042a.2 as changed), on the REAL app driven headless. Run on <runner> only:

    python -I e3a-pad.py <repo> <scratch> <pad>        pad = 0 | 1

The pad-1 run sets the one argument the graph changes (app.py:8520, cell_padding=0 -> 1) by wrapping
DataTable.__init__ for the widget id "a2l_tags_list" only; nothing else in the app changes. Synthetic data only: the
E1 pilot's MAP SYN_MAP_W at 0x1C2D3E00, length 2266 (evidence-e1/e1-pilot-explorer-widths.py, same A2L text and image).
For each width: the table's visible width, every column's label and render width (content + 2 x padding), the columns
that are fully visible, the first column that is cut at the right edge and how many of its cells show, the painted
header and row, and the glue strings of R-TUI-042a.2's threshold.
"""
import asyncio, pathlib, sys

repo = pathlib.Path(sys.argv[1]); scratch = pathlib.Path(sys.argv[2]); PAD = int(sys.argv[3])
NAME = sys.argv[4] if len(sys.argv) > 4 else "SYN_MAP_W"
WIDTHS = [int(x) for x in sys.argv[5].split(",")] if len(sys.argv) > 5 else [220, 160, 118, 100, 80]
sys.path.insert(0, str(repo))
import s19_app  # noqa: E402
import textual  # noqa: E402
print("s19_app.__file__ =", s19_app.__file__, "| textual", textual.__version__, "| pad", PAD)
from textual.widgets import DataTable  # noqa: E402

_orig_init = DataTable.__init__


def _init(self, *args, **kwargs):
    if kwargs.get("id") == "a2l_tags_list":
        kwargs["cell_padding"] = PAD
    _orig_init(self, *args, **kwargs)


DataTable.__init__ = _init
from s19_app.tui.app import S19TuiApp  # noqa: E402
from s19_app.tui.changes.io import emit_s19_from_mem_map  # noqa: E402

ADDR, NX, NY = 0x1C2D3E00, 87, 13
A2L = f"""ASAP2_VERSION 1 71
/begin PROJECT PSYN ""
/begin MODULE MSYN ""
/begin MOD_COMMON ""
BYTE_ORDER MSB_LAST
/end MOD_COMMON
/begin COMPU_METHOD CM_SYN "" IDENTICAL "%.0" ""
/end COMPU_METHOD
/begin RECORD_LAYOUT RL_SYN_MAP
NO_AXIS_PTS_X 1 UWORD
NO_AXIS_PTS_Y 2 UWORD
FNC_VALUES 3 UWORD COLUMN_DIR DIRECT
/end RECORD_LAYOUT
/begin CHARACTERISTIC {NAME} "synthetic map"
  MAP 0x{ADDR:08X} RL_SYN_MAP 4095 CM_SYN 0 4095
  /begin AXIS_DESCR
    FIX_AXIS NO_INPUT_QUANTITY CM_SYN {NX} 0 {NX - 1}
    FIX_AXIS_PAR 0 1 {NX}
  /end AXIS_DESCR
  /begin AXIS_DESCR
    FIX_AXIS NO_INPUT_QUANTITY CM_SYN {NY} 0 {NY - 1}
    FIX_AXIS_PAR 0 1 {NY}
  /end AXIS_DESCR
/end CHARACTERISTIC
/end MODULE
/end PROJECT
"""


def painted(widget):
    return [widget.render_line(y).text.rstrip() for y in range(widget.size.height)]


async def run(width):
    base = scratch / f"pad{PAD}_n{len(NAME)}_w{width}"
    base.mkdir(parents=True, exist_ok=True)
    a2l = base / "syn_map.a2l"; a2l.write_text(A2L, encoding="utf-8")
    size = 2 + 2 + NX * NY * 2
    img = base / "syn_img.s19"
    img.write_text(emit_s19_from_mem_map({ADDR + i: (i * 7) & 0xFF for i in range(size)}, [(ADDR, ADDR + size)]),
                   encoding="ascii")
    app = S19TuiApp(base_dir=base)
    async with app.run_test(size=(width, 54)) as pilot:
        await pilot.pause()
        app.load_selected_file(img)
        for _ in range(400):
            await pilot.pause()
            if app.current_file is not None and app.current_file.path.name == img.name:
                break
        app.load_a2l_from_path(a2l)
        await app.workers.wait_for_complete()
        for _ in range(20):
            await pilot.pause()
        await pilot.press("2")
        for _ in range(20):
            await pilot.pause()
        table = app.query_one("#a2l_tags_list", DataTable)
        table.focus()
        await pilot.pause()
        if table.row_count:
            table.move_cursor(row=0)
        for _ in range(10):
            await pilot.pause()
        tag = next(iter(app._a2l_row_key_to_tag.values()), {})
        visible = table.scrollable_content_region.width
        cols = []
        for col in table.columns.values():
            cols.append((str(col.label), col.get_render_width(table)))
        total = sum(w for _, w in cols)
        x = 0
        full, cut = [], None
        for label, w in cols:
            if x + w <= visible:
                full.append(label)
            elif cut is None and x < visible:
                cut = (label, visible - x, w)
            x += w
        lines = [ln for ln in painted(table) if ln.strip()]
        print(f"\n[P{PAD} W{width}] table size={table.size} visible={visible} virtual={table.virtual_size.width} "
              f"cell_padding={table.cell_padding} columns={len(cols)} total_render_width={total}")
        print(f"[P{PAD} N{len(NAME)} W{width}] column render widths: " + ", ".join(f"{l}={w}" for l, w in cols))
        print(f"[P{PAD} N{len(NAME)} W{width}] fully visible ({len(full)}): {', '.join(full)}")
        print(f"[P{PAD} N{len(NAME)} W{width}] first cut column: " + (f"{cut[0]} ({cut[1]} of {cut[2]} cells shown)" if cut else "none"))
        for ln in lines[:2]:
            print(f"[P{PAD} N{len(NAME)} W{width}] painted| {ln}")
        glue = [f"0x{ADDR:08X}{tag.get('length')}", NAME + "0x1C2D3E00", "17921792", "unknown0.."]
        row = lines[1] if len(lines) > 1 else ""
        print(f"[P{PAD} N{len(NAME)} W{width}] reader address={hex(tag.get('address') or 0)} length={tag.get('length')}; "
              + "; ".join(f"'{g}' painted {sum(g in ln for ln in lines)}" for g in glue)
              + f"; '0x1C2D3E00' painted {('0x1C2D3E00' in row)}; '2266' painted {('2266' in row)}")


print("name length", len(NAME))
for w in WIDTHS:
    asyncio.run(run(w))
