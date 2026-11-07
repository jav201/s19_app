"""Inc 11 E3 architect round 2 (batch-103): the A2L Explorer tag table with cell_padding 1 (R-TUI-042a.2) AND the
Tag-cell cap of R-TUI-042a.3 (a name wider than 34 cells shown as its first 16 cells, an ellipsis and its last 17
cells), on the REAL app driven headless. Run on cachyos-rtx only:

    python -I e3a2-cap.py <repo> <scratch> <pad> <name lengths csv> <widths csv> <cap 0|1>

The two changes the graph makes in app.py are set from outside, nothing else changes: cell_padding by wrapping
DataTable.__init__ for the widget id "a2l_tags_list" only; the cap by wrapping S19TuiApp._build_a2l_table_cells and
replacing only its first cell's name text (glyph, blank, capped name; same style). Synthetic data only: the E1 pilot's
MAP at 0x1C2D3E00, length 2266, renamed to an n-character synthetic name. For each width and name: the column render
widths, the painted Address and Length cells (the cells under those columns, cut at the pane edge), and whether a
proper prefix of 0x1C2D3E00 is painted as the Address cell.
"""
import asyncio, pathlib, sys

repo = pathlib.Path(sys.argv[1]); scratch = pathlib.Path(sys.argv[2]); PAD = int(sys.argv[3])
NLENS = [int(x) for x in sys.argv[4].split(",")]
CAP = int(sys.argv[6])
NAME = "SYN_MAP_W"
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
from rich.text import Text  # noqa: E402

_orig_cells = S19TuiApp._build_a2l_table_cells


def _cells(self, tag):
    cells = list(_orig_cells(self, tag))
    if CAP:
        name = str(tag.get("name") or "UNKNOWN").replace(chr(10), " ").strip()
        if len(name) > 34:
            name = name[:16] + "…" + name[-17:]
        glyph = "✓" if tag.get("in_memory") else "·"
        cells[0] = Text(f"{glyph} {name}", style=cells[0].style)
    return tuple(cells)


S19TuiApp._build_a2l_table_cells = _cells

ADDR, NX, NY = 0x1C2D3E00, 87, 13
def a2l_text():
    return f"""ASAP2_VERSION 1 71
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
    base = scratch / f"cap{CAP}_pad{PAD}_n{len(NAME)}_w{width}"
    base.mkdir(parents=True, exist_ok=True)
    a2l = base / "syn_map.a2l"; a2l.write_text(a2l_text(), encoding="utf-8")
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
        row0 = lines[1] if len(lines) > 1 else ""
        x0 = cols[0][1]
        acell = row0[x0:x0 + cols[1][1]] if len(row0) > x0 else ""
        lcell = row0[x0 + cols[1][1]:x0 + cols[1][1] + cols[2][1]] if len(row0) > x0 + cols[1][1] else ""
        a_s = acell.strip()
        partial = bool(a_s) and a_s != "0x1C2D3E00" and "0x1C2D3E00".startswith(a_s)
        print(f"[C{CAP} P{PAD} N{len(NAME)} W{width}] visible={visible} Tag col={cols[0][1]} Address col={cols[1][1]} "
              f"Length col={cols[2][1]} | Address cell painted={acell!r} Length cell painted={lcell!r} | "
              f"address whole={a_s == '0x1C2D3E00'} partial-prefix={partial} length whole={lcell.strip() == '2266'}")
        glue = [f"0x{ADDR:08X}{tag.get('length')}", NAME + "0x1C2D3E00", "17921792", "unknown0.."]
        row = lines[1] if len(lines) > 1 else ""
        print(f"[P{PAD} N{len(NAME)} W{width}] reader address={hex(tag.get('address') or 0)} length={tag.get('length')}; "
              + "; ".join(f"'{g}' painted {sum(g in ln for ln in lines)}" for g in glue)
              + f"; '0x1C2D3E00' painted {('0x1C2D3E00' in row)}; '2266' painted {('2266' in row)}")


PATTERN = "SYN_MAP_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" * 4
for n in NLENS:
    NAME = PATTERN[:n]
    print("name length", len(NAME))
    for w in WIDTHS:
        asyncio.run(run(w))
