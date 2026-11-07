"""Inc 11 E3 correction round 2 (batch-103), runner only: does Textual 8.2.8's DataTable(fixed_columns=2) keep the
Address and Length cells of the A2L Explorer tag table whole at every width from 80 to 220 columns, with long names,
a 64-bit address and a 7-digit length on one page, before and after a horizontal scroll?

    python -I e3c2-fixedcols.py <repo> <scratch> <config> <name lengths csv> <widths csv>

config: A = Address, Length, Tag, ... with fixed_columns=2 (the ruled design); B = today's order (Tag, Address,
Length, ...) with fixed_columns=0 (negative control 1); C = Address, Length first with fixed_columns=0 (negative
control 2, shows what fixing adds under a horizontal scroll). Every config has cell_padding=1 (R-TUI-042a.2) and the
Tag cap (R-TUI-042a.3: a name wider than 34 cells as its first 16 cells, an ellipsis, its last 17). The product is
changed from outside only (wrappers of DataTable.__init__, DataTable.add_columns and
S19TuiApp._build_a2l_table_cells, for the table id a2l_tags_list); the clone is read-only. Synthetic data only.
"""
import asyncio, pathlib, sys

repo = pathlib.Path(sys.argv[1]); scratch = pathlib.Path(sys.argv[2]); CFG = sys.argv[3]
NLENS = [int(x) for x in sys.argv[4].split(",")]
WIDTHS = [int(x) for x in sys.argv[5].split(",")]
REORDER = CFG in ("A", "C")
FIXED = 2 if CFG == "A" else 0
sys.path.insert(0, str(repo))
import s19_app, textual  # noqa: E402
print("s19_app.__file__ =", s19_app.__file__, "| textual", textual.__version__, "| config", CFG,
      "| reorder", REORDER, "| fixed_columns", FIXED)
from rich.cells import cell_len  # noqa: E402
from rich.text import Text  # noqa: E402
from textual.widgets import DataTable  # noqa: E402

_orig_init = DataTable.__init__
def _init(self, *a, **k):
    if k.get("id") == "a2l_tags_list":
        k["cell_padding"] = 1
        k["fixed_columns"] = FIXED
    _orig_init(self, *a, **k)
DataTable.__init__ = _init

_orig_add_columns = DataTable.add_columns
def _add_columns(self, *labels):
    if REORDER and self.id == "a2l_tags_list" and labels[:3] == ("Tag", "Address", "Length"):
        labels = ("Address", "Length", "Tag") + tuple(labels[3:])
    return _orig_add_columns(self, *labels)
DataTable.add_columns = _add_columns

from s19_app.tui.app import S19TuiApp  # noqa: E402
from s19_app.tui.changes.io import emit_s19_from_mem_map  # noqa: E402

_orig_cells = S19TuiApp._build_a2l_table_cells
def _cells(self, tag):
    cells = list(_orig_cells(self, tag))
    name = str(tag.get("name") or "UNKNOWN").replace("\n", " ").strip()
    if cell_len(name) > 34:
        name = name[:16] + "…" + name[-17:]
    cells[0] = Text(f"{cells[0].plain[:1]} {name}", style=cells[0].style)
    if REORDER:
        cells = [cells[1], cells[2], cells[0]] + cells[3:]
    return tuple(cells)
S19TuiApp._build_a2l_table_cells = _cells

ADDR, NX, NY = 0x1C2D3E00, 87, 13
ADDR64 = 0x1C2D3E004026


def name_of(prefix, n):
    pat = prefix + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" * 4
    return pat[:n]


def a2l_text(n):
    m, v, b = name_of("SYN_MAP_", n), name_of("SYN_V64_", n), name_of("SYN_BIG_", n)
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
/begin CHARACTERISTIC {m} "synthetic map"
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
/begin MEASUREMENT {v} "synthetic 64-bit address"
  UWORD CM_SYN 0 0 0 65535
  ECU_ADDRESS 0x{ADDR64:012X}
/end MEASUREMENT
/begin MEASUREMENT {b} "synthetic 1 MiB length"
  UBYTE CM_SYN 0 0 0 255
  ECU_ADDRESS 0x00001000
  LENGTH 1048576
/end MEASUREMENT
/end MODULE
/end PROJECT
"""


def painted(w):
    return [w.render_line(y).text.rstrip("\n") for y in range(w.size.height)]


def cell_report(table, lines, tag_rows, label):
    cols = [(str(c.label), c.get_render_width(table)) for c in table.ordered_columns]
    idx = {lab: i for i, (lab, _) in enumerate(cols)}
    xs, x = [], 0
    for _, w in cols:
        xs.append(x); x += w
    fixed_w = sum(w for _, w in cols[:FIXED])
    visible = table.scrollable_content_region.width
    sx = int(table.scroll_x)
    out, ok_all = [], True
    for r, cells in enumerate(tag_rows):
        line = lines[1 + r] if 1 + r < len(lines) else ""
        res = []
        for lab in ("Address", "Length"):
            i = idx[lab]
            want = cells[i].plain
            if i < FIXED:
                a, bnd = xs[i], xs[i] + cols[i][1]
            else:
                a, bnd = xs[i] - sx + (0 if FIXED == 0 else 0), xs[i] - sx + cols[i][1]
            seg = line[max(0, a):max(0, min(bnd, visible))] if bnd > 0 and a < visible else ""
            s = seg.strip()
            state = "whole" if s == want else ("not shown" if not s else ("PREFIX" if want.startswith(s) else f"OTHER({s!r})"))
            if state != "whole":
                ok_all = False
            res.append(f"{lab}={want!r}:{state}")
        tagc = cells[idx["Tag"]].plain
        res.append(f"Tag cell {cell_len(tagc)} cells{' with …' if '…' in tagc else ''}")
        out.append(f"row{r}: " + ", ".join(res))
    head = (f"[{CFG} {label}] visible={visible} scroll_x={sx} max_scroll_x={int(table.max_scroll_x)} fixed_w={fixed_w} "
            f"cols: " + ", ".join(f"{l}={w}" for l, w in cols[:4]))
    return head, out, ok_all


async def run(n, width):
    base = scratch / f"cfg{CFG}_n{n}_w{width}"
    base.mkdir(parents=True, exist_ok=True)
    a2l = base / "syn.a2l"; a2l.write_text(a2l_text(n), encoding="utf-8")
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
        if table.row_count:
            table.move_cursor(row=0)
        for _ in range(10):
            await pilot.pause()
        rows = [table.get_row_at(i) for i in range(table.row_count)]
        verdicts = []
        head, out, ok0 = cell_report(table, painted(table), rows, f"N{n} W{width} unscrolled")
        print(head); [print("   ", o) for o in out]
        verdicts.append(ok0)
        table.scroll_to(x=table.max_scroll_x, animate=False)
        for _ in range(10):
            await pilot.pause()
        head, out, ok1 = cell_report(table, painted(table), rows, f"N{n} W{width} scrolled-right")
        print(head); [print("   ", o) for o in out]
        verdicts.append(ok1)
        print(f"[{CFG} N{n} W{width}] rows={len(rows)} unscrolled_whole={ok0} scrolled_whole={ok1}")
        return ok0, ok1


tot = {"u": 0, "s": 0, "n": 0}
for n in NLENS:
    for w in WIDTHS:
        u, s = asyncio.run(run(n, w))
        tot["n"] += 1; tot["u"] += int(u); tot["s"] += int(s)
print(f"[{CFG} SUMMARY] cases={tot['n']} whole unscrolled={tot['u']}/{tot['n']} whole after scroll-right={tot['s']}/{tot['n']}")
