"""Inc 11 E1 pilot (batch-103), run on cachyos-rtx only: python e1-pilot-glued-cells.py <repo> <scratch>

Question: can the A2L Explorer tag table show a declared address with extra digits appended
(for example `0x1C2D3E00` read as `0x1C2D3E004026`) when the reader reads the address correctly?

Method (a stand-in table, marked partial):
  1. The e07fb00 reader parses a synthetic MAP whose name is a quoted string (no plain name), with two
     FIX_AXIS axes (33 and 61 points), so its length is 4026 bytes. All names and numbers are synthetic.
  2. The product's own cell builder (`S19TuiApp._build_a2l_table_cells`) gives the 16 cells of its row.
  3. A Textual DataTable built with the product's constructor arguments (app.py:8516-8521:
     zebra_stripes=True, cursor_type="row", cell_padding=0) and the product's 16 column names
     (app.py:8733-8750) paints the row headless (no display, no clipboard); each painted line is read back.
  4. Negative control: the same table with cell_padding=1.
  The reader's address is printed as an integer next to the painted text.
"""
import asyncio, pathlib, sys

repo = pathlib.Path(sys.argv[1]); scratch = pathlib.Path(sys.argv[2])
sys.path.insert(0, str(repo))
import s19_app  # noqa: E402
import textual  # noqa: E402
print("s19_app.__file__ =", s19_app.__file__, "| textual", textual.__version__)
from s19_app.tui.a2l import parse_a2l_file  # noqa: E402
from s19_app.tui.services.a2l_service import enrich_tags_and_render  # noqa: E402
from s19_app.tui import app as app_mod  # noqa: E402
from textual.app import App  # noqa: E402
from textual.widgets import DataTable  # noqa: E402

COLUMNS = ("Tag", "Address", "Length", "Source", "Raw", "Physical", "InMem", "Region", "Limits", "Unit",
           "Bits", "Endian", "Virt", "Func", "Access", "Dtype")
A2L = """ASAP2_VERSION 1 71
/begin PROJECT PSYN ""
/begin MODULE MSYN ""
/begin MOD_COMMON ""
BYTE_ORDER MSB_LAST
/end MOD_COMMON
/begin COMPU_METHOD CM_SYN "" IDENTICAL "%.0" "rpm"
/end COMPU_METHOD
/begin RECORD_LAYOUT RL_SYN_U16
FNC_VALUES 1 UWORD COLUMN_DIR DIRECT
/end RECORD_LAYOUT
/begin CHARACTERISTIC "Synthetic map"
  MAP 0x1C2D3E00 RL_SYN_U16 4095 CM_SYN 0 4095
  /begin AXIS_DESCR
    FIX_AXIS NO_INPUT_QUANTITY CM_SYN 33 0 32
    FIX_AXIS_PAR 0 1 33
  /end AXIS_DESCR
  /begin AXIS_DESCR
    FIX_AXIS NO_INPUT_QUANTITY CM_SYN 61 0 60
    FIX_AXIS_PAR 0 1 61
  /end AXIS_DESCR
/end CHARACTERISTIC
/end MODULE
/end PROJECT
"""

class StandIn(App):
    def __init__(self, cells, pad):
        super().__init__()
        self._cells, self._pad = cells, pad
    def compose(self):
        yield DataTable(id="t", zebra_stripes=True, cursor_type="row", cell_padding=self._pad)
    def on_mount(self):
        t = self.query_one(DataTable)
        t.add_columns(*COLUMNS)
        t.add_row(*self._cells)

async def paint(cells, pad):
    app = StandIn(cells, pad)
    async with app.run_test(size=(200, 6)) as pilot:
        await pilot.pause()
        t = app.query_one(DataTable)
        return [t.render_line(y).text.rstrip() for y in range(2)]

p = scratch / "synthetic_map.a2l"
p.write_text(A2L, encoding="utf-8")
data = parse_a2l_file(p)
tag = data["tags"][0]
print(f"[P0] reader: name={tag['name']!r} address={tag['address']!r} (= {hex(tag['address']) if isinstance(tag['address'], int) else None}) "
      f"length={tag['length']!r} errors={data['errors']}")
merged, summary = enrich_tags_and_render(data, None)
cells = app_mod.S19TuiApp._build_a2l_table_cells(None, merged[0])
print("[P1] product cells:", [c.plain for c in cells])
print("[P2] summary tag line:", [ln for ln in summary if "Synthetic" in ln][-1])
for pad in (0, 1):
    lines = asyncio.run(paint(cells, pad))
    print(f"[P3 cell_padding={pad}] header: {lines[0]}")
    print(f"[P3 cell_padding={pad}] row:    {lines[1]}")
    print(f"[P3 cell_padding={pad}] '0x1C2D3E004026' painted: {'0x1C2D3E004026' in lines[1]} | 'unknown0..4095' painted: {'unknown0..4095' in lines[1]}")
p.unlink()
