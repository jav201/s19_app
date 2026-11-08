"""E3 round-2 security probe (Inc 11), runner only: as p_r2_view.py (cell_padding=1 and the 34-cell Tag cap of
R-TUI-042a.3 applied by runtime wrappers in this process only; the e07fb00 clone is not edited), with a 4-digit
length: a VALUE carrying LENGTH 2266, which the e07fb00 reader takes. Question: is the Length cell painted whole or
not at all at 100 and 80 columns?"""
import asyncio, pathlib, sys
sys.path.insert(0, "/home/<user>/work/s19_app")
from rich.cells import cell_len
from rich.text import Text
from s19_app.tui.app import S19TuiApp
from s19_app.tui.changes.io import emit_s19_from_mem_map
from textual.widgets import DataTable

_orig_init = DataTable.__init__
def _init(self, *a, **k):
    if k.get("id") == "a2l_tags_list":
        k["cell_padding"] = 1
    _orig_init(self, *a, **k)
DataTable.__init__ = _init
_orig_cells = S19TuiApp._build_a2l_table_cells
def _cells(self, tag):
    cells = list(_orig_cells(self, tag))
    name = str(tag.get("name") or "UNKNOWN").replace("\n", " ").strip()
    if cell_len(name) > 34:
        name = name[:16] + "…" + name[-17:]
    cells[0] = Text(f"{cells[0].plain[:1]} {name}", style=cells[0].style)
    return tuple(cells)
S19TuiApp._build_a2l_table_cells = _cells
ADDR = 0x1C2D3E00
scratch = pathlib.Path("/tmp/b103-e3r2-11-S/work/viewlen")


async def run(width, height, n):
    base = scratch / f"w{width}n{n}"; base.mkdir(parents=True, exist_ok=True)
    name = ("N" * n)[: n - 3] + "END"
    f = base / "v.a2l"
    f.write_text(f"""ASAP2_VERSION 1 71
/begin PROJECT P ""
/begin MODULE M ""
/begin COMPU_METHOD CM_ID "" IDENTICAL "%.0" ""
/end COMPU_METHOD
/begin RECORD_LAYOUT RL_U16
FNC_VALUES 1 UWORD ROW_DIR DIRECT
/end RECORD_LAYOUT
/begin CHARACTERISTIC {name} "d"
VALUE 0x{ADDR:08X} RL_U16 0 CM_ID 0 65535
LENGTH 2266
/end CHARACTERISTIC
/end MODULE
/end PROJECT
""", encoding="utf-8")
    img = base / "v.s19"; img.write_text(emit_s19_from_mem_map({ADDR: 1, ADDR + 1: 2}, [(ADDR, ADDR + 2)]), encoding="ascii")
    app = S19TuiApp(base_dir=base)
    async with app.run_test(size=(width, height)) as pilot:
        await pilot.pause()
        app.load_selected_file(img)
        for _ in range(400):
            await pilot.pause()
            if app.current_file is not None and app.current_file.path.name == img.name:
                break
        app.load_a2l_from_path(f)
        await app.workers.wait_for_complete()
        for _ in range(20):
            await pilot.pause()
        await pilot.press("2")
        for _ in range(20):
            await pilot.pause()
        t = app.query_one("#a2l_tags_list", DataTable)
        row = next((t.render_line(y).text.rstrip() for y in range(t.size.height) if "END" in t.render_line(y).text), "")
        tail = row[row.find("END") + 3:]
        toks = tail.split()
        a = "full" if toks and toks[0] == f"0x{ADDR:08X}" else ("CUT " + repr(toks[0]) if toks else "not shown")
        ln = "full" if len(toks) > 1 and toks[1] == "2266" else ("CUT " + repr(toks[1]) if len(toks) > 1 else "not shown")
        print(f"[V2L w={width} name_len={n}] table_width={t.size.width} address: {a} | length 2266: {ln} | row tail={tail!r}")


async def main():
    for width, height, ns in ((100, 40, (20, 24, 26, 28, 30)), (80, 50, (9, 12, 14, 16, 20))):
        for n in ns:
            await run(width, height, n)


asyncio.run(main())
