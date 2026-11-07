"""Inc 11 E1 pilot (batch-103), run on cachyos-rtx only: python e1-pilot-explorer-widths.py <repo> <scratch>

Hypothesis 5 (display adjacency), on the REAL app: does the A2L Explorer paint a declared address next to the
computed length with no separator, so that the two read as one hex string, and at which terminal widths?

Synthetic data only (names, address and sizes are this pilot's own): a MAP `SYN_MAP_W` at 0x1C2D3E00 on a record
layout with two axis-count fields (NO_AXIS_PTS_X, NO_AXIS_PTS_Y) and FNC_VALUES, two FIX_AXIS axes of 87 and 13
points, so its length is computed by the reader (2 + 2 + 87 x 13 x 2 = 2266 bytes); an S19 image that holds those
bytes. The app runs headless (Textual run_test, no display, no clipboard; HOME/XDG/LOCALAPPDATA isolated by the
wrapper). For each width the A2L Explorer is shown (key 2), the cursor rests on the row, and the painted lines of the
tag table (#a2l_tags_list) and of the detail card (#a2l_detail_card) are read back from their rendered strips.
"""
import asyncio, pathlib, sys

repo = pathlib.Path(sys.argv[1]); scratch = pathlib.Path(sys.argv[2])
sys.path.insert(0, str(repo))
import s19_app  # noqa: E402
import textual  # noqa: E402
print("s19_app.__file__ =", s19_app.__file__, "| textual", textual.__version__)
from s19_app.tui.app import S19TuiApp  # noqa: E402
from s19_app.tui.changes.io import emit_s19_from_mem_map  # noqa: E402
from textual.widgets import DataTable  # noqa: E402

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
/begin CHARACTERISTIC SYN_MAP_W "synthetic map"
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
    base = scratch / f"app{width}"
    base.mkdir(parents=True, exist_ok=True)
    a2l = base / "syn_map.a2l"; a2l.write_text(A2L, encoding="utf-8")
    size = 2 + 2 + NX * NY * 2
    img = base / "syn_img.s19"
    img.write_text(emit_s19_from_mem_map({ADDR + i: (i * 7) & 0xFF for i in range(size)}, [(ADDR, ADDR + size)]), encoding="ascii")
    app = S19TuiApp(base_dir=base)
    async with app.run_test(size=(width, 50)) as pilot:
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
        rows = [ln for ln in painted(table) if ln.strip()]
        card = [ln for ln in painted(app.query_one("#a2l_detail_card")) if ln.strip()]
        glued = f"0x{ADDR:08X}{tag.get('length')}"
        print(f"\n[W{width}] table size={table.size} rows={table.row_count} reader address={hex(tag.get('address') or 0)} length={tag.get('length')}")
        for ln in rows[:3]:
            print(f"[W{width}] table| {ln}")
        for ln in card[:4]:
            print(f"[W{width}] card | {ln}")
        print(f"[W{width}] '{glued}' painted in the table: {any(glued in ln for ln in rows)} | "
              f"address text painted whole: {any(f'0x{ADDR:08X}' in ln for ln in rows)} | "
              f"'unknown0..' painted: {any('unknown0..' in ln for ln in rows)}")

for w in (220, 160, 118, 100, 80):
    asyncio.run(run(w))
