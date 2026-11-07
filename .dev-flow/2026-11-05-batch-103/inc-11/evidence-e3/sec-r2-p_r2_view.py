"""E3 round-2 security probe (Inc 11), runner only: the REAL A2L Explorer (e07fb00 clone, read-only), headless, with
the two Inc 11 view rules applied by runtime wrappers inside this process only (the clone is not edited):
R-TUI-042a.2 (cell_padding=1, a wrapper of DataTable.__init__) and R-TUI-042a.3 (a wrapper of
S19TuiApp._build_a2l_table_cells that shows a name wider than 34 cells as its first 16 cells, '...', its last 17).
Synthetic VALUE tags whose names are N characters long. Question: with both rules, is the Address cell (and the
Length cell) painted whole or not at all, at every width the product supports (R-TUI-042a.2 tests 220, 160, 118,
100 and 80)?"""
import asyncio, pathlib, sys
sys.path.insert(0, "/home/<user>/work/s19_app")
import s19_app, textual
print("s19_app.__file__ =", s19_app.__file__, "| textual", textual.__version__)
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
scratch = pathlib.Path("/tmp/b103-e3r2-11-S/work/view")


def a2l(chars):
    body = "".join(f'/begin CHARACTERISTIC {nm} "d"\n{kind} {addr} RL_U16 0 CM_ID 0 65535\n{extra}/end CHARACTERISTIC\n'
                   for nm, kind, addr, extra in chars)
    return f"""ASAP2_VERSION 1 71
/begin PROJECT P ""
/begin MODULE M ""
/begin COMPU_METHOD CM_ID "" IDENTICAL "%.0" ""
/end COMPU_METHOD
/begin RECORD_LAYOUT RL_U16
FNC_VALUES 1 UWORD ROW_DIR DIRECT
/end RECORD_LAYOUT
{body}/end MODULE
/end PROJECT
"""


def painted(w):
    return [w.render_line(y).text.rstrip() for y in range(w.size.height)]


def verdict(row, marker, full):
    tail = row[row.find(marker) + len(marker):] if marker in row else ""
    shown = tail.strip().split(" ")[0] if tail.strip() else ""
    if full in tail:
        return "full", tail
    if shown and full.startswith(shown):
        return "CUT " + repr(shown), tail
    return "not shown", tail


async def run(width, height, n, chars=None, label=""):
    base = scratch / f"w{width}n{n}{label}"; base.mkdir(parents=True, exist_ok=True)
    name = ("N" * n)[: n - 3] + "END"
    chars = chars or [(name, "VALUE", f"0x{ADDR:08X}", "")]
    f = base / "v.a2l"; f.write_text(a2l(chars), encoding="utf-8")
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
        lines = painted(t)
        return t.size.width, lines


async def main():
    plan = {80: (9, 20, 24, 26, 28, 34, 48), 100: (20, 28, 30, 34, 48), 118: (34, 35, 46, 48, 54),
            160: (34, 48, 100), 220: (48, 100)}
    heights = {80: 50, 100: 40, 118: 54, 160: 50, 220: 60}
    full = f"0x{ADDR:08X}"
    for width, ns in plan.items():
        for n in ns:
            tw, lines = await run(width, heights[width], n)
            rows = [ln for ln in lines if "END" in ln]
            row = rows[0] if rows else ""
            v, tail = verdict(row, "END", full)
            toks = tail.split()
            lv = "whole" if len(toks) > 1 and toks[1] == "2" else ("absent" if len(toks) <= 1 else "other " + repr(toks[1]))
            print(f"[V2 w={width} name_len={n}] table_width={tw} tag_cell={'capped' if n > 34 else 'whole'} "
                  f"address: {v} | length '2': {lv} | row tail={tail!r}")
    # one page holding a 64-bit header address (R-VAL-036 keeps it) and a 7-digit LENGTH, at 118
    chars = [("AAA_WIDE_ADDR_END", "VALUE", "0x1C2D3E004026", ""),
             ("BBB_LONG_LEN_END", "VALUE", f"0x{ADDR:08X}", "LENGTH 1048576\n"),
             ("C" * 45 + "_CAP_END", "VALUE", f"0x{ADDR:08X}", "LENGTH 1048576\n")]
    tw, lines = await run(118, 54, 0, chars=chars, label="pair")
    for marker, full_addr, full_len in (("WIDE_ADDR_END", "0x1C2D3E004026", "2"), ("LONG_LEN_END", full, "1048576"),
                                        ("_CAP_END", full, "1048576")):
        row = next((ln for ln in lines if marker in ln), "")
        tail = row[row.find(marker) + len(marker):] if marker in row else ""
        toks = tail.split()
        print(f"[V2 w=118 page with a 64-bit address] {marker}: address {'full' if full_addr in toks else 'CUT/absent'} "
              f"length {'full' if full_len in toks else ('CUT ' + repr(toks[1]) if len(toks) > 1 else 'absent')} | tail={tail!r}")


asyncio.run(main())
