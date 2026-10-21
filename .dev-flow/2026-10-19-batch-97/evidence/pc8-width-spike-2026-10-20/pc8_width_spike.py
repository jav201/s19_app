"""PC-8 spike v2: batch-97 split, painted cells across 118->220->118, timing."""
import asyncio, sys, tempfile, time
from pathlib import Path
sys.path.insert(0, r"C:\Users\jjgh8\Github\s19_app")
from rich.text import Text
from textual.widgets import DataTable
from s19_app.tui.app import S19TuiApp
from s19_app.utils import safe_text

A2L = Path(r"C:\Users\jjgh8\Github\s19_app\examples\case_00_public\ASAP2_Demo_V161.a2l")
CAP, FMIN, PFLOOR, GUTTER = 10, 4, 42, 1

def clip_param(name, w):
    if len(name) <= w: return name
    first = name.split(".")[0]
    if len(first) + 2 > w: first = first[: max(1, w // 3)]
    return first + "…" + name[-(w - len(first) - 1):]

def clip_fmt(s, w):
    s = s.rstrip()
    return s if len(s) <= w else s[: w - 1] + "…"

def check_layout(table_w, longest):
    usable = table_w - GUTTER
    fixed = 3 + 12 + 2 + 2
    f = max(FMIN, min(min(longest, CAP), usable - fixed - PFLOOR))
    return usable - fixed - f, f

def painted(app, table):
    strips = app.screen._compositor.render_strips()  # idiom of tests/test_tui_diff_screen.py:872
    lines = ["".join(seg.text for seg in st) for st in strips]
    r = table.region
    return [lines[y][r.x:r.x + r.width] for y in range(r.y, r.y + r.height)]

def style(panel, table):
    panel.styles.padding = (0, 0)
    L = panel.query_one("#check_left_column"); R = panel.query_one("#check_right_column")
    L.styles.width = "1fr"; L.styles.border = ("round", "gray")
    R.styles.width = "38%"; R.styles.min_width = 41; R.styles.border = ("round", "gray"); R.styles.padding = (0, 1)
    table.styles.scrollbar_size_vertical = GUTTER

def build_rows(panel, table, pw, fw):
    for name, (addr, size, fmt) in panel._param_rows.items():
        table.add_row(Text("·"), safe_text(clip_param(name, pw)), safe_text(f"0x{addr:08X}"), safe_text(clip_fmt(fmt, fw)))

def set_widths(table, pw, fw):
    cols = table.ordered_columns
    for c, w in ((cols[0], 1), (cols[1], pw), (cols[2], 10), (cols[3], fw)):
        c.width = w; c.auto_width = False

async def p1(app, panel, table, pw, fw):
    set_widths(table, pw, fw)
    table.refresh(layout=True)

async def p2(app, panel, table, pw, fw):
    set_widths(table, pw, fw)
    # re-clip text too (DataTable crops with no ellipsis) via direct data write
    for i, (name, (addr, size, fmt)) in enumerate(panel._param_rows.items()):
        rk = list(table.rows)[i]
        ck = [c.key for c in table.ordered_columns]
        table._data[rk][ck[1]] = safe_text(clip_param(name, pw)); table._data[rk][ck[3]] = safe_text(clip_fmt(fmt, fw))
    table._clear_caches(); table._require_update_dimensions = True; table.refresh(layout=True)

async def p3(app, panel, table, pw, fw):
    set_widths(table, pw, fw)
    ck = [c.key for c in table.ordered_columns]
    for i, (rk, (name, (addr, size, fmt))) in enumerate(zip(list(table.rows), panel._param_rows.items())):
        table.update_cell(rk, ck[1], safe_text(clip_param(name, pw)), update_width=(i == 0))
        table.update_cell(rk, ck[3], safe_text(clip_fmt(fmt, fw)))

async def p4(app, panel, table, pw, fw):
    set_widths(table, pw, fw)
    cur, sy = table.cursor_row, table.scroll_y
    table.clear()
    build_rows(panel, table, pw, fw)
    table.move_cursor(row=cur, animate=False, scroll=False)
    table.scroll_to(y=sy, animate=False)

async def drive(fn, extra_rows=0):
    app = S19TuiApp(base_dir=Path(tempfile.mkdtemp()))
    out = []
    async with app.run_test(size=(118, 54)) as pilot:
        app.load_a2l_from_path(A2L)
        for _ in range(6): await pilot.pause()
        await pilot.press("equals_sign")
        for _ in range(6): await pilot.pause()
        panel = app.query_one("#check_editor_panel"); table = app.query_one("#check_param_table", DataTable)
        if extra_rows:
            base = dict(panel._param_rows)
            for i in range(extra_rows):
                panel._param_rows[f"SYNTH.PARAM.NUMBER_{i:05d}.LONG_TAIL_NAME"] = (0x10000 + i, 2, "u16 hours")
        style(panel, table)
        longest = max(len(v[2].rstrip()) for v in panel._param_rows.values())
        for _ in range(4): await pilot.pause()
        table.move_cursor(row=40); 
        for _ in range(3): await pilot.pause()
        for size in [(118, 54), (220, 60), (118, 54), (118, 53)]:
            await pilot.resize_terminal(*size)
            for _ in range(6): await pilot.pause()
            pw, fw = check_layout(table.content_region.width, longest)
            t0 = time.perf_counter(); await fn(app, panel, table, pw, fw); dt = time.perf_counter() - t0
            for _ in range(6): await pilot.pause()
            p = painted(app, table)
            long_rows = [l.rstrip() for l in p if "BITMASK_0FF0" in l or "TAB_VERB_NO" in l]
            ellipsis_ok = all(("…" in l) or True for l in long_rows)
            out.append(dict(size=size, card=panel.query_one("#check_right_column").region.width,
                left=panel.query_one("#check_left_column").region.width,
                table_w=table.content_region.width, P=pw, F=fw,
                rw=[c.get_render_width(table) for c in table.ordered_columns],
                virt=table.virtual_size.width, msx=table.max_scroll_x, cur=table.cursor_row,
                sy=table.scroll_y, ms=round(dt * 1000, 1), header=p[0].rstrip(), sample=long_rows[:2],
                hdr_cut="Fmt · Unit" not in p[0]))
    return out

async def main():
    for nm, fn in [("P1 Column.width + refresh(layout=True) only", p1), ("P2 _clear_caches", p2), ("P3 update_cell", p3), ("P4 clear rows + re-add", p4)]:
        print("=====", nm)
        for r in await drive(fn): print(" ", r)
    print("===== timing with 5000 synthetic rows")
    for nm, fn in [("P3", p3), ("P4", p4)]:
        rs = await drive(fn, extra_rows=5000)
        print(" ", nm, [(r["size"], r["ms"], r["msx"]) for r in rs])

asyncio.run(main())
