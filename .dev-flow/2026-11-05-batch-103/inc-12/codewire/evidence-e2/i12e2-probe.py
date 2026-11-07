"""Inc 12 E2 (batch-103), runner only: measure the graph's examples on the REAL app, headless.

    python -I i12e2-probe.py <repo> <scratch> <variant label> <scenario>

<repo> is either the read-only clone (variant label `base`, e07fb00 unchanged) or a throwaway copy patched by
i12e2-mkproto.py (labels full / noshow / nopostfit / noresize). The probe never writes into <repo>; it wraps
S19TuiApp.update_a2l_tags_view and ._fit_a2l_tag_cells (when present) with call counters, in this process only.
Synthetic data only (fixtures SYNMAP, LONGMAP(n), PAGE64(n), PAGE64W(n), MANY of ../../02-test-cases.md).

Every table state prints: the visible width (scrollable_content_region.width), scroll_x / max_scroll_x, the vertical
scrollbar, the first four column render widths, w = visible - Address - Length - 4 (the definition), the header line,
the painted row lines, and per row: Address / Length painted whole or not, the Tag cell, its end column and whether
it ends inside the visible width, and whether it equals the form R-TUI-042a.3 / .5 ask for that w.
"""
import asyncio
import pathlib
import re
import sys
import time

repo = pathlib.Path(sys.argv[1]); scratch = pathlib.Path(sys.argv[2]); VARIANT = sys.argv[3]; SCEN = sys.argv[4]
sys.path.insert(0, str(repo))
import s19_app  # noqa: E402
import textual  # noqa: E402

# the account directory of the runner is masked as ~ (no person's name in a record)
print("s19_app.__file__ =", re.sub(r"^/home/[^/]+", "~", s19_app.__file__), "| textual", textual.__version__,
      "| variant", VARIANT, "| scenario", SCEN)
from rich.cells import cell_len  # noqa: E402
from textual.widgets import DataTable  # noqa: E402

from s19_app.tui.app import S19TuiApp  # noqa: E402
from s19_app.tui.changes.io import emit_s19_from_mem_map  # noqa: E402

COUNT = {"build": 0, "fit": 0, "fit_rebuild": 0}
_orig_build = S19TuiApp.update_a2l_tags_view


def _build(self, *a, **k):
    COUNT["build"] += 1
    return _orig_build(self, *a, **k)


S19TuiApp.update_a2l_tags_view = _build
HAS_FIT = hasattr(S19TuiApp, "_fit_a2l_tag_cells")
if HAS_FIT:
    _orig_fit = S19TuiApp._fit_a2l_tag_cells

    def _fit(self, *a, **k):
        COUNT["fit"] += 1
        before = COUNT["build"]
        out = _orig_fit(self, *a, **k)
        COUNT["fit_rebuild"] += COUNT["build"] - before
        return out

    S19TuiApp._fit_a2l_tag_cells = _fit

ADDR, NX, NY = 0x1C2D3E00, 87, 13
ADDR64 = 0x1C2D3E004026
ADDR16 = 0xFEDCBA9876543210
MAP_LEN = 2 + 2 + NX * NY * 2  # 2266


def longname(n):  # LONGMAP(n): SYN_MAP_ + L x (n - 12) + _END
    return "SYN_MAP_" + "L" * (n - 12) + "_END"


def name_of(prefix, n):  # PAGE64(n): F's names
    return (prefix + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" * 4)[:n]


HEAD = """ASAP2_VERSION 1 71
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
"""
TAIL = "/end MODULE\n/end PROJECT\n"


def map_block(name):
    return f"""/begin CHARACTERISTIC {name} "synthetic map"
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
"""


def meas(name, addr, dtype="UWORD", length=None):
    hexdig = max(8, len(f"{addr:X}"))
    extra = f"  LENGTH {length}\n" if length is not None else ""
    return (f'/begin MEASUREMENT {name} "synthetic"\n  {dtype} CM_SYN 0 0 0 65535\n'
            f"  ECU_ADDRESS 0x{addr:0{hexdig}X}\n{extra}/end MEASUREMENT\n")


def page_syn():
    return HEAD + map_block("SYN_MAP_W") + TAIL, {f"0x{ADDR:08X}"}


def page_long(n):
    return HEAD + map_block(longname(n)) + TAIL, {f"0x{ADDR:08X}"}


def page64(n, wide16=False):
    body = (map_block(name_of("SYN_MAP_", n)) + meas(name_of("SYN_V64_", n), ADDR64)
            + meas(name_of("SYN_BIG_", n), 0x1000, "UBYTE", 1048576))
    declared = {f"0x{ADDR:08X}", f"0x{ADDR64:08X}", "0x00001000"}
    if wide16:
        body += meas(name_of("SYN_W16_", n), ADDR16)
        declared.add(f"0x{ADDR16:08X}")
    return HEAD + body + TAIL, declared


def page_many(count, n, wide_at=None):
    body = map_block(longname(n))
    declared = {f"0x{ADDR:08X}"}
    for i in range(count):
        addr = ADDR64 if i == wide_at else 0x2000 + 2 * i
        body += meas(name_of(f"SYN_M{i:03d}_", n), addr)
        declared.add(f"0x{addr:08X}")
    return HEAD + body + TAIL, declared


def expected_tag(name, w):
    """R-TUI-042a.3 / .5 as written: w >= 34 -> a name over 34 cells as 16 + ... + 17; w < 34 -> a name over w
    cells as floor((w-1)/2) + ... + ceil((w-1)/2)."""
    width = 34 if w is None or w >= 34 else w
    if cell_len(name) <= width:
        return name
    head = (width - 1) // 2
    return name[:head] + "…" + name[len(name) - (width - 1 - head):]


def painted(widget):
    return [widget.render_line(y).text.rstrip("\n") for y in range(widget.size.height)]


def report(app, table, label, declared, show_rows=3, check_form=True):
    cols = [(str(c.label), c.get_render_width(table)) for c in table.ordered_columns]
    xs, x = [], 0
    for _, cw in cols:
        xs.append(x); x += cw
    fixed = table.fixed_columns
    fixed_w = sum(cw for _, cw in cols[:fixed])
    visible = table.scrollable_content_region.width
    sx, sy = int(table.scroll_x), int(table.scroll_y)
    idx = {lab: i for i, (lab, _) in enumerate(cols)}
    w = visible - cols[0][1] - cols[1][1] - (2 * table.cell_padding + 2)
    lines = painted(table)
    print(f"[{VARIANT} {label}] visible={visible} vbar={table.show_vertical_scrollbar} scroll_x={sx}/"
          f"{int(table.max_scroll_x)} scroll_y={sy} fixed_columns={fixed} padding={table.cell_padding} "
          f"cols: " + ", ".join(f"{lab}={cw}" for lab, cw in cols[:4]) + f" | w={w} | rows={table.row_count} "
          f"cursor_row={table.cursor_row} | builds={COUNT['build']} fits={COUNT['fit']} "
          f"fit_rebuilds={COUNT['fit_rebuild']}")
    print(f"[{VARIANT} {label}] header| {lines[0].rstrip() if lines else ''}")
    tags = list(app._a2l_row_key_to_tag.values())
    n_ok = n_rows = 0
    hex_bad = set()
    for r in range(table.row_count):
        y = 1 + r - sy
        if y < 1 or y >= len(lines) - (1 if table.show_horizontal_scrollbar else 0):
            continue
        line = lines[y]
        cells = table.get_row_at(r)
        res = []
        ok = True
        for lab in ("Address", "Length"):
            i = idx.get(lab)
            want = cells[i].plain
            if i < fixed:
                a, b = xs[i], xs[i] + cols[i][1]
            else:
                a, b = max(fixed_w, xs[i] - sx), xs[i] - sx + cols[i][1]
            seg = line[a:min(b, visible)] if a < visible and b > 0 else ""
            whole = seg.strip() == want and xs[i] + (0 if i < fixed else -sx) + 1 + cell_len(want) <= visible
            ok &= whole
            res.append(f"{lab}={want}:{'whole' if whole else 'CUT(' + repr(seg.strip()) + ')'}")
        ti = idx.get("Tag")
        tagc = cells[ti].plain
        tag_x = xs[ti] - (0 if ti < fixed else sx)
        tag_end = tag_x + 1 + cell_len(tagc)
        inside = tag_end <= visible if tag_x >= fixed_w or ti < fixed else True
        form = "-"
        if check_form and r < len(tags):
            name = str(tags[r].get("name"))
            want_tag = tagc[:2] + expected_tag(name, w)
            form = "form=ok" if tagc == want_tag else f"form=DIFF(want {want_tag!r})"
            ok &= tagc == want_tag
        if sx == 0:
            ok &= inside
        res.append(f"Tag={tagc!r} ({cell_len(tagc)} cells, ends at {tag_end}, "
                   f"{'inside' if inside else 'PAST the visible width'}, {form})")
        n_rows += 1
        n_ok += int(ok)
        if r < show_rows:
            print(f"[{VARIANT} {label}] row{r}| {line.rstrip()}")
            print(f"[{VARIANT} {label}] row{r}: " + "; ".join(res))
        for run in re.findall(r"0x[0-9A-F]+", line):
            if run not in declared:
                hex_bad.add(run)
    print(f"[{VARIANT} {label}] ROWS OK {n_ok}/{n_rows} | painted 0x runs not declared: {sorted(hex_bad) or 'none'}")
    return n_ok == n_rows and not hex_bad, w, visible


async def settle(pilot, n=20):
    for _ in range(n):
        await pilot.pause()


async def load(app, pilot, base, a2l_text):
    a2l = base / "syn.a2l"; a2l.write_text(a2l_text, encoding="utf-8")
    img = base / "syn_img.s19"
    img.write_text(emit_s19_from_mem_map({ADDR + i: (i * 7) & 0xFF for i in range(MAP_LEN)}, [(ADDR, ADDR + MAP_LEN)]),
                   encoding="ascii")
    await pilot.pause()
    app.load_selected_file(img)
    for _ in range(400):
        await pilot.pause()
        if app.current_file is not None and app.current_file.path.name == img.name:
            break
    app.load_a2l_from_path(a2l)
    await app.workers.wait_for_complete()
    await settle(pilot)


async def explorer(app, pilot):
    await pilot.press("2")
    await settle(pilot)
    table = app.query_one("#a2l_tags_list", DataTable)
    table.focus()
    if table.row_count:
        table.move_cursor(row=0)
    await settle(pilot, 10)
    return table


def card_first_line(app):
    lines = [ln.rstrip() for ln in painted(app.query_one("#a2l_detail_card")) if ln.strip()]
    return lines[0] if lines else ""


async def one(label, a2l_and_declared, size, scrolled=False, show_rows=3, card=False):
    text, declared = a2l_and_declared
    base = scratch / f"{VARIANT}_{SCEN}_{re.sub(r'[^A-Za-z0-9]+', '_', label)}"
    base.mkdir(parents=True, exist_ok=True)
    for k in COUNT:
        COUNT[k] = 0
    app = S19TuiApp(base_dir=base)
    async with app.run_test(size=size) as pilot:
        await load(app, pilot, base, text)
        table = await explorer(app, pilot)
        ok0, w, vis = report(app, table, f"{label} {size[0]}x{size[1]} unscrolled", declared, show_rows)
        if card:
            card_lines = [ln.rstrip() for ln in painted(app.query_one("#a2l_detail_card")) if ln.strip()]
            print(f"[{VARIANT} {label}] card width={app.query_one('#a2l_detail_card').size.width}")
            for ln in card_lines[:4]:
                print(f"[{VARIANT} {label}] card| {ln}")
            for ln in painted(app.query_one("#a2l_detail_card")):
                for run in re.findall(r"0x[0-9A-F]+", ln):
                    if run not in declared:
                        print(f"[{VARIANT} {label}] card 0x run not declared: {run}")
        ok1 = None
        if scrolled:
            table.scroll_to(x=table.max_scroll_x, animate=False)
            await settle(pilot, 10)
            ok1, _, _ = report(app, table, f"{label} {size[0]}x{size[1]} scrolled-right", declared, show_rows,
                               check_form=False)
        return ok0, ok1


async def scen_resize():
    for label, page, cursor_to in (("LONGMAP(48)", page_long(48), 0), ("PAGE64(48)", page64(48), 2)):
        text, declared = page
        base = scratch / f"{VARIANT}_resize_{label[:6]}"
        base.mkdir(parents=True, exist_ok=True)
        for k in COUNT:
            COUNT[k] = 0
        app = S19TuiApp(base_dir=base)
        async with app.run_test(size=(220, 60)) as pilot:
            await load(app, pilot, base, text)
            table = await explorer(app, pilot)
            table.move_cursor(row=cursor_to)
            await settle(pilot, 10)
            report(app, table, f"resize {label} start 220x60", declared)
            if cursor_to:
                table.scroll_to(x=table.max_scroll_x, animate=False)
                await settle(pilot, 10)
                print(f"[{VARIANT} resize {label}] scrolled right at 220: scroll_x={int(table.scroll_x)}")
            await pilot.resize_terminal(80, 54)
            await settle(pilot, 30)
            report(app, table, f"resize {label} after 220->80", declared, check_form=not cursor_to)
            if cursor_to:
                table.scroll_to(x=0, animate=False)
                await settle(pilot, 10)
                report(app, table, f"resize {label} after 220->80, scroll_x set to 0", declared)
            await pilot.resize_terminal(220, 60)
            await settle(pilot, 30)
            if cursor_to:
                table.scroll_to(x=0, animate=False)
                await settle(pilot, 10)
            report(app, table, f"resize {label} back 80->220", declared)
            print(f"[{VARIANT} resize {label}] keys pressed after the first paint: none (pilot.resize_terminal only)")


async def scen_flip():
    text, declared = page_many(230, 48, wide_at=215)
    base = scratch / f"{VARIANT}_flip"
    base.mkdir(parents=True, exist_ok=True)
    for k in COUNT:
        COUNT[k] = 0
    app = S19TuiApp(base_dir=base)
    async with app.run_test(size=(80, 54)) as pilot:
        await load(app, pilot, base, text)
        table = await explorer(app, pilot)
        report(app, table, "flip page1 (200 rows) 80x54", declared, show_rows=2)
        await pilot.press("plus")
        await settle(pilot, 30)
        report(app, table, "flip page2 (31 rows, one 64-bit address) 80x54", declared, show_rows=2)
        await pilot.press("minus")
        await settle(pilot, 30)
        report(app, table, "flip back to page1 80x54", declared, show_rows=2)
        # timing of one page build and one no-op fit, on the shown 200-row page
        times, fits = [], []
        for _ in range(5):
            t0 = time.perf_counter(); app.update_a2l_tags_view(app._a2l_filtered_tags); times.append(time.perf_counter() - t0)
            await settle(pilot, 10)
            if HAS_FIT:
                t0 = time.perf_counter(); app._fit_a2l_tag_cells(); fits.append(time.perf_counter() - t0)
        times.sort(); fits.sort()
        print(f"[{VARIANT} flip timing] 200-row page build median {times[2] * 1000:.1f} ms (5 runs: "
              + ", ".join(f"{t * 1000:.1f}" for t in times) + ")"
              + (f"; no-op fit median {fits[2] * 1000:.1f} ms" if fits else ""))


async def scen_flipbar():
    """220 tags, 32-bit addresses only: page 1 has 200 rows (vertical scrollbar), page 2 has 21 (none)."""
    text, declared = page_many(219, 48)
    base = scratch / f"{VARIANT}_flipbar"
    base.mkdir(parents=True, exist_ok=True)
    for k in COUNT:
        COUNT[k] = 0
    app = S19TuiApp(base_dir=base)
    async with app.run_test(size=(80, 54)) as pilot:
        await load(app, pilot, base, text)
        table = await explorer(app, pilot)
        report(app, table, "flipbar page1 (200 rows) 80x54", declared, show_rows=1)
        await pilot.press("plus")
        await settle(pilot, 30)
        report(app, table, "flipbar page2 (20 rows) 80x54", declared, show_rows=1)
        await pilot.press("minus")
        await settle(pilot, 30)
        report(app, table, "flipbar back to page1 (200 rows) 80x54", declared, show_rows=1)


async def scen_rehide():
    """Shown at 80x54, hidden (key 1), the A2L reloaded while hidden, shown again at the SAME size (key 2)."""
    text, declared = page_long(48)
    base = scratch / f"{VARIANT}_rehide"
    base.mkdir(parents=True, exist_ok=True)
    for k in COUNT:
        COUNT[k] = 0
    app = S19TuiApp(base_dir=base)
    resizes = []
    async with app.run_test(size=(80, 54)) as pilot:
        await load(app, pilot, base, text)
        table = await explorer(app, pilot)
        # patched on DataTable itself: Textual dispatches ONE of _on_resize / on_resize per class in the MRO, so a
        # spy put on the A2LTagTable subclass would shadow that subclass's own on_resize
        orig = DataTable._on_resize

        def spy(self, event, _orig=orig):
            if self.id == "a2l_tags_list":
                resizes.append((tuple(event.size), self.scrollable_content_region.width))
            return _orig(self, event)

        DataTable._on_resize = spy
        report(app, table, "rehide shown 80x54", declared, show_rows=1)
        await pilot.press("1")
        await settle(pilot)
        print(f"[{VARIANT} rehide] hidden: region width {table.scrollable_content_region.width}, size {tuple(table.size)}")
        app.load_a2l_from_path(base / "syn.a2l")
        await app.workers.wait_for_complete()
        await settle(pilot)
        print(f"[{VARIANT} rehide] reloaded while hidden: Tag cell {table.get_row_at(0)[2].plain!r} builds={COUNT['build']}")
        await pilot.press("2")
        await settle(pilot)
        report(app, table, "rehide shown again 80x54", declared, show_rows=1)
        print(f"[{VARIANT} rehide] table Resize events after the first paint (size, visible): {resizes}")


async def main():
    if SCEN == "syn":
        for wd in (220, 160, 118, 100, 80):
            await one(f"SYNMAP W{wd}", page_syn(), (wd, 50), card=True, show_rows=1)
    elif SCEN == "long":
        for n, wd, ht in ((46, 118, 54), (48, 118, 54), (50, 118, 54), (54, 118, 54), (100, 220, 60), (34, 118, 54),
                          (35, 118, 54), (48, 80, 54), (48, 95, 54), (48, 100, 54), (20, 80, 54), (48, 220, 60)):
            await one(f"LONGMAP({n})", page_long(n), (wd, ht), card=(n == 48 and wd == 118), show_rows=1)
    elif SCEN == "long-few":
        for n, wd, ht in ((48, 118, 54), (48, 80, 54)):
            await one(f"LONGMAP({n})", page_long(n), (wd, ht), show_rows=1)
    elif SCEN == "p64":
        tot = {"n": 0, "u": 0, "s": 0}
        for n in (20, 28, 34, 48, 100):
            for wd in (80, 85, 90, 95, 100, 118, 160, 220):
                ok0, ok1 = await one(f"PAGE64({n})", page64(n), (wd, 54), scrolled=True,
                                     show_rows=3 if n == 48 and wd in (80, 95, 100, 118, 220) else 0)
                tot["n"] += 1; tot["u"] += int(ok0); tot["s"] += int(bool(ok1))
        print(f"[{VARIANT} p64 SUMMARY] cases={tot['n']} rows all OK unscrolled={tot['u']}/{tot['n']} "
              f"Address+Length whole after scroll-right={tot['s']}/{tot['n']}")
    elif SCEN == "p64-few":
        for wd in (80, 118):
            await one("PAGE64(48)", page64(48), (wd, 54), scrolled=True)
    elif SCEN == "p64w":
        await one("PAGE64W(48)", page64(48, wide16=True), (80, 54), scrolled=True, show_rows=4)
    elif SCEN == "resize":
        await scen_resize()
    elif SCEN == "flip":
        await scen_flip()
    elif SCEN == "flipbar":
        await scen_flipbar()
    elif SCEN == "rehide":
        await scen_rehide()
    elif SCEN == "order":
        base = scratch / f"{VARIANT}_order"
        base.mkdir(parents=True, exist_ok=True)
        app = S19TuiApp(base_dir=base)
        async with app.run_test(size=(118, 54)) as pilot:
            await load(app, pilot, base, page_syn()[0])
            table = await explorer(app, pilot)
            labels = [str(c.label) for c in table.ordered_columns]
            print(f"[{VARIANT} order] ordered_columns labels ({len(labels)}): {labels}")
            print(f"[{VARIANT} order] header line starts with 'Address' at column {painted(table)[0].find('Address')}"
                  f" | header| {painted(table)[0].rstrip()}")
    else:
        raise SystemExit(f"unknown scenario {SCEN}")


asyncio.run(main())
