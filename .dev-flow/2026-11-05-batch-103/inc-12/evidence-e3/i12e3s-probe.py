"""Inc 12 E3 security (batch-103), runner only. Synthetic names only; the corpus census prints counts only.

    python -I i12e3s-probe.py <repo> <scratch> <variant> <scenario>

<repo>: the read-only clone (variant `base`, e07fb00) or the throwaway copy patched by Inc 12 E2's i12e2-mkproto.py
(variant `design`, the graph's prototype as E2 measured it). The probe never writes into <repo>; it wraps
update_a2l_tags_view / _fit_a2l_tag_cells with counters in this process only.
Scenarios: units, collide, hostile, zwcost:<n>, longcost:<n>, flood.
"""
import asyncio
import os
import pathlib
import re
import subprocess
import sys
import time
import unicodedata

repo = pathlib.Path(sys.argv[1]); scratch = pathlib.Path(sys.argv[2]); VARIANT = sys.argv[3]; SCEN = sys.argv[4]
sys.path.insert(0, str(repo))
import s19_app  # noqa: E402
import textual  # noqa: E402
import importlib.metadata as _md  # noqa: E402

print("s19_app.__file__ =", re.sub(r"^/home/[^/]+", "~", s19_app.__file__), "| textual", textual.__version__,
      "| rich", _md.version("rich"), "| variant", VARIANT, "| scenario", SCEN)
from rich.cells import cell_len  # noqa: E402
from textual import events  # noqa: E402
from textual.geometry import Size  # noqa: E402
from textual.widgets import DataTable  # noqa: E402

import s19_app.tui.app as appmod  # noqa: E402
from s19_app.tui.app import S19TuiApp  # noqa: E402
from s19_app.tui.changes.io import emit_s19_from_mem_map  # noqa: E402
from s19_app.utils import safe_text  # noqa: E402

SHORTEN = getattr(appmod, "_shorten_tag_name", None)
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

OPENS = "‪‫‭‮⁦⁧⁨"  # LRE RLE LRO RLO LRI RLI FSI
CLOSES = "‬⁩"  # PDF PDI
ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def vis(s):
    """Printable view of a string: every character outside U+0020..U+007E (and the app's own glyphs) as <U+XXXX>."""
    return "".join(c if (0x20 <= ord(c) < 0x7F or c in "✓·…") else f"<U+{ord(c):04X}>" for c in s)


def nbidi(s):
    return sum(s.count(c) for c in OPENS), sum(s.count(c) for c in CLOSES)


ADDR, NX, NY = 0x1C2D3E00, 87, 13
MAP_LEN = 2 + 2 + NX * NY * 2
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


def meas(name, addr, dtype="UWORD"):
    return (f'/begin MEASUREMENT {name} "synthetic"\n  {dtype} CM_SYN 0 0 0 65535\n'
            f"  ECU_ADDRESS 0x{addr:08X}\n/end MEASUREMENT\n")


def name_of(prefix, n):
    return (prefix + ALNUM * 4)[:n]


def painted(widget):
    return [widget.render_line(y).text.rstrip("\n") for y in range(widget.size.height)]


def report(app, table, label, check_form=True, show_rows=2):
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
    print(f"[{VARIANT} {label}] visible={visible} scroll_x={sx}/{int(table.max_scroll_x)} scroll_y={sy} "
          f"cols: " + ", ".join(f"{lab}={cw}" for lab, cw in cols[:4]) + f" | w={w} | rows={table.row_count} "
          f"cursor_row={table.cursor_row} | builds={COUNT['build']} fits={COUNT['fit']} "
          f"fit_rebuilds={COUNT['fit_rebuild']}")
    tags = list(app._a2l_row_key_to_tag.values())
    n_ok = n_rows = 0
    for r in range(table.row_count):
        y = 1 + r - sy
        if y < 1 or y >= len(lines) - (1 if table.show_horizontal_scrollbar else 0):
            continue
        line = lines[y]
        cells = table.get_row_at(r)
        ok = True
        res = []
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
        inside = tag_end <= visible
        if sx == 0:
            ok &= inside
        if check_form and SHORTEN is not None and r < len(tags):
            name = str(tags[r].get("name") or "UNKNOWN").replace("\n", " ").strip()
            want_tag = safe_text(tagc[:2] + SHORTEN(name, 34 if w >= 34 else w)).plain
            ok &= tagc == want_tag
        n_rows += 1
        n_ok += int(ok)
        if r < show_rows:
            print(f"[{VARIANT} {label}] row{r}| {vis(line.rstrip())}")
            print(f"[{VARIANT} {label}] row{r}: " + "; ".join(res) + f"; Tag ends at {tag_end} "
                  f"({'inside' if inside else 'PAST the visible width'})")
    print(f"[{VARIANT} {label}] ROWS OK {n_ok}/{n_rows}")
    return n_ok == n_rows, w


async def settle(pilot, n=20):
    for _ in range(n):
        await pilot.pause()


def write_files(base, a2l_text):
    a2l = base / "syn.a2l"; a2l.write_text(a2l_text, encoding="utf-8")
    img = base / "syn_img.s19"
    img.write_text(emit_s19_from_mem_map({ADDR + i: (i * 7) & 0xFF for i in range(MAP_LEN)}, [(ADDR, ADDR + MAP_LEN)]),
                   encoding="ascii")
    return a2l, img


async def load(app, pilot, base, a2l_text):
    a2l, img = write_files(base, a2l_text)
    await pilot.pause()
    app.load_selected_file(img)
    for _ in range(400):
        await pilot.pause()
        if app.current_file is not None and app.current_file.path.name == img.name:
            break
    app.load_a2l_from_path(a2l)
    await app.workers.wait_for_complete()
    await settle(pilot)
    return a2l


async def explorer(app, pilot):
    await pilot.press("2")
    await settle(pilot)
    table = app.query_one("#a2l_tags_list", DataTable)
    table.focus()
    if table.row_count:
        table.move_cursor(row=0)
    await settle(pilot, 10)
    return table


def new_app(tag):
    base = scratch / f"{VARIANT}_{tag}"
    base.mkdir(parents=True, exist_ok=True)
    for k in COUNT:
        COUNT[k] = 0
    return S19TuiApp(base_dir=base), base


# --------------------------------------------------------------------------------------------------- units
def scen_units():
    chars = [("ESC", "\x1b"), ("BEL", "\x07"), ("C1 CSI", "\x9b"), ("RLO", "‮"), ("PDF", "‬"),
             ("RLI", "⁧"), ("PDI", "⁩"), ("LRM", "‎"), ("ALM", "؜"), ("ZWSP", "​"),
             ("ZWJ", "‍"), ("WJ", "⁠"), ("BOM", "﻿"), ("LS", " "), ("PS", " "),
             ("SHY", "\xad"), ("COMBINING ACUTE", "́"), ("REPLACEMENT", "�"), ("HANGUL FILLER", "ㅤ"),
             ("HANGUL CHOSEONG FILLER", "ᅟ"), ("FULLWIDTH A", "Ａ"), ("EMOJI", "\U0001f600"),
             ("VS16", "️"), ("TAG LATIN A", "\U000e0041"), ("HEBREW SHIN", "ש"), ("ELLIPSIS", "…")]
    for label, ch in chars:
        print(f"[units char] {label} U+{ord(ch):04X}: category {unicodedata.category(ch)}, bidi class "
              f"{unicodedata.bidirectional(ch) or '-'}, rich cell_len {cell_len(ch)}, safe_text "
              f"{'keeps it' if safe_text(ch).plain == ch else 'deletes it'}")
    if SHORTEN is None:
        print("[units] no _shorten_tag_name in this variant"); return
    for label, name in (("RLO ... PDF", "SYN_RLO_‮" + ALNUM + "‬_END"),
                        ("RLI ... PDI", "SYN_RLI_⁧" + ALNUM + "⁩_END")):
        o, c = nbidi(name)
        for w in (34, 14, 9):
            out = safe_text(SHORTEN(name, w)).plain
            oo, cc = nbidi(out)
            print(f"[units bidi] {label} ({len(name)} code points, {cell_len(name)} cells; opens {o}, closes {c}) "
                  f"w={w} -> {vis(out)!r}: opens {oo}, closes {cc} -> {'UNBALANCED' if oo > cc else 'balanced'}")
    for label, z in (("ZWSP", "​"), ("COMBINING ACUTE", "́"), ("ESC", "\x1b")):
        for n in (500, 1000, 2000, 4000, 8000, 16000):
            name = "SYN_ZW_" + "L" * 40 + z * n
            t0 = time.perf_counter(); out = SHORTEN(name, 34); dt = time.perf_counter() - t0
            print(f"[units cost tail] {n} x {label} at the END of a 47-cell name: _shorten_tag_name(name, 34) "
                  f"{dt * 1000:.1f} ms; painted {cell_len(safe_text(out).plain)} cells")
            if dt > 20:
                break
        name = z * 16000 + "L" * 40
        t0 = time.perf_counter(); SHORTEN(name, 34); dt = time.perf_counter() - t0
        print(f"[units cost head] 16000 x {label} at the START: {dt * 1000:.1f} ms")
    for n in (10_000, 100_000, 1_000_000):
        name = "SYN_" + "L" * n
        t0 = time.perf_counter(); SHORTEN(name, 34); dt = time.perf_counter() - t0
        print(f"[units cost ascii] {n}-character ASCII name: {dt * 1000:.2f} ms")

    def fffd_cut(name, width):  # the fix modelled: U+FFFD outside U+0021..U+007E, then slicing (1 cell per char)
        def p(s):
            return "".join(c if 0x21 <= ord(c) <= 0x7E else "�" for c in s)
        if len(name) <= width:
            return p(name)
        head = (width - 1) // 2
        return p(name[:head]) + "…" + p(name[len(name) - (width - 1 - head):])

    for label, name in (("16000 ZWSP tail", "SYN_ZW_" + "L" * 40 + "​" * 16000),
                        ("1,000,000 ASCII", "SYN_" + "L" * 1_000_000),
                        ("RLO ... PDF", "SYN_RLO_‮" + ALNUM + "‬_END")):
        t0 = time.perf_counter(); out = fffd_cut(name, 34); dt = time.perf_counter() - t0
        print(f"[units fix model] {label}: {dt * 1000:.3f} ms -> {vis(out)!r} ({cell_len(out)} cells)")
    pairs = (("SYN_TORQUE_LIMIT_CYL1_CORRECTION_FACTOR_END", "SYN_TORQUE_LIMIT_CYL2_CORRECTION_FACTOR_END"),
             ("SYN_KL_A_LONG_SHARED_PREFIX_ROW_DIR", "SYN_KL_A_LONG_SHARED_PREFIX_COLUMN_DIR"))
    for a, b in pairs:
        for w in (34, 31, 22, 14, 9, 5):
            sa, sb = SHORTEN(a, w), SHORTEN(b, w)
            print(f"[units collide] {len(a)}/{len(b)}-char pair, w={w}: {sa!r} vs {sb!r} -> "
                  f"{'SAME' if sa == sb else 'distinct'}")


# --------------------------------------------------------------------------------------------------- collide
NAME_RE = re.compile(r"/begin\s+(CHARACTERISTIC|MEASUREMENT)\s+(\"[^\"]*\"|\S+)")


def names_of(path):
    text = path.read_bytes().decode("utf-8", errors="replace")
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"//[^\n]*", " ", text)
    return [m.group(2).strip('"') for m in NAME_RE.finditer(text)]


def census(label, files):
    widths = (34, 31, 29, 23, 20, 14, 12, 9, 7, 5)
    tot = {w: {"long": 0, "file": 0, "page": 0, "files": 0} for w in widths}
    n_names = n_files = 0
    per_file = []
    for f, tagname in files:
        try:
            names = names_of(f)
        except OSError:
            continue
        if not names:
            continue
        n_files += 1
        uniq = list(dict.fromkeys(names))
        n_names += len(uniq)
        row = [tagname, len(uniq)]
        for w in widths:
            short = {nm: SHORTEN(nm, w) for nm in uniq}
            by = {}
            for nm, s in short.items():
                by.setdefault(s, set()).add(nm)
            hit_file = {nm for s, group in by.items() if len(group) > 1 for nm in group}
            hit_page = set()
            pages = {}
            for i, nm in enumerate(names):
                pages.setdefault(i // 200, []).append(nm)
            for pg in pages.values():
                bp = {}
                for nm in dict.fromkeys(pg):
                    bp.setdefault(short[nm], set()).add(nm)
                hit_page |= {nm for group in bp.values() if len(group) > 1 for nm in group}
            tot[w]["long"] += sum(1 for nm in uniq if cell_len(nm) > w)
            tot[w]["file"] += len(hit_file)
            tot[w]["page"] += len(hit_page)
            tot[w]["files"] += int(bool(hit_page))
            row.append(len(hit_page))
        per_file.append(row)
    print(f"[collide {label}] files with tags {n_files}, distinct names {n_names}")
    for w in widths:
        t = tot[w]
        print(f"[collide {label}] w={w}: names shortened {t['long']}; names whose shortened Tag cell equals another "
              f"name's on the SAME 200-row page {t['page']} (in {t['files']} files); file-wide {t['file']}")
    return per_file


def scen_collide():
    clone = pathlib.Path(os.environ["CLONE"])
    tracked = subprocess.run(["git", "-C", str(clone), "ls-files", "*.a2l"], capture_output=True, text=True).stdout.split()
    pf = census("tracked", [(clone / t, t) for t in tracked])
    for row in pf:
        if any(row[2:]):
            print(f"[collide tracked file] {row[0]}: {row[1]} names; same-page collisions at w=34,31,29,23,20,14,12,9,7,5:"
                  f" {row[2:]}")
    corpus = pathlib.Path(os.environ["CORPUS"])
    manifest = {}
    mpath = corpus.parent / "manifest.tsv"
    if mpath.exists():
        for ln in mpath.read_text(encoding="utf-8").splitlines()[1:]:
            parts = ln.split("\t")
            if len(parts) >= 7:
                manifest[parts[6]] = parts[0]
    files = sorted(p for p in corpus.iterdir() if p.is_file())
    import hashlib
    entries = []
    for p in files:
        h = hashlib.sha256(p.read_bytes()).hexdigest()
        entries.append((p, f"n{manifest.get(h, '?')}"))
    census("corpus", entries)


# --------------------------------------------------------------------------------------------------- hostile
H_RLO = "SYN_RLO_‮" + ALNUM + "‬_END"
H_HEB = "SYN_HEB_" + "שם" * 3 + "_END"
H_ESC = "SYN_ESC_\x1b]0;PWNED\x1b\\_END"
H_ZW = "SYN_ZW_" + "​" * 10 + ALNUM + "​" * 10 + "_END"


def screen_sequence(app):
    comp = app.screen._compositor
    upd = comp.render_full_update()
    return upd.render_segments(app.console)


async def scen_hostile():
    text = HEAD + map_block("SYN_MAP_W") + meas(H_RLO, 0x2000) + meas(H_HEB, 0x2010) + meas(H_ESC, 0x2020) \
        + meas(H_ZW, 0x2030) + TAIL
    for size in ((118, 54), (80, 54)):
        app, base = new_app(f"hostile_{size[0]}")
        async with app.run_test(size=size) as pilot:
            await load(app, pilot, base, text)
            table = await explorer(app, pilot)
            report(app, table, f"hostile {size[0]}x{size[1]}", check_form=True, show_rows=5)
            lines = painted(table)
            card = app.query_one("#a2l_detail_card")
            for r in range(table.row_count):
                tag = list(app._a2l_row_key_to_tag.values())[r]
                line = lines[1 + r]
                m = re.search(r"0x[0-9A-F]+", line)
                first_ctl = min([line.find(c) for c in OPENS if c in line] or [-1])
                o, c = nbidi(line)
                print(f"[{VARIANT} hostile {size[0]}] row{r} name {vis(tag.get('name'))!r}: Address at x "
                      f"{m.start() if m else None}, first bidi opener at x {first_ctl}; painted line opens {o} closes {c}"
                      f"{' -> UNBALANCED to the end of the screen row' if o > c else ''}")
                table.move_cursor(row=r)
                await settle(pilot, 8)
                y_screen = table.region.y + 1 + r - int(table.scroll_y)
                ci = y_screen - card.region.y
                cl = painted(card)
                same_row = cl[ci] if 0 <= ci < len(cl) else "(no card line)"
                seq = screen_sequence(app)
                print(f"[{VARIANT} hostile {size[0]}] row{r} cursor: card lines "
                      f"{[vis(x.rstrip()) for x in cl if x.strip()][:3]}; card line on the same screen row: "
                      f"{vis(same_row.rstrip())!r}; terminal output holds ESC ]0;PWNED: "
                      f"{'YES' if chr(27) + ']0;PWNED' in seq else 'no'}; RLO {seq.count(chr(0x202E))} "
                      f"PDF {seq.count(chr(0x202C))}; U+200B {seq.count(chr(0x200B))}")


# --------------------------------------------------------------------------------------------------- cost
async def scen_cost(name, label):
    text = HEAD + map_block("SYN_MAP_W") + meas(name, 0x2000) + TAIL
    app, base = new_app(label)
    async with app.run_test(size=(118, 54)) as pilot:
        t0 = time.perf_counter()
        await load(app, pilot, base, text)
        t1 = time.perf_counter()
        table = await explorer(app, pilot)
        t2 = time.perf_counter()
        print(f"[{VARIANT} {label}] load+build {t1 - t0:.2f} s; key 2 (show, fit) {t2 - t1:.2f} s; builds "
              f"{COUNT['build']} fits {COUNT['fit']} fit_rebuilds {COUNT['fit_rebuild']}")
        for wd, ht in ((80, 54), (118, 54), (100, 54)):
            t0 = time.perf_counter()
            await pilot.resize_terminal(wd, ht)
            await settle(pilot, 15)
            dt = time.perf_counter() - t0
            print(f"[{VARIANT} {label}] resize to {wd}x{ht}: {dt:.2f} s; builds {COUNT['build']} fits {COUNT['fit']} "
                  f"fit_rebuilds {COUNT['fit_rebuild']}; Tag cell {cell_len(table.get_row_at(1)[2 if HAS_FIT else 0].plain)}"
                  f" cells")
        report(app, table, label, check_form=False, show_rows=0)


# --------------------------------------------------------------------------------------------------- flood
SIZES = ((80, 54), (220, 60), (100, 54), (160, 54), (118, 54), (95, 54))


def burst(app, n, start=0):
    for i in range(n):
        size = Size(*SIZES[(start + i) % len(SIZES)])
        app._driver._size = size
        app.post_message(events.Resize(size, size))


def identity(app, table):
    start = app._a2l_window_start
    bad = 0
    for r in range(table.row_count):
        key = f"a2l:{start + r}"
        tag = app._a2l_row_key_to_tag.get(key)
        if tag is not app._a2l_filtered_tags[start + r]:
            bad += 1
            continue
        addr = tag.get("address")
        if table.get_row_at(r)[0].plain != (f"0x{addr:08X}" if isinstance(addr, int) else "n/a"):
            bad += 1
    return bad


async def scen_flood():
    body = map_block("SYN_MAP_" + "L" * 36 + "_END")
    for i in range(229):
        body += meas(name_of(f"SYN_M{i:03d}_", 48), 0x2000 + 2 * i)
    app, base = new_app("flood")
    async with app.run_test(size=(220, 60)) as pilot:
        a2l = await load(app, pilot, base, HEAD + body + TAIL)
        table = await explorer(app, pilot)
        table.move_cursor(row=150)
        await settle(pilot, 10)
        table.scroll_to(x=table.max_scroll_x, animate=False)
        await settle(pilot, 10)
        card = app.query_one("#a2l_detail_card")
        print(f"[{VARIANT} flood] start 220x60: cursor_row {table.cursor_row}, scroll_x {int(table.scroll_x)}/"
              f"{int(table.max_scroll_x)}, scroll_y {int(table.scroll_y)}")
        for k in COUNT:
            COUNT[k] = 0

        async def phase(label, final_settle=60):
            t0 = time.perf_counter()
            await settle(pilot, final_settle)
            dt = time.perf_counter() - t0
            cur = table.cursor_row
            key = f"a2l:{app._a2l_window_start + cur}"
            want = str(app._a2l_row_key_to_tag[key]["name"])
            card_plain = card.render().plain if hasattr(card.render(), "plain") else str(card.render())
            print(f"[{VARIANT} flood {label}] settled in {dt:.2f} s; size {tuple(app.size)}; cursor_row {cur} "
                  f"(window start {app._a2l_window_start}); scroll_x {int(table.scroll_x)}/{int(table.max_scroll_x)} "
                  f"scroll_y {int(table.scroll_y)}; card shows the cursor row's full name: "
                  f"{'yes' if want in card_plain.replace(chr(10), '') else 'NO'}; row/tag identity mismatches "
                  f"{identity(app, table)}")
            table.scroll_to(x=0, animate=False)
            await settle(pilot, 8)
            report(app, table, f"flood {label} (scroll_x set to 0 for the check)", check_form=True, show_rows=1)
            for k in COUNT:
                COUNT[k] = 0

        t0 = time.perf_counter(); burst(app, 41); print(f"[{VARIANT} flood A] 41 Resize posted, no pause "
                                                          f"({(time.perf_counter() - t0) * 1000:.1f} ms)")
        await phase("A (burst of 41, ends 100x54)")
        table.move_cursor(row=150); table.scroll_to(x=table.max_scroll_x, animate=False); await settle(pilot, 8)
        t0 = time.perf_counter()
        for i in range(20):
            await pilot.resize_terminal(*SIZES[i % 2])
        print(f"[{VARIANT} flood B] 20 pilot.resize_terminal 80/220 alternating, one pause each: "
              f"{time.perf_counter() - t0:.2f} s; builds {COUNT['build']} fits {COUNT['fit']} "
              f"fit_rebuilds {COUNT['fit_rebuild']}")
        await phase("B (ends 220x60)")
        table.move_cursor(row=150); await settle(pilot, 8)
        burst(app, 10)
        await pilot.press("plus")
        burst(app, 10, 3)
        app.load_a2l_from_path(a2l)
        burst(app, 11, 1)
        await app.workers.wait_for_complete()
        await phase("C (bursts around a page change and a reload, ends 220x60)")


async def main():
    if SCEN == "units":
        scen_units()
    elif SCEN == "collide":
        scen_collide()
    elif SCEN == "hostile":
        await scen_hostile()
    elif SCEN.startswith("zwcost:"):
        n = int(SCEN.split(":")[1])
        await scen_cost("SYN_ZW_" + "L" * 40 + "​" * n, f"zwcost {n} ZWSP at the end of the name")
    elif SCEN.startswith("longcost:"):
        n = int(SCEN.split(":")[1])
        await scen_cost("SYN_" + "L" * n, f"longcost {n}-character ASCII name")
    elif SCEN == "flood":
        await scen_flood()
    else:
        raise SystemExit(f"unknown scenario {SCEN}")


asyncio.run(main())
