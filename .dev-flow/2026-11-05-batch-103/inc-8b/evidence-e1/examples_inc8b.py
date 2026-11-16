"""Inc 8b E1 (batch-103): computes the examples the Inc 8b rows and graph nodes cite.

Spec-side oracle: the formulas of CTX-PE-DEF and CTX-PE-BENCH as amended in ../01-requirements.md,
written from the requirements, standard library only. It imports nothing from s19_app and reads no
file, so it runs anywhere (HT-01: no product code runs on the main PC):

    python -I -B examples_inc8b.py > examples_inc8b-transcript.txt

On Windows (UTF-8 and LF, PF-05; E3R1 regenerated it this way):

    python -I -B -c "import sys, runpy; sys.stdout.reconfigure(encoding='utf-8', newline='\\n'); runpy.run_path('examples_inc8b.py', run_name='__main__')" > examples_inc8b-transcript.txt

Output: one line per fact, `KEY = value` (values are repr() so spaces and glyphs are exact).
Data: DEFC = tools/synth/make_release_case.py --case definitions, seed 20260001 (facts copied from
../../inc-8/evidence-e1/pilot_inc8-transcript.txt and ../../inc-9/codewire/graph-inc9.md EX-A1..A3);
V171 = examples/case_00_public/ASAP2_Demo_V171.a2l with the Inc 8 pilot's hand image.
Rounding: Python's round() (half to even), as the shipped code uses it.
"""
from __future__ import annotations

import math
import struct
import unicodedata

# --------------------------------------------------------------------------- grid (CTX-PE-DEF grid widths)

MARK = 2
COLUMNS = (("Parameter", 26), ("Kind", 10), ("Current", 20), ("New", 16), ("Unit", 8), ("Limits", 34), ("Δ", 20))
SLOT = 7          # a limit slot: 6 cells of number, right-aligned, then 1 unit-letter cell
TRACK = 34 - 2 * SLOT - 2   # the Limits width minus two slots and two spaces = 18
BLOCKS7 = "▁▂▃▄▅▆▇"        # strip levels 1..7 (F-R14-1: never the full block)
BLOCKS8 = "▁▂▃▄▅▆▇█"       # Inc 9's levels 1..8, for the before/after record
# E3R1: a FLOAT32_IEEE word read from erased flash (`FF FF FF FF`, big-endian) decodes to NaN
ERASED_FLOAT32 = struct.unpack(">f", bytes.fromhex("FFFFFFFF"))[0]


def out(key: str, value: object) -> None:
    print(f"{key} = {value!r}")


def column_starts() -> list[tuple[str, int, int]]:
    """(label, start, width): each column starts after the previous one and its gutter."""
    starts, x = [], MARK
    for label, width in COLUMNS:
        starts.append((label, x, width))
        x += width + 1
    return starts


def grid_width() -> int:
    return MARK + sum(w + 1 for _, w in COLUMNS)


def header_line() -> str:
    return " " * MARK + "".join(label.ljust(w)[:w] + "│" for label, w in COLUMNS)


def header_rule() -> str:
    return "━" * MARK + "".join("━" * w + "┿" for _, w in COLUMNS)


def scroll_end(view: int) -> int:
    return max(0, grid_width() - view)


# --------------------------------------------------------------------------- cells (CTX-PE-DEF plain text, clip)


def plain(text: str) -> str:
    return "".join("�" if (ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F) else c for c in text)


def cells(char: str) -> int:
    return 2 if unicodedata.east_asian_width(char) in ("W", "F") else 1


def width_of(text: str) -> int:
    return sum(cells(c) for c in text)


def clip(text: str, width: int) -> str:
    """The longest start that fits in width-1 cells, then `…` (a bounded prefix is scanned)."""
    head = plain(text[: width * 4 + 16])
    if width_of(head) <= width and len(text) <= width * 4 + 16:
        return head
    keep, total = 0, 0
    for index, char in enumerate(head):
        total += cells(char)
        if total > width - 1:
            break
        keep = index + 1
    return head[:keep] + "…"


def fit(text: str, width: int) -> str:
    text = clip(text, width)
    return text + " " * (width - width_of(text))


# --------------------------------------------------------------------------- numbers (CTX-PE-DEF short number, slot)


def short_number(x: float) -> str:
    if x != x or x in (math.inf, -math.inf):
        return str(x)
    if abs(x) < 1000:
        r = round(x, 1)
        return str(int(r)) if float(r).is_integer() else str(r)
    units = ((1e3, "k"), (1e6, "M"), (1e9, "G"))
    for index, (div, suffix) in enumerate(units):
        mantissa = abs(x) / div
        decimals = 2 if mantissa < 9.995 else 1 if mantissa < 99.95 else 0
        text = f"{x / div:.{decimals}f}"
        if abs(float(text)) < 1000:
            return text + suffix
        if index + 1 == len(units):
            return f"{x / div:.2e}{suffix}"
    raise AssertionError


def exponent_form(x: float) -> str:
    """One significant digit, `<d>e<exp>`: 4.29e12 -> 4e12; -1.7e308 -> -2e308."""
    mantissa, exponent = f"{x:.0e}".split("e")
    return f"{mantissa}e{int(exponent)}"


def slot_text(x: float) -> str:
    text = short_number(x)
    return text if len(text) <= 6 else exponent_form(x)


def slot(x: float) -> str:
    """7 cells: the number right-aligned in 6, its unit letter (k M G) in the 7th, else a space."""
    text = slot_text(x)
    if text[-1:] in ("k", "M", "G"):
        return text[:-1].rjust(6) + text[-1]
    return text.rjust(6) + " "


def track_index(v: float, lower: float, upper: float) -> tuple[int, bool]:
    if v < lower:
        return 0, True
    if v > upper:
        return TRACK - 1, True
    pos = position(v, lower, upper)
    return min(TRACK - 2, max(1, 1 + int(round(pos * (TRACK - 3))))), False


def position(v: float, lower: float, upper: float) -> float:
    """E4 (R-PE-DEF.117): (v - lower)/(upper - lower) computed on halves, so a finite span never overflows."""
    return (v / 2 - lower / 2) / (upper / 2 - lower / 2)


def as_float(x) -> float:
    """E4 (R-PE-DEF.117): a limit as a float; an integer beyond the float range is +-inf."""
    try:
        return float(x)
    except OverflowError:
        return math.inf if x > 0 else -math.inf


def range_form(lower, upper) -> str:
    """Both slots, the track slot blank but for `…` at its centre; `-` there when a limit is missing."""
    middle = (TRACK - 1) // 2
    if lower is None or upper is None:
        return " " * SLOT + " " + " " * middle + "-" + " " * (TRACK - middle - 1) + " " + " " * SLOT
    return slot(lower) + " " + " " * middle + "…" + " " * (TRACK - middle - 1) + " " + slot(upper)


def no_position_form(lower, upper) -> str:
    """E3R1 (R-PE-DEF.114): both slots and the bare track, `?` at its cell 8 (offset 16), no mark."""
    middle = (TRACK - 1) // 2
    track = "├" + "─" * (middle - 1) + "?" + "─" * (TRACK - middle - 2) + "┤"
    return slot(lower) + " " + track + " " + slot(upper)


def position_is_finite(value, lower, upper) -> bool:
    """A value in range has a position (v - lower)/(upper - lower); a value beyond an end has none."""
    if not math.isfinite(value):
        return False
    if value < lower or value > upper:
        return True
    return math.isfinite(position(value, lower, upper))


def limits_cell(lower, upper, current=None, new=None) -> str:
    if lower is None or upper is None:
        return range_form(None, None)
    finite = all(math.isfinite(v) for v in (lower, upper))
    if not finite or not upper > lower:
        return range_form(lower, upper)
    if not all(position_is_finite(v, lower, upper) for v in (current, new) if v is not None):
        return no_position_form(lower, upper)
    track = ["├"] + ["─"] * (TRACK - 2) + ["┤"]
    taken = None
    for value, glyph in ((current, "●"), (new, "◆")):
        if value is None:
            continue
        index, beyond = track_index(value, lower, upper)
        if index == taken and not beyond:
            index = index + 1 if index + 1 <= TRACK - 2 else index - 1
        track[index] = "◀" if beyond and index == 0 else "▶" if beyond else glyph
        taken = index
    return slot(lower) + " " + "".join(track) + " " + slot(upper)


def offsets(cell: str) -> dict:
    return {g: cell.index(g) for g in "├┤…-" if g in cell}


def marks(cell: str) -> dict:
    return {g: cell.index(g) for g in "●◆◀▶?" if g in cell}


# --------------------------------------------------------------------------- strips (CTX-PE-BENCH array row cells)


def level_index(v: float, lo: float, hi: float, levels: int) -> int:
    t = 0.0 if lo == hi else (v - lo) / (hi - lo)
    return round(t * (levels - 1))


def chart_strip(values, width: int, blocks: str) -> str:
    lo, hi = min(values), max(values)
    k = max(1, math.ceil(len(values) / width))
    return "".join(blocks[level_index(values[p], lo, hi, len(blocks))] for p in range(0, len(values), k))


def grid_strip(values, nx: int, ny: int, width: int, blocks: str) -> str:
    lo, hi = min(values), max(values)
    k = max(1, math.ceil(nx / width))
    out_ = []
    for column in range(0, nx, k):
        col = [values[column + nx * row] for row in range(ny) if column + nx * row < len(values)]
        out_.append(blocks[level_index(sum(col) / len(col), lo, hi, len(blocks))])
    return "".join(out_)


def ramp_steps(values, nx: int, ny: int) -> list[int]:
    lo, hi = min(values), max(values)
    steps = []
    for column in range(nx):
        col = [values[column + nx * row] for row in range(ny)]
        steps.append(min(11, max(0, round((sum(col) / len(col) - lo) / (hi - lo) * 11))))
    return steps


# --------------------------------------------------------------------------- cards (CTX-PE-DEF bit table, hex grid)


def hex_bytes(data) -> str:
    return " ".join(f"{b:02X}" for b in data)


def bit_table(word_before: bytes, word_after: bytes, mask: int, order: str = "big") -> list[str]:
    bits = 8 * len(word_before)
    before = int.from_bytes(word_before, order)
    after = int.from_bytes(word_after, order)
    lines = []
    for block, high in enumerate(range(bits - 1, -1, -16)):
        span = [b for b in range(high, max(-1, high - 16), -1)]
        first = block == 0
        head, bef, msk, aft = "bit    ", "before ", "mask   ", "after  "
        for b in span:
            head += f"{b:>3}"
            bef += f"{(before >> b) & 1:>3}"
            msk += "  ■" if (mask >> b) & 1 else "  ·"
            aft += f"{(after >> b) & 1:>3}"
            if b % 4 == 0:
                head, bef, msk, aft = head + " │", bef + " │", msk + " │", aft + " │"
        if first:
            head += " hex"
            bef += " " + hex_bytes(word_before)
            msk += " " + f"{mask:0{2 * len(word_before)}X}"
            aft += " " + hex_bytes(word_after)
        lines += [head, bef, msk, aft]
    return lines


def changed_bits(word_before: bytes, word_after: bytes, order: str = "big") -> list[int]:
    a, b = int.from_bytes(word_before, order), int.from_bytes(word_after, order)
    return [bit for bit in range(8 * len(word_before) - 1, -1, -1) if ((a ^ b) >> bit) & 1]


def ascii_of(b: int) -> str:
    return chr(b) if 0x20 <= b <= 0x7E else "·"


def hex_grid(before: bytes, after: bytes) -> list[str]:
    shown = min(len(after), 64)
    head = "off │" + "".join(f" +{c:X}" + (" │" if c == 7 else "") for c in range(16)) + " │ ASCII"
    rows = [head]
    for off in range(0, shown, 16):
        line = f"+{off:02X} │"
        for c in range(16):
            i = off + c
            line += f" {after[i]:02X}" if i < shown else "   "
            if c == 7:
                line += " │"
        line += " │ " + "".join(ascii_of(after[i]) for i in range(off, min(off + 16, shown)))
        rows.append(line)
    if len(after) > 64:
        rows.append(f"… {len(after) - 64} more B")
    return rows


def card(title: str, rows: list[str], cap: int) -> list[str]:
    inner = min(cap - 2, max([width_of(r) for r in rows] + [width_of(title) + 4]) + 2)
    title = clip(title, inner - 4)
    top = "╭─ " + title + " " + "─" * (inner - width_of(title) - 3) + "╮"
    body = ["│ " + fit(r, inner - 2) + " │" for r in rows]
    return [top] + body + ["╰" + "─" * inner + "╯"]


# --------------------------------------------------------------------------- the facts


def main() -> None:
    G = grid_width()
    out("G.grid_width", G)
    for label, start, width in column_starts():
        out(f"G.start.{label}", start)
        out(f"G.gutter_after.{label}", start + width)
    out("G.header_line", header_line())
    out("G.header_rule", header_rule())
    out("G.header_rule.len", len(header_rule()))
    # E4: the product's view width at 80x24, 118x54, 220x60, measured through the real Patch Editor on base
    # 48af05ff and on the merged tree (inc-8b/evidence-e4/i8b/probe-geometry-*.txt); E1 assumed 73, 111, 195.
    for cols, view in ((80, 70), (118, 110), (220, 194)):
        out(f"G.view.{cols}cols", view)
        out(f"G.scrollbar.{cols}cols", G > view)
        out(f"G.end.{cols}cols", scroll_end(view))
    out("G.detail_cap.V111", max(G, 111) - 4)
    out("G.detail_cap.V195", max(G, 195) - 4)
    # row window: body content height h -> visible h-2, room h-3
    for h in (8, 9, 20):
        out(f"W.visible.h{h}", h - 2)
        out(f"W.room.h{h}", h - 3)
    out("W.standin_10_detail.h8.painted", min(10, (8 - 2) - 1))
    # E3R1 (E3-8b-05): the test host (SheetApp, no chrome) at 118x54 with W2's height rules:
    # sheet 54 rows -> grid scroller 53 (the formula bar takes 1) -> body 52 (the scrollbar takes 1)
    sheet_h = 54
    grid_h = sheet_h - 1
    body_h = grid_h - 1
    out("W.harness_118x54.sheet", sheet_h)
    out("W.harness_118x54.grid", grid_h)
    out("W.harness_118x54.body", body_h)
    out("W.harness_118x54.visible", body_h - 2)
    out("W.harness_118x54.room", body_h - 3)
    # E3R1 (E3-8b-02): _detail_geometry() = (V - 4, room) with room = body height - 3
    for view, h in ((111, 20), (73, 8), (195, 20)):
        out(f"W.detail_geometry.V{view}.h{h}", (view - 4, h - 3))
    # the base's _bench_geometry: the body's own width (143 once it is width auto, or V when wider)
    # and visible = h - 1, room = h - 2
    out("W.bench_geometry.base.V111.h20", (max(G, 111), 20 - 2))
    out("W.bench_geometry.base.V73.h8", (max(G, 73), 8 - 2))

    # clip of hostile cells
    name = "温度" * 14
    c = fit(name, 26)
    out("C.name_wide.fit26", c)
    out("C.name_wide.fit26.cells", width_of(c))
    out("C.name_wide.fit26.kept_chars", len(c.rstrip(" …")))
    u = fit("温度温度温度", 8)
    out("C.unit_wide.fit8", u)
    out("C.unit_wide.fit8.cells", width_of(u))
    e = fit("1 " + "X" * 300, 20)
    out("C.enum_long.current20", e)
    out("C.name_esc.fit26", fit("A\x1b[2JB", 26))
    big = "N" * 10_000
    out("C.name_10000.fit26", fit(big, 26))
    out("C.unit_40.fit8", fit("U" * 40, 8))

    # limits: slots and alignment
    for x in (0, 1, 3, -40, 150, 255, 65535, -1000, 1000, -50, 50, 5, 9, -655350, 999.4e9, 999.6e9,
              4.29e12, -1.7e308, 4294967295):
        out(f"L.short.{x!r}", short_number(x))
        out(f"L.slot.{x!r}", slot(x))
    for x in (math.inf, -math.inf, math.nan):
        out(f"L.slot.{x!r}", slot(x))
    rows = {
        "DISPLAY_0001.cur143.5.new25.5": (-40, 150, 143.5, 25.5),
        "DISPLAY_0001.cur143.5": (-40, 150, 143.5, None),
        "DISPLAY_0001.new175": (-40, 150, 143.5, 175),
        "DISPLAY_0001.new-45": (-40, 150, 143.5, -45),
        "MASK_FIELD_0001.cur174.new255": (0, 255, 174, 255),
        "MASK_BIT_0001.cur1.new0": (0, 1, 1, 0),
        "ENUM_0001.cur1": (0, 3, 1, None),
        "limits_5_5": (5, 5, None, None),
        "limits_9_1": (9, 1, None, None),
        "lower_-inf": (-math.inf, 150, 143.5, None),
        "upper_nan": (0, math.nan, None, None),
        "huge": (-1.7e308, 4.29e12, 0, None),
        "neg_big": (-655350, -1000, None, None),
        "no_limits": (None, None, None, None),
        # E3R1 (E3-8b-04, R-PE-DEF.114): a value or a position that is not finite -> the no-position form
        "float32_erased": (-40, 150, ERASED_FLOAT32, None),
        "span_overflow": (-1.7e308, 1.7e308, 1e308, None),
        # E4 (R-PE-DEF.117): a span wider than the float range; an enum bound beyond it (ENUM_0001 entries 0 .. 3
        # with the last raw 2**1100, current 1)
        "span_overflow.lower_end": (-1.7e308, 1.7e308, -1.7e308, None),
        "enum_beyond_float": (0.0, as_float(2**1100), 1, None),
        "DISPLAY_0001.new_inf": (-40, 150, 143.5, math.inf),
        # E3R1 (E3-8b-07): both marks on cell 16 -> the second moves left, `┤` stays at 25
        "DISPLAY_0001.cur150.new149.9": (-40, 150, 150, 149.9),
    }
    out("L.float32.FFFFFFFF", ERASED_FLOAT32)
    for key, (lo, hi, cur, new) in rows.items():
        cell = limits_cell(lo, hi, cur, new)
        out(f"L.cell.{key}", cell)
        out(f"L.cell.{key}.len", len(cell))
        out(f"L.cell.{key}.offsets", offsets(cell))
        if key in ("float32_erased", "span_overflow", "span_overflow.lower_end", "DISPLAY_0001.new_inf", "DISPLAY_0001.cur150.new149.9",
                   "DISPLAY_0001.cur143.5.new25.5"):
            out(f"L.cell.{key}.marks", marks(cell))
    for key, (lo, hi) in {"CURVE_DEF_0001": (0, 65535), "MAP_DEF_0001": (-1000, 1000),
                          "VAL_BLK_DEF_0001": (-50, 50)}.items():
        cell = range_form(lo, hi)
        out(f"L.bench.{key}", cell)
        out(f"L.bench.{key}.offsets", offsets(cell))
    out("L.track", TRACK)
    out("L.offset.track_start", SLOT + 1)
    out("L.offset.track_end", SLOT + TRACK)
    out("L.offset.range_mark", SLOT + 1 + (TRACK - 1) // 2)
    out("L.offset.upper_unit_cell", 34 - 1)
    out("L.offset.lower_unit_cell", SLOT - 1)

    # strips (F-R14-1)
    curve = [37818, 52215, 28375, 58106, 11719]
    mapv = [472, 132, 610, 330, 709, -890, -383, -636, 843, -485, 730, -556]
    vb = [36.85, 10.95, 31.8, -20.65, -19.75, -10.7]
    for key, count in (("CURVE_DEF_0001", 5), ("MAP_DEF_0001", 12), ("VAL_BLK_DEF_0001", 6)):
        out(f"S.strip_width.{key}", 20 - len(str(count)) - 2)
    out("S.before.CURVE_DEF_0001", chart_strip(curve, 17, BLOCKS8))
    out("S.before.MAP_DEF_0001.ramp_steps", ramp_steps(mapv, 4, 3))
    out("S.before.VAL_BLK_DEF_0001.ramp_steps", ramp_steps(vb, 3, 2))
    out("S.after.CURVE_DEF_0001", chart_strip(curve, 17, BLOCKS7))
    out("S.after.MAP_DEF_0001", grid_strip(mapv, 4, 3, 16, BLOCKS7))
    out("S.after.VAL_BLK_DEF_0001", grid_strip(vb, 3, 2, 17, BLOCKS7))
    out("S.after.current.CURVE_DEF_0001", chart_strip(curve, 17, BLOCKS7) + " 5")
    out("S.after.current.MAP_DEF_0001", grid_strip(mapv, 4, 3, 16, BLOCKS7) + " 12")
    out("S.after.current.VAL_BLK_DEF_0001", grid_strip(vb, 3, 2, 17, BLOCKS7) + " 6")
    out("S.flat.all_equal", chart_strip([7.0, 7.0, 7.0], 17, BLOCKS7))
    ramp = list(range(40))
    out("S.wide.40_points_in_17", chart_strip(ramp, 17, BLOCKS7))
    # E4 (R-PE-DEF.97/8): the after bytes of the DISPLAY_0001 pending 25.5 row's own preview. DISPLAY_0001 is
    # phys = 0.5*raw over a 2-byte big-endian word (pilot ENC.DISPLAY_0001.'25.5' = Encoded(0x800020, 00 33)).
    raw = round(25.5 / 0.5)
    out("S.after_bytes.DISPLAY_0001.25.5", " ".join(f"{b:02X}" for b in raw.to_bytes(2, "big")))

    # bit table (MASK_FIELD_0001: UWORD big-endian, mask 0x0FF0, word 1A E7; pending 255 -> 1F F7)
    for key, before, after, mask in (
        ("MASK_FIELD_0001.pending255", bytes.fromhex("1AE7"), bytes.fromhex("1FF7"), 0x0FF0),
        ("MASK_FIELD_0001.start", bytes.fromhex("1AE7"), bytes.fromhex("1AE7"), 0x0FF0),
        ("MASK_BIT_0001.pending0", bytes.fromhex("1AE7"), bytes.fromhex("1AE6"), 0x0001),
        ("ULONG_FF0000.pending0x12", bytes.fromhex("12345678"), bytes.fromhex("12125678"), 0x00FF0000),
    ):
        table = bit_table(before, after, mask)
        for n, line in enumerate(table):
            out(f"B.{key}.line{n}", line)
        out(f"B.{key}.width", max(width_of(t) for t in table))
        out(f"B.{key}.changed_bits", changed_bits(before, after))
    frame = card("MASK_FIELD_0001 · bit editor · other bits kept",
                 bit_table(bytes.fromhex("1AE7"), bytes.fromhex("1FF7"), 0x0FF0), G - 4)
    for n, line in enumerate(frame):
        out(f"B.card.MASK_FIELD_0001.line{n}", line)
    out("B.card.MASK_FIELD_0001.width", width_of(frame[0]))

    # hex grid (V171 ASCII, 42 B at 0x00810200: "Hello ASAM" NUL-padded; pending ABC)
    v171 = b"Hello ASAM" + b"\x00" * 32
    abc = b"ABC" + b"\x00" * 39
    for key, before, after in (("V171.start", v171, v171), ("V171.pendingABC", v171, abc)):
        grid = hex_grid(before, after)
        for n, line in enumerate(grid):
            out(f"T.{key}.line{n}", line)
        out(f"T.{key}.ascii_guide_cols", [line.rindex("│") for line in grid])
        out(f"T.{key}.changed_offsets", [i for i in range(len(after)) if after[i] != before[i]])
    hostile = bytes([0x00, 0x1B, 0x7F, 0x80, 0xFF, 0x41, 0x20, 0x7E])
    out("T.hostile.ascii", "".join(ascii_of(b) for b in hostile))
    out("T.span65.more", hex_grid(b"\x00" * 65, b"\x00" * 65)[-1])
    out("T.span1048576.more", f"… {1048576 - 64} more B")
    frame = card("ASAM.C.ASCII.UBYTE.NUMBER_42 · text editor · 16 B per row", hex_grid(v171, abc), G - 4)
    out("T.card.V171.width", width_of(frame[0]))
    out("T.card.V171.line0", frame[0])

    # enum card (ENUM_0001 entries 0 OFF, 1 IDLE, 2 RUN, 3 FAULT; default UNKNOWN_STATE)
    options = '( ) 0 OFF   (●) 1 IDLE   ( ) 2 RUN   ( ) 3 FAULT   default "UNKNOWN_STATE"'
    frame = card("ENUM_0001 · choose one", [options, "↔ choose · enter stage"], G - 4)
    for n, line in enumerate(frame):
        out(f"E.card.ENUM_0001.line{n}", line)
    many = "   ".join(f"( ) {i} STATE_{i}" for i in range(300))
    frame = card("BIG_ENUM · choose one", [many], G - 4)
    out("E.card.300_entries.line1", frame[1])
    out("E.card.300_entries.width", width_of(frame[1]))
    out("E.card.cap.V111", G - 4)

    # E3R1 (E3-8b-06): hostile card texts; widths in terminal cells, texts as CTX-PE-DEF plain text
    hint = "↔ choose · enter stage"

    def enum_options(first: str) -> str:
        return f'( ) 0 {first}   (●) 1 IDLE   ( ) 2 RUN   ( ) 3 FAULT   default "UNKNOWN_STATE"'

    frame = card("A\x1b[2J · choose one", [options, hint], G - 4)
    out("E.card.name_esc.line0", frame[0])
    frame = card("ENUM_0001 · choose one", [enum_options("A\x1b[2J"), hint], G - 4)
    out("E.card.row_esc.line1", frame[1])
    frame = card("ENUM_0001 · choose one", [enum_options("[@click=app.quit]OFF[/]"), hint], G - 4)
    out("E.card.markup.line1", frame[1])
    frame = card("温度" * 200 + " · choose one", [options, hint], G - 4)
    out("E.card.name_wide200.line0", frame[0])
    out("E.card.name_wide200.line0.cells", width_of(frame[0]))
    out("E.card.name_wide200.line0.chars", len(frame[0]))
    out("E.card.name_wide200.title_ends_with_ellipsis", frame[0][3:].split(" ─")[0].endswith("…"))
    frame = card("ENUM_0001 · choose one", [enum_options("温度"), hint], G - 4)
    for n, line in enumerate(frame):
        out(f"E.card.enum_wide.line{n}", line)
        out(f"E.card.enum_wide.line{n}.cells", width_of(line))
    out("E.card.enum_wide.line1.chars", len(frame[1]))
    frame = card("ENUM_0001 · choose one", [enum_options("温度" * 100), hint], G - 4)
    out("E.card.enum_wide100.line1", frame[1])
    out("E.card.enum_wide100.line1.cells", width_of(frame[1]))


if __name__ == "__main__":
    main()
