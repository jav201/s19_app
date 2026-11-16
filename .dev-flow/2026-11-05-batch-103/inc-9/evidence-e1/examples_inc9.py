"""Inc 9 E1 examples (batch-103): the arithmetic of CTX-PE-BENCH, written once as a throwaway oracle.

Pure Python (no s19_app import). Inputs are the DEFC facts of pilot_inc9-transcript.txt, copied as data.
Run on the Linux runner:  python -B -I examples_inc9.py
Output: one line per example, `EX-<id> = value`; the rows and the graph cite the ids.
"""
from __future__ import annotations

import math
from decimal import ROUND_HALF_UP, Decimal

EIGHTHS = "▁▂▃▄▅▆▇█"

# DEFC facts (pilot_inc9-transcript.txt: DEFC.*.values; physical values are stored × factor).
CURVE = [37818, 52215, 28375, 58106, 11719]                      # CURVE_DEF_0001, IDENTICAL
MAP = [472, 132, 610, 330, 709, -890, -383, -636, 843, -485, 730, -556]  # MAP_DEF_0001 (4 x 3), element order
MAP_SHAPE = (4, 3)
VB_STORED = [737, 219, 636, -413, -395, -214]                    # VAL_BLK_DEF_0001 (3 x 2), LINEAR 0.05
VB = [s * 0.05 for s in VB_STORED]
VB_SHAPE = (3, 2)


def short(x: float) -> str:
    """CTX-PE-DEF short number."""
    if abs(x) < 1000:
        t = f"{round(x, 1):.1f}"
        return t[:-2] if t.endswith(".0") else t
    for div, suf in ((1e9, "G"), (1e6, "M"), (1e3, "k")):
        if abs(x) >= div:
            v = x / div
            digits = 3 - (int(math.floor(math.log10(abs(v)))) + 1)
            return f"{v:.{max(digits, 0)}f}{suf}"
    return str(x)


def result_text(value: float, decimals) -> str:
    if decimals is None:
        return f"{value:.15g}"
    q = Decimal(f"{value:.15g}").quantize(Decimal(1).scaleb(-decimals), rounding=ROUND_HALF_UP)
    return str(int(q)) if decimals == 0 else format(q, f".{decimals}f")


def step(v, lo, hi):
    return round((v - lo) / ((hi - lo) or 1) * 11)


def strip_chart(values, width):
    lo, hi = min(values), max(values)
    k = max(1, -(-len(values) // width))
    return "".join(EIGHTHS[round((v - lo) / ((hi - lo) or 1) * 7)] for v in values[::k])


def column_means(values, shape):
    nx, ny = shape
    return [sum(values[x + nx * y] for y in range(ny)) / ny for x in range(nx)]


# Inc 8's column widths at W = 118: Current 18 (EX-W1 of graph-inc8.md).
cur_w = 18
for label, values in (("CURVE_DEF_0001", CURVE),):
    count = str(len(values))
    strip_w = cur_w - 1 - len(count) - 1
    print(f"EX-G1 {label} strip width {strip_w} = {strip_chart(values, strip_w)} {count}")
for label, values, shape in (("MAP_DEF_0001", MAP, MAP_SHAPE), ("VAL_BLK_DEF_0001", VB, VB_SHAPE)):
    means = column_means(values, shape)
    lo, hi = min(values), max(values)
    print(f"EX-G2 {label} column means {[round(m, 3) for m in means]} -> ramp steps {[step(m, lo, hi) for m in means]} (lo {lo:g}, hi {hi:g})")
lo, hi = min(MAP), max(MAP)
print(f"EX-G3 MAP_DEF_0001 cell steps (c,r): " + ", ".join(
    f"({i % 4},{i // 4})={MAP[i]}:{step(MAP[i], lo, hi)}" for i in range(12)))
print(f"EX-G4 MAP_DEF_0001 legend = 'shade {'█' * 12} {short(lo)} … {short(hi)}   sel x0,y0   * / bold = edited'")
clo, chi = min(CURVE), max(CURVE)
base = clo - (chi - clo) / 10
print(f"EX-G5 CURVE_DEF_0001 legend = 'scale {short(base)} … {short(chi)}   █ edited  ─ old level' (base {base:g})")
for W in (96, 118, 200):
    for nx in (3, 4, 16):
        nc = min(nx, (W - 6) // 6)
        cw = max(5, min(20, (W - 6) // nc - 1))
        print(f"EX-G6 W {W} nx {nx} -> columns shown {nc}, cell width {cw}")
for W, n in ((118, 5), (80, 5), (118, 64)):
    print(f"EX-G7 chart W {W} points {n} -> column width {max(1, min(6, (W - 10) // n))}")
print("EX-G8 where = curve [3], [1..3]; map [x0,y0], [x0..1,y0..1]; 1-D array [36..43]")
for value, d in ((10.95 * 1.1, 1), ((36.85 + 31.8) / 2, 1), ((36.85 + 10.95 + 31.8) / 3, 1), (572.5, 0), (-572.5, 0), (36.85 + 5, 1), (10.95 + 5, 1), (0.1 + 0.2, None)):
    print(f"EX-G9 result text {value!r} d={d} -> {result_text(value, d)}")
for x in (65535, 58106, base, 11719, -890, 843, 0, -1000, 1000):
    print(f"EX-G10 short {x!r} -> {short(x)}")
smooth_row0 = MAP[0:4]
print(f"EX-G11 MAP row 0 smooth c0..3 before {smooth_row0} -> (1,0) {result_text(sum(smooth_row0[0:3]) / 3, 0)}, (2,0) {result_text(sum(smooth_row0[1:4]) / 3, 0)}")
print(f"EX-G12 LARGE 1-D 1048576 elements -> grid rows {1048576 // 16}, columns 16")
