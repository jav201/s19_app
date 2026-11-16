"""Inc 9 E3R1 examples (batch-103): the CTX-PE-BENCH arithmetic changed by the E3 rulings, as a throwaway oracle.

Pure Python (no s19_app import). Run on the Linux runner:  python -B -I examples_e3r1.py
Output: one line per example, `<KEY> = value`; the graph's new examples (EX-W2, W3, N1 ... N4, J1, B1) cite the keys.
"""
from __future__ import annotations

import math
import re

# CTX-PE-BENCH grid geometry after E3R1 (E3S-05): nc clamped to >= 1; the bench minimum width is 12.
MIN_W = 12


def geometry(width: int, nx: int) -> tuple[int, int]:
    nc = max(1, min(nx, (width - 6) // 6))
    cw = max(5, min(20, (width - 6) // nc - 1))
    return nc, cw


for w in (0, 5, 6, 8, 10, 11, 12, 76, 114):
    nc, cw = geometry(w, 16)
    grid_fits = w >= MIN_W and 6 + nc * cw + (nc - 1) <= w
    print(f"GEOM.W{w} = nc {nc}, cw {cw}, below minimum {w < MIN_W}, grid fits {grid_fits}")

# Chart height after E3R1: h = max(1, min(16, room - 4)).
for room in (0, 1, 3, 5, 8, 30):
    print(f"CHART.room{room} = h {max(1, min(16, room - 4))}")


# Finite values (E3S-01): lo/hi over the finite shown values only; none finite -> lo = hi = 0.
def finite_lo_hi(values):
    finite = [v for v in values if math.isfinite(v)]
    return (min(finite), max(finite)) if finite else (0.0, 0.0)


def step(v, lo, hi):
    if not math.isfinite(v):
        return None
    return 0 if hi == lo else round((v - lo) / (hi - lo) * 11)


nan, inf = float("nan"), float("inf")
for label, values in (("nan_first", [nan, 1.0, 3.0]), ("nan_middle", [1.0, nan, 3.0]),
                      ("inf_middle", [1.0, inf, 3.0]), ("all_nan", [nan, nan, nan])):
    lo, hi = finite_lo_hi(values)
    print(f"FINITE.{label} = lo {lo:g}, hi {hi:g}, steps {[step(v, lo, hi) for v in values]}")

# Operand (E3S-02): the number text grammar of CTX-PE-BENCH, then a finite double.
NUMBER = re.compile(r"\s*[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?\s*\Z")


def operand(text: str):
    if not NUMBER.match(text):
        return None
    value = float(text)
    return value if math.isfinite(value) else None


for label, text in (("1e999", "1e999"), ("400x9", "9" * 400), ("1.5e2", " +1.5e2 "), ("1_0", "1_0"), ("abc", "abc")):
    print(f"OPERAND.{label} = grammar {bool(NUMBER.match(text))}, number {operand(text)}")

# Result (E3S-02): x% 100 on 1.7e308 is not finite, so it refuses before the result text rule.
result = 1.7e308 * (1 + 100 / 100)
print(f"RESULT.mul = {result}, finite {math.isfinite(result)}")
print("RESULT.status = Patch Editor: ×% gives a value that is not finite for F64_BLK[0].")

# Memory bound of R-PE-BENCH.28 (E3S-03): 64 MiB kept + one decode's peak ([B1] 216 B per element).
MIB = 1024 * 1024
peak = 216 * 1048576 / MIB
print(f"MEM.one_decode_peak_MiB = {peak:g}; threshold = 64 + 256 (rounded up) = {64 + 256} MiB")

# R-PE-BENCH.72 reworded (E3A-06): I-8.2's template with shown = "<k> <value word>".
for name, k, n, addr in (("VAL_BLK_DEF_0001", 1, 12, 0x800090), ("MAP_DEF_0001", 4, 32, 0x800070)):
    shown = f"{k} {'value' if k == 1 else 'values'}"
    print(f"MSG.{name} = Patch Editor: {name} staged as {shown} ({n} B at 0x{addr:X}).")

# EX-B1: MAP_DEF_0001 (0,0) = 472 (pilot DEFC.MAP_DEF_0001.values), +Δ 100.
print(f"B1.map_00_plus_100 = {472 + 100}")
