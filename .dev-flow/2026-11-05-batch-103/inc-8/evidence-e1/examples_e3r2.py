"""Inc 8 E3R2 (batch-103): computes the examples the E3R2 rows and graph nodes cite.

Run from the repository root of a clone of b103-inc8 on the Linux runner, in an isolated env:
    python -B -I examples_e3r2.py
It writes nothing. Output: one line per fact, `KEY = value`. Part W2 is pure arithmetic of
CTX-PE-DEF (row window with the detail cut); part S times the bounded per-row work of E3S-10
against one full I-2 decode of a 1 MiB span (the negative control), on the clone's product tree;
part R12 is the arithmetic of E3A-13's case (DISPLAY_0001 raw 287).
"""
from __future__ import annotations

import dataclasses
import os
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, ".")
import s19_app  # noqa: E402

print("s19_app.__file__ =", s19_app.__file__)
print("loadavg =", os.getloadavg())

from s19_app.tui.a2l import parse_a2l_file  # noqa: E402
from s19_app.tui.a2l_definition import decode_definition, describe_definition  # noqa: E402


# W2 — the row window with the detail cut to room = visible − 1 (E3A-14).
def row_window(selected: int, top: int, visible: int, detail: int) -> tuple[int, int]:
    shown = min(detail, visible - 1)
    need = 1 + shown
    if selected < top:
        return selected, shown
    if selected - top + need > visible:
        return selected + need - visible, shown
    return top, shown


for args in ((40, 0, 20, 1), (18, 0, 20, 3), (5, 0, 20, 3), (3, 0, 3, 3), (10, 0, 8, 10)):
    t, shown = row_window(*args)
    print(f"W2.row_window{args} = top {t}; detail lines painted {shown}; selected row on body line {args[0] - t}")


# R12 — E3A-13: DISPLAY_0001 raw 287 under factor 0.5 (the picker's page A2L) and 1.0 (the app's new A2L).
print(f"R12.DISPLAY_0001.raw287.factor_0.5 = {287 * 0.5}; factor_1.0 = {287 * 1.0:g}")


# S — E3S-10: 200 rows of one 1 MiB ASCII span at one address, one 42-byte entry inside it.
def med(fn, n=5):
    times = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        times.append(time.perf_counter() - t0)
    return statistics.median(times), max(times)


v171 = parse_a2l_file(Path("examples/case_00_public/ASAP2_Demo_V171.a2l"))
asc = describe_definition("ASAM.C.ASCII.UBYTE.NUMBER_42", v171)
SPAN = 1_048_576
big = dataclasses.replace(asc, byte_length=SPAN)
image = {asc.address + i: 0x41 for i in range(SPAN)}
entries = [(asc.address + 64, tuple(b"XYZ" + bytes(39)))]  # 42 bytes inside the span


def bounded_row():
    """What the E3R2 rule does per row: `<n> B`, and one pass over the document's bytes in the span."""
    text = f"{big.byte_length} B"
    lo, hi = big.address, big.address + big.byte_length
    staged = False
    looked = 0
    for address, data in entries:
        for offset, byte in enumerate(data):
            a = address + offset
            if lo <= a < hi:
                looked += 1
                if image.get(a) != byte:
                    staged = True
    return text, staged, looked


text, staged, looked = bounded_row()
print(f"S.bounded_row = Current {text!r}; staged {staged}; image lookups per row {looked}")
m, x = med(lambda: [bounded_row() for _ in range(200)])
print(f"S.bounded_200_rows.median_s = {m:.6f}; max_s = {x:.6f}")
m1, x1 = med(lambda: decode_definition(big, v171, image), n=3)
print(f"S.decode_1MiB.median_s = {m1:.4f}; max_s = {x1:.4f}")
print(f"S.negative_control.full_decode_200_rows_x2.estimate_s = {400 * m1:.1f} (400 × S.decode_1MiB)")
print("PROBE_DONE")
