"""Inc 8 E2: the computed examples of graph-inc8.md (widths, short numbers, Δ texts, ruler positions, overlay words).

Pure arithmetic from the rules of CTX-PE-DEF (01-requirements.md) and the facts of
evidence-e1/pilot_inc8-transcript.txt; it imports nothing from s19_app. Run: python -B examples_inc8.py
"""
from __future__ import annotations

import sys

sys.stdout.reconfigure(encoding="utf-8")

WIDTH_CLASSES = (  # (lowest W, Parameter, Kind, Current, New, Unit, Δ)
    (160, 24, 10, 44, 20, 8, 22),
    (100, 18, 9, 18, 13, 7, 16),
    (0, 16, 0, 14, 12, 0, 10),
)


def widths(w: int) -> dict:
    for low, name, kind, cur, new, unit, delta in WIDTH_CLASSES:
        if w >= low:
            others = name + kind + cur + new + unit + delta
            limits = min(64, w - 2 - others - 1)
            return dict(mark=2, name=name, kind=kind, current=cur, new=new, unit=unit, limits=limits, delta=delta)
    raise AssertionError


def short(x: float) -> str:
    a = abs(x)
    if a < 1000:
        r = round(x, 1)
        return str(int(r)) if float(r).is_integer() else str(r)
    # 3 significant digits, trailing zeros kept (E5: aligned with the P-054 F-1 fix, was `.3g`,
    # which dropped them: 1000 -> `1k`); a mantissa that rounds to 1000 moves to the next unit.
    sign = "-" if x < 0 else ""
    for div, suffix in ((1e3, "k"), (1e6, "M"), (1e9, "G")):
        r = float(f"{a:.3g}") / div  # round the value itself (9995 -> 10.0k), not a float quotient
        if r < 1000:
            decimals = 2 if r < 10 else 1 if r < 100 else 0
            return f"{sign}{r:.{decimals}f}{suffix}"
    return f"{x / 1e9:.2e}G"


def ruler_index(track: int, lo: float, hi: float, value: float):
    pos = (value - lo) / ((hi - lo) or 1.0)
    if pos < 0:
        return "left end ◀"
    if pos > 1:
        return "right end ▶"
    return min(track - 2, max(1, 1 + int(round(pos * (track - 3)))))


def signed(text: str) -> str:
    return text if text.startswith("-") else "+" + text


for w in (96, 118, 200):
    print(f"WIDTHS.W{w} = {widths(w)}")
print("WIDTHS.W80 =", widths(80))
for x in (-40, 150, 0, 255, 655350, 4294967295, 65.349, -50, 200, 1000, -1000, 999500):
    print(f"SHORT.{x} = {short(x)}")

# DISPLAY_0001 (pilot: LINEAR 0.5, decimals 1, limits -40..150, current 143.5)
cur, new, lo, hi = 143.5, 25.5, -40.0, 150.0
d = new - cur
print(f"DELTA.DISPLAY_0001.pending_25.5 = {signed(f'{d:.1f}')} ({signed(f'{100 * d / (hi - lo):.1f}')}%)")
print(f"DELTA.DISPLAY_0001.staged_25.5 = {signed(f'{d:.1f}')} staged")
print(f"DELTA.DISPLAY_0001.p_over_extended (negative control) = {100 * d / (200 - -50):.1f}%")
print(f"DELTA.MASK_FIELD_0001.255 = {signed(str(255 - 174))}")
track = widths(118)["limits"] - 12
print(f"RULER.DISPLAY_0001.W118.track = {track}; current at {ruler_index(track, lo, hi, cur)}; 25.5 at {ruler_index(track, lo, hi, 25.5)}; 175 at {ruler_index(track, lo, hi, 175)}")

# The masked word (pilot DEFC.word.image = 1a e7; masks 0x0FF0 and 0x0001)
image_word = 0x1AE7
field = (image_word & 0x0FF0) >> 4
print(f"MASK.field_at_start = {field} (0x{field:02X}); bit_at_start = {image_word & 1}")
after_field = (image_word & ~0x0FF0 & 0xFFFF) | (255 << 4)
after_both = after_field & ~0x0001 & 0xFFFF
print(f"MASK.word_after_field_255 = {after_field:04X}; after_both = {after_both:04X}")
print("MASK.bit_strip_bits_high_first =", format(image_word, "016b"))

# V171 ASCII: "Hello ASAM" + 32 NUL vs "ABC" + 39 NUL
before = b"Hello ASAM" + bytes(32)
after = b"ABC" + bytes(39)
print(f"TEXT.changed_positions = {sum(1 for a, b in zip(before, after) if a != b)}; rows = {[f'+{o:02X}' for o in range(0, 42, 16)]}")
print(f"TEXT.formula_tail_count = {len('ABC')}/{len(before)}")
