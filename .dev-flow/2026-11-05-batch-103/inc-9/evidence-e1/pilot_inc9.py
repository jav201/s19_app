"""Inc 9 E1 pilot (batch-103): computes the examples the Inc 9 rows cite, through I-2 on base 593d56a4.

Run from the repository root of a clone of b103-inc9 on the Linux runner, in an isolated env:
    python -B -I pilot_inc9.py <scratch dir>
It writes nothing into the clone; the DEFC case goes to <scratch dir>/defc.
Output: one line per fact, `KEY = value`, so rows and the graph cite KEY.
The bench tool arithmetic below is the CTX-PE-BENCH rule written once as a throwaway oracle
(results written with 15 significant digits, then rounded half away from zero to the display
decimals; an integer datatype with no conversion or IDENTICAL rounds to a whole number).
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path

sys.path.insert(0, ".")
import s19_app  # noqa: E402

print("s19_app.__file__ =", s19_app.__file__)

from s19_app.core import S19File  # noqa: E402
from s19_app.tui.a2l import parse_a2l_file  # noqa: E402
from s19_app.tui.a2l_definition import (  # noqa: E402
    Decoded,
    Encoded,
    Refusal,
    decode_values,
    describe_definitions,
    display_text,
    element_name,
    encode_values,
)


def show(value):
    if isinstance(value, Refusal):
        return f"Refusal({value.code!r}, {value.message!r})"
    if isinstance(value, Encoded):
        return f"Encoded(0x{value.address:X}, {value.data.hex(' ')}, notices={value.notices!r})"
    return repr(value)


def overlay_of(image, staged):
    view = dict(image)
    for address, data in staged:
        for offset, byte in enumerate(data):
            view[address + offset] = byte
    return view


def texts(decoded):
    return [v.text if isinstance(v, Decoded) else f"<{v.code}>" for v in decoded.values]


def numbers(decoded):
    return [v.value if isinstance(v, Decoded) else None for v in decoded.values]


def result_text(definition, value):
    """CTX-PE-BENCH result text (the throwaway oracle of the rule)."""
    integral = definition.datatype not in ("FLOAT16_IEEE", "FLOAT32_IEEE", "FLOAT64_IEEE") and (
        definition.conversion_type in (None, "IDENTICAL")
    )
    d = 0 if integral else definition.decimals
    if d is None:
        return f"{value:.15g}"
    q = Decimal(f"{value:.15g}").quantize(Decimal(1).scaleb(-d), rounding=ROUND_HALF_UP)
    return str(int(q)) if d == 0 else format(q, f".{d}f")


def flat(shape, x, y):
    return x + shape[0] * y


scratch = Path(sys.argv[1])
defc = scratch / "defc"
subprocess.run(
    [sys.executable, "-B", "tools/synth/make_release_case.py", "--case", "definitions", "--out", str(defc)],
    check=True,
)
a2l = parse_a2l_file(defc / "definitions.a2l")
image = S19File(str(defc / "definitions.s19")).get_memory_map()
names = ["CURVE_DEF_0001", "CURVE_DEF_0002", "MAP_DEF_0001", "VAL_BLK_DEF_0001", "DISPLAY_0001"]
defs = describe_definitions(names, a2l)
FIELDS = (
    "kind", "char_type", "address", "byte_length", "datatype", "byte_order", "conversion_type",
    "method_name", "display_format", "decimals", "unit", "limits", "extended_limits", "shape",
    "element_count", "index_mode", "values_offset", "record_layout", "refusal",
)
for name in names:
    d = defs[name]
    for f in FIELDS:
        print(f"DEFC.{name}.{f} = {getattr(d, f)!r}")
    for axis in d.axes:
        print(
            f"DEFC.{name}.axis.{axis.letter} = kind {axis.axis_kind}, points {axis.point_count}, "
            f"object {axis.axis_object!r}, monotony {axis.monotony}, has_points {axis.has_points}"
        )
    dv = decode_values(d, a2l, image)
    if isinstance(dv, Refusal):
        print(f"DEFC.{name}.decode_values = {show(dv)}")
        continue
    print(f"DEFC.{name}.values = {texts(dv)}")
    for ax in dv.axes:
        pts = None if ax.points is None else [p.text if isinstance(p, Decoded) else f"<{p.code}>" for p in ax.points]
        print(f"DEFC.{name}.axis_texts.{ax.letter} = {pts}")

vb, mp, cv = defs["VAL_BLK_DEF_0001"], defs["MAP_DEF_0001"], defs["CURVE_DEF_0001"]
vb_now = numbers(decode_values(vb, a2l, image))
mp_now = numbers(decode_values(mp, a2l, image))
cv_now = numbers(decode_values(cv, a2l, image))
print(f"NAME.VB.(1,1) = {element_name(vb, (1, 1))!r}; NAME.MAP.(1,2) = {element_name(mp, (1, 2))!r}; NAME.CURVE.(3,) = {element_name(cv, (3,))!r}")
print(f"DISPLAY.VB.36.9 = {display_text(vb, 36.9)!r}; DISPLAY.MAP.472 = {display_text(mp, 472)!r}")


def enc(defn, edit, img=image):
    return encode_values(defn, a2l, edit, img)


def diff(defn, encoded, img=image):
    if not isinstance(encoded, Encoded):
        return show(encoded)
    runs = [i for i in range(len(encoded.data)) if img.get(defn.address + i) != encoded.data[i]]
    return f"{len(runs)} of {len(encoded.data)} B differ at offsets {runs}"


# Tool results (CTX-PE-BENCH) on VAL_BLK_DEF_0001 (3 x 2, element order (0,0),(1,0),(2,0),(0,1),...).
s = vb.shape
tools = {
    "SET.(0,0).'10'": {(0, 0): "10"},
    "ADD5.(0,0)(1,0)": {(x, 0): result_text(vb, vb_now[flat(s, x, 0)] + 5) for x in (0, 1)},
    "PCT10.(1,0)(2,0)": {(x, 0): result_text(vb, vb_now[flat(s, x, 0)] * 1.10) for x in (1, 2)},
    "INTERP.y0.x0..2": {(1, 0): result_text(vb, vb_now[flat(s, 0, 0)] + (vb_now[flat(s, 2, 0)] - vb_now[flat(s, 0, 0)]) * 1 / 2)},
    "SMOOTH.y0.x0..2": {(1, 0): result_text(vb, sum(vb_now[flat(s, x, 0)] for x in (0, 1, 2)) / 3)},
    "SET.(1,1).'abc'": {(1, 1): "abc"},
    "SET.(0,0).'60'": {(0, 0): "60"},
    "SET.(0,0).'10.03'": {(0, 0): "10.03"},
}
for key, edit in tools.items():
    e = enc(vb, edit)
    print(f"TOOL.VB.{key}.edit = {edit}")
    print(f"TOOL.VB.{key}.encoded = {show(e)}")
    print(f"TOOL.VB.{key}.diff = {diff(vb, e)}")
    if isinstance(e, Encoded):
        print(f"TOOL.VB.{key}.decoded_after = {texts(decode_values(vb, a2l, overlay_of(image, [(e.address, e.data)])))}")

# Stage two edits of one record over the overlay (the E3A-07/E3S-08 obligation for arrays).
e1 = enc(vb, {(0, 0): "10"})
e2 = enc(vb, {(1, 1): "-5"}, overlay_of(image, [(e1.address, e1.data)]))
print(f"ORDER.VB.e1 = {show(e1)}")
print(f"ORDER.VB.e2 = {show(e2)}")
print(f"ORDER.VB.after = {texts(decode_values(vb, a2l, overlay_of(image, [(e2.address, e2.data)])))}")
bad = enc(vb, {(1, 1): "-5"})
print(f"ORDER.VB.no_overlay.after = {texts(decode_values(vb, a2l, overlay_of(image, [(bad.address, bad.data)])))}")

# MAP_DEF_0001 (4 x 3, COLUMN_DIR): Set and +delta on a rectangle; axis edits refused.
ms = mp.shape
m_set = enc(mp, {(1, 2): "0"})
print(f"TOOL.MAP.SET.(1,2).'0'.encoded = {show(m_set)}; diff = {diff(mp, m_set)}")
m_add = {(x, y): result_text(mp, mp_now[flat(ms, x, y)] + 100) for x in (0, 1) for y in (0, 1)}
e = enc(mp, m_add)
print(f"TOOL.MAP.ADD100.x0..1.y0..1.edit = {m_add}")
print(f"TOOL.MAP.ADD100.x0..1.y0..1.encoded = {show(e)}; diff = {diff(mp, e)}")
print(f"TOOL.MAP.ADD100.x0..1.y0..1.decoded_after = {texts(decode_values(mp, a2l, overlay_of(image, [(e.address, e.data)])))}")
print(f"TOOL.MAP.SET.(0,0).'2000' = {show(enc(mp, {(0, 0): '2000'}))}")
print(f"AXIS.MAP.Y.FIX = {show(enc(mp, {('Y', 0): '11'}))}")
print(f"AXIS.CURVE.X.COM = {show(enc(cv, {('X', 0): '1'}))}")

# CURVE_DEF_0001: Set on two points, then the tool on a range.
c_set = enc(cv, {(1,): "40000", (3,): "40000"})
print(f"TOOL.CURVE.SET.(1)(3).'40000'.encoded = {show(c_set)}; diff = {diff(cv, c_set)}")
c_pct = {(x,): result_text(cv, cv_now[x] * 1.5) for x in range(5)}
print(f"TOOL.CURVE.PCT50.all.edit = {c_pct}")
print(f"TOOL.CURVE.PCT50.all.encoded = {show(enc(cv, c_pct))}")

# Kinds and element counts in the public A2L examples (decides the row-summary bound).
for label, path in (("V171", "examples/case_00_public/ASAP2_Demo_V171.a2l"), ("SWA", "examples/case_00_public/software_a.a2l")):
    data = parse_a2l_file(Path(path))
    tags = [t.get("name") for t in data.get("tags") or [] if t.get("name")]
    all_defs = describe_definitions(tags, data)
    kinds, counts = {}, []
    biggest = None
    for name, d in all_defs.items():
        if d.kind in ("array", "curve", "map"):
            kinds[d.kind] = kinds.get(d.kind, 0) + 1
            if d.element_count is not None:
                counts.append(d.element_count)
                if biggest is None or d.element_count > biggest[1]:
                    biggest = (name, d.element_count, d.byte_length)
    over = sum(1 for c in counts if c > 4096)
    mid = sum(1 for c in counts if 64 < c <= 4096)
    print(f"KINDS.{label} = {dict(sorted(kinds.items()))}; counted = {len(counts)}; <=64 = {len(counts) - over - mid}; 65..4096 = {mid}; >4096 = {over}")
    if biggest:
        name, count, length = biggest
        d = all_defs[name]
        zero = {d.address + i: 0 for i in range(d.byte_length)} if d.address is not None and d.byte_length else {}
        for ax in d.axes:
            if ax.axis_object_record is not None and ax.axis_object_record.address is not None:
                rec = ax.axis_object_record
                zero.update({rec.address + i: 0 for i in range(rec.byte_length or 0)})
        t0 = time.perf_counter()
        r = decode_values(d, data, zero)
        t1 = time.perf_counter()
        n = len(r.values) if not isinstance(r, Refusal) else 0
        print(f"KINDS.{label}.max = {count} elements, {length} B; decode_s = {t1 - t0:.4f} ({n} values); loadavg = {os.getloadavg()}")
