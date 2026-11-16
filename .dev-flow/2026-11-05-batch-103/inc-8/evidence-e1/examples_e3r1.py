"""Inc 8 E3R1 (batch-103): computes the examples the E3R1 rows and graph nodes cite.

Run from the repository root of a clone of b103-inc8 on the Linux runner, in an isolated env:
    python -B -I examples_e3r1.py <scratch dir>
It writes nothing into the clone; the DEFC case goes to <scratch dir>/defc.
Output: one line per fact, `KEY = value`. Corpus rule (PP-05): no object name of software_a is
printed, only kinds and numbers. Parts W, C, L, T are pure arithmetic of CTX-PE-DEF; parts F, M,
X go through I-2 and the change-document writer on the clone's product tree.
"""
from __future__ import annotations

import dataclasses
import json
import os
import subprocess
import sys
from collections import Counter
from collections.abc import Mapping
from pathlib import Path

sys.path.insert(0, ".")
import s19_app  # noqa: E402

print("s19_app.__file__ =", s19_app.__file__)
print("loadavg =", os.getloadavg())

from rich.cells import cell_len  # noqa: E402

from s19_app.core import S19File  # noqa: E402
from s19_app.tui.a2l import parse_a2l_file  # noqa: E402
from s19_app.tui.a2l_definition import (  # noqa: E402
    Decoded, Encoded, Refusal, decode_definition, describe_definition, describe_definitions,
    encode_definition,
)
from s19_app.tui.changes.io import parse_change_document, serialize_change_document  # noqa: E402
from s19_app.tui.changes.model import ChangeDocument, ChangeEntry  # noqa: E402

scratch = Path(sys.argv[1])


class Overlay(Mapping):
    """Stand-in for I-8.1 (image + entries' bytes in document order); not product code."""

    def __init__(self, image, entries):
        self._image = image if image is not None else {}
        self._top = {}
        for address, data in entries:
            for offset, byte in enumerate(data):
                self._top[address + offset] = byte

    def __getitem__(self, address):
        if address in self._top:
            return self._top[address]
        return self._image[address]

    def __iter__(self):
        return iter(set(self._image) | set(self._top))

    def __len__(self):
        return len(set(self._image) | set(self._top))


def show(value):
    if isinstance(value, Refusal):
        return f"Refusal({value.code!r})"
    if isinstance(value, Encoded):
        tail = "…" if len(value.data) > 8 else ""
        return f"Encoded(0x{value.address:X}, {value.data[:8].hex(' ').upper()}{tail}, len={len(value.data)})"
    if isinstance(value, Decoded):
        return f"Decoded(stored={value.stored!r}, text={value.text!r})"
    return repr(value)[:120]


# W — the row window (CTX-PE-DEF "row window"): the first painted row `top` keeps the selected
# row and its detail lines inside `visible` body lines; the selected row comes first when even
# that does not fit.
def row_window(selected: int, top: int, visible: int, detail: int) -> int:
    need = 1 + detail
    if visible <= need or selected < top:
        return selected
    if selected - top + need > visible:
        return selected + need - visible
    return top


for args in ((40, 0, 20, 1), (39, 22, 20, 1), (21, 22, 20, 1), (5, 0, 20, 3), (18, 0, 20, 3), (3, 0, 3, 3)):
    print(f"W.row_window{args} = {row_window(*args)}")
top = 0
for selected in range(1, 41):
    top = row_window(selected, top, 20, 1)
print(f"W.down_x40_from_0.visible20.detail1 = top {top}; selected line {40 - top}; detail line {40 - top + 1}")
print(f"W.negative_control.top0.selected40.visible20 = selected line {40 - 0} (outside 0..19)")


# C — clipping in cells (CTX-PE-DEF column widths).
def clip_cells(text: str, width: int) -> str:
    if cell_len(text) <= width:
        return text
    out = ""
    for ch in text:
        if cell_len(out + ch) > width - 1:
            break
        out += ch
    return out + "…"


def clip_len(text: str, width: int) -> str:  # the negative control: a len()-based clip
    return text if len(text) <= width else text[: width - 1] + "…"


for label, text, width in (("name", "温度" * 6, 18), ("unit", "温度温度", 7)):
    good, bad = clip_cells(text, width), clip_len(text, width)
    print(f"C.{label}.w{width}.cells = {good!r} ({cell_len(good)} cells); len_clip = {bad!r} ({cell_len(bad)} cells)")


# L — limits that are not ordered (E3S-05): the dots form and the Δ without the percent.
def short(x: float) -> str:
    a = abs(x)
    if a < 1000:
        r = round(x, 1)
        return str(int(r)) if float(r).is_integer() else str(r)
    for div, suffix in ((1e9, "G"), (1e6, "M"), (1e3, "k")):
        if a >= div:
            return f"{x / div:.3g}{suffix}"
    raise AssertionError


for lo, hi in ((5.0, 5.0), (9.0, 1.0)):
    d = 25.5 - 143.5
    print(f"L.limits_{short(lo)}_{short(hi)}.cell = {short(lo)} … {short(hi)}; pending_25.5.delta = {d:.1f}")
try:
    _ = 100 * (25.5 - 143.5) / (5.0 - 5.0)
except ZeroDivisionError as exc:
    print(f"L.negative_control.plain_division = ZeroDivisionError({exc})")


# T — the text rows cut and the span cap (E3S-04).
for span in (42, 64, 65, 4096, 4097, 1_048_576):
    rows = min(4, (span + 15) // 16)
    more = span - 64 if span > 64 else 0
    lines = 1 + rows + (1 if more else 0)
    print(f"T.span_{span}.text_rows = {rows}; cut_line = {('… %d more B' % more) if more else '(none)'}; detail_lines = {lines}; editable = {span <= 4096}")
print(f"T.negative_control.span_1048576.all_text_rows = {1_048_576 // 16}")
print(f"T.fill_cap.enum_text_5000 = {len(('E' * 5000)[:4096])}")


# F — the fallback ops (E3A-02): what I-2 gives the non-scalar kinds of a software_a page.
sa = parse_a2l_file(Path("examples/case_00_public/software_a.a2l"))
addressed = [t.get("name") for t in sa.get("tags") or [] if isinstance(t.get("address"), int)]
page = addressed[:200]
defs = describe_definitions(page, sa)
shapes = Counter()
for name in page:
    d = defs[name]
    if d.kind in ("array", "curve", "map"):
        shapes[(d.kind, d.char_type, d.element_count, d.byte_length, d.refusal is not None)] += 1
for key, count in sorted(shapes.items(), key=lambda kv: (kv[0][0], str(kv[0][2]))):
    print(f"F.page200.(kind, char_type, element_count, byte_length, refused) = {key} × {count}")


# M — E3S-08: an entry staged over one image, then a new image with another bit under it.
defc = scratch / "defc"
subprocess.run([sys.executable, "-B", "tools/synth/make_release_case.py", "--case", "definitions", "--out", str(defc)], check=True, stdout=subprocess.DEVNULL)
a2l = parse_a2l_file(defc / "definitions.a2l")
image = S19File(str(defc / "definitions.s19")).get_memory_map()
dm = describe_definitions(["MASK_FIELD_0001", "MASK_BIT_0001"], a2l)
w = dm["MASK_BIT_0001"].address
e1 = encode_definition(dm["MASK_FIELD_0001"], a2l, "255", Overlay(image, []))
image2 = dict(image)
image2[w + 1] = image[w + 1] & 0xFE  # word 1A E7 → 1A E6
print(f"M.e1 = {show(e1)}; image2.word = {image2[w]:02X} {image2[w + 1]:02X}")
print(f"M.MASK_BIT.current_over_image2 = {show(decode_definition(dm['MASK_BIT_0001'], a2l, image2))}")
print(f"M.MASK_BIT.staged_over_overlay = {show(decode_definition(dm['MASK_BIT_0001'], a2l, Overlay(image2, [(e1.address, e1.data)])))}")
print(f"M.MASK_FIELD.staged_over_overlay = {show(decode_definition(dm['MASK_FIELD_0001'], a2l, Overlay(image2, [(e1.address, e1.data)])))}")


# X — E3S-02: a `string` entry over a text row's span, replaced by a bytes entry, saved and read back.
v171 = parse_a2l_file(Path("examples/case_00_public/ASAP2_Demo_V171.a2l"))
asc = describe_definition("ASAM.C.ASCII.UBYTE.NUMBER_42", v171)
vimg = {asc.address + i: b for i, b in enumerate(b"Hello ASAM" + bytes(32))}
enc = encode_definition(asc, v171, "XYZ", vimg)
print(f"X.encode_XYZ = {show(enc)}")
old = ChangeEntry("string", asc.address, tuple(b"Q" * 42), value="Q" * 42)
for label, entry in (
    ("kept_string_entry (negative control)", dataclasses.replace(old, encoded_bytes=tuple(enc.data))),
    ("replaced_by_bytes_entry", ChangeEntry("bytes", enc.address, tuple(enc.data), symbol=old.symbol)),
):
    doc = ChangeDocument(format="s19app-changeset", version="2.0", kind="change", encoding="ascii", value_mode="text", entries=[entry])
    wire = serialize_change_document(doc)
    item = json.loads(wire)["entries"][0]
    back = parse_change_document(wire.decode("utf-8"))
    reread = Overlay(vimg, [(e.address, e.encoded_bytes) for e in back.entries])
    print(f"X.{label}.wire_type = {item['type']}; reload_decode = {show(decode_definition(asc, v171, reread))}")
print("PROBE_DONE")
