"""Inc 8 E1 pilot (batch-103): computes the examples the Inc 8 rows cite, through I-2 on base 91d5ae56.

Run from the repository root of a clone of b103-inc8 on the Linux runner, in an isolated env:
    python -B pilot_inc8.py <scratch dir>
It writes nothing into the clone; the DEFC case goes to <scratch dir>/defc.
Output: one line per fact, `KEY = value`, so rows and the graph cite KEY.
"""
from __future__ import annotations

import statistics
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, ".")
import s19_app  # noqa: E402

print("s19_app.__file__ =", s19_app.__file__)

from s19_app.core import S19File  # noqa: E402
from s19_app.tui.a2l import parse_a2l_file  # noqa: E402
from s19_app.tui.a2l_definition import (  # noqa: E402
    Encoded,
    Refusal,
    decode_definition,
    describe_definitions,
    encode_definition,
)


def overlay_of(image, staged):
    view = dict(image)
    for address, data in staged:
        for offset, byte in enumerate(data):
            view[address + offset] = byte
    return view


def show(value):
    if isinstance(value, Refusal):
        return f"Refusal({value.code!r}, {value.message!r})"
    if isinstance(value, Encoded):
        return f"Encoded(0x{value.address:X}, {value.data.hex(' ')}, notices={value.notices!r})"
    return repr(value)


scratch = Path(sys.argv[1])
defc = scratch / "defc"
subprocess.run(
    [sys.executable, "-B", "tools/synth/make_release_case.py", "--case", "definitions", "--out", str(defc)],
    check=True,
)
a2l = parse_a2l_file(defc / "definitions.a2l")
image = S19File(str(defc / "definitions.s19")).get_memory_map()
names = ["ENUM_0001", "MASK_BIT_0001", "MASK_FIELD_0001", "DISPLAY_0001"]
defs = describe_definitions(names, a2l)
FIELDS = (
    "kind", "section", "char_type", "address", "byte_length", "datatype", "byte_order", "bit_mask",
    "bit_mask_text", "conversion_type", "method_name", "display_format", "decimals", "unit", "limits",
    "extended_limits", "enum_table", "enum_entries", "default_text", "coeffs_linear", "coeffs",
    "record_layout", "shared_with", "refusal",
)
for name in names:
    d = defs[name]
    for f in FIELDS:
        print(f"DEFC.{name}.{f} = {getattr(d, f)!r}")
    print(f"DEFC.{name}.decode = {show(decode_definition(d, a2l, image))}")

word_addr = defs["MASK_BIT_0001"].address
print(f"DEFC.word.image = {image[word_addr]:02x} {image[word_addr + 1]:02x}")

ENC = [
    ("DISPLAY_0001", "25.5"), ("DISPLAY_0001", "150"), ("DISPLAY_0001", "175"), ("DISPLAY_0001", "250"), ("DISPLAY_0001", "abc"),
    ("DISPLAY_0001", "x" * 300), ("ENUM_0001", "RUN"), ("ENUM_0001", "WALK"), ("ENUM_0001", "2"),
    ("MASK_FIELD_0001", "255"), ("MASK_FIELD_0001", "256"), ("MASK_BIT_0001", "0"), ("MASK_BIT_0001", "2"),
    ("DISPLAY_0001", "A[b]\x1b[2J"),
]
for name, text in ENC:
    result = encode_definition(defs[name], a2l, text, image)
    label = text if len(text) <= 20 else f"<{len(text)} x {text[0]!r}>"
    print(f"ENC.{name}.{label!r} = {show(result)}")
    if isinstance(result, Refusal):
        print(f"ENC.{name}.{label!r}.message_len = {len(result.message)}")

# Two masked edits of one word, staged in either order over the overlay (E3A-07 / E3S-08).
for order in (("MASK_FIELD_0001", "255", "MASK_BIT_0001", "0"), ("MASK_BIT_0001", "0", "MASK_FIELD_0001", "255")):
    n1, t1, n2, t2 = order
    staged = []
    e1 = encode_definition(defs[n1], a2l, t1, image)
    staged = [(e1.address, e1.data)]
    e2 = encode_definition(defs[n2], a2l, t2, overlay_of(image, staged))
    staged = [(e2.address, e2.data)]  # same span: the second replaces the first's bytes
    final = overlay_of(image, staged)
    print(f"ORDER.{n1}->{n2}.e1 = {show(e1)}")
    print(f"ORDER.{n1}->{n2}.e2 = {show(e2)}")
    for name in ("MASK_FIELD_0001", "MASK_BIT_0001"):
        print(f"ORDER.{n1}->{n2}.decode.{name} = {show(decode_definition(defs[name], a2l, final))}")
    # Negative control: encode the second over the base image (no overlay) and keep both entries' last write.
    bad = encode_definition(defs[n2], a2l, t2, image)
    lost = overlay_of(image, [(e1.address, e1.data), (bad.address, bad.data)])
    print(f"ORDER.{n1}->{n2}.no_overlay.decode.{n1} = {show(decode_definition(defs[n1], a2l, lost))}")

# Unstage one field of the combined word: its bits return to the image's bits.
mask_bit = defs["MASK_BIT_0001"].bit_mask
combined = encode_definition(
    defs["MASK_BIT_0001"], a2l, "0",
    overlay_of(image, [(word_addr, encode_definition(defs["MASK_FIELD_0001"], a2l, "255", image).data)]),
)
cw = int.from_bytes(combined.data, "big")
iw = (image[word_addr] << 8) | image[word_addr + 1]
restored = (cw & ~mask_bit & 0xFFFF) | (iw & mask_bit)
print(f"UNSTAGE.combined = {cw:04x}; UNSTAGE.image = {iw:04x}; UNSTAGE.bit_restored = {restored:04x}")

# V171: the ASCII object and the masked objects (overlap refusals) with a hand image.
v171 = parse_a2l_file(Path("examples/case_00_public/ASAP2_Demo_V171.a2l"))
vimg = {0x810200 + i: b for i, b in enumerate(b"Hello ASAM" + bytes(32))}
vimg.update({0x810000: 0, 0x810001: 0, 0x810002: 0x34, 0x810003: 0x12, 0x810004: 2, 0x810005: 0})
vnames = ["ASAM.C.ASCII.UBYTE.NUMBER_42", "ASAM.C.SCALAR.UWORD.IDENTICAL.BITMASK_0FF0"]
vdefs = describe_definitions(vnames, v171)
for name in vnames:
    d = vdefs[name]
    for f in ("kind", "char_type", "byte_length", "record_layout", "shared_with", "refusal"):
        print(f"V171.{name}.{f} = {getattr(d, f)!r}")
    print(f"V171.{name}.decode = {show(decode_definition(d, v171, vimg))}")
for text in ("ABC", "x" * 43, "été"):
    r = encode_definition(vdefs[vnames[0]], v171, text, vimg)
    label = text if len(text) <= 20 else f"<{len(text)} x {text[0]!r}>"
    print(f"V171.ENC.ASCII.{label!r} = {show(r)}")
print(f"V171.ENC.MASK = {show(encode_definition(vdefs[vnames[1]], v171, '5', vimg))}")

# Cost of one sheet page: one describe_definitions call for 200 names, then 200 decodes.
sa = parse_a2l_file(Path("examples/case_00_public/software_a.a2l"))
page = [t.get("name") for t in sa.get("tags") or [] if isinstance(t.get("address"), int)][:200]
times_d, times_x = [], []
for _ in range(5):
    t0 = time.perf_counter()
    pdefs = describe_definitions(page, sa)
    t1 = time.perf_counter()
    for name in page:
        decode_definition(pdefs[name], sa, {})
    t2 = time.perf_counter()
    times_d.append(t1 - t0)
    times_x.append(t2 - t1)
print(f"COST.page_names = {len(page)}; COST.tags = {len(sa.get('tags') or [])}")
print(f"COST.describe_200.median_s = {statistics.median(times_d):.4f}; COST.describe_200.max_s = {max(times_d):.4f}")
print(f"COST.decode_200.median_s = {statistics.median(times_x):.4f}; COST.decode_200.max_s = {max(times_x):.4f}")
kinds = {}
for name in page:
    kinds[pdefs[name].kind or "(refused)"] = kinds.get(pdefs[name].kind or "(refused)", 0) + 1
print(f"COST.page_kinds = {dict(sorted(kinds.items()))}")
