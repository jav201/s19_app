"""P12: emitter edge cases — Intel HEX data record crossing a 64 KiB boundary,
S19 width selection, address above 32 bits, S19 random round-trip vs the
repo loader and an independent parser."""
from common import *
import random
from s19_app.tui.changes.io import emit_s19_from_mem_map, emit_intel_hex_from_mem_map
from s19_app.core import S19File
from s19_app.hexfile import IntelHexFile
d = Path(tempfile.mkdtemp())
mem = {a: a & 0xFF for a in range(0xFFF8, 0x10008)}
txt = emit_intel_hex_from_mem_map(mem, [(0xFFF8, 0x10008)])
print("HEX crossing 64K:", txt.splitlines())
(d / "x.hex").write_text(txt)
lin, _ = mini_hex(d / "x.hex")
# spec-strict 16-bit wrap reading (what a segment-style/wrapping programmer does)
wrap = {}
upper = 0
for line in txt.splitlines():
    raw = bytes.fromhex(line[1:]); cnt, addr, typ = raw[0], int.from_bytes(raw[1:3], "big"), raw[3]
    if typ == 4: upper = int.from_bytes(raw[4:6], "big")
    if typ == 0:
        for i, b in enumerate(raw[4:4 + cnt]): wrap[(upper << 16) | ((addr + i) & 0xFFFF)] = b
print("  linear reader ranges:", [(hex(a), hex(b)) for a, b in ranges_of(lin)], "| 16-bit-wrap reader ranges:", [(hex(a), hex(b)) for a, b in ranges_of(wrap)])
print("S19 width: S3-only source <0x10000 re-emitted as:", sorted({l[:2] for l in emit_s19_from_mem_map({0x100: 1}, [(0x100, 0x101)]).splitlines()}))
try:
    t = emit_s19_from_mem_map({0x100000000: 1}, [(0x100000000, 0x100000001)])
    print("S19 addr>32bit emitted:", t.splitlines()[1], "len", len(t.splitlines()[1]))
    (d / "big.s19").write_text(t); print("  reload errors:", S19File(str(d / "big.s19")).get_errors()[:1])
except Exception as e:
    print("S19 addr>32bit raised:", type(e).__name__, e)
# random sparse round trip, both formats
random.seed(7); bad = 0
for trial in range(200):
    m = {}
    for _ in range(random.randint(1, 6)):
        base = random.choice([0, 0x8000, 0xFFF0, 0x1FFF0, 0x80000000, 0xFFFFFF00]) + random.randint(0, 64)
        for i in range(random.randint(1, 80)): m[base + i] = random.randint(0, 255)
    r = ranges_of(m)
    (d / "r.s19").write_text(emit_s19_from_mem_map(m, r)); (d / "r.hex").write_text(emit_intel_hex_from_mem_map(m, r))
    a = mini_s19(d / "r.s19")[0]; b = S19File(str(d / "r.s19")).get_memory_map(); c = mini_hex(d / "r.hex")[0]; e = dict(IntelHexFile(str(d / "r.hex")).memory)
    if not (a == b == c == e == m): bad += 1
print("random round trips (200, S19+HEX, repo loader + independent parser): mismatches =", bad)
