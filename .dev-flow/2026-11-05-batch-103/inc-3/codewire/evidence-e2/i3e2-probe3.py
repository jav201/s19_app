"""Inc 3 E2 probe 3 (batch-103): the D-14 replacement inputs and the DEFC VAL_BLK conversion.

R1: what the tag table gives V171 `ASAM.C.CUBE_4.ROW_DIR` (the new R-A2L-DEF.4 case, D-14).
R2: an INLINE CUBOID whose address word is not a number (the new R-A2L-DEF.24/1 input, D-14).
R3: the DEFC VAL_BLK under LINEAR 0.05 with `%.1`: planned texts, the 17-significant-digit round trip
    through the frozen encode limb, and the R-A2L-DEF.132 negative control (re-encode from display texts).
A THROWAWAY probe; nothing is written to any tree.

Usage: python -I i3e2-probe3.py <clone> <out dir>
"""
from __future__ import annotations

import random
import struct
import sys
from pathlib import Path

clone = Path(sys.argv[1])
out_dir = Path(sys.argv[2])
sys.path.insert(0, str(clone))
import s19_app  # noqa: E402
from s19_app.tui import a2l as A  # noqa: E402

print("s19_app.__file__ =", s19_app.__file__)


def p(tag, *vals):
    print(f"[{tag}]", *vals)


V171 = A.parse_a2l_file(clone / "examples" / "case_00_public" / "ASAP2_Demo_V171.a2l")
for name in ["ASAM.C.CUBE_4.ROW_DIR", "ASAM.C.CUBOID.ROW_DIR"]:
    t = next(t for t in V171["tags"] if t["name"] == name)
    p("R1 " + name, "char_type", t["char_type"], "address", hex(t["address"]) if t["address"] is not None else None)

text = """ASAP2_VERSION 1 71
/begin PROJECT P "p"
  /begin MODULE M "m"
    /begin MOD_COMMON ""
      BYTE_ORDER MSB_FIRST
    /end MOD_COMMON
    /begin RECORD_LAYOUT RL_U16
      FNC_VALUES 1 UWORD ROW_DIR DIRECT
    /end RECORD_LAYOUT
    /begin COMPU_METHOD CM_IDENT "i"
      IDENTICAL "%.3" ""
    /end COMPU_METHOD
    /begin CHARACTERISTIC CB "c"
      CUBOID 0xZZ RL_U16 0 CM_IDENT 0 65535
    /end CHARACTERISTIC
  /end MODULE
/end PROJECT
"""
path = out_dir / "inline3-cuboid.a2l"
path.write_text(text, encoding="utf-8")
d = A.parse_a2l_file(path)
t = next(t for t in d["tags"] if t["name"] == "CB")
p("R2 INLINE CUBOID CB address 0xZZ", "char_type", t["char_type"], "address", t["address"])

rng = random.Random(20260001)
[rng.randrange(256) for _ in range(256)]
rng.choice([0, 1, 2, 3]); rng.randrange(2); rng.randrange(256); rng.randint(-80, 300)
sorted(rng.sample(range(1, 2000), 5)); [rng.randrange(65536) for _ in range(10)]
sorted(rng.sample(range(0, 1000), 4)); [rng.randint(-1000, 1000) for _ in range(12)]
vb = [rng.randint(-800, 800) for _ in range(6)]
meth = {"name": "CM_DEF_FINE", "conversion_type": "LINEAR", "coeffs_linear": [0.05, 0.0], "format": "%.3", "unit": "units"}
tagview = {"name": "V", "section": "CHARACTERISTIC", "char_type": None, "matrix_dim": None, "datatype": "SWORD",
           "length": 2, "effective_byte_order": "big", "compu_method_name": "CM_DEF_FINE", "conversion": "CM_DEF_FINE",
           "lower_limit": None, "upper_limit": None, "record_layout_name": None}
values = [A._apply_compu_method(s, meth, {}, None)[0] for s in vb]
texts = [f"{v:.1f}" for v in values]
p("R3 VAL_BLK_DEF_0001 stored", vb, "values", values, "texts (%.1)", texts)
round17 = []
drift = []
for s, v, t1 in zip(vb, values, texts):
    b17, err17, _ = A.encode_physical_to_raw_bytes(tagview, float(f"{v:.17g}"), {"CM_DEF_FINE": meth}, {}, None)
    bd, errd, _ = A.encode_physical_to_raw_bytes(tagview, float(t1), {"CM_DEF_FINE": meth}, {}, None)
    s17 = struct.unpack(">h", bytes(b17))[0] if b17 else err17
    sd = struct.unpack(">h", bytes(bd))[0] if bd else errd
    round17.append(s17)
    drift.append(sd)
p("R3 encode of the 17-significant-digit texts -> stored", round17, "equal", round17 == vb)
p("R3 mutant: re-encode from the display texts -> stored", drift, "changed cells", sum(1 for a, b in zip(drift, vb) if a != b))
b, err, _ = A.encode_physical_to_raw_bytes(tagview, -12.5, {"CM_DEF_FINE": meth}, {}, None)
p("R3 edit (1,1) -12.5 -> bytes", bytes(b).hex(" ") if b else err, "stored", struct.unpack(">h", bytes(b))[0] if b else None)
b, err, _ = A.encode_physical_to_raw_bytes(tagview, 12.34, {"CM_DEF_FINE": meth}, {}, None)
p("R3 edit 12.34 -> ", b, err)
