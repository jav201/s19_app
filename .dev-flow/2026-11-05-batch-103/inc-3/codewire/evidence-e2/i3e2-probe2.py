"""Inc 3 E2 probe 2 (batch-103): the pinned DEFC text and INLINE3 shapes through the app's parser.

Writes the graph's pinned definitions-case A2L (Inc 2's part + Inc 3's part) and a few INLINE3 files into
the out dir, parses them with the frozen ``a2l.parse_a2l_file``, and checks what the graph's examples rely
on: tag fields, AXIS_PTS / AXIS_DESCR / FIX_AXIS_PAR_LIST sections, byte orders, component offsets by the
frozen walk on a cleaned layout, the planned DEFC values read back by the graph's element and point rules,
the monotony rule on the nine R-A2L-DEF.129 cases, the FIX_AXIS formulas and the RAT_FUNC element of
R-A2L-DEF.119/1. A THROWAWAY simulation; nothing is written to any tree.

Usage: python -I i3e2-probe2.py <clone> <out dir>
"""
from __future__ import annotations

import math
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


def clean_lines(lines):
    text = A._strip_a2l_comments("\n".join(lines))
    return [A._split_line_respecting_quotes(x) for x in text.split("\n") if x.strip()]


def place(layout_lines, axis_counts, extra=()):
    comps, align = [], []
    for ws in clean_lines(layout_lines):
        if ws[0] in A._ALIGNMENT_DIRECTIVES:
            align.append(" ".join(ws))
        elif ws[0] in ("FNC_VALUES", "AXIS_PTS_X", "AXIS_PTS_Y", "NO_AXIS_PTS_X", "NO_AXIS_PTS_Y"):
            comps.append(ws)
    comps.sort(key=lambda ws: int(ws[1]))
    walked = A._walk_record_layout_components({"lines": align + list(extra) + [" ".join(c) for c in comps]}, axis_counts)
    return None if walked is None else ({c["component"]: c["offset"] for c in walked}, walked[-1]["end"])


HEAD = """ASAP2_VERSION 1 71
/begin PROJECT P "p"
  /begin MODULE M "m"
    /begin MOD_COMMON ""
      BYTE_ORDER MSB_FIRST
{mod_extra}    /end MOD_COMMON
    /begin COMPU_METHOD CM_IDENT "i"
      IDENTICAL "%.3" ""
    /end COMPU_METHOD
"""
TAIL = """  /end MODULE
/end PROJECT
"""


def write_parse(name, body, mod_extra=""):
    path = out_dir / name
    path.write_text(HEAD.format(mod_extra=mod_extra) + body + TAIL, encoding="utf-8")
    return A.parse_a2l_file(path)


def tag(d, name):
    return next(t for t in d["tags"] if t["name"] == name)


# ---------------------------------------------------------------- Q1 INLINE3 offsets
inl = """    /begin RECORD_LAYOUT RL_CS
      NO_AXIS_PTS_X 1 UBYTE
      AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT
      FNC_VALUES 3 SWORD ROW_DIR DIRECT
    /end RECORD_LAYOUT
    /begin RECORD_LAYOUT RL_CA2
      NO_AXIS_PTS_X 1 UBYTE
      AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT
      ALIGNMENT_WORD 2
      FNC_VALUES 3 UWORD ROW_DIR DIRECT
    /end RECORD_LAYOUT
    /begin RECORD_LAYOUT RL_CA2P
      NO_AXIS_PTS_X 1 UBYTE
      AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT
      FNC_VALUES 3 UWORD ROW_DIR DIRECT
    /end RECORD_LAYOUT
    /begin RECORD_LAYOUT RL_ORD
      FNC_VALUES 2 UWORD ROW_DIR DIRECT
      AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT
    /end RECORD_LAYOUT
    /begin RECORD_LAYOUT RL_CI
      NO_AXIS_PTS_X 1 UBYTE
      AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT
      FNC_VALUES 3 UWORD ROW_DIR DIRECT
    /end RECORD_LAYOUT
    /begin RECORD_LAYOUT RL_MN
      NO_AXIS_PTS_X 1 UBYTE
      NO_AXIS_PTS_Y 2 UBYTE
      AXIS_PTS_X 3 UBYTE INDEX_INCR DIRECT
      AXIS_PTS_Y 4 UBYTE INDEX_INCR DIRECT
      FNC_VALUES 5 UWORD ROW_DIR DIRECT
    /end RECORD_LAYOUT
    /begin RECORD_LAYOUT RL_AXO
      AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT
    /end RECORD_LAYOUT
    /begin RECORD_LAYOUT RL_U16
      FNC_VALUES 1 UWORD ROW_DIR DIRECT
    /end RECORD_LAYOUT
    /begin CHARACTERISTIC CS "c"
      CURVE 0x100 RL_CS 0 CM_IDENT 0 65535
      /begin AXIS_DESCR
        STD_AXIS NO_INPUT CM_IDENT 4 0 255
      /end AXIS_DESCR
    /end CHARACTERISTIC
    /begin CHARACTERISTIC CR "c"
      CURVE 0x100 RL_U16 0 CM_IDENT 0 65535
      /begin AXIS_DESCR
        COM_AXIS NO_INPUT CM_IDENT 8 0 255
        AXIS_PTS_REF AXO
      /end AXIS_DESCR
    /end CHARACTERISTIC
    /begin AXIS_PTS AXO "a"
      0x200 NO_INPUT RL_AXO 0 CM_IDENT 5 0 255
      BYTE_ORDER MSB_LAST
    /end AXIS_PTS
    /begin CHARACTERISTIC FL "c"
      CURVE 0x100 RL_U16 0 CM_IDENT 0 65535
      /begin AXIS_DESCR
        FIX_AXIS NO_INPUT CM_IDENT 6 0 255
        /begin FIX_AXIS_PAR_LIST
          1 2 3 4 5
        /end FIX_AXIS_PAR_LIST
      /end AXIS_DESCR
    /end CHARACTERISTIC
    /begin MEASUREMENT MC "m"
      UBYTE CM_IDENT 0 0 0 255
      ECU_ADDRESS 0x10
      MATRIX_DIM 3 2
      LAYOUT COLUMN_DIR
    /end MEASUREMENT
"""
d = write_parse("inline3-a.a2l", inl)
p("Q0 inline3-a parse errors", d["errors"])
for lname, counts in [("RL_CS", [4]), ("RL_CA2", [2]), ("RL_CA2P", [2]), ("RL_ORD", [2]), ("RL_CI", [4]), ("RL_MN", [3, 2])]:
    p("Q1 offsets " + lname, counts, place(d["record_layouts_by_name"][lname]["lines"], counts))
cr = tag(d, "CR")
p("Q2 CR tag", cr["char_type"], hex(cr["address"]), cr["record_layout_name"], cr["effective_byte_order"], cr["length"])
axo = next(s for s in A._collect_sections_by_name(d["sections"], "AXIS_PTS"))
words = A._flatten_body_tokens([axo["meta"]] + axo["lines"])
p("Q2 AXO header words", words, "BYTE_ORDER line", A._byte_order_from_section_lines(axo["lines"]))
fl_sec = [s for s in A._collect_sections_by_name(d["sections"], "CHARACTERISTIC") if s["meta"].startswith("FL")][0]
axd = [c for c in fl_sec["children"] if c["name"] == "AXIS_DESCR"][0]
p("Q2 FL AXIS_DESCR words", A._flatten_body_tokens(axd["lines"]), "children",
  [(c["name"], A._flatten_body_tokens(c["lines"])) for c in axd["children"]])
mc = tag(d, "MC")
mc_sec = [s for s in A._collect_sections_by_name(d["sections"], "MEASUREMENT") if s["meta"].startswith("MC")][0]
p("Q2 MC tag", mc["datatype"], mc["matrix_dim"], mc["length"], "LAYOUT line", [ws for ws in clean_lines(mc_sec["lines"]) if ws[0] == "LAYOUT"])
# .114: AXO points little-endian vs big
p("Q2 .114 bytes 02 01 as little / big", int.from_bytes(b"\x02\x01", "little"), int.from_bytes(b"\x02\x01", "big"))

# ---------------------------------------------------------------- Q3 monotony rule on the nine R-A2L-DEF.129 cases
RULES = {
    "STRICT_INCREASE": lambda pts: all(b > a for a, b in zip(pts, pts[1:])),
    "STRICT_DECREASE": lambda pts: all(b < a for a, b in zip(pts, pts[1:])),
    "MON_INCREASE": lambda pts: all(b >= a for a, b in zip(pts, pts[1:])),
    "MON_DECREASE": lambda pts: all(b <= a for a, b in zip(pts, pts[1:])),
    "STRICT_MON": lambda pts: RULES["STRICT_INCREASE"](pts) or RULES["STRICT_DECREASE"](pts),
    "MONOTONOUS": lambda pts: RULES["MON_INCREASE"](pts) or RULES["MON_DECREASE"](pts),
    "NOT_MON": lambda pts: True,
}


def breaking_point(rule, pts):
    for k in range(1, len(pts)):
        if not RULES[rule](pts[: k + 1]):
            return k
    return None


cases = [("/1", "STRICT_INCREASE", [10, 20, 30, 40], {2: 20}), ("/2", "STRICT_DECREASE", [40, 30, 20, 10], {1: 45}),
         ("/3", "MON_INCREASE", [10, 20, 30, 40], {2: 20}), ("/4", "MON_INCREASE", [10, 20, 30, 40], {2: 15}),
         ("/5", "MON_DECREASE", [40, 30, 20, 10], {2: 35}), ("/6", "STRICT_MON", [10, 20, 30, 40], {3: 30}),
         ("/7", "MONOTONOUS", [10, 20, 30, 40], {1: 5}), ("/8", "NOT_MON", [10, 20, 30, 40], {1: 50}),
         ("/9", "STRICT_INCREASE", [10, 20, 30, 40], {1: 35}), (".130/3", "STRICT_INCREASE", [10, 20, 30, 40], {1: 50})]
for cid, rule, pts, edit in cases:
    after = list(pts)
    for k, v in edit.items():
        after[k] = v
    k = breaking_point(rule, after)
    p("Q3 R-A2L-DEF.129" + cid, rule, after, "breaking point", None if k is None else f"X[{k}] = {after[k]}")
# an axis read from the image is not refused for its own order: the decode never calls the rule
p("Q3 STRICT_INCREASE on an unedited zigzag 10 30 20 40", breaking_point("STRICT_INCREASE", [10, 30, 20, 40]), "(only an edit of this axis checks it)")

# ---------------------------------------------------------------- Q4 FIX_AXIS formulas
p("Q4 FIX_AXIS_PAR 0 2 4", [0 + k * 2 ** 2 for k in range(4)])
p("Q4 FIX_AXIS_PAR_DIST 1 1 6 / 0 4 6 / 1 1 3", [1 + k * 1 for k in range(6)], [0 + k * 4 for k in range(6)], [1 + k for k in range(3)])

# ---------------------------------------------------------------- Q5 RAT_FUNC element of R-A2L-DEF.119/1 (raw = p^2 + 1), limits 0..10
meth = {"name": "CM_R", "conversion_type": "RAT_FUNC", "coeffs": [1.0, 0.0, 1.0, 0.0, 0.0, 1.0], "format": "%.3", "unit": ""}
for stored in (5, 0, 10):
    p("Q5 RAT_FUNC 1 0 1 0 0 1 stored", stored, A._apply_compu_method(stored, meth, {}, (0.0, 10.0)))

# ---------------------------------------------------------------- Q6 the pinned DEFC text (Inc 2 part + Inc 3 part) through the parser
rng = random.Random(20260001)
fill = [rng.randrange(256) for _ in range(256)]
enum_raw, bit, field, disp = rng.choice([0, 1, 2, 3]), rng.randrange(2), rng.randrange(256), rng.randint(-80, 300)
ax_pts = sorted(rng.sample(range(1, 2000), 5))
c1 = [rng.randrange(65536) for _ in range(5)]
c2 = [rng.randrange(65536) for _ in range(5)]
mx = sorted(rng.sample(range(0, 1000), 4))
mv = [rng.randint(-1000, 1000) for _ in range(12)]
vb = [rng.randint(-800, 800) for _ in range(6)]
image = {0x800000 + k: b for k, b in enumerate(fill)}
word = (fill[0x10] << 8 | fill[0x11]) & ~0x0FF1 | (bit << 0) | (field << 4)
planned = {0x800000: bytes([enum_raw]), 0x800010: struct.pack(">H", word), 0x800020: struct.pack(">h", disp),
           0x800040: struct.pack(">H", 5) + b"".join(struct.pack(">H", x) for x in ax_pts),
           0x800050: b"".join(struct.pack(">H", v) for v in c1), 0x800060: b"".join(struct.pack(">H", v) for v in c2)}
map_vals = [0] * 12
for y in range(3):
    for x in range(4):
        map_vals[y + 3 * x] = mv[x + 4 * y]
planned[0x800070] = b"".join(struct.pack(">H", x) for x in mx) + b"".join(struct.pack(">h", v) for v in map_vals)
planned[0x800090] = b"".join(struct.pack(">h", v) for v in vb)
for base, data in planned.items():
    for k, b in enumerate(data):
        image[base + k] = b
DEFC = """ASAP2_VERSION 1 71
/begin PROJECT SYNTH_DEFINITIONS_DEMO "Synthetic definitions demo project"
  /begin MODULE ECU_DEFINITIONS "Synthetic definitions demo module"
    /begin MOD_COMMON ""
      BYTE_ORDER MSB_FIRST
      ALIGNMENT_BYTE 1
      ALIGNMENT_WORD 2
    /end MOD_COMMON
    /begin MEMORY_SEGMENT cal DATA FLASH INTERN FLASH 0x00800000 0x000100
    /end MEMORY_SEGMENT
    /begin RECORD_LAYOUT RL_U8
      FNC_VALUES 1 UBYTE COLUMN_DIR DIRECT
    /end RECORD_LAYOUT
    /begin RECORD_LAYOUT RL_U16
      FNC_VALUES 1 UWORD COLUMN_DIR DIRECT
    /end RECORD_LAYOUT
    /begin RECORD_LAYOUT RL_S16
      FNC_VALUES 1 SWORD COLUMN_DIR DIRECT
    /end RECORD_LAYOUT
    /begin RECORD_LAYOUT RL_DEF_AXIS
      NO_AXIS_PTS_X 1 UWORD
      AXIS_PTS_X 2 UWORD INDEX_INCR DIRECT
    /end RECORD_LAYOUT
    /begin RECORD_LAYOUT RL_DEF_MAP
      AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT
      FNC_VALUES 2 SWORD COLUMN_DIR DIRECT
    /end RECORD_LAYOUT
    /begin RECORD_LAYOUT RL_DEF_S16_ROW
      FNC_VALUES 1 SWORD ROW_DIR DIRECT
    /end RECORD_LAYOUT
    /begin COMPU_METHOD CM_DEF_IDENT "synthetic IDENTICAL conversion"
      IDENTICAL "%.0" ""
    /end COMPU_METHOD
    /begin COMPU_METHOD CM_DEF_LIN "synthetic LINEAR conversion"
      LINEAR "%.3" "units"
      COEFFS_LINEAR 0.5 0
    /end COMPU_METHOD
    /begin AXIS_PTS AXIS_DEF_0001 "synthetic common axis"
      0x00800040 NO_INPUT_QUANTITY RL_DEF_AXIS 0 CM_DEF_LIN 5 0 1000
    /end AXIS_PTS
    /begin CHARACTERISTIC CURVE_DEF_0001 "synthetic curve on the common axis"
      CURVE 0x00800050 RL_U16 0 CM_DEF_IDENT 0 65535
      /begin AXIS_DESCR
        COM_AXIS NO_INPUT_QUANTITY CM_DEF_LIN 5 0 1000
        AXIS_PTS_REF AXIS_DEF_0001
      /end AXIS_DESCR
    /end CHARACTERISTIC
    /begin CHARACTERISTIC CURVE_DEF_0002 "synthetic second curve on the common axis"
      CURVE 0x00800060 RL_U16 0 CM_DEF_IDENT 0 65535
      /begin AXIS_DESCR
        COM_AXIS NO_INPUT_QUANTITY CM_DEF_LIN 5 0 1000
        AXIS_PTS_REF AXIS_DEF_0001
      /end AXIS_DESCR
    /end CHARACTERISTIC
    /begin CHARACTERISTIC MAP_DEF_0001 "synthetic map"
      MAP 0x00800070 RL_DEF_MAP 0 CM_DEF_IDENT -1000 1000
      /begin AXIS_DESCR
        STD_AXIS NO_INPUT_QUANTITY CM_DEF_IDENT 4 0 1000
        MONOTONY STRICT_INCREASE
      /end AXIS_DESCR
      /begin AXIS_DESCR
        FIX_AXIS NO_INPUT_QUANTITY CM_DEF_IDENT 3 0 100
        FIX_AXIS_PAR_DIST 10 5 3
      /end AXIS_DESCR
    /end CHARACTERISTIC
    /begin CHARACTERISTIC VAL_BLK_DEF_0001 "synthetic 2-D value block"
      VAL_BLK 0x00800090 RL_DEF_S16_ROW 0 CM_DEF_LIN -500 500
      MATRIX_DIM 3 2
      FORMAT "%.1"
    /end CHARACTERISTIC
  /end MODULE
/end PROJECT
"""
path = out_dir / "defc-inc3-part.a2l"
path.write_text(DEFC, encoding="utf-8")
dd = A.parse_a2l_file(path)
p("Q6 DEFC (Inc 3 part) parse errors", dd["errors"], "tags", [(t["name"], t["char_type"], hex(t["address"]), t["record_layout_name"], t["effective_byte_order"], t["length"]) for t in dd["tags"]])
axs = A._collect_sections_by_name(dd["sections"], "AXIS_PTS")
p("Q6 DEFC AXIS_PTS header words", [A._flatten_body_tokens([s["meta"]] + s["lines"]) for s in axs])
for lname, counts in [("RL_DEF_AXIS", [5]), ("RL_DEF_MAP", [4, 3]), ("RL_DEF_S16_ROW", [6]), ("RL_U16", [5])]:
    lay = dd["record_layouts_by_name"][lname]["lines"]
    p("Q6 DEFC offsets " + lname, place(lay, counts), "with MOD_COMMON ALIGNMENT_WORD 2", place(lay, counts, ["ALIGNMENT_BYTE 1", "ALIGNMENT_WORD 2"]))


def rd(addr, fmt):
    n = struct.calcsize(fmt)
    return struct.unpack(fmt, bytes(image[addr + k] for k in range(n)))[0]


cnt = rd(0x800040, ">H")
pts = [rd(0x800042 + 2 * k, ">H") for k in range(5)]
p("Q6 DEFC axis object: count", cnt, "stored points", pts, "texts", [f"{x * 0.5:.3f}" for x in pts])
p("Q6 DEFC CURVE_DEF_0001 values", [rd(0x800050 + 2 * k, ">H") for k in range(5)], "CURVE_DEF_0002", [rd(0x800060 + 2 * k, ">H") for k in range(5)])
mxr = [rd(0x800070 + 2 * k, ">H") for k in range(4)]
grid = {(x, y): rd(0x800078 + 2 * (y + 3 * x), ">h") for x in range(4) for y in range(3)}
p("Q6 DEFC MAP_DEF_0001 axis X", mxr, "axis Y (PAR_DIST 10 5 3)", [10 + 5 * k for k in range(3)],
  "(0,0) (1,0) (3,0) (0,1) (1,2) (3,2)", [grid[k] for k in [(0, 0), (1, 0), (3, 0), (0, 1), (1, 2), (3, 2)]],
  "equals plan", all(grid[(x, y)] == mv[x + 4 * y] for x in range(4) for y in range(3)))
vbr = {(i, j): rd(0x800090 + 2 * (i + 3 * j), ">h") for i in range(3) for j in range(2)}
p("Q6 DEFC VAL_BLK_DEF_0001 (0,0) (1,0) (2,0) (0,1) (2,1)", [vbr[k] for k in [(0, 0), (1, 0), (2, 0), (0, 1), (2, 1)]],
  "texts", [f"{vbr[k] * 0.5:.1f}" for k in [(0, 0), (1, 0), (2, 0), (0, 1), (2, 1)]],
  "equals plan", all(vbr[(i, j)] == vb[i + 3 * j] for i in range(3) for j in range(2)))
# a transposed (COLUMN_DIR) read of the VAL_BLK gives other values: R-A2L-DEF.135's n1 != n2 guard
tr = {(i, j): rd(0x800090 + 2 * (j + 2 * i), ">h") for i in range(3) for j in range(2)}
p("Q6 DEFC VAL_BLK read as COLUMN_DIR differs from plan at", sum(1 for i in range(3) for j in range(2) if tr[(i, j)] != vb[i + 3 * j]), "of 6")
# edit (1,0) of MAP_DEF_0001 to 123 at its COLUMN_DIR offset: bytes
p("Q6 DEFC MAP edit (1,0) 123 -> record byte offset", 8 + 2 * (0 + 3 * 1), "bytes", struct.pack(">h", 123).hex(" "))
p("Q6 DEFC VAL_BLK edit (1,1) -12.5 -> stored", -12.5 / 0.5, "record byte offset", 2 * (1 + 3 * 1), "bytes", struct.pack(">h", -25).hex(" "))
p("Q6 DEFC MAP axis X edit X[2] = 100 (points become)", [mxr[0], mxr[1], 100, mxr[3]], "breaking point", breaking_point("STRICT_INCREASE", [mxr[0], mxr[1], 100, mxr[3]]))
