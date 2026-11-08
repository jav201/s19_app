"""Inc 3 E2 probe (batch-103): checks the example values of graph-inc3.md on the base tree.

Reads the tracked A2L fixtures and case 08 through the app's own parser (frozen ``a2l.py``), and runs a
THROWAWAY simulation of the graph's array rules (this file only; nothing is written to any tree): the
record-layout reading, the component placement through ``a2l._walk_record_layout_components`` on a cleaned
layout, the MOD_COMMON alignment comparison, the axis reading, the element and point offsets, and the DEFC
draw order. Every printed line is tagged ``[P…]`` and cited by the graph.

Usage: python -I i3e2-probe.py <clone> <out dir>
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
sys.path.insert(0, str(clone / "tools" / "synth"))

import s19_app  # noqa: E402
from s19_app.tui import a2l as A  # noqa: E402
from s19_app.core import S19File  # noqa: E402
import make_release_case as M  # noqa: E402

print("s19_app.__file__ =", s19_app.__file__)
print("make_release_case.__file__ =", M.__file__)

EX = clone / "examples" / "case_00_public"
ASAM_TYPES = [k for k in A.DATATYPE_SIZES if k not in ("BYTE", "WORD", "LONG")]


def p(tag, *vals):
    print(f"[{tag}]", *vals)


def parse(path):
    return A.parse_a2l_file(Path(path))


# ---------------------------------------------------------------- section helpers (simulation)
def object_sections(sections):
    out = []

    def walk(nodes):
        for n in nodes:
            if n["name"] in ("MEASUREMENT", "CHARACTERISTIC"):
                out.append(n)
            walk(n.get("children") or [])

    walk(sections)
    return out


def pair(a2l_data):
    """Inc 2's _find_tag pairing: tag i <-> object section i in file order."""
    secs = sorted(object_sections(a2l_data["sections"]), key=lambda s: s["start_line"])
    return {t["name"]: (t, secs[i]) for i, t in reversed(list(enumerate(a2l_data["tags"])))}


def clean_lines(lines):
    text = A._strip_a2l_comments("\n".join(lines))
    return [A._split_line_respecting_quotes(x) for x in text.split("\n") if x.strip()]


def module_of(sections, target):
    found = []

    def walk(nodes, module):
        for n in nodes:
            m = n if n["name"] == "MODULE" else module
            if n is target:
                found.append(m)
            walk(n.get("children") or [], m)

    walk(sections, None)
    return found[0] if found else None


def mod_common_alignments(module):
    if module is None:
        return []
    for c in module.get("children") or []:
        if c["name"] == "MOD_COMMON":
            return [ws for ws in clean_lines(c.get("lines") or []) if ws and ws[0] in A._ALIGNMENT_DIRECTIVES]
    return []


def find_axis_pts(sections, ref):
    for s in A._collect_sections_by_name(sections, "AXIS_PTS"):
        words = A._flatten_body_tokens([s.get("meta") or ""] + (s.get("lines") or []))
        if words and words[0] == ref:
            return s, words
    return None


COMPONENTS = {"FNC_VALUES", "AXIS_PTS_X", "AXIS_PTS_Y", "NO_AXIS_PTS_X", "NO_AXIS_PTS_Y"}


def read_layout(lines):
    """-> dict(components=[words...] in position order, align=[words], fix_no={letter:n}, bad=...)"""
    comps, align, fix_no, unknown = [], [], {}, None
    for ws in clean_lines(lines):
        w0 = ws[0]
        if w0 in COMPONENTS:
            comps.append(ws)
        elif w0 in A._ALIGNMENT_DIRECTIVES:
            align.append(ws)
        elif w0 in ("FIX_NO_AXIS_PTS_X", "FIX_NO_AXIS_PTS_Y"):
            fix_no[w0[-1]] = int(ws[1])
        elif ws == ["DIRECT"]:
            pass
        elif unknown is None:
            unknown = w0
    positions = []
    for ws in comps:
        try:
            positions.append(int(ws[1]))
        except (IndexError, ValueError):
            positions.append(None)
    pos_ok = None not in positions and len(set(positions)) == len(positions)
    if pos_ok:
        comps = [c for _, c in sorted(zip(positions, comps), key=lambda t: t[0])]
    return {"components": comps, "align": align, "fix_no": fix_no, "unknown": unknown, "pos_ok": pos_ok}


def place(layout, counts_by_letter, element_count, extra_align=()):
    """Offsets by the frozen walk on a cleaned layout: components in position order + ALIGNMENT lines."""
    lines = [" ".join(ws) for ws in layout["align"]] + [" ".join(ws) for ws in extra_align]
    lines += [" ".join(ws) for ws in layout["components"]]
    # the walk sizes FNC_VALUES by prod(axis_counts) and AXIS_PTS_X/Y by axis_counts[0]/[1]
    if counts_by_letter:
        axis_counts = [counts_by_letter.get("X", 1), counts_by_letter.get("Y", 1)][: len(counts_by_letter)]
    else:
        axis_counts = [element_count]
    walked = A._walk_record_layout_components({"lines": lines}, axis_counts)
    if walked is None:
        return None
    return {c["component"]: c["offset"] for c in walked}, walked[-1]["end"] if walked else 0


def with_module_alignment(layout, module_align):
    declared = {ws[0] for ws in layout["align"]}
    return [ws for ws in module_align if ws[0] not in declared]


# ---------------------------------------------------------------- P0 V171 parse and pairing
V171 = parse(EX / "ASAP2_Demo_V171.a2l")
p("P0 V171 errors", V171["errors"])
unclosed = [s["name"] + " " + (s.get("meta") or "")[:40] for s in object_sections(V171["sections"]) if "end_line" not in s]
p("P0 V171 object sections without /end", len(unclosed), unclosed[:3])
mods = A._collect_sections_by_name(V171["sections"], "MODULE")
p("P0 V171 MODULE sections / end_line present", len(mods), ["end_line" in m for m in mods])
PV = pair(V171)

ARR = ["ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR", "ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.COLUMN_DIR",
       "ASAM.C.ARRAY.SWORD.MATRIX_DIM_6.ROW_DIR", "ASAM.M.MATRIX_DIM_8_4_2.UBYTE.IDENTICAL",
       "ASAM.M.MATRIX_DIM_16_1.UBYTE.IDENTICAL", "ASAM.M.MATRIX_DIM_8_2.UBYTE.IDENTICAL",
       "ASAM.M.MATRIX_DIM_16.UBYTE.IDENTICAL"]
for name in ARR:
    t, s = PV[name]
    md = [ws for ws in clean_lines(s["lines"]) if ws and ws[0] == "MATRIX_DIM"]
    lay = [ws for ws in clean_lines(s["lines"]) if ws and ws[0] == "LAYOUT"]
    p("P1 " + name, "char_type", t["char_type"], "addr", hex(t["address"]) if t["address"] is not None else None,
      "MATRIX_DIM words", md[0][1:] if md else None, "LAYOUT", lay[0][1:] if lay else None,
      "deposit", t["record_layout_name"], "datatype", t["datatype"], "bo", t["effective_byte_order"],
      "length", t["length"])

# ---------------------------------------------------------------- P2 V171 curves/maps: axes, layouts, offsets
module = mods[0]
MALIGN = mod_common_alignments(module)
p("P2 V171 MOD_COMMON alignment lines", MALIGN)
CUR = ["ASAM.C.CURVE.STD_AXIS", "ASAM.C.CURVE.COM_AXIS", "ASAM.C.CURVE.COM_AXIS_2", "ASAM.C.CURVE.FIX_AXIS.PAR_DIST",
       "ASAM.C.CURVE.FIX_AXIS.PAR", "ASAM.C.CURVE.FIX_AXIS.PAR_LIST", "ASAM.C.CURVE.CURVE_AXIS",
       "ASAM.C.CURVE.RES_AXIS", "ASAM.C.MAP.STD_AXIS.STD_AXIS", "ASAM.C.MAP.COM_AXIS.FIX_AXIS"]
for name in CUR:
    t, s = PV[name]
    axes = [c for c in s.get("children") or [] if c["name"] == "AXIS_DESCR"]
    words = [A._flatten_body_tokens(c.get("lines") or []) for c in axes]
    lists = [[A._flatten_body_tokens(g.get("lines") or []) for g in (c.get("children") or [])
              if g["name"] == "FIX_AXIS_PAR_LIST"] for c in axes]
    p("P2 " + name, "addr", hex(t["address"]), "deposit", t["record_layout_name"], "bo", t["effective_byte_order"],
      "axes", words, "PAR_LIST", lists)
for lname in ["RL.CURVE.SWORD.SBYTE.DECR", "RL.MAP.SWORD.SBYTE.SBYTE.INCR", "RL.AXIS_PTS.SBYTE.DECR",
              "RL.FNC.SWORD.ROW_DIR", "RL.AXIS_PTS.RES_AXIS"]:
    lay = read_layout(V171["record_layouts_by_name"][lname]["lines"])
    p("P2 layout " + lname, "components", lay["components"], "unknown", lay["unknown"])
cases = [("RL.CURVE.SWORD.SBYTE.DECR", {"X": 8}, 8), ("RL.MAP.SWORD.SBYTE.SBYTE.INCR", {"X": 4, "Y": 5}, 20),
         ("RL.FNC.SWORD.ROW_DIR", {"X": 8}, 8), ("RL.FNC.SWORD.ROW_DIR", {"X": 8, "Y": 3}, 24),
         ("RL.AXIS_PTS.SBYTE.DECR", {"X": 8}, 8)]
for lname, counts, n in cases:
    lay = read_layout(V171["record_layouts_by_name"][lname]["lines"])
    a = place(lay, counts, n)
    b = place(lay, counts, n, with_module_alignment(lay, MALIGN))
    p("P3 offsets " + lname + " " + str(counts), "layout reading", a, "MOD_COMMON reading", b)
ax = find_axis_pts(V171["sections"], "ASAM.C.AXIS_PTS.UBYTE_8")
p("P3 V171 AXIS_PTS header words", ax[1] if ax else None)
p("P3 V171 AXIS_PTS byte order line / its layout byte order", A._byte_order_from_section_lines(ax[0]["lines"]),
  V171["record_layouts_by_name"]["RL.AXIS_PTS.SBYTE.DECR"]["byte_order"])
p("P3 V171 AXIS_PTS name lookup among tags", any(t["name"] == "ASAM.C.AXIS_PTS.UBYTE_8" for t in V171["tags"]))

# ---------------------------------------------------------------- P4 element offsets on V171 images
def elem_offset(idx, shape, mode):
    if mode == "ROW_DIR":
        off, mul = 0, 1
        for i, n in zip(idx, shape):
            off += i * mul
            mul *= n
        return off
    if len(shape) == 1:
        return idx[0]
    i, j = idx
    return j + shape[1] * i


def le16(vals):
    return b"".join(struct.pack("<h", v) for v in vals)


img = {0x810100 + k: b for k, b in enumerate(le16(range(1, 13)))}
for idx in [(1, 0), (0, 1), (2, 3)]:
    o = elem_offset(idx, (3, 4), "ROW_DIR")
    p("P4 ROW_DIR 3x4 SWORD 1..12", idx, "offset", o, "value", struct.unpack("<h", bytes([img[0x810100 + 2 * o], img[0x810101 + 2 * o]]))[0])
for idx in [(1, 0), (0, 1), (2, 3)]:
    o = elem_offset(idx, (3, 4), "COLUMN_DIR")
    p("P4 COLUMN_DIR 3x4 SWORD 1..12", idx, "offset", o, "value", o + 1)
for idx in [(1, 1, 1), (7, 3, 1)]:
    p("P4 ROW_DIR 8x4x2 bytes 0..63", idx, "value", elem_offset(idx, (8, 4, 2), "ROW_DIR"))
for idx in [(1, 2), (7, 0), (0, 1)]:
    p("P4 ROW_DIR map 8x3 SWORD 0..23", idx, "value", elem_offset(idx, (8, 3), "ROW_DIR"))
ax8 = [0x46, 0x3C, 0x32, 0x28, 0x1E, 0x14, 0x0A, 0x00]
pts = [struct.unpack("b", bytes([ax8[8 - 1 - k]]))[0] for k in range(8)]
p("P4 INDEX_DECR AX8 points", pts)
p("P4 edit (1,0) -7 SWORD little bytes", struct.pack("<h", -7).hex(" "), "ROW_DIR byte offset",
  2 * elem_offset((1, 0), (3, 4), "ROW_DIR"), "COLUMN_DIR byte offset", 2 * elem_offset((1, 0), (3, 4), "COLUMN_DIR"))

# ---------------------------------------------------------------- P5 every V171 array/curve/map: kind and first refusal (simulation)
def classify(a2l_data, name, t, s, module_align):
    """Simulation of the array refusal order (subset sufficient for the tracked files)."""
    ct = t.get("char_type")
    md_lines = [ws for ws in clean_lines(s["lines"]) if ws and ws[0] == "MATRIX_DIM"]
    if t["section"] == "MEASUREMENT":
        if not md_lines or all(w == "1" for w in md_lines[0][1:]):
            return "scalar", None, None
        kind = "array"
    elif ct == "VAL_BLK":
        kind = "array"
    elif ct in ("CURVE", "MAP"):
        kind = ct.lower()
    elif ct in ("VALUE", "ASCII"):
        return "scalar", None, None
    else:
        return "", "A2L-DEF-KIND", 0
    shape = None
    if md_lines:
        ws = md_lines[0][1:]
        if not (1 <= len(ws) <= 3 and all(w.isdigit() and int(w) >= 1 for w in ws)):
            return kind, "A2L-DEF-MATRIX", 0
        dims = [int(w) for w in ws]
        while len(dims) > 1 and dims[-1] == 1:
            dims.pop()
        shape = tuple(dims)
    if t["section"] == "MEASUREMENT":
        dt = t.get("datatype")
        if dt not in ASAM_TYPES:
            return kind, "A2L-DEF-DATATYPE", math.prod(shape)
        if t.get("address") is None:
            return kind, "A2L-DEF-ADDRESS", math.prod(shape)
        return kind, None, math.prod(shape)
    lname = t.get("record_layout_name")
    rl = a2l_data["record_layouts_by_name"].get(lname)
    if rl is None:
        return kind, "A2L-DEF-LAYOUT", None
    lay = read_layout(rl["lines"])
    if not lay["pos_ok"]:
        return kind, "A2L-DEF-LAYOUT-POSITION", None
    if lay["unknown"]:
        return kind, "A2L-DEF-LAYOUT-PART " + lay["unknown"], None
    fnc = [c for c in lay["components"] if c[0] == "FNC_VALUES"]
    if not fnc:
        return kind, "A2L-DEF-LAYOUT-VALUES", None
    counts = {}
    if kind in ("curve", "map"):
        axes = [c for c in s.get("children") or [] if c["name"] == "AXIS_DESCR"]
        if len(axes) != (1 if kind == "curve" else 2):
            return kind, "A2L-DEF-AXES", None
        for letter, axs in zip("XY", axes):
            w = A._flatten_body_tokens(axs.get("lines") or [])
            if w[0] not in ("STD_AXIS", "FIX_AXIS", "COM_AXIS"):
                return kind, "A2L-DEF-AXIS-KIND " + w[0], None
            if w[0] == "COM_AXIS":
                ref = w[w.index("AXIS_PTS_REF") + 1] if "AXIS_PTS_REF" in w else None
                found = find_axis_pts(a2l_data["sections"], ref) if ref else None
                if not found:
                    return kind, "A2L-DEF-AXIS-REF " + str(ref), None
                try:
                    int(found[1][2], 0)
                except ValueError:
                    return kind, "A2L-DEF-AXIS-REF", None
                arl = a2l_data["record_layouts_by_name"].get(found[1][4])
                if arl is None or not any(c[0] == "AXIS_PTS_X" for c in read_layout(arl["lines"])["components"]):
                    return kind, "A2L-DEF-AXIS-LAYOUT", None
                maxw = found[1][7]
            else:
                maxw = w[3]
            if not (maxw.isdigit() and int(maxw) >= 1):
                return kind, "A2L-DEF-AXIS-MAX", None
            counts[letter] = int(maxw)
            fn = lay["fix_no"].get(letter)
            if fn is not None and fn != counts[letter]:
                return kind, ("A2L-DEF-AXIS-CURRENT" if fn == 0 or fn > counts[letter] else "A2L-DEF-AXIS-PARTIAL"), math.prod(counts.values())
        shape = tuple(counts[k] for k in "XY"[: len(counts)])
    else:
        if shape is None:
            num = [ws for ws in clean_lines(s["lines"]) if ws and ws[0] == "NUMBER"]
            if num:
                shape = (int(num[0][1]),)
            else:
                ln = [ws for ws in clean_lines(s["lines"]) if ws and ws[0] in ("LENGTH", "DATA_SIZE")]
                size = A.DATATYPE_SIZES.get(fnc[0][2])
                if ln and size and int(ln[0][1], 0) % size == 0:
                    shape = (int(ln[0][1], 0) // size,)
                elif ln:
                    return kind, "A2L-DEF-SHAPE", None
                else:
                    return kind, "A2L-DEF-ADDRESS(no shape)", None
    n = math.prod(shape)
    a = place(lay, counts, n)
    b = place(lay, counts, n, with_module_alignment(lay, module_align))
    if a is None or b is None:
        return kind, "walk None", n
    if a[0] != b[0]:
        diff = [(c, a[0][c], b[0][c]) for c in a[0] if a[0][c] != b[0][c]]
        return kind, f"A2L-DEF-ALIGNMENT {diff[0]}", n
    return kind, None, (n, a[1], shape, fnc[0][2:4])


tally = {}
for t in V171["tags"]:
    name = t["name"]
    if name not in PV:
        continue
    tt, s = PV[name]
    if tt is not t:
        continue
    kind, refusal, info = classify(V171, name, t, s, MALIGN)
    if kind in ("scalar",):
        continue
    p("P5 V171", name, kind, refusal, info)
    tally[(kind, (refusal or "none").split(" ")[0])] = tally.get((kind, (refusal or "none").split(" ")[0]), 0) + 1
p("P5 V171 tally", sorted(tally.items()))

# ---------------------------------------------------------------- P6 software_a, check_test, update_test1/2
SOFTA = parse(EX / "software_a.a2l")
PS = pair(SOFTA)
smodule = A._collect_sections_by_name(SOFTA["sections"], "MODULE")[0]
SALIGN = mod_common_alignments(smodule)
p("P6 SOFTA MOD_COMMON alignment", SALIGN)
first = {}
stally = {}
for t in SOFTA["tags"]:
    tt, s = PS[t["name"]]
    if tt is not t:
        continue
    ct = t.get("char_type")
    kind, refusal, info = classify(SOFTA, t["name"], t, s, SALIGN)
    if kind == "scalar":
        continue
    key = (kind, (refusal or "none").split(" ")[0])
    stally[key] = stally.get(key, 0) + 1
    if ct == "VAL_BLK" and "valblk" not in first:
        first["valblk"] = (t["name"], t["record_layout_name"], [ws for ws in clean_lines(s["lines"]) if ws and ws[0] == "NUMBER"],
                           SOFTA["record_layouts_by_name"][t["record_layout_name"]]["lines"], refusal, info)
    if t["section"] == "MEASUREMENT" and "meas811" not in first:
        md = [ws for ws in clean_lines(s["lines"]) if ws and ws[0] == "MATRIX_DIM"]
        if md and md[0][1:] == ["8", "1", "1"]:
            first["meas811"] = (t["name"], refusal, info)
    if ct == "CURVE" and t["record_layout_name"] == "Hldoj[5].hg16.uc16.MXW3.QMGZFJ_TGXVUC" and "fixno" not in first:
        first["fixno"] = (t["name"], SOFTA["record_layouts_by_name"][t["record_layout_name"]]["lines"], refusal, info)
    if ct == "CURVE" and "comaxis" not in first:
        axes = [c for c in s.get("children") or [] if c["name"] == "AXIS_DESCR"]
        w = A._flatten_body_tokens(axes[0].get("lines") or []) if axes else []
        if w and w[0] == "COM_AXIS":
            ref = w[w.index("AXIS_PTS_REF") + 1]
            found = find_axis_pts(SOFTA["sections"], ref)
            first["comaxis"] = (t["name"], "AXIS_DESCR max", w[3], "ref", ref, "axis object max",
                                found[1][7] if found else None, refusal, info)
for k, v in first.items():
    p("P6 SOFTA first " + k, v)
p("P6 SOFTA tally (kind, first refusal)", sorted(stally.items()))

for fname, objs in [("check_test.a2l", ["Curve_ExternalAxis"]),
                    ("update_test1.a2l", ["Curve_ExternalAxis", "Curve_InternalAxis", "Map_ExternalAxis", "Map_InternalAxis", "Characteristic_ValBlk"]),
                    ("update_test2.a2l", ["Curve_InternalAxis_bad_axis_size"])]:
    d = parse(EX / fname)
    pd = pair(d)
    mal = mod_common_alignments((A._collect_sections_by_name(d["sections"], "MODULE") or [None])[0])
    for o in objs:
        if o not in pd:
            p("P6 " + fname, o, "absent")
            continue
        t, s = pd[o]
        lay = d["record_layouts_by_name"].get(t["record_layout_name"])
        p("P6 " + fname, o, classify(d, o, t, s, mal), "layout", t["record_layout_name"],
          "fix_no", read_layout(lay["lines"])["fix_no"] if lay else None)

# ---------------------------------------------------------------- P7 case 08 (1 MiB, seed 20260001)
c08 = out_dir / "c08"
M.generate(c08, 20260001, 1.0)
for a2l_name in ["firmware.a2l", "firmware_issues.a2l"]:
    d = parse(c08 / a2l_name)
    pd = pair(d)
    mal = mod_common_alignments(A._collect_sections_by_name(d["sections"], "MODULE")[0])
    ctally = {}
    for t in d["tags"]:
        tt, s = pd[t["name"]]
        if tt is not t:
            continue
        kind, refusal, info = classify(d, t["name"], t, s, mal)
        if kind == "scalar":
            continue
        key = (t.get("char_type"), (refusal or "none").split(" ")[0], info[0] if isinstance(info, tuple) else info)
        ctally[key] = ctally.get(key, 0) + 1
    p("P7 C08 " + a2l_name + " tally (char_type, refusal, element count)", sorted(ctally.items()))
d = parse(c08 / "firmware.a2l")
pd = pair(d)
for o in ["VAL_BLK_0001", "CURVE_0001", "MAP_0001"]:
    t, s = pd[o]
    p("P7 C08", o, "addr", hex(t["address"]), "bo", t["effective_byte_order"], "deposit", t["record_layout_name"],
      "layout lines", d["record_layouts_by_name"][t["record_layout_name"]]["lines"])
objs = M.build_objects(M.compute_region_sizes(1.0), random.Random(20260001))
plan = {o["name"]: o for o in objs}
mem = S19File(str(c08 / "firmware.s19")).get_memory_map() if hasattr(S19File, "get_memory_map") else None
for o in ["VAL_BLK_0001", "CURVE_0001", "MAP_0001"]:
    ob = plan[o]
    big = ob["big_endian"]
    vals = [struct.unpack(">H" if big else "<H", ob["raw_bytes"][2 * k: 2 * k + 2])[0] for k in range(len(ob["raw_bytes"]) // 2)]
    p("P7 C08 plan", o, "addr", hex(ob["address"]), "big", big, "n values", len(vals), "first 3", vals[:3],
      "value numbers 8x+y at (1,2):", vals[8 * 1 + 2] if o == "MAP_0001" else None,
      "image equals plan", mem is not None and all(mem.get(ob["address"] + k) == b for k, b in enumerate(ob["raw_bytes"])))

# ---------------------------------------------------------------- P8 DEFC draw order (Inc 2's five draws, then Inc 3's six)
rng = random.Random(20260001)
fill = [rng.randrange(256) for _ in range(256)]
enum_raw = rng.choice([0, 1, 2, 3])
bit = rng.randrange(2)
field = rng.randrange(256)
disp = rng.randint(-80, 300)
p("P8 Inc 2 draws (enum, bit, field, display)", enum_raw, bit, field, disp, "fill word at +0x10", hex(fill[0x10] << 8 | fill[0x11]))
ax_pts = sorted(rng.sample(range(1, 2000), 5))
c1 = [rng.randrange(65536) for _ in range(5)]
c2 = [rng.randrange(65536) for _ in range(5)]
mx = sorted(rng.sample(range(0, 1000), 4))
mv = [rng.randint(-1000, 1000) for _ in range(12)]
vb = [rng.randint(-800, 800) for _ in range(6)]
p("P8 Inc 3 draw 6 axis object stored points", ax_pts, "physical (x0.5)", [x * 0.5 for x in ax_pts])
p("P8 Inc 3 draw 7 CURVE_DEF_0001 values", c1)
p("P8 Inc 3 draw 8 CURVE_DEF_0002 values", c2)
p("P8 Inc 3 draw 9 MAP_DEF_0001 axis X stored points", mx)
p("P8 Inc 3 draw 10 MAP_DEF_0001 values in element order", mv)
p("P8 Inc 3 draw 11 VAL_BLK_DEF_0001 stored values in element order", vb, "physical", [x * 0.5 for x in vb])
# planned record bytes (big-endian)
axis_rec = struct.pack(">H", 5) + b"".join(struct.pack(">H", x) for x in ax_pts)
map_vals = [None] * 12
for y in range(3):
    for x in range(4):
        map_vals[y + 3 * x] = mv[x + 4 * y]  # element (x,y), element-order index x + 4y, COLUMN_DIR offset y + 3x
map_rec = b"".join(struct.pack(">H", x) for x in mx) + b"".join(struct.pack(">h", v) for v in map_vals)
vb_rec = b"".join(struct.pack(">h", v) for v in vb)  # ROW_DIR: element order = memory order
p("P8 AXIS_DEF_0001 record @0x800040", axis_rec.hex(" "))
p("P8 CURVE_DEF_0001 record @0x800050", b"".join(struct.pack(">H", v) for v in c1).hex(" "))
p("P8 CURVE_DEF_0002 record @0x800060", b"".join(struct.pack(">H", v) for v in c2).hex(" "))
p("P8 MAP_DEF_0001 record @0x800070", map_rec.hex(" "), "len", len(map_rec))
p("P8 MAP_DEF_0001 element (1,2) planned / at COLUMN_DIR offset", mv[1 + 4 * 2], map_vals[2 + 3 * 1])
p("P8 VAL_BLK_DEF_0001 record @0x800090", vb_rec.hex(" "), "texts", [f"{x * 0.5:.1f}" for x in vb])
p("P8 fill bytes under the Inc 3 objects (0x40..0x9B) differ from planned in", sum(1 for k, b in enumerate(axis_rec) if fill[0x40 + k] != b), "of", len(axis_rec), "axis bytes")
