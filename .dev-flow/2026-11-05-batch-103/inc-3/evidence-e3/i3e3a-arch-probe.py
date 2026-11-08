"""Inc 3a E3 architect probe (batch-103). THROWAWAY; writes nothing outside its scratch dir.

Runs on <runner> against a git-archive of the Inc 2a implementation (b103-inc2a-code @ 82f5f8e5),
extracted under /tmp/b103-e3-3-architect/clone. Pure functions only; no app, no display, no clipboard.

Q1  Inc 2a's real describe_definitions over every software_a name (median of 3) -- the base of
    R-A2L-DEF.136 that the rebase estimated with a prototype (0.740 s).
Q2  the walk alone vs the walk with Inc 3's two maps (AXIS_PTS by name, MOD_COMMON by identity).
Q3  Inc 3's per-object reads through the maps (the rebase's model, copied unchanged).
Q4  estimate = Q1 + (Q2 extra) + Q3, against 2.0 s.
Q5  describe-time amplification of FIX_AXIS points: K curves of FIX_AXIS_PAR_DIST 0 1 1048576 built
    as the graph's _fixed_points builds them (a tuple of n ints per axis): seconds and peak bytes.
Q6  AXIS_DESCR header words on the /begin line (meta) in V171 and software_a.
Q7  Inc 2a's describe of a MEASUREMENT with MATRIX_DIM 1 6 1 (leading 1) and of one with
    MATRIX_DIM written after ECU_ADDRESS on the same line.
Q8  the frozen layout walk on a layout line that holds two components.

Usage: python -I -B i3e3a-arch-probe.py <clone> <scratch dir>
"""
from __future__ import annotations

import statistics
import sys
import time
import tracemalloc
from pathlib import Path

clone = Path(sys.argv[1])
scratch = Path(sys.argv[2])
sys.path.insert(0, str(clone))
import s19_app  # noqa: E402
from s19_app.tui import a2l as A  # noqa: E402
from s19_app.tui import a2l_definition as D  # noqa: E402
from s19_app.tui.a2l_parse import parse_a2l_file  # noqa: E402

print("s19_app.__file__ =", s19_app.__file__, flush=True)
print("a2l_definition.__file__ =", D.__file__, flush=True)


def line(tag, value):
    print(f"[{tag}] {value}", flush=True)


COMPONENTS = {"FNC_VALUES", "AXIS_PTS_X", "AXIS_PTS_Y", "NO_AXIS_PTS_X", "NO_AXIS_PTS_Y"}


def clean_lines(lines):
    text = A._strip_a2l_comments("\n".join(lines))
    return [A._split_line_respecting_quotes(x) for x in text.split("\n") if x.strip()]


def walk_alone(data):
    objects, methods, tables = {}, {}, {}

    def _walk(nodes):
        for node in nodes:
            n = node.get("name")
            parsed = A.parse_begin_meta(node.get("meta", "") or "")
            if n in ("MEASUREMENT", "CHARACTERISTIC"):
                objects.setdefault(parsed[0], []).append(node)
            elif n == "COMPU_METHOD":
                methods.setdefault(parsed[0], node)
            elif n in ("COMPU_VTAB", "COMPU_VTAB_RANGE"):
                tables.setdefault(parsed[0], node)
            _walk(node.get("children") or [])

    _walk(data.get("sections") or [])
    return objects, methods, tables


def build_maps3(data):
    objects, methods, tables, axis_pts, mod_common_of = {}, {}, {}, {}, {}
    stack = [(s, None) for s in reversed(data["sections"])]
    while stack:
        s, mc = stack.pop()
        n = s.get("name")
        if n == "MODULE":
            mc = next((c for c in (s.get("children") or []) if c.get("name") == "MOD_COMMON"), None)
        elif n in ("MEASUREMENT", "CHARACTERISTIC"):
            objects.setdefault(A.parse_begin_meta(s.get("meta", "") or "")[0], s)
            mod_common_of[id(s)] = mc
        elif n == "AXIS_PTS":
            axis_pts.setdefault(A.parse_begin_meta(s.get("meta", "") or "")[0], s)
            mod_common_of[id(s)] = mc
        elif n == "COMPU_METHOD":
            methods.setdefault(A.parse_begin_meta(s.get("meta", "") or "")[0], s)
        elif n in ("COMPU_VTAB", "COMPU_VTAB_RANGE"):
            tables.setdefault(A.parse_begin_meta(s.get("meta", "") or "")[0], s)
        ch = s.get("children")
        if ch:
            stack.extend((c, mc) for c in reversed(ch))
    return objects, methods, tables, axis_pts, mod_common_of


def read_layout(lines):
    comps, align = [], []
    for ws in clean_lines(lines):
        if ws[0] in COMPONENTS:
            comps.append(ws)
        elif ws[0] in A._ALIGNMENT_DIRECTIVES:
            align.append(ws)
    try:
        comps.sort(key=lambda ws: int(ws[1]))
    except (IndexError, ValueError):
        pass
    return comps, align


def place(comps, align, counts):
    lines = [" ".join(ws) for ws in align] + [" ".join(ws) for ws in comps]
    return A._walk_record_layout_components({"lines": lines}, list(counts))


def inc3_reads(data, maps):
    objects, _m, _t, axis_pts, mod_common_of = maps
    layouts = data.get("record_layouts_by_name") or {}
    seen = {"VAL_BLK": 0, "CURVE": 0, "MAP": 0, "MEASUREMENT array": 0, "COM axes": 0, "AXIS_DESCR": 0}
    for t in data["tags"]:
        sec = objects.get(t["name"])
        if sec is None:
            continue
        kind = t.get("char_type") if t.get("section") == "CHARACTERISTIC" else "MEASUREMENT"
        own = clean_lines(sec.get("lines") or [])
        md = next((ws for ws in own if ws and ws[0] == "MATRIX_DIM"), None)
        if kind == "MEASUREMENT":
            if md is None or all(w == "1" for w in md[1:]):
                continue
            seen["MEASUREMENT array"] += 1
            continue
        if kind not in ("VAL_BLK", "CURVE", "MAP"):
            continue
        seen[kind] += 1
        header = A._flatten_body_tokens([sec.get("meta") or ""] + list(sec.get("lines") or []))
        lay = layouts.get(header[4] if len(header) > 4 else None)
        if lay is None:
            continue
        comps, align = read_layout(lay.get("lines") or [])
        counts = []
        for c in sec.get("children") or []:
            if c.get("name") != "AXIS_DESCR":
                continue
            seen["AXIS_DESCR"] += 1
            words = A._flatten_body_tokens([c.get("meta") or ""] + list(c.get("lines") or []))
            try:
                counts.append(int(words[3]))
            except (IndexError, ValueError):
                counts.append(1)
            if words and words[0] == "COM_AXIS" and "AXIS_PTS_REF" in words:
                i = words.index("AXIS_PTS_REF")
                ax = axis_pts.get(words[i + 1] if i + 1 < len(words) else None)
                if ax is not None:
                    seen["COM axes"] += 1
                    ah = A._flatten_body_tokens([ax.get("meta") or ""] + list(ax.get("lines") or []))
                    alay = layouts.get(ah[4] if len(ah) > 4 else None)
                    if alay is not None:
                        ac, aa = read_layout(alay.get("lines") or [])
                        n = int(ah[7]) if len(ah) > 7 and ah[7].isdigit() else 1
                        place(ac, aa, [n])
                        _ = mod_common_of.get(id(ax))
                    counts[-1] = int(ah[7]) if len(ah) > 7 and ah[7].isdigit() else counts[-1]
        if kind == "VAL_BLK":
            counts = [1]
        place(comps, align, counts or [1])
        mc = mod_common_of.get(id(sec))
        if mc is not None:
            malign = [ws for ws in clean_lines(mc.get("lines") or []) if ws and ws[0] in A._ALIGNMENT_DIRECTIVES]
            declared = {ws[0] for ws in align}
            extra = [ws for ws in malign if ws[0] not in declared]
            if extra:
                place(comps, align + extra, counts or [1])
    return seen


INLINE = """ASAP2_VERSION 1 71
/begin PROJECT P ""
/begin MODULE M ""
/begin MOD_COMMON ""
BYTE_ORDER MSB_FIRST
/end MOD_COMMON
/begin MEASUREMENT MD161 ""
UBYTE NO_COMPU_METHOD 0 0 0 255
ECU_ADDRESS 0x10
MATRIX_DIM 1 6 1
/end MEASUREMENT
/begin MEASUREMENT MDMID ""
UBYTE NO_COMPU_METHOD 0 0 0 255
ECU_ADDRESS 0x20 MATRIX_DIM 4
/end MEASUREMENT
/end MODULE
/end PROJECT
"""


def main():
    softa = clone / "examples" / "case_00_public" / "software_a.a2l"
    v171 = clone / "examples" / "case_00_public" / "ASAP2_Demo_V171.a2l"
    data = parse_a2l_file(softa)
    names = [t["name"] for t in data["tags"]]
    line("Q0 software_a tags", len(names))

    runs = []
    for _ in range(3):
        t0 = time.perf_counter()
        D.describe_definitions(names, data)
        runs.append(time.perf_counter() - t0)
    q1 = statistics.median(runs)
    line("Q1 Inc 2a real describe_definitions, every name: runs s / median s", ([round(r, 3) for r in runs], round(q1, 3)))

    w2, w3 = [], []
    for _ in range(5):
        t0 = time.perf_counter()
        walk_alone(data)
        w2.append(time.perf_counter() - t0)
        t0 = time.perf_counter()
        maps = build_maps3(data)
        w3.append(time.perf_counter() - t0)
    line("Q2 walk alone / walk with Inc 3's two maps, median ms",
         (round(statistics.median(w2) * 1000, 2), round(statistics.median(w3) * 1000, 2)))

    r3 = []
    for _ in range(3):
        t0 = time.perf_counter()
        seen = inc3_reads(data, maps)
        r3.append(time.perf_counter() - t0)
    q3 = statistics.median(r3)
    line("Q3 Inc 3 per-object reads: shapes", seen)
    line("Q3 Inc 3 per-object reads: runs s / median s", ([round(r, 4) for r in r3], round(q3, 4)))
    total = q1 + (statistics.median(w3) - statistics.median(w2)) + q3
    line("Q4 estimate: Inc 2a real + maps' extra + Inc 3 reads, s (bound 2.0 s)", round(total, 3))
    line("Q4 same with Inc 3 reads scaled x1.35 (2a real / 2a prototype = 1.0/0.74)", round(q1 + (statistics.median(w3) - statistics.median(w2)) + q3 * 1.35, 3))

    # Q5: FIX points built at describe, as the graph's _fixed_points does (n ints per axis).
    for k in (1, 4):
        tracemalloc.start()
        t0 = time.perf_counter()
        kept = []
        for _ in range(k):
            o, d, n = 0, 1, 1048576
            kept.append(tuple(o + i * d for i in range(n)))
        dt = time.perf_counter() - t0
        _cur, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        line(f"Q5 {k} FIX curve(s) of 1048576 points built at describe: s / peak MB",
             (round(dt, 3), round(peak / 1e6, 1)))
        del kept

    # Q6: AXIS_DESCR header on the /begin line.
    for label, path in (("V171", v171), ("SOFTA", softa)):
        d = parse_a2l_file(path)
        tot = in_meta = 0
        stack = list(d["sections"])
        while stack:
            s = stack.pop()
            if s.get("name") == "AXIS_DESCR":
                tot += 1
                if (s.get("meta") or "").strip():
                    in_meta += 1
            stack.extend(s.get("children") or [])
        line(f"Q6 {label} AXIS_DESCR sections / with words on the /begin line", (tot, in_meta))

    # Q7: Inc 2a on a leading-1 MATRIX_DIM and a mid-line MATRIX_DIM.
    p = scratch / "inline-q7.a2l"
    p.write_text(INLINE, encoding="ascii")
    d = parse_a2l_file(p)
    for nm in ("MD161", "MDMID"):
        tag = next(t for t in d["tags"] if t["name"] == nm)
        df = D.describe_definition(nm, d)
        line(f"Q7 {nm}: tag matrix_dim / 2a kind / 2a byte_length / refusal",
             (tag.get("matrix_dim"), df.kind, df.byte_length, df.refusal))

    # Q8: the frozen walk on a line holding two components.
    lay = {"lines": ["NO_AXIS_PTS_X 1 UBYTE AXIS_PTS_X 2 UBYTE INDEX_INCR DIRECT",
                     "FNC_VALUES 3 UWORD ROW_DIR DIRECT"]}
    out = A._walk_record_layout_components(lay, [4])
    line("Q8 walk on 'NO_AXIS_PTS_X 1 UBYTE AXIS_PTS_X 2 UBYTE …' + FNC_VALUES, 4 points: (component, offset)",
         [(c["component"], c["offset"]) for c in (out or [])])


if __name__ == "__main__":
    main()
