"""E3 round-5 security probe 2, Inc 2 (batch-103): real-file exposure of R-A2L-DEF.138's index. Base parser only
(clone e07fb00), read-only. Imports the model of sec-r5-probe.py (same folder; its Part 1-3 do not run on import).

Q: in the 35 tracked fixture files, which objects does the row let an encode write (refusal None and shared_with None
   in the POS reading) although their bytes overlap bytes that the A2L declares for an object the index leaves out or
   under-sizes:
     INSTANCE   address = the 4th word of the record, size = the TYPEDEF's (a TYPEDEF_MEASUREMENT datatype, a
                TYPEDEF_CHARACTERISTIC VALUE's record-layout datatype, a TYPEDEF_AXIS's max points x its layout
                datatype), x the INSTANCE's MATRIX_DIM product; an unknown size counts 1 byte (a lower bound)
     BLOB       address and size words
     AXIS_PTS   address word, max axis points x the AXIS_PTS_X datatype of its record layout (else 1 byte)
     MATRIX_DIM an indexed MEASUREMENT / CHARACTERISTIC whose MATRIX_DIM line has several numbers: the product
     no length  a MEASUREMENT / CHARACTERISTIC with a declared address and no length: 1 byte at its address (lower bound)
"""
import collections, pathlib, re, subprocess, sys
here = pathlib.Path(__file__).resolve().parent
repo = pathlib.Path(sys.argv[1])
sys.argv = [sys.argv[0], sys.argv[1], sys.argv[2]]
src = (here / "sec-r5-probe.py").read_text(encoding="utf-8")
cut = src.index("# ------------------------------------------------------------------------------------------------ Part 1")
ns = {"__name__": "probe", "__file__": str(here / "sec-r5-probe.py")}
exec(compile(src[:cut], "sec-r5-probe.py(helpers)", "exec"), ns)
a = ns["a"]; model = ns["model"]; walk = ns["walk"]; shared_with = ns["shared_with"]; _sw = ns["_sw_unmasked"]
readable = ns["readable"]; num = ns["num"]; DEC = ns["DEC"]

def words(s): return a._flatten_body_tokens([s.get("meta", "")] + list(s.get("lines") or []))
def dims(ws):
    if "MATRIX_DIM" not in ws: return 1
    j = ws.index("MATRIX_DIM") + 1; p = 1
    while j < len(ws) and DEC.fullmatch(ws[j]): p *= int(ws[j]); j += 1
    return p
def layout_dt(data, name, component):
    lay = data["record_layouts_by_name"].get(name) or {}
    for ln in lay.get("lines") or []:
        p = ln.split()
        if len(p) >= 3 and p[0] == component and p[2] in a.DATATYPE_SIZES: return a.DATATYPE_SIZES[p[2]]
    return None

files = subprocess.run(["git", "-C", str(repo), "ls-files", "*.a2l"], capture_output=True, text=True, check=True).stdout.split()
TOT = collections.Counter(); HITS = []
for f in files:
    data = a.parse_a2l_file(repo / f)
    try: objs = model(data)
    except AssertionError: print(f"[FX2] {f}: mismatch, skipped"); continue
    secs = list(walk(data["sections"]))
    typedef = {}
    for s in secs:
        if s["name"].startswith("TYPEDEF_"):
            w = words(s); size = None
            if s["name"] == "TYPEDEF_MEASUREMENT" and len(w) > 2: size = a.DATATYPE_SIZES.get(w[2])
            elif s["name"] == "TYPEDEF_CHARACTERISTIC" and len(w) > 3 and w[2] == "VALUE": size = layout_dt(data, w[3], "FNC_VALUES")
            elif s["name"] == "TYPEDEF_AXIS" and len(w) > 6 and DEC.fullmatch(w[6] or ""): size = (layout_dt(data, w[3], "AXIS_PTS_X") or 1) * int(w[6])
            typedef[w[0] if w else ""] = size
    spans = []   # (kind, name, start, end)
    for s in secs:
        w = words(s)
        try:
            if s["name"] == "INSTANCE" and len(w) > 3 and readable(w[3]):
                size = typedef.get(w[2]); spans.append(("INSTANCE", w[0], num(w[3]), num(w[3]) + (size or 1) * dims(w[4:]) - 1, size is not None))
            elif s["name"] == "BLOB" and len(w) > 3 and readable(w[2]) and DEC.fullmatch(w[3]):
                spans.append(("BLOB", w[0], num(w[2]), num(w[2]) + int(w[3]) - 1, True))
            elif s["name"] == "AXIS_PTS" and len(w) > 7 and readable(w[2]) and DEC.fullmatch(w[7]):
                el = layout_dt(data, w[4], "AXIS_PTS_X"); spans.append(("AXIS_PTS", w[0], num(w[2]), num(w[2]) + (el or 1) * int(w[7]) - 1, el is not None))
        except (ValueError, IndexError):
            pass
    msecs = [s for s in secs if s["name"] in ("MEASUREMENT", "CHARACTERISTIC")]
    for o, s in zip(objs, msecs):
        if o["addr"] is None: continue
        if not o["length"]:
            spans.append(("no-length", o["name"], o["addr"], o["addr"], False)); continue
        p = dims(words(s))
        md = [ln.split() for ln in s["lines"] if ln.split()[:1] == ["MATRIX_DIM"]]
        if md:
            first = int(md[-1][1], 0) if DEC.fullmatch(md[-1][1]) else None
            if first and p != first:
                spans.append(("MATRIX_DIM", o["name"], o["addr"], o["addr"] + (o["length"] // first) * p - 1, True))
    TOT["undeclared-spans"] += len(spans)
    if not spans: continue
    for o in objs:
        if o["refusal"] is not None or o["addr"] is None or not o["length"]: continue
        lo, hi = o["addr"], o["addr"] + o["length"] - 1
        hits = [(k, n, st, en, exact) for k, n, st, en, exact in spans if n != o["name"] and st <= hi and lo <= en]
        if not hits: continue
        sw = shared_with(objs, o, "POS") if o["mask"] is not None else _sw(objs, o)
        TOT["defined-objects-over-an-unindexed-span"] += 1
        if sw is None:
            TOT["...of which-.138-lets-encode"] += 1
            HITS.append((f, o["name"], hex(o["addr"]), o["length"], [(k, n, hex(st), en - st + 1, "exact" if ex else "lower bound") for k, n, st, en, ex in hits]))
    print(f"[FX2] {f}: unindexed-or-undersized spans={collections.Counter(k for k, *_ in spans)}")
print("[FX2-total] " + " ".join(f"{k}={v}" for k, v in TOT.items()))
for h in HITS: print("[FX2-hit] " + repr(h))
