"""E3 round-2 security probe (Inc 11), runner only, against the read-only e07fb00 clone. Modes:
  enrich  - what the base downstream code does with a tag whose length the corrected reader refuses (READ.38/.61):
            the tag's 'length' is set to None (the Inc 11 outcome per the graph), then the base
            enrich_a2l_tags_with_values (a2l.py, Inc 11's own file, not in the graph) and the base picker
            (A2LParameterPicker.set_parameters, unmounted) are run; their byte_size / size is the write size of the
            Patch Editor's 'Use parameter' and of a Check Editor field.
  named   - E3A-01's named-kind rule makes sections reachable that the base readers never saw. Each public-corpus file
            is read as bytes (never copied); in memory, a '/begin <named kind>' line alone gets its name line (and the
            long-identifier line) joined onto it, then the base parse, render, enrich and validation run on that text
            through a duck-typed path. Counts only: exceptions, and how many more COMPU_METHOD / RECORD_LAYOUT /
            COMPU_VTAB names the base readers find.
  depth   - a 32-level tree (the cap) through every base recursive walker, and render."""
import io, sys, time, hashlib, collections, re
sys.path.insert(0, "/home/<user>/work/s19_app")
import s19_app
from pathlib import Path
from s19_app.tui import a2l as A
print("s19_app.__file__ =", s19_app.__file__)
MODE = sys.argv[1]


class FakePath:
    def __init__(self, text, name):
        self.text, self.name = text, name
    def open(self, *a, **k):
        return io.StringIO(self.text)
    def __str__(self):
        return self.name


def parse_text(text, name="mem.a2l"):
    return A.parse_a2l_file(FakePath(text, name))


if MODE == "enrich":
    from s19_app.tui.a2l_parameter_picker import A2LParameterPicker
    text = """ASAP2_VERSION 1 71
/begin PROJECT P ""
/begin MODULE M ""
/begin COMPU_METHOD CM_ID "" IDENTICAL "%.0" ""
/end COMPU_METHOD
/begin RECORD_LAYOUT RL_U16
FNC_VALUES 1 UWORD ROW_DIR DIRECT
/end RECORD_LAYOUT
/begin CHARACTERISTIC C_B6 "VALUE on RL_U16 with LENGTH 4 (sizes 2 and 4)"
VALUE 0x2000 RL_U16 0 CM_ID 0 65535
LENGTH 4
/end CHARACTERISTIC
/begin CHARACTERISTIC C_VB "VAL_BLK MATRIX_DIM 4 and NUMBER 5 (sizes 8 and 10)"
VAL_BLK 0x2100 RL_U16 0 CM_ID 0 65535
MATRIX_DIM 4
NUMBER 5
/end CHARACTERISTIC
/begin CHARACTERISTIC C_L0 "VALUE LENGTH 0 (outside 1..1048576)"
VALUE 0x2200 RL_U16 0 CM_ID 0 65535
LENGTH 0
/end CHARACTERISTIC
/begin CHARACTERISTIC C_X4 "VALUE MATRIX_DIM x4 (gives no number)"
VALUE 0x2300 RL_U16 0 CM_ID 0 65535
MATRIX_DIM x4
/end CHARACTERISTIC
/begin MEASUREMENT M_L0 "UWORD LENGTH 0"
UWORD CM_ID 0 0 0 65535
ECU_ADDRESS 0x3000
LENGTH 0
/end MEASUREMENT
/end MODULE
/end PROJECT
"""
    d = parse_text(text)
    print("[EN] base reader: " + "; ".join(f"{t['name']} length={t.get('length')}" for t in d["tags"]))
    for t in d["tags"]:
        t["length"] = None  # the Inc 11 outcome of READ.38 / READ.61 for each of these five tags (graph examples)
    mem = {a: 0x11 for a in range(0x2000, 0x2400)}
    mem.update({a: 0x22 for a in range(0x3000, 0x3010)})
    en = A.enrich_a2l_tags_with_values(d, mem)
    for t in en:
        print(f"[EN] {t['name']}: reader length=None -> enriched byte_size={t.get('byte_size')} raw_bytes={t.get('raw_bytes')} "
              f"raw_value={t.get('raw_value')} physical={t.get('physical_value')}")
    rows = [t for t in en if isinstance(t.get("address"), int)]
    pk = A2LParameterPicker(mode="highlight")
    pk.set_parameters(rows)
    for name, (addr, size, fmt) in pk._param_rows.items():
        print(f"[EN-picker] {name}: address=0x{addr:X} size={size} fmt={fmt!r}  (the 'Use parameter' prefill size)")

elif MODE == "named":
    NAMED = {"AXIS_PTS", "BLOB", "CHARACTERISTIC", "COMPU_METHOD", "COMPU_TAB", "COMPU_VTAB", "COMPU_VTAB_RANGE", "FRAME",
             "FUNCTION", "GROUP", "INSTANCE", "MEASUREMENT", "MEMORY_SEGMENT", "MODULE", "PROJECT", "RECORD_LAYOUT",
             "TRANSFORMER", "UNIT"}
    from s19_app.validation import rules as V
    man = {}
    for row in Path("/home/<user>/a2l-corpus/manifest.tsv").read_text(encoding="utf-8", errors="replace").splitlines()[1:]:
        parts = row.split("\t")
        if len(parts) > 2:
            man[parts[2] if len(parts[2]) == 64 else parts[-1]] = parts[0]
    agg = collections.Counter(); seen = set(); excs = collections.Counter()
    for k, f in enumerate(sorted(Path("/home/<user>/a2l-corpus/files").iterdir())):
        raw = f.read_bytes(); sha = hashlib.sha256(raw).hexdigest()
        if sha in seen:
            continue
        seen.add(sha); fid = man.get(sha, f"#{k}")
        text = raw.decode("utf-8", errors="replace")
        lines = re.split(r"\r\n|\r|\n", text)
        out, i, joined = [], 0, 0
        while i < len(lines):
            ln = lines[i]; parts = ln.split()
            if len(parts) == 2 and parts[0].lower() == "/begin" and (parts[1] in NAMED or parts[1].startswith("TYPEDEF_")):
                j = i + 1
                while j < len(lines) and not lines[j].strip():
                    j += 1
                if j < len(lines) and not lines[j].strip().lower().startswith(("/begin", "/end", "/*", "//")):
                    merged = ln + " " + lines[j].strip()
                    nxt = j + 1
                    if len(lines[j].split()) == 1 and nxt < len(lines) and lines[nxt].strip().startswith('"'):
                        merged += " " + lines[nxt].strip(); nxt += 1
                    out.append(merged); out.extend([""] * (nxt - i - 1)); i = nxt; joined += 1; continue
            out.append(ln); i += 1
        if not joined:
            continue
        agg["files_with_joins"] += 1; agg["joins"] += joined
        before = parse_text(text)
        try:
            d = parse_text("\n".join(out), name=f"n{fid}")
        except BaseException as e:
            excs[("parse", type(e).__name__)] += 1; print(f"[NK-exc] n={fid} parse {type(e).__name__}"); continue
        for stage, fn in (("render", lambda: A.render_a2l_view(d)), ("enrich", lambda: A.enrich_a2l_tags_with_values(d, None)),
                          ("validate", lambda: V.validate_a2l_structure(d, d.get("tags")))):
            try:
                fn()
            except BaseException as e:
                excs[(stage, type(e).__name__)] += 1; print(f"[NK-exc] n={fid} {stage} {type(e).__name__}")
        for key in ("compu_methods_by_name", "record_layouts_by_name", "compu_tabs_by_name"):
            agg[key + "_gained"] += len(d.get(key) or {}) - len(before.get(key) or {})
        bl = {(t.get("section"), t.get("name")): t.get("length") for t in before.get("tags", [])}
        for t in d.get("tags", []):
            key = (t.get("section"), t.get("name"))
            if key in bl and bl[key] != t.get("length"):
                agg["tag_length_changed"] += 1
    print("[NK] " + " ".join(f"{k}={agg[k]}" for k in sorted(agg)) + f" exceptions={dict(excs) or 0}")

elif MODE == "depth":
    for depth in (32,):
        text = 'ASAP2_VERSION 1 71\n' + "".join(f"/begin GROUP G{i} \"\"\n" for i in range(depth - 3)) + \
            '/begin PROJECT P ""\n/begin MODULE M ""\n/begin MEASUREMENT X ""\nUWORD CM_ID 0 0 0 65535\nECU_ADDRESS 0x10\n/end MEASUREMENT\n/end MODULE\n/end PROJECT\n' + \
            "".join("/end GROUP\n" for i in range(depth - 3))
        d = parse_text(text)
        A.render_a2l_view(d); A.iter_section_lines(d["sections"]); A.extract_memory_segments(d["sections"])
        A.extract_record_layouts(d["sections"]); A.enrich_a2l_tags_with_values(d, None)
        print(f"[DP {depth} levels] base walkers + render: no exception; tags={len(d['tags'])} errors={d['errors']}")
