"""E3 round-3 security probe 2: where V171's unclosed /begin sits, and the own-lines variant of rule R."""
import sys, pathlib
repo = pathlib.Path(sys.argv[1]); sys.path.insert(0, str(repo))
import s19_app.tui.a2l as a
p = repo / "examples/case_00_public/ASAP2_Demo_V171.a2l"
d = a.parse_a2l_file(p)
def walk(ss, depth=0, parent=None):
    for s in ss:
        yield s, depth, parent
        yield from walk(s.get("children") or [], depth + 1, s)
print("errors:", d["errors"])
for s, dep, par in walk(d["sections"]):
    if "end_line" not in s:
        print(f"[V-unclosed] {s['name']} {a.parse_begin_meta(s['meta'])[0]!r} start_line={s['start_line']} depth={dep} children={len(s['children'])}")
OBJ = ("MEASUREMENT", "CHARACTERISTIC", "AXIS_PTS")
for s, dep, par in walk(d["sections"]):
    if s["name"] in OBJ and par is not None and par["name"] in OBJ:
        print(f"[V-nested-object] {s['name']} {a.parse_begin_meta(s['meta'])[0]} inside {par['name']} {a.parse_begin_meta(par['meta'])[0]} (line {s['start_line']})"); break
lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
first_bad = None
for s, dep, par in walk(d["sections"]):
    if "end_line" not in s:
        print("[V-context] lines", s["start_line"], "..", s["start_line"] + 6, ":", [l.strip() for l in lines[s['start_line']-1:s['start_line']+6]])
# own-lines variant: letters in meta + own lines only (no children); and rule E
def open_state(text):
    i, n, st = 0, len(text), None
    while i < n:
        c = text[i]
        if st == "quote":
            if c == '"' and text[i-1] != "\\": st = None
            i += 1; continue
        if st == "comment":
            if c == "*" and i+1 < n and text[i+1] == "/": st = None; i += 2; continue
            i += 1; continue
        if c == '"': st = "quote"; i += 1; continue
        if text.startswith("/*", i): st = "comment"; i += 2; continue
        if text.startswith("//", i):
            while i < n and text[i] != "\n": i += 1
            continue
        i += 1
    return st
own_hits, e_hits, nonobj_child_hits = [], [], []
for s, dep, par in walk(d["sections"]):
    if s["name"] not in ("MEASUREMENT", "CHARACTERISTIC"): continue
    own = "\n".join([s["meta"]] + s["lines"])
    words = a._flatten_body_tokens([s["meta"]] + s["lines"])
    n_own = own.upper().count("BIT_MASK")
    read = "BIT_MASK" in words[8 if s["name"] == "MEASUREMENT" else 9:]
    if n_own > 1 or (n_own == 1 and not read): own_hits.append(a.parse_begin_meta(s["meta"])[0])
    if open_state(own): e_hits.append(a.parse_begin_meta(s["meta"])[0])
    def nonobj(sec):
        for c in sec.get("children") or []:
            if c["name"] in OBJ: continue
            yield "\n".join([c["meta"]] + c["lines"]); yield from nonobj(c)
    if any("BIT_MASK" in t.upper() for t in nonobj(s)): nonobj_child_hits.append(a.parse_begin_meta(s["meta"])[0])
print(f"[V-own-lines R] {len(own_hits)} {own_hits[:5]}")
print(f"[V-rule E] {len(e_hits)} {e_hits[:5]}")
print(f"[V-non-object children holding BIT_MASK] {len(nonobj_child_hits)} {nonobj_child_hits[:5]}")
