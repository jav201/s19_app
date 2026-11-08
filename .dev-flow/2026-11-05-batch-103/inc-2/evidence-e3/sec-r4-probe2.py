"""E3 round-4 security probe 2, Inc 2 (batch-103). Base parser only (clone e07fb00), read-only.

Q: an object commented out with a block comment whose /begin and /end lines start their lines
   (the usual way to keep an old copy) - does the line-based section builder make it a live
   section and a live tag, and which one does "the first tag / first section of the name"
   (R-A2L-DEF.5, `_find_tag`, `describe_definitions`) pick when the live copy follows it?
REF = the C-rule reader of sec-r4-probe.py (comments removed before /begin and /end are matched).
"""
import sys, pathlib, tempfile, re
repo = pathlib.Path(sys.argv[1]); scratch = pathlib.Path(sys.argv[2])
sys.path.insert(0, str(repo))
import s19_app, s19_app.tui.a2l as a
print("s19_app.__file__ =", s19_app.__file__)

HDR = '''ASAP2_VERSION 1 71
/begin PROJECT P ""
/begin MODULE M ""
/begin MOD_COMMON ""
BYTE_ORDER MSB_FIRST
/end MOD_COMMON
/begin COMPU_METHOD CM_ID "" IDENTICAL "%.0" ""
/end COMPU_METHOD
@BODY@
/end MODULE
/end PROJECT
'''
OLD = '''/* old copy, kept for reference
/begin MEASUREMENT X "old"
 UWORD CM_ID 0 0 0 65535
 ECU_ADDRESS 0x10
/end MEASUREMENT
*/'''
NEW = '''/begin MEASUREMENT X "new"
 UWORD CM_ID 0 0 0 65535
 ECU_ADDRESS 0x20
/end MEASUREMENT'''
CASES = {"P1 old copy commented out, live copy below": OLD + "\n" + NEW,
         "P2 only a commented-out copy": OLD}

def walk(secs):
    for s in secs:
        yield s; yield from walk(s.get("children") or [])

def ref_addresses(text, name):
    t = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return [int(m.group(1), 0) for m in re.finditer(r"/begin\s+MEASUREMENT\s+" + re.escape(name) + r"\s.*?ECU_ADDRESS\s+(\S+)", t, flags=re.S)]

with tempfile.TemporaryDirectory(dir=str(scratch)) as d:
    for label, body in CASES.items():
        text = HDR.replace("@BODY@", body)
        p = pathlib.Path(d) / "x.a2l"; p.write_text(text, encoding="utf-8")
        data = a.parse_a2l_file(p)
        secs = [s for s in walk(data["sections"]) if s["name"] == "MEASUREMENT" and a.parse_begin_meta(s["meta"])[0] == "X"]
        tags = [t for t in data["tags"] if t["name"] == "X"]
        print(f"[{label.split()[0]}] {label}")
        print(f"     parse errors={data['errors']}")
        print(f"     sections named X: {[(s['start_line'], s.get('end_line'), a.parse_begin_meta(s['meta'])[1]) for s in secs]}")
        print(f"     tags named X (file order): {[(t['address'], t['datatype'], t['length']) for t in tags]}")
        print(f"     first tag (R-A2L-DEF.5 / _find_tag): address={tags[0]['address'] if tags else None!r}; first section long id={a.parse_begin_meta(secs[0]['meta'])[1] if secs else None!r}")
        print(f"     REF (comments removed first): live X at {ref_addresses(text, 'X')}")
