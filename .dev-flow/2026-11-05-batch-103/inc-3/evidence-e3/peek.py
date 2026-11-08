import sys, pathlib
sys.path.insert(0, "/home/<user>/work/b103-int2a")
import s19_app, s19_app.tui.a2l as a
print("s19_app.__file__ =", s19_app.__file__)
d = a.parse_a2l_file(pathlib.Path("/home/<user>/work/b103-int2a/examples/case_00_public/ASAP2_Demo_V171.a2l"))
print(sorted(d.keys()))
def walk(ns, out):
    for n in ns:
        out.append(n); walk(n.get("children") or [], out)
out=[]; walk(d["sections"], out)
for s in out:
    if s.get("name")=="CHARACTERISTIC" and "CURVE.COM_AXIS" in (s.get("meta") or ""):
        print({k:v for k,v in s.items() if k!="children"})
        for c in s.get("children") or []: print("  child", {k:v for k,v in c.items() if k!="children"})
        break
for s in out:
    if s.get("name")=="AXIS_PTS": print({k:v for k,v in s.items() if k!="children"}); break
for s in out:
    if s.get("name")=="CHARACTERISTIC" and "PAR_LIST" in (s.get("meta") or ""):
        for c in s.get("children") or []:
            print("  child", {k:v for k,v in c.items() if k!="children"})
            for g in c.get("children") or []: print("    grand", {k:v for k,v in g.items() if k!="children"})
print(d["record_layouts_by_name"]["RL.AXIS_PTS.SBYTE.DECR"])
print(repr(a._A2L_LINE_SENTINEL))
t=[t for t in d["tags"] if t.get("name")=="ASAM.C.CURVE.COM_AXIS"][0]; print(t)
