"""B: SEC6-3 — manifest destination checked unresolved against THIS work area.
B1: project folder already a junction into another work area at write time.
B2: swap AFTER the containment check, before os.replace (residual window).
B3: staging leftovers on every failure path (containment refusal, serialize
    refusal, replace failure: project.json is a folder; held project.json)."""
import ctypes, os, sys, json
from common import *
from s19_app.tui.models import ProjectVariantSet
from s19_app.tui.services import manifest_writer as mw

def vs():
    return ProjectVariantSet(project_name="P", variants=(), active_id=None)

def staging(base):
    st = wa(base) / "temp" / ".staging"
    return sorted(p.name for p in st.iterdir()) if st.exists() else "<no .staging>"

# B1
root = fresh("B1")
b1, b2 = root / "one", root / "two"
P, Q = wa(b1) / "P", wa(b2) / "Q"
P.parent.mkdir(parents=True); Q.mkdir(parents=True)
(Q / "project.json").write_text('{"schema_version": 1, "active_variant": "victim"}')
before = snap(wa(b2))
junction(P, Q)
try:
    written, issues = mw.write_project_manifest(vs(), P, b1)
finally:
    rm_junction(P)
print("[B1 junction at write] written:", written, "codes:", [i.code for i in issues])
print("   other work area diff:", diff(before, snap(wa(b2))), "| staging:", staging(b1))

# B2: swap inside the window between _check_destination_contained and os.replace
root = fresh("B2")
b1, b2 = root / "one", root / "two"
P, Q = wa(b1) / "P", wa(b2) / "Q"
P.mkdir(parents=True); Q.mkdir(parents=True)
(Q / "project.json").write_text('{"schema_version": 1, "active_variant": "victim"}')
before = snap(wa(b2))
real_stage = mw._private_stage_dir
def swapping_stage(workarea):
    os.rmdir(P)            # P is empty: replace it by a junction to Q
    junction(P, Q)
    return real_stage(workarea)
mw._private_stage_dir = swapping_stage
try:
    written, issues = mw.write_project_manifest(vs(), P, b1)
finally:
    mw._private_stage_dir = real_stage
    if P.exists(): rm_junction(P)
print("[B2 swap after check] written:", written, "codes:", [i.code for i in issues])
print("   other work area diff:", diff(before, snap(wa(b2))), "| staging:", staging(b1))
print("   Q/project.json now:", (Q / "project.json").read_text()[:80].replace("\n", " "))

# B3 leftovers
root = fresh("B3")
base = root / "app"
P = wa(base) / "P"; P.mkdir(parents=True)
(P / "project.json").mkdir()      # replace fails: a folder
w, iss = mw.write_project_manifest(vs(), P, base)
print("[B3a project.json is a folder] written:", w, [i.code for i in iss], "| staging:", staging(base))
(P / "project.json").rmdir()
w, iss = mw.write_project_manifest(vs(), P, base, batch=["../x.json"])
print("[B3b serialize refusal] written:", w, [i.code for i in iss], "| staging:", staging(base))
(P / "project.json").write_text("{}")
k32 = ctypes.windll.kernel32
k32.CreateFileW.restype = ctypes.c_void_p
h = k32.CreateFileW(str(P / "project.json"), 0x80000000, 0, None, 3, 0x80, None)  # share mode 0
try:
    w, iss = mw.write_project_manifest(vs(), P, base)
finally:
    k32.CloseHandle(ctypes.c_void_p(h))
print("[B3c project.json held (share 0)] written:", w, [i.code for i in iss], "| staging:", staging(base))
print("   message:", iss[0].message[:160] if iss else None)
