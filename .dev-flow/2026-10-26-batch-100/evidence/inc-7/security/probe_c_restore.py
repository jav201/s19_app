"""C: SEC2-10 — _abort_save's restore (_restore_manifest) and the claimed
project.json.previous-<UTC> copy.
C1 held project.json (share mode 0) for the whole rollback -> retry, then copy.
C2 held for 0.2 s only -> the retry lands the restore, no copy.
C3 every claimable name pre-exists -> nothing overwritten, status says not kept.
C4 the claimed name pre-exists as a junction to an outside folder -> skipped.
C5 project folder swapped for a junction to an outside folder before the keep."""
import asyncio, ctypes, os, threading, time
from datetime import datetime, timezone
from common import *
from s19_app.tui.app import S19TuiApp
k32 = ctypes.windll.kernel32
k32.CreateFileW.restype = ctypes.c_void_p

def hold(path):
    return k32.CreateFileW(str(path), 0x80000000, 0, None, 3, 0x80, None)

def release(h):
    k32.CloseHandle(ctypes.c_void_p(h))

async def drive(base, fn):
    app = S19TuiApp(base_dir=base)
    statuses = []
    real = app.set_status
    app.set_status = lambda m, *a, **k: (statuses.append(str(m)), real(m, *a, **k))[1]
    async with app.run_test(size=(118, 54)) as pilot:
        await pilot.pause()
        out = fn(app)
        await pilot.pause()
        log4 = str(app.query_one("#log_line_4").render())
    return statuses, log4, out

PREV = b'{"schema_version": 1, "active_variant": "previous-bytes"}'

def setup(tag):
    base = fresh(tag) / "app"
    P = wa(base) / "P"; P.mkdir(parents=True)
    (P / "project.json").write_bytes(b'{"new": "bytes of the failed save"}')
    return base, P

def listing(P):
    return sorted(p.name for p in P.iterdir())

# C1
base, P = setup("C1")
h = hold(P / "project.json")
try:
    t = time.perf_counter()
    st, log4, _ = asyncio.run(drive(base, lambda app: app._restore_manifest(P / "project.json", PREV)))
    dt = time.perf_counter() - t
finally:
    release(h)
copies = [p for p in P.iterdir() if p.name.startswith("project.json.previous-")]
print("[C1 held] listing:", listing(P))
print("   copy bytes == previous:", [c.read_bytes() == PREV for c in copies], "| project.json unchanged:", (P / "project.json").read_bytes()[:20])
print("   status:", st, "\n   log_line_4:", log4)
print("   staging left:", sorted((wa(base) / "temp" / ".staging").iterdir()) if (wa(base) / "temp" / ".staging").exists() else "<none>")

# C2
base, P = setup("C2")
h = hold(P / "project.json")
threading.Timer(0.2, release, args=(h,)).start()
st, log4, _ = asyncio.run(drive(base, lambda app: app._restore_manifest(P / "project.json", PREV)))
time.sleep(0.3)
print("[C2 held 0.2 s] restored:", (P / "project.json").read_bytes() == PREV, "| listing:", listing(P), "| status:", st)

# C3: every name pre-exists (stamp for now..now+4 s, all 10 suffixes)
base, P = setup("C3")
now = datetime.now(timezone.utc).timestamp()
pre = {}
for d in range(0, 6):
    stamp = datetime.fromtimestamp(now + d, timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    for sfx in ["", *[f"-{n}" for n in range(1, 10)]]:
        f = P / f"project.json.previous-{stamp}{sfx}"
        f.write_bytes(b"PRE-EXISTING " + f.name.encode())
        pre[f] = f.read_bytes()
h = hold(P / "project.json")
try:
    st, log4, kept = asyncio.run(drive(base, lambda app: app._restore_manifest(P / "project.json", PREV)))
finally:
    release(h)
print("[C3 all names taken] pre-existing untouched:", all(f.read_bytes() == b for f, b in pre.items()),
      "| new files:", sorted(set(listing(P)) - {f.name for f in pre} - {"project.json"}), "| status:", st)

# C4: claimed name is a junction to outside
base, P = setup("C4")
outside = fresh("C4out"); (outside / "keep.txt").write_text("x")
links = []
for d in range(0, 4):
    stamp = datetime.fromtimestamp(time.time() + d, timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    l = P / f"project.json.previous-{stamp}"
    junction(l, outside); links.append(l)
h = hold(P / "project.json")
try:
    st, log4, _ = asyncio.run(drive(base, lambda app: app._restore_manifest(P / "project.json", PREV)))
finally:
    release(h)
print("[C4 name is a junction] outside folder:", sorted(p.name for p in outside.iterdir()), "| P:", listing(P), "| status:", st)
for l in links: rm_junction(l)

# C5: keep goes through a project folder swapped for a junction (direct call)
root = fresh("C5")
P = wa(root / "app") / "P"; P.parent.mkdir(parents=True)
outside = root / "outside"; outside.mkdir()
junction(P, outside)
try:
    kept = S19TuiApp._keep_previous_manifest(P / "project.json", PREV)
finally:
    rm_junction(P)
print("[C5 keep through a junction project folder] kept:", kept, "| outside now holds:", sorted(p.name for p in outside.iterdir()))
