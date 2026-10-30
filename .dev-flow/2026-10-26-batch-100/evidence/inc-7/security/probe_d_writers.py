"""D: the in-project writers through the real app routes.
D1 SEC6-2 refusal matrix: 4 writers x manifest conditions -> bytes identical?
D2 Save project into the existing project P whose manifest has an unknown key
   and schema_version 2.
D3 SEC6-3 through the app: the variant append with P swapped for a junction
   into another work area between the placement and the manifest write."""
import asyncio, json, os, shutil, sys, time
from pathlib import Path
from common import *
sys.path.insert(0, str(WT))
import tests.test_b100_active_variant as T
from tests.support import b100_projects as projects
from s19_app.tui.app import S19TuiApp

COND = {
    "schema-2": lambda m: m.__setitem__("schema_version", 2),
    "unknown-key": lambda m: m.__setitem__("custom_user_key", {"keep": True}),
    "skipped-entry": lambda m: m["batch"].append("../outside.json"),
    "schema-true(bool)": lambda m: m.__setitem__("schema_version", True),
    "nested-derived-extra": lambda m: m.__setitem__("derived_from", {"firmware.s19": {"base": "base.s19", "sha256": "0" * 64, "differ": 3, "note": "user field"}}),
    "nested-region-extra": lambda m: m["declared_regions"][0].__setitem__("note", "user field") if m.get("declared_regions") else m.__setitem__("declared_regions", [{"name": "r", "start": 0, "end": 15, "note": "user field"}]),
}
WRITERS = ["variant-append", "mac-sync", "a2l-sync", "save-back"]
which = sys.argv[1:] or ["D1", "D2", "D3"]

if "D1" in which:
    for cond, fn in COND.items():
        for writer in WRITERS:
            tmp = fresh(f"D1_{writer}")
            base = tmp / "app"
            pdir = projects.seed_project_with_every_key(T._workarea(base))
            m = projects.read_manifest(pdir); fn(m)
            (pdir / "project.json").write_text(json.dumps(m, separators=(",", ":")), encoding="utf-8")
            before = (pdir / "project.json").read_bytes()
            try:
                st = T._run_writer(tmp, base, writer)
            except Exception as e:
                print(f"[D1 {cond:22s} {writer:14s}] DRIVER ERROR {type(e).__name__}: {str(e)[:120]}")
                continue
            after = (pdir / "project.json").read_bytes()
            same = after == before
            lost = ""
            if not same:
                a, b = json.loads(before), json.loads(after)
                lost = f" schema {a.get('schema_version')!r}->{b.get('schema_version')!r};"
                for k in ("derived_from", "declared_regions"):
                    if k in a and a.get(k) != b.get(k):
                        lost += f" {k}: {json.dumps(a.get(k))[:90]} -> {json.dumps(b.get(k))[:90]};"
            msg = [s for s in st if "not rewritten" in s or "manifest verified" in s]
            print(f"[D1 {cond:22s} {writer:14s}] bytes identical={same}{lost} status={msg[:1]}")

if "D2" in which:
    tmp = fresh("D2"); base = tmp / "app"
    pdir = projects.seed_project_with_every_key(T._workarea(base))
    m = projects.read_manifest(pdir); m["custom_user_key"] = {"keep": True}; m["schema_version"] = 2
    (pdir / "project.json").write_text(json.dumps(m), encoding="utf-8")
    statuses = []
    async def drive():
        app = S19TuiApp(base_dir=base)
        real = app.set_status
        app.set_status = lambda s, *a, **k: (statuses.append(str(s)), real(s, *a, **k))[1]
        async with app.run_test() as pilot:
            await pilot.pause()
            await T._open_seeded_project(pilot, app)
            statuses.clear()
            from s19_app.tui.app import SaveProjectPayload
            app._handle_save_dialog(SaveProjectPayload(parent_folder=str(app.workarea), project_name="P"))
            for _ in range(60): await pilot.pause()
    asyncio.run(drive())
    after = projects.read_manifest(pdir)
    print("[D2 Save project into P (unknown key, schema 2)] keys after:", sorted(after), "schema:", after.get("schema_version"))
    print("   statuses:", statuses[:4])

if "D3" in which:
    tmp = fresh("D3"); base = tmp / "app"; other = tmp / "other"
    pdir = projects.seed_project_with_every_key(T._workarea(base))
    Q = wa(other) / "Q"; Q.mkdir(parents=True)
    (Q / "project.json").write_text('{"schema_version": 1, "active_variant": "victim"}')
    before_other = snap(wa(other))
    src = projects.copy_sources(tmp / "src", projects.CASE02_DIR, "firmware.s19") / "firmware.s19"
    statuses = []; moved = pdir.with_name("P_moved")
    async def drive():
        app = S19TuiApp(base_dir=base)
        real = app.set_status
        app.set_status = lambda s, *a, **k: (statuses.append(str(s)), real(s, *a, **k))[1]
        real_write = app._write_and_verify_manifest
        def swapped(project_dir, **kw):
            os.rename(pdir, moved); junction(pdir, Q)
            try:
                return real_write(project_dir, **kw)
            finally:
                rm_junction(pdir); os.rename(moved, pdir)
        app._write_and_verify_manifest = swapped
        async with app.run_test() as pilot:
            await pilot.pause()
            await T._open_seeded_project(pilot, app)
            statuses.clear()
            app.load_from_path(src)
            for _ in range(300):
                if any(s.startswith("Added variant") for s in statuses): break
                await pilot.pause()
            for _ in range(6): await pilot.pause()
    asyncio.run(drive())
    print("[D3 append, P swapped for a junction before the manifest write] other work area:", diff(before_other, snap(wa(other))))
    print("   statuses:", statuses[:4])
