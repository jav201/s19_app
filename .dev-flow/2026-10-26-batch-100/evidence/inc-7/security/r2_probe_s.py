"""R2-S: the cp1 save-side changes - security-reviewer round 2.
S1 SEC7-2: the swap after the check (probe B2's seam) -> the post-replace
   re-check; what the finding message carries (it is notify()'d verbatim).
S2 SEC7-6 (a): _keep_previous_manifest (now an instance method) with the
   project folder a junction to an outside folder -> no copy outside.
S3 SEC7-3 rollback: Save project over a manifest it cannot carry keeps
   project.json.previous-<UTC>; the save then fails after the manifest
   write while project.json is held, so the restore cannot land.
   S3a every later candidate name is taken -> is the first copy (the only
       one holding the previous bytes) deleted by the rollback?
   S3b control: nothing pre-claimed."""
import asyncio, ctypes, json, os, re, sys, time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from common import *
sys.path.insert(0, str(WT))
from s19_app.tui.models import ProjectVariantSet
from s19_app.tui.services import manifest_writer as mw
from s19_app.tui.app import S19TuiApp, SaveProjectPayload
import tests.test_b100_active_variant as T
from tests.support import b100_projects as projects

k32 = ctypes.windll.kernel32
k32.CreateFileW.restype = ctypes.c_void_p
EXC = re.compile(r"\b[A-Z][A-Za-z]*(Error|Exception)\b")
which = sys.argv[1:] or ["S1", "S2", "S3"]

if "S1" in which:
    root = fresh("S1")
    b1, b2 = root / "one", root / "two"
    P, Q = wa(b1) / "P", wa(b2) / "Q"
    P.mkdir(parents=True); Q.mkdir(parents=True)
    (Q / "project.json").write_text('{"schema_version": 1, "active_variant": "victim"}')
    before = snap(wa(b2))
    real_stage = mw._private_stage_dir

    def swapping_stage(workarea):
        os.rmdir(P); junction(P, Q)
        return real_stage(workarea)
    mw._private_stage_dir = swapping_stage
    try:
        written, issues = mw.write_project_manifest(
            ProjectVariantSet(project_name="P", variants=(), active_id=None), P, b1)
    finally:
        mw._private_stage_dir = real_stage
        if os.path.lexists(P): rm_junction(P)
    print("[S1 SEC7-2 swap after the check] written:", written, "codes:", [i.code for i in issues])
    print("   other work area:", diff(before, snap(wa(b2))))
    msg = "; ".join(i.message for i in issues)
    print("   message (app.py notify()s it as the toast body):", msg[:150], "...")
    print("   exception class names in it:", EXC.findall(msg) and [m.group(0) for m in EXC.finditer(msg)],
          "| names the outside folder:", str(Q) in msg or os.path.realpath(Q) in msg)


async def drive(base, fn, open_project=False):
    app = S19TuiApp(base_dir=base)
    statuses = []
    real = app.set_status
    app.set_status = lambda m, *a, **k: (statuses.append(str(m)), real(m, *a, **k))[1]
    async with app.run_test(size=(118, 54)) as pilot:
        await pilot.pause()
        if open_project:
            await T._open_seeded_project(pilot, app)
            statuses.clear()
        out = fn(app)
        for _ in range(60):
            await pilot.pause()
    return statuses, out

if "S2" in which:
    root = fresh("S2")
    base = root / "app"
    P = wa(base) / "P"; P.parent.mkdir(parents=True)
    outside = root / "outside"; outside.mkdir()
    junction(P, outside)
    try:
        st, kept = asyncio.run(drive(base, lambda app: app._keep_previous_manifest(P / "project.json", b"PREVIOUS")))
    finally:
        rm_junction(P)
    print("[S2 SEC7-6 keep through a junction project folder] kept:", kept, "| outside holds:", sorted(x.name for x in outside.iterdir()))

if "S3" in which:
    for tag, preclaim in (("S3a later names taken", True), ("S3b control", False)):
        tmp = fresh(tag.split()[0]); base = tmp / "app"
        pdir = projects.seed_project_with_every_key(T._workarea(base))
        m = projects.read_manifest(pdir); m["custom_user_key"] = {"keep": True}
        (pdir / "project.json").write_text(json.dumps(m), encoding="utf-8")
        previous = (pdir / "project.json").read_bytes()
        handles = []
        calls = {"keep": 0}

        def fn(app):
            real_write = app._write_and_verify_manifest
            real_keep = app._keep_previous_manifest

            def failing_write(project_dir, **kw):
                ok = real_write(project_dir, **kw)  # lands, arms the restore (on_written)
                # another program now holds project.json; the save then fails
                handles.append(k32.CreateFileW(str(pdir / "project.json"), 0x80000000, 0, None, 3, 0x80, None))
                raise PermissionError(13, "held by another program", str(pdir / "project.json"))

            def keep(manifest_path, previous_bytes):
                calls["keep"] += 1
                if calls["keep"] == 2 and preclaim:
                    now = datetime.now(timezone.utc)
                    for s in range(0, 4):
                        stamp = (now + timedelta(seconds=s)).strftime("%Y%m%dT%H%M%SZ")
                        for suffix in ("", *(f"-{n}" for n in range(1, 10))):
                            c = manifest_path.with_name(f"{manifest_path.name}.previous-{stamp}{suffix}")
                            if not c.exists():
                                c.write_bytes(b"pre-existing")
                return real_keep(manifest_path, previous_bytes)
            app._write_and_verify_manifest = failing_write
            app._keep_previous_manifest = keep
            app._handle_save_dialog(SaveProjectPayload(parent_folder=str(app.workarea), project_name="P"))
        try:
            st, _ = asyncio.run(drive(base, fn, open_project=True))
        finally:
            for h in handles: k32.CloseHandle(ctypes.c_void_p(h))
        holders = [x.name for x in sorted(pdir.iterdir()) if x.is_file() and x.read_bytes() == previous]
        prev_names = [x.name for x in pdir.iterdir() if ".previous-" in x.name and x.read_bytes() != b"pre-existing"]
        print(f"[{tag}] keep calls: {calls['keep']} | files holding the previous bytes: {holders}")
        print("   previous-* copies left (not pre-claimed):", prev_names)
        print("   project.json == previous:", (pdir / "project.json").read_bytes() == previous)
        print("   statuses:", [s[:150] for s in st if "previous" in s or "NOT saved" in s or "restored" in s])

if "S4" in which:
    # SEC7-3 refusal arm: every candidate name for the next 4 seconds is taken -> no copy -> Save project must not overwrite
    tmp = fresh("S4"); base = tmp / "app"
    pdir = projects.seed_project_with_every_key(T._workarea(base))
    m = projects.read_manifest(pdir); m["custom_user_key"] = {"keep": True}
    (pdir / "project.json").write_text(json.dumps(m), encoding="utf-8")
    previous = (pdir / "project.json").read_bytes()

    def fn(app):
        now = datetime.now(timezone.utc)
        for s in range(0, 6):
            stamp = (now + timedelta(seconds=s)).strftime("%Y%m%dT%H%M%SZ")
            for suffix in ("", *(f"-{n}" for n in range(1, 10))):
                (pdir / f"project.json.previous-{stamp}{suffix}").write_bytes(b"pre-existing")
        app._handle_save_dialog(SaveProjectPayload(parent_folder=str(app.workarea), project_name="P"))
    st, _ = asyncio.run(drive(base, fn, open_project=True))
    taken = [x for x in pdir.iterdir() if ".previous-" in x.name]
    print("[S4 SEC7-3 no copy possible] project.json unchanged:", (pdir / "project.json").read_bytes() == previous,
          "| pre-claimed names intact:", all(x.read_bytes() == b"pre-existing" for x in taken), len(taken))
    print("   statuses:", [s[:140] for s in st])
