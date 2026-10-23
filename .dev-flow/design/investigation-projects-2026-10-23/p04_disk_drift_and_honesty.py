"""P04: a saved project whose files change on disk after the save, and what
the Load reports. Each case saves P with case_01 S19+MAC+A2L in its own base,
mutates the project folder (or the original sources), then loads P in a fresh
app. Also: A2L-only and MAC-only projects, a corrupt / stale project.json, and
the non-project folders Load project lists."""
from common import *


async def make(base, with_a2l=True, files=("firmware.s19", "firmware.mac", "firmware.a2l")):
    app = new_app(base)
    async with app.run_test(size=(160, 50)) as pilot:
        await settle(app, pilot)
        for f in files:
            await load_path(app, pilot, C1 / f)
        save_project(app, app.workarea, "P"); await settle(app, pilot)
        snap = snapshot(app)
        st = app._probe_status[-2:]
    return base / ".s19tool" / "workarea" / "P", snap, st


async def load(base, label, saved):
    app = new_app(base)
    async with app.run_test(size=(160, 50)) as pilot:
        await settle(app, pilot)
        try:
            app._handle_load_project("P")
        except Exception as exc:  # noqa: BLE001
            print(f"[{label}] LOAD RAISED {type(exc).__name__}: {exc}")
        await settle(app, pilot)
        s = snapshot(app)
        diffs = {k: (saved[k], s[k]) for k in ("file", "mem", "mac_path", "a2l_path", "a2l_tags", "project", "variants") if saved.get(k) != s.get(k)}
        print(f"[{label}] status={app._probe_status[-2:]} notices={[(n[0], n[1]) for n in app._probe_notes]}")
        print(f"[{label}]   vs saved session: {diffs}")
        return app


async def main():
    # 1 sources moved/deleted after save (project holds copies?)
    base = new_base(); src = base / "src"; src.mkdir()
    for f in ("firmware.s19", "firmware.mac", "firmware.a2l"):
        shutil.copyfile(C1 / f, src / f)
    app = new_app(base)
    async with app.run_test(size=(160, 50)) as pilot:
        await settle(app, pilot)
        for f in ("firmware.s19", "firmware.mac", "firmware.a2l"):
            await load_path(app, pilot, src / f)
        save_project(app, app.workarea, "P"); await settle(app, pilot)
        saved = snapshot(app)
    shutil.rmtree(src); shutil.rmtree(base / ".s19tool/workarea/temp"); (base / ".s19tool/workarea/temp").mkdir()
    await load(base, "1 sources+temp deleted", saved)

    # 2 project image edited on disk after save (one byte flipped inside a data record, checksum fixed)
    base = new_base(); proj, saved, _ = await make(base)
    from s19_app.core import S19File
    before = S19File(str(proj / "firmware.s19")).get_memory_map()
    lines = (proj / "firmware.s19").read_text().splitlines()
    i = next(n for n, l in enumerate(lines) if l.startswith("S3"))
    raw = bytearray(bytes.fromhex(lines[i][2:])); raw[6] ^= 0xFF; raw[-1] = (~sum(raw[:-1])) & 0xFF
    lines[i] = lines[i][:2] + raw.hex().upper(); (proj / "firmware.s19").write_text("\n".join(lines) + "\n")
    a = await load(base, "2 image edited on disk", saved)
    print("[2]   loaded image == saved image?", mem_digest(a.current_file.mem_map) == mem_digest(before), "(no hash in project.json to detect it)")

    # 3 A2L deleted from the project
    base = new_base(); proj, saved, _ = await make(base); (proj / "firmware.a2l").unlink()
    await load(base, "3 A2L deleted", saved)
    # 4 MAC deleted
    base = new_base(); proj, saved, _ = await make(base); (proj / "firmware.mac").unlink()
    await load(base, "4 MAC deleted", saved)
    # 5 image deleted (MAC + A2L remain)
    base = new_base(); proj, saved, _ = await make(base); (proj / "firmware.s19").unlink()
    await load(base, "5 S19 deleted", saved)
    # 6 image replaced by a corrupt one
    base = new_base(); proj, saved, _ = await make(base); (proj / "firmware.s19").write_text("S3FFgarbage\n")
    await load(base, "6 S19 corrupt", saved)
    # 7 project.json corrupt
    base = new_base(); proj, saved, _ = await make(base); (proj / "project.json").write_text("{not json")
    await load(base, "7 project.json corrupt", saved)
    # 8 project.json names a variant that is gone; and a second variant exists
    base = new_base(); proj, saved, _ = await make(base)
    shutil.copyfile(EX / "case_00_public/prg.s19", proj / "aaa.s19")
    m = json.loads((proj / "project.json").read_text()); m["active_variant"] = "zzz"; (proj / "project.json").write_text(json.dumps(m))
    await load(base, "8 active_variant gone", saved)
    # 9 project.json deleted (legacy) with two variants -> which one opens?
    base = new_base(); proj, saved, _ = await make(base)
    shutil.copyfile(EX / "case_00_public/prg.s19", proj / "aaa.s19"); (proj / "project.json").unlink()
    await load(base, "9 project.json deleted, 2 variants", saved)
    # 10 A2L-only project
    base = new_base(); proj, saved, st = await make(base, files=("firmware.a2l",))
    print("[10] A2L-only save status:", st, "files:", [l.split('  ')[0] for l in tree(proj)])
    await load(base, "10 A2L-only", saved)
    # 11 MAC-only project
    base = new_base(); proj, saved, st = await make(base, files=("firmware.mac",))
    print("[11] MAC-only save status:", st, "files:", [l.split('  ')[0] for l in tree(proj)])
    await load(base, "11 MAC-only", saved)
    # 12 what Load project lists
    app = new_app(base)
    async with app.run_test(size=(160, 50)) as pilot:
        await settle(app, pilot)
        (app.workarea / "reports").mkdir(exist_ok=True)
        print("[12] list_projects():", app.list_projects())
        app._handle_load_project("patches"); await settle(app, pilot)
        print("[12] load 'patches' ->", app._probe_status[-1:])


asyncio.run(main())
