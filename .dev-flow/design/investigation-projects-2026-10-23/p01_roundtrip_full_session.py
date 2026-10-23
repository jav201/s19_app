"""P01: the headline round-trip. Load case_01 S19 + MAC + A2L through the real
Load-file route, apply a Patch Editor entry to the in-memory image (not saved
back), Save project, then Load project in a FRESH app on the same base and
compare state, bytes and values. Also prints what the project folder holds."""
from common import *


async def main():
    base = new_base()
    app = new_app(base)
    async with app.run_test(size=(160, 50)) as pilot:
        await settle(app, pilot)
        await load_path(app, pilot, C1 / "firmware.s19")
        await load_path(app, pilot, C1 / "firmware.mac")
        await load_path(app, pilot, C1 / "firmware.a2l")
        before_patch = snapshot(app)
        orig_mem = dict(app.current_file.mem_map)
        lo = max(orig_mem) - 3  # last 4 data bytes (avoids the S0-at-0x0 artefact, H-1)
        patch_apply(app, hex(lo), "DE AD BE EF")
        patched_mem = dict(app.current_file.mem_map)
        changed = [a for a in patched_mem if patched_mem[a] != orig_mem.get(a)]
        s_before = snapshot(app)
        print("SESSION before save:", s_before)
        print("  in-memory patch changed", len(changed), "bytes at", [hex(a) for a in changed[:4]])
        save_project(app, app.workarea, "P1")
        await settle(app, pilot)
        print("SAVE status:", app._probe_status[-3:], "notices:", app._probe_notes)
        proj = app.workarea / "P1"
        print("PROJECT TREE:")
        for line in tree(proj):
            print("   ", line)
        print("project.json:", json.loads((proj / "project.json").read_text()) if (proj / "project.json").exists() else "ABSENT")
        from s19_app.core import S19File
        disk = S19File(str(proj / "firmware.s19")).get_memory_map()
        print("project firmware.s19 == in-memory patched image?", mem_digest(disk) == mem_digest(patched_mem),
              "| == original?", mem_digest(disk) == mem_digest(orig_mem))
    app2 = new_app(base)
    async with app2.run_test(size=(160, 50)) as pilot:
        await settle(app2, pilot)
        print("LOAD list_projects():", app2.list_projects())
        app2._handle_load_project("P1")
        await settle(app2, pilot)
        s_after = snapshot(app2)
        print("SESSION after load:", s_after)
        print("LOAD status:", app2._probe_status[-3:], "notices:", app2._probe_notes)
        for k in s_before:
            if s_before[k] != s_after[k]:
                print(f"  DIFF {k}: saved-session={s_before[k]!r}  restored={s_after[k]!r}")
        print("restored image has the patch?", all(app2.current_file.mem_map.get(a) == patched_mem[a] for a in changed))
        print("workarea/temp after load:", sorted(p.name for p in (app2.workarea / "temp").iterdir()))


run(main)
