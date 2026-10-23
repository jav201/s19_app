"""P02: re-saving a project, the Patch Editor save-back into a project, and
the `<name>_<N>` copy growth in the project folder and in workarea/temp.

A: save P, patch in memory, save-back under the SAME name as the project image,
   save P again, reload in a fresh app.
B: save-back under the default `<stem>-patched.s19`, save P again, reload.
C: save P twice with nothing changed; then load a DIFFERENT file with the same
   name (case_02 firmware.s19 after case_01 firmware.s19) while P is open, and
   re-save.
"""
from common import *
from s19_app.core import S19File


async def scenario(tag, saveback_name, same_file_twice=False):
    base = new_base()
    app = new_app(base)
    async with app.run_test(size=(160, 50)) as pilot:
        await settle(app, pilot)
        await load_path(app, pilot, C1 / "firmware.s19")
        save_project(app, app.workarea, "P")
        await settle(app, pilot)
        proj = app.workarea / "P"
        orig = dict(app.current_file.mem_map)
        addr = max(orig) - 3
        patch_apply(app, hex(addr), "DE AD BE EF")
        patched = dict(app.current_file.mem_map)
        if saveback_name:
            from s19_app.tui.screens_directionb import PatchEditorPanel as Pn
            app.on_patch_editor_panel_save_back_decision(Pn.SaveBackDecision(saveback_name))
            await settle(app, pilot)
            print(f"[{tag}] save-back '{saveback_name}' status:", app._probe_status[-2:])
            print(f"[{tag}]   current_file.path after save-back:", app.current_file.path.relative_to(app.workarea).as_posix())
        save_project(app, app.workarea, "P")
        await settle(app, pilot)
        print(f"[{tag}] re-save status:", app._probe_status[-2:])
        print(f"[{tag}] project tree:", [l.split('  ')[0] for l in tree(proj)])
        print(f"[{tag}] project.json:", json.loads((proj / "project.json").read_text()))
        for p in sorted(proj.glob("*.s19")):
            m = S19File(str(p)).get_memory_map()
            print(f"[{tag}]   {p.name}: patched={mem_digest(m)==mem_digest(patched)} original={mem_digest(m)==mem_digest(orig)}")
    app2 = new_app(base)
    async with app2.run_test(size=(160, 50)) as pilot:
        await settle(app2, pilot)
        app2._handle_load_project("P")
        await settle(app2, pilot)
        m = app2.current_file.mem_map
        print(f"[{tag}] RELOAD -> file={app2.current_file.path.name} variants={[v.variant_id for v in app2._variant_set.variants]} "
              f"active={app2._variant_set.active_id} image_is_patched={mem_digest(m)==mem_digest(patched)} image_is_original={mem_digest(m)==mem_digest(orig)}")
        print(f"[{tag}]   status:", app2._probe_status[-1:])


async def scenario_c():
    base = new_base()
    app = new_app(base)
    async with app.run_test(size=(160, 50)) as pilot:
        await settle(app, pilot)
        await load_path(app, pilot, C1 / "firmware.s19")
        save_project(app, app.workarea, "P"); await settle(app, pilot)
        save_project(app, app.workarea, "P"); await settle(app, pilot)
        proj = app.workarea / "P"
        print("[C] after 2 identical saves:", [l.split('  ')[0] for l in tree(proj)])
        await load_path(app, pilot, EX / "case_02_gaps_and_patch_targets" / "firmware.s19")
        print("[C] load case_02 firmware.s19 while P open -> status:", app._probe_status[-2:])
        print("[C]   temp:", sorted(p.name for p in (app.workarea / "temp").iterdir()))
        print("[C]   project:", [l.split('  ')[0] for l in tree(proj)])
        await load_path(app, pilot, C1 / "firmware.s19")
        await load_path(app, pilot, EX / "case_02_gaps_and_patch_targets" / "firmware.s19")
        save_project(app, app.workarea, "P"); await settle(app, pilot)
        print("[C] after re-loading both twice + save:")
        print("[C]   temp:", sorted(p.name for p in (app.workarea / "temp").iterdir()))
        print("[C]   project:", [l.split('  ')[0] for l in tree(proj)], "variants:", [v.variant_id for v in app._variant_set.variants])
        print("[C]   temp sha:", [l for l in tree(app.workarea / "temp")])
        print("[C]   project sha:", [l for l in tree(proj) if l.endswith('.s19') or '.s19 ' in l])


async def main():
    import sys
    if "--c-only" not in sys.argv:
        await scenario("A", "firmware.s19")
        await scenario("B", "firmware-patched.s19")
        await scenario("N", None)
    await scenario_c()

asyncio.run(main())
