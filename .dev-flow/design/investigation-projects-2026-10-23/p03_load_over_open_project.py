"""P03: Load project while another project (or loose files) is open — what
state leaks from the previous session into the newly loaded project?

P1 = case_01 firmware.s19 + firmware.mac + firmware.a2l (+ a paste-authored
Patch Editor entry and a declared region in the session).
P2 = case_00 prg.s19 only (no MAC, no A2L).
Both are saved by the app itself in a first app; a second app loads P1 then P2
and compares against a third app that loads P2 cold.
"""
from common import *


async def build(base):
    app = new_app(base)
    async with app.run_test(size=(160, 50)) as pilot:
        await settle(app, pilot)
        await load_path(app, pilot, C1 / "firmware.s19")
        await load_path(app, pilot, C1 / "firmware.mac")
        await load_path(app, pilot, C1 / "firmware.a2l")
        save_project(app, app.workarea, "P1"); await settle(app, pilot)
    app = new_app(base)
    async with app.run_test(size=(160, 50)) as pilot:
        await settle(app, pilot)
        await load_path(app, pilot, EX / "case_00_public" / "prg.s19")
        save_project(app, app.workarea, "P2"); await settle(app, pilot)
    print("P1 files:", [l.split('  ')[0] for l in tree(base / ".s19tool/workarea/P1")])
    print("P2 files:", [l.split('  ')[0] for l in tree(base / ".s19tool/workarea/P2")])


async def main():
    base = new_base()
    await build(base)
    cold = new_app(base)
    async with cold.run_test(size=(160, 50)) as pilot:
        await settle(cold, pilot)
        cold._handle_load_project("P2"); await settle(cold, pilot)
        s_cold = snapshot(cold)
    app = new_app(base)
    async with app.run_test(size=(160, 50)) as pilot:
        await settle(app, pilot)
        app._handle_load_project("P1"); await settle(app, pilot)
        patch_apply(app, hex(max(app.current_file.mem_map) - 3), "01 02")
        from s19_app.tui.services.report_addendum import DeclaredRegion
        app._declared_regions = (DeclaredRegion(name="cal", start=0x80000000, end=0x80000010),)
        print("after P1 load (+1 patch entry):", snapshot(app))
        app._handle_load_project("P2"); await settle(app, pilot)
        s_warm = snapshot(app)
        print("P2 cold:", s_cold)
        print("P2 warm:", s_warm)
        for k in s_cold:
            if s_cold[k] != s_warm[k]:
                print(f"  LEAK {k}: cold={s_cold[k]!r}  after-P1={s_warm[k]!r}")
        print("status:", app._probe_status[-2:], "notices:", app._probe_notes)
        # does a save of P2 now carry P1's A2L / MAC into P2?
        save_project(app, app.workarea, "P2"); await settle(app, pilot)
        print("P2 files after re-save:", [l.split('  ')[0] for l in tree(app.workarea / "P2")])
        print("re-save status:", app._probe_status[-2:])


asyncio.run(main())
