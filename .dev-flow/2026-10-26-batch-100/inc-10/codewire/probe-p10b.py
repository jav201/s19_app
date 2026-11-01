"""Inc 10 E2 baseline probe on a throwaway copy of 8947666 (read-only for the repo).

Run: python -I probe-p10b.py <tree>   (the tree's s19_app goes first on sys.path)
"""
import asyncio, shutil, sys, tempfile
from pathlib import Path

TREE = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(TREE))
EX = TREE / "examples"

import s19_app
from textual.widgets import Button, ListItem
from s19_app.tui import app as app_mod
from s19_app.tui.app import S19TuiApp
from s19_app.tui.workspace import WORKAREA_DIRNAME, WORKAREA_SUBDIR, WORKAREA_TEMP
from s19_app.tui.screens_directionb import PatchEditorPanel, LoadGuardScreen
from s19_app.tui.screens import ConfirmDiscardScreen, LOAD_RESULT_SELECT_VARIANT
from s19_app.tui.flow_screens import FlowBuilderPanel
from s19_app.tui.services.project_gather_service import painted_names


def say(*a):
    print(" ".join(str(x) for x in a), flush=True)


async def flush(pilot, n=15):
    for _ in range(n):
        await pilot.pause()


def stack(app):
    return [type(s).__name__ for s in app.screen_stack]


def patch_image(app, same=False):
    f = app.current_file
    addr = sorted(f.mem_map)[len(app._change_service.document.entries)]
    old = f.mem_map[addr]
    new = old if same else (old + 1) & 0xFF
    app._change_service.add_entry(f"0x{addr:08X}", "", f"{new:02X}")
    app._change_service.apply(f.mem_map, f.ranges, f.mac_records, None)
    return addr, old, new


def D(app):
    f = app.current_file
    return app._change_service.differs_from_last_saved(f.mem_map if f else None)


def W(app):
    return app.query_one("#patch_editor_panel", PatchEditorPanel)._dirty


async def settle(app, pilot, n=30):
    await app.workers.wait_for_complete()
    await flush(pilot, n)


async def main():
    say("import", Path(s19_app.__file__).parent)
    tmp = Path(tempfile.mkdtemp(prefix="p10b_"))
    base = tmp / "app"
    wa = base / WORKAREA_DIRNAME / WORKAREA_SUBDIR
    t = wa / WORKAREA_TEMP
    t.mkdir(parents=True)
    for n in ("firmware.s19", "firmware.mac"):
        shutil.copy2(EX / "case_01_basic_valid" / n, t / n)
    shutil.copy2(EX / "case_00_public" / "prg.s19", t / "prg.s19")
    shutil.copy2(EX / "case_00_public" / "prg.s19", tmp / "other.s19")
    shutil.copy2(EX / "case_01_basic_valid" / "firmware.mac", tmp / "typed.mac")
    shutil.copy2(EX / "case_01_basic_valid" / "firmware.mac", tmp / "typed2.MAC")
    pv = wa / "PV"; pv.mkdir()
    shutil.copy2(EX / "case_01_basic_valid" / "firmware.s19", pv / "firmware.s19")
    shutil.copy2(EX / "case_02_gaps_and_patch_targets" / "firmware.s19", pv / "firmware_b.s19")
    m2 = wa / "M2"; m2.mkdir()
    shutil.copy2(EX / "case_01_basic_valid" / "firmware.s19", m2 / "a.s19")
    shutil.copy2(EX / "case_01_basic_valid" / "firmware.mac", m2 / "m1.mac")
    shutil.copy2(EX / "case_01_basic_valid" / "firmware.mac", m2 / "m2.mac")

    say("U0 Button.BINDINGS keys:", [b.key for b in Button.BINDINGS])
    say("U0 PatchEditorPanel.is_dirty exists:", hasattr(PatchEditorPanel, "is_dirty"))
    say("U0 painted_names:", repr(painted_names(["[b]x.s19"])), repr(painted_names(["a‮b.s19"])),
        len(painted_names(["n" * 130])), painted_names(["n" * 130])[-1])
    say("U0 Path suffixes:", repr(Path("x.mac.").suffix), repr(Path("x.MAC").suffix.lower()))

    app = S19TuiApp(base_dir=base)
    async with app.run_test(size=(118, 54)) as pilot:
        await pilot.pause()
        fb = app.query_one("#flow_panel", FlowBuilderPanel)
        say("U1 flow default:", repr(fb.current_flow.name), "is_dirty", fb.is_dirty)

        # U2 same-byte patch -> D stays False
        app.load_selected_file(t / "firmware.s19"); await settle(app, pilot)
        patch_image(app, same=True); await flush(pilot)
        say("U2 same-byte patch: D =", D(app))
        app.load_selected_file(t / "firmware.s19"); await settle(app, pilot)
        addr, old, new = patch_image(app); await flush(pilot)
        say("U2 real patch: D =", D(app), "| entries", len(app._change_service.document.entries), "| W =", W(app))

        # U3 typed .mac over a patched image: classification and outcome
        say("U3 _typed_load_route(typed.mac) =", app._typed_load_route(tmp / "typed.mac"),
            "| typed2.MAC =", app._typed_load_route(tmp / "typed2.MAC"),
            "| other.s19 =", app._typed_load_route(tmp / "other.s19"))
        app._load_path_from_user_input(tmp / "typed.mac"); await settle(app, pilot)
        say("U3 typed .mac over patch: stack", stack(app), "| file", app.current_file.path.name,
            "| mac", app.current_file.mac_path.name if app.current_file.mac_path else None,
            "| byte kept", app.current_file.mem_map.get(addr) == new, "| D =", D(app))

        # U4 Workarea pick over patch
        item = ListItem(); item.data = "prg.s19"
        app._load_from_item(item); await settle(app, pilot)
        say("U4 WORKAREA pick over patch: stack", stack(app), "| file", app.current_file.path.name,
            "| D =", D(app), "| entries kept", len(app._change_service.document.entries))

        # U5 router over patch (base router takes a Path)
        app.load_selected_file(t / "firmware.s19"); await settle(app, pilot)
        patch_image(app); await flush(pilot)
        app._handle_load_dialog(tmp / "other.s19"); await settle(app, pilot)
        say("U5 LOAD DIALOG router over patch: stack", stack(app), "| file", app.current_file.path.name)

        # U6 interim line: project load with 1+ document entries
        app.load_selected_file(t / "firmware.s19"); await settle(app, pilot)
        patch_image(app); await flush(pilot)
        n_entries = len(app._change_service.document.entries)
        resets = []
        real_reset = app._reset_project_session
        def spy_reset():
            r = real_reset(); resets.append(r); return r
        app._reset_project_session = spy_reset
        app._route_load_project("PV"); await settle(app, pilot)
        lines = [ln for ln in app._status_lines() if "Closed the Patch Editor" in ln] if hasattr(app, "_status_lines") else None
        say("U6 project PV over", n_entries, "entries: stack", stack(app), "| reset returns", resets,
            "| D after =", D(app), "| W after =", W(app), "| current_project", app.current_project)
        say("U6 status log interim lines:", [ln for ln in list(app.log_lines if hasattr(app, "log_lines") else []) if "Closed the Patch Editor" in str(ln)][-1:])
        # panel v: close the Load-result panel and route through it
        if type(app.screen).__name__ == "LoadResultScreen":
            app.pop_screen(); await flush(pilot)
        say("U7 D right after project load =", D(app), "(the panel's v meets D = False by keys)")
        app._handle_load_result(LOAD_RESULT_SELECT_VARIANT); await flush(pilot)
        say("U7 panel v route: stack", stack(app))
        app.pop_screen(); await flush(pilot)

        # U8 variant switch: _pending_variant_id stamped before the load
        patch_image(app); await flush(pilot)
        calls = []
        real_lfp = app.load_from_path
        app.load_from_path = lambda p: calls.append((p.name, app._pending_variant_id))
        app._handle_select_variant("firmware_b")
        say("U8 _handle_select_variant('firmware_b'): load_from_path calls", calls, "(pending id set before the load)")
        app.load_from_path = real_lfp
        app._pending_variant_id = None
        app._handle_select_variant("firmware_b"); await settle(app, pilot)
        say("U8 VARIANT switch over patch: stack", stack(app), "| active", app._variant_set.active_id, "| D =", D(app))

        # U9 LLR-174.3c: listed project M2 (1 data + 2 MAC) refused before the reset
        patch_image(app); await flush(pilot)
        pe = app.query_one("#patch_editor_panel", PatchEditorPanel)
        pe._dirty = True
        resets.clear()
        before = (app.current_file.path.name, app.current_project)
        app._route_load_project("M2"); await settle(app, pilot)
        say("U9 project M2 (2 MAC) over D+W: stack", stack(app), "| resets", resets, "| D =", D(app), "| W =", W(app),
            "| session same", (app.current_file.path.name, app.current_project) == before)
        app._reset_project_session = real_reset

        # U10 Flow Builder dirty across a project load
        fb._mark_dirty()
        app._route_load_project("PV"); await settle(app, pilot)
        if type(app.screen).__name__ == "LoadResultScreen":
            app.pop_screen(); await flush(pilot)
        say("U10 FLOW dirty across project load: is_dirty", fb.is_dirty, "| name", fb.current_flow.name)

        # U11 priority keys under a ModalScreen[bool] stand-in (LoadGuardScreen)
        answers = []
        app.push_screen(LoadGuardScreen(), answers.append); await flush(pilot)
        say("U11 LoadGuardScreen focus:", app.focused.id if app.focused else None)
        for key in ("y", "a", "l", "p", "s", "q"):
            await pilot.press(key); await flush(pilot, 4)
        say("U11 after y a l p s q: stack", stack(app), "| answers", answers)
        density_before = [c for c in app.classes if c.startswith("density")]
        ran = []
        for name in ("load_file", "save_project", "focus_palette", "cycle_density"):
            real = getattr(app, f"action_{name}")
            def wrap(real=real, name=name):
                ran.append(name); return real()
            setattr(app, f"action_{name}", wrap)
        await pilot.press("ctrl+l"); await flush(pilot)
        say("U11 ctrl+l under LoadGuardScreen: ran", ran, "| stack", stack(app))
        app.pop_screen(); await flush(pilot)
        await pilot.press("ctrl+s"); await flush(pilot)
        say("U11 ctrl+s under LoadGuardScreen: ran", ran, "| stack", stack(app))
        app.pop_screen(); await flush(pilot)
        await pilot.press("ctrl+k"); await flush(pilot)
        await pilot.press("ctrl+d"); await flush(pilot)
        say("U11 ctrl+k, ctrl+d: ran", ran, "| stack", stack(app), "| density",
            density_before, "->", [c for c in app.classes if c.startswith("density")])
        await pilot.press("escape"); await flush(pilot)
        app.set_focus(None)
        if type(app.screen).__name__ == "LoadGuardScreen":
            app.screen.query_one("#load_guard_cancel").focus(); await flush(pilot)
            await pilot.press("escape"); await flush(pilot)
        say("U11 escape -> answers", answers, "| stack", stack(app))
        app.push_screen(LoadGuardScreen(), answers.append); await flush(pilot)
        await pilot.press("enter"); await flush(pilot)
        say("U11 immediate enter on LoadGuardScreen -> answers", answers, "| stack", stack(app))

        # U12 ConfirmDiscardScreen keys (the pattern LLR-174.2p must not reuse)
        cd = []
        app.push_screen(ConfirmDiscardScreen("t"), cd.append); await flush(pilot)
        say("U12 ConfirmDiscardScreen focus:", app.focused.id if app.focused else None,
            "| buttons", [b.label.plain for b in app.screen.query(Button)])
        await pilot.press("escape"); await flush(pilot)
        await pilot.press("n"); await flush(pilot)
        say("U12 escape, n -> stack", stack(app), "| answers", cd)
        app.pop_screen(); await flush(pilot)

        # U13 the Patch Editor's own load while W -> LoadGuardScreen
        pe._dirty = True
        pe.query_one("#patch_doc_load_button", Button).press(); await flush(pilot)
        say("U13 Patch Editor Load while dirty: stack", stack(app))
    shutil.rmtree(tmp, ignore_errors=True)


asyncio.run(main())
