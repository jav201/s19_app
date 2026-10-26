"""P0 premise probe (batch-100): Load / Save / Load-project dialogs, focus after
a load, load over a patched image, reserved project names, `_<N>` growth.

Throwaway, read-only toward the repo. Run with S19_WT=<git archive snapshot>,
s19env, PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8, NO_COLOR
unset. Reuses the 2026-10-23 investigation helpers (`common.py`), which import
the tree named by S19_WT and build a temp base dir per scenario.

Scenarios (each in a fresh app on a fresh temp base):
  S1 Load file dialog: what it shows; empty Load; Enter; escape (Load dialog
     request, D10, CW-U-12, CW-U-13)
  S2 Save project dialog: empty name; escape (CW-U-12, CW-U-13)
  S3 Load project dialog: escape (CW-U-12)
  S4 focus after Load file and after Load project; do `p`, `k`, `t` reach the
     app (CW-U-2)
  S5 Load file / Load project over a patched, unsaved image (CW-U-5)
  S6 Save project with a reserved name (backlog item)
  S7 copy_into_workarea `_<N>` growth, and load of a file already in the work area (M-1)
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, r"C:\Users\jjgh8\Github\s19_app\.dev-flow\design\investigation-projects-2026-10-23")
from common import *  # noqa: E402,F401,F403

C2 = EX / "case_02_gaps_and_patch_targets"
C0 = EX / "case_00_public"


def wid(w):
    if w is None:
        return "None"
    return f"{type(w).__name__}#{w.id}"


def scr(app):
    return type(app.screen).__name__


def stack(app):
    return [type(s).__name__ for s in app.screen_stack]


def dump_dialog(app):
    out = []
    for w in app.screen.query("*"):
        name = type(w).__name__
        if name in ("Container", "Horizontal", "Vertical"):
            continue
        text = ""
        try:
            if hasattr(w, "label") and name == "Button":
                text = str(w.label)
            elif name in ("Label", "Static"):
                text = str(w.render())
            elif hasattr(w, "value") and name.endswith("Input"):
                text = f"value={w.value!r} placeholder={getattr(w, 'placeholder', '')!r}"
        except Exception as exc:  # noqa: BLE001
            text = f"<{exc}>"
        out.append(f"{name}#{w.id} {text}".rstrip())
    return out


def new_msgs(app, n_status, n_notes):
    return app._probe_status[n_status:], app._probe_notes[n_notes:]


async def open_load_file(app, pilot):
    await pilot.press("ctrl+l")
    await settle(app, pilot, 2)


async def dialog_load(app, pilot, path):
    """The operator route: ctrl+l, type the path, click Load."""
    await open_load_file(app, pilot)
    app.screen.query_one("#load_path").value = str(path)
    await pilot.click("#load_ok")
    await settle(app, pilot)


async def s1():
    print("== S1 Load file dialog")
    base = new_base()
    app = new_app(base)
    async with app.run_test(size=(160, 50)) as pilot:
        await settle(app, pilot)
        await load_path(app, pilot, C1 / "firmware.s19")
        await load_path(app, pilot, C2 / "firmware.s19")
        print("work-area temp before opening:", sorted(p.name for p in (app.workarea / "temp").iterdir()))
        # plain `l` first (non-priority), then ctrl+l
        app.set_focus(None)
        await pilot.press("l"); await settle(app, pilot, 2)
        print("`l` with no focus -> screen:", scr(app))
        if scr(app) == "LoadFileScreen":
            await pilot.click("#load_cancel"); await settle(app, pilot, 2)
        await open_load_file(app, pilot)
        print("ctrl+l -> screen:", scr(app), "| focused:", wid(app.focused))
        print("dialog widgets:")
        for line in dump_dialog(app):
            print("   ", line)
        kinds = {type(w).__name__ for w in app.screen.query("*")}
        print("dialog has a list/picker widget?", sorted(k for k in kinds if k in ("ListView", "OptionList", "DataTable", "DirectoryTree", "SelectionList", "Select", "Tree")) or "none")
        painted = " ".join(dump_dialog(app))
        print("dialog names a work-area file (firmware_1)?", "firmware_1" in painted,
              "| names a recent source (case_01/case_02)?", ("case_01" in painted) or ("case_02" in painted))
        # CW-U-13: empty Load
        ns, nn = len(app._probe_status), len(app._probe_notes)
        await pilot.click("#load_ok"); await settle(app, pilot, 2)
        st, no = new_msgs(app, ns, nn)
        print("empty Load click -> screen:", scr(app), "| new status:", st, "| new notices:", no)
        # empty Enter
        app.screen.query_one("#load_path").focus()
        await pilot.press("enter"); await settle(app, pilot, 2)
        st, no = new_msgs(app, ns, nn)
        print("empty Enter -> screen:", scr(app), "| new status:", st, "| new notices:", no)
        # D10: Enter with a path
        app.screen.query_one("#load_path").value = str(C0 / "prg.s19")
        app.screen.query_one("#load_path").focus()
        before = app.current_file.path.name if app.current_file else None
        await pilot.press("enter"); await settle(app, pilot)
        print("Enter with a typed path -> screen:", scr(app), "| current_file before/after:", before, "/",
              app.current_file.path.name if app.current_file else None)
        # CW-U-12: escape
        if scr(app) != "LoadFileScreen":
            await open_load_file(app, pilot)
        await pilot.press("escape"); await settle(app, pilot, 2)
        print("escape on LoadFileScreen -> screen:", scr(app), "| stack:", stack(app))


async def s2():
    print("== S2 Save project dialog")
    base = new_base()
    app = new_app(base)
    async with app.run_test(size=(160, 50)) as pilot:
        await settle(app, pilot)
        await load_path(app, pilot, C1 / "firmware.s19")
        await pilot.press("ctrl+s"); await settle(app, pilot, 2)
        print("ctrl+s -> screen:", scr(app))
        for line in dump_dialog(app):
            if "Input" in line or "Label" in line:
                print("   ", line)
        app.screen.query_one("#project_name").value = ""
        ns, nn = len(app._probe_status), len(app._probe_notes)
        await pilot.click("#save_ok"); await settle(app, pilot, 2)
        st, no = new_msgs(app, ns, nn)
        print("empty name Save click -> screen:", scr(app), "| new status:", st, "| new notices:", no)
        await pilot.press("escape"); await settle(app, pilot, 2)
        print("escape on SaveProjectScreen -> screen:", scr(app), "| stack:", stack(app))


async def s3():
    print("== S3 Load project dialog")
    base = new_base()
    app = new_app(base)
    async with app.run_test(size=(160, 50)) as pilot:
        await settle(app, pilot)
        await load_path(app, pilot, C1 / "firmware.s19")
        save_project(app, app.workarea, "P"); await settle(app, pilot)
        app.action_load_project(); await settle(app, pilot, 2)
        print("action_load_project -> screen:", scr(app))
        for line in dump_dialog(app):
            print("   ", line)
        await pilot.press("escape"); await settle(app, pilot, 2)
        print("escape on LoadProjectScreen -> screen:", scr(app), "| stack:", stack(app))


async def try_key(app, pilot, key):
    await pilot.press(key); await settle(app, pilot, 2)
    s = scr(app)
    # close whatever opened so the next key starts from the main screen
    while len(app.screen_stack) > 1:
        app.pop_screen(); await settle(app, pilot, 1)
    return s


async def s4():
    print("== S4 focus after a load (CW-U-2)")
    base = new_base()
    app = new_app(base)
    async with app.run_test(size=(160, 50)) as pilot:
        await settle(app, pilot)
        await load_path(app, pilot, C1 / "firmware.s19")
        save_project(app, app.workarea, "P"); await settle(app, pilot)
        await dialog_load(app, pilot, C0 / "prg.s19")
        f = app.focused
        try:
            win = app.query_one("#screen_split_join")
            hidden = (not win.display) or (not win.visible) or win.region.area == 0
        except Exception as exc:  # noqa: BLE001
            hidden = f"<{exc}>"
        print("after Load file dialog: current_file:", app.current_file.path.name, "| focused:", wid(f),
              "| focused region area:", f.region.area if f else None, "| split window hidden:", hidden)
        print("   `p` ->", await try_key(app, pilot, "p"))
        await dialog_load(app, pilot, C0 / "prg.s19")
        print("   `k` ->", await try_key(app, pilot, "k"))
        await dialog_load(app, pilot, C0 / "prg.s19")
        print("   `t` ->", await try_key(app, pilot, "t"))
        # Load project through its dialog
        app.action_load_project(); await settle(app, pilot, 2)
        await pilot.click("#project_ok"); await settle(app, pilot)
        f = app.focused
        print("after Load project dialog: project:", app.current_project, "| focused:", wid(f),
              "| focused region area:", f.region.area if f else None, "| status:", app._probe_status[-1:])
        print("   `p` ->", await try_key(app, pilot, "p"))


async def s5():
    print("== S5 load over a patched, unsaved image (CW-U-5)")
    base = new_base()
    app = new_app(base)
    async with app.run_test(size=(160, 50)) as pilot:
        await settle(app, pilot)
        await load_path(app, pilot, C1 / "firmware.s19")
        save_project(app, app.workarea, "P"); await settle(app, pilot)
        orig = mem_digest(app.current_file.mem_map)
        patch_apply(app, hex(max(app.current_file.mem_map) - 3), "DE AD BE EF")
        await settle(app, pilot)
        patched = mem_digest(app.current_file.mem_map)
        print("patched in memory:", orig, "->", patched, "| status:", app._probe_status[-1:])
        ns, nn = len(app._probe_status), len(app._probe_notes)
        await open_load_file(app, pilot)
        app.screen.query_one("#load_path").value = str(C2 / "firmware.s19")
        await pilot.click("#load_ok")
        await settle(app, pilot)
        st, no = new_msgs(app, ns, nn)
        print("Load file over patched image -> stack:", stack(app), "| current_file:", app.current_file.path.name,
              "| image still patched?", mem_digest(app.current_file.mem_map) == patched,
              "| new status:", st, "| new notices:", no)
        while len(app.screen_stack) > 1:
            app.pop_screen(); await settle(app, pilot, 1)
        # Load project over a patched image
        app._handle_load_project("P"); await settle(app, pilot)
        patch_apply(app, hex(max(app.current_file.mem_map) - 3), "01 02 03 04"); await settle(app, pilot)
        patched2 = mem_digest(app.current_file.mem_map)
        ns, nn = len(app._probe_status), len(app._probe_notes)
        app.action_load_project(); await settle(app, pilot, 2)
        await pilot.click("#project_ok"); await settle(app, pilot)
        st, no = new_msgs(app, ns, nn)
        print("Load project over patched image -> stack:", stack(app), "| image still patched?",
              mem_digest(app.current_file.mem_map) == patched2, "| new status:", st, "| new notices:", no)


async def s6():
    print("== S6 reserved project names")
    from s19_app.tui.workspace import RESERVED_WORKAREA_HOMES
    print("RESERVED_WORKAREA_HOMES:", RESERVED_WORKAREA_HOMES)
    base = new_base()
    app = new_app(base)
    async with app.run_test(size=(160, 50)) as pilot:
        await settle(app, pilot)
        await load_path(app, pilot, C1 / "firmware.s19")
        # through the real dialog
        await pilot.press("ctrl+s"); await settle(app, pilot, 2)
        app.screen.query_one("#project_parent_path").value = str(app.workarea)
        app.screen.query_one("#project_name").value = "reports"
        await pilot.click("#save_ok"); await settle(app, pilot)
        print("dialog Save 'reports' -> status:", app._probe_status[-2:], "| current_project:", app.current_project)
        for name in ("crc", "Splits", "flows"):
            save_project(app, app.workarea, name); await settle(app, pilot)
            print(f"handler Save {name!r} -> status:", app._probe_status[-2:], "| current_project:", app.current_project)
        print("workarea dirs:", sorted(p.name for p in app.workarea.iterdir() if p.is_dir()))
        print("list_projects():", app.list_projects())


def s7():
    print("== S7 copy_into_workarea _<N> growth (M-1)")
    from s19_app.tui.workspace import copy_into_workarea
    base = new_base()
    temp = base / ".s19tool" / "workarea" / "temp"
    temp.mkdir(parents=True)
    seq = [("case_01", C1 / "firmware.s19"), ("case_02", C2 / "firmware.s19"),
           ("case_02 again", C2 / "firmware.s19"), ("case_01 again", C1 / "firmware.s19"),
           ("case_02 third", C2 / "firmware.s19")]
    for tag, src in seq:
        out = copy_into_workarea(src, temp)
        print(f"copy {tag:14s} -> {out.name}")
    print("temp:", tree(temp))
    # a file already inside the work area, copied back into temp
    inside = temp / "firmware_1.s19"
    if inside.exists():
        out = copy_into_workarea(inside, temp)
        print("copy temp/firmware_1.s19 into temp ->", out.name, "| temp:", sorted(p.name for p in temp.iterdir()))


async def s7_app():
    print("== S7b app load of a file already in the work area")
    base = new_base()
    app = new_app(base)
    async with app.run_test(size=(160, 50)) as pilot:
        await settle(app, pilot)
        await load_path(app, pilot, C1 / "firmware.s19")
        await load_path(app, pilot, C2 / "firmware.s19")
        inside = app.workarea / "temp" / "firmware_1.s19"
        await load_path(app, pilot, inside)
        print("Load file temp/firmware_1.s19 -> current_file:", app.current_file.path.relative_to(app.workarea).as_posix(),
              "| status:", app._probe_status[-2:], "| temp:", sorted(p.name for p in (app.workarea / "temp").iterdir()))
        # external source re-load after the work copy diverged (patched + saved back under the same name)
        await load_path(app, pilot, C1 / "firmware.s19")
        patch_apply(app, hex(max(app.current_file.mem_map) - 3), "DE AD BE EF"); await settle(app, pilot)
        from s19_app.tui.screens_directionb import PatchEditorPanel as Pn
        app.on_patch_editor_panel_save_back_decision(Pn.SaveBackDecision("firmware.s19")); await settle(app, pilot)
        print("save-back status:", app._probe_status[-1:], "| workarea files:",
              sorted(p.relative_to(app.workarea).as_posix() for p in app.workarea.rglob("*.s19")))
        await load_path(app, pilot, C1 / "firmware.s19")
        print("re-load external case_01 -> current_file:", app.current_file.path.relative_to(app.workarea).as_posix(),
              "| temp:", sorted(p.name for p in (app.workarea / "temp").iterdir()))


async def main():
    import s19_app
    print("s19_app imported from:", s19_app.__file__)
    only = sys.argv[1:] or ["s1", "s2", "s3", "s4", "s5", "s6", "s7", "s7b"]
    for name in only:
        try:
            if name == "s7":
                s7()
            elif name == "s7b":
                await s7_app()
            else:
                await globals()[name]()
        except Exception as exc:  # noqa: BLE001
            import traceback
            print(f"!! {name} RAISED {type(exc).__name__}: {exc}")
            traceback.print_exc(limit=4)
        print()


asyncio.run(main())
