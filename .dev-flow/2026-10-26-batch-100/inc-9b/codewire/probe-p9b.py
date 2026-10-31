"""Probe p9b — Inc 9b E2 baseline, run once on the 9a tree (a scratch copy).

python -I probe-p9b.py <repo>   (the repo is put first on sys.path; import line printed)
LOCALAPPDATA is pointed at a temp folder before the app is imported: the probe
never touches the real recent-sources store.
"""
import asyncio
import os
import shutil
import sys
import tempfile
from pathlib import Path

REPO = Path(sys.argv[1])
sys.path.insert(0, str(REPO))
STORE_HOME = Path(tempfile.mkdtemp(prefix="p9b_store_"))
os.environ["LOCALAPPDATA"] = str(STORE_HOME)

import s19_app  # noqa: E402

print("== import", s19_app.__file__)
from textual.widgets import Input, Label, ListView  # noqa: E402

import s19_app.tui.app as appmod  # noqa: E402
from s19_app.tui.app import S19TuiApp  # noqa: E402
from s19_app.tui.workspace import list_workarea_files, read_recent_sources  # noqa: E402

CASE01 = REPO / "examples" / "case_01_basic_valid" / "firmware.s19"
A2L = REPO / "examples" / "case_00_public" / "ASAP2_Demo_V161.a2l"


def stack(app):
    return [type(s).__name__ for s in app.screen_stack]


def make_app(base):
    app = S19TuiApp(base_dir=base)
    seen = []
    orig = app.set_status

    def spy(msg, *a, **k):
        seen.append(str(msg))
        return orig(msg, *a, **k)

    app.set_status = spy
    return app, seen


async def part_projects():
    base = Path(tempfile.mkdtemp(prefix="p9b_"))
    os.chdir(base)
    app, seen = make_app(base)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        wa = app.workarea
        # U1 / U2: 0 projects -> `p`
        await pilot.press("p")
        await pilot.pause()
        print("== U1 p with 0 projects -> stack", stack(app), "status", seen[-1:])
        for name, files in [
            ("ab", {"project.json": "{}", "firmware.s19": CASE01}),
            ("E", {}),
            ("n", {"notes.txt": "x"}),
            ("j", {"project.json": "{}"}),
            ("s", {"x.s19": CASE01}),
            ("c", {"c.a2l": A2L}),
            ("[b]P", {"project.json": "{}", "firmware.s19": CASE01}),
        ]:
            (wa / name).mkdir()
            for fname, src in files.items():
                if isinstance(src, Path):
                    shutil.copy(src, wa / name / fname)
                else:
                    (wa / name / fname).write_text(src, encoding="utf-8")
        print("== U2 list_projects", app.list_projects())
        for name in ["E", "n", "j"]:
            seen.clear()
            app.current_project = None
            app._handle_load_project(name)
            await pilot.pause()
            print(f"== U3 _handle_load_project({name!r}) ->", seen[-1:], "project=", app.current_project)
        typed = wa / "E"
        seen.clear()
        app._load_path_from_user_input(typed)
        await pilot.pause()
        print("== U4 typed <workarea>/E ->", seen[-1:])
        # U5: the Load project dialog
        await pilot.press("p")
        await pilot.pause()
        scr = app.screen
        lv = scr.query_one("#project_list", ListView)
        labels = list(scr.query("#project_list Label"))
        painted = [str(lb.render()) for lb in labels]
        print("== U5 p -> stack", stack(app), "focused", getattr(app.focused, "id", None),
              "index", lv.index, "rows", len(labels))
        print("== U5 painted labels", painted)
        bP = next(lb for lb in labels if "P" in str(lb.render()) and "ab" != str(lb.render()))
        vis = bP.render()
        spans = getattr(vis, "spans", None)
        print("== U5 '[b]P' label renders", repr(str(vis)), "type", type(vis).__name__,
              "spans", [(s.start, s.end, str(s.style)) for s in spans] if spans else spans)
        await pilot.press("escape")
        await pilot.pause()
        print("== U6 escape on LoadProjectScreen -> stack", stack(app))
        await pilot.press("down")
        await pilot.pause()
        print("== U6 down -> index", lv.index, "focused", getattr(app.focused, "id", None))
        seen.clear()
        await pilot.press("enter")
        await pilot.pause()
        await pilot.pause()
        print("== U7 enter on list -> stack", stack(app), "status", seen[-1:], "project=", app.current_project)
        while len(app.screen_stack) > 1:
            app.pop_screen()
            await pilot.pause()
        await pilot.press("p")
        await pilot.pause()
        scr = app.screen
        scr.query_one("#project_list", ListView).index = 0
        await pilot.pause()
        seen.clear()
        await pilot.click("#project_ok")
        await pilot.pause()
        await pilot.pause()
        print("== U8 project_ok on index 0 -> stack", stack(app), "status", seen[-1:], "project=", app.current_project)


async def part_load_file():
    base = Path(tempfile.mkdtemp(prefix="p9b_"))
    other = Path(tempfile.mkdtemp(prefix="p9b_cwd_"))
    os.chdir(other)
    app, seen = make_app(base)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        wa = app.workarea
        await pilot.press("l")
        await pilot.pause()
        print("== F1 l -> stack", stack(app), "focused", getattr(app.focused, "id", None))
        await pilot.press("escape")
        await pilot.pause()
        print("== F2 escape on LoadFileScreen -> stack", stack(app))
        seen.clear()
        await pilot.click("#load_ok")
        await pilot.pause()
        print("== F3 empty Load click -> stack", stack(app), "status", seen)
        app.screen.query_one("#load_path", Input).value = str(CASE01)
        app.screen.query_one("#load_path", Input).focus()
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        print("== F4 Enter with a typed path -> stack", stack(app), "current_file", app.current_file)
        # F5: priority keys under the modal (LLR-173.2e)
        density_before = app.screen_stack[0].query_one("#workspace_body").classes
        ran = []
        for action in ["load_file", "save_project", "focus_palette", "cycle_density"]:
            orig_action = getattr(app, f"action_{action}")

            def counted(*a, _o=orig_action, _n=action, **k):
                ran.append(_n)
                return _o(*a, **k)

            setattr(app, f"action_{action}", counted)
        for key in ["ctrl+l", "ctrl+s", "ctrl+k", "ctrl+d"]:
            before = stack(app)
            ran.clear()
            await pilot.press(key)
            await pilot.pause()
            print(f"== F5 {key} under LoadFileScreen -> actions run", ran, "stack", stack(app), "(before", before, ")",
                  "focused", type(app.focused).__name__, getattr(app.focused, "id", None))
            while len(app.screen_stack) > 2:
                app.pop_screen()
                await pilot.pause()
        density_after = app.screen_stack[0].query_one("#workspace_body").classes
        print("== F5 density classes before/after", sorted(density_before), sorted(density_after))
        while len(app.screen_stack) > 1:
            app.pop_screen()
            await pilot.pause()
        # F6: CR9-1 -- a relative source found only through the base-folder fallback
        (base / "R").mkdir()
        shutil.copy(CASE01, base / "R" / "x.s19")
        seen.clear()
        app._load_path_from_user_input(Path("R") / "x.s19")
        await pilot.pause()
        await app.workers.wait_for_complete()
        await pilot.pause()
        rs = read_recent_sources()
        print("== F6 typed relative R\\x.s19 (cwd elsewhere) -> status", seen[-1:])
        print("== F6 store", [(e.path.replace(str(base), "<base>"), e.kind) for e in rs.entries], rs.problem)
        # F7: Workarea Files pick -- copy_into_workarea calls (LLR-173.1b)
        shutil.copy(A2L, wa / "temp" / "w.a2l")
        shutil.copy(CASE01, wa / "temp" / "w.s19")
        (wa / "temp" / "w.a2l.json").write_text("{}", encoding="utf-8")
        calls = []
        orig_copy = appmod.copy_into_workarea

        def spy_copy(*a, **k):
            calls.append(Path(a[0]).name)
            return orig_copy(*a, **k)

        appmod.copy_into_workarea = spy_copy
        try:
            class Item:
                pass
            for name in ["w.s19", "w.a2l", "w.a2l.json"]:
                calls.clear()
                seen.clear()
                it = Item()
                it.data = name
                app._load_from_item(it)
                await pilot.pause()
                await app.workers.wait_for_complete()
                await pilot.pause()
                print(f"== F7 _load_from_item({name!r}) -> copy_into_workarea calls", calls, "status", seen[-1:])
        finally:
            appmod.copy_into_workarea = orig_copy
        print("== F8 list_workarea_files", [p.name for p in list_workarea_files(wa)])
        rs = read_recent_sources()
        print("== F9 store after picks", len(rs.entries))


asyncio.run(part_projects())
asyncio.run(part_load_file())
shutil.rmtree(STORE_HOME, ignore_errors=True)
