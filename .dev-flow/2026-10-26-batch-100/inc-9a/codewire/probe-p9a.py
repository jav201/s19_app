import sys, os, asyncio, shutil, tempfile
from pathlib import Path
REPO = Path(sys.argv[1])
sys.path.insert(0, str(REPO))
import s19_app
print("== import", s19_app.__file__)
from s19_app.tui.app import S19TuiApp
from s19_app.tui.workspace import validate_project_files
CASE01 = REPO / "examples" / "case_01_basic_valid" / "firmware.s19"

def statuses(app):
    return [m for m in getattr(app, "_status_history", [])] if hasattr(app, "_status_history") else None

async def main():
    base = Path(tempfile.mkdtemp(prefix="p9a_"))
    os.chdir(base)
    app = S19TuiApp(base_dir=base)
    seen = []
    orig = app.set_status
    def spy(msg, *a, **k):
        seen.append(str(msg)); return orig(msg, *a, **k)
    app.set_status = spy
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        wa = app.workarea
        (wa / "ab").mkdir()
        shutil.copy(CASE01, wa / "ab" / "firmware.s19")
        (wa / "ab" / "project.json").write_text("{}", encoding="utf-8")
        (wa / "E").mkdir()
        shutil.copy(CASE01, wa / "temp" / "firmware.s19")
        print("== U1 list_projects", app.list_projects())
        print("== U2 validate_project_files(temp)", [p.name for p in validate_project_files(wa / "temp")[0]])
        for typed in [wa / "ab", wa / "ab" / "project.json", Path("ab"), Path("temp")]:
            seen.clear()
            app._load_path_from_user_input(typed)
            await pilot.pause()
            print("== U3 typed", typed if typed.is_absolute() is False else str(typed).replace(str(base), "<base>"), "->", seen, "project=", app.current_project)
        seen.clear()
        app._handle_load_project("temp")
        await pilot.pause(); await pilot.pause()
        print("== U4 _handle_load_project('temp') ->", seen[-2:], "project=", app.current_project, "dir_has_project_json=", (wa/"temp"/"project.json").exists())
        seen.clear()
        app.current_project = None
        app._handle_load_project("TEMP")
        await pilot.pause()
        print("== U5 _handle_load_project('TEMP') ->", seen[-2:], "project=", app.current_project)
        app.current_project = None
        seen.clear()
        app._handle_load_project("E")
        await pilot.pause()
        print("== U6 _handle_load_project('E') ->", seen[-2:])
asyncio.run(main())
