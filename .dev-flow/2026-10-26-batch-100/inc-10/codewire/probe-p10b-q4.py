"""Q-4 probe: the trailing-dot MAC path on base (read-only; throwaway tree)."""
import asyncio, shutil, sys, tempfile
from pathlib import Path, PureWindowsPath
TREE = Path(sys.argv[1]).resolve(); sys.path.insert(0, str(TREE))
from s19_app.tui.app import S19TuiApp
from s19_app.tui.workspace import recent_kind, WORKAREA_DIRNAME, WORKAREA_SUBDIR, WORKAREA_TEMP
print("Q4 PureWindowsPath('x.mac.').suffix =", repr(PureWindowsPath("x.mac.").suffix), "| recent_kind =", recent_kind(Path("x.mac.")))
async def main():
    tmp = Path(tempfile.mkdtemp(prefix="p10q4_")); base = tmp / "app"
    t = base / WORKAREA_DIRNAME / WORKAREA_SUBDIR / WORKAREA_TEMP; t.mkdir(parents=True)
    shutil.copy2(TREE / "examples/case_01_basic_valid/firmware.s19", t / "firmware.s19")
    shutil.copy2(TREE / "examples/case_01_basic_valid/firmware.mac", tmp / "x.mac")
    app = S19TuiApp(base_dir=base)
    async with app.run_test(size=(118, 54)) as pilot:
        await pilot.pause()
        app.load_selected_file(t / "firmware.s19")
        for _ in range(15): await pilot.pause()
        typed = Path(str(tmp / "x.mac") + ".")
        print("Q4 exists(typed 'x.mac.') =", typed.exists(), "| route =", app._typed_load_route(typed))
        app._load_path_from_user_input(typed)
        await app.workers.wait_for_complete()
        for _ in range(30): await pilot.pause()
        print("Q4 after typed 'x.mac.': file", app.current_file.path.name, "| mac", app.current_file.mac_path.name if app.current_file.mac_path else None, "| last status", list(app.log_lines)[-1:])
    shutil.rmtree(tmp, ignore_errors=True)
asyncio.run(main())
