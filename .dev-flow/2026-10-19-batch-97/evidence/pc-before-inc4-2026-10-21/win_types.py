import sys, asyncio, tempfile, pathlib
sys.path.insert(0, sys.argv[1]); sys.path.insert(1, r"C:\Users\jjgh8\Github\s19_app")
from s19_app.tui.app import S19TuiApp
from textual.containers import Container
async def main():
    app = S19TuiApp(base_dir=pathlib.Path(tempfile.mkdtemp()))
    async with app.run_test(size=(118,54)) as pilot:
        await pilot.pause(); app.action_show_screen("patch"); await pilot.pause()
        for i in ("patch_win_script","patch_win_script_body","patch_win_json","patch_win_json_body","patch_win_json_dock_spacer","patch_win_checks","patch_win_checks_body","patch_saveback_row","patch_before_after_row","patch_checks_results","patch_pane_entries","patch_paste_row","patch_doc_entry_inputs","patch_history_controls"):
            w = app.query_one("#"+i); print(i, type(w).__name__, isinstance(w, Container))
asyncio.run(main())
