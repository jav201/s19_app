"""Thread U1: Load file dialog -> load -> status / log / Workspace / Workarea Files.

Real keys through Pilot: `l` opens the dialog, the path is typed, `Load` is clicked.
Data: examples/case_01_basic_valid/firmware.s19 and case_02's firmware.s19 (same
name, other bytes) as a "changed" external source.
"""
import shutil
from ucommon import *  # noqa: F403


async def main():
    base = new_base()
    ext = base / "ext"; ext.mkdir()
    src = ext / "firmware.s19"
    shutil.copy2(C1 / "firmware.s19", src)
    app = new_app(base)
    temp = app.workarea / "temp"
    async with app.run_test(size=SIZE) as pilot:
        await settle(app, pilot)
        take(app)
        p("== U1.0 start: Workarea Files =", listview_items(app, "#files_list"))

        async def dialog_load(path_text, label):
            await pilot.press("l")
            await settle(app, pilot, 3)
            scr = app.screen
            p(f"== {label}: dialog screen = {type(scr).__name__}")
            if type(scr).__name__ == "LoadFileScreen":
                from textual.widgets import Button, Label
                p("   dialog title  =", [text_of(w) for w in scr.query(Label)])
                p("   dialog buttons=", [text_of(b) for b in scr.query(Button)])
                p("   dialog widgets=", sorted({type(w).__name__ for w in scr.query("*")}))
                inp = scr.query_one("#load_path")
                inp.value = path_text
                await pilot.click("#load_ok")
                await settle(app, pilot)
            p(f"   after: screen = {type(app.screen).__name__}")
            p("   recorded     =", take(app))
            p("   painted      =", screen_lines(app))
            p("   temp dir     =", sorted(x.name for x in temp.iterdir()) if temp.exists() else None)
            p("   Workarea Files list =", listview_items(app, "#files_list"))
            f = app.current_file
            p("   current_file =", (f.path.name, mem_digest(f.mem_map)) if f else None)

        await dialog_load(str(src), "U1.1 first load of ext/firmware.s19 (case_01)")
        await dialog_load(str(src), "U1.2 re-load, same bytes")
        shutil.copy2(C2 / "firmware.s19", src)
        await dialog_load(str(src), "U1.3 re-load after the source changed (case_02 bytes)")
        shutil.copy2(C1 / "firmware.s19", src)
        await dialog_load(str(src), "U1.4 source changed back to case_01 bytes")
        await dialog_load(str(temp / "firmware_1.s19"), "U1.5 load the work copy itself (temp/firmware_1.s19)")
        await dialog_load("", "U1.6 empty input, Load clicked")
        if type(app.screen).__name__ == "LoadFileScreen":
            p("   dialog still open after empty Load; recorded =", take(app))
            await pilot.click("#load_cancel")
            await settle(app, pilot, 2)
        await dialog_load(str(base / "nope.s19"), "U1.7 missing path")
        await dialog_load(str(ext), "U1.8 a folder path")
        # selecting an item of Workarea Files, if the list has one
        items = listview_items(app, "#files_list")
        p("== U1.9 Workarea Files items =", items)
        # the workarea root, where refresh_files globs
        p("   workarea root files =", sorted(x.name for x in app.workarea.iterdir() if x.is_file()))
        p("   workarea root dirs  =", sorted(x.name for x in app.workarea.iterdir() if x.is_dir()))
        # loaded panel text
        p("   #loaded_panel text =", q_text(app, "#loaded_panel"))


run(main)
