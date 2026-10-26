import asyncio, shutil, tempfile
from pathlib import Path
from s19_app.tui.app import S19TuiApp
from textual.widgets import Label

tmp = Path(tempfile.mkdtemp())
src = tmp / "firmware.s19"
shutil.copyfile("tests/fixtures/synth/synth_no_terminator.s19", src)
app = S19TuiApp(base_dir=tmp)


async def drive():
    async with app.run_test(size=(120, 54)) as pilot:
        await pilot.pause()
        await pilot.press("l")
        for _ in range(6):
            await pilot.pause()
        await pilot.click("#load_path")
        await pilot.press(*str(src))
        await pilot.click("#load_ok")
        for _ in range(80):
            await pilot.pause()
        for wid in ("#status_text", "#log_line_1", "#log_line_2", "#log_line_3", "#log_line_4"):
            try:
                print(wid, repr(str(app.query_one(wid, Label).render())))
            except Exception as e:
                print(wid, "ERR", e)


asyncio.run(drive())
