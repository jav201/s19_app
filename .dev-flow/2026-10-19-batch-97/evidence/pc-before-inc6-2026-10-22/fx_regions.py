"""Probe (pre-Inc-6, not product): #fx_panel and #screen_flow_execution regions at HEAD."""
import asyncio, sys, tempfile
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import s19_app, textual
from s19_app.tui.app import S19TuiApp
async def one(w, h):
    app = S19TuiApp(base_dir=Path(tempfile.mkdtemp()))
    async with app.run_test(size=(w, h)) as pilot:
        await pilot.pause(); app.action_show_screen("flow_execution")
        for _ in range(5): await pilot.pause()
        sc = app.query_one("#screen_flow_execution"); p = app.query_one("#fx_panel")
        fl = app.query_one("#flow_panel")
        return (w, h, tuple(sc.region), tuple(p.region), tuple(p.content_region), app.focused and app.focused.id)
async def main():
    print("S19_APP_FROM", s19_app.__file__, "textual", textual.__version__)
    for w, h in ((118, 54), (118, 53), (220, 60), (220, 59)):
        print(await one(w, h))
asyncio.run(main())
