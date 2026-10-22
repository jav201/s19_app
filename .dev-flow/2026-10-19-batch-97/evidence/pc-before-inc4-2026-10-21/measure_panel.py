import sys, asyncio, tempfile, pathlib
sys.path.insert(0, r"C:\Users\jjgh8\Github\s19_app")
from s19_app.tui.app import S19TuiApp
async def run(size):
    app = S19TuiApp(base_dir=pathlib.Path(tempfile.mkdtemp()))
    async with app.run_test(size=size) as pilot:
        await pilot.pause(); app.action_show_screen("patch"); await pilot.pause(); await pilot.pause(); await pilot.pause()
        p = app.query_one("#patch_editor_panel"); s = app.query_one("#screen_patch")
        hdr = [ (w.id, tuple(w.region)) for w in s.children ]
        print(size, "screen", tuple(s.region), "panel region", tuple(p.region), "content", tuple(p.content_region), "scrollbar_v", p.scrollbar_size_vertical, "children", hdr)
for size in ((118,54),(118,53),(220,60),(220,59)):
    asyncio.run(run(size))
