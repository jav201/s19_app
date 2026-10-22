"""Throwaway spike (PC before Inc-5): #flow_panel heights at HEAD + S4-1 path."""
import asyncio, sys, tempfile, traceback
from pathlib import Path
REPO = Path(r"C:\Users\jjgh8\Github\s19_app")
sys.path.insert(0, str(REPO))
from textual import events
from textual.widgets import Input, Select, Button
from s19_app.tui.app import S19TuiApp
from tests.b97_fixtures import make_project, load_project

async def settled(pilot, n=6):
    for _ in range(n):
        await pilot.pause()

async def heights():
    for size in [(118, 54), (118, 53), (220, 60), (220, 59)]:
        with tempfile.TemporaryDirectory(dir=".", ignore_cleanup_errors=True) as td:
            app = S19TuiApp(base_dir=Path(td))
            async with app.run_test(size=size) as pilot:
                app.action_show_screen("flow")
                await settled(pilot)
                panel = app.query_one("FlowBuilderPanel")
                scr = app.query_one("#screen_flow")
                print(f"{size[0]}x{size[1]}: #screen_flow {tuple(scr.region)} #flow_panel {tuple(panel.region)} content {tuple(panel.content_region)}")

async def s41():
    with tempfile.TemporaryDirectory(dir=".", ignore_cleanup_errors=True) as td:
        app = S19TuiApp(base_dir=Path(td))
        async with app.run_test(size=(118, 54)) as pilot:
            make_project(app); load_project(app)
            app.action_show_screen("flow")
            await settled(pilot)
            panel = app.query_one("FlowBuilderPanel")
            # 1) source prg.s19
            panel.query_one("#flow_kind", Select).value = "source"
            await settled(pilot)
            panel.query_one("#flow_ref", Input).value = "prg.s19"
            panel.query_one("#flow_add", Button).press(); await settled(pilot)
            # 2) write_out with a pasted NUL
            panel.query_one("#flow_kind", Select).value = "write_out"
            await settled(pilot)
            ref = panel.query_one("#flow_ref", Input)
            ref.focus(); await settled(pilot)
            ref.post_message(events.Paste("o\x00ut.s19")); await settled(pilot)
            print("input value after paste:", repr(ref.value))
            panel.query_one("#flow_add", Button).press(); await settled(pilot)
            print("blocks:", [ (b.kind, getattr(b,'output_name',getattr(b,'image_ref',None))) for b in panel._blocks])
            notice = panel.query_one("#flow_wiring_notice")
            print("notice displayed:", notice.display, repr(str(notice.render())))
            panel.query_one("#flow_run", Button).press(); await settled(pilot, 12)
            res = panel.query_one("#flow_result")
            texts = []
            for w in res.walk_children():
                try:
                    r = w.render()
                    texts.append(str(r))
                except Exception:
                    pass
            print("result texts:", [t for t in texts if t.strip()][:12])

asyncio.run(heights())
try:
    asyncio.run(s41())
except Exception:
    traceback.print_exc()
