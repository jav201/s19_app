"""Probe (pre-Inc-6, not product): where the focus and the binding chain sit after ']'."""
import asyncio, sys, tempfile
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import s19_app
from s19_app.tui.app import S19TuiApp
from textual.widgets import Input
async def main():
    app = S19TuiApp(base_dir=Path(tempfile.mkdtemp()))
    async with app.run_test(size=(118, 54)) as pilot:
        await pilot.pause()
        for label, prep in (("start, then ]", None), ("focus None, then ]", "none"), ("focus #fx_set_name", "input")):
            if prep == "none": app.set_focus(None)
            await pilot.press("right_square_bracket")
            for _ in range(3): await pilot.pause()
            if prep == "input":
                app.query_one("#fx_set_name", Input).focus(); await pilot.pause()
            chain = [getattr(n, "id", None) or type(n).__name__ for n, _ in app.screen._binding_chain]
            inside = any(getattr(n, "id", None) == "screen_flow_execution" for n, _ in app.screen._binding_chain)
            print(label, "| focused:", app.focused and app.focused.id, "| section in chain:", inside, "| chain:", chain)
        inp = app.query_one("#fx_set_name", Input)
        print("Input consumes 'c':", inp.check_consume_key("c", "c"))
asyncio.run(main())
