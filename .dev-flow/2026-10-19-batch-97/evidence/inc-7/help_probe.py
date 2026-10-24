"""Inc-7 help-modal probe: for each window-help section at each size, open the
modal and report the dialog region, the screen size, whether the dialog fits,
and whether the LAST line of the keys block (or body) can be brought on screen
(scroll_end on any scrollable ancestor) and is painted."""
import asyncio, sys, tempfile
from pathlib import Path
ROOT = Path(sys.argv[1]).resolve(); sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / "tests"))
from s19_app.tui.app import S19TuiApp
from s19_app.tui.window_help import WINDOW_HELP_SECTIONS, open_window_help
SIZES = [tuple(map(int, s.split("x"))) for s in (sys.argv[2:] or ["118x54", "80x24"])]
async def probe(size):
    app = S19TuiApp(base_dir=Path(tempfile.mkdtemp()))
    out = []
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        for key in WINDOW_HELP_SECTIONS:
            open_window_help(app, key)
            for _ in range(4): await pilot.pause()
            scr = app.screen
            dlg = scr.query_one("#window_help_dialog")
            last = (scr.query("#window_help_keys") or scr.query("#window_help_body")).last()
            text_last = str(last.render()).rstrip("\n").split("\n")[-1].strip()
            for w in scr.query("*"):
                if getattr(w, "max_scroll_y", 0) and w.max_scroll_y > 0:
                    w.scroll_end(animate=False)
            for _ in range(3): await pilot.pause()
            strips = scr._compositor.render_strips()
            rows = ["".join(s.text for s in st) for st in strips]
            seen = any(text_last[:30] in r for r in rows)
            out.append((key, tuple(dlg.region), dlg.region.y >= 0 and dlg.region.bottom <= size[1], seen))
            await pilot.press("escape")
            for _ in range(3): await pilot.pause()
    return out
async def main():
    for size in SIZES:
        for row in await probe(size):
            print(size, *row)
asyncio.run(main())
