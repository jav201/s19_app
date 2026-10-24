"""Inc-7 PC-10 race probe: settle the app BEFORE run_before (the initial
resize's deferred update_project_labels has already run), then run the
snapshot harness's run_before and read #status_context after 1 and 6 pauses."""
import asyncio, sys, tempfile
from pathlib import Path
ROOT = Path(sys.argv[1]).resolve(); sys.path.insert(0, str(ROOT))
from s19_app.tui.app import S19TuiApp
from tests import test_tui_snapshot as snap
class F:
    def mktemp(self, name, numbered=True): return Path(tempfile.mkdtemp(prefix=name))
triple = snap.public_triple._get_wrapped_function()(F())
async def once(cell):
    p = next(p for p in snap._ALL_SNAPSHOT_CELLS if p.id == cell)
    screen, density, size_key = p.values
    w, h = snap._SIZES[size_key]
    app = S19TuiApp(base_dir=Path(tempfile.mkdtemp()))
    async with app.run_test(size=(w, h)) as pilot:
        for _ in range(10): await pilot.pause()
        await snap._snapshot_run_before(screen, density, triple)(pilot)
        await pilot.pause()
        a = str(app.query_one("#status_context").render()).strip()
        for _ in range(6): await pilot.pause()
        b = str(app.query_one("#status_context").render()).strip()
        return a, b
async def main():
    print("tree", ROOT)
    for cell in ("mac-compact-120x30", "workspace-comfortable-80x24", "patch-comfortable-120x30"):
        print(cell, *(await once(cell)), sep=" | ")
asyncio.run(main())
