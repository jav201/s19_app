"""Inc-6 copy of inc-3/snapshot_cells.py with six more pauses before the capture (settled).

PC-10 executed check: render the 29 snapshot cells and hash each painted frame.

Run with a tree root as the only argument (the working tree, or a HEAD worktree):
    python snapshot_cells.py <tree_root>  > cells-<label>.txt
Each line: ``<cell id> <sha256 of the composited frame>`` — every painted segment's
text and style; temp-dir names and clock times are normalised (the first SVG hash
differed between two runs of the same tree, so it was not a usable instrument). Comparing the two outputs cell by cell is
the C-22 prediction's verification without a snapshot regen (D17).
"""
import asyncio
import hashlib
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(ROOT))

from s19_app.tui.app import S19TuiApp  # noqa: E402
from tests import test_tui_snapshot as snap  # noqa: E402


class _Factory:
    def mktemp(self, name, numbered=True):
        return Path(tempfile.mkdtemp(prefix=name))


triple = snap.public_triple._get_wrapped_function()(_Factory())


async def render(screen, density, size_key):
    width, height = snap._SIZES[size_key]
    app = S19TuiApp(base_dir=Path(tempfile.mkdtemp()))
    async with app.run_test(size=(width, height)) as pilot:
        await snap._snapshot_run_before(screen, density, triple)(pilot)
        await pilot.pause()
        # Inc-6: settle to idle — the A2L-name status column lands a tick
        # later on some runs (load-timing noise, both trees).
        for _ in range(6):
            await pilot.pause()
        strips = app.screen._compositor.render_strips()
        frame = chr(10).join(
            "".join(seg.text for seg in strip) for strip in strips
        )
    frame = re.sub(r"tmp\w+", "TMP", frame)
    frame = re.sub(r"\d\d:\d\d(:\d\d)?", "HH:MM", frame)
    return frame


async def main():
    for param in snap._ALL_SNAPSHOT_CELLS:
        screen, density, size_key = param.values
        frame = await render(screen, density, size_key)
        print(f"===== {param.id} sha256 {hashlib.sha256(frame.encode('utf-8')).hexdigest()}")
        print(frame, flush=True)


asyncio.run(main())
