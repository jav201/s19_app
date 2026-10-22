"""Inc-4 guard (design Inc-4 row item (6), D23 / Inc-3 F9): the Check Editor's
painted text frame at 118x54 and 220x60, on a given tree.

Run with a tree root as the only argument (the working tree, or a HEAD
worktree):  python check_frames.py <tree_root> > check-frames-<label>.txt
The frame is the composited text of ``#screen_check_editor`` after the demo
A2L loads and two parameters are included (``open_check_editor`` + the
Include button); temp-dir names and clock times are normalised. Comparing the
two outputs row by row shows whether an Inc-4 rule restyled the Check Editor
(no snapshot cell renders it).
"""
import asyncio
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(ROOT))

from s19_app.tui.app import S19TuiApp  # noqa: E402
from tests.b97_fixtures import open_check_editor  # noqa: E402
from tests.b97_probes import painted_rows, settle  # noqa: E402


async def frame(size):
    app = S19TuiApp(base_dir=Path(tempfile.mkdtemp()))
    async with app.run_test(size=size) as pilot:
        panel = await open_check_editor(app, pilot)
        table = panel.query_one("#check_param_table")
        for row in (0, 2):
            table.move_cursor(row=row)
            await settle(pilot, 2)
            panel.query_one("#check_param_include_button").press()
            await settle(pilot, 2)
        table.move_cursor(row=0)
        await settle(pilot, 4)
        rows = painted_rows(app, app.query_one("#screen_check_editor"))
    text = "\n".join(rows)
    text = re.sub(r"tmp\w+", "TMP", text)
    return re.sub(r"\d\d:\d\d(:\d\d)?", "HH:MM", text)


async def main():
    for size in ((118, 54), (220, 60)):
        print(f"===== check-editor {size[0]}x{size[1]}")
        print(await frame(size), flush=True)


asyncio.run(main())
