"""Inc-6 guard (design Inc-6 row item (11)): the painted text frames of the
Check Editor, the Patch Editor and the Flow Builder at 118x54 and 220x60, on a
given tree — the Builder frame is also the guard of the ``FlowChip`` swap
(every Builder ``Button(`` became a ``FlowChip(``). Derived from
``evidence/inc-5/frames.py`` (its Execution frame replaced by the Builder's).

Run with a tree root as the only argument (the working tree, or a HEAD
worktree):  python frames.py <tree_root> > frames-<label>.txt
Check Editor: the demo A2L with two parameters included (the Inc-4
``check_frames.py`` procedure). Patch Editor: ``prg.s19`` and
``calib_hotfix.json`` loaded. Flow Execution: the screen with a project
loaded and no lanes (Inc-5); Flow Builder (Inc-6): ``patch_chain`` loaded
through Load…, then Run.
Temp-dir names and clock times are normalised. Comparing two outputs row by
row shows whether an Inc-5 rule restyled a neighbouring screen (no snapshot
cell renders any of the three).
"""
import asyncio
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(ROOT))

from s19_app.tui.app import S19TuiApp  # noqa: E402
from tests.b97_fixtures import (  # noqa: E402
    flow_project,
    load_flow,
    open_flow_builder,
    calib_hotfix,
    load_change_file,
    load_project,
    make_project,
    open_check_editor,
    open_patch_editor,
)
from tests.b97_probes import painted_rows, settle  # noqa: E402


def normalise(rows):
    text = "\n".join(rows)
    text = re.sub(r"tmp\w+", "TMP", text)
    return re.sub(r"\d\d:\d\d(:\d\d)?", "HH:MM", text)


async def check_frame(size):
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
        return normalise(painted_rows(app, app.query_one("#screen_check_editor")))


async def patch_frame(size):
    base = Path(tempfile.mkdtemp())
    app = S19TuiApp(base_dir=base)
    async with app.run_test(size=size) as pilot:
        panel = await open_patch_editor(app, pilot)
        await load_change_file(app, pilot, panel, calib_hotfix(base))
        await settle(pilot, 6)
        return normalise(painted_rows(app, app.query_one("#screen_patch")))


async def builder_frame(size):
    app = S19TuiApp(base_dir=Path(tempfile.mkdtemp()))
    async with app.run_test(size=size) as pilot:
        await settle(pilot)
        flow_project(app)
        panel = await open_flow_builder(app, pilot)
        await load_flow(app, pilot, "patch_chain")
        panel.query_one("#flow_run").press()
        for _ in range(60):
            await pilot.pause()
            if panel.query("#flow_result .flow-banner"):
                break
        await settle(pilot, 6)
        return normalise(painted_rows(app, app.query_one("#screen_flow")))


async def main():
    for name, fn in (("check-editor", check_frame), ("patch-editor", patch_frame), ("flow-builder", builder_frame)):
        for size in ((118, 54), (220, 60)):
            print(f"===== {name} {size[0]}x{size[1]}")
            print(await fn(size), flush=True)


asyncio.run(main())
