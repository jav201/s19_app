"""Inc-8 guard (PC-24 / LLR-150.6 "nothing else moves"): the painted text
frames of the four batch-97 screens' containers, on a given tree and at given
sizes. The Inc-8 tree at 118x54 / 220x60 is compared with 9793fcd at 118x53 /
220x59 — the same container height (41 / 47) — so the only difference a
two-row key bar may make is the one row it takes. Derived from
``evidence/inc-6/frames.py`` (plus a Flow Execution frame, Inc-5's idiom).

    python frames.py <tree_root> 118x54 220x60 > frames-inc8.txt
    python frames.py <head_tree> 118x53 220x59 > frames-9793fcd.txt

Inc-6 notes, kept: the painted text frames of the
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
    fx_project,
    load_change_file,
    open_flow_execution,
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


async def execution_frame(size):
    app = S19TuiApp(base_dir=Path(tempfile.mkdtemp()))
    async with app.run_test(size=size) as pilot:
        await settle(pilot)
        fx_project(app)
        await open_flow_execution(app, pilot)
        await settle(pilot, 6)
        return normalise(painted_rows(app, app.query_one("#screen_flow_execution")))


SIZES = [tuple(int(v) for v in arg.split("x")) for arg in sys.argv[2:]] or [(118, 54), (220, 60)]


async def main():
    frames = (
        ("check-editor", check_frame), ("patch-editor", patch_frame),
        ("flow-builder", builder_frame), ("flow-execution", execution_frame),
    )
    for name, fn in frames:
        for index, size in enumerate(SIZES):
            print(f"===== {name} size#{index}")
            print(await fn(size), flush=True)


asyncio.run(main())
