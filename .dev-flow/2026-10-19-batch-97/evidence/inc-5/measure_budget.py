"""PC-24 / design §3 Builder budget, measured on the real tree (decision B).

For the 4-block ``patch_chain`` and the EXT-STEP ``flash_chain`` (with the
EXT-STEP form open), at 118x54, 118x53, 220x60 and 220x59: the panel height H,
the ribbon / palette / add / clip / run / legend rows, the pipeline frame
height and its card height, the result area's rows, and Run's position.
Run from the repo root:  python .dev-flow/2026-10-19-batch-97/evidence/inc-5/measure_budget.py
"""
import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path.cwd()))

from s19_app.tui.app import S19TuiApp  # noqa: E402
from tests.b97_fixtures import flow_project, load_flow, open_flow_builder  # noqa: E402
from tests.b97_probes import settle, settled  # noqa: E402


async def measure(size, stem, ext):
    app = S19TuiApp(base_dir=Path(tempfile.mkdtemp()))
    async with app.run_test(size=size) as pilot:
        await settle(pilot)
        flow_project(app)
        panel = await open_flow_builder(app, pilot)
        await load_flow(app, pilot, stem)
        if ext:
            panel.query_one("#flow_palette_external_step").press()
            await settled(pilot, lambda: panel.query_one("#flow_ext_log").region.height > 0, "ext form")
        await settle(pilot, 6)
        row = lambda wid: panel.query_one(wid).region.height  # noqa: E731
        scroll = panel.query_one("#flow_pipeline_scroll")
        run = panel.query_one("#flow_run").region
        return {
            "H": panel.region.height,
            "ribbon": row("#flow_ribbon"),
            "palette": row("#flow_palette"),
            "add": row("#flow_add_row"),
            "clip": row("#flow_clip_row"),
            "run": row("#flow_run_row"),
            "legend": row("#flow_legend"),
            "frame": scroll.region.height,
            "cards": row("#flow_pipeline"),
            "scrolls": scroll.max_scroll_x > 0,
            "result": row("#flow_result"),
            "run_inside": panel.region.contains_region(run),
        }


async def main():
    for stem, ext in (("patch_chain", False), ("flash_chain", True)):
        for size in ((118, 54), (118, 53), (220, 60), (220, 59)):
            print(f"{stem:12s} ext_form={ext!s:5s} {size[0]}x{size[1]}: {await measure(size, stem, ext)}", flush=True)


asyncio.run(main())
