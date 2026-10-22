"""F5: the 4-block patch_chain rail across 118..134 columns at height 54 —
the rail's scrollable content width, the card width and whether the cards
scroll sideways (the 120-133 degraded band, LED-...97.13).
Run from the repo root: python .dev-flow/2026-10-19-batch-97/evidence/inc-5/measure_band.py
"""
import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path.cwd()))

from s19_app.tui.app import S19TuiApp  # noqa: E402
from tests.b97_fixtures import flow_project, load_flow, open_flow_builder  # noqa: E402
from tests.b97_probes import settle  # noqa: E402


async def measure(cols):
    app = S19TuiApp(base_dir=Path(tempfile.mkdtemp()))
    async with app.run_test(size=(cols, 54)) as pilot:
        await settle(pilot)
        flow_project(app)
        panel = await open_flow_builder(app, pilot)
        await load_flow(app, pilot, "patch_chain")
        await settle(pilot, 8)
        scroll = panel.query_one("#flow_pipeline_scroll")
        return scroll.scrollable_content_region.width, panel._card_w, scroll.max_scroll_x


async def main():
    for cols in range(118, 135):
        rail, card, sx = await measure(cols)
        print(f"{cols}x54 rail={rail} card_w={card} max_scroll_x={sx} scrolls={sx > 0}", flush=True)


asyncio.run(main())
