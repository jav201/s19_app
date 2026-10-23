"""Inc-6 vertical budget (design §3 Flow Execution table; PC-24): the panel
height H, the fixed rows, the log, the lanes frame and its viewport, the card
height and the empty rows under the last lane, measured on the real tree at
118x54, 118x53, 220x60 and 220x59 — before a run and after the paused 3-lane
run; plus the viewport width the D24 readings use (4 and 6 blocks).

Usage: python measure_budget.py <tree root>
"""
import asyncio
import sys
import tempfile
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(ROOT))

from s19_app.tui import flow_screens as fs  # noqa: E402
from s19_app.tui.app import S19TuiApp  # noqa: E402
from tests.b97_fixtures import fx_project, import_lanes, run_lanes  # noqa: E402
from tests.b97_probes import settle  # noqa: E402


async def measure(size, stems, run):
    app = S19TuiApp(base_dir=Path(tempfile.mkdtemp()))
    async with app.run_test(size=size) as pilot:
        await settle(pilot)
        fx_project(app)
        panel = await import_lanes(app, pilot, *stems)
        if run:
            await run_lanes(app, pilot, panel, key=True)
        await settle(pilot, 8)
        scroll = panel.query_one("#fx_lanes_scroll")
        view = scroll.scrollable_content_region
        lanes = [panel.query_one(f"#fx_lane_{i}") for i in range(len(stems))]
        content = lanes[-1].region.bottom - lanes[0].region.y + int(scroll.scroll_y)
        log = panel.query_one("#fx_log").region.height
        req = panel.query_one("#fx_required").region.height if panel.query_one("#fx_required").display else 0
        card_h = panel.query_one("#fx_card_0_0").region.height
        n_max = max(len(lane.flow.blocks) for lane in panel._lanes)
        print(
            f"{size[0]}x{size[1]} stems={len(stems)} run={run}: H={panel.region.height} W={panel.region.width} "
            f"frame={scroll.region.height} viewport={view.width}x{view.height} log={log} required={req} "
            f"card_h={card_h} lane_rows={card_h + 1} content={content} empty_under_last={view.height - content} "
            f"max_scroll=({scroll.max_scroll_x},{scroll.max_scroll_y}) lane_layout={tuple(fs.lane_layout(view.width, n_max))}",
            flush=True,
        )


async def main():
    for size in ((118, 54), (118, 53), (220, 60), (220, 59)):
        await measure(size, ("patch_chain", "flash_chain", "err_chain"), False)
        await measure(size, ("patch_chain", "flash_chain", "err_chain"), True)
        await measure(size, ("six_ok_a", "six_ok_b", "six_wait"), True)


asyncio.run(main())
