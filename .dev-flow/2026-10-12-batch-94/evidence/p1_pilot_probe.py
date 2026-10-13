# P1 pilot measurement for 2026-10-12-batch-94 -- the C-23/C-29 two-axis
# geometry budget of the app chrome and the boxed surfaces this batch
# reworks or creates. Throwaway evidence tooling; not part of the suite.
# Chrome is measured by proxy (no file loaded): the rail width is the
# workspace's left edge, the top chrome is the workspace's top edge, the
# footer is the Footer widget's height.
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from s19_app.tui.app import S19TuiApp


async def one(size):
    app = S19TuiApp()
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        await pilot.pause()
        w, h = size
        print(f"=== {w}x{h}")
        ws = app.query_one("#screen_workspace")
        print(f"  screen {w}x{h}: workspace region={ws.region}")
        rail_w = ws.region.x
        top = ws.region.y
        foot = app.query("Footer")
        foot_h = foot.first().region.height if foot else -1
        print(f"  chrome    : rail_width={rail_w}  top={top}  footer_h={foot_h}")
        for sid, key in (("#screen_patch", "6"), ("#screen_flow", "8"),
                         ("#screen_checks", "9")):
            await pilot.press(key)
            for _ in range(3):
                await pilot.pause()
            try:
                el = app.query_one(sid)
            except Exception as exc:  # noqa: BLE001 - probe resilience
                print(f"  {sid:<14}: MISSING ({exc})")
                continue
            r, c = el.region, el.content_region
            print(f"  {sid:<14}: region={r}  content={c.width}x{c.height}")
        # the two-regime breakpoint: which regime are we in?
        regime = "fixed" if w >= 120 else "icon"
        print(f"  regime    : {regime} (breakpoint 120)")


for size in [(80, 24), (120, 30), (160, 40)]:
    asyncio.run(one(size))
