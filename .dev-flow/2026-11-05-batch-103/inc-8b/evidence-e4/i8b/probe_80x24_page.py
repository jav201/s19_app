import pytest
from tests.test_b103_inc8b_at import defc, run, focus_filter_and_type, need, BODY, GRID, SIZE_80, row_names, plain  # noqa: F401


def test_probe80(tmp_path, defc):
    async def body(app, pilot, panel):
        await focus_filter_and_type(pilot, panel, "_0001")
        for _ in range(100):
            await pilot.pause(0.02)
        b = need(panel, BODY)
        g = need(panel, GRID)
        print("BODY region", b.region, "content", b.content_size, "GRID region", g.region, g.scrollable_content_region)
        print("ROWS", row_names(panel, defc["names"]))
        for line in plain(b).splitlines():
            print("L|" + line[:100])
        return True
    run(tmp_path, defc, body, size=SIZE_80)
