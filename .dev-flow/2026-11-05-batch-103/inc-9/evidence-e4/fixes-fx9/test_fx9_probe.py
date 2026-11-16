"""FX9 diagnosis probe for F-MW9-2 (scratch only, not a product test).

PROBE env var picks the variant:
  base  - the product as is (29_2's scenario: LARGE, Set 7 on 4,096 cells, `right` until the preview result)
  swi   - same, sys.setswitchinterval(0.0005) during the presses
  sleep - the worker's encode_values first sleeps 12 s (GIL released), then runs the real encode
  spin  - the worker's encode_values first spins 12 s in pure Python (GIL held in bytecode), then the real encode
Per press: start offset (s) from the apply, duration (s), the worker phase at the start, and the number of
event-loop selector calls during the press (each call releases and re-acquires the GIL).
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import time

from s19_app.tui.screens_directionb.patch_editor import bench_sheet as bs
from tests.support.b103_inc9_w import (  # noqa: F401
    LARGE_COUNT, apply_tool, big_case, defc_dir, open_bench, run, sheet_of, st,
)

LARGE = "LARGE"
PHASE = {"v": "idle"}


def previewed(sheet) -> bool:
    preview = st(sheet, LARGE).preview
    return preview is not None and not isinstance(preview, str)


def test_probe(tmp_path, defc_dir, monkeypatch):
    variant = os.environ.get("PROBE", "base")
    original = bs.encode_values

    def stub(*args, **kwargs):
        if variant == "sleep":
            PHASE["v"] = "sleep"
            time.sleep(12)
        elif variant == "spin":
            PHASE["v"] = "spin"
            end, x = time.monotonic() + 12, 0
            while time.monotonic() < end:
                x += 1
        PHASE["v"] = "encode"
        try:
            return original(*args, **kwargs)
        finally:
            PHASE["v"] = "done"

    monkeypatch.setattr(bs, "encode_values", stub)
    a2l, s19 = big_case(tmp_path, LARGE_COUNT, rows=(LARGE,))

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await open_bench(pilot, sheet, LARGE)
        await pilot.press(*(["shift+right"] * 15 + ["shift+down"] * 255))
        selector = asyncio.get_running_loop()._selector
        real_select, count = selector.select, [0]

        def counting(timeout=None):
            count[0] += 1
            return real_select(timeout)

        selector.select = counting
        old = sys.getswitchinterval()
        if variant == "swi":
            sys.setswitchinterval(0.0005)
        try:
            t0 = time.perf_counter()
            await apply_tool(pilot, sheet, "s", "7")
            apply_s = time.perf_counter() - t0
            rows, end = [], time.monotonic() + 240
            while not previewed(sheet) and time.monotonic() < end:
                phase, c0, s = PHASE["v"], count[0], time.perf_counter()
                await pilot.press("right")
                rows.append((round(s - t0, 3), round(time.perf_counter() - s, 3), phase, count[0] - c0))
            after = []
            for _ in range(3):
                c0, s = count[0], time.perf_counter()
                await pilot.press("right")
                after.append((round(time.perf_counter() - s, 3), count[0] - c0))
            return apply_s, rows, after
        finally:
            sys.setswitchinterval(old)
            selector.select = real_select

    apply_s, rows, after = run(tmp_path, defc_dir, body, a2l=a2l, image=s19)
    print("PROBE", variant, "load", " ".join(f"{x:.2f}" for x in os.getloadavg()))
    print("APPLY_S", round(apply_s, 3))
    for row in rows:
        print("PRESS", json.dumps(row))
    for row in after:
        print("AFTER", json.dumps(row))
