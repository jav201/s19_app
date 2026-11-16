"""FX9 diagnosis probe 2 for F-MW9-2 (scratch only): where does a `right` press spend its time while LARGE's
preview encode runs?  Per press, from the moment the key event is sent to the app (driver.send_message):
  handle_s - until the sheet's action_choose returned (the key handled: cursor moved, sheet repainted)
  frame_s  - until the first frame the app displayed after that
  press_s  - what `pilot.press` took (the instrument of 29_1 / 29_2 / 82_1)
PROBE=base | spin (the worker spins 12 s in pure Python before the real encode) |
      stall (control: action_choose sleeps 0.8 s ON THE UI THREAD, the defect the requirement guards)
"""
from __future__ import annotations

import json
import os
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


def test_probe2(tmp_path, defc_dir, monkeypatch):
    variant = os.environ.get("PROBE", "base")
    original = bs.encode_values

    def stub(*args, **kwargs):
        if variant == "spin":
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
        marks = {"send": None, "handled": None, "frame": None}
        driver = app._driver
        real_send, real_choose, real_display = driver.send_message, sheet.action_choose, app._display

        def send(message):
            if getattr(message, "key", None) == "right":
                marks["send"], marks["handled"], marks["frame"] = time.perf_counter(), None, None
            return real_send(message)

        def choose(delta):
            if variant == "stall":
                time.sleep(0.8)
            real_choose(delta)
            marks["handled"] = time.perf_counter()

        def display(screen, renderable):
            real_display(screen, renderable)
            if marks["handled"] is not None and marks["frame"] is None:
                marks["frame"] = time.perf_counter()

        driver.send_message, sheet.action_choose, app._display = send, choose, display
        try:
            t0 = time.perf_counter()
            await apply_tool(pilot, sheet, "s", "7")
            rows, end = [], time.monotonic() + 240
            while not previewed(sheet) and time.monotonic() < end:
                phase, s = PHASE["v"], time.perf_counter()
                await pilot.press("right")
                press = time.perf_counter() - s
                await pilot.pause(0.05)
                sent = marks["send"]
                handled = None if marks["handled"] is None else round(marks["handled"] - sent, 4)
                frame = None if marks["frame"] is None else round(marks["frame"] - sent, 4)
                rows.append({"t": round(s - t0, 2), "phase": phase, "handle_s": handled, "frame_s": frame,
                             "press_s": round(press, 3)})
                if variant == "stall" and len(rows) >= 4:
                    break
            return rows
        finally:
            driver.send_message, sheet.action_choose, app._display = real_send, real_choose, real_display

    rows = run(tmp_path, defc_dir, body, a2l=a2l, image=s19)
    print("PROBE2", variant, "load", " ".join(f"{x:.2f}" for x in os.getloadavg()))
    for row in rows:
        print("PRESS", json.dumps(row))
