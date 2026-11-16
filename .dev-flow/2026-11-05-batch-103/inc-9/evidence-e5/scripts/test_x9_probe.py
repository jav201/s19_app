"""X9 probe (scratch only, never in the repo): 29_2's scenario, keys from a thread every `interval` s; prints per key
(sent offset, latency), each _job_done (kind, offset, duration) and each _paint longer than 50 ms."""
import json
import threading
import time

import pytest

import tests.test_b103_inc9_w_jobs as J
from tests.test_b103_inc9_w_jobs import LARGE, LARGE_COUNT, apply_tool, big_case, defc_dir, open_bench, previewed, run, sheet_of  # noqa: F401


@pytest.mark.parametrize("interval", [0.1, 0.5])
def test_probe(tmp_path, defc_dir, interval):
    a2l, s19 = big_case(tmp_path, LARGE_COUNT, rows=(LARGE,))

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await open_bench(pilot, sheet, LARGE)
        await pilot.press(*(["shift+right"] * 15 + ["shift+down"] * 255))
        await apply_tool(pilot, sheet, "s", "7")
        jd, pt, sent, handled = [], [], [], []
        real_done, real_paint, real_choose = sheet._job_done, sheet._paint, sheet.action_choose

        def done_wrap(*a):
            t = time.perf_counter(); real_done(*a); jd.append((a[0], t, time.perf_counter() - t))

        def paint_wrap():
            t = time.perf_counter(); real_paint(); d = time.perf_counter() - t
            if d > 0.05:
                pt.append((t, d))

        def choose_wrap(*a):
            real_choose(*a); handled.append(time.perf_counter())

        sheet._job_done, sheet._paint, sheet.action_choose = done_wrap, paint_wrap, choose_wrap
        stop = threading.Event()

        def typist():
            while not stop.is_set():
                sent.append(time.perf_counter()); app._driver.send_message(J.events.Key("right", None)); stop.wait(interval)

        t0 = time.perf_counter()
        th = threading.Thread(target=typist, daemon=True); th.start()
        end = time.monotonic() + 180
        while not previewed(sheet) and time.monotonic() < end:
            await pilot.pause(0.05)
        await pilot.pause(1.0)
        stop.set(); th.join()
        for _ in range(200):
            if len(handled) >= len(sent):
                break
            await pilot.pause(0.05)
        out = {"interval": interval, "keys": [(round(s - t0, 3), round(h - s, 3)) for s, h in zip(sent, handled)],
               "n_sent": len(sent), "n_handled": len(handled),
               "job_done": [(k, round(t - t0, 3), round(d, 3)) for k, t, d in jd],
               "slow_paints": [(round(t - t0, 3), round(d, 3)) for t, d in pt]}
        print("X9PROBE " + json.dumps(out))
        return out

    run(tmp_path, defc_dir, body, a2l=a2l, image=s19)
