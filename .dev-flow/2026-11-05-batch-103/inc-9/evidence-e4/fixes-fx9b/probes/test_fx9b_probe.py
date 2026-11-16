"""FX9b probe (scratch only, never committed to tests/): where the UI thread spends its time in 82_1 / 29_2.

probe_record: 82_1's scenario; cProfile of the UI-thread record stage (``_stage_bench_record``), plus per-key
(sent, wait = send -> action start, action = action start -> end) with the one-key typist.
probe_arrival: 29_2's scenario; per key the same split, the preview arrival time, and every ``_paint`` duration.
"""
import cProfile
import io
import json
import pstats
import threading
import time

import tests.test_b103_inc9_w_jobs as J
from tests.test_b103_inc9_w_jobs import LARGE, LARGE_COUNT, apply_tool, big_case, defc_dir, entries_of, large_with_selection, open_bench, previewed, run, sheet_of, wait_for  # noqa: F401


def _split_keys(sheet, action, t0):
    real = getattr(sheet, action)
    starts, ends = [], []

    def timed(*a):
        starts.append(time.perf_counter())
        real(*a)
        ends.append(time.perf_counter())
    setattr(sheet, action, timed)
    return starts, ends


def _typed(app, key, starts, ends, stop):
    sent = []
    th = threading.Thread(target=J._typist, args=(app._driver, key, sent, ends, stop), daemon=True)
    return sent, th


def _keys(sent, starts, ends, t0):
    return [(round(s - t0, 3), round(a - s, 3), round(e - a, 3)) for s, a, e in zip(sent, starts, ends)]


def _paints(sheet, t0, log):
    real = sheet._paint

    def wrap():
        t = time.perf_counter(); real(); log.append((round(t - t0, 3), round(time.perf_counter() - t, 3)))
    sheet._paint = wrap


def test_probe_record(tmp_path, defc_dir):
    a2l, s19 = big_case(tmp_path, LARGE_COUNT, rows=(LARGE,))

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await large_with_selection(pilot, sheet)
        await wait_for(pilot, lambda: previewed(sheet), "the preview result", 240)
        t0 = time.perf_counter()
        prof, steps = cProfile.Profile(), []
        real_stage = app._stage_bench_record

        def stage(*a):
            t = time.perf_counter(); prof.enable()
            try:
                return real_stage(*a)
            finally:
                prof.disable(); steps.append(("_stage_bench_record", round(t - t0, 3), round(time.perf_counter() - t, 3)))
        app._stage_bench_record = stage
        paints = []
        _paints(sheet, t0, paints)
        starts, ends = _split_keys(sheet, "action_move", t0)
        stop = threading.Event()
        sent, th = _typed(app, "down", starts, ends, stop)
        await pilot.press("alt+s")
        t0 = time.perf_counter()
        th.start()
        end = time.monotonic() + 180
        while len(entries_of(app)) != 1 and time.monotonic() < end:
            await pilot.pause(0.05)
        stop.set(); th.join()
        for _ in range(200):
            if len(ends) >= len(sent):
                break
            await pilot.pause(0.05)
        out = io.StringIO()
        pstats.Stats(prof, stream=out).sort_stats("cumulative").print_stats(45)
        print("FX9BREC " + json.dumps({"keys_over_0.3": [k for k in _keys(sent, starts, ends, t0) if k[1] + k[2] > 0.3],
                                       "n_keys": len(sent), "steps": steps,
                                       "paints_over_0.1": [p for p in paints if p[1] > 0.1]}))
        print("FX9BPROF\n" + out.getvalue())

    run(tmp_path, defc_dir, body, a2l=a2l, image=s19)


def test_probe_arrival(tmp_path, defc_dir):
    a2l, s19 = big_case(tmp_path, LARGE_COUNT, rows=(LARGE,))

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await open_bench(pilot, sheet, LARGE)
        await pilot.press(*(["shift+right"] * 15 + ["shift+down"] * 255))
        t0 = time.perf_counter()
        paints, arrivals = [], []
        real_done = sheet._job_done

        def done(*a):
            t = time.perf_counter(); real_done(*a); arrivals.append((a[0], round(t - t0, 3), round(time.perf_counter() - t, 3)))
        sheet._job_done = done
        _paints(sheet, t0, paints)
        starts, ends = _split_keys(sheet, "action_choose", t0)
        await apply_tool(pilot, sheet, "s", "7")
        stop = threading.Event()
        sent, th = _typed(app, "right", starts, ends, stop)
        t0 = time.perf_counter()
        th.start()
        end = time.monotonic() + 180
        while not previewed(sheet) and time.monotonic() < end:
            await pilot.pause(0.05)
        stop.set(); th.join()
        for _ in range(200):
            if len(ends) >= len(sent):
                break
            await pilot.pause(0.05)
        keys = _keys(sent, starts, ends, t0)
        print("FX9BARR " + json.dumps({"n_keys": len(sent), "max": max((k[1] + k[2] for k in keys), default=None),
                                       "keys_over_0.25": [k for k in keys if k[1] + k[2] > 0.25],
                                       "action_s": sorted(k[2] for k in keys)[-5:], "wait_s": sorted(k[1] for k in keys)[-5:],
                                       "arrivals": arrivals, "paints_over_0.1": [p for p in paints if p[1] > 0.1],
                                       "paint_median": sorted(p[1] for p in paints)[len(paints) // 2] if paints else None}))

    run(tmp_path, defc_dir, body, a2l=a2l, image=s19)
