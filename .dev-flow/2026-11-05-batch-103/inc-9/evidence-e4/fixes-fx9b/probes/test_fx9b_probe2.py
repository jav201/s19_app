"""FX9b probe 2 (scratch only): wall-clock parts of the UI-thread record stage (no profiler), and a what-if of
``sys.setswitchinterval`` (env FX9B_SWI, seconds) on the key wait while a worker computes."""
import json
import os
import sys
import threading
import time

import s19_app.tui.app.patch as app_patch
import s19_app.tui.definition_bench as db
import s19_app.tui.definition_sheet as ds
import tests.test_b103_inc9_w_jobs as J
from tests.test_b103_inc9_w_jobs import LARGE, LARGE_COUNT, apply_tool, big_case, defc_dir, entries_of, large_with_selection, open_bench, previewed, run, sheet_of, wait_for  # noqa: F401
from tests.test_fx9b_probe import _keys, _split_keys, _typed

SWI = float(os.environ.get("FX9B_SWI", "0") or 0)


def _swi():
    old = sys.getswitchinterval()
    if SWI:
        sys.setswitchinterval(SWI)
    return old


def _timer(log, t0ref):
    def wrap_attr(obj, name, label=None):
        real = getattr(obj, name)

        def w(*a, **k):
            t = time.perf_counter()
            try:
                return real(*a, **k)
            finally:
                log.append((label or name, round(t - t0ref[0], 3), round(time.perf_counter() - t, 3)))
        setattr(obj, name, w)
    return wrap_attr


def test_probe_parts(tmp_path, defc_dir):
    a2l, s19 = big_case(tmp_path, LARGE_COUNT, rows=(LARGE,))
    old = _swi()

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await large_with_selection(pilot, sheet)
        await wait_for(pilot, lambda: previewed(sheet), "the preview result", 240)
        t0, log = [time.perf_counter()], []
        w = _timer(log, t0)
        w(app, "_stage_bench_record"); w(app, "_refresh_patch_history_view"); w(panel, "_show_document")
        w(panel, "_render_before_after_card"); w(sheet, "set_document"); w(sheet, "_paint")
        w(app._change_service, "stage_record"); w(app_patch, "serialize_change_document")
        w(db, "_max_staged_delta"); w(ds, "_staged_by_bytes"); w(ds, "build_row")
        w(panel.query_one("#patch_json_view"), "find_matching_bracket"); w(panel.query_one("#patch_json_view"), "load_text")
        starts, ends = _split_keys(sheet, "action_move", t0)
        stop = threading.Event()
        sent, th = _typed(app, "down", starts, ends, stop)
        await pilot.press("alt+s")
        t0[0] = time.perf_counter()
        th.start()
        end = time.monotonic() + 180
        while len(entries_of(app)) != 1 and time.monotonic() < end:
            await pilot.pause(0.05)
        stop.set(); th.join()
        for _ in range(200):
            if len(ends) >= len(sent):
                break
            await pilot.pause(0.05)
        keys = _keys(sent, starts, ends, t0[0])
        print("FX9BPARTS " + json.dumps({"swi": SWI, "n_keys": len(keys), "max": max(k[1] + k[2] for k in keys),
                                         "keys_over_0.3": [k for k in keys if k[1] + k[2] > 0.3],
                                         "parts": [p for p in log if p[0] != "_paint" or p[2] > 0.05]}))

    try:
        run(tmp_path, defc_dir, body, a2l=a2l, image=s19)
    finally:
        sys.setswitchinterval(old)


def test_probe_arrival_swi(tmp_path, defc_dir):
    a2l, s19 = big_case(tmp_path, LARGE_COUNT, rows=(LARGE,))
    old = _swi()

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await open_bench(pilot, sheet, LARGE)
        await pilot.press(*(["shift+right"] * 15 + ["shift+down"] * 255))
        t0 = time.perf_counter()
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
        tot = sorted(k[1] + k[2] for k in keys)
        print("FX9BSWI " + json.dumps({"swi": SWI, "n_keys": len(keys), "encode_s": round(time.perf_counter() - t0, 1),
                                       "max": tot[-1], "p50": tot[len(tot) // 2], "top5": tot[-5:],
                                       "wait_top5": sorted(k[1] for k in keys)[-5:], "action_top5": sorted(k[2] for k in keys)[-5:]}))

    try:
        run(tmp_path, defc_dir, body, a2l=a2l, image=s19)
    finally:
        sys.setswitchinterval(old)
