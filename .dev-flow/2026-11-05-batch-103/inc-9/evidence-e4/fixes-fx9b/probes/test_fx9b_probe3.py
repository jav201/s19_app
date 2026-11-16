"""FX9b probe 3 (scratch only): 29_2's typist against (a) a worker spinning pure Python for 12 s before the real
encode (GIL preemptible every switch interval), (b) the real encode, (c) an idle worker for 5 s after the arrival."""
import json
import threading
import time

import s19_app.tui.screens_directionb.patch_editor.bench_sheet as bs
from tests.test_b103_inc9_w_jobs import LARGE, LARGE_COUNT, apply_tool, big_case, defc_dir, open_bench, previewed, run, sheet_of  # noqa: F401
from tests.test_fx9b_probe import _keys, _split_keys, _typed

SPIN_S = 12.0


def _summary(keys, lo, hi):
    tot = sorted(k[1] + k[2] for k in keys if lo <= k[0] < hi)
    wait = sorted(k[1] for k in keys if lo <= k[0] < hi)
    if not tot:
        return None
    return {"n": len(tot), "p50": tot[len(tot) // 2], "max": tot[-1], "wait_p50": wait[len(wait) // 2], "wait_max": wait[-1]}


def test_probe_phases(tmp_path, defc_dir, monkeypatch):
    a2l, s19 = big_case(tmp_path, LARGE_COUNT, rows=(LARGE,))
    real_encode = bs.encode_values
    marks = {}

    def spin_then_encode(*a, **k):
        marks["spin0"] = time.perf_counter()
        end = marks["spin0"] + SPIN_S
        x = 0
        while time.perf_counter() < end:
            for i in range(1000):
                x += i
        marks["enc0"] = time.perf_counter()
        return real_encode(*a, **k)
    monkeypatch.setattr(bs, "encode_values", spin_then_encode)

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
        end = time.monotonic() + 240
        while not previewed(sheet) and time.monotonic() < end:
            await pilot.pause(0.05)
        arrived = time.perf_counter() - t0
        await pilot.pause(5.0)
        stop.set(); th.join()
        for _ in range(200):
            if len(ends) >= len(sent):
                break
            await pilot.pause(0.05)
        keys = _keys(sent, starts, ends, t0)
        spin0, enc0 = marks["spin0"] - t0, marks["enc0"] - t0
        print("FX9BPHASES " + json.dumps({"spin": _summary(keys, spin0 + 0.5, enc0), "encode": _summary(keys, enc0, arrived),
                                          "idle": _summary(keys, arrived + 0.5, 1e9),
                                          "spin0": round(spin0, 2), "enc0": round(enc0, 2), "arrived": round(arrived, 2)}))

    run(tmp_path, defc_dir, body, a2l=a2l, image=s19)
