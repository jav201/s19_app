"""X9 probe (scratch only): 82_1's scenario with the one-key-at-a-time typist; per key (sent offset, latency) and the
duration of each UI-thread step of the record stage."""
import json
import threading
import time

import tests.test_b103_inc9_w_jobs as J
from tests.test_b103_inc9_w_jobs import LARGE, LARGE_COUNT, big_case, defc_dir, entries_of, large_with_selection, previewed, run, sheet_of, wait_for  # noqa: F401


def test_probe82(tmp_path, defc_dir):
    a2l, s19 = big_case(tmp_path, LARGE_COUNT, rows=(LARGE,))

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await large_with_selection(pilot, sheet)
        await wait_for(pilot, lambda: previewed(sheet), "the preview result", 240)
        steps, sent, handled, t0 = [], [], [], time.perf_counter()

        def timed(obj, name):
            real = getattr(obj, name)

            def wrap(*a, **k):
                t = time.perf_counter(); r = real(*a, **k); steps.append((name, round(t - t0, 3), round(time.perf_counter() - t, 3))); return r
            setattr(obj, name, wrap)

        for obj, name in ((sheet, "_job_done"), (sheet, "set_document"), (sheet, "record_staged"), (sheet, "record_done"),
                          (app._change_service, "stage_record"), (app, "_refresh_patch_history_view"), (app, "_report_change_result")):
            timed(obj, name)
        real_move = sheet.action_move

        def move(*a):
            real_move(*a); handled.append(time.perf_counter())
        sheet.action_move = move
        stop = threading.Event()
        th = threading.Thread(target=J._typist, args=(app._driver, "down", sent, handled, stop), daemon=True)
        await pilot.press("alt+s")
        t0 = time.perf_counter()
        th.start()
        end = time.monotonic() + 180
        while len(entries_of(app)) != 1 and time.monotonic() < end:
            await pilot.pause(0.05)
        written = time.perf_counter() - t0
        stop.set(); th.join()
        for _ in range(200):
            if len(handled) >= len(sent):
                break
            await pilot.pause(0.05)
        print("X9PROBE82 " + json.dumps({"written": round(written, 3), "keys": [(round(s - t0, 3), round(h - s, 3)) for s, h in zip(sent, handled)],
                                         "steps": [s for s in steps if s[2] > 0.02 or s[0] in ("_job_done", "stage_record")]}))

    run(tmp_path, defc_dir, body, a2l=a2l, image=s19)
