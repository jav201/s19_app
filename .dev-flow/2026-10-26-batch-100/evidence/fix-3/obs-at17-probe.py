"""Probe (fix round 3, not a test of record): when does pilot.press("enter") return in AT-B100-17 parse half?"""
import re
import time

from tests.test_b100_workers import (
    CASE06, FRAMES, ld, neutral_focus, painted_log, run, status, wait, bar,
)


def test_probe_at17(tmp_path):
    base = tmp_path / "app"
    step2 = re.compile(r"^[" + FRAMES + r"] Loading firmware\.a2l  ·  step 2/3 Parse  ·  (\d\d:\d\d)$")
    t0 = time.monotonic()
    ev = []
    seen = []

    def mark(what):
        ev.append((round(time.monotonic() - t0, 3), what))

    async def scenario(app, pilot, log):
        orig_step = app.step_busy

        def step(key, gen, n, done=None, total=None, *a, **k):
            if done is None or done == total or not seen:
                if done is not None:
                    seen.append(done)
                mark(f"step_busy {key} n={n} done={done} total={total}")
            return orig_step(key, gen, n, done, total, *a, **k)

        app.step_busy = step
        neutral_focus(app)
        await pilot.press("l")
        await ld.wait_for_dialog(pilot, app)
        await ld.type_into_path(pilot, app, str(CASE06 / "firmware.a2l"))
        mark("enter: pressing")
        await pilot.press("enter")
        mark(f"enter: returned; status={status(app)[:60]!r} bar={bar(app)}")
        await wait(pilot, lambda: painted_log(app)[-1] == "A2L loaded: firmware.a2l", "the attach to end", 300)
        mark("attach ended")

    run(base, scenario)
    for e in ev:
        print(e)
