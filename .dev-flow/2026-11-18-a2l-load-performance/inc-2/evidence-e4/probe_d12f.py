"""D-12 probe 6: replicate the NEW .034[case06] window assertion exactly.
Prints: window gaps (asserted) vs preserved-refresh gaps (recorded).
Run: /c/Users/<user>/anaconda3/envs/s19env/python.exe -B probe_d12f.py
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))

from s19_app.tui.app import S19TuiApp
from tests.test_alp_inc2_a2l_attach import (
    CASE06,
    Sampler,
    _focus_key_pair,
    _is_busy_progress,
    _log_lines,
    _run,
)
from tests.support.timing import timing_bound


def main() -> None:
    tmp = ROOT / ".dev-flow" / "2026-11-18-a2l-load-performance" / "inc-2" / "evidence-e4" / "probe-tmp"
    base = tmp / "app"
    bound = timing_bound(1.0)

    async def body(app, pilot):
        app.set_focus(app.query_one("#files_list"))
        await pilot.pause()
        sampler = Sampler()
        task = sampler.start(pilot, app, bar=True)
        await pilot.pause(0.1)
        refresh_entry: list = []
        real_refresh = app._refresh_a2l_dependent_views

        def refresh_spy():
            refresh_entry.append(time.monotonic())
            return real_refresh()

        app._refresh_a2l_dependent_views = refresh_spy
        deadline = time.monotonic() + 300
        app.load_a2l_from_path(CASE06)
        keys = await _focus_key_pair(pilot, app, bound=bound)
        while True:
            if (
                app.current_a2l_path is not None
                and Path(app.current_a2l_path).name == "firmware.a2l"
                and "a2l_load" not in app._busy.runs
            ):
                break
            if time.monotonic() > deadline:
                raise AssertionError("terminal outcome never reached")
            await pilot.pause(0.05)
        sampler.stop.set()
        await task
        changes = sampler.text_changes()
        times = [t for t, _ in changes]
        gaps = [b - a for a, b in zip(times, times[1:])]
        t0_abs = sampler.frames[0][0]
        refresh_rel = refresh_entry[0] - t0_abs
        window_gaps = [g for (a, b), g in zip(zip(times, times[1:]), gaps) if b <= refresh_rel]
        out = ROOT / ".dev-flow" / "2026-11-18-a2l-load-performance" / "inc-2" / "evidence-e4" / "probe-d12f.txt"
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(f"key latencies: {keys}\n")
            fh.write(f"refresh_rel: {refresh_rel:.2f}s, total gaps: {len(gaps)}\n")
            fh.write(f"window gaps (asserted <=1.0): {window_gaps}\n")
            fh.write(f"window gaps max: {max(window_gaps) if window_gaps else None}\n")
            fh.write(f"recorded (unasserted) gaps: {[g for g in gaps if g > 1.0 and g not in window_gaps]}\n")
            fh.write(f"log: {_log_lines(app)}\n")
        print("PROBE6 OK")

    _run(base, body)


if __name__ == "__main__":
    main()
