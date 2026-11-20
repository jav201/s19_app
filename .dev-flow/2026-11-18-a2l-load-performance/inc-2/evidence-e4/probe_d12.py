"""D-12 ground-truth probe: where do the >1.0s sampler gaps fall relative to
worker completion, install and the preserved common refresh?

Run: /c/Users/<user>/anaconda3/envs/s19env/python.exe -m probe_d12  (from repo root)
Writes: probe-d12.txt (timeline markers + gap positions).
"""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]  # repo root (evidence-e4 probe)
sys.path.insert(0, str(ROOT))

import asyncio

from s19_app.tui.app import S19TuiApp
from tests.support.b100_workers import settle_workers
from tests.test_alp_inc2_a2l_attach import (
    CASE06,
    SIZE,
    Sampler,
    _focus_key_pair,
    _log_lines,
    _run,
)
from tests.support.timing import timing_bound

def main() -> None:
    tmp = ROOT / ".dev-flow" / "2026-11-18-a2l-load-performance" / "inc-2" / "evidence-e4" / "probe-tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    base = tmp / "app"
    bound = timing_bound(1.0)
    markers: list = []

    async def body(app, pilot):
        app.set_focus(app.query_one("#files_list"))
        await pilot.pause()

        def mark(name):
            markers.append((name, time.monotonic()))

        real_worker = app._a2l_attach_worker
        real_install = app._install_attached_a2l
        real_refresh = app._refresh_a2l_dependent_views
        real_attached = app._on_a2l_attached

        def worker(request):
            mark("worker-start")
            try:
                return real_worker(request)
            finally:
                mark("worker-end")

        def attached(result):
            mark("on-attached")
            return real_attached(result)

        def install(result):
            mark("install-start")
            try:
                return real_install(result)
            finally:
                mark("install-end")

        def refresh():
            mark("refresh-start")
            try:
                return real_refresh()
            finally:
                mark("refresh-end")

        app._a2l_attach_worker = worker
        app._install_attached_a2l = install
        app._refresh_a2l_dependent_views = refresh
        app._on_a2l_attached = attached

        sampler = Sampler()
        task = sampler.start(pilot, app, bar=True)
        await pilot.pause(0.1)
        mark("load-call")
        app.load_a2l_from_path(CASE06)
        mark("load-return")
        keys = await _focus_key_pair(pilot, app, bound=bound)
        mark("keys-ack")
        deadline = time.monotonic() + 300
        while True:
            if (
                app.current_a2l_path is not None
                and Path(app.current_a2l_path).name == "firmware.a2l"
                and "a2l_load" not in app._busy.runs
            ):
                break
            if time.monotonic() > deadline:
                raise AssertionError("never reached terminal outcome")
            await pilot.pause(0.05)
        mark("terminal")
        sampler.stop.set()
        await task
        changes = sampler.text_changes()
        times = [t for t, _ in changes]
        gaps = [b - a for a, b in zip(times, times[1:])]
        with open(ROOT / ".dev-flow" / "2026-11-18-a2l-load-performance" / "inc-2" / "evidence-e4" / "probe-d12.txt", "w", encoding="utf-8") as fh:
            t0 = markers[0][1]
            fh.write("markers (rel s):\n")
            for name, t in markers:
                fh.write(f"  {name:14s} {t - t0:8.3f}\n")
            fh.write(f"key latencies: {keys}\n")
            fh.write(f"total gaps: {len(gaps)}\n")
            fh.write("big gaps (rel to markers):\n")
            for i, g in enumerate(gaps):
                if g > 0.9:
                    gt = t0 + sum(gaps[:i])
                    fh.write(f"  gap[{i}] {g:6.3f}  at t={gt - t0:8.3f}\n")
            fh.write("last 10 gaps:\n")
            for i, g in enumerate(gaps[-10:], len(gaps) - 10):
                fh.write(f"  gap[{i}] {g:6.3f}\n")
            fh.write(f"log lines: {_log_lines(app)}\n")
        print("PROBE OK")

    _run(base, body)

if __name__ == "__main__":
    main()
