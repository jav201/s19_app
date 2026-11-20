"""D-12 probe 3: is the loop blocked (GIL) or is the status text just static?
Ticker (pure loop) vs sampler (status text) vs preparation phases.

Run: /c/Users/<user>/anaconda3/envs/s19env/python.exe -B probe_d12c.py
"""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))

import asyncio

import s19_app.tui.app.file_load as fl_module
from s19_app.tui import a2l_definition as definition_module
from s19_app.tui.app import S19TuiApp
from tests.support.b100_workers import settle_workers
from tests.test_alp_inc2_a2l_attach import (
    CASE06,
    Sampler,
    _focus_key_pair,
    _log_lines,
    _run,
)
from tests.support.timing import timing_bound


def main() -> None:
    tmp = ROOT / ".dev-flow" / "2026-11-18-a2l-load-performance" / "inc-2" / "evidence-e4" / "probe-tmp"
    base = tmp / "app"
    bound = timing_bound(1.0)
    events: list = []

    def ev(name):
        events.append((name, time.monotonic(), threading.get_ident()))

    real_parse = fl_module.deps.parse_a2l_cached
    real_enrich = fl_module.enrich_tags_and_render
    real_describe = definition_module.describe_definitions

    def parse_spy(path, *a, **k):
        ev("parse-entry")
        try:
            return real_parse(path, *a, **k)
        finally:
            ev("parse-exit")

    fl_module.deps.parse_a2l_cached = parse_spy

    def enrich_spy(*a, **k):
        ev("enrich-entry")
        try:
            return real_enrich(*a, **k)
        finally:
            ev("enrich-exit")

    fl_module.enrich_tags_and_render = enrich_spy

    def describe_spy(names, data):
        ev("describe-entry")
        try:
            return real_describe(names, data)
        finally:
            ev("describe-exit")

    definition_module.describe_definitions = describe_spy

    async def body(app, pilot):
        app.set_focus(app.query_one("#files_list"))
        await pilot.pause()

        ticker: list = []
        stop_ticker = threading.Event()

        async def tick():
            while not stop_ticker.is_set():
                ticker.append(time.monotonic())
                await asyncio.sleep(0.01)

        tick_task = asyncio.create_task(tick())
        sampler = Sampler()
        task = sampler.start(pilot, app, bar=True)
        await pilot.pause(0.1)
        ev("load-call")
        app.load_a2l_from_path(CASE06)
        ev("load-return")
        keys = await _focus_key_pair(pilot, app, bound=bound)
        ev("keys-ack")
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
        ev("terminal")
        sampler.stop.set()
        await task
        stop_ticker.set()
        await tick_task
        t0 = events[0][1]
        out = ROOT / ".dev-flow" / "2026-11-18-a2l-load-performance" / "inc-2" / "evidence-e4" / "probe-d12c.txt"
        with open(out, "w", encoding="utf-8") as fh:
            fh.write("events (rel s, thread):\n")
            for name, t, ident in events:
                fh.write(f"  {name:15s} {t - t0:9.3f}  {ident}\n")
            fh.write(f"key latencies: {keys}\n")
            tgaps = [b - a for a, b in zip(ticker, ticker[1:])]
            big_t = [(i, g) for i, g in enumerate(tgaps) if g > 0.5]
            fh.write(f"ticker gaps > 0.5s: {len(big_t)}\n")
            for i, g in big_t[:30]:
                fh.write(f"  tickgap[{i}] {g:6.3f} at t={ticker[i] - t0:8.3f}\n")
            changes = sampler.text_changes()
            times = [t for t, _ in changes]
            gaps = [b - a for a, b in zip(times, times[1:])]
            fh.write("sampler big gaps:\n")
            for i, g in enumerate(gaps):
                if g > 0.9:
                    gt = t0 + sum(gaps[:i])
                    fh.write(f"  gap[{i}] {g:6.3f}  at t={gt - t0:8.3f}\n")
            fh.write(f"log: {_log_lines(app)}\n")
        print("PROBE3 OK")

    _run(base, body)


if __name__ == "__main__":
    main()
