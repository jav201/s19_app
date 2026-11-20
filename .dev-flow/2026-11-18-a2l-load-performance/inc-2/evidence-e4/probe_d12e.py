"""D-12 probe 5: which preparation sub-phase holds the GIL?
Worker-side phase timestamps + main-thread ticker gaps, correlated.

Run: /c/Users/<user>/anaconda3/envs/s19env/python.exe -B probe_d12e.py
"""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))

import s19_app.tui.app.file_load as fl_module
from s19_app.tui import a2l_definition as definition_module
from s19_app.tui import a2l_parameter_picker as picker_module
from s19_app.tui.app import S19TuiApp
from s19_app.tui.services import a2l_service

_prepare = S19TuiApp._prepare_a2l_attach_snapshot
CASE06 = ROOT / "examples" / "case_06_large_nested_a2l" / "firmware.a2l"

def main() -> None:
    ticks: list = []
    stop = threading.Event()
    phases: list = []

    def mark(name):
        phases.append((name, time.monotonic()))

    def ticker():
        while not stop.is_set():
            ticks.append(time.monotonic())
            time.sleep(0.01)

    t = threading.Thread(target=ticker, daemon=True)
    t.start()

    real_enrich = a2l_service.enrich_tags_and_render
    real_render = a2l_service.render_a2l_view
    real_describe = definition_module.describe_definitions

    def enrich_spy(*a, **k):
        mark("enrich-entry")
        try:
            return real_enrich(*a, **k)
        finally:
            mark("enrich-exit")

    a2l_service.enrich_tags_and_render = enrich_spy

    def render_spy(*a, **k):
        mark("summary-entry")
        try:
            return real_render(*a, **k)
        finally:
            mark("summary-exit")

    a2l_service.render_a2l_view = render_spy

    def describe_spy(names, data):
        mark("describe-entry")
        try:
            return real_describe(names, data)
        finally:
            mark("describe-exit")

    definition_module.describe_definitions = describe_spy
    picker_module.describe_definitions = describe_spy

    entry = fl_module.deps.parse_a2l_cached(CASE06, None)
    a2l_data = entry[1]
    fake = S19TuiApp.__new__(S19TuiApp)
    fake.logger = SimpleNamespace(info=lambda *a, **k: None, warning=lambda *a, **k: None)
    mark("start")
    prepared = _prepare(
        fake,
        a2l_path=CASE06,
        a2l_data=a2l_data,
        image_mem_map=None,
        expected_a2l_generation=1,
        expected_image_generation=1,
    )
    mark("end")
    stop.set()
    t.join()
    t0 = phases[0][1]
    out = ROOT / ".dev-flow" / "2026-11-18-a2l-load-performance" / "inc-2" / "evidence-e4" / "probe-d12e.txt"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("phases (rel s):\n")
        for name, ts in phases:
            fh.write(f"  {name:14s} {ts - t0:8.3f}\n")
        gaps = [b - a for a, b in zip(ticks, ticks[1:])]
        fh.write("ticker gaps > 0.4s:\n")
        for i, g in enumerate(gaps):
            if g > 0.4:
                fh.write(f"  gap[{i}] {g:6.3f} at t={ticks[i] - t0:8.3f}\n")
    print("PROBE5 OK")


if __name__ == "__main__":
    main()
