"""D-12 probe 4: pure-product GIL test. Does the case_06 preparation
(enrichment + 2 bulk describes) starve another Python thread?

Run: /c/Users/<user>/anaconda3/envs/s19env/python.exe -B probe_d12d.py
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
from s19_app.tui.app import S19TuiApp
from s19_app.tui.services import a2l_service

_prepare_a2l_attach_snapshot = S19TuiApp._prepare_a2l_attach_snapshot

CASE06 = ROOT / "examples" / "case_06_large_nested_a2l" / "firmware.a2l"

def main() -> None:
    ticks: list = []
    stop = threading.Event()

    def ticker():
        while not stop.is_set():
            ticks.append(time.monotonic())
            time.sleep(0.01)

    t = threading.Thread(target=ticker, daemon=True)
    t.start()

    parse = fl_module.deps.parse_a2l_cached
    entry = parse(CASE06, None)
    a2l_data = entry[1]
    print("parsed; tags:", len(a2l_data.get("tags") or []))
    key = (1, 1, -1)
    t0 = time.monotonic()
    fake = S19TuiApp.__new__(S19TuiApp)
    fake.logger = SimpleNamespace(info=lambda *a, **k: None, warning=lambda *a, **k: None)
    prepared = _prepare_a2l_attach_snapshot(
        fake,
        a2l_path=CASE06,
        a2l_data=a2l_data,
        image_mem_map=None,
        expected_a2l_generation=1,
        expected_image_generation=1,
    )
    elapsed = time.monotonic() - t0
    stop.set()
    t.join()
    gaps = [b - a for a, b in zip(ticks, ticks[1:])]
    big = [g for g in gaps if g > 0.5]
    out = ROOT / ".dev-flow" / "2026-11-18-a2l-load-performance" / "inc-2" / "evidence-e4" / "probe-d12d.txt"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(f"preparation wall time: {elapsed:.3f}s\n")
        fh.write(f"ticker gaps > 0.5s: {len(big)}\n")
        for i, g in enumerate(big[:20]):
            fh.write(f"  gap {g:6.3f}\n")
    print("PROBE4 OK")

if __name__ == "__main__":
    main()
