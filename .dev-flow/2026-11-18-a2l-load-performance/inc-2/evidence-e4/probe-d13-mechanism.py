"""D-13 mechanism probe: ticker thread vs case_06 preparation variants.
A: plain  B: gc disabled around work  C: plain + host load sample
Prints max ticker gap per variant. Evidence, not a test verdict.
"""
import gc
import sys
import threading
import time

sys.path.insert(0, ".")

from pathlib import Path

from s19_app.tui.a2l_parse import parse_a2l_file
from s19_app.tui.a2l_definition import describe_definitions
from s19_app.tui.services.a2l_service import enrich_tags_and_render

CASE = Path("examples/case_06_large_nested_a2l/firmware.a2l")


def ticker_gaps(stop: threading.Event, out: list):
    last = time.monotonic()
    while not stop.is_set():
        time.sleep(0.01)
        now = time.monotonic()
        out.append(now - last)
        last = now


def run_variant(label: str, disable_gc: bool) -> float:
    print(f"parsing {CASE} ...", flush=True)
    t0 = time.perf_counter()
    a2l = parse_a2l_file(CASE)
    print(f"  parse {time.perf_counter() - t0:.1f}s tags={len(a2l['tags'])}", flush=True)

    enriched, _summary = enrich_tags_and_render(a2l, None, max_tag_lines=500)
    names = [t["name"] for t in enriched if isinstance(t.get("address"), int)]
    print(f"  names={len(names)}", flush=True)

    stop = threading.Event()
    gaps: list = []
    tick = threading.Thread(target=ticker_gaps, args=(stop, gaps), daemon=True)
    tick.start()
    time.sleep(0.2)

    def work():
        if disable_gc:
            gc.disable()
        try:
            t1 = time.perf_counter()
            describe_definitions(names, a2l)
            d1 = time.perf_counter() - t1
            t2 = time.perf_counter()
            describe_definitions(names, a2l)
            d2 = time.perf_counter() - t2
        finally:
            if disable_gc:
                gc.enable()
        print(f"  {label}: describe1 {d1:.1f}s describe2 {d2:.1f}s", flush=True)

    worker = threading.Thread(target=work)
    worker.start()
    worker.join()
    stop.set()
    tick.join(timeout=2)
    peak = max(gaps) if gaps else 0.0
    over = sorted((g for g in gaps if g > 0.5), reverse=True)[:8]
    print(f"  {label}: ticker gaps n={len(gaps)} peak={peak:.3f}s >0.5s: {[round(g,3) for g in over]}", flush=True)
    return peak


peak_a = run_variant("A-plain", disable_gc=False)
peak_b = run_variant("B-gc-off", disable_gc=True)
print(f"RESULT A={peak_a:.3f}s B={peak_b:.3f}s")
