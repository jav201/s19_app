"""Scratch probe (never in the repo): what holds the memory after LARGE is deselected."""
import gc, tracemalloc, os
from tests.test_b103_inc9_w_jobs import big_case, LARGE_COUNT, run, sheet_of, pick, wait_for, has_values, st, LARGE, defc_dir  # noqa


def test_probe(tmp_path, defc_dir):
    a2l, s19 = big_case(tmp_path, LARGE_COUNT, rows=(LARGE,))
    out = open("~/work/zq-mw9/out/probe262.txt", "w")

    async def traced(app, pilot, panel):
        sheet = sheet_of(panel)
        gc.collect()
        tracemalloc.start()
        try:
            snap0 = tracemalloc.take_snapshot()
            base = tracemalloc.get_traced_memory()[0]
            await pick(pilot, sheet, LARGE)
            await wait_for(pilot, lambda: has_values(sheet, LARGE), "LARGE", 1800)
            gc.collect()
            held = tracemalloc.get_traced_memory()[0] - base
            await pick(pilot, sheet, "SMALL_BLK")
            await wait_for(pilot, lambda: has_values(sheet, "SMALL_BLK"), "SMALL", 600)
            gc.collect()
            after = tracemalloc.get_traced_memory()[0] - base
            snap1 = tracemalloc.take_snapshot()
            out.write(f"held={held} after={after}\n")
            for s in snap1.compare_to(snap0, "lineno")[:20]:
                out.write(str(s) + "\n")
            out.write("--- by traceback top 3\n")
            for s in snap1.compare_to(snap0, "traceback")[:3]:
                out.write(f"{s.size_diff} {s.count_diff}\n")
                for l in s.traceback.format()[:12]:
                    out.write(l + "\n")
            lg = st(sheet, LARGE)
            out.write(f"LARGE state: values={lg.values is None} staged={lg.staged is None} axes={len(lg.axes)} strip={len(lg.strip) if lg.strip else None} labels={lg.labels is not None}\n")
            out.flush()
        finally:
            tracemalloc.stop()

    run(tmp_path, defc_dir, traced, a2l=a2l, image=s19)
