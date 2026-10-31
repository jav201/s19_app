"""C: file / depth / entry ceilings (nested tree and one huge folder), the
per-file cap, free space with rounding."""
from __future__ import annotations

import os
import sys
import time
from collections import namedtuple
from pathlib import Path

from common8b import *  # noqa: F401,F403
import common8b as c
import s19_app.tui.app as appmod
import s19_app.tui.workspace as ws


def save_q(base, name="Q", before=None):
    timing = {}

    async def sc(app, pilot, log):
        await c.open_p(pilot, app)
        if before:
            before(app)
        t0 = time.perf_counter()
        lines = await c.save(pilot, app, log, name)
        timing["save"] = time.perf_counter() - t0
        return lines
    lines = c.run(base, sc)
    return lines, timing["save"]


def outcome(lines):
    return [l[:160] for l in lines if "NOT saved" in l or "Saved project" in l or "could not" in l]


def mkdir_spy():
    """Count mkdir calls under W/Q made after the plan (Path.mkdir)."""
    calls = []
    original = Path.mkdir

    def spy(self, *a, **k):
        if "Q" in self.parts:
            calls.append(str(self))
        return original(self, *a, **k)
    return calls, original, spy


def c1_files():
    print("\n== C1 file ceiling: 2 000 copies vs 2 001 ==")
    for n in (2000, 2001):
        root, base, W = c.new_base(f"C1_{n}")
        c.bp.bulk_files(W / "P", "reports", n)
        calls, orig, spy = mkdir_spy()
        Path.mkdir = spy
        try:
            lines, t = save_q(base)
        finally:
            Path.mkdir = orig
        q = W / "Q"
        print(f"  {n}: save {t:.2f}s  Q exists={q.exists()} files in Q/reports={len(list((q / 'reports').iterdir())) if (q / 'reports').exists() else 0} mkdir under Q={len(calls)}")
        print("    ", outcome(lines), c.scan_lines(lines))


def c2_depth():
    print("\n== C2 depth ceiling: 32 vs 33 components ==")
    for n in (32, 33):
        root, base, W = c.new_base(f"C2_{n}")
        rel = c.bp.deep_file(W / "P", n, folder="r")
        lines, t = save_q(base)
        q = W / "Q"
        print(f"  {n}: save {t:.2f}s Q exists={q.exists()} deep file copied={(q.joinpath(*rel.split('/'))).exists()}")
        print("    ", outcome(lines))


def c3_entries():
    print("\n== C3 entry ceiling: nested empty folders (10 000 vs 10 001 walked entries) ==")
    for target in (10000, 10001):
        root, base, W = c.new_base(f"C3_{target}")
        P = W / "P"
        existing = c.bp.walked_entries(P)
        c.bp.nested_empty_folders(P, target - existing - 1, folder="reports")  # reports itself counts 1
        walked = c.bp.walked_entries(P)
        t0 = time.perf_counter()
        from s19_app.tui.services.project_gather_service import inventory_project_tree
        inv = inventory_project_tree(P)
        t_inv = time.perf_counter() - t0
        lines, t = save_q(base)
        print(f"  walked={walked}: inventory {t_inv:.2f}s over_ceiling={inv.over_ceiling}; save {t:.2f}s Q exists={(W / 'Q').exists()}")
        print("    ", outcome(lines))


def c4_huge_folder():
    print("\n== C4 one folder of 50 000 files ==")
    root, base, W = c.new_base("C4")
    P = W / "P"
    d = P / "reports"
    d.mkdir()
    t0 = time.perf_counter()
    for i in range(50000):
        with open(d / f"f{i:05d}.txt", "wb") as h:
            h.write(b"x")
    print(f"  created in {time.perf_counter() - t0:.1f}s")
    import s19_app.tui.services.project_gather_service as g
    yielded = {"n": 0}
    orig_walk = g.walk_tree_no_links

    def counting(*a, **k):
        for item in orig_walk(*a, **k):
            yielded["n"] += 1
            yield item
    g.walk_tree_no_links = counting
    try:
        t0 = time.perf_counter()
        inv = g.inventory_project_tree(P)
        t_inv = time.perf_counter() - t0
        lines, t = save_q(base)
    finally:
        g.walk_tree_no_links = orig_walk
    print(f"  inventory {t_inv:.2f}s over_ceiling={inv.over_ceiling} walker yields (two runs)={yielded['n']}; save {t:.2f}s Q exists={(W / 'Q').exists()}")
    print("    ", outcome(lines))


def c5_cap():
    print("\n== C5 per-file cap read at call time (cap lowered to 4096) ==")
    saved_cap = ws.DEFAULT_COPY_SIZE_CAP_BYTES
    for size in (4096, 4097):
        root, base, W = c.new_base(f"C5_{size}")
        (W / "P" / "reports").mkdir()
        (W / "P" / "reports" / "big.bin").write_bytes(b"y" * size)
        ws.DEFAULT_COPY_SIZE_CAP_BYTES = 4096
        try:
            lines, t = save_q(base)
        finally:
            ws.DEFAULT_COPY_SIZE_CAP_BYTES = saved_cap
        print(f"  {size}: Q exists={(W / 'Q').exists()} ", outcome(lines))
    # top-level copy over the cap
    root, base, W = c.new_base("C5_top")
    (W / "P" / "notes.bin").write_bytes(b"y" * 4097)
    ws.DEFAULT_COPY_SIZE_CAP_BYTES = 4096
    try:
        lines, t = save_q(base)
    finally:
        ws.DEFAULT_COPY_SIZE_CAP_BYTES = saved_cap
    print(f"  top-level 4097: Q exists={(W / 'Q').exists()} ", outcome(lines))


def c6_free_space():
    print("\n== C6 free space with rounding ==")
    sizes = {"reports/a.md": 1, "reports/b.md": 4096, "reports/c.md": 4097, "flows/e.json": 0, "notes.txt": 10}
    totals = {}
    for label in ("measure", "equal", "short"):
        root, base, W = c.new_base(f"C6_{label}")
        for rel, n in sizes.items():
            p = W / "P" / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b"z" * n)
        orig_plan = appmod.S19TuiApp._plan_project_save
        orig_du = appmod.shutil.disk_usage
        seen = {}

        def plan_spy(self, *a, **k):
            plan = orig_plan(self, *a, **k)
            seen["total"] = plan.total_bytes
            seen["rows"] = [(r.role, r.action, Path(r.landing).name) for r in plan.rows]
            return plan

        def du(path):
            real = orig_du(path)
            if label == "measure":
                free = 0
            elif label == "equal":
                free = totals["t"]
            else:
                free = totals["t"] - 1
            return type(real)(real.total, real.used, free)

        appmod.S19TuiApp._plan_project_save = plan_spy
        appmod.shutil.disk_usage = du
        try:
            lines, t = save_q(base)
        finally:
            appmod.S19TuiApp._plan_project_save = orig_plan
            appmod.shutil.disk_usage = orig_du
        if label == "measure":
            totals["t"] = seen["total"]
            img = (W / "P" / "firmware.s19").stat().st_size
            print("  plan rows:", seen["rows"])
            print("  plan total:", seen["total"], " independent (image + copies rounded + 64 KiB):",
                  c.bp.save_as_total([img, *sizes.values()]))
        print(f"  {label}: Q exists={(W / 'Q').exists()} ", outcome(lines))


if __name__ == "__main__":
    which = sys.argv[1:] or ["1", "2", "3", "4", "5", "6"]
    for k, f in (("1", c1_files), ("2", c2_depth), ("3", c3_entries), ("4", c4_huge_folder), ("5", c5_cap), ("6", c6_free_space)):
        if k in which:
            f()
