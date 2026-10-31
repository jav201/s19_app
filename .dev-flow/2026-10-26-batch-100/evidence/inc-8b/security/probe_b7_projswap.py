"""B7: the open project folder P itself swapped for a junction between the
plan and the copy (after the S3-6 check)."""
from __future__ import annotations
import os, shutil
from pathlib import Path
from common8b import *  # noqa
import common8b as c
import s19_app.tui.app as appmod
from probe_b_swaps import setup, report

def b7(target_kind):
    print(f"\n== B7-{target_kind} W/P swapped for a junction between plan and copy ==")
    root, base, W, P, outside = setup("B7" + target_kind)
    # a look-alike tree with the same relative names, every file a marker
    look = root / "lookalike" if target_kind == "outside" else (root / "base2" / ".s19tool" / "workarea" / "R")
    shutil.copytree(P, look)
    for p in look.rglob("*"):
        if p.is_file():
            p.write_bytes(b"OUTSIDE_MARKER")
    before = c.digests(outside)
    original = appmod.S19TuiApp._copy_project_subfolders
    def wrapped(self, source_dir, project_dir, copies, *a, **k):
        if not getattr(wrapped, "done", False):
            wrapped.done = True
            os.rename(P, P.parent / "P_moved")
            c.junction(P, look)
        return original(self, source_dir, project_dir, copies, *a, **k)
    appmod.S19TuiApp._copy_project_subfolders = wrapped
    try:
        async def sc(app, pilot, log):
            await c.open_p(pilot, app)
            return await c.save(pilot, app, log, "Q")
        lines = c.run(base, sc)
    finally:
        appmod.S19TuiApp._copy_project_subfolders = original
    report("B7-" + target_kind, lines, W, outside, before)
    Q = W / "Q"
    if Q.exists():
        print("   Q files whose bytes came from the junction target:", sorted(k for k in c.digests(Q) if (Q / k).read_bytes() == b"OUTSIDE_MARKER"))

if __name__ == "__main__":
    try:
        b7("outside"); b7("other_wa")
    finally:
        print("\nlinks removed:", c.remove_links(c.SCRATCH / "B7outside") + c.remove_links(c.SCRATCH / "B7other_wa"))
