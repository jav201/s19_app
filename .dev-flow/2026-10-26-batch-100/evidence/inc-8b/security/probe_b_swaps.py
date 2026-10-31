"""B: link swapped between plan and copy, between copy steps, destination
swapped under a junction mid-copy, rollback through a swapped folder,
mid-copy failure, target appearing between plan and mkdir."""
from __future__ import annotations

import os
import shutil
from pathlib import Path

from common8b import *  # noqa: F401,F403
import common8b as c
import s19_app.tui.app as appmod


def setup(case):
    root, base, W = c.new_base(case)
    P = W / "P"
    c.bp.write_tree(P, c.bp.SUBFOLDER_FILES)
    for i in range(6):
        (P / "reports" / f"z{i}.md").write_bytes(f"report {i}".encode())
    outside = root / "outside"
    outside.mkdir()
    for i in range(6):
        (outside / f"z{i}.md").write_bytes(b"OUTSIDE_MARKER")
    (outside / "r.md").write_bytes(b"OUTSIDE_MARKER")
    return root, base, W, P, outside


def report(label, lines, W, outside, before_outside, extra=None):
    Q = W / "Q"
    qd = c.digests(Q)
    hits = [k for k in qd if b"MARKER" in (Q / k).read_bytes()]
    print(f"  {label}: Q exists={Q.exists()} files={len(qd)} marker files={hits} outside unchanged={c.digests(outside) == before_outside}")
    for l in c.short(lines, 220):
        print("    |", ascii(l))
    print("    scan:", c.scan_lines(lines))
    if extra:
        print("   ", extra)


def b1_swap_between_plan_and_copy():
    print("\n== B1 P/reports swapped for a junction to outside between plan and copy ==")
    root, base, W, P, outside = setup("B1")
    before = c.digests(outside)
    original = appmod.S19TuiApp._copy_project_subfolders

    def wrapped(self, source_dir, project_dir, copies, *a, **k):
        if not getattr(wrapped, "done", False):
            wrapped.done = True
            os.rename(P / "reports", P / "reports_moved")
            c.junction(P / "reports", outside)
        return original(self, source_dir, project_dir, copies, *a, **k)

    appmod.S19TuiApp._copy_project_subfolders = wrapped
    try:
        async def sc(app, pilot, log):
            await c.open_p(pilot, app)
            return await c.save(pilot, app, log, "Q")
        lines = c.run(base, sc)
    finally:
        appmod.S19TuiApp._copy_project_subfolders = original
    report("B1", lines, W, outside, before)


def b2_swap_between_copy_steps(target_kind):
    print(f"\n== B2-{target_kind} a folder swapped between two placements ==")
    root, base, W, P, outside = setup("B2" + target_kind)
    before = c.digests(outside)
    R = W / "R" / "reports"
    R.mkdir(parents=True)
    for i in range(6):
        (R / f"z{i}.md").write_bytes(b"OTHER_PROJECT_MARKER")
    original = appmod.place_into_workarea
    calls = {"n": 0}

    def wrapped(source, destination, *a, **k):
        calls["n"] += 1
        res = original(source, destination, *a, **k)
        if calls["n"] == 3 and not calls.get("swapped"):
            calls["swapped"] = True
            os.rename(P / "reports", P / "reports_moved")
            tgt = {"outside": outside, "other": R, "insideP": P / "flows"}[target_kind]
            c.junction(P / "reports", tgt)
        return res

    appmod.place_into_workarea = wrapped
    try:
        async def sc(app, pilot, log):
            await c.open_p(pilot, app)
            return await c.save(pilot, app, log, "Q")
        lines = c.run(base, sc)
    finally:
        appmod.place_into_workarea = original
    report("B2-" + target_kind, lines, W, outside, before,
           extra=f"other-project files in Q: {[k for k, v in c.digests(W / 'Q').items() if (W / 'Q' / k).read_bytes() == b'OTHER_PROJECT_MARKER']}")


def b3_destination_swapped_and_rollback():
    print("\n== B3 Q/reports swapped for a junction to R/reports after a placement; rollback ==")
    root, base, W, P, outside = setup("B3")
    before = c.digests(outside)
    R = W / "R" / "reports"
    R.mkdir(parents=True)
    # R's user files carry the SAME names Q placed under reports
    names = sorted(p.name for p in (P / "reports").iterdir() if p.is_file())
    for n in names:
        (R / n).write_bytes(b"R_USER_FILE")
    original = appmod.place_into_workarea
    calls = {"n": 0}

    def wrapped(source, destination, *a, **k):
        res = original(source, destination, *a, **k)
        calls["n"] += 1
        # after the LAST reports file lands, move Q/reports away and junction it to R/reports
        if Path(destination).name == "reports" and Path(source).name == names[-1] and not calls.get("swapped"):
            calls["swapped"] = True
            q = Path(destination)
            os.rename(q, q.parent / "reports_old")
            c.junction(q, R)
            raise PermissionError(13, "injected failure after swap")
        return res

    appmod.place_into_workarea = wrapped
    try:
        async def sc(app, pilot, log):
            await c.open_p(pilot, app)
            return await c.save(pilot, app, log, "Q")
        lines = c.run(base, sc)
    finally:
        appmod.place_into_workarea = original
    left = sorted(p.name for p in R.iterdir())
    print("  R/reports before:", names)
    print("  R/reports after :", left)
    print("  R user files deleted by the rollback:", sorted(set(names) - set(left)))
    report("B3", lines, W, outside, before)


def b4_midcopy_failure():
    print("\n== B4 4th placement raises PermissionError; rollback ==")
    root, base, W, P, outside = setup("B4")
    before = c.digests(outside)
    original = appmod.place_into_workarea
    calls = {"n": 0}

    def wrapped(source, destination, *a, **k):
        calls["n"] += 1
        if calls["n"] == 4:
            raise PermissionError(13, "Access is denied", str(source))
        return original(source, destination, *a, **k)

    appmod.place_into_workarea = wrapped
    try:
        async def sc(app, pilot, log):
            await c.open_p(pilot, app)
            lines = await c.save(pilot, app, log, "Q")
            return lines, str(app.current_project_dir)
        lines, cur = c.run(base, sc)
    finally:
        appmod.place_into_workarea = original
    report("B4", lines, W, outside, before, extra=f"current_project_dir after: {cur}")


def b5_target_appears_before_mkdir():
    print("\n== B5 Q created by another writer between the plan and mkdir (user files) ==")
    root, base, W, P, outside = setup("B5")
    before = c.digests(outside)
    import shutil as sh
    original = sh.disk_usage

    def wrapped(path):
        Q = W / "Q"
        if not Q.exists():
            (Q / "reports").mkdir(parents=True)
            (Q / "reports" / "r.md").write_bytes(b"USER_PRE_EXISTING")
            (Q / "keep.txt").write_bytes(b"USER_PRE_EXISTING")
        return original(path)

    appmod.shutil.disk_usage = wrapped
    try:
        async def sc(app, pilot, log):
            await c.open_p(pilot, app)
            return await c.save(pilot, app, log, "Q")
        lines = c.run(base, sc)
    finally:
        appmod.shutil.disk_usage = original
    Q = W / "Q"
    print("  Q contents after:", sorted(c.digests(Q)))
    print("  user files intact:", (Q / "reports" / "r.md").read_bytes() == b"USER_PRE_EXISTING" and (Q / "keep.txt").read_bytes() == b"USER_PRE_EXISTING")
    report("B5", lines, W, outside, before)


def b6_file_grows_past_cap():
    print("\n== B6 a copied file replaced by a link to outside after the plan (file level) ==")
    root, base, W, P, outside = setup("B6")
    before = c.digests(outside)
    original = appmod.S19TuiApp._copy_project_subfolders

    def wrapped(self, source_dir, project_dir, copies, *a, **k):
        if not getattr(wrapped, "done", False):
            wrapped.done = True
            os.remove(P / "reports" / "r.md")
            c.symlink(P / "reports" / "r.md", outside / "r.md")
        return original(self, source_dir, project_dir, copies, *a, **k)

    appmod.S19TuiApp._copy_project_subfolders = wrapped
    try:
        async def sc(app, pilot, log):
            await c.open_p(pilot, app)
            return await c.save(pilot, app, log, "Q")
        lines = c.run(base, sc)
    finally:
        appmod.S19TuiApp._copy_project_subfolders = original
    report("B6", lines, W, outside, before)


if __name__ == "__main__":
    try:
        b1_swap_between_plan_and_copy()
        for k in ("outside", "other", "insideP"):
            b2_swap_between_copy_steps(k)
        b3_destination_swapped_and_rollback()
        b4_midcopy_failure()
        b5_target_appears_before_mkdir()
        b6_file_grows_past_cap()
    finally:
        n = c.remove_links(c.SCRATCH)
        print("\nlinks removed:", n, " reparse points left in scratch:", c.sweep(c.SCRATCH))
