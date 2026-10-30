"""security-reviewer probe, batch-100 Inc 5 (SEC-4 re-run + Save project write paths).

Usage: python -B sec_inc5_probe.py <worktree> <scratch-work-dir>
Every scenario builds its own folder under <scratch-work-dir>; every junction
is removed with rmdir (never rmtree through it) before the folder is removed.
The worktree is never written: examples are copied out, test helpers are only
imported.
"""
import asyncio
import logging
import os
import shutil
import stat
import subprocess
import sys
import traceback
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
WT = Path(sys.argv[1]).resolve()
WORK = Path(sys.argv[2]).resolve()
sys.path.insert(0, str(WT))
import s19_app  # noqa: E402

print("s19_app.__file__ =", s19_app.__file__)
print("python =", sys.version.split()[0])

import s19_app.tui.app as app_module  # noqa: E402
import s19_app.tui.services.change_service as cs_module  # noqa: E402
from s19_app.tui import workspace as ws  # noqa: E402
from s19_app.tui.changes import apply as ap  # noqa: E402
from s19_app.tui.screens import SaveProjectPayload  # noqa: E402
from s19_app.tui.app import S19TuiApp  # noqa: E402
from s19_app.tui.screens_directionb import PatchEditorPanel  # noqa: E402

CASE01 = WT / "examples" / "case_01_basic_valid" / "firmware.s19"
PATCH_ADDRESS, PATCH_BYTES = 0x8000007C, (0xDE, 0xAD, 0xBE, 0xEF)
JUNCTIONS: list = []
FAILS: list = []


def junction(link: Path, target: Path) -> None:
    r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True)
    assert r.returncode == 0, r
    JUNCTIONS.append(link)


def is_reparse(p: str) -> bool:
    try:
        return bool(os.lstat(p).st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    except OSError:
        return False


def tree(root: Path) -> dict:
    """rel path -> 'J' (junction, not descended) / 'D' / size; never follows a reparse point."""
    out = {}
    if not root.exists():
        return out
    stack = [root]
    while stack:
        d = stack.pop()
        for e in os.scandir(d):
            rel = str(Path(e.path).relative_to(root))
            if is_reparse(e.path):
                out[rel] = "J"
            elif e.is_dir(follow_symlinks=False):
                out[rel] = "D"
                stack.append(Path(e.path))
            else:
                out[rel] = os.lstat(e.path).st_size
    return out


def diff(before: dict, after: dict) -> dict:
    return {
        "created": sorted(k for k in after if k not in before),
        "removed": sorted(k for k in before if k not in after),
        "changed": sorted(k for k in after if k in before and after[k] != before[k]),
    }


def check(label: str, ok: bool) -> None:
    print(f"  CHECK {label}: {'ok' if ok else 'FAIL'}")
    if not ok:
        FAILS.append(label)


def outside(created: list, wa_rel: str) -> list:
    """Entries of a whole-scratch diff that are NOT inside this work area and not the app's own log."""
    return [
        c for c in created
        if not c.startswith(wa_rel)
        and not c.startswith(str(Path("app") / ".s19tool" / "logs"))
    ]


def close_logs() -> None:
    for name in list(logging.Logger.manager.loggerDict):
        lg = logging.getLogger(name)
        for h in list(lg.handlers):
            try:
                h.close()
            finally:
                lg.removeHandler(h)


def fresh(name: str):
    root = WORK / name
    root.mkdir(parents=True, exist_ok=False)
    wa = ws.ensure_workarea(root / "app")
    other_wa = root / "other" / ".s19tool" / "workarea"
    (other_wa / "T").mkdir(parents=True)
    shutil.copy2(CASE01, other_wa / "T" / "firmware.s19")
    return root, wa, other_wa


async def wait_for(pilot, pred, attempts=300):
    for _ in range(attempts):
        if pred():
            return True
        await pilot.pause()
    return False


def painted(app) -> str:
    return "\n".join(list(app.log_lines)[-6:]) if getattr(app, "log_lines", None) else ""


def add_apply(app) -> None:
    app._change_service.add_entry(f"0x{PATCH_ADDRESS:08X}", "", " ".join(f"{b:02X}" for b in PATCH_BYTES))
    lf = app.current_file
    app._change_service.apply(lf.mem_map, lf.ranges, lf.mac_records, None)


# ---------------------------------------------------------------------------
# A: API-level re-run of sec_inc1_r2_emit_probe on this tree
# ---------------------------------------------------------------------------
def scenario_a() -> None:
    print("\n== A: save_patched_image API (the Round-2 SEC-4 probe shape) ==")
    root, wa, other_wa = fresh("A")
    junction(wa / "evil", other_wa / "T")
    real_stage = ap._private_stage_dir
    staged: list = []

    def spy(r):
        d = real_stage(r)
        staged.append(str(d))
        return d

    ap._private_stage_dir = spy
    try:
        image = {0x1000: 0xAA, 0x1001: 0xBB}
        rng = [(0x1000, 0x1002)]
        cases = [
            ("A1 junction dest, root=None", wa / "evil", None),
            ("A2 junction dest, root=this work area", wa / "evil", wa),
            ("A3 PRE-RESOLVED junction dest, root=this work area", (wa / "evil").resolve(), wa),
            ("A4 junction dest, root=None, upper-cased spelling", Path(str(wa / "evil").upper()), None),
        ]
        for label, dest, root_arg in cases:
            staged.clear()
            b = tree(root / "other")
            path, issues = ap.save_patched_image(image, rng, dest, "firmware_patched.s19",
                                                 source_kind="s19", workarea_root=root_arg)
            a = tree(root / "other")
            d = diff(b, a)
            print(f" {label}: path={path} issues={[getattr(i, 'code', str(i)) for i in issues]}")
            print(f"   staging dirs created: {staged}")
            print(f"   other-work-area diff: {d}")
            check(f"{label}: refused", path is None)
            check(f"{label}: no staging dir created", staged == [])
            check(f"{label}: 0 entries created in the other work area", d["created"] == [] and d["changed"] == [])
        # A5: the remaining no-root caller shape (flow/variant execution) with a PRE-RESOLVED dest
        staged.clear()
        b = tree(root / "other")
        path, issues = ap.save_patched_image(image, rng, (wa / "evil").resolve(), "firmware_patched.s19",
                                             source_kind="s19", workarea_root=None)
        a = tree(root / "other")
        d = diff(b, a)
        print(f" A5 PRE-RESOLVED junction dest, root=None (SEC-6 shape, not an app path today): path={path}")
        print(f"   staging dirs created: {staged}")
        print(f"   other-work-area diff: {d}")
        # control: a legitimate destination works and stages under THIS work area
        (wa / "P").mkdir()
        staged.clear()
        path, issues = ap.save_patched_image(image, rng, wa / "P", "firmware_patched.s19",
                                             source_kind="s19", workarea_root=wa)
        print(f" A6 control, real project dest with root: path={path}; staged under: {staged}")
        check("A6 control accepted", path is not None and path.exists())
        check("A6 staging under this work area", bool(staged) and all(
            os.path.normcase(s).startswith(os.path.normcase(str(wa.resolve()))) for s in staged))
    finally:
        ap._private_stage_dir = real_stage


# ---------------------------------------------------------------------------
# B / C / D / E: real app routes in Textual run_test
# ---------------------------------------------------------------------------
def run_app(base: Path, body):
    async def drive():
        app = S19TuiApp(base_dir=base)
        async with app.run_test(size=(220, 60)) as pilot:
            await pilot.pause()
            return await body(app, pilot)
    try:
        return asyncio.run(drive())
    finally:
        close_logs()


async def load_project(app, pilot, name):
    app._handle_load_project(name)
    ok = await wait_for(pilot, lambda: app.current_project == name and app.current_file is not None)
    assert ok, f"project {name} did not load"


async def load_file(app, pilot, path):
    app.load_selected_file(path)
    ok = await wait_for(pilot, lambda: app.current_file is not None and app.current_file.path.name == path.name)
    assert ok, f"file {path} did not load"


def save(app, parent: str, name: str):
    exc = None
    try:
        app._handle_save_dialog(SaveProjectPayload(parent_folder=parent, project_name=name))
    except BaseException as e:  # noqa: BLE001 - the probe records it
        exc = e
    return exc


def scenario_b() -> None:
    print("\n== B: app save-back with a junction project open ==")
    root, wa, other_wa = fresh("B")
    junction(wa / "evil", other_wa / "T")
    wa_rel = str(wa.relative_to(root))

    async def body(app, pilot):
        await load_project(app, pilot, "evil")
        print("  current_project_dir:", app.current_project_dir,
              "| equals its resolved form:", app.current_project_dir == app.current_project_dir.resolve())
        add_apply(app)
        before = tree(root)
        app.on_patch_editor_panel_save_back_decision(PatchEditorPanel.SaveBackDecision("patched.s19", 32))
        await wait_for(pilot, lambda: "Saved + verified" in painted(app) or "not saved" in painted(app).lower())
        after = tree(root)
        return before, after, painted(app)

    before, after, status = run_app(root / "app", body)
    d = diff(before, after)
    out = outside(d["created"] + d["changed"], wa_rel)
    print("  status tail:", status.replace("\n", " | ")[-300:])
    print("  whole-scratch diff:", d)
    print("  entries created/changed OUTSIDE this work area:", out)
    check("B save-back refused", "Patched image not saved" in status or "not saved" in status.lower())
    check("B 0 entries outside this work area", out == [])


def scenario_c() -> None:
    print("\n== C: Save project (emit path) with a junction project open ==")
    root, wa, other_wa = fresh("C")
    junction(wa / "evil", other_wa / "T")
    (root / "outside").mkdir()
    wa_rel = str(wa.relative_to(root))
    real_guard = ap._guarded_destination
    at_guard: list = []

    def guard_spy(dest, workarea_root=None):
        at_guard.append((str(dest), sorted(tree(root / "other")), sorted(tree(root / "outside"))))
        return real_guard(dest, workarea_root)

    ap._guarded_destination = guard_spy

    async def body(app, pilot):
        await load_project(app, pilot, "evil")
        add_apply(app)
        results = []
        cases = [
            ("C1 name=evil (the junction itself)", str(app.workarea), "evil"),
            ("C2 parent=<wa>\\evil (absolute, through the junction), name=X", str(app.workarea / "evil"), "X"),
            ("C3 parent=relative '.s19tool/workarea/evil' (resolve_input_path resolves it), name=Y",
             str(Path(".s19tool") / "workarea" / "evil"), "Y"),
            ("C4 parent=<wa>\\EVIL upper-cased, name=Z", str(app.workarea).upper() + "\\EVIL", "Z"),
            ("C5 parent outside every work area, name=W", str(root / "outside"), "W"),
            ("C6 control: parent=<wa>, new name P2", str(app.workarea), "P2"),
        ]
        for label, parent, name in cases:
            at_guard.clear()
            before = tree(root)
            exc = save(app, parent, name)
            await pilot.pause()
            after = tree(root)
            results.append((label, before, after, list(list(app.log_lines)[-3:]), exc, list(at_guard)))
        return results

    try:
        results = run_app(root / "app", body)
    finally:
        ap._guarded_destination = real_guard
    for label, before, after, lines, exc, guards in results:
        d = diff(before, after)
        out = outside(d["created"] + d["changed"] + d["removed"], wa_rel)
        print(f" {label}")
        print(f"   status: {lines[-1] if lines else ''}")
        print(f"   exception escaped the handler: {exc!r}")
        for g in guards:
            print(f"   emit guard called with dest={g[0]}")
            print(f"     other tree at that moment: {g[1]}")
            print(f"     outside tree at that moment: {g[2]}")
        print(f"   whole-scratch diff: {d}")
        print(f"   net entries OUTSIDE this work area: {out}")
        check(f"{label}: no exception", exc is None)
        check(f"{label}: net 0 entries outside this work area", out == [])
        if label.startswith("C6"):
            check("C6 control saved", any("Saved project to" in s for s in lines))


def scenario_d() -> None:
    print("\n== D: Save project rollback — does it delete only what it created? ==")
    root, wa, other_wa = fresh("D")
    src_dir = root / "src"
    src_dir.mkdir()
    shutil.copy2(CASE01, src_dir / "firmware.s19")

    async def body(app, pilot):
        out = {}
        await load_file(app, pilot, src_dir / "firmware.s19")
        add_apply(app)
        # D1: first save emits into M; then a second save into M (now the open
        # project) must REUSE the identical image; force the manifest stage to fail.
        save(app, str(app.workarea), "M")
        await pilot.pause()
        m_before = tree(wa / "M")
        m_bytes = {k: (wa / "M" / k).read_bytes() for k, v in m_before.items() if v not in ("D", "J")}
        real_manifest = app._write_and_verify_manifest
        app._write_and_verify_manifest = lambda *a, **k: False
        exc = save(app, str(app.workarea), "M")
        await pilot.pause()
        app._write_and_verify_manifest = real_manifest
        m_after = tree(wa / "M")
        out["D1"] = (m_before, m_after, list(list(app.log_lines)[-2:]), exc,
                     all((wa / "M" / k).read_bytes() == v for k, v in m_bytes.items() if (wa / "M" / k).exists()))
        # D2: a concurrent writer creates the planned landing between plan and emit
        real_emit = app._change_service.emit_and_verify
        planted: list = []

        def racing_emit(image, ranges, dest_dir, filename, **kw):
            p = Path(dest_dir) / filename
            p.write_bytes(b"FOREIGN-WRITER\n")
            planted.append(p)
            return real_emit(image, ranges, dest_dir, filename, **kw)

        app._change_service.emit_and_verify = racing_emit
        b = tree(wa)
        exc = save(app, str(app.workarea), "C")
        await pilot.pause()
        app._change_service.emit_and_verify = real_emit
        out["D2"] = (b, tree(wa), list(list(app.log_lines)[-2:]), exc,
                     [(str(p), p.exists() and p.read_bytes() == b"FOREIGN-WRITER\n") for p in planted])
        # D3: the verify re-read raises OSError AFTER the emit placed the file
        real_verify = cs_module.verify_written_image

        def verify_oserror(*a, **k):
            raise OSError(13, "probe: verify re-read denied")

        cs_module.verify_written_image = verify_oserror
        b = tree(wa)
        exc = save(app, str(app.workarea), "V")
        await pilot.pause()
        out["D3"] = (b, tree(wa), list(list(app.log_lines)[-2:]), exc, None)

        # D4: the verify re-read raises ValueError (the documented parse error)
        def verify_valueerror(*a, **k):
            raise ValueError("probe: verify re-read parse error")

        cs_module.verify_written_image = verify_valueerror
        b = tree(wa)
        exc = save(app, str(app.workarea), "V2")
        await pilot.pause()
        cs_module.verify_written_image = real_verify
        out["D4"] = (b, tree(wa), list(list(app.log_lines)[-2:]), exc, None)
        return out

    res = run_app(root / "app", body)
    m_before, m_after, lines, exc, same = res["D1"]
    print(" D1 reuse + manifest failure in the open project M")
    print("   status:", lines)
    print("   exception:", repr(exc))
    print("   M diff:", diff(m_before, m_after), "| every pre-existing file byte-identical after:", same)
    check("D1 rollback removed nothing that pre-existed", diff(m_before, m_after)["removed"] == [] and same)
    for key, title in (("D2", "concurrent writer at the planned landing (project C)"),
                       ("D3", "verify raises OSError after the emit placed (project V)"),
                       ("D4", "verify raises ValueError after the emit placed (project V2)")):
        b, a, lines, exc, extra = res[key]
        print(f" {key} {title}")
        print("   status:", lines)
        print("   exception escaped the handler:", repr(exc))
        print("   work-area diff:", diff(b, a))
        if extra is not None:
            print("   foreign file survives intact:", extra)
    b, a, _l, _e, extra = res["D2"]
    check("D2 foreign file survives", all(ok for _p, ok in extra))
    check("D2 the save's own dedup file removed", not any(k.startswith("C\\firmware_") for k in diff(b, a)["created"]))
    b, a, _l, exc, _x = res["D3"]
    print("   D3 leftover entries after rollback:", diff(b, a)["created"])
    b, a, _l, exc, _x = res["D4"]
    print("   D4 leftover entries:", diff(b, a)["created"])


def scenario_e() -> None:
    print("\n== E: TOCTOU — the target becomes a junction between plan and run ==")
    root, wa, other_wa = fresh("E")
    src_dir = root / "src"
    src_dir.mkdir()
    shutil.copy2(CASE01, src_dir / "firmware.s19")
    wa_rel = str(wa.relative_to(root))

    async def body(app, pilot):
        await load_file(app, pilot, src_dir / "firmware.s19")
        add_apply(app)
        out = {}
        # E1: junction planted after the plan, before mkdir
        real_plan = app._plan_project_save

        def plan_then_swap(project_dir, name, step):
            plan = real_plan(project_dir, name, step)
            junction(Path(project_dir), other_wa / "T")
            return plan

        app._plan_project_save = plan_then_swap
        b = tree(root)
        exc = save(app, str(app.workarea), "Q")
        await pilot.pause()
        app._plan_project_save = real_plan
        out["E1"] = (b, tree(root), list(list(app.log_lines)[-2:]), exc)
        # E2: our freshly created folder is swapped for a junction after mkdir
        real_validate = app_module.validate_project_files
        swapped: list = []

        def validate_then_swap(project_dir):
            if not swapped and Path(project_dir).name == "R":
                os.rmdir(project_dir)
                junction(Path(project_dir), other_wa / "T")
                swapped.append(project_dir)
            return real_validate(project_dir)

        app_module.validate_project_files = validate_then_swap
        b = tree(root)
        exc = save(app, str(app.workarea), "R")
        await pilot.pause()
        app_module.validate_project_files = real_validate
        out["E2"] = (b, tree(root), list(list(app.log_lines)[-2:]), exc)
        return out

    res = run_app(root / "app", body)
    for key, title in (("E1", "junction planted at the target after the plan, before mkdir"),
                       ("E2", "the folder this save created swapped for a junction before the placement")):
        b, a, lines, exc = res[key]
        d = diff(b, a)
        other = {k: v for k, v in d.items()}
        out = outside(d["created"] + d["changed"] + d["removed"], wa_rel)
        print(f" {key} {title}")
        print("   status:", lines)
        print("   exception escaped the handler:", repr(exc))
        print("   whole-scratch diff:", other)
        print("   net entries OUTSIDE this work area:", out)
        print("   other work area T now:", sorted(tree(other_wa / "T")))
        check(f"{key} 0 entries outside this work area", out == [])
        check(f"{key} other work area's file intact", (other_wa / "T" / "firmware.s19").read_bytes() == CASE01.read_bytes())


if __name__ == "__main__":
    WORK.mkdir(parents=True, exist_ok=False)
    try:
        for sc in (scenario_a, scenario_b, scenario_c, scenario_d, scenario_e):
            try:
                sc()
            except Exception:  # noqa: BLE001
                print("SCENARIO CRASHED:")
                traceback.print_exc(file=sys.stdout)
                FAILS.append(sc.__name__ + " crashed")
    finally:
        close_logs()
        for j in reversed(JUNCTIONS):
            if os.path.lexists(j) and is_reparse(str(j)):
                subprocess.run(["cmd", "/c", "rmdir", str(j)], capture_output=True)
        left = [str(j) for j in JUNCTIONS if os.path.lexists(j)]
        print("\njunctions still present after rmdir:", left)
        if not left:
            shutil.rmtree(WORK, ignore_errors=True)
        print("scratch folder removed:", not WORK.exists())
        print("FAILED CHECKS:", FAILS)
