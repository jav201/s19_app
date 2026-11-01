"""Probe p12a (E2 baseline, Inc 12a). Runs on the throwaway copy work/tree, read-only
against the repo. Usage: python -I probe-p12a.py <tree>

Records, on the base, for each of the 7 long actions one success and one failure arm:
the set_progress values (spy), the status-log lines added, the final #status_text and
bar value, and whether an exception left the action. Plus the 12a sweep arms owed at E2
(LLR-172.6b (a)(b), LLR-172.6c, LLR-172.5i, LLR-172.4e, LLR-172.4f, LLR-172.5k sites),
B9 (OBS-9a-2) and the label surfaces (LLR-173.2m)."""
from __future__ import annotations

import ast
import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

TREE = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(TREE))
import s19_app  # noqa: E402

print("import", s19_app.__file__)
from textual.widgets import Label, ListItem, ProgressBar  # noqa: E402

import s19_app.tui.app as app_mod  # noqa: E402
from s19_app.tui import workspace  # noqa: E402
from s19_app.tui.app import S19TuiApp  # noqa: E402
from s19_app.tui.screens import SaveProjectPayload  # noqa: E402

CASE01 = TREE / "examples" / "case_01_basic_valid"


def status_text(app):
    lab = app.query_one("#status_text", Label)
    return str(lab.render())


def bar(app):
    return app.query_one("#progress_bar", ProgressBar).progress


class Rec:
    def __init__(self, app):
        self.app = app
        self.progress = []
        orig = S19TuiApp.set_progress

        def spy(value, message=None, _o=orig, _a=app):
            self.progress.append(value)
            return _o(_a, value, message)

        app.set_progress = spy
        self.log = []
        olog = S19TuiApp._append_log_line

        def logspy(message, _o=olog, _a=app):
            if message.strip():
                self.log.append(message.strip()[:90])
            return _o(_a, message)

        app._append_log_line = logspy

    def lines(self):
        return list(self.log)


async def flush(pilot, n=12):
    for _ in range(n):
        await pilot.pause()


async def settle(app, pilot):
    await flush(pilot)
    await app.workers.wait_for_complete()
    await flush(pilot)


def report(tag, rec, app, exc=None):
    print(f"== {tag} progress={rec.progress} end_bar={bar(app)} status_text={status_text(app)!r}"
          f" exc={type(exc).__name__ if exc else None}")
    print(f"   log+ {rec.lines()}")


def write_s19(path: Path, size_bytes: int = 0) -> None:
    shutil.copy2(CASE01 / "firmware.s19", path)
    if size_bytes:
        data = path.read_bytes()
        pad = size_bytes - len(data)
        if pad > 0:
            path.write_bytes(data + b"\n" * pad)


def make_project(app, name="P", a2l=False):
    p = app.workarea / name
    p.mkdir(parents=True, exist_ok=True)
    shutil.copy2(CASE01 / "firmware.s19", p / "firmware.s19")
    if a2l:
        shutil.copy2(CASE01 / "firmware.a2l", p / "firmware.a2l")
    (p / "project.json").write_text(json.dumps({"schema_version": 1, "active_variant": "firmware"}), encoding="utf-8")
    return p


async def run_case(tag, body, size=(118, 54)):
    base = Path(tempfile.mkdtemp(prefix="p12a_", dir=os.environ.get("P12A_TMP")))
    app = S19TuiApp(base_dir=base)
    async with app.run_test(size=size) as pilot:
        await flush(pilot)
        await body(app, pilot, base)
    shutil.rmtree(base, ignore_errors=True)


# ---------------------------------------------------------------- U1 actions
async def u1_file_load(app, pilot, base):
    rec = Rec(app)
    app.load_from_path(CASE01 / "firmware.s19")
    await settle(app, pilot)
    report("U1.1 file_load success", rec, app)
    rec = Rec(app)
    orig_p = S19TuiApp._parse_loaded_file

    def pboom(self, path, a2l_files=None):
        raise RuntimeError("synthetic parse failure")

    S19TuiApp._parse_loaded_file = pboom
    try:
        app.load_from_path(CASE01 / "firmware.s19")
        await settle(app, pilot)
    finally:
        S19TuiApp._parse_loaded_file = orig_p
    report("U1.2 file_load failure (parse raises -> _handle_load_error)", rec, app)
    rec = Rec(app)
    orig = app_mod.copy_into_workarea

    def boom(*a, **k):
        raise workspace.WorkareaContainmentError("synthetic containment refusal")

    app_mod.copy_into_workarea = boom
    try:
        app.load_from_path(CASE01 / "firmware.s19")
    finally:
        app_mod.copy_into_workarea = orig
    await settle(app, pilot)
    report("U1.3 file_load failure (copy refused)", rec, app)


async def u1_a2l(app, pilot, base):
    rec = Rec(app)
    app.load_a2l_from_path(CASE01 / "firmware.a2l")
    await settle(app, pilot)
    report("U1.4 a2l_load success", rec, app)
    rec = Rec(app)
    orig = S19TuiApp._load_a2l_data_with_cache

    def boom(self, path):
        raise RuntimeError("synthetic A2L parse failure")

    S19TuiApp._load_a2l_data_with_cache = boom
    exc = None
    try:
        app.load_a2l_from_path(CASE01 / "firmware.a2l")
    except Exception as e:  # noqa: BLE001
        exc = e
    finally:
        S19TuiApp._load_a2l_data_with_cache = orig
    await settle(app, pilot)
    report("U1.5 a2l_load failure (parse raises)", rec, app, exc)


async def u1_project(app, pilot, base):
    make_project(app, "P", a2l=True)
    rec = Rec(app)
    app._handle_load_project("P")
    await settle(app, pilot)
    report("U1.6 project_load success", rec, app)
    q = app.workarea / "Q"
    q.mkdir()
    (q / "project.json").write_text(json.dumps({"schema_version": 1}), encoding="utf-8")
    rec = Rec(app)
    app._handle_load_project("Q")
    await settle(app, pilot)
    report("U1.7 project_load failure (manifest only: no data or A2L)", rec, app)
    # the E13 wa-files seed (B9): project.json without `files`
    check_project_files = app_mod.check_project_files
    read_project_manifest = app_mod.read_project_manifest
    r = app.workarea / "R"
    r.mkdir()
    shutil.copy2(CASE01 / "firmware.s19", r / "firmware.s19")
    (r / "project.json").write_text(json.dumps({"schema_version": 1, "active_variant": "firmware"}), encoding="utf-8")
    probs = check_project_files(r, read_project_manifest(r))
    print("== U1.8 B9 wa-files seed problems", [(p.kind, p.file, p.code) for p in probs])


async def u1_save(app, pilot, base):
    app.load_from_path(CASE01 / "firmware.s19")
    await settle(app, pilot)
    rec = Rec(app)
    app._handle_save_dialog(SaveProjectPayload(str(app.workarea), "S1"))
    await settle(app, pilot)
    report("U1.9 save_project success", rec, app)
    rec = Rec(app)
    orig = app_mod.place_into_workarea

    def boom(*a, **k):
        raise OSError(28, "synthetic no space")

    app_mod.place_into_workarea = boom
    exc = None
    try:
        app._handle_save_dialog(SaveProjectPayload(str(app.workarea), "S2"))
    except Exception as e:  # noqa: BLE001
        exc = e
    finally:
        app_mod.place_into_workarea = orig
    await settle(app, pilot)
    report("U1.10 save_project failure (placement OSError after mkdir)", rec, app, exc)
    print("   S2 exists after failure:", (app.workarea / "S2").exists())


async def u1_report(app, pilot, base):
    from tests.test_tui_report_seam import _generate_through_surface, _make_report_project
    _make_report_project(app, "proj")
    await flush(pilot)
    app._handle_load_project("proj")
    await settle(app, pilot)
    rec = Rec(app)
    await _generate_through_surface(app, pilot)
    report("U1.11 report success", rec, app)
    orig = app_mod.generate_project_report

    def boom(*a, **k):
        raise RuntimeError("synthetic report failure")

    app_mod.generate_project_report = boom
    rec = Rec(app)
    try:
        await _generate_through_surface(app, pilot)
    finally:
        app_mod.generate_project_report = orig
    report("U1.12 report failure (generator raises)", rec, app)


async def u1_diff(app, pilot, base):
    from s19_app.tui.screens_directionb import AbDiffPanel  # noqa: F401

    class R:  # minimal written result
        def __init__(self, written, path=None, diagnostics=()):
            self.written, self.path, self.diagnostics = written, path, list(diagnostics)

    panel = app.query_one("#ab_diff_panel")
    for tag, md, html in (("U1.13 diff_report success", R(True, base / "d.md"), R(True, base / "d.html")),
                          ("U1.14 diff_report failure (markdown refused)", R(False, diagnostics=["synthetic"]), None)):
        om, oh = app_mod.generate_diff_report, app_mod.generate_diff_report_html
        app_mod.generate_diff_report = lambda result, **k: md
        app_mod.generate_diff_report_html = lambda result, **k: html
        rec = Rec(app)
        try:
            app.set_progress(15)  # what on_ab_diff_panel_report_requested does before dispatch
            app._start_diff_report_worker(panel, object(), {}, "-")
            await settle(app, pilot)
        finally:
            app_mod.generate_diff_report, app_mod.generate_diff_report_html = om, oh
        report(tag, rec, app)


async def u1_before_after(app, pilot, base):
    rec = Rec(app)
    app.action_before_after_report()
    await settle(app, pilot)
    report("U1.15 before_after refused (nothing loaded)", rec, app)

    class Res:
        written, md_path, html_path, diagnostics = True, base / "ba.md", base / "ba.html", ()

    orig = app_mod.compose_before_after_report
    app_mod.compose_before_after_report = lambda *a, **k: Res()
    rec = Rec(app)
    try:
        app.action_before_after_report()
        await settle(app, pilot)
    finally:
        app_mod.compose_before_after_report = orig
    report("U1.16 before_after success (composer stubbed)", rec, app)


# ---------------------------------------------------------------- U2 sweep
async def u2_sweep(app, pilot, base):
    temp = app.workarea / workspace.WORKAREA_TEMP
    temp.mkdir(parents=True, exist_ok=True)
    for n in ("a.s19", "b.hex", "c.mac", "d.a2l", "d.a2l.json", "e.txt"):
        (temp / n).write_text("x", encoding="utf-8")
    app.refresh_files()
    await flush(pilot)
    rows = [it.data for it in app.query_one("#files_list").children]
    print("== U2.1 refresh_files rows", rows)
    for n in ("a.s19", "b.hex", "c.mac", "d.a2l", "d.a2l.json", "e.txt"):
        (temp / n).unlink()

    calls = []
    orig_parse = S19TuiApp._parse_loaded_file

    def spy_parse(self, path, a2l_files=None):
        calls.append(Path(path).name)
        return orig_parse(self, path, a2l_files)

    S19TuiApp._parse_loaded_file = spy_parse
    try:
        # (a) a folder named fw.s19 where a file was listed
        (temp / "fw.s19").mkdir()
        item = ListItem(Label("fw.s19"))
        item.data = "fw.s19"
        rec = Rec(app)
        exc = None
        try:
            app._load_from_item(item)
            await settle(app, pilot)
        except Exception as e:  # noqa: BLE001
            exc = e
        print(f"== U2.2 pick folder fw.s19 -> parse calls {calls} exc={type(exc).__name__ if exc else None} log+ {rec.lines()}")
        (temp / "fw.s19").rmdir()
        calls.clear()
        # (b) a junction named fw.s19 to a folder outside the work area
        outside = base / "outside_dir"
        outside.mkdir()
        made = "no"
        if os.name == "nt":
            r = subprocess.run(["cmd", "/c", "mklink", "/J", str(temp / "fw.s19"), str(outside)],
                               capture_output=True, text=True)
            made = "yes" if r.returncode == 0 else f"no ({r.stdout.strip()} {r.stderr.strip()})"
        if made == "yes":
            rec = Rec(app)
            exc = None
            try:
                app._load_from_item(item)
                await settle(app, pilot)
            except Exception as e:  # noqa: BLE001
                exc = e
            print(f"== U2.3 pick junction fw.s19 -> parse calls {calls} exc={type(exc).__name__ if exc else None} log+ {rec.lines()}")
            os.rmdir(temp / "fw.s19")
        else:
            print("== U2.3 junction not made:", made)
        calls.clear()
        # (c) a file symbolic link to a file outside the work area
        target = base / "outside.s19"
        write_s19(target)
        try:
            os.symlink(target, temp / "fw.s19")
            rec = Rec(app)
            app._load_from_item(item)
            await settle(app, pilot)
            print(f"== U2.4 pick file symlink fw.s19 -> parse calls {calls} current_file={getattr(app.current_file, 'path', None)}")
            (temp / "fw.s19").unlink()
        except OSError as e:
            print("== U2.4 file symlink not made (not run):", type(e).__name__, getattr(e, "winerror", ""))
        calls.clear()
        # LLR-172.6c: cap and cap + 1
        old_cap = workspace.DEFAULT_COPY_SIZE_CAP_BYTES
        workspace.DEFAULT_COPY_SIZE_CAP_BYTES = 1024
        try:
            for name, size in (("edge.s19", 1024), ("big.s19", 1025)):
                write_s19(temp / name, size)
                it = ListItem(Label(name))
                it.data = name
                app._load_from_item(it)
                await settle(app, pilot)
            print(f"== U2.5 cap 1024: picks edge.s19 (1024 B) big.s19 (1025 B) -> parse calls {calls}")
        finally:
            workspace.DEFAULT_COPY_SIZE_CAP_BYTES = old_cap
    finally:
        S19TuiApp._parse_loaded_file = orig_parse

    # LLR-172.5i: NUL in typed text
    for text in ("fw\x00.s19", str(base / "fw\x00.s19")):
        try:
            r = app._typed_load_route(Path(text))
            print(f"== U2.6 _typed_load_route({text!r}) -> {r}")
        except Exception as e:  # noqa: BLE001
            print(f"== U2.6 _typed_load_route({text!r}) raises {type(e).__name__}: {e}")
        try:
            app._load_path_from_user_input(Path(text))
            print(f"== U2.7 _load_path_from_user_input({text!r}) -> returned")
        except Exception as e:  # noqa: BLE001
            print(f"== U2.7 _load_path_from_user_input({text!r}) raises {type(e).__name__}")

    # LLR-172.4e: trailing dot / space folders (Windows arm via \\?\)
    for n in ("fw-v1.", "fw-v2 "):
        p = "\\\\?\\" + str(app.workarea / n) if os.name == "nt" else str(app.workarea / n)
        os.makedirs(p, exist_ok=True)
        with open(p + ("\\" if os.name == "nt" else "/") + "project.json", "w", encoding="utf-8") as fh:
            fh.write('{"schema_version": 1}')
    make_project(app, "P")
    print("== U2.8 list_projects with 'fw-v1.', 'fw-v2 ', 'P' on", os.name, "->", app.list_projects())


# ---------------------------------------------------------------- U3 labels / timers
async def u3_labels(app, pilot, base):
    entries = [(e.label, e.action) for e in app._build_palette_entries()]
    print("== U3.1 palette load entries", [e for e in entries if e[1] in ("load_file", "load_project")])
    descs = [(b.key, b.action, b.description) for b in app.BINDINGS if not isinstance(b, tuple)
             and b.action in ("load_file", "load_project")]
    print("== U3.2 bindings", descs)
    print("== U3.3 timers attribute", type(getattr(app, "_timers", None)).__name__,
          "count", len(getattr(app, "_timers", ()) or ()))
    print("== U3.4 status_line height", app.query_one("#status_line").region.height,
          "progress_bar", app.query_one("#progress_bar").region, "log_line_1 y", app.query_one("#log_line_1").region.y)


def u4_ast():
    src = (TREE / "s19_app" / "tui" / "app.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    out = {}
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        doc = ast.get_docstring(fn, clean=False)
        for n in ast.walk(fn):
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value != doc:
                for tok in ("could not be read", "could not be ", "not a project", "is not a "):
                    if tok in n.value:
                        out.setdefault(fn.name, []).append((n.lineno, tok, n.value[:60]))
    print("== U4.1 refusal literal sites (docstrings excluded)")
    for k, v in sorted(out.items()):
        print("  ", k, v)


async def main():
    for body in (u1_file_load, u1_a2l, u1_project, u1_save, u1_report, u1_diff, u1_before_after,
                 u2_sweep, u3_labels):
        try:
            await run_case(body.__name__, body)
        except Exception as e:  # noqa: BLE001
            print(f"!! {body.__name__} crashed: {type(e).__name__}: {e}")
    u4_ast()


asyncio.run(main())
