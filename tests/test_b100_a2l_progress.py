"""batch-100 Inc 12b — the A2L parser's byte callback and the main-thread steps.

Summary:
    Independent tests (E4 tester) for TC-B100-73 (LLR-176.4, LLR-176.4a,
    LLR-176.4b: ``parse_a2l_file(path, progress=None)`` reports the bytes it
    has consumed, the result does not depend on the callback, and
    ``s19_app/tui/a2l.py`` is back in the frozen-engine guard) and
    TC-B100-52 (LLR-176.3: a step that runs on the main thread paints its
    name before its work). Oracles: the Inc 12b design files
    (``inc-12b/E1-requirements-draft.md`` §B2, ``codewire/interfaces-12b.md``
    S-f / S-g, ``codewire/proto-12b-a2l-refusal.md`` D12b-01 … D12b-08 and
    C12b-34, ``codewire/proto-12b-load-save.md`` P1-26); never the code.

    Why this matters (US-166, US-167): the case_06 parse is 5 s on a worker;
    without byte reports the bar would not move inside it, and a report
    stream that changed the parse result would corrupt every A2L the app
    reads. The tag-table build and the project install stay on the main
    thread (HLR-176's declared freeze); painting their step name FIRST is
    what tells the engineer what the frozen second is.

Dependencies:
    Uses:
        - ``s19_app.tui.a2l`` (``parse_a2l_file``, ``build_section_tree``)
        - ``tests.test_engine_unchanged._ENGINE_PATHS``
        - ``tests.support.b100_projects`` (``run_app``)
        - ``tests.support.b100_workers.settle_workers``
"""

from __future__ import annotations

import ast
import re
import shutil
from pathlib import Path

import pytest

import s19_app.tui.app as app_module
from s19_app.tui import a2l as a2l_module
from s19_app.tui.app import S19TuiApp
from s19_app.tui.workspace import WORKAREA_DIRNAME, WORKAREA_SUBDIR

from tests.support import b100_projects as projects
from tests.support.b100_workers import settle_workers

ROOT = Path(__file__).resolve().parents[1]
CASE01_A2L = ROOT / "examples" / "case_01_basic_valid" / "firmware.a2l"
CASE06 = ROOT / "examples" / "case_06_large_nested_a2l"
CASE06_A2L = CASE06 / "firmware.a2l"
FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
SIZE = (118, 54)


def _parse_with(path: Path, progress):
    """Call the parse entry point with a callback; a base without the
    parameter fails here as a behaviour (it cannot report), not as an
    import error."""
    try:
        return a2l_module.parse_a2l_file(path, progress=progress)
    except TypeError as exc:
        pytest.fail(f"parse_a2l_file takes no progress callback: {exc}")


def _recorder():
    seen: list = []
    return seen, (lambda done, total: seen.append((done, total)))


# ===========================================================================
# TC-B100-73 — the parser's byte callback (LLR-176.4, LLR-176.4a, LLR-176.4b)
# ===========================================================================


def test_tc_b100_73_case06_reports_bytes_and_parses_the_same(tmp_path: Path) -> None:
    """LLR-176.4, LLR-176.4a (D12b-01, D12b-04): the case_06 A2L (37 742 888
    bytes, 1 039 926 lines) parsed with a recording callback → at least 2
    calls, every ``total`` equal to the file size, the consumed values
    non-decreasing, the first report strictly inside the file
    (``0 < done < size``: it counts what the read has consumed, not the
    size), the last report ``(size, size)``, and no more reports
    than one per 4 096 lines plus the final one (ruling Q-f1); the result
    equals the result of the same parse with no callback (tag count and
    every parsed field).

    Why: the bar of the 5 s parse moves only by these reports; a callback
    that changed the result would corrupt the A2L the app reads.
    Negative control (code read, base): ``parse_a2l_file(path)`` takes no
    callback → RED; a mutant that reports only once at the end → 1 call →
    RED; a mutant that adds a field when a callback is given → unequal →
    RED; E5 round 2 (mutant 110): a mutant that reports the size as the
    consumed bytes → the first report reads ``(size, size)`` → RED."""
    size = CASE06_A2L.stat().st_size
    seen, progress = _recorder()
    with_cb = _parse_with(CASE06_A2L, progress)
    without = a2l_module.parse_a2l_file(CASE06_A2L)
    assert len(seen) >= 2, len(seen)
    assert all(total == size for _done, total in seen), {t for _d, t in seen}
    dones = [d for d, _t in seen]
    assert dones == sorted(dones), "consumed bytes went down"
    assert 0 < seen[0][0] < size, seen[0]
    assert seen[-1] == (size, size), seen[-1]
    lines = sum(1 for _ in CASE06_A2L.open("rb"))
    assert len(seen) <= lines // 4096 + 1, (len(seen), lines)
    assert len(with_cb.get("tags", [])) == len(without.get("tags", [])) > 0
    assert with_cb == without


def test_tc_b100_73_small_a2l_reports_once_and_parses_the_same(tmp_path: Path) -> None:
    """LLR-176.4 boundary, LLR-176.4a (D12b-02, D12b-04): case_01's A2L
    (1 444 bytes, 53 lines — smaller than one progress chunk) → exactly one
    report ``(1444, 1444)``; the result equals the parse with no callback.

    Why: a small A2L must still finish its step (the bar's final report).
    Negative control: no final report → 0 calls → RED; base: no callback →
    RED."""
    seen, progress = _recorder()
    with_cb = _parse_with(CASE01_A2L, progress)
    assert seen == [(1444, 1444)], seen
    assert with_cb == a2l_module.parse_a2l_file(CASE01_A2L)


def test_tc_b100_73_no_report_without_a_file_and_none_without_a_callback(tmp_path: Path) -> None:
    """LLR-176.4 (empty), LLR-176.4a (D12b-03): a missing file with a
    callback → ``errors == ['File not found.']`` from the tree read and 0
    reports; ``build_section_tree`` with no callback returns the same
    sections and errors as with one.

    Why: a report from a failed open would move the bar for a file that
    was never read. Negative control: base has no callback parameter →
    RED."""
    seen, progress = _recorder()
    try:
        sections, errors = a2l_module.build_section_tree(tmp_path / "missing.a2l", progress)
    except TypeError as exc:
        pytest.fail(f"build_section_tree takes no progress callback: {exc}")
    assert errors == ["File not found."] and seen == [], (errors, seen)
    plain = a2l_module.build_section_tree(CASE01_A2L)
    reported = a2l_module.build_section_tree(CASE01_A2L, progress)
    assert plain == reported


def test_tc_b100_73_a_failed_read_reports_no_final_total(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-176.4 (D12b-06): a 6 000-line A2L whose read raises
    ``OSError(5)`` at line 5 000 → the ``OSError`` still leaves
    ``build_section_tree`` (unchanged), the callback saw exactly one report
    (at line 4 096) and never the final ``(total, total)``.

    Why: a final report after a failed read would fill the bar for a parse
    that did not complete. Negative control: a final report in a
    ``finally`` → ``(total, total)`` after the failure → RED; base: no
    callback → RED."""
    path = tmp_path / "six.a2l"
    body = "/begin PROJECT P \"\"\n" + "".join(f"/* line {i} */\n" for i in range(5998)) + "/end PROJECT\n"
    path.write_text(body, encoding="utf-8")
    size = path.stat().st_size
    real_open = Path.open

    class _Failing:
        def __init__(self, handle):
            self._h = handle

        def __getattr__(self, name):
            return getattr(self._h, name)

        def __enter__(self):
            self._h.__enter__()
            return self

        def __exit__(self, *exc):
            return self._h.__exit__(*exc)

        def __iter__(self):
            for number, line in enumerate(self._h, 1):
                if number == 5000:
                    raise OSError(5, "synthetic read error")
                yield line

    def _open(self, *args, **kwargs):
        handle = real_open(self, *args, **kwargs)
        if self == path:
            return _Failing(handle)
        return handle

    monkeypatch.setattr(Path, "open", _open)
    seen, progress = _recorder()
    with pytest.raises(OSError):
        try:
            a2l_module.build_section_tree(path, progress)
        except TypeError as exc:
            pytest.fail(f"build_section_tree takes no progress callback: {exc}")
    assert len(seen) == 1, seen
    assert seen[0][1] == size and seen[0][0] < size, seen


def test_tc_b100_73_one_argument_callers_outside_the_app_are_unchanged() -> None:
    """LLR-176.4 (D12b-08), interfaces S-f: every ``parse_a2l_file(`` call
    in ``s19_app/`` outside ``app.py`` passes exactly 1 positional argument
    and no keyword, and the entry point's second parameter defaults to
    ``None`` (an optional callback).

    Why: four services call it with one argument; a required second
    parameter would break them. Negative control: a signature
    ``parse_a2l_file(path, progress)`` with no default → RED; base: no
    second parameter → RED."""
    import inspect

    params = list(inspect.signature(a2l_module.parse_a2l_file).parameters.values())
    assert len(params) >= 2 and params[1].name == "progress" and params[1].default is None, params
    bad = []
    for source in (ROOT / "s19_app").rglob("*.py"):
        if source.name == "app.py" or source.name == "a2l.py":
            continue
        tree = ast.parse(source.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", None)
                if name == "parse_a2l_file" and (len(node.args) != 1 or node.keywords):
                    bad.append(f"{source.relative_to(ROOT)}:{node.lineno}")
    assert bad == [], bad


def test_tc_b100_73_a2l_py_is_listed_in_the_frozen_engine_guard() -> None:
    """LLR-176.4b (D12b-05): ``s19_app/tui/a2l.py`` is an entry of
    ``tests/test_engine_unchanged.py::_ENGINE_PATHS`` again (1 assertion).
    TC-027 itself compares against ``main``, where ``a2l.py`` differs until
    the increment merges, so its full run is owed after the merge
    (declared, E1 LLR-176.4b note).

    Why: the parser is a frozen engine; 12b's crossing is named and then
    closed again. Negative control (code read, base): the entry is commented
    out since batch-95 → RED."""
    from tests.test_engine_unchanged import _ENGINE_PATHS

    assert "s19_app/tui/a2l.py" in _ENGINE_PATHS, sorted(_ENGINE_PATHS)


# ===========================================================================
# TC-B100-52 — a main-thread step paints its name before its work (LLR-176.3)
# ===========================================================================


def _status(app) -> str:
    return str(app.query_one("#status_text").render())


def _probe_step(monkeypatch, key: str, n: int, seen: list, started: dict):
    """Wrap ``step_busy``: right after the real call for ``key`` step ``n``,
    schedule a read of ``#status_text`` with ``call_after_refresh`` — it
    runs after the next refresh, before any work queued behind it."""
    real = S19TuiApp.step_busy

    def _step(app, k, gen, step, done=None, total=None):
        result = real(app, k, gen, step, done, total)
        if k == key and step == n and done is None:
            app.call_after_refresh(lambda: seen.append((_status(app), dict(started))))
        return result

    monkeypatch.setattr(S19TuiApp, "step_busy", _step)


def test_tc_b100_52_a2l_tag_table_step_is_painted_before_the_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-176.3 (A2L arm) (C12b-34): the case_06 A2L attach → a read of
    ``#status_text`` scheduled with ``call_after_refresh`` right after the
    step-3 call reads ``<glyph> Loading firmware.a2l · step 3/3 Build the
    tag table · <mm:ss>``, and the tag-table build had not started.

    Why: the ~3.5 s tag-table build blocks the loop by design (HLR-176);
    the user must see what is happening before it starts.
    Negative control: the install called directly → the read comes after
    the build and the end → it reads the file state → RED (base: the build
    runs in the same frame as the step)."""
    seen: list = []
    started = {"build": False}
    _probe_step(monkeypatch, "a2l_load", 3, seen, started)
    real_view = S19TuiApp.update_a2l_view

    def _view(app, *a, **k):
        started["build"] = True
        return real_view(app, *a, **k)

    monkeypatch.setattr(S19TuiApp, "update_a2l_view", _view)

    async def scenario(app, pilot, log):
        app.load_a2l_from_path(CASE06_A2L)
        for _ in range(3000):
            if app.current_a2l_path is not None and not app._busy.runs:
                break
            await pilot.pause(0.02)
        await settle_workers(pilot)
        return list(seen)

    got = projects.run_app(tmp_path / "app", scenario, size=SIZE)
    assert len(got) == 1, got
    text, flags = got[0]
    assert re.match(r"^[" + FRAMES + r"] Loading firmware\.a2l  ·  step 3/3 Build the tag table  ·  \d\d:\d\d$",
                    text), text
    assert flags == {"build": False}, flags


@pytest.mark.parametrize("case", ["case_06", "case_01"])
def test_tc_b100_52_project_install_step_is_painted_before_the_install(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    """LLR-176.3 (project arm, and the small arm) (P1-26): a project of the
    case's image, MAC and A2L → a read of ``#status_text`` scheduled right
    after the ``project_load`` step-4 call reads ``<glyph> Loading project
    P · step 4/4 Install · <mm:ss>`` and the install had not started
    (``_install_prepared_project`` not entered).

    Why: the install is the main-thread step of a project load; painted
    after it, the user would never see it named.
    Negative control: an install called directly → the read sees
    ``Loaded project 'P' -> …`` → RED (base: the install runs in the frame
    of step 4)."""
    seen: list = []
    started = {"install": False}
    _probe_step(monkeypatch, "project_load", 4, seen, started)
    real_install = getattr(S19TuiApp, "_install_prepared_project", None)

    if real_install is not None:
        def _install(app, *a, **k):
            started["install"] = True
            return real_install(app, *a, **k)

        monkeypatch.setattr(S19TuiApp, "_install_prepared_project", _install)
    else:
        real_apply = S19TuiApp._apply_loaded_file

        def _apply(app, *a, **k):
            started["install"] = True
            return real_apply(app, *a, **k)

        monkeypatch.setattr(S19TuiApp, "_apply_loaded_file", _apply)

    source = CASE06 if case == "case_06" else ROOT / "examples" / "case_01_basic_valid"
    base = tmp_path / "app"
    project = base / WORKAREA_DIRNAME / WORKAREA_SUBDIR / "P"
    project.mkdir(parents=True)
    for name in ("firmware.s19", "firmware.mac", "firmware.a2l"):
        shutil.copyfile(source / name, project / name)

    async def scenario(app, pilot, log):
        app._handle_load_project("P")
        for _ in range(6000):
            if app.current_project == "P" and not app._busy.runs:
                break
            await pilot.pause(0.02)
        await settle_workers(pilot)
        return list(seen)

    got = projects.run_app(base, scenario, size=SIZE)
    assert len(got) == 1, got
    text, flags = got[0]
    assert re.match(r"^[" + FRAMES + r"] Loading project P  ·  step 4/4 Install  ·  \d\d:\d\d$", text), text
    assert flags == {"install": False}, flags


def test_tc_b100_73_no_fstat_without_a_callback(monkeypatch: pytest.MonkeyPatch) -> None:
    """CR12b-4 (behaviour-neutral, LLR-176.4a): with no callback the read
    makes 0 ``os.fstat`` calls, so a failing ``fstat`` cannot change the
    callback-free parse: ``parse_a2l_file(case_01)`` returns the same
    result as before the stand-in was installed. With a callback the same
    stand-in is called exactly once (the size the reports carry) — the
    positive control that the stand-in sits on the read's path.

    Why: the callback-free parse is the one every caller outside the app
    uses; it must stay the base parse. Negative control (81ac4c0): ``fstat``
    runs with no callback -> the raise is logged and re-raised -> RED."""
    import os as real_os

    expected = a2l_module.parse_a2l_file(CASE01_A2L)
    calls: list = []

    class _Os:
        def __getattr__(self, name):
            return getattr(real_os, name)

        @staticmethod
        def fstat(fd):
            calls.append(fd)
            raise OSError(5, "synthetic fstat failure")

    monkeypatch.setattr(a2l_module, "os", _Os())
    assert a2l_module.parse_a2l_file(CASE01_A2L) == expected
    assert calls == [], calls
    with pytest.raises(OSError):
        a2l_module.build_section_tree(CASE01_A2L, lambda done, total: None)
    assert len(calls) == 1, calls
