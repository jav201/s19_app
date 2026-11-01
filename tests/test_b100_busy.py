"""batch-100 Inc 12a — the progress indicator (TC-B100-50, TC-B100-51, AT-B100-17 12a half).

Summary:
    Independent tests (E4 tester) for the one progress seam
    (``begin_busy`` / ``step_busy`` / ``end_busy``), its 0.1 s timer, the
    one stored file-state line and the seven long actions that drive it
    (file load, A2L load, project load, Save project, report, diff report,
    before/after). Every oracle comes from the Inc 12a design files
    (``.dev-flow/2026-10-26-batch-100/inc-12a``: ``E1-requirements-draft.md``,
    ``codewire/interfaces-12a.md``, ``codewire/proto-12a-indicator.md`` and the
    E1/E2/E3 rulings); the example ids ``A12-NN`` are that graph's.

    Why this matters (US-166): a long action that paints nothing looks like a
    frozen app, and a bar left at 100 after a load reads as "still working".
    The tests read what the user sees — ``#status_text``, ``#progress_bar``,
    the status log and the running timers — and use spies on the seam only to
    count begins and ends, never to replace behaviour.

Dependencies:
    Uses:
        - ``tests.support.b100_projects`` (``run_app``, ``StatusLog``)
        - ``tests.b97_probes.painted_rows`` (the painted row of a widget)
        - ``tests.test_tui_report_seam`` (the reportable project)
        - ``tests.test_tui_diff_screen._diff_result`` (a comparison)
"""

from __future__ import annotations

import ast
import inspect
import os
import re
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Optional

import pytest

import s19_app.tui.app as app_module
from s19_app.tui.app import S19TuiApp
from s19_app.tui.workspace import WORKAREA_DIRNAME, WORKAREA_SUBDIR, WORKAREA_TEMP

from tests.b97_probes import painted_rows
from tests.conftest import make_large_s19
from tests.support import b100_projects as projects

ROOT = Path(__file__).resolve().parents[1]
CASE01 = ROOT / "examples" / "case_01_basic_valid"
APP_SOURCE = Path(app_module.__file__)
SIZE = (118, 54)
WIN = sys.platform == "win32"

FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
DOT = "  ·  "
#: HLR-176's threshold pattern for any progress line.
LINE_RE = re.compile(
    r"^([" + FRAMES + r"]) (.+)  ·  step (\d+)/(\d+) (.+)  ·  (\d{2,}):(\d{2})$"
)
#: HLR-176's threshold for the FIRST line after a begin.
FIRST_RE = re.compile(r"^[" + FRAMES + r"] .+  ·  step 1/[1-9] .+  ·  00:0[0-9]$")

FILE_STEPS = ("Copy into the work area", "Parse", "Install")
A2L_STEPS = ("Copy into the work area", "Parse", "Build the tag table")
PROJECT_STEPS = ("Check the files", "Parse the A2L", "Parse the image", "Install")
SAVE_STEPS = ("Create the folder", "Place the files", "Gather the project files", "Write project.json")
REPORT_STEPS = ("Prepare the results", "Write the report")
DIFF_STEPS = ("Write Markdown", "Write HTML")
BA_STEPS = ("Compose the report",)

#: The fixed action table (interfaces S-c, ruling Q-5 confirmed).
TABLE = {
    "file_load": ("Loading {name}", FILE_STEPS),
    "a2l_load": ("Loading {name}", A2L_STEPS),
    "project_load": ("Loading project {name}", PROJECT_STEPS),
    "save_project": ("Saving project {name}", SAVE_STEPS),
    "report": ("Generating the project report", REPORT_STEPS),
    "diff_report": ("Writing the diff report", DIFF_STEPS),
    "before_after": ("Writing the before/after report", BA_STEPS),
}

ESC_ARM = pytest.mark.skipif(
    WIN, reason="not run on Windows (the name cannot be created), never passed"
)


# ---------------------------------------------------------------------------
# readers, recorders and spies
# ---------------------------------------------------------------------------


def _line(glyph: str, label: str, n: int, m: int, step: str, elapsed: str = "00:00") -> str:
    return f"{glyph} {label}{DOT}step {n}/{m} {step}{DOT}{elapsed}"


def _status(app) -> str:
    """``#status_text`` as the user reads it (the plain rendered text)."""
    return str(app.query_one("#status_text").render())


#: A C0 or C1 control code point (what ``safe_text`` removes).
CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _log_widgets(app) -> list:
    """The four painted status-log rows ``#log_line_1..4``."""
    return [str(app.query_one(f"#log_line_{i}").render()) for i in range(1, 5)]


def _bar(app) -> tuple:
    from textual.widgets import ProgressBar

    bar = app.query_one("#progress_bar", ProgressBar)
    return bar.progress, bar.total


def _bar_row(app) -> list:
    return [row.rstrip() for row in painted_rows(app, app.query_one("#progress_bar"))]


def _busy_timers(app) -> list:
    """The running 0.1 s interval timers the app owns (LLR-176.1e): Textual
    keeps a stopped timer in ``_timers`` until its task is collected, so a
    timer counts only while its task exists (F-5)."""
    found = []
    for owner in (app, app.query_one("#status_text")):
        for timer in list(getattr(owner, "_timers", ())):
            interval = getattr(timer, "_interval", None)
            if getattr(timer, "_task", None) is not None and interval is not None and abs(interval - 0.1) < 1e-9:
                found.append(timer)
    return found


def _is_progress(text: str) -> bool:
    return LINE_RE.match(text) is not None


class Painted:
    """Every value written to ``#status_text`` (``Label.update``), in order,
    with the thread that wrote it."""

    def __init__(self, app) -> None:
        self.values: list = []
        self.threads: list = []
        label = app.query_one("#status_text")
        original = label.update

        def _update(content="", *args, **kwargs):
            self.values.append(str(content))
            self.threads.append(threading.get_ident())
            return original(content, *args, **kwargs)

        label.update = _update

    def progress(self, start: int = 0) -> list:
        return [v for v in self.values[start:] if _is_progress(v)]


class Seam:
    """Class-level spies: every bar value written through ``set_progress``
    and, when the seam exists, every begin, step and end with the end's
    return value and the running 0.1 s timers right after it. On a tree
    without the seam only the bar spy is installed, so the bar sequence
    still reads (the base RED is the sequence, not an import error)."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.bar: list = []
        self.begins: list = []
        self.steps: list = []
        self.ends: list = []
        self.order: list = []
        seam = self
        original_bar = S19TuiApp.set_progress

        def _set_progress(app, value, message=None):
            seam.bar.append(value)
            return original_bar(app, value, message)

        monkeypatch.setattr(S19TuiApp, "set_progress", _set_progress)
        begin = getattr(S19TuiApp, "begin_busy", None)
        step = getattr(S19TuiApp, "step_busy", None)
        end = getattr(S19TuiApp, "end_busy", None)
        if begin is not None:

            def _begin(app, key, label, steps):
                gen = begin(app, key, label, steps)
                seam.begins.append((key, label, tuple(steps), gen))
                seam.order.append(("begin", key))
                return gen

            monkeypatch.setattr(S19TuiApp, "begin_busy", _begin)
        if step is not None:

            def _step(app, key, gen, n, done=None, total=None):
                seam.steps.append((key, gen, n, done, total))
                return step(app, key, gen, n, done, total)

            monkeypatch.setattr(S19TuiApp, "step_busy", _step)
        if end is not None:

            def _end(app, key, gen, outcome):
                result = end(app, key, gen, outcome)
                seam.ends.append(
                    SimpleNamespace(
                        key=key, gen=gen, outcome=outcome, result=result,
                        timers=len(_busy_timers(app)), status=_status(app),
                    )
                )
                seam.order.append(("end", key))
                return result

            monkeypatch.setattr(S19TuiApp, "end_busy", _end)

    def effective(self, key: Optional[str] = None) -> list:
        return [e for e in self.ends if e.result is True and (key is None or e.key == key)]

    def step_numbers(self, key: str) -> list:
        return [n for k, _g, n, _d, _t in self.steps if k == key]


def _run(base: Path, scenario, size: tuple = SIZE):
    return projects.run_app(base, scenario, size=size)


async def _settle(pilot, n: int = 6) -> None:
    for _ in range(n):
        await pilot.pause()


async def _wait(pilot, predicate, what: str, attempts: int = 600) -> None:
    for _ in range(attempts):
        if predicate():
            return
        await pilot.pause()
    raise AssertionError(f"timed out waiting for {what}")


async def _drain(app, pilot) -> None:
    await app.workers.wait_for_complete()
    await _settle(pilot, 4)


def _workarea(base: Path) -> Path:
    return base / WORKAREA_DIRNAME / WORKAREA_SUBDIR


def _copy_case01(folder: Path, *names: str) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    for name in names:
        (folder / name).write_bytes((CASE01 / name).read_bytes())
    return folder


def _project_p(base: Path, *, a2l: bool = True, name: str = "P") -> Path:
    """Project ``P`` in the work area: ``firmware.s19`` (and ``firmware.a2l``)
    plus a ``project.json`` without ``files`` (probe p12a U1.6)."""
    import json

    names = ("firmware.s19", "firmware.a2l") if a2l else ("firmware.s19",)
    folder = _copy_case01(_workarea(base) / name, *names)
    (folder / "project.json").write_text(json.dumps({"schema_version": 1}), encoding="utf-8")
    return folder


def _new_app(tmp_path: Path) -> S19TuiApp:
    return S19TuiApp(base_dir=tmp_path / "app")


# ===========================================================================
# TC-B100-50 — the seam: begin, steps, timer, end (LLR-176.1 … LLR-176.1s)
# ===========================================================================


def test_tc_b100_50_begin_paints_the_first_progress_line(tmp_path: Path) -> None:
    """LLR-176.1, HLR-176 (A12-01, A12-02): a begin paints, in the same
    frame, ``⠋ <label>  ·  step 1/<m> <first step>  ·  00:00`` and returns
    the run's generation; a 1-step run paints ``step 1/1``.

    Why: the first line is the user's only sign that the action started; a
    line that waits for the first tick leaves a blank 0.1 s at best.
    RED (base, P12a-2): no progress line exists (no ``begin_busy``)."""

    async def scenario(app, pilot, log):
        gen = app.begin_busy("file_load", "Loading x.s19", FILE_STEPS)
        first = _status(app)
        app.end_busy("file_load", gen, "")
        await _settle(pilot, 2)
        gen2 = app.begin_busy("before_after", "Writing the before/after report", BA_STEPS)
        second = _status(app)
        app.end_busy("before_after", gen2, "")
        return gen, first, gen2, second

    gen, first, gen2, second = _run(tmp_path / "app", scenario)
    assert first == _line(FRAMES[0], "Loading x.s19", 1, 3, "Copy into the work area"), first
    assert gen == 1, gen
    assert second == _line(FRAMES[0], "Writing the before/after report", 1, 1, "Compose the report"), second
    assert gen2 == gen + 1, (gen, gen2)


def test_tc_b100_50_long_label_stays_on_one_row(tmp_path: Path) -> None:
    """LLR-176.1 boundary (A12-03, E2 ruling G-A P-3): a 200-character label
    → ``#status_text`` holds the whole line, its region is 1 row high, and
    the visible row ends in ``…`` (clipped by the ellipsis, never wrapped).

    Why: a wrapped line inside the one-row status bar shows the user only
    blank padding (probe ga-long).
    RED (base): no ``begin_busy``."""
    label = "Loading " + "x" * 188 + ".s19"

    async def scenario(app, pilot, log):
        gen = app.begin_busy("file_load", label, FILE_STEPS)
        whole = _status(app)
        await _settle(pilot, 3)
        widget = app.query_one("#status_text")
        out = (whole, widget.region.height, painted_rows(app, widget))
        app.end_busy("file_load", gen, "")
        return out

    whole, height, rows = _run(tmp_path / "app", scenario)
    assert whole == _line(FRAMES[0], label, 1, 3, "Copy into the work area"), whole
    assert height == 1, (height, rows)
    assert rows and rows[0].rstrip().endswith("…"), rows


def test_tc_b100_50_begin_sets_the_bar_to_zero(tmp_path: Path) -> None:
    """LLR-176.1a (A12-04): the bar at 40 before a begin → 0 of 100 after it.

    Why: a bar that starts where the last action left it reads as that
    action's progress.
    RED (base, P12a-1): the file load begins at 10; no ``begin_busy``."""

    async def scenario(app, pilot, log):
        app.set_progress(40)
        gen = app.begin_busy("report", "R", ("a", "b"))
        out = _bar(app)
        app.end_busy("report", gen, "")
        return out

    assert _run(tmp_path / "app", scenario) == (0, 100)


def test_tc_b100_50_steps_by_index_set_the_bar(tmp_path: Path) -> None:
    """LLR-176.1b (A12-05, A12-06): 4 steps reached in order paint
    ``step 1/4`` … ``step 4/4`` with their names and set the bar to 0, 25,
    50, 75; a 1-step run's step 1 → bar 0; a 3-step run's last step → 66.

    Why: the bar is the user's estimate of how much is left.
    Negative control: a step that paints but leaves the bar → 0, 0, 0, 0.
    RED (base): no seam."""

    async def scenario(app, pilot, log):
        out = []
        g = app.begin_busy("report", "L", ("a", "b", "c", "d"))
        out.append((_status(app), _bar(app)[0]))
        for n in (2, 3, 4):
            app.step_busy("report", g, n)
            out.append((_status(app), _bar(app)[0]))
        app.end_busy("report", g, "")
        g1 = app.begin_busy("before_after", "One", ("only",))
        app.step_busy("before_after", g1, 1)
        one = (_status(app), _bar(app)[0])
        app.end_busy("before_after", g1, "")
        g3 = app.begin_busy("diff_report", "Three", ("a", "b", "c"))
        app.step_busy("diff_report", g3, 3)
        last = (_status(app), _bar(app)[0])
        app.end_busy("diff_report", g3, "")
        return out, one, last

    out, one, last = _run(tmp_path / "app", scenario)
    assert [bar for _t, bar in out] == [0, 25, 50, 75], out
    for (text, _bar_value), (n, name) in zip(out, enumerate("abcd", start=1)):
        assert _line(FRAMES[0], "L", n, 4, name) == text, text
    assert one == (_line(FRAMES[0], "One", 1, 1, "only"), 0), one
    assert last == (_line(FRAMES[0], "Three", 3, 3, "c"), 66), last


def test_tc_b100_50_step_amount_moves_the_bar_within_the_step(tmp_path: Path) -> None:
    """LLR-176.1c, HLR-176b (A12-07; E2 ruling G-A P-2): step 2 of 2 → 50,
    then 1, 2, 3 and 4 MiB of 4 MiB → 62, 75, 87, 100, rising 4 times;
    ``done = 0`` → 50; ``done = total`` → 100.

    Why: the operator's condition on the P-D verdict — "la barra de progreso
    realmente hace su trabajo" — needs the bar to move inside a long step.
    Negative control: amounts ignored → 50, 50, 50, 50. RED (base): no seam."""
    mib = 2**20

    async def scenario(app, pilot, log):
        g = app.begin_busy("report", "L", ("a", "b"))
        app.step_busy("report", g, 2)
        start = _bar(app)[0]
        values = []
        for done in (1, 2, 3, 4):
            app.step_busy("report", g, 2, done * mib, 4 * mib)
            values.append(_bar(app)[0])
        app.end_busy("report", g, "")
        g2 = app.begin_busy("report", "L", ("a", "b"))
        app.step_busy("report", g2, 2, 0, 4 * mib)
        zero = _bar(app)[0]
        app.step_busy("report", g2, 2, 4 * mib, 4 * mib)
        full = _bar(app)[0]
        app.end_busy("report", g2, "")
        return start, values, zero, full

    start, values, zero, full = _run(tmp_path / "app", scenario)
    assert start == 50, start
    assert values == [62, 75, 87, 100], values
    assert all(b > a for a, b in zip([start] + values, values)), values
    assert (zero, full) == (50, 100), (zero, full)


@pytest.mark.parametrize(
    "arm, call, step_text, bar_value",
    [
        ("step 0", (0, None, None), "step 1/3 a", 0),
        ("step m + 1", (4, None, None), "step 3/3 c", 66),
        ("total 0", (2, 5, 0), "step 2/3 b", 50),
        ("total -1", (2, 5, -1), "step 2/3 b", 50),
        ("done -5", (2, -5, 10), "step 2/3 b", 50),
        ("done total + 1", (2, 11, 10), "step 2/3 b", 66),
    ],
)
def test_tc_b100_50_out_of_range_step_data_is_clamped(
    tmp_path: Path, arm: str, call: tuple, step_text: str, bar_value: int
) -> None:
    """LLR-176.1d (A12-08, 6 arms): from step 2 at fraction 0.5 (bar 50), a
    step outside ``1 … m``, a ``total`` of 0 or less, or a ``done`` outside
    ``0 … total`` → 0 exceptions, the painted step clamped into ``1 … 3``,
    the bar within 0 … 100 and, on the same step, never below 50.

    Why: a worker's byte callback is outside the seam's control; one bad
    number must not crash the indicator or move the bar backwards.
    Negative controls: no clamp → ``ZeroDivisionError`` on ``total 0``; no
    max rule → ``done -5`` reads 33. RED (base): no seam."""
    n, done, total = call

    async def scenario(app, pilot, log):
        g = app.begin_busy("report", "L", ("a", "b", "c"))
        app.step_busy("report", g, 2, 1, 2)
        before = _bar(app)[0]
        try:
            app.step_busy("report", g, n, done, total)
            raised = None
        except Exception as exc:  # noqa: BLE001 — the threshold counts raises
            raised = repr(exc)
        out = (before, raised, _status(app), _bar(app)[0])
        app.end_busy("report", g, "")
        return out

    before, raised, text, bar = _run(tmp_path / "app", scenario)
    assert before == 50, before
    assert raised is None, raised
    assert f"{DOT}{step_text}{DOT}" in text, text
    assert bar == bar_value, (arm, bar)
    assert 0 <= bar <= 100


def test_tc_b100_50_spinner_and_elapsed_advance_while_a_worker_runs(tmp_path: Path) -> None:
    """LLR-176.1e, HLR-176a (A12-09): a synthetic worker action of at least
    1.2 s (a plain thread that ends the run through ``call_from_thread``) →
    the painted line takes at least 5 distinct glyphs and the elapsed text
    ``00:00`` then ``00:01``.

    Loaded-host rule: the thread runs at least 1.2 s and then waits until
    ``00:01`` has been painted (at most 8 s), so the assertions read observed
    transitions, never a wall-clock count.
    Why: "so that I do not think the app froze" (US-166).
    RED (base, P12a-2): ``set_interval(`` occurs 0 times; no seam."""

    async def scenario(app, pilot, log):
        painted = Painted(app)
        seen_one = threading.Event()
        done = threading.Event()
        gen = app.begin_busy("report", "Synthetic", ("a", "b"))

        def worker():
            started = time.monotonic()
            time.sleep(1.2)
            seen_one.wait(timeout=max(0.0, 8.0 - (time.monotonic() - started)))
            app.call_from_thread(app.end_busy, "report", gen, "done")
            done.set()

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        for _ in range(400):
            if done.is_set():
                break
            if any(v.endswith(f"{DOT}00:01") for v in painted.values):
                seen_one.set()
            await pilot.pause(0.05)
        thread.join(timeout=10)
        await _settle(pilot, 2)
        return painted.progress()

    lines = _run(tmp_path / "app", scenario)
    glyphs = {LINE_RE.match(v).group(1) for v in lines}
    assert len(glyphs) >= 5, (glyphs, lines[:20])
    elapsed = [f"{LINE_RE.match(v).group(6)}:{LINE_RE.match(v).group(7)}" for v in lines]
    assert "00:00" in elapsed and "00:01" in elapsed, elapsed
    assert elapsed.index("00:00") < elapsed.index("00:01"), elapsed


def test_tc_b100_50_overlapping_runs_share_one_timer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-176.1e (A12-10): two overlapping begins → 1 ``set_interval`` call
    and 1 running 0.1 s timer.

    Why: one timer per run would advance the glyph twice per tick and leak
    timers on every overlap.
    Negative control: a timer per begin → 2. RED (base): no seam."""

    async def scenario(app, pilot, log):
        calls = []
        original = app.set_interval

        def _spy(interval, *args, **kwargs):
            calls.append(interval)
            return original(interval, *args, **kwargs)

        monkeypatch.setattr(app, "set_interval", _spy)
        g1 = app.begin_busy("report", "R", REPORT_STEPS)
        g2 = app.begin_busy("file_load", "Loading x.s19", FILE_STEPS)
        await _settle(pilot, 2)
        out = (list(calls), len(_busy_timers(app)))
        app.end_busy("file_load", g2, "")
        app.end_busy("report", g1, "")
        return out

    calls, timers = _run(tmp_path / "app", scenario)
    assert calls == [0.1], calls
    assert timers == 1, timers


def test_tc_b100_50_action_shorter_than_a_tick(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-176.1e / LLR-176.1f boundary (A12-11): a begin and an end in the
    same frame → 0 ticks, the progress line painted once and then ``Ready.``,
    0 running timers.

    Why: a fast action must leave no spinner behind.
    RED (base): no ``_busy_tick`` / seam."""
    ticks = []
    original = S19TuiApp._busy_tick

    def _tick(self):
        ticks.append(1)
        return original(self)

    monkeypatch.setattr(S19TuiApp, "_busy_tick", _tick)

    async def scenario(app, pilot, log):
        painted = Painted(app)
        gen = app.begin_busy("file_load", "Loading x.s19", FILE_STEPS)
        app.end_busy("file_load", gen, "")
        await _settle(pilot, 3)
        return painted.values, _status(app), len(_busy_timers(app))

    values, final, timers = _run(tmp_path / "app", scenario)
    assert ticks == [], ticks
    assert [v for v in values if _is_progress(v)] == [
        _line(FRAMES[0], "Loading x.s19", 1, 3, "Copy into the work area")
    ], values
    assert final == "Ready.", final
    assert timers == 0, timers


def test_tc_b100_50_last_end_stops_the_timer(tmp_path: Path) -> None:
    """LLR-176.1f (A12-12): after the last end, 0 running progress timers at
    once and after a pause, and ``#status_text`` unchanged 0.5 s later.

    Why: a timer left running repaints a progress line over the final text.
    Negative control: the timer never stopped → the next tick repaints.
    RED (base): no seam."""

    async def scenario(app, pilot, log):
        gen = app.begin_busy("report", "R", REPORT_STEPS)
        await pilot.pause(0.25)
        during = len(_busy_timers(app))
        app.end_busy("report", gen, "done")
        at_once = len(_busy_timers(app))
        text = _status(app)
        await pilot.pause()
        after_pause = len(_busy_timers(app))
        await pilot.pause(0.5)
        return during, at_once, after_pause, text, _status(app)

    during, at_once, after_pause, text, later = _run(tmp_path / "app", scenario)
    assert during == 1, during
    assert (at_once, after_pause) == (0, 0), (at_once, after_pause)
    assert text == "Ready." and later == text, (text, later)


@pytest.mark.parametrize(
    "seconds, expected",
    [(0, "00:00"), (59.9, "00:59"), (60, "01:00"), (3599, "59:59"), (4503, "75:03")],
)
def test_tc_b100_50_elapsed_is_minutes_and_seconds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, seconds: float, expected: str
) -> None:
    """LLR-176.1g (A12-13, injected clock, F-6): elapsed 0, 59.9, 60, 3 599
    and 4 503 s → ``00:00``, ``00:59``, ``01:00``, ``59:59``, ``75:03`` (the
    minutes are not capped at 59). The clock is patched around one
    synchronous ``_busy_line`` call on an app that is not running.

    Why: a load over an hour must not read as a short one.
    Negative control: ``%M:%S`` of a time value → ``15:03``. RED (base): no
    ``_BusyRun`` / ``_busy_line``."""
    app = _new_app(tmp_path)
    run = app_module._BusyRun(1, "L", ("s",), 1, 0.0, 1000.0)
    with monkeypatch.context() as patch:
        patch.setattr(app_module.time, "monotonic", lambda: 1000.0 + seconds)
        text = app._busy_line(run)
    assert text == _line(FRAMES[0], "L", 1, 1, "s", expected), text


def test_tc_b100_50_file_state_waits_while_a_run_is_shown(tmp_path: Path) -> None:
    """LLR-176.1h, HLR-176d (A12-14): during a run, two file-state writes
    change nothing on ``#status_text``; the last end paints the second.
    Boundary: with no run a file-state write is painted at once.

    Why: one owner of the status line (UX-29 / B-11) — P12a-2 shows the file
    state painted over a load that still runs (bar at 50).
    RED (base, P12a-2): ``set_file_status`` paints at once."""

    async def scenario(app, pilot, log):
        gen = app.begin_busy("report", "R", REPORT_STEPS)
        line = _status(app)
        app.set_file_status("A")
        app.set_file_status("B")
        during = _status(app)
        app.end_busy("report", gen, "")
        after = _status(app)
        app.set_file_status("Loaded x.s19 (S19 only)")
        idle = _status(app)
        return line, during, after, idle

    line, during, after, idle = _run(tmp_path / "app", scenario)
    assert _is_progress(line), line
    assert during == line, (line, during)
    assert after == "B", after
    assert idle == "Loaded x.s19 (S19 only)", idle


def test_tc_b100_50_end_writes_the_outcome_to_the_status_log(tmp_path: Path) -> None:
    """LLR-176.1i (A12-15): an end with outcome ``Loaded x.s19`` → the log's
    last line is it and the log gained 1 line; an end with ``""`` or
    ``"   "`` adds none.

    Why: the outcome is the only record of how the action ended once the
    line is cleared. Negative control: the outcome dropped → 0 lines.
    RED (base): no seam."""

    async def scenario(app, pilot, log):
        g = app.begin_busy("file_load", "Loading x.s19", FILE_STEPS)
        mark = len(log.messages)
        app.end_busy("file_load", g, "Loaded x.s19")
        first = (log.since(mark), app.log_lines[-1])
        mark = len(log.messages)
        g2 = app.begin_busy("report", "R", REPORT_STEPS)
        app.end_busy("report", g2, "")
        g3 = app.begin_busy("report", "R", REPORT_STEPS)
        app.end_busy("report", g3, "   ")
        return first, log.since(mark)

    (added, last), empty = _run(tmp_path / "app", scenario)
    assert added == ["Loaded x.s19"], added
    assert last == "Loaded x.s19", last
    assert empty == [], empty


def test_tc_b100_50_last_end_paints_the_stored_file_state(tmp_path: Path) -> None:
    """LLR-176.1j (A12-16, A12a-06): the start-up file state is ``Ready.``;
    a run with no file-state write ends on ``Ready.``; a run with two
    writes ends on the last one.

    Why: the file and project line must survive a long action (LLR-178.2);
    one stored line replaces three hand-back slots.
    RED (base): no seam."""
    project_line = "Loaded project 'P' -> firmware.s19"

    async def scenario(app, pilot, log):
        g = app.begin_busy("report", "R", REPORT_STEPS)
        app.end_busy("report", g, "o")
        bare = _status(app)
        g2 = app.begin_busy("project_load", "Loading project P", PROJECT_STEPS)
        app.set_file_status("Loaded firmware.s19 (S19 only)")
        app.set_file_status(project_line)
        during = _status(app)
        app.end_busy("project_load", g2, "o")
        return bare, during, _status(app)

    bare, during, after = _run(tmp_path / "app", scenario)
    assert bare == "Ready.", bare
    assert _is_progress(during), during
    assert after == project_line, after


def test_tc_b100_50_last_end_clears_the_bar(tmp_path: Path) -> None:
    """LLR-176.1k, HLR-176c (A12-17, A12-18): a run whose last step reported
    100 → after the end, progress 0 of 100 and the painted bar row equals
    the start-up row; a run ended before any step → the same.

    Why: a bar left at 100 reads as "still working" (the stale-100 defect).
    RED (base, P12a-2): the bar ends at 100; no seam."""

    async def scenario(app, pilot, log):
        await _settle(pilot, 2)
        idle_row = _bar_row(app)
        g = app.begin_busy("report", "L", ("a", "b"))
        app.step_busy("report", g, 2, 4, 4)
        full = _bar(app)
        app.end_busy("report", g, "done")
        await _settle(pilot, 3)
        after = (_bar(app), _bar_row(app))
        g2 = app.begin_busy("report", "L", ("a", "b"))
        app.end_busy("report", g2, "Report failed: x")
        await _settle(pilot, 3)
        failed = (_bar(app), _bar_row(app))
        return idle_row, full, after, failed

    idle_row, full, after, failed = _run(tmp_path / "app", scenario)
    assert full == (100, 100), full
    assert after == ((0, 100), idle_row), (after, idle_row)
    assert failed == ((0, 100), idle_row), (failed, idle_row)


@pytest.mark.parametrize("arm", ["end of an unknown key", "step of an unknown key", "end of a replaced run"])
def test_tc_b100_50_unknown_or_replaced_run_leaves_the_indicator(tmp_path: Path, arm: str) -> None:
    """LLR-176.1m (A12-19, A12a-04): against a running file load, an end for
    a key never begun, a step for it, and an end (and a step) from the first
    of two file-load runs → ``#status_text``, the bar and the timer count
    unchanged; the two ends still log their outcome, the step logs nothing.

    Why: ``exclusive=True`` workers can post an end after a newer run began;
    that end must not clear the newer run's indicator, but the log is
    history. Negative control: keyed by the key only → arm 3 clears ``b``.
    RED (base): no seam."""

    async def scenario(app, pilot, log):
        if arm == "end of a replaced run":
            g1 = app.begin_busy("file_load", "Loading a.s19", FILE_STEPS)
            g2 = app.begin_busy("file_load", "Loading b.s19", FILE_STEPS)
        else:
            g2 = app.begin_busy("file_load", "Loading b.s19", FILE_STEPS)
        before = (_status(app), _bar(app), len(_busy_timers(app)))
        mark = len(log.messages)
        if arm == "end of an unknown key":
            result = app.end_busy("diff_report", 99, "x")
        elif arm == "step of an unknown key":
            result = app.step_busy("diff_report", 99, 2)
        else:
            result = app.end_busy("file_load", g1, "Loaded a.s19")
            app.step_busy("file_load", g1, 3)
        after = (_status(app), _bar(app), len(_busy_timers(app)))
        added = log.since(mark)
        app.end_busy("file_load", g2, "")
        return before, after, added, result

    before, after, added, result = _run(tmp_path / "app", scenario)
    assert after == before, (before, after)
    assert before[0] == _line(FRAMES[0], "Loading b.s19", 1, 3, "Copy into the work area"), before
    if arm == "end of an unknown key":
        assert result is False and added == ["x"], (result, added)
    elif arm == "step of an unknown key":
        assert added == [], added
    else:
        assert result is False and added == ["Loaded a.s19"], (result, added)


def test_tc_b100_50_a_newer_action_is_the_one_shown(tmp_path: Path) -> None:
    """LLR-176.1n (A12-20): a report at step 2 (bar 50), then a file load
    begun → the load's line and bar 0; the report's later step changes
    neither. Boundary: a third run is shown; ending it shows the load again.

    Why: the newest action is what the user just asked for.
    Negative control: the first run kept shown → the report's line stays.
    RED (base): no seam."""

    async def scenario(app, pilot, log):
        gr = app.begin_busy("report", "Generating the project report", REPORT_STEPS)
        app.step_busy("report", gr, 2)
        gl = app.begin_busy("file_load", "Loading x.s19", FILE_STEPS)
        shown = (_status(app), _bar(app)[0])
        app.step_busy("report", gr, 2, 3, 4)
        kept = (_status(app), _bar(app)[0])
        gb = app.begin_busy("before_after", "Writing the before/after report", BA_STEPS)
        third = _status(app)
        app.end_busy("before_after", gb, "")
        back = _status(app)
        app.end_busy("file_load", gl, "")
        app.end_busy("report", gr, "")
        return shown, kept, third, back

    shown, kept, third, back = _run(tmp_path / "app", scenario)
    load_line = _line(FRAMES[0], "Loading x.s19", 1, 3, "Copy into the work area")
    assert shown == (load_line, 0), shown
    assert kept == shown, (shown, kept)
    assert "Writing the before/after report" in third and _is_progress(third), third
    assert back == load_line, back


def test_tc_b100_50_the_newest_running_action_is_shown_after_an_end(tmp_path: Path) -> None:
    """LLR-176.1o (A12-21): report at step 2, load begun, load ends → the
    report's line, bar 50, the load's outcome logged, 1 running timer; the
    report then ends → ``Ready.``, bar 0, 0 timers. Boundary: the older run
    ends first → the load stays shown at bar 0.

    Why: a finished action must not hide one that still runs.
    Negative control: the last-end hand-back on any end → ``Ready.`` while
    the report runs. RED (base): no seam."""

    async def scenario(app, pilot, log):
        gr = app.begin_busy("report", "Generating the project report", REPORT_STEPS)
        app.step_busy("report", gr, 2)
        gl = app.begin_busy("file_load", "Loading x.s19", FILE_STEPS)
        app.end_busy("file_load", gl, "Loaded x.s19")
        await _settle(pilot, 2)
        middle = (_status(app), _bar(app)[0], app.log_lines[-1], len(_busy_timers(app)))
        app.end_busy("report", gr, "Report: reports/r.md")
        await _settle(pilot, 2)
        last = (_status(app), _bar(app)[0], len(_busy_timers(app)))
        gr2 = app.begin_busy("report", "Generating the project report", REPORT_STEPS)
        gl2 = app.begin_busy("file_load", "Loading x.s19", FILE_STEPS)
        app.end_busy("report", gr2, "x")
        older = (_status(app), _bar(app)[0])
        app.end_busy("file_load", gl2, "")
        return middle, last, older

    middle, last, older = _run(tmp_path / "app", scenario)
    text, bar, logged, timers = middle
    match = LINE_RE.match(text)
    assert match and match.group(2) == "Generating the project report", text
    assert text.endswith(f"step 2/2 Write the report{DOT}00:00"), text
    assert (bar, logged, timers) == (50, "Loaded x.s19", 1), middle
    assert last == ("Ready.", 0, 0), last
    assert older[0].startswith(f"{older[0][0]} Loading x.s19{DOT}step 1/3"), older
    assert older[1] == 0, older


def test_tc_b100_50_a_begin_under_a_running_key_restarts_it(tmp_path: Path) -> None:
    """LLR-176.1p (A12-22): a file load at ``step 2/3`` showing ``00:01``,
    then a second file-load begin → ``step 1/3`` and ``00:00`` for the new
    name, one run for the key (its end alone clears the indicator), and the
    next generation; the replaced run's end returns ``False``.

    Loaded-host rule: the test waits until ``00:01`` is painted (at most 6 s).
    Why: a restarted load must not show the old load's step or time.
    Negative control: both entries kept → after the second end the old run
    is still shown. RED (base): no seam."""

    async def scenario(app, pilot, log):
        g1 = app.begin_busy("file_load", "Loading a.s19", FILE_STEPS)
        app.step_busy("file_load", g1, 2)
        for _ in range(120):
            if _status(app).endswith(f"step 2/3 Parse{DOT}00:01"):
                break
            await pilot.pause(0.05)
        reached = _status(app)
        g2 = app.begin_busy("file_load", "Loading b.s19", FILE_STEPS)
        restarted = _status(app)
        stale = app.end_busy("file_load", g1, "x")
        app.end_busy("file_load", g2, "")
        await _settle(pilot, 2)
        return g1, g2, reached, restarted, stale, _status(app), len(_busy_timers(app))

    g1, g2, reached, restarted, stale, final, timers = _run(tmp_path / "app", scenario)
    assert reached.endswith(f"step 2/3 Parse{DOT}00:01"), reached
    assert LINE_RE.match(restarted) and restarted.endswith(
        f" Loading b.s19{DOT}step 1/3 Copy into the work area{DOT}00:00"
    ), restarted
    assert g2 == g1 + 1, (g1, g2)
    assert stale is False, stale
    assert (final, timers) == ("Ready.", 0), (final, timers)


WORKER_ACTIONS = ("file_load", "report", "diff_report", "before_after")
FIRST_LINES = {
    "file_load": _line(FRAMES[0], "Loading firmware.s19", 1, 3, "Copy into the work area"),
    "report": _line(FRAMES[0], "Generating the project report", 1, 2, "Prepare the results"),
    "diff_report": _line(FRAMES[0], "Writing the diff report", 1, 2, "Write Markdown"),
    "before_after": _line(FRAMES[0], "Writing the before/after report", 1, 1, "Compose the report"),
}


def _stub_diff(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *, md="written", html="written") -> dict:
    """A comparison exists (``compare_images`` stubbed) and the two
    generators return the given outcome: ``written``, ``refused`` or
    ``raise``."""
    from s19_app.tui.services.diff_report_service import DiffReportResult
    from tests.test_tui_diff_screen import _diff_result

    out_dir = tmp_path / "diff_out"
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {"md": out_dir / "r.md", "html": out_dir / "r.html"}
    fake = _diff_result([(0x10, 0x14, "changed")])

    def _gen(kind: str, mode: str):
        def _generator(*_a, **_k):
            if mode == "raise":
                raise RuntimeError("x")
            if mode == "refused":
                return DiffReportResult(path=None, written=False, diagnostics=["synthetic" if kind == "md" else "y"])
            paths[kind].write_text(kind, encoding="utf-8")
            return DiffReportResult(path=paths[kind], written=True)

        return _generator

    monkeypatch.setattr(app_module, "compare_images", lambda *a, **k: fake)
    monkeypatch.setattr(app_module, "generate_diff_report", _gen("md", md))
    monkeypatch.setattr(app_module, "generate_diff_report_html", _gen("html", html))
    return paths


async def _press_diff_report(app, pilot) -> None:
    app.action_show_screen("diff")
    await pilot.pause()
    app.query_one("#diff_compare_button").press()
    await _settle(pilot, 2)
    app.query_one("#diff_report_button").press()
    await pilot.pause()


async def _load_report_project(app, pilot) -> None:
    from tests.test_tui_report_seam import _make_report_project

    _make_report_project(app, "proj")
    await pilot.pause()
    app._handle_load_project("proj")
    await _settle(pilot, 12)
    await _drain(app, pilot)


async def _press_report(app, pilot) -> None:
    from textual.widgets import Button

    from s19_app.tui.screens import ReportViewerScreen

    app.action_view_reports()
    await _settle(pilot, 12)
    screen = app.screen_stack[-1]
    assert isinstance(screen, ReportViewerScreen)
    screen.query_one("#report_generate", Button).press()
    await pilot.pause()


def _stub_before_after(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> SimpleNamespace:
    result = SimpleNamespace(
        written=True, md_path=tmp_path / "ba.md", html_path=tmp_path / "ba.html", diagnostics=[]
    )
    monkeypatch.setattr(app_module, "compose_before_after_report", lambda *a, **k: result)
    return result


async def _drive_worker_action(action: str, app, pilot) -> None:
    """Start one of the 4 worker actions from idle and let it finish."""
    if action == "file_load":
        app.load_from_path(CASE01 / "firmware.s19")
    elif action == "report":
        await _press_report(app, pilot)
    elif action == "diff_report":
        await _press_diff_report(app, pilot)
    else:
        app.action_before_after_report()
    await pilot.pause()
    await _drain(app, pilot)


@pytest.mark.parametrize("action", WORKER_ACTIONS)
def test_tc_b100_50_each_worker_action_begins_with_a_progress_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, action: str
) -> None:
    """HLR-176 (A12-35, 4 of 4): from idle, the first ``#status_text`` text
    after the begin of a file load, a report, a diff report and a
    before/after report matches HLR-176's pattern and equals its pd_A line.

    Why: these four run on a worker today, so they are the ones the user
    actually watches at 12a.
    RED (base, P12a-2): ``#status_text`` takes no progress line."""
    if action == "diff_report":
        _stub_diff(monkeypatch, tmp_path)

    async def scenario(app, pilot, log):
        if action == "report":
            await _load_report_project(app, pilot)
        await _settle(pilot, 2)
        painted = Painted(app)
        await _drive_worker_action(action, app, pilot)
        return painted.values

    values = _run(tmp_path / "app", scenario)
    progress = [v for v in values if _is_progress(v)]
    assert progress, values
    assert FIRST_RE.match(progress[0]), progress[0]
    assert progress[0] == FIRST_LINES[action], progress[0]


@pytest.mark.parametrize("action", WORKER_ACTIONS)
def test_tc_b100_50_progress_widgets_are_written_on_the_main_thread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, action: str
) -> None:
    """LLR-176.1q (A12-23): a thread-id probe on ``#status_text`` and
    ``#progress_bar`` updates across each worker action → at least 1
    progress line written, and 0 writes off the main thread.

    Why: Textual widgets are not thread-safe; an off-thread write corrupts
    the screen or raises. The probe must see the seam's writes, so a tree
    that paints no progress line cannot pass it vacuously.
    Negative control: a worker that calls ``step_busy`` directly → an
    off-main write. RED (base): no progress line is written."""
    from textual.widgets import ProgressBar

    if action == "diff_report":
        _stub_diff(monkeypatch, tmp_path)
    bar_threads: list = []
    original_update = ProgressBar.update

    def _bar_update(self, *args, **kwargs):
        if self.id == "progress_bar":
            bar_threads.append(threading.get_ident())
        return original_update(self, *args, **kwargs)

    monkeypatch.setattr(ProgressBar, "update", _bar_update)

    async def scenario(app, pilot, log):
        main = threading.get_ident()
        if action == "report":
            await _load_report_project(app, pilot)
        painted = Painted(app)
        bar_threads.clear()
        await _drive_worker_action(action, app, pilot)
        return main, painted.values, painted.threads, list(bar_threads)

    main, values, threads, bars = _run(tmp_path / "app", scenario)
    assert any(_is_progress(v) for v in values), values
    assert [t for t in threads if t != main] == [], "off-main #status_text write"
    assert bars and [t for t in bars if t != main] == [], "off-main #progress_bar write"


@pytest.mark.parametrize(
    "arm",
    ["markup", "bidi override", "130 characters", pytest.param("ESC and BEL", marks=ESC_ARM)],
)
def test_tc_b100_50_names_paint_literally_through_load_from_path(
    tmp_path: Path, tmp_path_factory: pytest.TempPathFactory, arm: str
) -> None:
    """LLR-176.1r (A12-24, S12a-02, S12a-04), driven through
    ``load_from_path`` (the real entry):
    ``[b]x.s19`` → painted verbatim with 0 markup spans;
    ``fw`` + U+202E + ``gpj.s19`` → 0 U+202E characters in the progress line,
    and the outcome is ``Loaded fwgpj.s19`` (SE5-12a-2);
    a 130-character name → the label is ``Loading `` + 119 characters + ``…``;
    ``a`` + ESC + ``]0;x`` + BEL + ``.s19`` → no ``\\x1b`` / ``\\x07`` in the
    painted line, and no C0/C1 code point in any stored or painted status-log
    line (SE5-12a-1).

    The ESC/BEL arm is declared "not run on Windows (the name cannot be
    created), never passed" (S12a-R2-3); it runs on the Linux CI. The
    130-character arm reads only the begin's line: on a host without long
    paths the copy into the work area may then fail, which is not this
    requirement.
    Why: a file name is attacker-shaped text that reaches the terminal.
    Negative control: the raw name inserted → U+202E present.
    RED (base, P12a-2): no progress line."""
    names = {
        "markup": "[b]x.s19",
        "bidi override": "fw‮gpj.s19",
        "130 characters": "n" * 126 + ".s19",
        "ESC and BEL": "a\x1b]0;x\x07.s19",
    }
    name = names[arm]
    src = tmp_path_factory.mktemp("n")
    try:
        (src / name).write_bytes((CASE01 / "firmware.s19").read_bytes())
    except (OSError, ValueError) as exc:
        pytest.skip(f"the volume refuses this name (reported not run): {exc}")

    async def scenario(app, pilot, log):
        painted = Painted(app)
        mark = len(log.messages)
        try:
            app.load_from_path(src / name)
            raised = None
        except Exception as exc:  # noqa: BLE001 — only the 130 arm may raise here
            raised = repr(exc)
        await _drain(app, pilot)
        label = app.query_one("#status_text")
        spans = list(getattr(label.render(), "spans", []))
        shown = list(app.log_lines) + _log_widgets(app)
        return painted.values, log.since(mark), raised, spans, shown

    values, added, raised, spans, shown = _run(tmp_path / "app", scenario)
    progress = [v for v in values if _is_progress(v)]
    assert progress, values
    first = progress[0]
    if arm == "markup":
        assert raised is None, raised
        assert first == _line(FRAMES[0], "Loading [b]x.s19", 1, 3, "Copy into the work area"), first
        assert spans == [], spans
    elif arm == "bidi override":
        assert raised is None, raised
        assert first == _line(FRAMES[0], "Loading fwgpj.s19", 1, 3, "Copy into the work area"), first
        assert all("‮" not in v for v in progress), [ascii(v) for v in progress]
        # SE5-12a-2 (O-12a-1): the outcome names the file as the progress
        # line did (``painted_names``, as A12a-03 does for the A2L). The
        # file-state line ``Loaded <name> (S19 only)`` keeps its base text
        # (BACKLOG-CODE), so it is not part of this arm.
        outcome = [m for m in added if m.startswith("Loaded ") and "(" not in m]
        assert outcome == ["Loaded fwgpj.s19"], [ascii(m) for m in added]
    elif arm == "130 characters":
        label = LINE_RE.match(first).group(2)
        assert label == "Loading " + "n" * 119 + "…", label
    else:
        assert raised is None, raised
        assert all("\x1b" not in v and "\x07" not in v for v in values), [ascii(v) for v in values]
        outcome = [m for m in added if m.startswith("Loaded ") and "(" not in m]
        assert outcome, added
        # SE5-12a-1: the status log as stored and as painted, not only the
        # ``set_status`` calls — the coexistence line is appended directly.
        assert [line for line in shown if CONTROL.search(line)] == [], [ascii(x) for x in shown]


def test_tc_b100_50_control_bytes_never_reach_the_status_log(
    tmp_path: Path, tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-176.1r / S12a-02 (SE5-12a-1), the arm that runs on Windows: the
    file-load install appends its coexistence line straight to the status
    log. With the formatter returning what a POSIX name ``a`` + ESC +
    ``]0;x`` + BEL + ``.s19`` gives (NTFS refuses that name), no ESC, BEL or
    other C0/C1 code point is stored in ``app.log_lines`` or painted in
    ``#log_line_1..4``, and the line itself still arrives (scrubbed). A
    direct ``_append_log_line`` with a C1 CSI and a NUL is scrubbed too.

    Why: ``#log_line_*`` are ``markup=False`` Labels and Textual drops only
    BEL/BS/VT/FF/CR, so an ESC reaches the terminal (title change, screen
    clear, clipboard write).
    Negative control / RED (71376a3): the raw ``\\x1b`` is stored and painted
    on the third log row (rev12a-security/probe_esc_log.py arm B)."""
    src = tmp_path_factory.mktemp("esc")
    good = src / "good.s19"
    good.write_bytes((CASE01 / "firmware.s19").read_bytes())
    monkeypatch.setattr(
        S19TuiApp,
        "_format_coexistence_status",
        lambda self, loaded, path: "Loaded a\x1b]0;x\x07.s19 (S19 only)",
    )

    async def scenario(app, pilot, log):
        app.load_from_path(good)
        await _drain(app, pilot)
        after_load = list(app.log_lines) + _log_widgets(app) + [_status(app)]
        app._append_log_line("direct \x9b2J\x00 line")
        await _settle(pilot, 2)
        return after_load, list(app.log_lines), _log_widgets(app)

    after_load, lines, widgets = _run(tmp_path / "app", scenario)
    assert "Loaded a]0;x.s19 (S19 only)" in after_load, [ascii(x) for x in after_load]
    assert [x for x in after_load if CONTROL.search(x)] == [], [ascii(x) for x in after_load]
    assert lines[-1] == "direct 2J line", [ascii(x) for x in lines]
    assert [x for x in lines + widgets if CONTROL.search(x)] == [], [ascii(x) for x in lines + widgets]


def _class_methods(tree: ast.Module, cls: str = "S19TuiApp") -> dict:
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == cls:
            return {
                item.name: item
                for item in node.body
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
    raise AssertionError(f"class {cls} not found in {APP_SOURCE}")


def _callee(func) -> Optional[str]:
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return None


def test_tc_b100_50_begin_busy_is_called_only_from_the_one_label_helper() -> None:
    """LLR-176.1r (S12a-04): in ``app.py``, ``begin_busy(`` is called only
    inside ``_busy_begin_action`` (1 call site), the one place that formats
    a label and scrubs its name.

    Why: a second site that formats its own label skips the name scrub.
    Negative control: a site calling ``begin_busy`` with a formatted label →
    2 sites. RED (base): 0 call sites."""
    methods = _class_methods(ast.parse(APP_SOURCE.read_text(encoding="utf-8")))
    sites = []
    for name, node in methods.items():
        for inner in ast.walk(node):
            if isinstance(inner, ast.Call) and _callee(inner.func) == "begin_busy":
                sites.append(name)
            elif (
                isinstance(inner, ast.Call)
                and _callee(inner.func) == "call_from_thread"
                and inner.args
                and _callee(inner.args[0]) == "begin_busy"
            ):
                sites.append(name)
    assert sites == ["_busy_begin_action"], sites


@pytest.mark.parametrize("size, log_y", [((118, 54), 47), ((80, 24), 17)])
def test_tc_b100_50_the_bar_keeps_its_row_when_idle(tmp_path: Path, size: tuple, log_y: int) -> None:
    """LLR-176.1s (A12-25): at 118×54 and 80×24, idle and during a held run,
    the ``#progress_bar`` region height and the ``#log_line_1`` ``y`` are
    equal (1 / 1 and 47 / 47, 1 / 1 and 17 / 17).

    Why: a status area that jumps when an action starts moves the log the
    user is reading. Declared (E1): base holds the geometry; the base RED is
    the missing seam (a held run cannot be made), and the requirement's own
    RED is the hide-when-idle mutant."""

    async def scenario(app, pilot, log):
        await _settle(pilot, 3)
        idle = (app.query_one("#progress_bar").region.height, app.query_one("#log_line_1").region.y)
        gen = app.begin_busy("report", "R", REPORT_STEPS)
        await _settle(pilot, 3)
        busy = (app.query_one("#progress_bar").region.height, app.query_one("#log_line_1").region.y)
        app.end_busy("report", gen, "")
        return idle, busy

    idle, busy = _run(tmp_path / "app", scenario, size=size)
    assert idle == busy == (1, log_y), (idle, busy)


def test_tc_b100_50_running_line_paints_in_the_accent(tmp_path: Path) -> None:
    """LLR-176.1 look (A12-26, ruling Q-6 / E2 P-3): while a run is shown
    ``#status_text`` paints in ``$accent-calm`` (#91abec); after a non-last
    end it still does; after the last end it is back to its idle colour.

    Why: the pd_A verdict tints the running line so it reads as transient.
    Negative control: the tint removed on any end → the middle reading
    fails. RED (base): no seam."""

    async def scenario(app, pilot, log):
        label = app.query_one("#status_text")
        await _settle(pilot, 2)
        idle = label.styles.color.rgb
        g1 = app.begin_busy("report", "R", REPORT_STEPS)
        g2 = app.begin_busy("file_load", "Loading x.s19", FILE_STEPS)
        await _settle(pilot, 2)
        busy = label.styles.color.rgb
        app.end_busy("file_load", g2, "")
        await _settle(pilot, 2)
        middle = label.styles.color.rgb
        app.end_busy("report", g1, "")
        await _settle(pilot, 2)
        return idle, busy, middle, label.styles.color.rgb

    idle, busy, middle, after = _run(tmp_path / "app", scenario)
    assert busy == (0x91, 0xAB, 0xEC), busy
    assert middle == busy, middle
    assert after == idle and idle != busy, (idle, after)


def test_tc_b100_50_status_line_has_one_owner_during_a_worker_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """HLR-176d, LLR-176.1h (A12-36): every ``#status_text`` value written
    between the begin and the end of a worker load of case_01 is a progress
    line (``step 1..3/3``), 0 other values; after the end it reads
    ``Loaded firmware.s19 (S19 only)``.

    Why: UX-29 / B-11 — P12a-2 shows the file state painted while the bar
    is at 50. RED (base, P12a-2): the file state is painted mid-load."""
    seam = Seam(monkeypatch)

    async def scenario(app, pilot, log):
        painted = Painted(app)
        app.load_from_path(CASE01 / "firmware.s19")
        await _drain(app, pilot)
        return painted.values, _status(app)

    values, final = _run(tmp_path / "app", scenario)
    assert values, values
    assert values[-1] == "Loaded firmware.s19 (S19 only)", values
    during = values[:-1]
    assert during and all(_is_progress(v) for v in during), values
    assert all(int(LINE_RE.match(v).group(4)) == 3 for v in during), during
    assert final == "Loaded firmware.s19 (S19 only)", final
    assert len(seam.effective("file_load")) == 1, seam.ends


def test_tc_b100_50_image_pick_file_state_waits_for_a_running_report(tmp_path: Path) -> None:
    """LLR-176.1h boundary (A12-73, F-11): a work-area image pick with no
    run paints ``Loaded x.s19 (S19 only)`` at once and begins nothing; the
    same pick while a report is held open keeps the report's line, and the
    stored file state is painted when the report ends.

    Why: the work-area pick is not a long action at 12a, but it must still
    respect the one owner of ``#status_text``.
    RED (base): no seam (the held report cannot be made)."""
    base = tmp_path / "app"
    temp = _workarea(base) / WORKAREA_TEMP
    temp.mkdir(parents=True)
    (temp / "x.s19").write_bytes((CASE01 / "firmware.s19").read_bytes())
    (temp / "y.s19").write_bytes((CASE01 / "firmware.s19").read_bytes())

    async def scenario(app, pilot, log):
        runs_before = dict(app._busy.runs)
        app._load_workarea_file("x.s19")
        await _wait(pilot, lambda: app.current_file is not None, "the pick of x.s19")
        await _settle(pilot, 4)
        idle = (_status(app), dict(app._busy.runs))
        gen = app.begin_busy("report", "Generating the project report", REPORT_STEPS)
        app._load_workarea_file("y.s19")
        await _wait(
            pilot,
            lambda: app.current_file is not None and Path(app.current_file.path).name == "y.s19",
            "the pick of y.s19",
        )
        await _settle(pilot, 4)
        held = _status(app)
        app.end_busy("report", gen, "Report: reports/r.md")
        return runs_before, idle, held, _status(app)

    runs_before, (idle_text, idle_runs), held, after = _run(base, scenario)
    assert runs_before == {} and idle_runs == {}, (runs_before, idle_runs)
    assert idle_text == "Loaded x.s19 (S19 only)", idle_text
    assert _is_progress(held) and "Generating the project report" in held, held
    assert after == "Loaded y.s19 (S19 only)", after


# --- LLR-176.1l — an exception still ends the indicator (8 arms) -------------


def _boom(*_a, **_k):
    raise RuntimeError("forced")


def test_tc_b100_50_kickoff_raise_ends_the_file_load_first(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-176.1l (A12-71, the main-thread kickoff): ``copy_into_workarea``
    raising ``PermissionError`` (not a containment error) → one effective
    end ``("file_load", g, "Loading firmware.s19 failed")`` recorded, then
    the ``PermissionError`` leaves ``load_from_path``; 0 running timers;
    ``#status_text`` reads ``Ready.``.

    Why: a raise must not leave a spinner running forever.
    Negative control: no guard → the run stays with 1 timer.
    RED (base): no end is recorded."""
    seam = Seam(monkeypatch)

    def _deny(*_a, **_k):
        raise PermissionError("synthetic")

    monkeypatch.setattr(app_module, "copy_into_workarea", _deny)

    async def scenario(app, pilot, log):
        with pytest.raises(PermissionError):
            app.load_from_path(CASE01 / "firmware.s19")
        await _settle(pilot, 3)
        return _status(app), len(_busy_timers(app))

    final, timers = _run(tmp_path / "app", scenario)
    ends = seam.effective("file_load")
    assert [e.outcome for e in ends] == ["Loading firmware.s19 failed"], seam.ends
    assert ends[0].gen == seam.begins[-1][3], (seam.begins, seam.ends)
    assert (final, timers, ends[0].timers) == ("Ready.", 0, 0), (final, timers, ends[0].timers)


def _worker_raise_scene(tmp_path: Path, seam: Seam, start, key: str, until_attempts: int = 600):
    """Run a worker action that raises inside its worker; return whether the
    app surfaced the exception (``run_test`` raises it at exit)."""

    async def scenario(app, pilot, log):
        await start(app, pilot)
        try:
            for _ in range(until_attempts):
                if seam.effective(key):
                    break
                await pilot.pause()
        except Exception:  # noqa: BLE001 — the app may already be exiting
            pass
        return None

    try:
        _run(tmp_path / "app", scenario)
    except BaseException as exc:  # noqa: BLE001 — WorkerFailed is the expected exit
        return exc
    return None


@pytest.mark.parametrize("action", ["file_load", "report", "diff_report", "before_after"])
def test_tc_b100_50_worker_raise_ends_the_action_first(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, action: str
) -> None:
    """LLR-176.1l, S12a-06 (A12-33, A12-56, A12-62, A12-66): a forced raise
    inside each worker (``_apply_prepared_load`` for the file load;
    ``_log_report_event(ok=True)`` for the three reports) → exactly one
    effective end with ``<label> failed`` recorded, 0 running timers right
    after it, and the exception still leaves the worker (re-raise: the app
    surfaces it).

    Why: at 12a the end must run before the exception leaves (ruling Q8);
    keeping the app alive is LLR-177.2 at 12b.
    Negative control: the ``except BaseException`` guard removed → 0 ends.
    RED (base): no end is recorded."""
    seam = Seam(monkeypatch)
    outcomes = {
        "file_load": "Loading firmware.s19 failed",
        "report": "Generating the project report failed",
        "diff_report": "Writing the diff report failed",
        "before_after": "Writing the before/after report failed",
    }
    if action == "file_load":
        monkeypatch.setattr(S19TuiApp, "_apply_prepared_load", _boom)
    else:
        original = S19TuiApp._log_report_event

        def _log(self, *args, **kwargs):
            if kwargs.get("ok") is True:
                raise RuntimeError("forced")
            return original(self, *args, **kwargs)

        monkeypatch.setattr(S19TuiApp, "_log_report_event", _log)
        if action == "diff_report":
            _stub_diff(monkeypatch, tmp_path)
        if action == "before_after":
            _stub_before_after(monkeypatch, tmp_path)

    async def start(app, pilot):
        if action == "file_load":
            app.load_from_path(CASE01 / "firmware.s19")
        elif action == "report":
            await _load_report_project(app, pilot)
            await _press_report(app, pilot)
        elif action == "diff_report":
            await _press_diff_report(app, pilot)
        else:
            app.action_before_after_report()

    surfaced = _worker_raise_scene(tmp_path, seam, start, action)
    ends = seam.effective(action)
    assert [e.outcome for e in ends] == [outcomes[action]], seam.ends
    assert ends[0].timers == 0, ends[0].timers
    assert surfaced is not None, "the worker's exception was swallowed (S12a-06: end, then re-raise)"


def test_tc_b100_50_a2l_raise_ends_the_action_first(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-176.1l (A12-40): ``_load_a2l_data_with_cache`` raising → one
    effective end ``("a2l_load", g, "Loading firmware.a2l failed")``, then
    the ``RuntimeError`` leaves ``load_a2l_from_path``; bar ``[0, 33, 0]``;
    0 timers; ``#status_text`` reads ``Ready.``.

    Why: a parse crash must not leave the bar mid-fill (p12a U1.5).
    RED (base, U1.5): bar ``[10, 50]`` left at 50, no end."""
    seam = Seam(monkeypatch)
    monkeypatch.setattr(S19TuiApp, "_load_a2l_data_with_cache", _boom)

    async def scenario(app, pilot, log):
        with pytest.raises(RuntimeError):
            app.load_a2l_from_path(CASE01 / "firmware.a2l")
        await _settle(pilot, 3)
        return _status(app), len(_busy_timers(app))

    final, timers = _run(tmp_path / "app", scenario)
    assert seam.bar == [0, 33, 0], seam.bar
    assert [e.outcome for e in seam.effective("a2l_load")] == ["Loading firmware.a2l failed"], seam.ends
    assert (final, timers) == ("Ready.", 0), (final, timers)


def test_tc_b100_50_project_raise_ends_the_action_first(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-176.1l (A12-45): ``_install_project_image`` raising → one
    effective end ``("project_load", g, "Loading project P failed")``, then
    the ``RuntimeError`` leaves ``_handle_load_project``; bar
    ``[0, 25, 50, 0]``; 0 timers.

    Why: a project load that crashes must not leave the indicator up.
    RED (base): no end is recorded."""
    base = tmp_path / "app"
    _project_p(base)
    seam = Seam(monkeypatch)
    monkeypatch.setattr(S19TuiApp, "_install_project_image", _boom)

    async def scenario(app, pilot, log):
        with pytest.raises(RuntimeError):
            app._handle_load_project("P")
        await _settle(pilot, 3)
        return len(_busy_timers(app))

    timers = _run(base, scenario)
    assert seam.bar == [0, 25, 50, 0], seam.bar
    assert [e.outcome for e in seam.effective("project_load")] == ["Loading project P failed"], seam.ends
    assert timers == 0, timers


async def _load_case01_image(app, pilot) -> None:
    await projects.load_image(pilot, app, CASE01 / "firmware.s19")
    await _settle(pilot, 4)


def test_tc_b100_50_save_raise_ends_the_action_first(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-176.1l, SEC-7 (A12-49): ``gather_project_artifacts`` raising in
    the app module → the rollback runs, one effective end
    ``("save_project", g, "Saving project S3 failed")``, then the
    ``RuntimeError`` leaves ``_handle_save_dialog``; bar ``[0, 25, 50, 0]``;
    ``S3`` removed; 0 timers.

    Why: a save that crashes must not leave the indicator up nor a
    half-written project. RED (base): no end is recorded."""
    from s19_app.tui.screens import SaveProjectPayload

    seam = Seam(monkeypatch)
    monkeypatch.setattr(app_module, "gather_project_artifacts", _boom)

    async def scenario(app, pilot, log):
        await _load_case01_image(app, pilot)
        seam.bar.clear()
        with pytest.raises(RuntimeError):
            app._handle_save_dialog(SaveProjectPayload(parent_folder=str(app.workarea), project_name="S3"))
        await _settle(pilot, 3)
        return (app.workarea / "S3").exists(), len(_busy_timers(app))

    exists, timers = _run(tmp_path / "app", scenario)
    assert seam.bar == [0, 25, 50, 0], seam.bar
    assert [e.outcome for e in seam.effective("save_project")] == ["Saving project S3 failed"], seam.ends
    assert exists is False and timers == 0, (exists, timers)


# ===========================================================================
# TC-B100-51 — the action table and every exit (LLR-176.2 … LLR-176.2d)
# ===========================================================================

#: Example A12-27 decision-id scan (TC-B100-66 shares it).
DECISION_ID = re.compile(r"\bD\d+\b|\bO-\d+|VS-|LLR-|HLR-|US-|AT-|TC-|LED|UX-|\bCR\d|\bSEC\d")


def test_tc_b100_51_action_table_names_the_seven_long_actions() -> None:
    """LLR-176.2b (A12-27, ruling Q-5): ``_BUSY_ACTIONS`` holds exactly 7
    rows, one per long action, each with a non-empty English label and at
    least one step; step counts 3, 3, 4, 4, 2, 2, 1 (19 names; the graph's
    "18" is an arithmetic slip, E4 integration SR-12a-1), with the
    confirmed labels and step names.

    Why: one table is the single source of what each action paints, and
    Inc 12b reads its steps (parse, tag table, install, per-file save).
    Negative control: a row removed → 6. RED (base): no table."""
    table = app_module._BUSY_ACTIONS
    assert len(table) == 7, sorted(table)
    got = {key: (row.label, tuple(row.steps)) for key, row in table.items()}
    assert got == TABLE, got
    assert [len(steps) for _l, steps in (TABLE[k] for k in table)] == [len(TABLE[k][1]) for k in table]
    assert sum(len(row.steps) for row in table.values()) == 19


#: A12-28: the baseline ``set_progress`` sites, as (function, event, key,
#: step) with the number of baseline sites each event replaces.
CENSUS = [
    ("action_before_after_report", "begin", "before_after", None, 1),
    ("_start_before_after_worker", "end", "before_after", None, 3),
    ("_trigger_generate_report", "begin", "report", None, 1),
    ("_start_generate_report_worker", "end", "report", None, 2),
    ("_start_generate_report_worker", "step", "report", 2, 1),
    ("_finish_generate_report", "end", "report", None, 1),
    ("on_ab_diff_panel_report_requested", "begin", "diff_report", None, 1),
    ("_start_diff_report_worker", "end", "diff_report", None, 4),
    ("_start_diff_report_worker", "step", "diff_report", 2, 1),
    ("load_from_path", "begin", "file_load", None, 1),
    ("load_from_path", "end", "file_load", None, 1),
    ("load_from_path", "step", "file_load", 2, 1),
    ("load_a2l_from_path", "begin", "a2l_load", None, 1),
    ("load_a2l_from_path", "end", "a2l_load", None, 2),
    ("load_a2l_from_path", "step", "a2l_load", 2, 1),
    ("_start_load_worker", "end", "file_load", None, 1),
    ("_handle_load_error", "end", "file_load", None, 1),
]


def _seam_events(node) -> list:
    """(event, key, step) for every seam call in ``node`` — direct, or as
    the first argument of ``call_from_thread`` (nested defs included)."""
    out = []
    for inner in ast.walk(node):
        if not isinstance(inner, ast.Call):
            continue
        name = _callee(inner.func)
        args = list(inner.args)
        if name == "call_from_thread" and args:
            name = _callee(args[0])
            args = args[1:]
        event = {"_busy_begin_action": "begin", "begin_busy": "begin", "step_busy": "step", "end_busy": "end"}.get(name)
        if event is None:
            continue
        key = args[0].value if args and isinstance(args[0], ast.Constant) else None
        step = None
        if event == "step" and len(args) >= 3 and isinstance(args[2], ast.Constant):
            step = args[2].value
        out.append((event, key, step))
    return out


def test_tc_b100_51_every_baseline_bar_site_maps_to_a_seam_event() -> None:
    """LLR-176.2 (A12-28): the 24 baseline ``set_progress`` sites in 12
    functions each map to one begin, step or end of the action table; the
    AST of ``app.py`` holds, per function, at least as many seam calls of
    each (event, key, step) as the baseline sites it replaces (24 in all).

    Why: a site left on the raw bar escapes the indicator's rules (stale
    100, no end). Negative control: the report step removed → the census
    names ``_start_generate_report_worker`` step 2.
    RED (base, P12a-1): 24 sites, no seam call."""
    methods = _class_methods(ast.parse(APP_SOURCE.read_text(encoding="utf-8")))
    missing = []
    total = 0
    for function, event, key, step, count in CENSUS:
        total += count
        node = methods.get(function)
        found = 0 if node is None else _seam_events(node).count((event, key, step))
        if found < count:
            missing.append((function, event, key, step, f"{found}/{count}"))
    assert total == 24
    assert missing == [], missing


def test_tc_b100_51_only_the_seam_sets_the_bar() -> None:
    """LLR-176.2a (A12-29): ``set_progress`` is referenced only inside
    ``begin_busy``, ``step_busy`` and ``end_busy`` (a call, or the method
    passed to ``call_from_thread``); ``#progress_bar`` is queried only in
    ``set_progress``.

    Why: one writer of the bar is what makes "cleared at the last end"
    true for every action. RED (base, P12a-1): 24 references outside."""
    methods = _class_methods(ast.parse(APP_SOURCE.read_text(encoding="utf-8")))
    allowed = {"begin_busy", "step_busy", "end_busy", "set_progress"}
    outside = []
    queries = []
    for name, node in methods.items():
        for inner in ast.walk(node):
            if isinstance(inner, ast.Attribute) and inner.attr == "set_progress" and name not in allowed:
                outside.append((name, inner.lineno))
            if (
                isinstance(inner, ast.Call)
                and _callee(inner.func) == "query_one"
                and inner.args
                and isinstance(inner.args[0], ast.Constant)
                and inner.args[0].value == "#progress_bar"
                and name != "set_progress"
            ):
                queries.append((name, inner.lineno))
    assert outside == [], outside
    assert queries == [], queries


def test_tc_b100_51_workers_take_the_run_generation() -> None:
    """Interfaces S-m, ruling Q-1 (A12-69): the 4 workers take ``gen`` as a
    required keyword-only parameter, ``_handle_load_error`` and
    ``_finish_generate_report`` take it as their last parameter, and every
    call of the 4 workers in ``app.py`` passes ``gen=``.

    The example says a call without ``gen`` raises ``TypeError``; a
    ``@work`` method raises inside its worker, so the signature is read
    instead (declared in the tester notes).
    Why: a worker that reads ``self._busy`` off-thread races the main
    thread; the generation is how a replaced run's end is recognised.
    RED (base): no ``gen`` parameter."""
    workers = (
        "_start_load_worker", "_start_before_after_worker",
        "_start_generate_report_worker", "_start_diff_report_worker",
    )
    for name in workers:
        params = inspect.signature(getattr(S19TuiApp, name)).parameters
        assert "gen" in params, (name, list(params))
        assert params["gen"].kind is inspect.Parameter.KEYWORD_ONLY, (name, params["gen"])
        assert params["gen"].default is inspect.Parameter.empty, (name, params["gen"])
    for name in ("_handle_load_error", "_finish_generate_report"):
        assert list(inspect.signature(getattr(S19TuiApp, name)).parameters)[-1] == "gen", name
    tree = ast.parse(APP_SOURCE.read_text(encoding="utf-8"))
    calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _callee(node.func) in workers
    ]
    assert len(calls) >= 4, len(calls)
    assert [c.lineno for c in calls if not any(k.arg == "gen" for k in c.keywords)] == []


# --- LLR-176.2c — each action ends on every success and failure exit ---------


def test_tc_b100_51_file_load_ends_once_on_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-176.2c success, HLR-176c, A12a-05 (A12-30, A12-72, A12-34):
    a worker load of case_01 → 1 begin ``Loading firmware.s19``, bar
    ``[0, 33, 66, 0]``, exactly 1 effective end with ``Loaded firmware.s19``
    and nothing logged after it, no begin or step line in the log,
    ``#status_text`` = the file state, 0 timers; a missing file and a
    ``.txt`` file are refused before any begin.

    Why: success is the common path; a second ``failed`` end or a sync line
    after the outcome would make the log lie.
    RED (base, p12a U1.1): bar ``[10, 50, 100]``, begin and step lines."""
    seam = Seam(monkeypatch)
    (tmp_path / "x.txt").write_text("x", encoding="utf-8")

    async def scenario(app, pilot, log):
        mark = len(log.messages)
        app.load_from_path(CASE01 / "firmware.s19")
        await _drain(app, pilot)
        added = log.since(mark)
        success = (list(seam.bar), added, _status(app), len(_busy_timers(app)), list(seam.begins))
        begins = len(seam.begins)
        seam.bar.clear()
        app.load_from_path(tmp_path / "missing.s19")
        app.load_from_path(tmp_path / "x.txt")
        await _settle(pilot, 3)
        return success, len(seam.begins) - begins, list(seam.bar)

    (bar, added, final, timers, begins), refused_begins, refused_bar = _run(tmp_path / "app", scenario)
    assert bar == [0, 33, 66, 0], bar
    assert [b[:3] for b in begins] == [("file_load", "Loading firmware.s19", FILE_STEPS)], begins
    ends = seam.effective("file_load")
    assert [e.outcome for e in ends] == ["Loaded firmware.s19"], seam.ends
    assert added[-1] == "Loaded firmware.s19", added
    assert not any(m.startswith(("Copying", "Parsing")) for m in added), added
    assert final == "Loaded firmware.s19 (S19 only)", final
    assert timers == 0, timers
    assert refused_begins == 0 and refused_bar == [], (refused_begins, refused_bar)


def test_tc_b100_51_file_load_ends_once_on_a_parse_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-176.2c failure (A12-31, A12-52): ``_parse_loaded_file`` raising,
    or returning ``None`` → bar ``[0, 33, 0]``, the log ends
    ``Load failed: <reason>`` then ``Load failed``, 1 effective end,
    ``#status_text`` ``Ready.``, 0 timers.

    Why: a failed load must clear the indicator, not leave the bar at 100.
    Negative control: no end in ``_handle_load_error`` → 1 run, 1 timer.
    RED (base, p12a U1.2): the bar ends at 100."""
    seam = Seam(monkeypatch)
    mode = {"value": "raise"}

    def _parse(self, *args, **kwargs):
        if mode["value"] == "raise":
            raise RuntimeError("synthetic parse failure")
        return None

    monkeypatch.setattr(S19TuiApp, "_parse_loaded_file", _parse)

    async def scenario(app, pilot, log):
        out = []
        for value in ("raise", "none"):
            mode["value"] = value
            seam.bar.clear()
            mark = len(log.messages)
            app.load_from_path(CASE01 / "firmware.s19")
            await _drain(app, pilot)
            out.append((list(seam.bar), log.since(mark)[-2:], _status(app), len(_busy_timers(app))))
        return out

    raised, unsupported = _run(tmp_path / "app", scenario)
    assert raised == ([0, 33, 0], ["Load failed: synthetic parse failure", "Load failed"], "Ready.", 0), raised
    assert unsupported == ([0, 33, 0], ["Load failed: Unsupported file type: .s19", "Load failed"], "Ready.", 0), unsupported
    assert [e.outcome for e in seam.effective("file_load")] == ["Load failed", "Load failed"], seam.ends


def test_tc_b100_51_file_load_ends_once_on_a_containment_refusal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-176.2c failure after the begin (A12-32): ``copy_into_workarea``
    refusing → bar ``[0, 0]``, the log ``Cannot load file: synthetic
    containment refusal``, ``#status_text`` ``Ready.``, 1 effective end.

    Why: a refusal after the begin must still end the indicator.
    RED (base, p12a U1.3): bar ``[10, 0]``."""
    from s19_app.tui.workspace import WorkareaContainmentError

    seam = Seam(monkeypatch)

    def _refuse(*_a, **_k):
        raise WorkareaContainmentError("synthetic containment refusal")

    monkeypatch.setattr(app_module, "copy_into_workarea", _refuse)

    async def scenario(app, pilot, log):
        mark = len(log.messages)
        app.load_from_path(CASE01 / "firmware.s19")
        await _settle(pilot, 3)
        return log.since(mark), _status(app), len(_busy_timers(app))

    added, final, timers = _run(tmp_path / "app", scenario)
    assert seam.bar == [0, 0], seam.bar
    assert added == ["Cannot load file: synthetic containment refusal"], added
    assert (final, timers) == ("Ready.", 0), (final, timers)
    assert [e.outcome for e in seam.effective("file_load")] == ["Cannot load file: synthetic containment refusal"]


def test_tc_b100_51_a2l_load_ends_once_on_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-176.2c success, A12a-03 (A12-38, A12-41): ``load_a2l_from_path``
    of case_01's A2L → 1 begin ``Loading firmware.a2l``, bar
    ``[0, 33, 66, 0]``, the log gains only ``A2L loaded: firmware.a2l``
    (the outcome), ``#status_text`` ``Ready.``, 1 effective end, 0 timers;
    a missing A2L and a ``.txt`` begin nothing.

    Why: the outcome is the action's last painted line, which other tests
    read in ``#log_line_4``.
    RED (base, p12a U1.4): bar ``[10, 50, 100]``, 4 log lines."""
    seam = Seam(monkeypatch)
    (tmp_path / "x.txt").write_text("x", encoding="utf-8")

    async def scenario(app, pilot, log):
        mark = len(log.messages)
        app.load_a2l_from_path(CASE01 / "firmware.a2l")
        await _settle(pilot, 4)
        out = (list(seam.bar), log.since(mark), _status(app), len(_busy_timers(app)), list(seam.begins))
        begins = len(seam.begins)
        app.load_a2l_from_path(tmp_path / "missing.a2l")
        app.load_a2l_from_path(tmp_path / "x.txt")
        await _settle(pilot, 3)
        return out, len(seam.begins) - begins

    (bar, added, final, timers, begins), refused = _run(tmp_path / "app", scenario)
    assert bar == [0, 33, 66, 0], bar
    assert [b[:3] for b in begins] == [("a2l_load", "Loading firmware.a2l", A2L_STEPS)], begins
    assert added == ["A2L loaded: firmware.a2l"], added
    assert (final, timers) == ("Ready.", 0), (final, timers)
    assert [e.outcome for e in seam.effective("a2l_load")] == ["A2L loaded: firmware.a2l"], seam.ends
    assert refused == 0, refused


def test_tc_b100_51_a2l_load_ends_once_on_a_containment_refusal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-176.2c failure (A12-39): ``copy_into_workarea`` refusing the A2L
    → bar ``[0, 0]``, the log ``Cannot load A2L: synthetic containment
    refusal``, 1 effective end.

    RED (base): bar ``[10, 0]``."""
    from s19_app.tui.workspace import WorkareaContainmentError

    seam = Seam(monkeypatch)

    def _refuse(*_a, **_k):
        raise WorkareaContainmentError("synthetic containment refusal")

    monkeypatch.setattr(app_module, "copy_into_workarea", _refuse)

    async def scenario(app, pilot, log):
        mark = len(log.messages)
        app.load_a2l_from_path(CASE01 / "firmware.a2l")
        await _settle(pilot, 3)
        return log.since(mark)

    added = _run(tmp_path / "app", scenario)
    assert seam.bar == [0, 0], seam.bar
    assert added == ["Cannot load A2L: synthetic containment refusal"], added
    assert [e.outcome for e in seam.effective("a2l_load")] == ["Cannot load A2L: synthetic containment refusal"]


def test_tc_b100_51_project_load_ends_once_on_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-176.2c success, LLR-176.1j, A12a-09 (A12-42): project ``P``
    (with an A2L) → 1 begin ``Loading project P``, steps ``[2, 3, 4]``, bar
    ``[0, 25, 50, 75, 0]``, 1 effective end whose outcome is the summary
    line (the log's last line), and ``#status_text`` reads the project and
    file line ``Loaded project 'P' -> firmware.s19``.

    Why: the summary goes to the log and the project line stays on the
    status line (LLR-178.2). RED (base, p12a U1.6): bar ``[]``."""
    base = tmp_path / "app"
    _project_p(base)
    seam = Seam(monkeypatch)

    async def scenario(app, pilot, log):
        mark = len(log.messages)
        app._handle_load_project("P")
        await _settle(pilot, 8)
        return log.since(mark), _status(app), len(_busy_timers(app))

    added, final, timers = _run(base, scenario)
    assert seam.bar == [0, 25, 50, 75, 0], seam.bar
    assert [b[:3] for b in seam.begins] == [("project_load", "Loading project P", PROJECT_STEPS)], seam.begins
    assert seam.step_numbers("project_load") == [2, 3, 4], seam.steps
    ends = seam.effective("project_load")
    assert len(ends) == 1, seam.ends
    assert ends[0].outcome.startswith("Loaded project 'P' -> firmware.s19"), ends[0].outcome
    assert ends[0].outcome.endswith("details: p"), ends[0].outcome
    assert added and ends[0].outcome.startswith(added[-1]) and len(added[-1]) >= 50, added
    assert final == "Loaded project 'P' -> firmware.s19", final
    assert timers == 0, timers


def test_tc_b100_51_project_load_without_an_a2l_skips_its_step(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A12a-09 (A12-68): a project holding only ``firmware.s19`` → steps
    ``[3, 4]`` (``Parse the A2L`` is skipped), bar ``[0, 50, 75, 0]``, 1
    effective end.

    Why: naming a step that does not happen misreports the work.
    RED (base): bar ``[]``."""
    base = tmp_path / "app"
    _project_p(base, a2l=False)
    seam = Seam(monkeypatch)

    async def scenario(app, pilot, log):
        app._handle_load_project("P")
        await _settle(pilot, 8)
        return None

    _run(base, scenario)
    assert seam.bar == [0, 50, 75, 0], seam.bar
    assert seam.step_numbers("project_load") == [3, 4], seam.steps
    assert len(seam.effective("project_load")) == 1, seam.ends


def test_tc_b100_51_project_load_ends_once_on_a_failure_after_the_begin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-176.2c failure, A12a-02 (A12-43, A12-44, A12-67): ``A2LONLY``
    whose A2L read raises after the begin → bar ``[0, 25, 0]``, the log's
    last line ``No supported files in project: A2LONLY``, 1 effective end,
    ``#status_text`` ``Ready.``; the cheap refusals before the begin —
    ``Q`` holding only ``project.json``, and ``P`` whose ``project.json``
    lstat raises — paint their line with 0 begins and no ``failed`` end.

    Why: refusals that never began must not add an end; a failure after the
    begin must add exactly one. RED (base): bar ``[]``, no end."""
    import json

    base = tmp_path / "app"
    wa = _workarea(base)
    a2l_only = _copy_case01(wa / "A2LONLY", "firmware.a2l")
    (a2l_only / "project.json").write_text(json.dumps({"schema_version": 1}), encoding="utf-8")
    (wa / "Q").mkdir(parents=True)
    (wa / "Q" / "project.json").write_text(json.dumps({"schema_version": 1}), encoding="utf-8")
    _project_p(base)
    seam = Seam(monkeypatch)
    real_lstat = os.lstat
    gate = os.path.normcase(str(wa / "P" / "project.json"))

    def _lstat(path, *args, **kwargs):
        if not isinstance(path, int) and os.path.normcase(os.fspath(path)) == gate:
            raise PermissionError(13, "injected", os.fspath(path))
        return real_lstat(path, *args, **kwargs)

    def _bad_a2l(*_a, **_k):
        raise ValueError("synthetic")

    async def scenario(app, pilot, log):
        with monkeypatch.context() as patch:
            patch.setattr(S19TuiApp, "_load_a2l_data_with_cache", _bad_a2l)
            mark = len(log.messages)
            app._handle_load_project("A2LONLY")
            await _settle(pilot, 6)
            failed = (list(seam.bar), log.since(mark), _status(app), len(_busy_timers(app)))
        begins = len(seam.begins)
        seam.bar.clear()
        mark = len(log.messages)
        app._handle_load_project("Q")
        await _settle(pilot, 4)
        with monkeypatch.context() as patch:
            patch.setattr(app_module.os, "lstat", _lstat)
            app._handle_load_project("P")
        await _settle(pilot, 4)
        return failed, len(seam.begins) - begins, list(seam.bar), log.since(mark)

    (bar, added, final, timers), refused_begins, refused_bar, refusals = _run(base, scenario)
    assert bar == [0, 25, 0], bar
    assert added[-1] == "No supported files in project: A2LONLY", added
    assert (final, timers) == ("Ready.", 0), (final, timers)
    ends = seam.effective("project_load")
    assert [e.outcome for e in ends] == ["No supported files in project: A2LONLY"], seam.ends
    assert refused_begins == 0 and refused_bar == [], (refused_begins, refused_bar)
    assert any("'Q' has no data or A2L file" in m for m in refusals), refusals
    assert any("'P' could not be read" in m for m in refusals), refusals
    assert not any(m.endswith("failed") for m in refusals), refusals


def test_tc_b100_51_save_project_reports_its_phases_as_steps(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-176.2d, LLR-176.2c success (A12-46, A12-47; boundary "no MAC and
    no A2L"): case_01's image alone saved as ``S1`` → 1 begin
    ``("save_project", "Saving project S1", <4 phases>)``, steps 2, 3, 4
    once each and in order, bar ``[0, 25, 50, 75, 0]``, 1 effective end with
    ``Saved project to …S1 (variant 'firmware')`` (the log's last line),
    ``#status_text`` as before the save; an empty name and the reserved
    ``temp`` are refused in the dialog with 0 begins.

    Why: Inc 11 ruling Q2 — the save's real progress; a refused save never
    begins. RED (base, P12a-1): no progress call in the save."""
    from s19_app.tui.screens import SaveProjectPayload

    seam = Seam(monkeypatch)

    async def scenario(app, pilot, log):
        await _load_case01_image(app, pilot)
        seam.bar.clear()
        before = _status(app)
        mark = len(log.messages)
        app._handle_save_dialog(SaveProjectPayload(parent_folder=str(app.workarea), project_name="S1"))
        await _settle(pilot, 6)
        saved = (log.since(mark), _status(app), before, len(_busy_timers(app)))
        begins = len(seam.begins)
        mark = len(log.messages)
        for name in ("", "temp"):
            app._handle_save_dialog(SaveProjectPayload(parent_folder=str(app.workarea), project_name=name))
            await _settle(pilot, 3)
        return saved, len(seam.begins) - begins, log.since(mark)

    (added, final, before, timers), refused_begins, refusals = _run(tmp_path / "app", scenario)
    assert seam.bar == [0, 25, 50, 75, 0], seam.bar
    assert [b[:3] for b in seam.begins] == [("save_project", "Saving project S1", SAVE_STEPS)], seam.begins
    assert seam.step_numbers("save_project") == [2, 3, 4], seam.steps
    ends = seam.effective("save_project")
    assert len(ends) == 1, seam.ends
    assert ends[0].outcome.startswith("Saved project to ") and ends[0].outcome.endswith(
        "S1 (variant 'firmware')"
    ), ends[0].outcome
    assert added[-1] == ends[0].outcome[: len(added[-1])], added
    assert final == before and timers == 0, (final, before, timers)
    assert refused_begins == 0, refused_begins
    assert any("name is empty" in m for m in refusals) and any("reserved name" in m for m in refusals), refusals


def test_tc_b100_51_save_project_ends_once_on_a_placement_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-176.2c failure after the begin (A12-48): ``place_into_workarea``
    raising ``OSError(28)`` → 1 effective end whose outcome is the log's
    last line ``Project NOT saved: could not save — …``, bar ``[0, 25, 0]``,
    ``S2`` does not exist.

    Why: a save that fails half-way must clear the indicator and report it.
    RED (base, p12a U1.10): no progress call in the save."""
    from s19_app.tui.screens import SaveProjectPayload

    seam = Seam(monkeypatch)

    def _no_space(*_a, **_k):
        raise OSError(28, "synthetic no space")

    monkeypatch.setattr(app_module, "place_into_workarea", _no_space)

    async def scenario(app, pilot, log):
        await _load_case01_image(app, pilot)
        seam.bar.clear()
        mark = len(log.messages)
        app._handle_save_dialog(SaveProjectPayload(parent_folder=str(app.workarea), project_name="S2"))
        await _settle(pilot, 6)
        return log.since(mark), (app.workarea / "S2").exists()

    added, exists = _run(tmp_path / "app", scenario)
    assert seam.bar == [0, 25, 0], seam.bar
    ends = seam.effective("save_project")
    assert len(ends) == 1, seam.ends
    assert ends[0].outcome.startswith("Project NOT saved: could not save"), ends[0].outcome
    assert "synthetic no space" in ends[0].outcome, ends[0].outcome
    assert added[-1] == ends[0].outcome[: len(added[-1])], added
    assert exists is False


def test_tc_b100_51_report_ends_once_on_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """LLR-176.2c success, LLR-176.1k (A12-53, A12-57): a real report of
    the reportable project → bar ``[0, 50, 0]``, 1 effective end
    ``Report: reports/<stamp>-report.md`` (the log's last line),
    ``#status_text`` unchanged from before the report; with no project the
    refusal begins nothing.

    Why: the report is the slowest worker the user waits on.
    RED (base, p12a U1.11): bar ``[15, 55, 100]``."""
    seam = Seam(monkeypatch)

    async def scenario(app, pilot, log):
        mark = len(log.messages)
        app._trigger_generate_report(16)
        await _settle(pilot, 3)
        refused = (len(seam.begins), list(seam.bar), log.since(mark))
        await _load_report_project(app, pilot)
        seam.bar.clear()
        before = _status(app)
        mark = len(log.messages)
        await _press_report(app, pilot)
        await _drain(app, pilot)
        return refused, log.since(mark), before, _status(app)

    refused, added, before, after = _run(tmp_path / "app", scenario)
    assert refused[0] == 0 and refused[1] == [], refused
    assert seam.bar == [0, 50, 0], seam.bar
    ends = seam.effective("report")
    assert len(ends) == 1 and re.fullmatch(r"Report: reports/.+-report\.md", ends[0].outcome), seam.ends
    assert added[-1] == ends[0].outcome, added
    assert after == before, (before, after)


@pytest.mark.parametrize("arm", ["generator raises", "rejected input"])
def test_tc_b100_51_report_ends_once_on_a_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str) -> None:
    """LLR-176.2c failure (A12-54, A12-55): the generator raising →
    bar ``[0, 50, 0]`` and ``Report failed: RuntimeError: synthetic report
    failure``; ``context_bytes = -1`` → bar ``[0, 0]`` and a line starting
    ``Report rejected: ``; each 1 effective end, the log's last line.

    RED (base): the bar sequences start at 15 and no end is recorded."""
    seam = Seam(monkeypatch)
    if arm == "generator raises":

        def _fail(*_a, **_k):
            raise RuntimeError("synthetic report failure")

        monkeypatch.setattr(app_module, "generate_project_report", _fail)

    async def scenario(app, pilot, log):
        await _load_report_project(app, pilot)
        seam.bar.clear()
        mark = len(log.messages)
        if arm == "generator raises":
            await _press_report(app, pilot)
        else:
            app._trigger_generate_report(-1)
        await _drain(app, pilot)
        return log.since(mark)

    added = _run(tmp_path / "app", scenario)
    ends = seam.effective("report")
    assert len(ends) == 1, seam.ends
    if arm == "generator raises":
        assert seam.bar == [0, 50, 0], seam.bar
        assert ends[0].outcome == "Report failed: RuntimeError: synthetic report failure", ends[0].outcome
    else:
        assert seam.bar == [0, 0], seam.bar
        assert ends[0].outcome.startswith("Report rejected: "), ends[0].outcome
    assert added[-1] == ends[0].outcome[: len(added[-1])], added


@pytest.mark.parametrize(
    "arm, md, html, bar, outcome",
    [
        ("written", "written", "written", [0, 50, 0], "Diff report written: {md}  |  {html}"),
        ("markdown refused", "refused", "written", [0, 0], "Report refused: synthetic"),
        ("html raises", "written", "raise", [0, 50, 0], "Diff report failed: RuntimeError: x"),
        ("html refused", "written", "refused", [0, 50, 0], "HTML report refused: y"),
    ],
)
def test_tc_b100_51_diff_report_ends_once_and_logs_its_outcome(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str, md: str, html: str, bar: list, outcome: str
) -> None:
    """LLR-176.2c, HLR-176c, E2 ruling "Diff report" (A12-58, A12-59,
    A12-60, A12-61): written, Markdown refused, HTML raising and HTML
    refused → the given bar sequence, 1 effective end, and the outcome is
    the log's new last line (the diff report wrote no log line before);
    a Report press with no comparison begins nothing.

    Why: the diff report's result lived only in the panel; the outcome now
    reaches the status log like every other action.
    RED (base, p12a U1.13 / U1.14): 0 status-log lines, bar 100 or 0."""
    paths = _stub_diff(monkeypatch, tmp_path, md=md, html=html)
    seam = Seam(monkeypatch)
    expected = outcome.format(md=paths["md"], html=paths["html"])

    async def scenario(app, pilot, log):
        mark = len(log.messages)
        await _press_diff_report(app, pilot)
        await _drain(app, pilot)
        return log.since(mark), app.size.width

    added, width = _run(tmp_path / "app", scenario)
    assert seam.bar == bar, seam.bar
    ends = seam.effective("diff_report")
    assert [e.outcome for e in ends] == [expected], seam.ends
    # E4 integration: ``log`` (StatusLog) records each ``set_status`` message
    # in full; the width clip happens later, in ``_append_log_line``.
    assert added and added[-1] == expected.strip(), (added, expected, width)


def test_tc_b100_51_diff_report_without_a_comparison_begins_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A12-61 with the seam present: Report pressed before any Compare →
    the panel refuses, 0 begins, 0 bar writes, 0 status-log lines.

    Why: a refusal before the begin must not flash a progress line.
    RED (base): no seam (the begin count cannot be read; declared)."""
    assert hasattr(S19TuiApp, "begin_busy"), "the progress seam does not exist"
    seam = Seam(monkeypatch)

    async def scenario(app, pilot, log):
        app.action_show_screen("diff")
        await pilot.pause()
        mark = len(log.messages)
        app.query_one("#diff_report_button").press()
        await _settle(pilot, 4)
        return log.since(mark)

    added = _run(tmp_path / "app", scenario)
    assert (seam.begins, seam.bar, added) == ([], [], []), (seam.begins, seam.bar, added)


@pytest.mark.parametrize("arm", ["written", "refused"])
def test_tc_b100_51_before_after_ends_once_and_logs_its_outcome(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str
) -> None:
    """LLR-176.2c (A12-63, A12-64): the composer stubbed to written →
    bar ``[0, 0]`` (1 step), 1 effective end ``Before/after report written:
    <md> | <html>``; nothing loaded → the composer refuses, bar ``[0, 0]``,
    1 effective end ``Before/after report refused: …``; each outcome is
    the log's last ``set_status`` message (in full; the painted row clips it).

    Why: a 1-step action still begins and ends exactly once.
    RED (base, p12a U1.15): bar ``[15, 100]`` / ``[15, 0]``, no end."""
    result = _stub_before_after(monkeypatch, tmp_path) if arm == "written" else None
    seam = Seam(monkeypatch)

    async def scenario(app, pilot, log):
        mark = len(log.messages)
        app.action_before_after_report()
        await _drain(app, pilot)
        return log.since(mark), app.size.width

    added, width = _run(tmp_path / "app", scenario)
    assert seam.bar == [0, 0], seam.bar
    ends = seam.effective("before_after")
    assert len(ends) == 1, seam.ends
    if arm == "written":
        assert ends[0].outcome == f"Before/after report written: {result.md_path} | {result.html_path}", ends[0].outcome
    else:
        assert ends[0].outcome.startswith(
            "Before/after report refused: No applied change summary - apply a change document "
            "and save the patched image first."
        ), ends[0].outcome
    # E4 integration: ``log`` records the full ``set_status`` message (the
    # width clip is ``_append_log_line``'s), so the outcome is compared whole.
    assert added[-1] == ends[0].outcome.strip(), (added, ends[0].outcome, width)


# ===========================================================================
# AT-B100-17 (12a half) — black-box: a worker load of an 8 MiB-data S19 by keys
# ===========================================================================


def test_at_b100_17_worker_load_of_an_8_mib_s19_by_keys(tmp_path: Path) -> None:
    """AT-B100-17, 12a half (HLR-176, HLR-176a, HLR-176c, HLR-176d): in a
    scratch work area, ``l`` opens Load on the path field, the absolute path
    of a generated S19 holding 8 MiB of data (outside the work area) is
    typed and ``enter`` pressed. Sampling ``#status_text`` every 0.05 s
    while it loads:
    - at least 1 sample reads ``<glyph> Loading big8.s19  ·  step 2/3 Parse  ·  <mm:ss>``;
    - the elapsed text changes at least once;
    - at least 5 distinct glyphs.
    At the end: the status log's last line is ``Loaded big8.s19``,
    ``#status_text`` reads ``Loaded big8.s19 (S19 only)``, the bar row equals
    the idle row and 0 progress timers run (7 of 7).

    Loaded-host rule: only ≥ thresholds and observed transitions.
    Why: this is the operator's own case (P12a-3: about 2.4 s of parse).
    RED (base, P12a-2): ``#status_text`` takes only ``Ready.`` and the file
    state, and the bar ends at 100."""
    src = tmp_path / "src"
    src.mkdir()
    # The shared stress generator (tests/conftest.py): 2 048 ranges of 4 KiB
    # = 8 MiB of data in S3 records (about 24.6 MB on disk).
    big = make_large_s19(src / "big8.s19", num_ranges=2048, bytes_per_range=4096)
    base = tmp_path / "work"

    async def scenario(app, pilot, log):
        from tests.support import b100_load_dialog as ld

        await pilot.press("1")
        await _settle(pilot, 4)
        idle_row = _bar_row(app)
        await pilot.press("l")
        await ld.wait_for_dialog(pilot, app)
        await _settle(pilot, 3)
        await pilot.press(*str(big))
        await pilot.press("enter")
        samples = []
        for _ in range(3600):
            samples.append(_status(app))
            loaded = app.current_file is not None and Path(app.current_file.path).name == "big8.s19"
            if loaded and not _is_progress(samples[-1]) and list(app.log_lines)[-1:] == ["Loaded big8.s19"]:
                break
            await pilot.pause(0.05)
        await _settle(pilot, 4)
        return samples, idle_row, list(app.log_lines), _status(app), _bar_row(app), len(_busy_timers(app))

    samples, idle_row, log_lines, final, row, timers = _run(base, scenario)
    progress = [s for s in samples if _is_progress(s)]
    parse = [s for s in progress if s.startswith(tuple(FRAMES)) and f" Loading big8.s19{DOT}step 2/3 Parse{DOT}" in s]
    assert parse, progress[:10] or samples[:10]
    elapsed = {f"{LINE_RE.match(s).group(6)}:{LINE_RE.match(s).group(7)}" for s in progress}
    assert len(elapsed) >= 2, elapsed
    glyphs = {LINE_RE.match(s).group(1) for s in progress}
    assert len(glyphs) >= 5, glyphs
    assert log_lines[-1] == "Loaded big8.s19", log_lines
    assert final == "Loaded big8.s19 (S19 only)", final
    assert row == idle_row, (row, idle_row)
    assert timers == 0, timers


# ===========================================================================
# Inc 12a E5 corrective, round 2 — arms that kill the surviving mutants
# (evidence/inc-12a/mutation-summary.md; ids MUT12a-M-NN in E5-rulings.md)
# ===========================================================================


def test_tc_b100_50_a_restarted_key_becomes_the_newest_run(tmp_path: Path) -> None:
    """LLR-176.1p / LLR-176.1o (A12-22, MUT12a-M-09): begin ``report`` A,
    begin ``file_load`` B, restart ``report`` → the restarted report is the
    shown run: its step 2 paints (``step 2/2 b``, bar 50) and B's step 2
    paints nothing; ending the report shows B again.

    Why: a restart is the newest action the user started, so it owns the
    line; it must not drop back behind an older run.
    Negative control (M-09, the restart keeps its old position): the
    report's step is hidden behind B."""

    async def scenario(app, pilot, log):
        app.begin_busy("report", "A", ("a", "b"))
        gb = app.begin_busy("file_load", "B", FILE_STEPS)
        ga2 = app.begin_busy("report", "A2", ("a", "b"))
        app.step_busy("report", ga2, 2)
        restarted = (_status(app), _bar(app)[0])
        app.step_busy("file_load", gb, 2)
        hidden = _status(app)
        app.end_busy("report", ga2, "")
        handed = _status(app)
        app.end_busy("file_load", gb, "")
        return restarted, hidden, handed

    restarted, hidden, handed = _run(tmp_path / "app", scenario)
    assert restarted[0].endswith(f" A2{DOT}step 2/2 b{DOT}00:00"), restarted
    assert restarted[1] == 50, restarted
    assert hidden == restarted[0], (hidden, restarted)
    assert f" B{DOT}step 2/3 Parse{DOT}" in handed, handed


def test_tc_b100_50_a_falling_amount_never_lowers_the_bar(tmp_path: Path) -> None:
    """LLR-176.1c (``never falls within the same step``, MUT12a-M-20): one
    step; 50 of 100 → bar 50; then 20 of 100 on the same step → bar still
    50; then 80 of 100 → 80.

    Why: a bar that moves backwards reads as a restart or a fault.
    Negative control (M-20, the never-falls rule removed): 50, 20, 80."""

    async def scenario(app, pilot, log):
        g = app.begin_busy("report", "L", ("a",))
        values = []
        for done in (50, 20, 80):
            app.step_busy("report", g, 1, done, 100)
            values.append(_bar(app)[0])
        app.end_busy("report", g, "")
        return values

    assert _run(tmp_path / "app", scenario) == [50, 50, 80]


def test_tc_b100_50_ending_a_middle_run_shows_the_newest_remaining(tmp_path: Path) -> None:
    """LLR-176.1o (A12-21, MUT12a-M-28): three runs begun in the order
    report, diff report, file load (the file load at step 2); the diff
    report (the middle one) ends → the file load, the newest remaining run,
    is shown at ``step 2/3 Parse`` with bar 33.

    Why: the hand-back after an end must pick the newest run, not the
    oldest; with two runs left the choice is visible.
    Negative control (M-28, the oldest remaining is shown): the report."""

    async def scenario(app, pilot, log):
        gr = app.begin_busy("report", "R", REPORT_STEPS)
        gd = app.begin_busy("diff_report", "D", DIFF_STEPS)
        gl = app.begin_busy("file_load", "F", FILE_STEPS)
        app.step_busy("file_load", gl, 2)
        app.end_busy("diff_report", gd, "")
        shown = (_status(app), _bar(app)[0])
        app.end_busy("file_load", gl, "")
        app.end_busy("report", gr, "")
        return shown

    text, bar = _run(tmp_path / "app", scenario)
    assert f" F{DOT}step 2/3 Parse{DOT}" in text, text
    assert bar == 33, bar


def test_tc_b100_50_a_begin_after_the_last_end_starts_one_timer(tmp_path: Path) -> None:
    """LLR-176.1e / LLR-176.1f (MUT12a-M-31): begin, end (the last end),
    then two overlapping begins → exactly 1 running 0.1 s timer, and the
    spinner advances off its first frame within 3 s.

    Why: the second action of a session must animate like the first; a
    stopped timer kept as "the timer" leaves the line frozen.
    Negative control (M-31, the stopped timer is not cleared): 0 running
    timers and the glyph never moves."""

    async def scenario(app, pilot, log):
        g0 = app.begin_busy("report", "R", REPORT_STEPS)
        app.end_busy("report", g0, "")
        await _settle(pilot, 3)
        ga = app.begin_busy("report", "R", REPORT_STEPS)
        gb = app.begin_busy("file_load", "F", FILE_STEPS)
        await _settle(pilot, 2)
        timers = len(_busy_timers(app))
        moved = False
        for _ in range(60):
            if not _status(app).startswith(FRAMES[0]):
                moved = True
                break
            await pilot.pause(0.05)
        app.end_busy("file_load", gb, "")
        app.end_busy("report", ga, "")
        return timers, moved

    timers, moved = _run(tmp_path / "app", scenario)
    assert timers == 1, timers
    assert moved, "the spinner never left its first frame"


def test_tc_b100_50_a_stale_failure_logs_nothing(tmp_path: Path) -> None:
    """S-e / A12a-04 (MUT12a-M-44): a file load begun as ``a.s19`` is
    restarted as ``b.s19``; the replaced run's failure arrives late
    (``_busy_fail`` with the first generation) → returns ``False``, logs no
    line, and the ``b.s19`` line stays shown.

    Why: a replaced worker that raises must not write ``Loading b.s19
    failed`` for an action that is still running.
    Negative control (M-44, no generation check): ``Loading b.s19 failed``
    is logged."""

    async def scenario(app, pilot, log):
        g1 = app.begin_busy("file_load", "Loading a.s19", FILE_STEPS)
        g2 = app.begin_busy("file_load", "Loading b.s19", FILE_STEPS)
        before = _status(app)
        mark = len(log.messages)
        result = app._busy_fail("file_load", g1)
        out = (result, log.since(mark), _status(app) == before)
        app.end_busy("file_load", g2, "")
        return out

    result, added, unchanged = _run(tmp_path / "app", scenario)
    assert result is False, result
    assert added == [], added
    assert unchanged, "the running line changed"


def _commit_save_body_returns(function) -> list:
    """For each ``return`` after the ``_busy_begin_action`` begin in
    ``function`` (nested functions skipped): ``(line, has_end)``, where
    ``has_end`` says an earlier statement of the same block is an
    ``end_busy("save_project", …)`` call."""
    begin_line = None
    for node in ast.walk(function):
        if isinstance(node, ast.Call) and _callee(node.func) == "_busy_begin_action":
            begin_line = node.lineno
            break
    assert begin_line is not None, "no _busy_begin_action call in _commit_project_save"

    def _is_end(stmt) -> bool:
        return (
            isinstance(stmt, ast.Expr)
            and isinstance(stmt.value, ast.Call)
            and _callee(stmt.value.func) == "end_busy"
            and bool(stmt.value.args)
            and isinstance(stmt.value.args[0], ast.Constant)
            and stmt.value.args[0].value == "save_project"
        )

    found: list = []

    def _walk_block(stmts) -> None:
        for index, stmt in enumerate(stmts):
            if isinstance(stmt, ast.Return) and stmt.lineno > begin_line:
                found.append((stmt.lineno, any(_is_end(s) for s in stmts[:index])))
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            for field in ("body", "orelse", "finalbody"):
                inner = getattr(stmt, field, None)
                if isinstance(inner, list):
                    _walk_block(inner)
            for handler in getattr(stmt, "handlers", None) or []:
                _walk_block(handler.body)

    _walk_block(function.body)
    return found


def test_tc_b100_51_every_save_abort_return_ends_its_run_first() -> None:
    """LLR-176.2c (CR12a-2, MUT12a-M-69): in ``_commit_project_save``, every
    ``return`` after the busy begin is preceded, in its own block, by an
    ``end_busy("save_project", …)`` call — 10 abort exits today.

    Why: an abort arm that paints with ``set_status`` instead leaves the run
    open until the ``finally``, so the log ends with a stray
    ``Saving project <name> failed`` after the rollback note, and the arm's
    own text is no longer the outcome.
    Negative control (M-69, one arm's ``end_busy`` → ``set_status``): that
    return is listed without an end."""
    tree = ast.parse(APP_SOURCE.read_text(encoding="utf-8"))
    found = _commit_save_body_returns(_class_methods(tree)["_commit_project_save"])
    assert len(found) >= 10, found
    assert [line for line, has_end in found if not has_end] == [], found


def test_tc_b100_51_save_validation_abort_ends_with_its_own_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLR-176.2c (CR12a-2, MUT12a-M-69), one abort exit driven:
    ``validate_project_files`` returning an error inside
    ``_commit_project_save`` → 1 effective end whose outcome is that error,
    the error is the last log line, no ``… failed`` line, bar ``[0, 25, 0]``,
    0 timers.

    Why: the abort arm's own text is what the user must read last.
    Negative control (M-69): the error is painted, then the ``finally``
    logs ``Saving project S5 failed`` after it."""
    from s19_app.tui.screens import SaveProjectPayload

    seam = Seam(monkeypatch)
    real_validate = app_module.validate_project_files

    def _validate(folder, *args, **kwargs):
        if sys._getframe(1).f_code.co_name == "_commit_project_save":
            return [], [], "synthetic validation error"
        return real_validate(folder, *args, **kwargs)

    monkeypatch.setattr(app_module, "validate_project_files", _validate)

    async def scenario(app, pilot, log):
        await _load_case01_image(app, pilot)
        seam.bar.clear()
        mark = len(log.messages)
        app._handle_save_dialog(SaveProjectPayload(parent_folder=str(app.workarea), project_name="S5"))
        await _settle(pilot, 6)
        return log.since(mark), len(_busy_timers(app))

    added, timers = _run(tmp_path / "app", scenario)
    ends = seam.effective("save_project")
    assert [e.outcome for e in ends] == ["synthetic validation error"], seam.ends
    assert added[-1] == "synthetic validation error", added
    assert not [m for m in added if m.endswith(" failed")], added
    assert seam.bar == [0, 25, 0], seam.bar
    assert timers == 0, timers


def test_tc_b100_51_file_load_reads_the_copy_size_before_the_worker() -> None:
    """A12a-08 (MUT12a-M-82; tester notes §5): in ``load_from_path`` the
    ``copied.stat()`` call sits on an earlier line than the
    ``_start_load_worker(`` call.

    Why: a ``stat`` that raises must end the load through the kickoff's own
    failure arm while the kickoff still owns the run; after the dispatch
    the worker owns it and the run would end twice or not at all.
    Negative control (M-82, the ``stat`` after the dispatch): RED."""
    tree = ast.parse(APP_SOURCE.read_text(encoding="utf-8"))
    function = _class_methods(tree)["load_from_path"]
    stats = [
        node.lineno
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "stat"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "copied"
    ]
    starts = [
        node.lineno
        for node in ast.walk(function)
        if isinstance(node, ast.Call) and _callee(node.func) == "_start_load_worker"
    ]
    assert len(stats) == 1 and len(starts) == 1, (stats, starts)
    assert stats[0] < starts[0], (stats, starts)


def test_tc_b100_51_file_load_into_an_open_project_ends_after_the_sync(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A12a-05 (MUT12a-M-89): project ``P`` open; a worker load of a
    different image ``other.s19`` → the sync into the project writes its
    line, and the outcome ``Loaded other.s19`` is the last log line, after
    every sync line; 1 effective end.

    Why: the outcome closes the action; a project line logged after it would
    make the log say the load ended before its sync.
    Negative control (M-89, the end before the sync): the sync's line comes
    after ``Loaded other.s19``."""
    base = tmp_path / "app"
    _project_p(base, a2l=False)
    src = tmp_path / "src"
    src.mkdir()
    other = src / "other.s19"
    other.write_bytes((CASE01 / "firmware.s19").read_bytes())
    projects.flip_data_byte(other)
    seam = Seam(monkeypatch)

    async def scenario(app, pilot, log):
        app._handle_load_project("P")
        await _settle(pilot, 8)
        opened = app.current_project
        mark = len(log.messages)
        app.load_from_path(other)
        await _drain(app, pilot)
        return opened, log.since(mark)

    opened, added = _run(base, scenario)
    assert opened == "P", opened
    ends = seam.effective("file_load")
    assert [e.outcome for e in ends] == ["Loaded other.s19"], seam.ends
    assert added[-1] == "Loaded other.s19", added
    assert len(added) >= 2 and any("other" in m for m in added[:-1]), added
