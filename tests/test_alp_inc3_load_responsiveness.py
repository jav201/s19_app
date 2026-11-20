"""Batch 2026-11-18-a2l-load-performance Inc 3 E4 — prepared-load responsiveness.

Independent tester lane G-T-I3-PERF. Every oracle below comes from the Inc 3
ledger ``.dev-flow/2026-11-18-a2l-load-performance/inc-3/02-test-cases.md``
and the requirements ``01-requirements.md``: the duration budget and the
four named phases are R-A2L-REFRESH.040-.042, and the tick/gate/window
obligation moved to R-A2L-REFRESH.050 (E4R). Under the Q1 window
(preparation entry until installation is dispatched) a 50 ms UI timer keeps
every tick <= 100 ms late (``timing_bound`` on CI), >= 3 ticks during the
0.20 s producer-worker gate and zero failing observations; the held
install/publication step's worst stall is recorded (``install_worst_stall``)
but not asserted. The case_06 duration budget is per-route final bounds
(operator D1, 2026-11-20): .040 median <= 54 s and every run < 68 s,
.041 median <= 60 s and every run < 75 s, .042 median <= 52 s and every
run < 65 s. Platform/Python/host load are recorded without personal paths.

RED contract: each node opens with the seam guard, so the base revision
ceac08cf fails RED immediately without running the real case_06 routes
(which would take minutes on the base and prove nothing new). Every seam
is resolved lazily (``importlib`` + ``getattr``).
"""

from __future__ import annotations

import asyncio
import gc
import importlib
import json
import os
import platform
import statistics
import sys
import threading
import time
from pathlib import Path
from typing import Optional

import pytest

import s19_app.tui.app as app_module
from s19_app.tui.a2l_definition import describe_definitions
from s19_app.tui.a2l_parse import parse_a2l_file
from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens import ConfirmQuestionScreen
from s19_app.tui.services.a2l_service import enrich_tags_and_render
from tests.conftest import make_large_s19
from tests.support.b100_workers import settle_workers
from tests.support.b103_a2l_arrays import characteristic, inline
from tests.support.timing import report_margin, timing_bound, wait_until
from tests.test_alp_inc2_a2l_attach import _run, _submit_typed, _typed_attach

ROOT = Path(__file__).resolve().parents[1]
CASE06_DIR = ROOT / "examples" / "case_06_large_nested_a2l"
CASE06 = CASE06_DIR / "firmware.a2l"
CASE06_IMAGE = CASE06_DIR / "firmware.s19"
CASE06_MAC = CASE06_DIR / "firmware.mac"
CASE06_BYTES = 36_702_962
CASE06_TAGS = 220_040
CASE06_FIRST = "CHAR_00000_00"
CASE06_LAST = "MEAS_05500_19"

PHASES_IMAGE = ("admission/copy", "parse", "post-parse preparation", "install/publication")
PHASES_PROJECT = ("admission", "parse", "post-parse preparation", "install/publication")

TICK_PERIOD_S = 0.05
GATE_HOLD_S = 0.20
MIN_GATE_TICKS = 3
# Per-route final bounds (operator D1, 2026-11-20, M2c on the reference
# host): median bound = ⌈median × 1.25⌉ s, run bound = ⌈median bound × 1.25⌉ s,
# negative-control hold = run bound + 5 s (73/80/70 s).
BUDGET_S = {
    "R-A2L-REFRESH.040": (54.0, 68.0),
    "R-A2L-REFRESH.041": (60.0, 75.0),
    "R-A2L-REFRESH.042": (52.0, 65.0),
}
TICK_BOUND_S = 0.1

# ---------------------------------------------------------------------------
# Lazy seam access and the fast RED guard.
# ---------------------------------------------------------------------------


def _fl_module():
    return importlib.import_module("s19_app.tui.app.file_load")


def _pl_module():
    return importlib.import_module("s19_app.tui.app.project_load")


def _sh_module():
    return importlib.import_module("s19_app.tui.app.shared")


def _fields(dc) -> set:
    import dataclasses

    assert dc is not None
    return {f.name for f in dataclasses.fields(dc)}


def _sig_has(func, name: str) -> bool:
    import inspect

    return name in inspect.signature(func).parameters


def _guard_perf_seams() -> None:
    """The fast RED guard: the Inc 3 prepared-snapshot contracts must exist
    before any timing arm runs its real case_06 route."""
    fl = _fl_module()
    assert getattr(fl, "FileLoadRequest", None) is not None, (
        "FileLoadRequest (F1) missing — the Inc 3 prepared-load context is not implemented"
    )
    assert "a2l_preparation" in _fields(getattr(_sh_module(), "PreparedLoad")), (
        "PreparedLoad.a2l_preparation (S1) missing — the Inc 3 snapshot handoff is not implemented"
    )
    assert _sig_has(fl.FileLoadMixin._prepare_load_payload, "prepare_a2l"), "F5 prepare_a2l seam missing"
    assert _sig_has(fl.FileLoadMixin._start_load_worker, "context"), "F6 context seam missing"
    assert _sig_has(fl.FileLoadMixin._parse_loaded_file, "context"), "F4 context seam missing"
    pl = _pl_module()
    assert {"captured_a2l_generation", "captured_image_generation"} <= _fields(
        getattr(pl, "ProjectLoadRequest")
    ), "P1 captured-generation fields missing"
    assert "a2l_only" in _fields(getattr(pl, "PreparedProjectLoad")), "P2 a2l_only field missing"
    assert CASE06.stat().st_size == CASE06_BYTES, "case_06 fixture moved or changed size"


def _host_line() -> str:
    """Platform/Python/host load record with no personal paths."""
    cpu = os.cpu_count() or 0
    host_load = (
        f"{os.getloadavg()[0]:.2f}" if hasattr(os, "getloadavg") else "n/a"
    )
    return (
        f"host: platform={platform.platform()} python={platform.python_version()} "
        f"cpu_count={cpu} process_uptime_s={time.process_time():.1f} host_load={host_load}"
    )


# ---------------------------------------------------------------------------
# Instruments: 50 ms UI timer, timed producer gate, timed phase seams.
# ---------------------------------------------------------------------------


class TickTimer:
    """A self-re-arming 50 ms UI timer; records (due, fired, lateness)."""

    def __init__(self, app: S19TuiApp) -> None:
        self.app = app
        self.observations: list = []
        self.stopped = False

    def start(self) -> None:
        self._due = time.perf_counter() + TICK_PERIOD_S
        self.app.set_timer(TICK_PERIOD_S, self._fire)

    def _fire(self) -> None:
        if self.stopped:
            return
        fired = time.perf_counter()
        self.observations.append((self._due, fired, fired - self._due))
        self._due = fired + TICK_PERIOD_S
        self.app.set_timer(TICK_PERIOD_S, self._fire)

    def stop(self) -> None:
        self.stopped = True

    def gate_ticks(self, started: float, released: float) -> int:
        return sum(1 for _due, fired, _l in self.observations if started <= fired <= released)


class TimedGate:
    """Block the first producer call on the worker and time every call."""

    def __init__(self, monkeypatch) -> None:
        real = getattr(S19TuiApp, "_prepare_a2l_attach_snapshot", None)
        self.entered = threading.Event()
        self.release = threading.Event()
        self.gate_started: Optional[float] = None
        self.gate_released: Optional[float] = None
        self.call_times: list = []
        gate = self

        def _wrap(self_, **kwargs):
            if not gate.entered.is_set():
                # The real producer's first statement is gc.disable() (D-13); the
                # gate holds at producer entry, so it holds with the collector
                # disabled as production does. The window start is unchanged.
                gc.disable()
                gate.gate_started = time.perf_counter()
                gate.entered.set()
                if not gate.release.wait(120):
                    gc.enable()
                    raise TimeoutError("the 0.20 s producer gate was never released")
                gate.gate_released = time.perf_counter()
            t0 = time.perf_counter()
            try:
                return real(self_, **kwargs) if real is not None else None
            finally:
                gate.call_times.append((t0, time.perf_counter(), threading.get_ident()))

        monkeypatch.setattr(S19TuiApp, "_prepare_a2l_attach_snapshot", _wrap, raising=False)


def _timed(monkeypatch, owner, name: str, records: list) -> None:
    """Record (name, t0, t1, thread) around every real call."""
    real = getattr(owner, name)

    def wrapped(*args, **kwargs):
        t0 = time.perf_counter()
        try:
            return real(*args, **kwargs)
        finally:
            records.append((name, t0, time.perf_counter(), threading.get_ident()))

    monkeypatch.setattr(owner, name, wrapped, raising=False)


def _arm_route_recorders(app: S19TuiApp, monkeypatch, dispatch_name: str, outcomes: list, fanouts: list, dispatches: list) -> None:
    real_fanout = S19TuiApp._refresh_a2l_dependent_views

    def fanout() -> None:
        fanouts.append(threading.get_ident())
        real_fanout(app)

    monkeypatch.setattr(app, "_refresh_a2l_dependent_views", fanout, raising=False)
    real_ct = app.call_from_thread

    def ct(callback, *args, **kwargs):
        if getattr(callback, "__name__", "") == dispatch_name:
            dispatches.append(time.perf_counter())
        return real_ct(callback, *args, **kwargs)

    monkeypatch.setattr(app, "call_from_thread", ct)
    real_end = S19TuiApp.end_busy

    def end(key, gen, outcome):
        outcomes.append((key, str(outcome), time.perf_counter()))
        return real_end(app, key, gen, outcome)

    monkeypatch.setattr(app, "end_busy", end)


def _seed_project(workarea: Path, name: str, *, image: Optional[Path] = None, mac: Optional[Path] = None, a2l: Optional[Path] = None) -> Path:
    folder = workarea / name
    folder.mkdir(parents=True, exist_ok=True)
    active = None
    if image is not None:
        (folder / image.name).write_bytes(image.read_bytes())
        active = image.stem
    if mac is not None:
        (folder / mac.name).write_bytes(mac.read_bytes())
    if a2l is not None:
        (folder / a2l.name).write_bytes(a2l.read_bytes())
    (folder / "project.json").write_text(
        json.dumps({"schema_version": 1, "active_variant": active}), encoding="utf-8"
    )
    return folder


def _assert_fixture_guards(
    app: S19TuiApp,
    tag_count: int = CASE06_TAGS,
    first: str = CASE06_FIRST,
    last: str = CASE06_LAST,
) -> None:
    """The committed probe facts are fixture guards, never a measured
    load-time result."""
    assert app.current_a2l_data is not None
    tags = app.current_a2l_data["tags"]
    assert len(tags) == tag_count, len(tags)
    assert tags[0]["name"] == first, tags[0]
    assert tags[-1]["name"] == last, tags[-1]
    assert app.current_a2l_data["errors"] == []


async def _tick_loop(pilot, timer: TickTimer, gate: TimedGate) -> None:
    """Yield the UI until >= 3 ticks fired during a >= 0.20 s gate hold."""
    assert gate.gate_started is not None
    while True:
        ticks = timer.gate_ticks(gate.gate_started, time.perf_counter())
        if ticks >= MIN_GATE_TICKS and time.perf_counter() - gate.gate_started >= GATE_HOLD_S:
            return
        await asyncio.sleep(0.02)


def _gate_summary(run: dict, timer: TickTimer, gate: TimedGate, dispatches: list) -> None:
    """Record the gate and the R-A2L-REFRESH.050 Q1 tick window.

    The Q1 = A window runs from preparation entry (``gate.gate_started``)
    until installation is dispatched (``dispatches[0]``); only tick
    observations whose due time lies inside that window count as failures.
    The held install/publication step's worst tick stall after dispatch is
    recorded (``install_worst_stall``) but never asserted.
    """
    assert gate.gate_started is not None and gate.gate_released is not None
    assert dispatches, "the install dispatch was never recorded"
    run["gate_elapsed"] = gate.gate_released - gate.gate_started
    run["gate_ticks"] = timer.gate_ticks(gate.gate_started, gate.gate_released)
    run["tick_observations"] = list(timer.observations)
    window_start = gate.gate_started
    window_end = dispatches[0]
    run["window"] = (window_start, window_end)
    run["tick_failures"] = sum(
        1
        for due, _fired, lateness in timer.observations
        if lateness > timing_bound(TICK_BOUND_S) and window_start <= due <= window_end
    )
    run["install_worst_stall"] = max(
        (lateness for due, _fired, lateness in timer.observations if due > window_end),
        default=0.0,
    )
    run["window_worst"] = max(
        (
            lateness
            for due, _fired, lateness in timer.observations
            if window_start <= due <= window_end
        ),
        default=0.0,
    )


def test_r_a2l_refresh_050_gate_hold_loop_does_not_drive_the_pilot():
    """R-A2L-REFRESH.050 (E4R) — the gate-hold tick loop must not drive the
    pilot.  In Textual 8.2.8 every ``pilot.pause`` posts one callback to the
    app and to every widget and waits for all of them (643–858 UI callbacks
    per late tick), a test-made load that made the measured gate-hold ticks
    late (FA-TICK4); the loop only has to yield, so it sleeps via
    ``asyncio.sleep``.  Run ``_tick_loop`` under ``asyncio.run`` with a
    counting pilot, a timer whose ``gate_ticks`` returns 0 once then
    ``MIN_GATE_TICKS``, and a gate held for 1 s: it must return without a
    single ``pilot.pause`` call."""
    pause_calls: list = []

    class _CountingPilot:
        async def pause(self, *_args, **_kwargs):
            pause_calls.append(1)

    class _FakeTimer:
        def __init__(self):
            self._calls = 0

        def gate_ticks(self, _started, _now):
            self._calls += 1
            return 0 if self._calls == 1 else MIN_GATE_TICKS

    class _FakeGate:
        gate_started = time.perf_counter() - 1.0

    asyncio.run(_tick_loop(_CountingPilot(), _FakeTimer(), _FakeGate()))
    assert len(pause_calls) == 0, (
        f"the gate-hold loop drove the pilot's pause {len(pause_calls)} time(s)"
    )


# ---------------------------------------------------------------------------
# The three serial-timing alternatives (3 fresh-app runs each).
# ---------------------------------------------------------------------------


def _one_image_run(
    base: Path,
    monkeypatch,
    label: str,
    *,
    a2l: Path = CASE06,
    image: Path = CASE06_IMAGE,
    tag_count: int = CASE06_TAGS,
    first: str = CASE06_FIRST,
    last: str = CASE06_LAST,
) -> dict:
    async def body(app: S19TuiApp, pilot):
        # The attach is a separate route and is NOT part of the measured run.
        await _typed_attach(app, pilot, a2l)
        await settle_workers(pilot)
        a0, i0 = app._a2l_view_generation, app._image_generation
        assert app.current_a2l_data is not None
        assert len(app.current_a2l_data["tags"]) == tag_count

        phases: list = []
        outcomes: list = []
        fanouts: list = []
        dispatches: list = []
        _timed(monkeypatch, app, "_parse_loaded_file", phases)
        _timed(monkeypatch, app, "_prepare_load_payload", phases)
        _arm_route_recorders(app, monkeypatch, "_complete_prepared_load", outcomes, fanouts, dispatches)
        gate = TimedGate(monkeypatch)
        timer = TickTimer(app)
        timer.start()
        total_start = time.perf_counter()
        await _submit_typed(app, pilot, str(image))
        # The typed load may ask for confirmation first; when it does not, the
        # worker goes straight to the producer gate. Wait for whichever comes
        # first: waiting a fixed 10 s for a modal that never opens held the
        # 0.20 s gate for 10 s (M1, relevo-23: case_06 gate_elapsed 10.08 s).
        await wait_until(
            pilot,
            lambda: isinstance(app.screen, ConfirmQuestionScreen) or gate.entered.is_set(),
            "the typed-load confirm modal or the producer gate",
            timeout=180.0,
        )
        if isinstance(app.screen, ConfirmQuestionScreen):
            await pilot.press("y")
        await wait_until(pilot, gate.entered.is_set, "the producer gate", timeout=180.0)
        await _tick_loop(pilot, timer, gate)
        gate.release.set()
        await settle_workers(pilot)
        await wait_until(pilot, lambda: bool(outcomes), "the image outcome", timeout=180.0)
        timer.stop()
        await pilot.pause()
        run: dict = {"label": label, "total": outcomes[0][2] - total_start, "phases": {}}
        parse_entry = next(r for r in phases if r[0] == "_parse_loaded_file")
        prepare = next(r for r in phases if r[0] == "_prepare_load_payload")
        run["phases"]["admission/copy"] = parse_entry[1] - total_start
        run["phases"]["parse"] = parse_entry[2] - parse_entry[1]
        run["phases"]["post-parse preparation"] = prepare[2] - prepare[1]
        run["phases"]["install/publication"] = outcomes[0][2] - dispatches[0]
        _gate_summary(run, timer, gate, dispatches)
        assert len(outcomes) == 1 and outcomes[0][1].startswith("Loaded "), outcomes
        assert app._a2l_view_generation == a0 + 1 and app._image_generation == i0 + 1
        assert app.current_file is not None
        assert app._a2l_enriched_key == (a0 + 1, i0 + 1, len(app.current_file.mem_map))
        assert len(fanouts) == 1, fanouts
        accepted = getattr(app, "_accepted_a2l_picker_snapshots", None)
        assert accepted is not None and set(accepted) == {"check", "patch"}, accepted
        _assert_fixture_guards(app, tag_count, first, last)
        return run

    return _run(base, body)


def _one_project_run(
    base: Path,
    monkeypatch,
    label: str,
    shape: str,
    *,
    a2l: Path = CASE06,
    image: Path = CASE06_IMAGE,
    mac: Path = CASE06_MAC,
    tag_count: int = CASE06_TAGS,
    first: str = CASE06_FIRST,
    last: str = CASE06_LAST,
) -> dict:
    async def body(app: S19TuiApp, pilot):
        a0, i0 = app._a2l_view_generation, app._image_generation
        assert (a0, i0) == (0, 0)
        if shape == "pair":
            _seed_project(app.workarea, "proj_a", image=image, mac=mac, a2l=a2l)
        elif shape == "nomac":
            _seed_project(app.workarea, "proj_a", image=image, a2l=a2l)
        else:
            _seed_project(app.workarea, "proj_a", a2l=a2l)

        phases: list = []
        outcomes: list = []
        fanouts: list = []
        dispatches: list = []
        _timed(monkeypatch, app, "_prepare_project_load", phases)
        _timed(monkeypatch, app_module.deps, "parse_a2l_cached", phases)
        _timed(monkeypatch, app, "_parse_data_file", phases)
        if shape != "only":
            _timed(monkeypatch, app, "_prepare_load_payload", phases)
        _arm_route_recorders(app, monkeypatch, "_on_project_loaded", outcomes, fanouts, dispatches)
        gate = TimedGate(monkeypatch)
        timer = TickTimer(app)
        timer.start()
        total_start = time.perf_counter()
        from tests.support import b100_load_dialog as ld

        await pilot.press("p")
        await wait_until(pilot, lambda: len(app.screen.query("#load_path")) > 0, "Load dialog did not open")
        await ld.highlight_row(pilot, app, "proj_a")
        await pilot.press("enter")
        await wait_until(pilot, lambda: not ld.is_load_dialog(app.screen), "the Load dialog to close")
        await wait_until(pilot, gate.entered.is_set, "the producer gate", timeout=180.0)
        await _tick_loop(pilot, timer, gate)
        gate.release.set()
        await settle_workers(pilot)
        await wait_until(pilot, lambda: bool(outcomes), "the project outcome", timeout=180.0)
        timer.stop()
        await pilot.pause()
        run: dict = {"label": label, "total": outcomes[0][2] - total_start, "phases": {}}
        worker_entry = next(r for r in phases if r[0] == "_prepare_project_load")
        run["phases"]["admission"] = worker_entry[1] - total_start
        parse_a2l = sum(r[2] - r[1] for r in phases if r[0] == "parse_a2l_cached")
        parse_image = sum(r[2] - r[1] for r in phases if r[0] == "_parse_data_file")
        run["phases"]["parse"] = parse_a2l + parse_image
        if shape == "only":
            assert gate.call_times, "the P-ONLY producer call was never recorded"
            run["phases"]["post-parse preparation"] = gate.call_times[0][1] - gate.gate_started
        else:
            run["phases"]["post-parse preparation"] = sum(
                r[2] - r[1] for r in phases if r[0] == "_prepare_load_payload"
            )
        run["phases"]["install/publication"] = outcomes[0][2] - dispatches[0]
        _gate_summary(run, timer, gate, dispatches)
        assert len(outcomes) == 1, outcomes
        assert outcomes[0][1] not in (
            "Load superseded — current state kept.",
        ) and not outcomes[0][1].startswith("Project NOT loaded"), outcomes
        assert len(fanouts) == 1, fanouts
        _assert_fixture_guards(app, tag_count, first, last)
        accepted = getattr(app, "_accepted_a2l_picker_snapshots", None)
        assert accepted is not None and set(accepted) == {"check", "patch"}, accepted
        if shape == "pair":
            assert app._a2l_view_generation == a0 + 3 and app._image_generation == i0 + 2
            assert app.current_file is not None and app.current_file.mac_records
        elif shape == "nomac":
            assert app._a2l_view_generation == a0 + 2 and app._image_generation == i0 + 1
            assert app.current_file is not None
            assert not app.current_file.mac_records and app.current_file.mac_path is None
        else:
            assert app._a2l_view_generation == a0 + 2 and app._image_generation == i0
            assert app.current_file is None
        return run

    return _run(base, body)


def _assert_budget(label: str, runs: list, phase_names: tuple) -> None:
    median_bound, run_bound = BUDGET_S[label.split()[0]]
    totals = [run["total"] for run in runs]
    median = statistics.median(totals)
    assert median <= report_margin(label, median, timing_bound(median_bound)), runs
    assert all(total < timing_bound(run_bound) for total in totals), runs
    for run in runs:
        assert tuple(run["phases"]) == phase_names, run
        assert all(value >= 0 for value in run["phases"].values()), run
        # R-A2L-REFRESH.050 (E4R): the gate/tick/window asserts; the held
        # install stall is recorded (install_worst_stall), never asserted.
        assert run["gate_elapsed"] >= GATE_HOLD_S, run
        assert run["gate_ticks"] >= MIN_GATE_TICKS, run
        assert run["tick_failures"] == 0, run
        assert run["window_worst"] <= report_margin(
            f"{label} R-A2L-REFRESH.050 in-window tick lateness",
            run["window_worst"],
            timing_bound(TICK_BOUND_S),
        ), run
        assert run["tick_observations"], run
    print(f"[{label}] {_host_line()}")
    for run in runs:
        phases = " | ".join(f"{name}={run['phases'][name]:.3f}s" for name in phase_names)
        window_start, window_end = run["window"]
        print(
            f"[{label}] run {run['label']}: total={run['total']:.3f}s {phases} "
            f"gate_ticks={run['gate_ticks']} gate_elapsed={run['gate_elapsed']:.3f}s "
            f"window=[{window_start:.3f},{window_end:.3f}]s "
            f"install_worst_stall={run['install_worst_stall']:.3f}s "
            f"tick_observations={len(run['tick_observations'])} tick_failures={run['tick_failures']}"
        )
    print(
        f"[{label}] totals={[f'{t:.3f}' for t in totals]} median={median:.3f}s "
        f"bound_median={timing_bound(median_bound)}s bound_run={timing_bound(run_bound)}s"
    )


@pytest.mark.serial_timing
@pytest.mark.slow
def test_r040_image_post_parse_responsive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """R-A2L-REFRESH.040/1 (duration budget) with the tick/gate/window
    obligation cited as R-A2L-REFRESH.050 (E4R): 3 serial case_06 image+A2L
    runs; request-to-outcome total includes admission/copy and parse; 4
    named phases; median <= 54 s, every run < 68 s (D1); the 50 ms tick
    window (preparation entry to install dispatch) with every tick <= 100 ms
    late, >= 3 ticks during the 0.20 s producer gate, zero failing."""
    _guard_perf_seams()
    runs = [
        _one_image_run(tmp_path / f"run{i}", monkeypatch, f"{i + 1}/3")
        for i in range(3)
    ]
    _assert_budget("R-A2L-REFRESH.040 image+A2L case_06", runs, PHASES_IMAGE)


@pytest.mark.serial_timing
@pytest.mark.slow
@pytest.mark.parametrize(
    "shape",
    ["pair", "nomac"],
    ids=[f"R-A2L-REFRESH.041/{i}" for i in range(1, 3)],
)
def test_r041_project_pair_post_parse_responsive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shape: str) -> None:
    """R-A2L-REFRESH.041/1-/2 (duration budget) with the tick/gate/window
    obligation cited as R-A2L-REFRESH.050 (E4R): 3 serial case_06
    project-pair runs per shape (with and without MAC); total includes
    parse; 4 named phases; median <= 60 s, every run < 75 s (D1); the
    50 ms tick window and >= 3 gate ticks; each final pair current."""
    _guard_perf_seams()
    runs = [
        _one_project_run(tmp_path / f"run{i}", monkeypatch, f"{i + 1}/3", shape)
        for i in range(3)
    ]
    _assert_budget(f"R-A2L-REFRESH.041 project-pair {shape} case_06", runs, PHASES_PROJECT)


@pytest.mark.serial_timing
@pytest.mark.slow
def test_r042_a2l_only_post_parse_responsive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """R-A2L-REFRESH.042/1 (duration budget) with the tick/gate/window
    obligation cited as R-A2L-REFRESH.050 (E4R): 3 serial case_06 P-ONLY
    runs; total includes parse; admission/parse/preparation/
    install-publication reported with no copy phase fabricated; median
    <= 52 s, every run < 65 s (D1); the 50 ms tick window holds; final
    A2L-only state is current, no image/MAC."""
    _guard_perf_seams()
    runs = [
        _one_project_run(tmp_path / f"run{i}", monkeypatch, f"{i + 1}/3", "only")
        for i in range(3)
    ]
    _assert_budget("R-A2L-REFRESH.042 A2L-only case_06", runs, PHASES_PROJECT)
    for run in runs:
        assert "copy" not in "|".join(run["phases"]), run


# ---------------------------------------------------------------------------
# R-A2L-REFRESH.050 (E4R) — small same-oracle arms.
# ---------------------------------------------------------------------------

_SMALL_COUNT = 8000


def _small_pairwise_a2l(tmp_path: Path, count: int = _SMALL_COUNT) -> dict:
    """Generate ``count`` pairwise-disjoint one-byte objects at
    ``0x1000 + i*0x40 + (i % 7)*4`` (the same layout as
    ``tests/test_alp_a2l_occupancy.py::test_r_a2l_def_161_1``) and write the
    INLINE A2L into ``tmp_path``."""
    blocks = [
        characteristic(
            f"D{(i * 7919) % 10007}_{i}",
            "VALUE",
            f"0x{0x1000 + i * 0x40 + (i % 7) * 4:X}",
            "RL_U8",
            "NO_COMPU_METHOD",
            "0",
            "255",
        )
        for i in range(count)
    ]
    a2l = inline(tmp_path, *blocks)
    assert len(a2l["tags"]) == count, len(a2l["tags"])
    assert (a2l.get("errors") or []) == [], a2l.get("errors")
    return a2l


def _small_image(tmp_path: Path, count: int = _SMALL_COUNT) -> Path:
    """One contiguous S19 range covering every generated object address."""
    max_addr = 0x1000 + (count - 1) * 0x40 + ((count - 1) % 7) * 4
    span = max_addr - 0x1000 + 1
    bytes_per_range = (span + 15) // 16 * 16
    return make_large_s19(
        tmp_path / "small_image.s19",
        num_ranges=1,
        bytes_per_range=bytes_per_range,
        base_address=0x1000,
        gap_bytes=0,
    )


def _assert_small_oracle(label: str, run: dict) -> None:
    """The small-route R-A2L-REFRESH.050 oracle: gate/tick/window only, no
    duration budget."""
    assert run["gate_elapsed"] >= GATE_HOLD_S, run
    assert run["gate_ticks"] >= MIN_GATE_TICKS, run
    assert run["tick_failures"] == 0, run
    assert run["window_worst"] <= report_margin(
        f"{label} R-A2L-REFRESH.050 in-window tick lateness",
        run["window_worst"],
        timing_bound(TICK_BOUND_S),
    ), run
    assert run["tick_observations"], run
    window_start, window_end = run["window"]
    print(f"[{label}] {_host_line()}")
    print(
        f"[{label}] run: gate_ticks={run['gate_ticks']} "
        f"gate_elapsed={run['gate_elapsed']:.3f}s "
        f"window=[{window_start:.3f},{window_end:.3f}]s "
        f"install_worst_stall={run['install_worst_stall']:.3f}s "
        f"tick_observations={len(run['tick_observations'])} "
        f"tick_failures={run['tick_failures']}"
    )


@pytest.mark.serial_timing
@pytest.mark.parametrize("route", ["image", "project-pair", "a2l-only"])
def test_r_a2l_refresh_050_small_routes_same_oracle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, route: str) -> None:
    """R-A2L-REFRESH.050 (E4R) — the tick window holds on the three small
    routes with the same oracle as the case_06 arms: TimedGate 0.20 s,
    >= 3 gate ticks, 0 tick failures inside the Q1 window (preparation
    entry to install dispatch), exactly one fan-out, the success outcome
    and the generation bump; no duration budget."""
    _guard_perf_seams()
    a2l = _small_pairwise_a2l(tmp_path)
    a2l_path = Path(a2l["path"])
    image_path = _small_image(tmp_path)
    tag_count = len(a2l["tags"])
    first = a2l["tags"][0]["name"]
    last = a2l["tags"][-1]["name"]
    label = f"R-A2L-REFRESH.050 small {route}"
    if route == "image":
        run = _one_image_run(
            tmp_path / "run",
            monkeypatch,
            label,
            a2l=a2l_path,
            image=image_path,
            tag_count=tag_count,
            first=first,
            last=last,
        )
    elif route == "project-pair":
        run = _one_project_run(
            tmp_path / "run",
            monkeypatch,
            label,
            "nomac",
            a2l=a2l_path,
            image=image_path,
            tag_count=tag_count,
            first=first,
            last=last,
        )
    else:
        run = _one_project_run(
            tmp_path / "run",
            monkeypatch,
            label,
            "only",
            a2l=a2l_path,
            tag_count=tag_count,
            first=first,
            last=last,
        )
    _assert_small_oracle(label, run)


@pytest.mark.serial_timing
@pytest.mark.slow
@pytest.mark.parametrize(
    "route",
    ["describe", "enrich"],
    ids=["R-A2L-REFRESH.050/3", "R-A2L-REFRESH.050/4"],
)
def test_r_a2l_refresh_050_case06_producer_return_gap(route: str) -> None:
    """R-A2L-REFRESH.050 (E4R) — the case_06 producer return→resume gap.

    FA-TICK baseline 0.151–0.193 s: ``describe_definitions`` and
    ``enrich_tags_and_render`` each freed their large private containers in
    one C-level dealloc that held the GIL, so the 50 ms UI tick ran late.
    With the sliced release the gap from the target frame's ``return``
    profile event to the caller's next statement must be <= 50 ms
    (``report_margin``/``timing_bound``)."""
    a2l_data = parse_a2l_file(CASE06)
    assert len(a2l_data["tags"]) == CASE06_TAGS, len(a2l_data["tags"])
    if route == "describe":
        target = describe_definitions
        args = ([tag["name"] for tag in a2l_data["tags"]], a2l_data)
        label = "R-A2L-REFRESH.050 case_06 describe return→resume gap"
    else:
        target = enrich_tags_and_render
        args = (a2l_data, {})  # mem map {} — see REPORT.md
        label = "R-A2L-REFRESH.050 case_06 enrich return→resume gap"

    returned_at: list[float] = []

    def profiler(frame, event, arg):
        if event == "return" and frame.f_code is target.__code__:
            returned_at.append(time.perf_counter())

    sys.setprofile(profiler)
    gc.disable()
    try:
        result = target(*args)  # keep the result alive (the worker keeps it)
        resumed_at = time.perf_counter()
    finally:
        gc.enable()
        sys.setprofile(None)

    assert returned_at, "R-A2L-REFRESH.050: the return profile event was never observed"
    gap = resumed_at - returned_at[0]
    del result
    # One GIL hold of this length leaves a quarter of the R-A2L-REFRESH.050
    # 0.10 s tick bound for scheduler jitter (3/4 x 0.10 s; relevo-24 ruling).
    bound_s = 0.075
    print(f"[{label}] {_host_line()} gap={gap:.4f}s bound={timing_bound(bound_s)}s")
    assert gap <= report_margin(label, gap, timing_bound(bound_s)), (
        f"R-A2L-REFRESH.050: {route} return→resume gap {gap:.4f} s exceeds "
        f"{timing_bound(bound_s)} s"
    )
