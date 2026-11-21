"""P-279 I1, group G-APP (E4 tester): flag, snapshot producer and stage path.

Requirements: R-A2L-REFRESH.055-.059, .062, .064-.070 (the host-only arms of
.059/.063/.066/.068 and the page arm of .070 for the Patch page are run by the
orchestrator or belong to G-PICK; see ``02-test-cases-APP.md``).

Every test drives a product route under Textual Pilot (typed A2L attach,
image+A2L, project pair, project A2L-only; a stage is the sheet's own message
posted on ``#patch_sheet``). Private seams are reached lazily inside each test
body so the module collects on base and each node fails on its own. Flag arms
set ``S19_A2L_DESCRIBE`` AFTER the product modules are imported (the .055
control). Log lines are counted by exact text on the app's ``s19tui`` channel
only (E4 R3: a line on any other logger fails). Absence checks read every
logger and the app's visible status window.
"""
from __future__ import annotations

import gc
import importlib
import logging
import statistics
import sys
import threading
import time
import weakref
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
CASE01 = ROOT / "examples" / "case_01_basic_valid"
PUBLIC = ROOT / "examples" / "case_00_public"
FLAG = "S19_A2L_DESCRIBE"
ROUTES = ("attach", "image", "pair", "only")
D171_SCALAR = "ASAM.C.SCALAR.UBYTE.IDENTICAL"
D171_CURVE = "ASAM.C.CURVE.STD_AXIS"

LINE_PATH = "A2L describe path: unrecognised S19_A2L_DESCRIBE value ignored; eager used."
LINE_STALE = "A2L describe context stale: full describe used."
LINE_MISSING = "A2L describe context missing: full describe used."
LINE_FAILED = "A2L describe context failed: full describe used."
CONTEXT_LINES = (LINE_STALE, LINE_MISSING, LINE_FAILED)

HOSTILE = {
    "upper": "LAZY",
    "lead_space": " lazy",
    "trail_newline": "lazy\n",
    "empty": "",
    "long_32767": ("lazy" * 8192)[:32767],
    "escape": "\x1b[31mlazy",
}


# ---------------------------------------------------------------------------
# Lazy seams and fixtures.
# ---------------------------------------------------------------------------


def _i2():
    return importlib.import_module("tests.test_alp_inc2_a2l_attach")


def _definition():
    return importlib.import_module("s19_app.tui.a2l_definition")


def _set_flag(monkeypatch, value) -> None:
    """Import the product first, then set the variable (the .055 control)."""
    importlib.import_module("s19_app.tui.app")
    importlib.import_module("s19_app.tui.app.file_load")
    if value is None:
        monkeypatch.delenv(FLAG, raising=False)
    else:
        monkeypatch.setenv(FLAG, value)


def _fx(kind: str, tmp_path: Path) -> dict:
    """The corpus fixture: its A2L and an image (case_01 ships one; the d171
    image is a synthetic span over the addresses of the two staged names)."""
    if kind == "case_01":
        return {"a2l": CASE01 / "firmware.a2l", "image": CASE01 / "firmware.s19"}
    src = tmp_path / "src"
    src.mkdir(parents=True, exist_ok=True)
    mem = {0x810000 + i: (i * 7) & 0xFF for i in range(0x400)}
    return {"a2l": PUBLIC / "ASAP2_Demo_V171.a2l", "image": _i2()._write_image(src / "d171.s19", mem)}


def _patch_all(monkeypatch, name: str, wrap):
    """Replace ``name`` in the definition module and in every s19_app module
    that imported it, with ``wrap(real)``. Returns the real function."""
    real = getattr(_definition(), name)
    wrapper = wrap(real)
    for key, mod in list(sys.modules.items()):
        if not key.startswith("s19_app") or mod is None:
            continue
        try:
            held = getattr(mod, name, None)
        except Exception:
            continue
        if held is real:
            monkeypatch.setattr(mod, name, wrapper)
    return real


class _Rec:
    """Thread-tagged records of the describe seams (never retains results)."""

    def __init__(self) -> None:
        self.main = None
        self.defs: list = []
        self.builds: list = []
        self.overlap: list = []
        self.real_describe = None

    def reset(self) -> None:
        del self.defs[:], self.builds[:], self.overlap[:]


def _spies(monkeypatch, *, overlap: bool = False) -> _Rec:
    rec = _Rec()

    def wrap_describe(real):
        def spy(names, a2l_data):
            names = list(names)
            rec.defs.append((threading.get_ident(), len(names)))
            return real(names, a2l_data)

        return spy

    rec.real_describe = _patch_all(monkeypatch, "describe_definitions", wrap_describe)
    definition = _definition()
    if hasattr(definition, "build_describe_context"):

        def wrap_build(real):
            def spy(*args, **kwargs):
                rec.builds.append(threading.get_ident())
                return real(*args, **kwargs)

            return spy

        _patch_all(monkeypatch, "build_describe_context", wrap_build)
    if overlap:
        real_shared = getattr(definition, "_shared_with")

        def counted(*args, **kwargs):
            rec.overlap.append(threading.get_ident())
            return real_shared(*args, **kwargs)

        monkeypatch.setattr(definition, "_shared_with", counted)
    return rec


class _Tap(logging.Handler):
    """Collect the text of every log record of ``s19tui`` and ``s19_app.*``."""

    def __init__(self, app) -> None:
        super().__init__(logging.DEBUG)
        self.app = app
        self.messages: list = []
        self.channel: list = []
        self._last = None
        self._root = logging.getLogger()
        self._root_level = self._root.level
        self._root.setLevel(logging.INFO)
        self._root.addHandler(self)
        app.logger.addHandler(self)

    def emit(self, record) -> None:
        # The tap sits on the root and on ``s19tui``; a propagating record reaches both.
        if record is self._last:
            return
        self._last = record
        self.messages.append(record.getMessage())
        if record.name == self.app.logger.name:
            self.channel.append(record.getMessage())

    def reset(self) -> None:
        del self.messages[:]
        del self.channel[:]
        self._last = None

    def close(self) -> None:
        self._root.removeHandler(self)
        self.app.logger.removeHandler(self)
        self._root.setLevel(self._root_level)
        super().close()

    def count(self, text: str) -> int:
        return sum(1 for m in self.channel if m == text)

    def everything(self) -> list:
        return list(self.messages) + list(self.app.log_lines)


def _entry_ctx(entry):
    return getattr(entry, "describe_context", None)


def _ctx_of(picker):
    assert hasattr(type(picker), "describe_context"), "I-3: A2LParameterPicker.describe_context is missing"
    return picker.describe_context


def _measurable(app) -> list:
    return [t["name"] for t in app._a2l_enriched_tags if isinstance(t.get("address"), int)]


# ---------------------------------------------------------------------------
# Route drivers (the four load routes) and the measured-load runner.
# ---------------------------------------------------------------------------


async def _setup(route, app, pilot, fx, i2) -> None:
    if route == "image":
        await i2._typed_attach(app, pilot, fx["a2l"])
    elif route in ("pair", "only"):
        i2._seed_project(app.workarea, "proj_a", a2l=fx["a2l"], image=fx["image"] if route == "pair" else None)


async def _act(route, app, pilot, fx, i2) -> None:
    if route == "attach":
        await i2._typed_attach(app, pilot, fx["a2l"])
    elif route == "image":
        await i2._load_image(app, pilot, fx["image"])
    else:
        await i2._load_project(app, pilot, "proj_a")


def _capture_producer(monkeypatch) -> list:
    from s19_app.tui.app import S19TuiApp

    snapshots: list = []
    real = S19TuiApp._prepare_a2l_attach_snapshot

    def wrapped(self_, *args, **kwargs):
        result = real(self_, *args, **kwargs)
        snapshots.append(result)
        return result

    monkeypatch.setattr(S19TuiApp, "_prepare_a2l_attach_snapshot", wrapped)
    return snapshots


def _drive(tmp_path, monkeypatch, route, fx, *, flag, overlap=False) -> SimpleNamespace:
    """One measured load through ``route``; the results are read inside."""
    _set_flag(monkeypatch, flag)
    i2 = _i2()
    rec = _spies(monkeypatch, overlap=overlap)
    produced = _capture_producer(monkeypatch)
    out = SimpleNamespace(rec=rec)

    async def body(app, pilot):
        from tests.support.b100_workers import settle_workers

        rec.main = threading.get_ident()
        i2._mount_views(app)
        await pilot.pause()
        tap = _Tap(app)
        try:
            await _setup(route, app, pilot, fx, i2)
            rec.reset()
            del produced[:]
            tap.reset()
            await _act(route, app, pilot, fx, i2)
            await settle_workers(pilot)
            assert produced, "the producer ran no preparation on this route"
            out.snap = produced[-1]
            out.accepted = app._accepted_a2l_picker_snapshots
            out.data = app.current_a2l_data
            out.mem = dict(app.current_file.mem_map) if app.current_file is not None else None
            out.messages = tap.everything()
            out.tap_count = tap.count
            out.names = [t["name"] for t in out.snap.enriched_tags if isinstance(t.get("address"), int)]
            out.key = app._a2l_enriched_key
        finally:
            tap.close()

    i2._run(tmp_path / "app", body)
    return out


def _entries(out):
    assert set(out.accepted) == {"check", "patch"}, out.accepted
    return out.accepted["check"], out.accepted["patch"]


# ---------------------------------------------------------------------------
# R-A2L-REFRESH.055 / .056 / .057 - the flag.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("route", ROUTES)
def test_r_a2l_refresh_055_lazy_prepares_every_route(tmp_path, monkeypatch, route):
    """055/1-4: ``lazy`` set after import: each route's accepted snapshot
    carries a describe context and 0 bulk describes ran."""
    out = _drive(tmp_path, monkeypatch, route, _fx("case_01", tmp_path), flag="lazy")
    check, patch = _entries(out)
    for entry in (check, patch):
        assert _entry_ctx(entry) is not None, f"{route}: no describe context on the {entry.picker} entry"
        assert len(entry.definitions) == 0, entry.definitions
    assert out.rec.defs == [], f"{route}: bulk describes ran on the lazy path: {out.rec.defs}"


@pytest.mark.parametrize("flag", [None, "eager"], ids=["unset", "eager"])
@pytest.mark.parametrize("route", ROUTES)
def test_r_a2l_refresh_056_eager_is_todays_snapshot(tmp_path, monkeypatch, route, flag):
    """056/1-8: unset or ``eager``: no context, the bulk definitions mapping
    (the oracle is the bulk describe computed here) shared by both entries,
    and the enrichment part of the snapshot equals a fresh enrichment."""
    from s19_app.tui.services.a2l_service import enrich_tags_and_render

    out = _drive(tmp_path, monkeypatch, route, _fx("case_01", tmp_path), flag=flag)
    check, patch = _entries(out)
    assert _entry_ctx(check) is None and _entry_ctx(patch) is None
    assert check.definitions is patch.definitions
    want = out.rec.real_describe(out.names, out.data)
    assert dict(check.definitions) == want
    assert len(want) > 0
    image = out.mem if route != "attach" else None
    enriched, summary = enrich_tags_and_render(out.data, image, max_tag_lines=500)
    assert out.snap.enriched_tags == tuple(enriched)
    assert out.snap.summary_lines == tuple(summary)
    assert out.snap.enrichment_key == out.key


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("label", list(HOSTILE))
def test_r_a2l_refresh_057_hostile_values_use_eager_and_log_once(tmp_path, monkeypatch, route, label):
    """057/1-6: each hostile value prepares eager, logs the exact fixed line
    exactly once per load, and no byte of the value reaches the log."""
    value = HOSTILE[label]
    out = _drive(tmp_path, monkeypatch, route, _fx("case_01", tmp_path), flag=value)
    check, patch = _entries(out)
    assert _entry_ctx(check) is None and _entry_ctx(patch) is None, f"{label}: a hostile value selected lazy"
    assert dict(patch.definitions) == out.rec.real_describe(out.names, out.data)
    assert out.tap_count(LINE_PATH) == 1, [m for m in out.messages if "S19_A2L_DESCRIBE" in m]
    flagged = [m for m in out.messages if "S19_A2L_DESCRIBE" in m or "A2L describe path" in m]
    assert all(m == LINE_PATH for m in flagged), flagged
    joined = "\n".join(out.messages)
    if value:
        assert value[:200] not in joined, f"{label}: the value reached the log"
    assert "\x1b" not in joined


# ---------------------------------------------------------------------------
# R-A2L-REFRESH.058 / .059 - one context per generation, no overlap resolution.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["case_01", "d171"])
@pytest.mark.parametrize("route", ROUTES)
def test_r_a2l_refresh_058_one_context_built_off_the_ui_thread(tmp_path, monkeypatch, route, kind):
    """058/1-8: 1 build per load, on a worker; both entries hold the same
    context object."""
    out = _drive(tmp_path, monkeypatch, route, _fx(kind, tmp_path), flag="lazy")
    check, patch = _entries(out)
    assert len(out.rec.builds) == 1, out.rec.builds
    assert out.rec.builds[0] != out.rec.main, "the context was built on the UI thread"
    assert _entry_ctx(check) is not None and _entry_ctx(check) is _entry_ctx(patch)
    assert len(check.definitions) == 0 and len(patch.definitions) == 0


@pytest.mark.parametrize("route", ROUTES)
def test_r_a2l_refresh_059_lazy_resolves_no_overlap(tmp_path, monkeypatch, route):
    """059/1-4: d171 (has overlapping objects): 0 overlap resolutions on the
    load worker while preparing on the lazy path (the UI thread's page describe
    resolves overlaps for its shown page and is not preparation)."""
    out = _drive(tmp_path, monkeypatch, route, _fx("d171", tmp_path), flag="lazy", overlap=True)
    assert _entry_ctx(_entries(out)[1]) is not None, "the lazy path was not taken"
    worker = [t for t in out.rec.overlap if t != out.rec.main]
    assert worker == [], f"{len(worker)} overlap resolutions on a worker during lazy preparation"


def test_r_a2l_refresh_059_control_eager_resolves_overlaps(tmp_path, monkeypatch):
    """059 control: the overlap spy is alive - the eager path resolves some."""
    out = _drive(tmp_path, monkeypatch, "attach", _fx("d171", tmp_path), flag=None, overlap=True)
    worker = [t for t in out.rec.overlap if t != out.rec.main]
    assert len(worker) > 0, "the overlap spy saw no worker resolution on the eager path (dead instrument)"


# ---------------------------------------------------------------------------
# R-A2L-REFRESH.065 - a build failure ends through each route's failure outcome.
# ---------------------------------------------------------------------------


def _inject(monkeypatch, name, exc, armed):
    """Raise ``exc`` from ``name`` once ``armed["on"]`` is set."""
    assert hasattr(_definition(), name), f"I-1: {name} is missing"

    def wrap(real):
        def boom(*args, **kwargs):
            if armed["on"]:
                raise exc
            return real(*args, **kwargs)

        return boom

    _patch_all(monkeypatch, name, wrap)


async def _fail_route(route, app, pilot, fx, i2, armed):
    """Prior state, then the route that fails; returns (before, after, outcomes, spies)."""
    from s19_app.tui.screens import ConfirmQuestionScreen
    from tests.support import b100_load_dialog as ld
    from tests.support.b100_workers import settle_workers
    from tests.support.timing import wait_until

    prior = fx["prior"]
    await i2._typed_attach(app, pilot, prior["a2l"])
    if route in ("image", "pair"):
        await i2._load_image(app, pilot, prior["image"])
    if route in ("pair", "only"):
        i2._seed_project(app.workarea, "proj_a", a2l=fx["a2l"], image=fx["image"] if route == "pair" else None)
    await settle_workers(pilot)
    before = i2._state_snapshot(app)
    digests = i2._project_digests(app.workarea / "proj_a") if route in ("pair", "only") else None
    outcomes: list = []
    real_end = app.end_busy

    def end(key, gen, outcome):
        outcomes.append(str(outcome))
        return real_end(key, gen, outcome)

    import pytest as _pt

    mp = _pt.MonkeyPatch()
    try:
        mp.setattr(app, "end_busy", end)
        armed["on"] = True
        spies = {
            "replace": i2.Spy(mp, app, "_replace_current_a2l"),
            "fanout": i2.Spy(mp, app, "_refresh_a2l_dependent_views"),
        }
        if route == "attach":
            await i2._submit_typed(app, pilot, str(fx["a2l"]))
        elif route == "image":
            await i2._submit_typed(app, pilot, str(fx["image"]))
        else:
            await pilot.press("p")
            await wait_until(pilot, lambda: len(app.screen.query("#load_path")) > 0, "Load dialog did not open")
            await ld.highlight_row(pilot, app, "proj_a")
            await pilot.press("enter")
            await wait_until(pilot, lambda: not ld.is_load_dialog(app.screen), "the Load dialog to close")
        await wait_until(
            pilot,
            lambda: bool(outcomes) or isinstance(app.screen, ConfirmQuestionScreen),
            "the failure outcome or a confirmation",
            timeout=60.0,
        )
        if isinstance(app.screen, ConfirmQuestionScreen):
            await pilot.press("y")
        await settle_workers(pilot)
        await wait_until(pilot, lambda: bool(outcomes), "the failure outcome", timeout=60.0)
        if len(app.screen.query("#result_ok")) > 0:
            await pilot.press("escape")
        await settle_workers(pilot)
        installs = {k: len(v.calls) for k, v in spies.items()}
    finally:
        mp.undo()
    after = i2._state_snapshot(app)
    after_digests = i2._project_digests(app.workarea / "proj_a") if digests is not None else None
    return SimpleNamespace(
        before=before, after=after, outcomes=outcomes, installs=installs, digests=digests, after_digests=after_digests
    )


def _failure_run(tmp_path, monkeypatch, route, *, flag, exc_name):
    _set_flag(monkeypatch, flag)
    i2 = _i2()
    case = _fx("case_01", tmp_path)
    d171 = _fx("d171", tmp_path)
    fx = dict(d171, prior=case)
    rec = _spies(monkeypatch)
    armed = {"on": False}
    _inject(monkeypatch, exc_name, ValueError("CONTEXT_CONTROL"), armed)
    box = SimpleNamespace()

    async def body(app, pilot):
        rec.main = threading.get_ident()
        i2._mount_views(app)
        await pilot.pause()
        rec.reset()
        box.result = await _fail_route(route, app, pilot, fx, i2, armed)
        box.ui_describes = [d for d in rec.defs if d[0] == rec.main]

    i2._run(tmp_path / "app", body)
    return box


@pytest.mark.parametrize("route", ROUTES)
def test_r_a2l_refresh_065_build_failure_keeps_previous_state(tmp_path, monkeypatch, route):
    """065/1-4: an injected ValueError("CONTEXT_CONTROL") in the context build
    ends the load with the route's existing failure outcome (the reference is
    the same route failing in the eager describe); nothing is installed, the
    previous state and project hashes are unchanged, 0 UI-thread describes,
    and the direct attach ends with the exact .038 line."""
    with monkeypatch.context() as ref:
        reference = _failure_run(tmp_path / "ref", ref, route, flag=None, exc_name="describe_definitions")
    with monkeypatch.context() as lazy:
        got = _failure_run(tmp_path / "lazy", lazy, route, flag="lazy", exc_name="build_describe_context")
    result = got.result
    assert len(result.outcomes) == 1, result.outcomes
    assert result.outcomes == reference.result.outcomes, (result.outcomes, reference.result.outcomes)
    if route == "attach":
        assert result.outcomes[0] == _i2().FAILURE_OUTCOME.format(name="ASAP2_Demo_V171.a2l"), result.outcomes
    assert result.installs == {"replace": 0, "fanout": 0}, result.installs
    assert result.after == result.before, "the previous state changed"
    assert result.after_digests == result.digests
    assert got.ui_describes == [], got.ui_describes


# ---------------------------------------------------------------------------
# R-A2L-REFRESH.066 - the UI timer keeps time while the context builds.
# ---------------------------------------------------------------------------


class _BuildGate:
    """Hold the first worker-side context build for the tick loop."""

    def __init__(self) -> None:
        self.main = None
        self.armed = False
        self.entered = threading.Event()
        self.release = threading.Event()
        self.main_calls: list = []
        self.gate_started = None
        self.gate_released = None
        self.done = None

    def wrap(self, real):
        gate = self

        def held(*args, **kwargs):
            if threading.get_ident() == gate.main:
                gate.main_calls.append(1)
                return real(*args, **kwargs)
            if gate.armed and not gate.entered.is_set():
                gate.gate_started = time.perf_counter()
                gate.entered.set()
                if not gate.release.wait(120):
                    raise TimeoutError("the build hold was never released")
                gate.gate_released = time.perf_counter()
                try:
                    return real(*args, **kwargs)
                finally:
                    gate.done = time.perf_counter()
            return real(*args, **kwargs)

        return held


@pytest.mark.serial_timing
@pytest.mark.parametrize("route", ROUTES)
def test_r_a2l_refresh_066_ticks_on_time_while_the_context_builds(tmp_path, monkeypatch, route):
    """066/1-4: a 0.20 s hold inside the build: >= 3 ticks fire in the hold
    and every tick due inside the build window is <= 100 ms late."""
    from s19_app.tui.screens import ConfirmQuestionScreen
    from tests import test_alp_inc3_load_responsiveness as inc3
    from tests.support import b100_load_dialog as ld
    from tests.support.b100_workers import settle_workers
    from tests.support.timing import report_margin, timing_bound, wait_until

    _set_flag(monkeypatch, "lazy")
    i2 = _i2()
    fx = _fx("d171", tmp_path)
    gate = _BuildGate()
    assert hasattr(_definition(), "build_describe_context"), "I-1: build_describe_context is missing"
    _patch_all(monkeypatch, "build_describe_context", gate.wrap)

    async def body(app, pilot):
        gate.main = threading.get_ident()
        i2._mount_views(app)
        await pilot.pause()
        await _setup(route, app, pilot, fx, i2)
        gate.armed = True
        timer = inc3.TickTimer(app)
        timer.start()
        if route == "attach":
            await i2._submit_typed(app, pilot, str(fx["a2l"]))
        elif route == "image":
            await i2._submit_typed(app, pilot, str(fx["image"]))
        else:
            await pilot.press("p")
            await wait_until(pilot, lambda: len(app.screen.query("#load_path")) > 0, "Load dialog did not open")
            await ld.highlight_row(pilot, app, "proj_a")
            await pilot.press("enter")
            await wait_until(pilot, lambda: not ld.is_load_dialog(app.screen), "the Load dialog to close")
        await wait_until(
            pilot,
            lambda: gate.entered.is_set() or bool(gate.main_calls) or isinstance(app.screen, ConfirmQuestionScreen),
            "the context build or a confirmation",
            timeout=60.0,
        )
        if isinstance(app.screen, ConfirmQuestionScreen):
            await pilot.press("y")
            await wait_until(
                pilot, lambda: gate.entered.is_set() or bool(gate.main_calls), "the context build", timeout=60.0
            )
        assert not gate.main_calls, "the context was built on the UI thread"
        assert gate.entered.is_set()
        await inc3._tick_loop(pilot, timer, gate)
        gate.release.set()
        await settle_workers(pilot)
        timer.stop()
        return timer.observations, timer.gate_ticks(gate.gate_started, gate.gate_released)

    observations, hold_ticks = i2._run(tmp_path / "app", body)
    bound = timing_bound(0.1)
    inside = [late for due, _fired, late in observations if gate.gate_started <= due <= gate.done]
    assert hold_ticks >= 3, hold_ticks
    assert inside, "no tick was due inside the build window"
    worst = max(inside)
    assert worst <= report_margin(f"R-A2L-REFRESH.066 {route}", worst, bound), (worst, bound)


# ---------------------------------------------------------------------------
# R-A2L-REFRESH.067 / .068 - lifetime and size of the context.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("route", ["attach", "pair"])
def test_r_a2l_refresh_067_previous_context_is_released(tmp_path, monkeypatch, route):
    """067/1-2: attach then attach, project then project, on d171 with both
    pickers repopulated: a weak reference to the first context is dead after
    one gc.collect()."""
    from tests.support.b100_workers import settle_workers

    _set_flag(monkeypatch, "lazy")
    i2 = _i2()
    fx = _fx("d171", tmp_path)
    holder: dict = {}

    async def body(app, pilot):
        i2._mount_views(app)
        await pilot.pause()
        if route == "attach":
            await i2._typed_attach(app, pilot, fx["a2l"])
            await settle_workers(pilot)
        else:
            i2._seed_project(app.workarea, "proj_a", a2l=fx["a2l"], image=fx["image"])
            i2._seed_project(app.workarea, "proj_b", a2l=fx["a2l"], image=fx["image"])
            await i2._load_project(app, pilot, "proj_a")
        picker = i2._picker_of(i2._patch_panel(app))
        assert _ctx_of(picker) is not None, "the lazy path built no context"
        holder["ref"] = weakref.ref(picker.describe_context)
        del picker
        if route == "attach":
            await i2._typed_attach(app, pilot, fx["a2l"])
        else:
            await i2._load_project(app, pilot, "proj_b")
        await settle_workers(pilot)
        gc.collect()
        picker = i2._picker_of(i2._patch_panel(app))
        assert _ctx_of(picker) is not None and picker.describe_context is not holder["ref"](), "the second load kept the first context"
        return holder["ref"]() is None

    assert i2._run(tmp_path / "app", body), "the previous generation's context is still alive after gc.collect()"


def _interleaved_counts(tmp_path, monkeypatch, a2l) -> tuple:
    """Settled GC-tracked object counts of 3 eager and 3 lazy loads of
    ``a2l`` in ONE app (the variable is read at each load), so a
    drift of the process mostly cancels (E L L E E L: the lazy loads sit one
    third of a slot later on average, the conservative side)."""
    from tests.support.b100_workers import settle_workers

    _set_flag(monkeypatch, "eager")
    i2 = _i2()
    counts = {"eager": [], "lazy": []}

    async def body(app, pilot):
        i2._mount_views(app)
        await pilot.pause()
        for flag in ("eager", "lazy", "lazy", "eager", "eager", "lazy"):
            monkeypatch.setenv(FLAG, flag)
            await i2._typed_attach(app, pilot, a2l)
            await settle_workers(pilot)
            gc.collect()
            counts[flag].append(len(gc.get_objects()) + gc.get_freeze_count())

    i2._run(tmp_path, body)
    return counts["lazy"], counts["eager"]


@pytest.mark.parametrize("name", ["ASAP2_Demo_V171.a2l", "ASAP2_Demo_V161.a2l"])
def test_r_a2l_refresh_068_lazy_holds_no_more_objects_than_eager(tmp_path, monkeypatch, name):
    """068/1-2: 3 loads per path, ordered E L L E E L in one app, median of the
    settled GC-tracked object counts: lazy <= eager."""
    lazy, eager = _interleaved_counts(tmp_path, monkeypatch, PUBLIC / name)
    assert statistics.median(lazy) <= statistics.median(eager), (lazy, eager)


# ---------------------------------------------------------------------------
# Stage path: R-A2L-REFRESH.062, .064, .069, .070.
# ---------------------------------------------------------------------------


class _Walks(list):
    """The payload's section list, counting every iteration of it."""

    walks = 0

    def __iter__(self):
        self.walks += 1
        return super().__iter__()


def _count_walks(app) -> _Walks:
    data = app.current_a2l_data
    counted = _Walks(data["sections"])
    data["sections"] = counted
    return counted


def _open_patch(tmp_path, monkeypatch, flag, body, *, clear_snapshots=False):
    """Load d171 (A2L then image), optionally drop the accepted snapshots
    (population through the no-snapshot fallback), show the Patch screen, run
    ``body(app, pilot, picker, tap, rec, fx)``."""
    _set_flag(monkeypatch, flag)
    i2 = _i2()
    rec = _spies(monkeypatch)
    fx = _fx("d171", tmp_path)

    async def drive(app, pilot):
        rec.main = threading.get_ident()
        tap = _Tap(app)
        try:
            if clear_snapshots:
                app._prefill_patch_editor = lambda: None  # the Patch picker is not populated while loading
            await i2._typed_attach(app, pilot, fx["a2l"])
            await i2._load_image(app, pilot, fx["image"])
            if clear_snapshots:
                del app._prefill_patch_editor
                app._accepted_a2l_picker_snapshots = MappingProxyType({})
            app.action_show_screen("patch")
            for _ in range(8):
                await pilot.pause()
            picker = i2._picker_of(i2._patch_panel(app))
            return await body(app, pilot, picker, tap, rec, fx)
        finally:
            tap.close()

    return i2._run(tmp_path / "app", drive)


def _watch_stage(app, monkeypatch) -> list:
    """The definitions handed to ``stage_definition`` (the real one still runs)."""
    seen: list = []
    service = app._change_service
    real = service.stage_definition

    def spy(definition, *args, **kwargs):
        seen.append(definition)
        return real(definition, *args, **kwargs)

    monkeypatch.setattr(service, "stage_definition", spy)
    return seen


async def _stage_value(app, pilot, name, text) -> None:
    from s19_app.tui.screens_directionb.patch_editor.sheet import StagingSheet

    app.query_one("#patch_sheet").post_message(StagingSheet.StageRequested(name, text))
    for _ in range(8):
        await pilot.pause()


async def _stage_record(app, pilot, monkeypatch, name, definition) -> list:
    """Post the bench sheet's record request for ``name``; returns the
    results of ``_stage_bench_record`` (True = the guarded stage ran)."""
    from s19_app.tui.a2l_definition import Encoded
    from s19_app.tui.screens_directionb.patch_editor import bench_sheet

    results: list = []
    real = app._stage_bench_record

    def spy(event, sheet):
        wrote = real(event, sheet)
        results.append(wrote)
        return wrote

    monkeypatch.setattr(app, "_stage_bench_record", spy)
    sheet = app.query_one("#patch_sheet")
    outcome = Encoded(address=definition.address, data=bytes(definition.byte_length), notices=())
    sheet.post_message(
        bench_sheet.ArrayBenchSheet.RecordStageRequested(
            name, definition, 1, outcome, sheet.generation, (((0,), "0"),)
        )
    )
    for _ in range(8):
        await pilot.pause()
    return results


def _bulk(app, rec, name):
    return rec.real_describe(_measurable(app), app.current_a2l_data)[name]


def test_r_a2l_refresh_062_scalar_stage_walks_no_section(tmp_path, monkeypatch):
    """062/1: lazy, fresh context, a scalar value stage: 0 section walks, 0
    full describes, and the staged definition equals the bulk one."""

    async def body(app, pilot, picker, tap, rec, fx):
        ctx = _ctx_of(picker)
        assert ctx is not None and ctx.source is app.current_a2l_data, "premise: a fresh context"
        want = _bulk(app, rec, D171_SCALAR)
        seen = _watch_stage(app, monkeypatch)
        walks = _count_walks(app)
        rec.reset()
        await _stage_value(app, pilot, D171_SCALAR, "20")
        return seen, want, walks.walks, list(rec.defs), tap.everything()

    seen, want, walks, defs, lines = _open_patch(tmp_path, monkeypatch, "lazy", body)
    assert seen == [want], (seen, want)
    assert walks == 0 and defs == [], (walks, defs)
    assert not [m for m in lines if m in CONTEXT_LINES], lines


def test_r_a2l_refresh_062_bench_record_from_a_context_page_is_accepted(tmp_path, monkeypatch):
    """062/2: lazy, fresh context: a curve bench record described through the
    context is not refused as changed in the A2L, and 0 section walks ran."""

    async def body(app, pilot, picker, tap, rec, fx):
        ctx = _ctx_of(picker)
        assert ctx is not None and ctx.source is app.current_a2l_data, "premise: a fresh context"
        describe_in_context = getattr(_definition(), "describe_in_context")
        definition = describe_in_context([D171_CURVE], ctx)[D171_CURVE]
        assert definition == _bulk(app, rec, D171_CURVE)
        walks = _count_walks(app)
        rec.reset()
        results = await _stage_record(app, pilot, monkeypatch, D171_CURVE, definition)
        return results, walks.walks, list(rec.defs), tap.everything()

    results, walks, defs, lines = _open_patch(tmp_path, monkeypatch, "lazy", body)
    assert results == [True], results
    assert not [m for m in lines if "changed in the A2L" in m], lines
    assert walks == 0 and defs == [], (walks, defs)


_OLD_LIMITS = "      10 200\n      EXTENDED_LIMITS 0 256\n      DISPLAY_IDENTIFIER DI.ASAM.C.SCALAR.UBYTE\n"


def _modified_a2l(path: Path) -> Path:
    text = (PUBLIC / "ASAP2_Demo_V171.a2l").read_text(encoding="utf-8", errors="replace")
    assert _OLD_LIMITS in text, "fixture drifted: the UBYTE limits block moved"
    path.write_text(text.replace(_OLD_LIMITS, _OLD_LIMITS.replace("10 200", "9 199"), 1), encoding="utf-8")
    return path


@pytest.mark.parametrize("arm", ["second-a2l", "modified-copy-same-path"])
def test_r_a2l_refresh_064_stale_context_uses_the_full_describe(tmp_path, monkeypatch, arm):
    """064/1-2: the Patch picker keeps the first A2L's context while a second
    A2L (or a modified copy at the same path) is the loaded one: a stage
    describes the loaded A2L with ONE full single-name describe and logs the
    stale line once; the definition equals the bulk describe of the loaded
    A2L and differs from the stale one."""
    from tests.support.b100_workers import settle_workers

    i2 = _i2()

    async def body(app, pilot, picker, tap, rec, fx):
        src = tmp_path / "second"
        src.mkdir()
        if arm == "second-a2l":
            second = _modified_a2l(src / "other.a2l")
        else:
            second = src / "same.a2l"
            second.write_bytes(fx["a2l"].read_bytes())
            await i2._typed_attach(app, pilot, second)
            await settle_workers(pilot)
            app.action_show_screen("patch")
            await pilot.pause()
            second = _modified_a2l(second)
        old_data = app.current_a2l_data
        old_def = rec.real_describe(_measurable(app), old_data)[D171_SCALAR]
        stale = _ctx_of(picker)
        assert stale is not None, "premise: the first load built a context"
        monkeypatch.setattr(app, "_prefill_patch_editor", lambda: None)
        await i2._typed_attach(app, pilot, second)
        await settle_workers(pilot)
        assert app.current_a2l_data is not old_data and picker.describe_context.source is not app.current_a2l_data
        want = _bulk(app, rec, D171_SCALAR)
        assert want != old_def, "control: the modified A2L must change the staged definition"
        seen = _watch_stage(app, monkeypatch)
        tap.reset()
        rec.reset()
        await _stage_value(app, pilot, D171_SCALAR, "20")
        return seen, want, old_def, tap.count(LINE_STALE), [d[1] for d in rec.defs]

    seen, want, old_def, stale_lines, describes = _open_patch(tmp_path, monkeypatch, "lazy", body)
    assert seen == [want] and seen != [old_def], (seen, want, old_def)
    assert stale_lines == 1, stale_lines
    assert describes == [1], describes


@pytest.mark.parametrize("kind", ["value", "bench"])
def test_r_a2l_refresh_069_missing_context_logs_once_and_uses_the_full_describe(tmp_path, monkeypatch, kind):
    """069/1-2: lazy, the Patch picker populated through the no-snapshot
    fallback (no context): a stage or a bench record logs the missing line
    once and describes with one full single-name describe."""

    async def body(app, pilot, picker, tap, rec, fx):
        assert _ctx_of(picker) is None, "premise: the picker holds no context"
        want = _bulk(app, rec, D171_SCALAR if kind == "value" else D171_CURVE)
        tap.reset()
        rec.reset()
        if kind == "value":
            seen = _watch_stage(app, monkeypatch)
            await _stage_value(app, pilot, D171_SCALAR, "20")
            got = seen
        else:
            got = await _stage_record(app, pilot, monkeypatch, D171_CURVE, want)
            want = [True]
        return got, want, tap.count(LINE_MISSING), [d[1] for d in rec.defs], tap.everything()

    got, want, missing, describes, lines = _open_patch(tmp_path, monkeypatch, "lazy", body, clear_snapshots=True)
    assert got == ([want] if kind == "value" else want), (got, want)
    assert missing == 1, missing
    assert describes == [1], describes
    assert not [m for m in lines if m in (LINE_STALE, LINE_FAILED) or "changed in the A2L" in m], lines


def test_r_a2l_refresh_069_unset_logs_no_context_line(tmp_path, monkeypatch):
    """069/3: the variable unset, no context: the full describe runs and none
    of the three context lines is logged."""

    async def body(app, pilot, picker, tap, rec, fx):
        assert _ctx_of(picker) is None
        want = _bulk(app, rec, D171_SCALAR)
        seen = _watch_stage(app, monkeypatch)
        tap.reset()
        await _stage_value(app, pilot, D171_SCALAR, "20")
        return seen, want, tap.everything()

    seen, want, lines = _open_patch(tmp_path, monkeypatch, None, body, clear_snapshots=True)
    assert seen == [want], (seen, want)
    assert not [m for m in lines if m in CONTEXT_LINES], lines


def test_r_a2l_refresh_057_stage_path_never_rereads_the_flag(tmp_path, monkeypatch):
    """057/7: a hostile value set after import, ONE A2L load (no image), then
    two value stages: the fixed line is on the ``s19tui`` channel exactly once
    in total (the selection made when the load's preparation started holds for
    the generation; a stage never re-reads the variable)."""
    from tests.support.b100_workers import settle_workers

    _set_flag(monkeypatch, "LAZY")
    i2 = _i2()
    fx = _fx("d171", tmp_path)

    async def drive(app, pilot):
        tap = _Tap(app)
        try:
            await i2._typed_attach(app, pilot, fx["a2l"])
            await settle_workers(pilot)
            seen = _watch_stage(app, monkeypatch)
            app.action_show_screen("patch")
            for _ in range(8):
                await pilot.pause()
            await _stage_value(app, pilot, D171_SCALAR, "20")
            await _stage_value(app, pilot, D171_SCALAR, "21")
            return len(seen), tap.count(LINE_PATH)
        finally:
            tap.close()

    staged, lines = i2._run(tmp_path / "app", drive)
    assert staged == 2, staged
    assert lines == 1, lines


def _raise_in_context_describe(monkeypatch):
    def wrap(real):
        def boom(*args, **kwargs):
            raise TypeError("CONTEXT_CONTROL")

        return boom

    _patch_all(monkeypatch, "describe_in_context", wrap)


def test_r_a2l_refresh_070_stage_survives_a_raising_context(tmp_path, monkeypatch):
    """070/2: describe_in_context raises TypeError("CONTEXT_CONTROL") on a
    stage: the staged definition equals the bulk one, the failed line is
    logged once, and neither CONTEXT_CONTROL nor the name is in any line."""

    async def body(app, pilot, picker, tap, rec, fx):
        assert _ctx_of(picker) is not None, "premise: the picker holds a context"
        want = _bulk(app, rec, D171_SCALAR)
        seen = _watch_stage(app, monkeypatch)
        _raise_in_context_describe(monkeypatch)
        tap.reset()
        rec.reset()
        await _stage_value(app, pilot, D171_SCALAR, "20")
        return seen, want, tap.count(LINE_FAILED), tap.everything(), [d[1] for d in rec.defs]

    seen, want, failed, lines, describes = _open_patch(tmp_path, monkeypatch, "lazy", body)
    assert seen == [want], (seen, want)
    assert failed == 1, failed
    assert not [m for m in lines if "CONTEXT_CONTROL" in m], lines
    assert describes == [1], describes


def _page_rows(flag, tmp_path, monkeypatch, inject):
    """The painted rows of the Patch picker after a filter change."""

    async def body(app, pilot, picker, tap, rec, fx):
        from tests.support.timing import wait_until

        i2 = _i2()
        panel = i2._patch_panel(app)
        if inject:
            assert _ctx_of(picker) is not None, "premise: the picker holds a context"
            _raise_in_context_describe(monkeypatch)
        before = list(picker.visible_params)
        tap.reset()
        panel.query_one("#patch_param_filter").value = "scalar"
        await wait_until(pilot, lambda: list(picker.visible_params) != before, "the filtered page")
        for _ in range(6):
            await pilot.pause()
        return i2._picker_visible_shape(panel), tap.count(LINE_FAILED), tap.everything()

    return _open_patch(tmp_path, monkeypatch, flag, body)


def test_r_a2l_refresh_070_page_change_survives_a_raising_context(tmp_path, monkeypatch):
    """070/1: describe_in_context raises TypeError("CONTEXT_CONTROL") on a
    page change: the rows equal the eager path's, the failed line is logged
    once and carries no exception text."""
    with monkeypatch.context() as eager_mp:
        eager_rows, _n, _lines = _page_rows(None, tmp_path / "eager", eager_mp, False)
    with monkeypatch.context() as lazy_mp:
        rows, failed, lines = _page_rows("lazy", tmp_path / "lazy", lazy_mp, True)
    assert rows == eager_rows and rows, (rows, eager_rows)
    assert failed == 1, failed
    assert not [m for m in lines if "CONTEXT_CONTROL" in m], lines
