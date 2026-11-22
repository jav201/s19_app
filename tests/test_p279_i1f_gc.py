"""P-279 I1f, group G-GC (F4): the cycle-collector policy per A2L size.

Requirements (``R-A2L-REFRESH``, as amended by I1f E4-1): .071 a small load's
worker holds the collector disabled during preparation, as a large one does;
.072 a small install re-enables the collector without a full collection;
.073 a large load (incoming or installed A2L of at least 1 MiB) keeps the D-13
hold and its one install collection, .074 an unreadable size is treated as
large; plus the
overlap arm of .051 and the near-1-MiB tick arm of .050 (the tick arm itself
lives in ``tests/test_alp_inc3_load_responsiveness.py`` and reuses this
module's generator).

Every expectation is derived here from a size computed from the written
file or from a gate that the test drives, never from a retyped count. The
private seams (``a2l_holds_collector``, ``collector_hold``) are reached
lazily inside each test body so the module collects on the base revision and
each node fails on its own. Real A2L files are generated into ``tmp_path``
(the near-1-MiB generator is the I1f E3-3 one, embedded below and checked
against its recorded size and sha256); nothing generated is committed.
"""

from __future__ import annotations

import gc
import hashlib
import importlib
import os
import sys
import threading
from pathlib import Path
from typing import Callable, Optional

import pytest

import s19_app.tui.app as app_module
from s19_app.tui.a2l_parse import parse_a2l_file
from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens import ConfirmQuestionScreen
from tests.support.b100_workers import settle_workers
from tests.support.timing import wait_until
from tests.test_alp_inc2_a2l_attach import (
    _load_image,
    _load_project,
    _mount_views,
    _run,
    _submit_typed,
    _typed_attach,
)

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
CASE01 = EXAMPLES / "case_01_basic_valid"
CASE01_A2L = CASE01 / "firmware.a2l"
CASE01_IMAGE = CASE01 / "firmware.s19"
CASE06_A2L = EXAMPLES / "case_06_large_nested_a2l" / "firmware.a2l"
V171_A2L = EXAMPLES / "case_00_public" / "ASAP2_Demo_V171.a2l"

MIB = 1 << 20
PRODUCT_MODULES = frozenset(
    {
        "s19_app.tui.app.file_load",
        "s19_app.tui.app.loaded_state",
        "s19_app.tui.app.project_load",
    }
)

# --- The near-1-MiB generator of I1f E3-3 (evidence/e3/gen_a2l_under_1mib.py),
# --- parameterised on the byte limit; recorded output for the 1,048,575 limit.
NEAR_LIMIT = MIB - 1
NEAR_RECORD = {
    "characteristics": 6818,
    "measurements": 852,
    "bytes": 1048451,
    "sha256": "18c9b6bee7e52f1e85df2ff074accfd6a287f82824e81acff82799583838eef9",
}
_BASE_ADDR = 0x80000000
_LAYOUTS = (("RL_U8", 1), ("RL_U16", 2), ("RL_U32", 4))
_HEAD = """/begin PROJECT CASE_NEAR_1MIB "Generated near-1-MiB project (I1f E3-3)"
  /begin HEADER
    VERSION "1.0"
    PROJECT_NO 1
  /end HEADER

  /begin MODULE NEAR1MIB "Generated ECU module"
    /begin MOD_COMMON ""
      BYTE_ORDER MSB_FIRST
      ALIGNMENT_BYTE 1
      ALIGNMENT_WORD 2
      ALIGNMENT_LONG 4
      ALIGNMENT_FLOAT32_IEEE 4
    /end MOD_COMMON

    /begin RECORD_LAYOUT RL_U8
      FNC_VALUES 1 UBYTE COLUMN_DIR DIRECT
    /end RECORD_LAYOUT

    /begin RECORD_LAYOUT RL_U16
      FNC_VALUES 1 UWORD COLUMN_DIR DIRECT
    /end RECORD_LAYOUT

    /begin RECORD_LAYOUT RL_U32
      FNC_VALUES 1 ULONG COLUMN_DIR DIRECT
    /end RECORD_LAYOUT

    /begin COMPU_METHOD CM_IDENT "%6.2" IDENTICAL "%6.2" ""
      COEFFS 0 1 0 0 0 1
    /end COMPU_METHOD

"""
_TAIL = "  /end MODULE\n/end PROJECT\n"


def _gen_block(i: int) -> str:
    layout, size = _LAYOUTS[i % 3]
    addr = _BASE_ADDR + 0x10 + i * 4
    hi = (1 << (8 * size)) - 1
    text = (
        f'/begin CHARACTERISTIC CAL_{i:06d} "CAL_{i:06d} generated characteristic"\n'
        f"  VALUE 0x{addr:08X} {layout} 0 CM_IDENT 0 {hi}\n"
        f"/end CHARACTERISTIC\n"
    )
    if i % 8 == 7:
        maddr = _BASE_ADDR + 0x0800_0000 + (i // 8) * 4
        text += (
            f'/begin MEASUREMENT MEAS_{i // 8:06d} "MEAS_{i // 8:06d} generated measurement"\n'
            f"  UBYTE CM_IDENT 0 0 0 255\n  ECU_ADDRESS 0x{maddr:08X}\n/end MEASUREMENT\n"
        )
    return text


def gen_a2l_bytes(limit: int) -> tuple[bytes, int]:
    """Real-content A2L with the largest characteristic count that stays at
    most ``limit`` bytes; returns the bytes and the characteristic count."""
    parts, size, i = [_HEAD], len(_HEAD) + len(_TAIL), 0
    while True:
        nxt = _gen_block(i)
        if size + len(nxt) > limit:
            break
        parts.append(nxt)
        size += len(nxt)
        i += 1
    parts.append(_TAIL)
    return "".join(parts).encode("ascii"), i


def write_a2l_of_size(path: Path, size: int) -> Path:
    """Write a real-content A2L of exactly ``size`` bytes (the content fills
    the size to within one block; trailing newlines pad the rest) and assert
    the size from the written file."""
    data, _count = gen_a2l_bytes(size)
    path.write_bytes(data + b"\n" * (size - len(data)))
    assert path.stat().st_size == size, path.stat().st_size
    return path


@pytest.fixture(scope="module")
def a2l_sizes(tmp_path_factory) -> dict:
    """Generated A2Ls of exactly 1 MiB - 1, 1 MiB and 2 MiB (module-scoped)."""
    folder = tmp_path_factory.mktemp("i1f_gc_a2l")
    return {
        "below": write_a2l_of_size(folder / "below_1mib.a2l", MIB - 1),
        "at": write_a2l_of_size(folder / "at_1mib.a2l", MIB),
        "two": write_a2l_of_size(folder / "two_mib.a2l", 2 * MIB),
    }


# ---------------------------------------------------------------------------
# Lazy seams.
# ---------------------------------------------------------------------------


def _fl():
    return importlib.import_module("s19_app.tui.app.file_load")


def _holds() -> Callable:
    fn = getattr(_fl(), "a2l_holds_collector", None)
    assert fn is not None, "a2l_holds_collector (I-1) is missing from file_load"
    return fn


# ---------------------------------------------------------------------------
# FIRST: the near-1-MiB generated A2L (E3-3).
# ---------------------------------------------------------------------------


def test_r_a2l_refresh_050_near_1mib_generator_matches_record_and_parses(tmp_path: Path) -> None:
    """E3-3 fixture control: the in-test generator reproduces the recorded
    near-1-MiB A2L (size and sha256), the size is below the 1 MiB gate, and
    the app's A2L parser accepts it with no errors."""
    data, count = gen_a2l_bytes(NEAR_LIMIT)
    assert (count, count // 8, len(data)) == (
        NEAR_RECORD["characteristics"],
        NEAR_RECORD["measurements"],
        NEAR_RECORD["bytes"],
    )
    assert hashlib.sha256(data).hexdigest() == NEAR_RECORD["sha256"]
    path = tmp_path / "near_1mib.a2l"
    path.write_bytes(data)
    assert path.stat().st_size == NEAR_RECORD["bytes"] < MIB
    parsed = parse_a2l_file(path)
    assert (parsed.get("errors") or []) == [], parsed.get("errors")
    names = {tag["name"] for tag in parsed["tags"]}
    assert len(parsed["tags"]) == count + count // 8, len(parsed["tags"])
    assert {"CAL_000000", f"CAL_{count - 1:06d}", "MEAS_000000"} <= names


def test_r_a2l_refresh_071_threshold_constant_is_one_mib() -> None:
    """I-1: the gate is exactly 1 MiB (1,048,576 bytes)."""
    assert getattr(_fl(), "A2L_COLLECTOR_HOLD_BYTES", None) == MIB


# ---------------------------------------------------------------------------
# The size gate on its own (unit): .071 below, .073 at/above, .074 unreadable.
# ---------------------------------------------------------------------------


def test_r_a2l_refresh_071_gate_false_below_threshold(a2l_sizes) -> None:
    """R-A2L-REFRESH.071: both sizes below 1 MiB, or no path, do not hold."""
    holds = _holds()
    assert CASE01_A2L.stat().st_size < MIB and V171_A2L.stat().st_size < MIB
    assert a2l_sizes["below"].stat().st_size == MIB - 1
    assert holds(CASE01_A2L, None) is False
    assert holds(a2l_sizes["below"], None) is False
    assert holds(None, a2l_sizes["below"]) is False
    assert holds(CASE01_A2L, V171_A2L) is False
    assert holds(None, None) is False


def test_r_a2l_refresh_073_gate_true_at_and_above_threshold(a2l_sizes) -> None:
    """R-A2L-REFRESH.073: an incoming or an installed A2L of at least 1 MiB
    holds, including the large-to-small case (installed large, incoming
    small) and case_06."""
    holds = _holds()
    assert a2l_sizes["at"].stat().st_size == MIB
    assert holds(a2l_sizes["at"], None) is True
    assert holds(None, a2l_sizes["at"]) is True
    assert holds(CASE01_A2L, a2l_sizes["two"]) is True  # large -> small
    assert holds(a2l_sizes["two"], CASE01_A2L) is True
    assert CASE06_A2L.stat().st_size >= MIB
    assert holds(CASE06_A2L, None) is True


def test_r_a2l_refresh_074_gate_true_on_unreadable_size(tmp_path: Path, caplog) -> None:
    """R-A2L-REFRESH.074: a size that cannot be read (a missing file raises
    OSError; a path with an embedded NUL raises ValueError) holds; nothing
    escapes and nothing is logged."""
    holds = _holds()
    missing = tmp_path / "does_not_exist.a2l"
    nul = Path("bad\x00path.a2l")
    with caplog.at_level(0):
        assert holds(missing, None) is True
        assert holds(CASE01_A2L, missing) is True
        assert holds(nul, None) is True
        assert holds(CASE01_A2L, nul) is True
    assert caplog.records == [], [r.getMessage() for r in caplog.records]


# ---------------------------------------------------------------------------
# The route harness: one load observed from outside through the real routes.
# ---------------------------------------------------------------------------

ROUTES = ("attach", "image", "project-pair", "project-a2l-only")
_KEY = {
    "attach": "a2l_load",
    "image": "file_load",
    "project-pair": "project_load",
    "project-a2l-only": "project_load",
    "project-no-a2l": "project_load",
}
_ROUTE_LABEL = {"attach": "attach", "image": "image"}
_PROJECT = "proj_gc"
# Probe points a route reaches on its worker.
_POINTS = {
    "attach": {"parse_in", "parse_out", "prep_in", "prep_out"},
    "image": {"payload_in", "prep_in", "prep_out"},
    "project-pair": {"worker_in", "payload_in"},
    "project-a2l-only": {"worker_in", "prep_in", "prep_out"},
    "project-no-a2l": {"worker_in"},
}
# Probe points that lie after the worker's own disable on that route (the image
# route's payload preparation starts before the producer's disable).
_HELD = {**_POINTS, "image": {"prep_in", "prep_out"}}
_ABSENT = "<absent>"


class Obs:
    """What one observed load did, recorded from outside."""

    def __init__(self) -> None:
        self.holds: list = []
        self.probes: list = []
        self.collects: list = []
        self.log_records: list = []
        self.outcomes: list = []
        self.final_enabled: Optional[bool] = None

    def gc_lines(self) -> list:
        return [a for (_l, msg, a, _f) in self.log_records if msg.startswith("A2L load GC:")]

    def texts(self) -> list:
        out = []
        for _level, msg, args, _fn in self.log_records:
            try:
                out.append(msg % args if args else msg)
            except Exception:  # noqa: BLE001 - never mask the test with a format error
                out.append(msg)
        return out

    def probed(self, points) -> list:
        return [(p, e) for (p, e) in self.probes if p in points]


def _wrap_class(monkeypatch, name: str, before=None, after=None) -> None:
    real = getattr(S19TuiApp, name)

    def wrapper(self_, *args, **kwargs):
        if before is not None:
            before(args, kwargs)
        out = real(self_, *args, **kwargs)
        if after is not None:
            after()
        return out

    monkeypatch.setattr(S19TuiApp, name, wrapper)


def _arm(app: S19TuiApp, monkeypatch) -> Obs:
    """Install the observers: request capture, worker-thread collector
    probes, collection spy, logger spy and the outcome spy."""
    obs = Obs()
    main = threading.get_ident()
    assert gc.isenabled(), "the collector must be enabled before the observed load"

    def probe(point: str) -> None:
        if threading.get_ident() != main:
            obs.probes.append((point, gc.isenabled()))

    def probe_fn(point: str):
        return lambda *a, **k: probe(point)

    def record_request(args, kwargs) -> None:
        request = args[0] if args else kwargs.get("request")
        obs.holds.append(getattr(request, "collector_hold", _ABSENT))

    def record_context(args, kwargs) -> None:
        context = kwargs.get("context")
        if context is not None:
            obs.holds.append(getattr(context, "collector_hold", _ABSENT))

    _wrap_class(monkeypatch, "_a2l_attach_worker", before=record_request)
    _wrap_class(monkeypatch, "_project_load_worker", before=record_request)
    _wrap_class(monkeypatch, "_start_load_worker", before=record_context)
    _wrap_class(monkeypatch, "_prepare_project_load", before=probe_fn("worker_in"))
    _wrap_class(monkeypatch, "_prepare_load_payload", before=probe_fn("payload_in"))
    _wrap_class(
        monkeypatch, "_prepare_a2l_attach_snapshot_inner", before=probe_fn("prep_in")
    )
    _wrap_class(
        monkeypatch, "_prepare_a2l_attach_snapshot", after=lambda: probe("prep_out")
    )
    deps = app_module.deps
    real_parse = deps.parse_a2l_cached

    def parse_spy(*args, **kwargs):
        probe("parse_in")
        out = real_parse(*args, **kwargs)
        probe("parse_out")
        return out

    monkeypatch.setattr(deps, "parse_a2l_cached", parse_spy)

    real_collect = gc.collect

    def collect_spy(*args, **kwargs):
        caller = sys._getframe(1).f_globals.get("__name__")
        if caller in PRODUCT_MODULES:
            obs.collects.append((caller, threading.get_ident() == main))
        return real_collect(*args, **kwargs)

    monkeypatch.setattr(gc, "collect", collect_spy)
    for level in ("debug", "info", "warning", "error", "exception", "critical"):
        real = getattr(app.logger, level)

        def make(real_fn, level_name):
            def spy(msg, *args, **kwargs):
                obs.log_records.append(
                    (level_name, str(msg), args, sys._getframe(1).f_code.co_name)
                )
                return real_fn(msg, *args, **kwargs)

            return spy

        monkeypatch.setattr(app.logger, level, make(real, level))
    real_end = S19TuiApp.end_busy

    def end(key, gen, outcome):
        obs.outcomes.append((key, str(outcome)))
        return real_end(app, key, gen, outcome)

    monkeypatch.setattr(app, "end_busy", end)
    return obs


def _seed(workarea: Path, name: str, *, a2l: Optional[Path], image: Optional[Path]) -> None:
    import json

    folder = workarea / name
    folder.mkdir(parents=True, exist_ok=True)
    active = None
    if image is not None:
        (folder / image.name).write_bytes(image.read_bytes())
        active = image.stem
    if a2l is not None:
        (folder / a2l.name).write_bytes(a2l.read_bytes())
    (folder / "project.json").write_text(
        json.dumps({"schema_version": 1, "active_variant": active}), encoding="utf-8"
    )


async def _act(app, pilot, route: str, a2l: Optional[Path]) -> None:
    """The observed action of one route (``a2l`` is the incoming A2L for the
    attach and the project routes; the image route loads an image)."""
    if route == "attach":
        await _typed_attach(app, pilot, a2l)
    elif route == "image":
        await _load_image(app, pilot, CASE01_IMAGE)
    else:
        image = None if route == "project-a2l-only" else CASE01_IMAGE
        project_a2l = None if route == "project-no-a2l" else a2l
        _seed(app.workarea, _PROJECT, a2l=project_a2l, image=image)
        await _load_project(app, pilot, _PROJECT)


def _observe(
    tmp_path: Path,
    monkeypatch,
    route: str,
    *,
    a2l: Optional[Path],
    installed: Optional[Path] = None,
    prearm: Optional[Callable] = None,
) -> Obs:
    """Run one load through the product route. ``installed`` is attached
    first, unobserved; the observers arm right before the observed action."""

    async def body(app, pilot):
        _mount_views(app)
        await pilot.pause()
        if installed is not None:
            await _typed_attach(app, pilot, installed)
            await settle_workers(pilot)
        if prearm is not None:
            prearm(app)
        obs = _arm(app, monkeypatch)
        await _act(app, pilot, route, a2l)
        await settle_workers(pilot)
        key = _KEY[route]
        await wait_until(
            pilot,
            lambda: any(k == key for k, _t in obs.outcomes),
            f"the {route} outcome",
            timeout=120.0,
        )
        await pilot.pause()
        obs.final_enabled = gc.isenabled()
        return obs

    return _run(tmp_path / "app", body)


def _assert_outcome_ok(obs: Obs, route: str) -> None:
    texts = [t for k, t in obs.outcomes if k == _KEY[route]]
    assert texts, obs.outcomes
    assert not any("failed" in t or "NOT loaded" in t for t in texts), texts


def _assert_small(obs: Obs, route: str, label: str) -> None:
    """R-A2L-REFRESH.071/.072/.051 on one small load: held during the
    preparation as a large load is, then no collection at install."""
    reached = {p for p, _e in obs.probes}
    assert _POINTS[route] <= reached, f"{label}: probes reached {sorted(reached)}"
    held = obs.probed(_HELD[route])
    assert held and not any(e for _p, e in held), f"{label}: collector enabled at {held}"
    assert obs.collects == [], f"{label}: product collections {obs.collects}"
    assert obs.gc_lines() == [], f"{label}: GC log lines {obs.gc_lines()}"
    assert obs.final_enabled is True, label
    _assert_outcome_ok(obs, route)
    assert obs.holds == [False], f"{label}: request collector_hold {obs.holds}"


def _assert_large(obs: Obs, route: str, label: str) -> None:
    """R-A2L-REFRESH.073 (+ .052/.054) on one large load."""
    reached = {p for p, _e in obs.probes}
    assert _POINTS[route] <= reached, f"{label}: probes reached {sorted(reached)}"
    held = obs.probed(_HELD[route])
    assert held and not any(e for _p, e in held), f"{label}: collector enabled at {held}"
    assert len(obs.collects) == 1, f"{label}: product collections {obs.collects}"
    lines = obs.gc_lines()
    assert len(lines) == 1 and lines[0][0] == _ROUTE_LABEL.get(route, "project"), (
        f"{label}: GC log lines {lines}"
    )
    assert obs.final_enabled is True, label
    _assert_outcome_ok(obs, route)
    assert obs.holds == [True], f"{label}: request collector_hold {obs.holds}"


# ---------------------------------------------------------------------------
# .071 / .072 — small loads: held during preparation, no install collection.
# ---------------------------------------------------------------------------

_SMALL_INPUTS = {"case_01": CASE01_A2L, "asap2_demo_v171": V171_A2L}


@pytest.mark.parametrize("name", sorted(_SMALL_INPUTS))
@pytest.mark.parametrize("route", ROUTES)
def test_r_a2l_refresh_071_072_small_load_holds_then_skips_collection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, route: str, name: str
) -> None:
    """R-A2L-REFRESH.071 + R-A2L-REFRESH.072 (8 of the 9 arms): a small A2L (case_01 or
    ASAP2_Demo_V171) through direct attach, image+A2L (A2L installed first),
    project pair and A2L-only project: the request does not hold, the
    collector is disabled at every worker probe point after the worker's
    disable (so no automatic collection can delay a UI tick, .050), no
    product ``gc.collect()`` runs, no ``A2L load GC:`` line is logged, and
    the collector is enabled after the outcome."""
    a2l = _SMALL_INPUTS[name]
    installed = a2l if route == "image" else None
    obs = _observe(tmp_path, monkeypatch, route, a2l=a2l, installed=installed)
    _assert_small(obs, route, f"{route}/{name}")


def test_r_a2l_refresh_071_072_project_without_a2l_holds_then_skips_collection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R-A2L-REFRESH.071 + R-A2L-REFRESH.072 (the 9th arm): a project with an image and no
    A2L, nothing installed: no hold, the worker holds the collector, no
    collection at install, enabled after the outcome."""
    obs = _observe(tmp_path, monkeypatch, "project-no-a2l", a2l=None)
    _assert_small(obs, "project-no-a2l", "project-no-a2l")


def test_r_a2l_refresh_072_boundary_one_byte_below_one_mib_skips_collection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, a2l_sizes
) -> None:
    """R-A2L-REFRESH.072 boundary: an in-test A2L of exactly 1,048,575 bytes,
    nothing installed, direct attach: held during preparation, no collection
    at install."""

    obs = _observe(tmp_path, monkeypatch, "attach", a2l=a2l_sizes["below"])
    _assert_small(obs, "attach", "attach/1048575")


# ---------------------------------------------------------------------------
# .073 — large loads keep the D-13 hold and its one install collection.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("size", ["at", "two"], ids=["1MiB", "2MiB"])
@pytest.mark.parametrize("route", ROUTES)
def test_r_a2l_refresh_073_large_load_holds_collector_and_collects_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, a2l_sizes, route: str, size: str
) -> None:
    """R-A2L-REFRESH.073 (+ .052/.054 on the large side): an A2L of exactly
    1,048,576 bytes and one of 2 MiB through the four routes (the image route
    has it installed): the request holds, the collector is disabled at every
    worker probe point, then exactly one product collection and one
    ``A2L load GC:`` line carrying the route, and the collector is enabled
    after the outcome."""
    a2l = a2l_sizes[size]
    installed = a2l if route == "image" else None
    obs = _observe(tmp_path, monkeypatch, route, a2l=a2l, installed=installed)
    _assert_large(obs, route, f"{route}/{size}")


@pytest.mark.parametrize("route", ["attach", "project-pair"])
def test_r_a2l_refresh_073_large_to_small_keeps_hold_and_collects_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, a2l_sizes, route: str
) -> None:
    """R-A2L-REFRESH.073 large-to-small: a 2 MiB A2L installed, then case_01
    loaded by direct attach and by project pair: the second load is large
    (the installed file is at least 1 MiB), its worker holds the collector
    and its install makes exactly one collection and logs one line."""
    obs = _observe(
        tmp_path, monkeypatch, route, a2l=CASE01_A2L, installed=a2l_sizes["two"]
    )
    _assert_large(obs, route, f"{route}/large-to-small")


# ---------------------------------------------------------------------------
# .074 — an unreadable size is a large load (fault injected into the size read).
# ---------------------------------------------------------------------------

_TOKEN = "size-read-fault-074"


def _arm_lstat_fault(monkeypatch, file_name: str, exc: BaseException) -> list:
    """Make the lstat of ``file_name`` raise ``exc`` while the gate runs
    (identified by the gate's frame on the stack); returns the hit list."""
    real_lstat = os.lstat
    hits: list = []

    def fake(path, *args, **kwargs):
        if os.path.basename(os.fspath(path)) == file_name:
            frame = sys._getframe(1)
            for _ in range(8):
                if frame is None:
                    break
                if frame.f_code.co_name == "a2l_holds_collector":
                    hits.append(file_name)
                    raise exc
                frame = frame.f_back
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(os, "lstat", fake)
    return hits


@pytest.mark.parametrize(
    "arm",
    ["oserror-incoming-attach", "oserror-installed-project", "valueerror-incoming-attach"],
    ids=[f"R-A2L-REFRESH.074/{i}" for i in range(1, 4)],
)
def test_r_a2l_refresh_074_unreadable_size_holds_the_collector(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str
) -> None:
    """R-A2L-REFRESH.074: with the size read failing (OSError on the incoming
    file, OSError on the installed file, ValueError), a small load is prepared
    as large: the request holds, the worker holds the collector, one
    collection at install, the outcome is the success outcome of base, no
    exception leaves the request build, and the size read logs no path or
    error text."""
    folder = tmp_path / "in"
    folder.mkdir()
    small = folder / "unreadable_074.a2l"
    small.write_bytes(CASE01_A2L.read_bytes())
    installed_small = folder / "installed_074.a2l"
    installed_small.write_bytes(V171_A2L.read_bytes())
    if arm == "oserror-installed-project":
        route, a2l, installed, target = "project-pair", CASE01_A2L, installed_small, installed_small
        exc: BaseException = OSError(_TOKEN)
    else:
        route, a2l, installed, target = "attach", small, None, small
        exc = OSError(_TOKEN) if arm == "oserror-incoming-attach" else ValueError(_TOKEN)
    holder: dict = {}

    def prearm(app) -> None:
        # The installed file keeps its name in the workarea copy, so the fault
        # matches by file name and only fires inside the gate.
        holder["hits"] = _arm_lstat_fault(monkeypatch, target.name, exc)

    obs = _observe(tmp_path, monkeypatch, route, a2l=a2l, installed=installed, prearm=prearm)
    assert holder["hits"], "the size-read fault was never exercised"
    _assert_large(obs, route, arm)
    assert not any(_TOKEN in t for t in obs.texts()), obs.texts()
    assert not any(fn == "a2l_holds_collector" for *_x, fn in obs.log_records), obs.log_records


# ---------------------------------------------------------------------------
# .051 overlap arm — a large worker holds the collector while a small load
# completes; at most one collection per install, and enabled afterwards.
# ---------------------------------------------------------------------------


def test_r_a2l_refresh_051_overlap_large_held_while_small_completes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, a2l_sizes
) -> None:
    """R-A2L-REFRESH.051 (overlap arm, E3-4): a 2 MiB attach is held at a gate
    on its worker (collector disabled); its busy run is ended so the UI
    admits the next load (the product refuses a second load while busy, so
    this is the only way to overlap); a case_01 attach then completes; the
    large one is released and completes. The collector is enabled after both
    outcomes, each install makes at most one collection and the GC log lines
    equal the collections."""
    entered, release = threading.Event(), threading.Event()
    gc_at_gate: list = []
    real = S19TuiApp._prepare_a2l_attach_snapshot

    def gated(self_, *args, **kwargs):
        if not entered.is_set():
            gc_at_gate.append(gc.isenabled())
            entered.set()
            if not release.wait(180):
                raise TimeoutError("the overlap gate was never released")
        return real(self_, *args, **kwargs)

    monkeypatch.setattr(S19TuiApp, "_prepare_a2l_attach_snapshot", gated)
    marks: dict = {}

    async def body(app, pilot):
        _mount_views(app)
        await pilot.pause()
        obs = _arm(app, monkeypatch)
        await _submit_typed(app, pilot, str(a2l_sizes["two"]))
        if isinstance(app.screen, ConfirmQuestionScreen):
            await pilot.press("y")
        await wait_until(pilot, entered.is_set, "the large worker gate", timeout=180.0)
        run = app._busy.runs["a2l_load"]
        S19TuiApp.end_busy(app, "a2l_load", run.gen, "")  # admit the next load
        generation = app._a2l_view_generation
        await _submit_typed(app, pilot, str(CASE01_A2L))
        if isinstance(app.screen, ConfirmQuestionScreen):
            await pilot.press("y")
        await wait_until(
            pilot,
            lambda: app._a2l_view_generation > generation
            and any(k == "a2l_load" for k, _t in obs.outcomes),
            "the small attach outcome",
            timeout=180.0,
        )
        await pilot.pause()
        await pilot.pause()
        marks["small_collects"] = len(obs.collects)
        release.set()
        await settle_workers(pilot)
        await wait_until(
            pilot,
            lambda: len([k for k, _t in obs.outcomes if k == "a2l_load"]) >= 2,
            "the large attach outcome",
            timeout=180.0,
        )
        await pilot.pause()
        obs.final_enabled = gc.isenabled()
        return obs

    obs = _run(tmp_path / "app", body)
    assert gc_at_gate == [False], f"the large worker did not hold the collector: {gc_at_gate}"
    assert marks["small_collects"] <= 1, obs.collects
    assert len(obs.collects) - marks["small_collects"] <= 1, obs.collects
    assert len(obs.gc_lines()) == len(obs.collects), (obs.gc_lines(), obs.collects)
    assert obs.final_enabled is True
    assert obs.holds == [True, False], f"request collector_hold per attach: {obs.holds}"
