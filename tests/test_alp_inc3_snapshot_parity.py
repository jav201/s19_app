"""Batch 2026-11-18-a2l-load-performance Inc 3 E4 — prepared-load route parity.

Independent tester lane G-T-I3. Every oracle below comes from the Inc 3
ledger ``.dev-flow/2026-11-18-a2l-load-performance/inc-3/02-test-cases.md``,
the requirements ``01-requirements.md`` (R-A2L-REFRESH.039, .043-.048), the
frozen interfaces ``../../interfaces.md`` (I-ALP-2.2, I-ALP-3) and the E1
slice/rulings — never from an implementation.

Product-route rule: every acceptance arm instantiates the shipping
``S19TuiApp`` and drives the existing typed-path, project dialog and
direct-attach routes through Textual ``run_test()``/Pilot, reading visible
widgets and installed state after the real workers settle. No arm
substitutes a direct call to P5, L1 or a renderer for a route.

RED contract: every Inc 3 seam name is resolved lazily inside the test
body (``importlib`` + ``getattr`` defaults) and each node opens with a seam
guard, so each of the 35 nodes fails RED on the base revision ceac08cf with
a behavioural assertion, never a collection error. Stale arms build an
INDEPENDENT snapshot with the wrong expected pair through the real
producer and deliver it over the real worker-to-UI completion route; they
never mutate a frozen snapshot. No assertion is raised inside a UI
callback: callbacks record, the test asserts afterwards.
"""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import importlib
import json
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Optional

import pytest

from s19_app.tui.app import S19TuiApp
from s19_app.tui.changes.io import emit_s19_from_mem_map
from s19_app.tui.screens import ConfirmQuestionScreen
from tests.support.b100_workers import settle_workers
from tests.support.timing import wait_until
from tests.support.b103_a2l_arrays import characteristic, inline, meas
from s19_app.tui.a2l import parse_a2l_file
from tests.test_alp_inc2_a2l_attach import (
    IMG1,
    IMG2,
    NEW_ROWS,
    OLD_ROWS,
    SUPERSEDED_OUTCOME,
    _assert_panel_state,
    _a2l_viewer_names,
    _check_panel,
    _load_image,
    _load_project,
    _mid_a2l,
    _mount_views,
    _new_a2l,
    _old_a2l,
    _patch_panel,
    _project_digests,
    _run,
    _segment_block,
    _state_snapshot,
    _submit_typed,
    _typed_attach,
    _write_a2l,
    _write_image,
    _write_mac,
)
from tests.test_b103_a2l_refresh import _a2l_visible_shape, _arm_thread_spies

PROJECT_FAILURE_OUTCOME = (
    "Project NOT loaded: '{name}' could not be read — check that the folder "
    "can be opened, then load again."
)

# ---------------------------------------------------------------------------
# Lazy seam access — every Inc 3 name is resolved inside the test body.
# ---------------------------------------------------------------------------


def _fl_module():
    return importlib.import_module("s19_app.tui.app.file_load")


def _pl_module():
    return importlib.import_module("s19_app.tui.app.project_load")


def _sh_module():
    return importlib.import_module("s19_app.tui.app.shared")


def _service_module():
    return importlib.import_module("s19_app.tui.services.a2l_service")


def _definition_module():
    return importlib.import_module("s19_app.tui.a2l_definition")


def _picker_module():
    return importlib.import_module("s19_app.tui.a2l_parameter_picker")


def _sig_has(func, name: str) -> bool:
    import inspect

    return name in inspect.signature(func).parameters


def _dataclass_fields(dc) -> set:
    assert dc is not None
    return {field.name for field in dataclasses.fields(dc)}


def _guard_inc3_interface() -> None:
    """The fast RED guard for the Inc 3 prepared-snapshot contracts."""
    fl = _fl_module()
    assert getattr(fl, "FileLoadRequest", None) is not None, (
        "FileLoadRequest (F1) missing — the Inc 3 prepared-load context is not implemented"
    )
    assert "a2l_preparation" in _dataclass_fields(getattr(_sh_module(), "PreparedLoad")), (
        "PreparedLoad.a2l_preparation (S1) missing — the Inc 3 snapshot handoff is not implemented"
    )
    assert _sig_has(fl.FileLoadMixin._prepare_load_payload, "prepare_a2l"), (
        "F5 prepare_a2l seam missing"
    )
    assert _sig_has(fl.FileLoadMixin._start_load_worker, "context"), "F6 context seam missing"
    assert _sig_has(fl.FileLoadMixin._parse_loaded_file, "context"), "F4 context seam missing"
    pl = _pl_module()
    request_fields = _dataclass_fields(getattr(pl, "ProjectLoadRequest"))
    assert {"captured_a2l_generation", "captured_image_generation"} <= request_fields, (
        "P1 captured-generation fields missing"
    )
    assert "a2l_only" in _dataclass_fields(getattr(pl, "PreparedProjectLoad")), (
        "P2 a2l_only field missing"
    )


def _guard_image_route() -> None:
    fl = _fl_module()
    assert getattr(fl, "FileLoadRequest", None) is not None, (
        "FileLoadRequest (F1) missing — the Inc 3 image-route context is not implemented"
    )
    assert "a2l_preparation" in _dataclass_fields(getattr(_sh_module(), "PreparedLoad")), (
        "PreparedLoad.a2l_preparation (S1) missing — the Inc 3 snapshot handoff is not implemented"
    )
    assert _sig_has(fl.FileLoadMixin._prepare_load_payload, "prepare_a2l"), (
        "F5 prepare_a2l seam missing"
    )
    assert _sig_has(fl.FileLoadMixin._start_load_worker, "context"), "F6 context seam missing"
    assert _sig_has(fl.FileLoadMixin._parse_loaded_file, "context"), "F4 context seam missing"


def _guard_project_route() -> None:
    fl = _fl_module()
    pl = _pl_module()
    assert _sig_has(fl.FileLoadMixin._prepare_load_payload, "prepare_a2l"), (
        "F5 prepare_a2l seam missing"
    )
    assert "a2l_preparation" in _dataclass_fields(getattr(_sh_module(), "PreparedLoad")), (
        "PreparedLoad.a2l_preparation (S1) missing — the Inc 3 snapshot handoff is not implemented"
    )
    assert {"captured_a2l_generation", "captured_image_generation"} <= _dataclass_fields(
        getattr(pl, "ProjectLoadRequest")
    ), "P1 captured-generation fields missing"
    assert "a2l_only" in _dataclass_fields(getattr(pl, "PreparedProjectLoad")), (
        "P2 a2l_only field missing"
    )


def _accepted_snapshots(app):
    return getattr(app, "_accepted_a2l_picker_snapshots", None)


# ---------------------------------------------------------------------------
# Synthetic fixtures (equal-size OLD/NEW pairs, project seeding with MAC).
# ---------------------------------------------------------------------------


def _pair_a2l(path: Path, token: str) -> Path:
    """An equal-size A2L pair: ``OLD``/``NEW`` differ only in same-length
    marker names, so both files have identical byte sizes while their
    parsed content (names/addresses) differs."""
    base_addr = 0x2100 if token == "OLD" else 0x3100
    names = [f"{token}_TAG_A", f"{token}_TAG_B"]
    return _write_a2l(
        path,
        *[_segment_block(names[i], base_addr + i * 0x40, 2) for i in range(2)],
        characteristic(names[0], "VALUE", f"0x{base_addr:04X}", "RL_U16", "CM_IDENT", "0", "65535"),
        meas(names[1], "UWORD", addr=f"0x{base_addr + 0x40:04X}"),
    )


def _seed_project3(
    workarea: Path,
    name: str,
    *,
    a2l: Path,
    image: Optional[Path] = None,
    mac: Optional[Path] = None,
) -> Path:
    """Seed a project folder (image and/or MAC plus A2L) into a workarea."""
    folder = workarea / name
    folder.mkdir(parents=True, exist_ok=True)
    active = None
    if image is not None:
        (folder / image.name).write_bytes(image.read_bytes())
        active = image.stem
    (folder / a2l.name).write_bytes(a2l.read_bytes())
    if mac is not None:
        (folder / mac.name).write_bytes(mac.read_bytes())
    (folder / "project.json").write_text(
        json.dumps({"schema_version": 1, "active_variant": active}), encoding="utf-8"
    )
    return folder


def _expected_raws(rows, image) -> list:
    """The viewer's Raw cell text per fixture row under ``image``."""
    out = []
    for _name, address, size, _fmt in rows:
        if image is None or any(address + off not in image for off in range(size)):
            out.append("")
        else:
            out.append(str(sum(image[address + off] << (8 * off) for off in range(size))))
    return out


def _digest_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _parsed_without_path(data) -> dict:
    """The parse payload minus its lexical ``path`` item: the shipped routes
    parse the workarea copy of a fixture, so the embedded parse path differs
    from a fresh parse of the source fixture; every other item must stay
    byte-identical (D-6, E4 fixture/oracle correction)."""
    return {key: value for key, value in data.items() if key != "path"}


# ---------------------------------------------------------------------------
# Instruments (thread-recording; callbacks record, tests assert afterwards).
# ---------------------------------------------------------------------------


class ProducerSpy:
    """Record every Inc 2 producer call: thread, explicit kwargs and the
    returned (immutable) snapshot."""

    def __init__(self, monkeypatch) -> None:
        self.calls: list = []
        real = getattr(S19TuiApp, "_prepare_a2l_attach_snapshot", None)
        spy = self

        def _wrapped(self_, **kwargs):
            result = real(self_, **kwargs) if real is not None else None
            spy.calls.append(
                SimpleNamespace(
                    thread=threading.get_ident(), kwargs=kwargs, result=result
                )
            )
            return result

        monkeypatch.setattr(S19TuiApp, "_prepare_a2l_attach_snapshot", _wrapped, raising=False)


def _arm_construction_spies(monkeypatch) -> dict:
    """Thread-tagged enrichment/summary/definition construction records."""
    fl = _fl_module()
    service = _service_module()
    definition = _definition_module()
    picker = _picker_module()
    records: dict = {"enrich": [], "summary": [], "describe": []}
    real_enrich = getattr(fl, "enrich_tags_and_render", None)

    def enrich_spy(*args, **kwargs):
        records["enrich"].append(threading.get_ident())
        return real_enrich(*args, **kwargs) if real_enrich is not None else None

    monkeypatch.setattr(fl, "enrich_tags_and_render", enrich_spy, raising=False)
    monkeypatch.setattr(service, "enrich_tags_and_render", enrich_spy, raising=False)
    real_render = getattr(service, "render_a2l_view", None)

    def render_spy(*args, **kwargs):
        records["summary"].append(threading.get_ident())
        return real_render(*args, **kwargs) if real_render is not None else None

    monkeypatch.setattr(service, "render_a2l_view", render_spy, raising=False)
    real_describe = definition.describe_definitions

    def describe_spy(names, a2l_data):
        result = real_describe(list(names), a2l_data)
        records["describe"].append(threading.get_ident())
        return result

    monkeypatch.setattr(definition, "describe_definitions", describe_spy)
    monkeypatch.setattr(picker, "describe_definitions", describe_spy, raising=False)
    monkeypatch.setattr(fl, "describe_definitions", describe_spy, raising=False)
    return records


def _arm_timeline(app: S19TuiApp, monkeypatch, events: list) -> None:
    """install -> F -> OUTCOME timeline; each F records its pre/post paint."""
    real_fanout = S19TuiApp._refresh_a2l_dependent_views
    real_install = S19TuiApp._apply_prepared_load
    real_end = S19TuiApp.end_busy

    def fanout() -> None:
        pre = tuple(_a2l_viewer_names(app))
        real_fanout(app)
        post = tuple(_a2l_viewer_names(app))
        events.append(("F", time.monotonic(), pre, post))

    def install(prepared, path, load_started, **kwargs):
        events.append(("install", threading.get_ident()))
        return real_install(app, prepared, path, load_started, **kwargs)

    def end(key, gen, outcome):
        events.append(("OUTCOME", threading.get_ident(), key, str(outcome)))
        return real_end(app, key, gen, outcome)

    monkeypatch.setattr(app, "_refresh_a2l_dependent_views", fanout, raising=False)
    monkeypatch.setattr(app, "_apply_prepared_load", install, raising=False)
    monkeypatch.setattr(app, "end_busy", end)


def _arm_outcomes(app: S19TuiApp, monkeypatch, outcomes: list) -> None:
    real_end = S19TuiApp.end_busy

    def end(key, gen, outcome):
        outcomes.append((key, str(outcome)))
        return real_end(app, key, gen, outcome)

    monkeypatch.setattr(app, "end_busy", end)


def _arm_zero_spies(app: S19TuiApp, monkeypatch) -> dict:
    """Spies that every rejected/adverse arm asserts stay at zero."""
    spies: dict = {}
    for name in (
        "_reset_project_session",
        "_apply_prepared_load",
        "_refresh_a2l_dependent_views",
        "_store_a2l_cache",
        "_replace_current_a2l",
        "_sync_loaded_file_to_project",
    ):
        real = getattr(app, name, None)
        calls: list = []

        def _wrap(*args, __real=real, __calls=calls, **kwargs):
            __calls.append(threading.get_ident())
            return __real(*args, **kwargs) if __real is not None else None

        monkeypatch.setattr(app, name, _wrap, raising=False)
        spies[name] = calls
    return spies


def _arm_stale_producer(monkeypatch, *, a2l_delta: int = 0, image_delta: int = 0) -> None:
    """Return an INDEPENDENT snapshot with the wrong expected pair through
    the real producer (never a mutation of a frozen snapshot)."""
    real = S19TuiApp._prepare_a2l_attach_snapshot

    def stale(self_, **kwargs):
        bad = dict(kwargs)
        bad["expected_a2l_generation"] = kwargs["expected_a2l_generation"] + a2l_delta
        bad["expected_image_generation"] = kwargs["expected_image_generation"] + image_delta
        return real(self_, **bad)

    monkeypatch.setattr(S19TuiApp, "_prepare_a2l_attach_snapshot", stale, raising=False)


def _arm_keyless_stale(monkeypatch, *, a2l: bool = False, image: bool = False) -> None:
    """Keyless image-stage bundle carrying a stale legacy expectation."""
    real = S19TuiApp._prepare_load_payload

    def wrapped(self_, loaded, *args, **kwargs):
        result = real(self_, loaded, *args, **kwargs)
        if kwargs.get("prepare_a2l", True) is False:
            if a2l and result.a2l_view_generation is not None:
                result = dataclasses.replace(
                    result, a2l_view_generation=result.a2l_view_generation - 1
                )
            if image and result.a2l_image_generation is not None:
                result = dataclasses.replace(
                    result, a2l_image_generation=result.a2l_image_generation - 1
                )
        return result

    monkeypatch.setattr(S19TuiApp, "_prepare_load_payload", wrapped, raising=False)


def _arm_dispatch_gate(app: S19TuiApp, monkeypatch, predicate, dispatches: list):
    """Hold one worker-to-UI dispatch until the test releases it."""
    real = app.call_from_thread
    started = threading.Event()
    release = threading.Event()

    def gated(callback, *args, **kwargs):
        if predicate(callback) and not dispatches:
            dispatches.append((callback, args, kwargs))
            started.set()
            assert release.wait(20)
        return real(callback, *args, **kwargs)

    monkeypatch.setattr(app, "call_from_thread", gated)
    return started, release


def _state3(app: S19TuiApp) -> tuple:
    """The session/artifact surface the project adverse arms must preserve."""
    return (
        app.current_a2l_path,
        copy.deepcopy(app.current_a2l_data),
        app.current_project,
        None if app.current_file is None else app.current_file.path,
        None if app.current_file is None else copy.deepcopy(app.current_file.mem_map),
        copy.deepcopy(app._a2l_enriched_tags),
        app._a2l_enriched_key,
    )


async def _drive_project_load(app: S19TuiApp, pilot, name: str) -> None:
    """The real project dialog route, without any success assertion."""
    from tests.support import b100_load_dialog as ld

    await pilot.press("p")
    await wait_until(pilot, lambda: len(app.screen.query("#load_path")) > 0, "Load dialog did not open")
    await ld.highlight_row(pilot, app, name)
    await pilot.press("enter")
    await wait_until(pilot, lambda: not ld.is_load_dialog(app.screen), "the Load dialog to close")
    if isinstance(app.screen, ConfirmQuestionScreen):
        await pilot.press("y")
    await pilot.pause()


async def _drive_typed_no_assert(app: S19TuiApp, pilot, path: Path) -> None:
    """The typed load route without any success assertion; polls for the
    confirm question (it can open a beat after submission under load)."""
    await _submit_typed(app, pilot, str(path))
    try:
        await wait_until(
            pilot,
            lambda: isinstance(app.screen, ConfirmQuestionScreen),
            "the typed-load confirm modal",
            timeout=10.0,
        )
        await pilot.press("y")
    except AssertionError:
        pass  # no confirmation modal on this route
    await pilot.pause()


def _assert_frozen_snapshot(snap) -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        snap.expected_a2l_generation = 99


def _assert_ui_quiet(main: int, records: dict) -> None:
    """0 UI-thread enrichment/summary/definition constructions."""
    assert main not in records["enrich"], records
    assert main not in records["summary"], records
    assert main not in records["describe"], records


# ===========================================================================
# R-A2L-REFRESH.039 — one shared immutable prepared-snapshot interface (5/5).
# ===========================================================================


@pytest.mark.parametrize(
    "arm",
    ["direct-attach", "image-a2l", "project-pair-mac", "a2l-only", "project-pair-nomac"],
    ids=[f"R-A2L-REFRESH.039/{i}" for i in range(1, 6)],
)
def test_r039_shared_snapshot_interface(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str) -> None:
    """R-A2L-REFRESH.039/1-/5: every route calls the one Inc 2 producer
    exactly once with the stage pair; the returned snapshot is frozen,
    carries enrichment/summary/definition data, is consumed (current key +
    accepted picker mapping + painted sentinels) and builds nothing on UI."""
    _guard_inc3_interface()

    base = tmp_path / "app"
    src = tmp_path / "src"
    src.mkdir(parents=True)
    old = _old_a2l(src / "old.a2l")
    new = _new_a2l(src / "new.a2l")
    img1 = _write_image(src / "img1.s19", dict(IMG1))
    img2 = _write_image(src / "img2.s19", dict(IMG2))
    mac = _write_mac(src / "records.mac")

    async def body(app, pilot):
        main = threading.get_ident()
        _mount_views(app)
        await pilot.pause()
        producer = ProducerSpy(monkeypatch)
        constructions = _arm_construction_spies(monkeypatch)
        if arm == "direct-attach":
            await _load_image(app, pilot, img1)
            a0, i0 = app._a2l_view_generation, app._image_generation
            await _typed_attach(app, pilot, old)
            await settle_workers(pilot)
            assert len(producer.calls) == 1, producer.calls
            call = producer.calls[0]
            assert call.thread != main
            assert call.kwargs["expected_a2l_generation"] == a0 + 1, call.kwargs
            assert call.kwargs["expected_image_generation"] == i0, call.kwargs
            _assert_frozen_snapshot(call.result)
            assert set(call.result.picker_snapshots) == {"check", "patch"}
            assert call.result.enriched_tags and call.result.summary_lines
            snap_map = _accepted_snapshots(app)
            assert snap_map is not None and set(snap_map) == {"check", "patch"}, snap_map
            assert app._a2l_enriched_key == (
                a0 + 1,
                i0,
                len(call.kwargs["image_mem_map"]),
            )
            _assert_panel_state(_check_panel(app), OLD_ROWS)
            _assert_panel_state(_patch_panel(app), OLD_ROWS)
            _assert_ui_quiet(main, constructions)
        elif arm == "image-a2l":
            await _typed_attach(app, pilot, old)
            await _load_image(app, pilot, img1)
            a0, i0 = app._a2l_view_generation, app._image_generation
            constructions["enrich"].clear()
            constructions["summary"].clear()
            constructions["describe"].clear()
            producer.calls.clear()
            await _load_image(app, pilot, img2)
            await settle_workers(pilot)
            assert len(producer.calls) == 1, producer.calls
            call = producer.calls[0]
            assert call.thread != main
            assert call.kwargs["expected_a2l_generation"] == a0 + 1, call.kwargs
            assert call.kwargs["expected_image_generation"] == i0 + 1, call.kwargs
            _assert_frozen_snapshot(call.result)
            assert app._a2l_view_generation == a0 + 1 and app._image_generation == i0 + 1
            assert app._a2l_enriched_key == (a0 + 1, i0 + 1, len(IMG2))
            assert len(constructions["enrich"]) == 1, constructions
            assert len(constructions["summary"]) == 1, constructions
            assert len(constructions["describe"]) == 1, constructions
            _assert_ui_quiet(main, constructions)
            _assert_panel_state(_check_panel(app), OLD_ROWS)
            _assert_panel_state(_patch_panel(app), OLD_ROWS)
        elif arm == "project-pair-mac":
            _seed_project3(app.workarea, "proj_a", a2l=old, image=img1, mac=mac)
            assert app._a2l_view_generation == 0 and app._image_generation == 0
            await _load_project(app, pilot, "proj_a")
            await settle_workers(pilot)
            assert len(producer.calls) == 1, producer.calls
            call = producer.calls[0]
            assert call.thread != main
            assert call.kwargs["expected_a2l_generation"] == 3, call.kwargs
            assert call.kwargs["expected_image_generation"] == 2, call.kwargs
            _assert_frozen_snapshot(call.result)
            assert app._a2l_view_generation == 3 and app._image_generation == 2
            assert app._a2l_enriched_key == (3, 2, len(IMG1))
            assert app.current_file is not None and app.current_file.mac_records
            assert len(constructions["enrich"]) == 1, constructions
            assert len(constructions["summary"]) == 1, constructions
            assert len(constructions["describe"]) == 1, constructions
            _assert_ui_quiet(main, constructions)
            snap_map = _accepted_snapshots(app)
            assert snap_map is not None and set(snap_map) == {"check", "patch"}, snap_map
            _assert_panel_state(_check_panel(app), OLD_ROWS)
            _assert_panel_state(_patch_panel(app), OLD_ROWS)
        elif arm == "a2l-only":
            _seed_project3(app.workarea, "proj_a", a2l=old)
            assert app._a2l_view_generation == 0 and app._image_generation == 0
            await _load_project(app, pilot, "proj_a")
            await settle_workers(pilot)
            assert len(producer.calls) == 1, producer.calls
            call = producer.calls[0]
            assert call.thread != main
            assert call.kwargs["image_mem_map"] is None, call.kwargs
            assert call.kwargs["expected_a2l_generation"] == 2, call.kwargs
            assert call.kwargs["expected_image_generation"] == 0, call.kwargs
            _assert_frozen_snapshot(call.result)
            assert app._a2l_view_generation == 2 and app._image_generation == 0
            assert app.current_file is None
            assert app._a2l_enriched_key == (2, 0, -1)
            assert len(constructions["enrich"]) == 1, constructions
            assert len(constructions["summary"]) == 1, constructions
            assert len(constructions["describe"]) == 1, constructions
            _assert_ui_quiet(main, constructions)
            snap_map = _accepted_snapshots(app)
            assert snap_map is not None and set(snap_map) == {"check", "patch"}, snap_map
            _assert_panel_state(_check_panel(app), OLD_ROWS)
            _assert_panel_state(_patch_panel(app), OLD_ROWS)
        else:  # project-pair-nomac
            _seed_project3(app.workarea, "proj_a", a2l=old, image=img1)
            assert app._a2l_view_generation == 0 and app._image_generation == 0
            await _load_project(app, pilot, "proj_a")
            await settle_workers(pilot)
            assert len(producer.calls) == 1, producer.calls
            call = producer.calls[0]
            assert call.thread != main
            assert call.kwargs["expected_a2l_generation"] == 2, call.kwargs
            assert call.kwargs["expected_image_generation"] == 1, call.kwargs
            _assert_frozen_snapshot(call.result)
            assert app._a2l_view_generation == 2 and app._image_generation == 1
            assert app._a2l_enriched_key == (2, 1, len(IMG1))
            assert app.current_file is not None
            assert not app.current_file.mac_records and app.current_file.mac_path is None
            assert len(constructions["enrich"]) == 1, constructions
            assert len(constructions["summary"]) == 1, constructions
            assert len(constructions["describe"]) == 1, constructions
            _assert_ui_quiet(main, constructions)
            snap_map = _accepted_snapshots(app)
            assert snap_map is not None and set(snap_map) == {"check", "patch"}, snap_map
            _assert_panel_state(_check_panel(app), OLD_ROWS)
            _assert_panel_state(_patch_panel(app), OLD_ROWS)
        return None

    _run(base, body)


# ===========================================================================
# R-A2L-REFRESH.043 — preparation failure has no UI fallback (4/4).
# ===========================================================================


@pytest.mark.parametrize(
    "arm",
    ["image", "project-pair-mac", "a2l-only", "project-pair-nomac"],
    ids=[f"R-A2L-REFRESH.043/{i}" for i in range(1, 5)],
)
def test_r043_preparation_failure_has_no_ui_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str) -> None:
    """R-A2L-REFRESH.043/1-/4: ValueError("PREPARE_CONTROL") at the
    producer ends the route through the existing failure outcome with
    previous state/project hashes equal, 0 candidate installs, 0 UI
    preparation and 0 success; no minimal-bundle fallback installs."""
    _guard_inc3_interface()

    base = tmp_path / "app"
    src = tmp_path / "src"
    src.mkdir(parents=True)
    old = _old_a2l(src / "old.a2l")
    img1 = _write_image(src / "img1.s19", dict(IMG1))
    img2 = _write_image(src / "img2.s19", dict(IMG2))
    mac = _write_mac(src / "records.mac")

    async def body(app, pilot):
        main = threading.get_ident()
        _mount_views(app)
        await pilot.pause()

        def boom(self_, **kwargs):
            raise ValueError("PREPARE_CONTROL")

        if arm == "image":
            await _load_image(app, pilot, img1)
            await _typed_attach(app, pilot, old)
            before = _state_snapshot(app)
            monkeypatch.setattr(S19TuiApp, "_prepare_a2l_attach_snapshot", boom)
            zero = _arm_zero_spies(app, monkeypatch)
            constructions = _arm_construction_spies(monkeypatch)
            outcomes: list = []
            _arm_outcomes(app, monkeypatch, outcomes)
            widget_calls = _arm_thread_spies(app, monkeypatch)
            await _drive_typed_no_assert(app, pilot, img2)
            await settle_workers(pilot)
            await wait_until(pilot, lambda: bool(outcomes), "the image failure outcome", timeout=30.0)
            assert outcomes == [("file_load", "Load failed")], outcomes
            assert len(zero["_apply_prepared_load"]) == 0, zero
            assert len(zero["_store_a2l_cache"]) == 0
            assert len(zero["_refresh_a2l_dependent_views"]) == 0
            assert len(zero["_sync_loaded_file_to_project"]) == 0
            assert widget_calls == [], widget_calls
            assert main not in constructions["enrich"], constructions
            assert main not in constructions["summary"], constructions
            assert main not in constructions["describe"], constructions
            assert _state_snapshot(app) == before
        else:
            a2l = old
            if arm == "project-pair-mac":
                folder = _seed_project3(app.workarea, "proj_a", a2l=a2l, image=img1, mac=mac)
            elif arm == "a2l-only":
                folder = _seed_project3(app.workarea, "proj_a", a2l=a2l)
            else:
                folder = _seed_project3(app.workarea, "proj_a", a2l=a2l, image=img1)
            digests = _project_digests(folder)
            before = _state3(app)
            monkeypatch.setattr(S19TuiApp, "_prepare_a2l_attach_snapshot", boom)
            zero = _arm_zero_spies(app, monkeypatch)
            constructions = _arm_construction_spies(monkeypatch)
            outcomes: list = []
            _arm_outcomes(app, monkeypatch, outcomes)
            widget_calls = _arm_thread_spies(app, monkeypatch)
            await _drive_project_load(app, pilot, "proj_a")
            await settle_workers(pilot)
            await wait_until(pilot, lambda: bool(outcomes), "the project failure outcome", timeout=30.0)
            expected = PROJECT_FAILURE_OUTCOME.format(name="proj_a")
            assert outcomes == [("project_load", expected)], outcomes
            assert len(zero["_reset_project_session"]) == 0, zero
            assert len(zero["_apply_prepared_load"]) == 0
            assert len(zero["_refresh_a2l_dependent_views"]) == 0
            assert len(zero["_store_a2l_cache"]) == 0
            assert len(zero["_replace_current_a2l"]) == 0
            assert widget_calls == [], widget_calls
            assert main not in constructions["enrich"], constructions
            assert main not in constructions["summary"], constructions
            assert main not in constructions["describe"], constructions
            assert _state3(app) == before
            assert _project_digests(folder) == digests
            if arm == "project-pair-nomac":
                assert app.current_file is None, "a MAC/image was fabricated on the failure route"
        return None

    _run(base, body)


def test_r043_install_exception_reenables_gc(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R-A2L-REFRESH.051 (E4R) — loose image install-exception arm (reviewer
    MAJOR E5-INC3-F4): an injected exception in the loose prepared-load
    install body (_store_a2l_cache) propagates, but must RE-ENABLE the cycle
    collector that the prepared-load producer left disabled. Every
    observation is recorded inside the route and asserted after Textual's
    exception re-raise."""
    import gc

    _guard_inc3_interface()

    base = tmp_path / "app"
    src = tmp_path / "src"
    src.mkdir(parents=True)
    old = _old_a2l(src / "old.a2l")
    img1 = _write_image(src / "img1.s19", dict(IMG1))
    img2 = _write_image(src / "img2.s19", dict(IMG2))

    armed: dict = {"on": False}
    raised: list = []
    gc_at_boom: list = []
    gc_at_end: list = []
    outcomes: list = []

    async def body(app, pilot):
        _mount_views(app)
        await pilot.pause()
        await _load_image(app, pilot, img1)
        await _typed_attach(app, pilot, old)

        real_store = app._store_a2l_cache

        def store_boom(*args, **kwargs):
            if armed["on"]:
                raised.append(True)
                gc_at_boom.append(gc.isenabled())
                raise ValueError("install boom")
            return real_store(*args, **kwargs)

        monkeypatch.setattr(app, "_store_a2l_cache", store_boom)
        _arm_outcomes(app, monkeypatch, outcomes)
        armed["on"] = True
        await _drive_typed_no_assert(app, pilot, img2)
        await settle_workers(pilot)
        await wait_until(
            pilot, lambda: bool(raised), "the install exception", timeout=30.0
        )
        await pilot.pause()
        await pilot.pause()
        gc_at_end.append(gc.isenabled())
        return None

    with pytest.raises(Exception, match="install boom"):
        _run(base, body)
    assert raised, "the install exception never fired"
    assert gc_at_boom == [False], (
        "the producer left the cycle collector disabled for the install "
        f"window: {gc_at_boom}"
    )
    assert gc_at_end == [True], (
        "R-A2L-REFRESH.051: the cycle collector stayed disabled after the "
        f"install exception: {gc_at_end}"
    )
    assert bool(outcomes), outcomes


# ===========================================================================
# R-A2L-REFRESH.051/.052 — project/image outcomes leave GC enabled, no full
# collection on install.
# ===========================================================================


def test_r_a2l_refresh_051_project_success_gc_enabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R-A2L-REFRESH.051 (E4R) — project load success arm: after a project
    load installs and ends, the cycle collector is enabled."""
    import gc

    _guard_project_route()

    base = tmp_path / "app"
    src = tmp_path / "src"
    src.mkdir(parents=True)
    old = _old_a2l(src / "old.a2l")
    img1 = _write_image(src / "img1.s19", dict(IMG1))

    gc_at_end: list = []

    async def body(app, pilot):
        _mount_views(app)
        await pilot.pause()
        _seed_project3(app.workarea, "proj_a", a2l=old, image=img1)
        await _load_project(app, pilot, "proj_a")
        gc_at_end.append(gc.isenabled())
        return None

    _run(base, body)
    assert gc_at_end == [True], (
        "R-A2L-REFRESH.051: gc disabled after the project success outcome: "
        f"{gc_at_end}"
    )


@pytest.mark.parametrize(
    "arm",
    ["image", "project"],
    ids=[f"R-A2L-REFRESH.052/{i}" for i in range(1, 3)],
)
def test_r_a2l_refresh_052_install_runs_no_full_collection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str
) -> None:
    """R-A2L-REFRESH.052/.054 (E4R, operator D-GC = A) — image and
    project install arms: each install runs at most one full gc.collect()
    from a product module, and that single collection is logged by the
    ``s19tui`` logger with the arm's route and its duration in seconds."""
    import gc
    import sys

    if arm == "image":
        _guard_image_route()
    else:
        _guard_project_route()

    base = tmp_path / "app"
    src = tmp_path / "src"
    src.mkdir(parents=True)
    old = _old_a2l(src / "old.a2l")
    img = _write_image(src / "img1.s19", dict(IMG1))
    a2l = _mid_a2l(src, count=2000)

    real_collect = gc.collect
    product_collects: list = []

    def collect_spy(*args, **kwargs):
        caller = sys._getframe(1).f_globals.get("__name__")
        if caller in {
            "s19_app.tui.app.file_load",
            "s19_app.tui.app.loaded_state",
            "s19_app.tui.app.project_load",
        }:
            product_collects.append((caller, threading.get_ident()))
        return real_collect(*args, **kwargs)

    outcomes: list = []
    gc_log_lines: list = []

    async def body(app, pilot):
        _mount_views(app)
        await pilot.pause()
        _arm_outcomes(app, monkeypatch, outcomes)
        real_info = app.logger.info

        def info_spy(msg, *args, **kwargs):
            if isinstance(msg, str) and msg.startswith("A2L load GC:"):
                gc_log_lines.append((msg, args))
            return real_info(msg, *args, **kwargs)

        if arm == "image":
            # Attach the mid-size A2L first (its own install is not under
            # test); then arm the spies and load the image, whose install
            # must run at most one full collection.
            await _typed_attach(app, pilot, a2l)
            await settle_workers(pilot)
            monkeypatch.setattr(gc, "collect", collect_spy)
            monkeypatch.setattr(app.logger, "info", info_spy)
            await _load_image(app, pilot, img)
            await settle_workers(pilot)
            await wait_until(
                pilot,
                lambda: any(key == "file_load" for key, _ in outcomes),
                "the image-load outcome",
                timeout=60.0,
            )
        else:
            _seed_project3(app.workarea, "proj_a", a2l=a2l, image=img)
            monkeypatch.setattr(gc, "collect", collect_spy)
            monkeypatch.setattr(app.logger, "info", info_spy)
            await _load_project(app, pilot, "proj_a")
            await settle_workers(pilot)
        return None

    _run(base, body)
    if arm == "image":
        assert any(key == "file_load" for key, _ in outcomes), outcomes
    else:
        assert any(key == "project_load" for key, _ in outcomes), outcomes
    assert len(product_collects) <= 1, (
        f"R-A2L-REFRESH.052: the {arm} install ran more than one full "
        f"gc.collect() from a product module: {product_collects}"
    )
    assert len(product_collects) == len(gc_log_lines), (
        f"R-A2L-REFRESH.052/.054: the {arm} install's full collections are "
        "not one-to-one with the logged GC lines: "
        f"collects={product_collects} logs={gc_log_lines}"
    )
    assert gc_log_lines and all(args and args[0] == arm for _msg, args in gc_log_lines), (
        f"R-A2L-REFRESH.054: the {arm} install's GC log line does not carry "
        f"the {arm} route: {gc_log_lines}"
    )


# ===========================================================================
# R-A2L-REFRESH.044 — image route publishes the final pair once (3/3).
# ===========================================================================


@pytest.mark.parametrize(
    "arm",
    ["first-image", "different-path", "same-path-equal-size"],
    ids=[f"R-A2L-REFRESH.044/{i}" for i in range(1, 4)],
)
def test_r044_image_final_publication(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str) -> None:
    """R-A2L-REFRESH.044/1-/3: final image/A2L install -> exactly 1 F with
    the prepared final pair -> OUTCOME; no F before installation, no
    outgoing publication, OLD raw values are absent."""
    _guard_image_route()

    base = tmp_path / "app"
    src = tmp_path / "src"
    src.mkdir(parents=True)
    old = _old_a2l(src / "old.a2l")
    img1 = _write_image(src / "img1.s19", dict(IMG1))
    img2 = _write_image(src / "img2.s19", dict(IMG2))

    async def body(app, pilot):
        main = threading.get_ident()
        _mount_views(app)
        await pilot.pause()
        await _typed_attach(app, pilot, old)
        a0, i0 = app._a2l_view_generation, app._image_generation
        events: list = []
        if arm == "first-image":
            producer = ProducerSpy(monkeypatch)
            _arm_timeline(app, monkeypatch, events)
            await _load_image(app, pilot, img1)
            expected_mem = dict(IMG1)
            expected_raw = 0x2010
            expected_name = "img1.s19"
        elif arm == "different-path":
            await _load_image(app, pilot, img1)
            a0, i0 = app._a2l_view_generation, app._image_generation
            producer = ProducerSpy(monkeypatch)
            _arm_timeline(app, monkeypatch, events)
            await _load_image(app, pilot, img2)
            expected_mem = dict(IMG2)
            expected_raw = 0x8070
            expected_name = "img2.s19"
        else:  # same-path-equal-size
            # Both fixture writes use the SAME raw-LF emitter: the reused
            # write_text-based _write_image lands CRLF (42 B) on Windows
            # while the in-place overwrite is raw LF (39 B), which made the
            # equal-size pair unsatisfiable (E4 fixture correction).
            same = src / "image.s19"
            same.write_bytes(
                emit_s19_from_mem_map(dict(IMG1), [(min(IMG1), max(IMG1) + 1)]).encode("ascii")
            )
            await _load_image(app, pilot, same)
            a0, i0 = app._a2l_view_generation, app._image_generation
            size_before = same.stat().st_size
            same.write_bytes(
                emit_s19_from_mem_map(dict(IMG2), [(min(IMG2), max(IMG2) + 1)]).encode("ascii")
            )
            assert same.stat().st_size == size_before, "fixture: equal-size pair required"
            producer = ProducerSpy(monkeypatch)
            _arm_timeline(app, monkeypatch, events)
            await _load_image(app, pilot, same)
            expected_mem = dict(IMG2)
            expected_raw = 0x8070
            # The second typed load of the same path copies to the workarea
            # temp dir again and lands on the dedup suffix image_1.s19 (the
            # first load's copy still occupies image.s19), so the outcome
            # names that copy.
            expected_name = "image_1.s19"
        await settle_workers(pilot)
        await wait_until(pilot, lambda: any(e[0] == "OUTCOME" for e in events), "the image outcome", timeout=30.0)
        assert len(producer.calls) == 1, producer.calls
        call = producer.calls[0]
        assert call.thread != main, "the producer ran on the UI thread"
        assert call.kwargs["expected_a2l_generation"] == a0 + 1, call.kwargs
        assert call.kwargs["expected_image_generation"] == i0 + 1, call.kwargs
        kind = [e[0] for e in events if e[0] in {"install", "F", "OUTCOME"}]
        assert kind == ["install", "F", "OUTCOME"], events
        fs = [e for e in events if e[0] == "F"]
        assert len(fs) == 1, events
        assert fs[0][2] == tuple(name for name, *_ in OLD_ROWS), fs  # pre-paint = prepared final pair
        assert fs[0][3] == tuple(name for name, *_ in OLD_ROWS), fs
        outcomes = [e for e in events if e[0] == "OUTCOME"]
        assert len(outcomes) == 1 and outcomes[0][3].startswith(f"Loaded {expected_name}"), outcomes
        assert app.current_file is not None and app.current_file.mem_map == expected_mem
        assert app._a2l_enriched_key == (
            app._a2l_view_generation,
            app._image_generation,
            len(expected_mem),
        )
        tag = next(t for t in app._a2l_enriched_tags if t["name"] == "OLD_SCALAR")
        assert tag.get("raw_value") == expected_raw, tag
        shape = _a2l_visible_shape(app)
        expected_shape = [
            (name, f"0x{address:08X}", str(size), raw)
            for (name, address, size, _fmt), raw in zip(OLD_ROWS, _expected_raws(OLD_ROWS, expected_mem))
        ]
        assert shape == expected_shape, (shape, expected_shape)
        return None

    _run(base, body)


# ===========================================================================
# R-A2L-REFRESH.045 — project pair publishes the final pair once (3/3).
# ===========================================================================


@pytest.mark.parametrize(
    "arm",
    ["empty-pair", "outgoing-pair", "empty-nomac"],
    ids=[f"R-A2L-REFRESH.045/{i}" for i in range(1, 4)],
)
def test_r045_project_final_publication(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str) -> None:
    """R-A2L-REFRESH.045/1-/3: exactly 1 final F after the final
    image+MAC+A2L (or image+A2L) install and project identity, before
    OUTCOME; 0 reset/image-stage publications; no MAC fabricated."""
    _guard_project_route()

    base = tmp_path / "app"
    src = tmp_path / "src"
    src.mkdir(parents=True)
    old = _old_a2l(src / "old.a2l")
    new = _new_a2l(src / "new.a2l")
    img1 = _write_image(src / "img1.s19", dict(IMG1))
    img2 = _write_image(src / "img2.s19", dict(IMG2))
    mac = _write_mac(src / "records.mac")

    async def body(app, pilot):
        main = threading.get_ident()
        _mount_views(app)
        await pilot.pause()
        if arm == "outgoing-pair":
            _seed_project3(app.workarea, "proj_a", a2l=old, image=img1, mac=mac)
            await _load_project(app, pilot, "proj_a")
            await settle_workers(pilot)
            a0, i0 = app._a2l_view_generation, app._image_generation
            _seed_project3(app.workarea, "proj_b", a2l=new, image=img2, mac=mac)
            events: list = []
            producer = ProducerSpy(monkeypatch)
            _arm_timeline(app, monkeypatch, events)
            zero = _arm_zero_spies(app, monkeypatch)
            await _load_project(app, pilot, "proj_b")
            final_rows = NEW_ROWS
            final_mem = dict(IMG2)
            pre_names = tuple(name for name, *_ in OLD_ROWS)
            final_gens = (a0 + 3, i0 + 2)
            producer_pair = (a0 + 3, i0 + 2)
            installs = 2
            await settle_workers(pilot)
            assert len(zero["_reset_project_session"]) == 1, zero
            assert len(zero["_refresh_a2l_dependent_views"]) == 1, zero
            assert len(zero["_apply_prepared_load"]) == 2, zero
            macs = app.current_file.mac_records if app.current_file else []
        elif arm == "empty-nomac":
            a0, i0 = app._a2l_view_generation, app._image_generation
            assert (a0, i0) == (0, 0)
            _seed_project3(app.workarea, "proj_a", a2l=old, image=img1)
            events: list = []
            producer = ProducerSpy(monkeypatch)
            _arm_timeline(app, monkeypatch, events)
            zero = _arm_zero_spies(app, monkeypatch)
            await _load_project(app, pilot, "proj_a")
            final_rows = OLD_ROWS
            final_mem = dict(IMG1)
            pre_names = ()
            final_gens = (2, 1)
            producer_pair = (2, 1)
            installs = 1
            await settle_workers(pilot)
            assert len(zero["_reset_project_session"]) == 1, zero
            assert len(zero["_refresh_a2l_dependent_views"]) == 1, zero
            assert len(zero["_apply_prepared_load"]) == 1, zero
            macs = app.current_file.mac_records if app.current_file else []
            assert not macs and (app.current_file is None or app.current_file.mac_path is None)
        else:  # empty-pair
            a0, i0 = app._a2l_view_generation, app._image_generation
            assert (a0, i0) == (0, 0)
            _seed_project3(app.workarea, "proj_a", a2l=old, image=img1, mac=mac)
            events: list = []
            producer = ProducerSpy(monkeypatch)
            _arm_timeline(app, monkeypatch, events)
            zero = _arm_zero_spies(app, monkeypatch)
            await _load_project(app, pilot, "proj_a")
            final_rows = OLD_ROWS
            final_mem = dict(IMG1)
            pre_names = ()
            final_gens = (3, 2)
            producer_pair = (3, 2)
            installs = 2
            await settle_workers(pilot)
            assert len(zero["_reset_project_session"]) == 1, zero
            assert len(zero["_refresh_a2l_dependent_views"]) == 1, zero
            assert len(zero["_apply_prepared_load"]) == 2, zero
            macs = app.current_file.mac_records if app.current_file else []
            assert macs, "the final pair misses the MAC"
        await wait_until(pilot, lambda: any(e[0] == "OUTCOME" for e in events), "the project outcome", timeout=30.0)
        assert len(producer.calls) == 1, producer.calls
        call = producer.calls[0]
        assert call.thread != main, "the producer ran on the UI thread"
        assert (
            call.kwargs["expected_a2l_generation"],
            call.kwargs["expected_image_generation"],
        ) == producer_pair, call.kwargs
        kind = [e[0] for e in events if e[0] in {"install", "F", "OUTCOME"}]
        assert kind == ["install"] * installs + ["F", "OUTCOME"], events
        fs = [e for e in events if e[0] == "F"]
        assert len(fs) == 1, events
        assert fs[0][2] == pre_names, fs  # nothing painted before the final F
        assert fs[0][3] == tuple(name for name, *_ in final_rows), fs
        outcomes = [e for e in events if e[0] == "OUTCOME"]
        assert len(outcomes) == 1, outcomes
        assert outcomes[0][3] not in (SUPERSEDED_OUTCOME,) and not outcomes[0][3].startswith(
            "Project NOT loaded"
        ), outcomes
        assert app.current_project in {"proj_a", "proj_b"}
        assert app.current_file is not None and app.current_file.mem_map == final_mem
        assert (app._a2l_view_generation, app._image_generation) == final_gens
        assert _a2l_viewer_names(app) == [name for name, *_ in final_rows]
        return None

    _run(base, body)


# ===========================================================================
# R-A2L-REFRESH.046 — A2L-only project publishes once, no phantom state (2/2).
# ===========================================================================


@pytest.mark.parametrize(
    "arm",
    ["empty-a2l-only", "outgoing-image-a2l"],
    ids=[f"R-A2L-REFRESH.046/{i}" for i in range(1, 3)],
)
def test_r046_a2l_only_final_publication(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str) -> None:
    """R-A2L-REFRESH.046/1-/2: exactly 1 prepared A2L-only F before OUTCOME;
    A2L generation +2, image generation unchanged, no current_file, image
    or MAC fabricated, no reset publication."""
    _guard_project_route()

    base = tmp_path / "app"
    src = tmp_path / "src"
    src.mkdir(parents=True)
    old = _old_a2l(src / "old.a2l")
    new = _new_a2l(src / "new.a2l")
    img1 = _write_image(src / "img1.s19", dict(IMG1))

    async def body(app, pilot):
        _mount_views(app)
        await pilot.pause()
        if arm == "outgoing-image-a2l":
            await _load_image(app, pilot, img1)
            await _typed_attach(app, pilot, old)
            i0 = app._image_generation
            a0 = app._a2l_view_generation
            _seed_project3(app.workarea, "proj_a", a2l=new)
        else:
            a0, i0 = app._a2l_view_generation, app._image_generation
            assert (a0, i0) == (0, 0)
            _seed_project3(app.workarea, "proj_a", a2l=new)
        events: list = []
        producer = ProducerSpy(monkeypatch)
        _arm_timeline(app, monkeypatch, events)
        zero = _arm_zero_spies(app, monkeypatch)
        await _load_project(app, pilot, "proj_a")
        await settle_workers(pilot)
        await wait_until(pilot, lambda: any(e[0] == "OUTCOME" for e in events), "the project outcome", timeout=30.0)
        assert len(producer.calls) == 1, producer.calls
        call = producer.calls[0]
        assert call.thread != threading.get_ident(), "the producer ran on the UI thread"
        assert (
            call.kwargs["expected_a2l_generation"],
            call.kwargs["expected_image_generation"],
        ) == (a0 + 2, i0), call.kwargs
        assert call.kwargs["image_mem_map"] is None, call.kwargs
        kind = [e[0] for e in events if e[0] in {"install", "F", "OUTCOME"}]
        assert kind == ["F", "OUTCOME"], events
        fs = [e for e in events if e[0] == "F"]
        assert len(fs) == 1, events
        assert fs[0][3] == tuple(name for name, *_ in NEW_ROWS), fs
        outcomes = [e for e in events if e[0] == "OUTCOME"]
        assert len(outcomes) == 1 and not outcomes[0][3].startswith("Project NOT loaded"), outcomes
        assert len(zero["_apply_prepared_load"]) == 0, zero
        assert len(zero["_reset_project_session"]) == 1, zero
        assert app.current_project == "proj_a"
        assert app.current_file is None, "a phantom LoadedFile/image/MAC appeared"
        assert app._a2l_view_generation == a0 + 2
        assert app._image_generation == i0
        assert app.current_a2l_path is not None and app.current_a2l_path.name == "new.a2l"
        assert _a2l_viewer_names(app) == [name for name, *_ in NEW_ROWS]
        _assert_panel_state(_check_panel(app), NEW_ROWS)
        _assert_panel_state(_patch_panel(app), NEW_ROWS)
        snap_map = _accepted_snapshots(app)
        assert snap_map is not None and set(snap_map) == {"check", "patch"}, snap_map
        return None

    _run(base, body)


# ===========================================================================
# R-A2L-REFRESH.047 — same-path changed-content reload (6/6).
# ===========================================================================


@pytest.mark.parametrize(
    "arm",
    ["loose-image", "pair-a2l", "pair-image", "only-a2l", "nomac-a2l", "nomac-image"],
    ids=[f"R-A2L-REFRESH.047/{i}" for i in range(1, 7)],
)
def test_r047_same_path_changed_content(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str) -> None:
    """R-A2L-REFRESH.047/1-/6: an equal-size, same-path byte change with no
    clear publishes the NEW content under a strictly newer generation of
    the changed artifact; unchanged source bytes stay byte-identical while
    writer/reset stages move its generation per the stage matrix; no OLD
    marker survives and the final publication is singular."""
    _guard_inc3_interface()

    base = tmp_path / "app"
    src = tmp_path / "src"
    src.mkdir(parents=True)
    old_pair = _pair_a2l(src / "pair_old.a2l", "OLD")
    new_pair = _pair_a2l(src / "pair_new.a2l", "NEW")
    assert old_pair.stat().st_size == new_pair.stat().st_size, "fixture: equal-size A2L pair required"
    assert {t["name"] for t in parse_a2l_file(old_pair)["tags"]} == {"OLD_TAG_A", "OLD_TAG_B"}
    assert {t["name"] for t in parse_a2l_file(new_pair)["tags"]} == {"NEW_TAG_A", "NEW_TAG_B"}
    def emit(mem) -> bytes:
        return emit_s19_from_mem_map(dict(mem), [(min(mem), max(mem) + 1)]).encode("ascii")

    # Every equal-size arm's image fixture is written with the SAME raw-LF
    # emitter in both writes: the reused write_text-based _write_image lands
    # CRLF (42 B) on Windows while the arms' in-place overwrites are raw LF
    # (39 B), which made the equal-size pair unsatisfiable (E4 correction).
    img1 = _write_image(src / "img1.s19", dict(IMG1))
    img2 = _write_image(src / "img2.s19", dict(IMG2))
    img1.write_bytes(emit(IMG1))
    img2.write_bytes(emit(IMG2))
    assert img1.stat().st_size == img2.stat().st_size, "fixture: equal-size image pair required"
    mac = _write_mac(src / "records.mac")

    async def body(app, pilot):
        _mount_views(app)
        await pilot.pause()
        if arm == "loose-image":
            attach = _old_a2l(src / "att.a2l")
            same = src / "image.s19"
            same.write_bytes(emit(IMG1))
            await _typed_attach(app, pilot, attach)
            await _load_image(app, pilot, same)
            await settle_workers(pilot)
            a0, i0 = app._a2l_view_generation, app._image_generation
            size_before = same.stat().st_size
            same.write_bytes(emit(IMG2))
            assert same.stat().st_size == size_before, "fixture: equal-size pair required"
            events: list = []
            producer = ProducerSpy(monkeypatch)
            _arm_timeline(app, monkeypatch, events)
            await _load_image(app, pilot, same)
            await settle_workers(pilot)
            await wait_until(pilot, lambda: any(e[0] == "OUTCOME" for e in events), "the image outcome", timeout=30.0)
            assert len(producer.calls) == 1, producer.calls
            call = producer.calls[0]
            assert (
                call.kwargs["expected_a2l_generation"],
                call.kwargs["expected_image_generation"],
            ) == (a0 + 1, i0 + 1), call.kwargs
            assert len([e for e in events if e[0] == "F"]) == 1, events
            outcomes = [e for e in events if e[0] == "OUTCOME"]
            assert len(outcomes) == 1 and outcomes[0][3].startswith("Loaded "), outcomes
            assert app.current_file is not None and app.current_file.mem_map == dict(IMG2)
            assert app._image_generation == i0 + 1 > i0
            assert app._a2l_view_generation == a0 + 1
            assert _parsed_without_path(app.current_a2l_data) == _parsed_without_path(
                parse_a2l_file(attach)
            ), "unchanged A2L bytes must stay identical"
            tag = next(t for t in app._a2l_enriched_tags if t["name"] == "OLD_SCALAR")
            assert tag.get("raw_value") == 0x8070, tag
        elif arm == "pair-a2l":
            folder = _seed_project3(app.workarea, "proj_a", a2l=old_pair, image=img1, mac=mac)
            await _load_project(app, pilot, "proj_a")
            await settle_workers(pilot)
            a0, i0 = app._a2l_view_generation, app._image_generation
            image_digest = _digest_file(folder / img1.name)
            (folder / "pair_old.a2l").write_bytes(new_pair.read_bytes())
            assert (folder / "pair_old.a2l").stat().st_size == old_pair.stat().st_size
            events: list = []
            producer = ProducerSpy(monkeypatch)
            _arm_timeline(app, monkeypatch, events)
            await _load_project(app, pilot, "proj_a")
            await settle_workers(pilot)
            assert len(producer.calls) == 1, producer.calls
            call = producer.calls[0]
            assert (
                call.kwargs["expected_a2l_generation"],
                call.kwargs["expected_image_generation"],
            ) == (a0 + 3, i0 + 2), call.kwargs
            assert len([e for e in events if e[0] == "F"]) == 1, events
            assert app.current_file is not None and app.current_file.mem_map == dict(IMG1)
            assert _digest_file(folder / img1.name) == image_digest, "unchanged image bytes must stay identical"
            assert app._a2l_view_generation == a0 + 3 > a0
            assert app._image_generation == i0 + 2
            assert _parsed_without_path(app.current_a2l_data) == _parsed_without_path(
                parse_a2l_file(new_pair)
            )
            names = set(_a2l_viewer_names(app))
            assert names == {"NEW_TAG_A", "NEW_TAG_B"}, names
            assert "OLD_TAG_A" not in names and "OLD_TAG_B" not in names
        elif arm == "pair-image":
            folder = _seed_project3(app.workarea, "proj_a", a2l=old_pair, image=img1, mac=mac)
            await _load_project(app, pilot, "proj_a")
            await settle_workers(pilot)
            a0, i0 = app._a2l_view_generation, app._image_generation
            (folder / img1.name).write_bytes(emit(IMG2))
            assert (folder / img1.name).stat().st_size == img1.stat().st_size
            events: list = []
            producer = ProducerSpy(monkeypatch)
            _arm_timeline(app, monkeypatch, events)
            await _load_project(app, pilot, "proj_a")
            await settle_workers(pilot)
            assert len(producer.calls) == 1, producer.calls
            call = producer.calls[0]
            assert (
                call.kwargs["expected_a2l_generation"],
                call.kwargs["expected_image_generation"],
            ) == (a0 + 3, i0 + 2), call.kwargs
            assert len([e for e in events if e[0] == "F"]) == 1, events
            assert app.current_file is not None and app.current_file.mem_map == dict(IMG2)
            assert app._image_generation == i0 + 2 > i0
            assert app._a2l_view_generation == a0 + 3
            assert _parsed_without_path(app.current_a2l_data) == _parsed_without_path(
                parse_a2l_file(old_pair)
            ), "unchanged A2L bytes must stay identical"
            tag = next(t for t in app._a2l_enriched_tags if t["name"] == "OLD_TAG_A")
            assert tag.get("in_memory") is False or tag.get("raw_value") is not None
            assert _a2l_viewer_names(app)
        elif arm == "only-a2l":
            folder = _seed_project3(app.workarea, "proj_a", a2l=old_pair)
            await _load_project(app, pilot, "proj_a")
            await settle_workers(pilot)
            a0, i0 = app._a2l_view_generation, app._image_generation
            (folder / "pair_old.a2l").write_bytes(new_pair.read_bytes())
            events: list = []
            producer = ProducerSpy(monkeypatch)
            _arm_timeline(app, monkeypatch, events)
            await _load_project(app, pilot, "proj_a")
            await settle_workers(pilot)
            assert len(producer.calls) == 1, producer.calls
            call = producer.calls[0]
            assert (
                call.kwargs["expected_a2l_generation"],
                call.kwargs["expected_image_generation"],
            ) == (a0 + 2, i0), call.kwargs
            assert call.kwargs["image_mem_map"] is None, call.kwargs
            assert len([e for e in events if e[0] == "F"]) == 1, events
            assert app.current_file is None, "no image/MAC/current_file may be fabricated"
            assert app._a2l_view_generation == a0 + 2 > a0
            assert app._image_generation == i0
            assert _parsed_without_path(app.current_a2l_data) == _parsed_without_path(
                parse_a2l_file(new_pair)
            )
            names = set(_a2l_viewer_names(app))
            assert names == {"NEW_TAG_A", "NEW_TAG_B"}, names
            assert "OLD_TAG_A" not in names
        elif arm == "nomac-a2l":
            folder = _seed_project3(app.workarea, "proj_a", a2l=old_pair, image=img1)
            await _load_project(app, pilot, "proj_a")
            await settle_workers(pilot)
            a0, i0 = app._a2l_view_generation, app._image_generation
            image_digest = _digest_file(folder / img1.name)
            (folder / "pair_old.a2l").write_bytes(new_pair.read_bytes())
            events: list = []
            producer = ProducerSpy(monkeypatch)
            _arm_timeline(app, monkeypatch, events)
            await _load_project(app, pilot, "proj_a")
            await settle_workers(pilot)
            assert len(producer.calls) == 1, producer.calls
            call = producer.calls[0]
            assert (
                call.kwargs["expected_a2l_generation"],
                call.kwargs["expected_image_generation"],
            ) == (a0 + 2, i0 + 1), call.kwargs
            assert len([e for e in events if e[0] == "F"]) == 1, events
            assert app.current_file is not None and app.current_file.mem_map == dict(IMG1)
            assert _digest_file(folder / img1.name) == image_digest, "unchanged image bytes must stay identical"
            assert not app.current_file.mac_records and app.current_file.mac_path is None
            assert app._a2l_view_generation == a0 + 2 > a0
            assert app._image_generation == i0 + 1
            assert _parsed_without_path(app.current_a2l_data) == _parsed_without_path(
                parse_a2l_file(new_pair)
            )
            names = set(_a2l_viewer_names(app))
            assert names == {"NEW_TAG_A", "NEW_TAG_B"}, names
            assert "OLD_TAG_A" not in names
        else:  # nomac-image
            folder = _seed_project3(app.workarea, "proj_a", a2l=old_pair, image=img1)
            await _load_project(app, pilot, "proj_a")
            await settle_workers(pilot)
            a0, i0 = app._a2l_view_generation, app._image_generation
            (folder / img1.name).write_bytes(emit(IMG2))
            events: list = []
            producer = ProducerSpy(monkeypatch)
            _arm_timeline(app, monkeypatch, events)
            await _load_project(app, pilot, "proj_a")
            await settle_workers(pilot)
            assert len(producer.calls) == 1, producer.calls
            call = producer.calls[0]
            assert (
                call.kwargs["expected_a2l_generation"],
                call.kwargs["expected_image_generation"],
            ) == (a0 + 2, i0 + 1), call.kwargs
            assert len([e for e in events if e[0] == "F"]) == 1, events
            assert app.current_file is not None and app.current_file.mem_map == dict(IMG2)
            assert not app.current_file.mac_records and app.current_file.mac_path is None
            assert app._image_generation == i0 + 1 > i0
            assert app._a2l_view_generation == a0 + 2
            assert _parsed_without_path(app.current_a2l_data) == _parsed_without_path(
                parse_a2l_file(old_pair)
            ), "unchanged A2L bytes must stay identical"
        return None

    _run(base, body)


# ===========================================================================
# R-A2L-REFRESH.048 — whole-load stale-snapshot discard (12/12).
# ===========================================================================


@pytest.mark.parametrize(
    "arm",
    [
        "image-stale-a2l",
        "image-stale-image",
        "pair-mac-stale-a2l",
        "pair-mac-stale-image",
        "only-stale-a2l",
        "only-live-image",
        "pair-keyless-a2l",
        "pair-keyless-image",
        "pair-live-a2l",
        "pair-live-image",
        "nomac-stale-a2l",
        "nomac-stale-image",
    ],
    ids=[f"R-A2L-REFRESH.048/{i}" for i in range(1, 13)],
)
def test_r048_stale_snapshot_discard(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str) -> None:
    """R-A2L-REFRESH.048/1-/12: a candidate whose expected pair differs from
    the stage requirement is discarded whole before any candidate cache,
    session, widget, project, reset or publication mutation; the exact
    REFRESH.028 superseded outcome remains binding."""
    _guard_inc3_interface()

    base = tmp_path / "app"
    src = tmp_path / "src"
    src.mkdir(parents=True)
    old = _old_a2l(src / "old.a2l")
    img1 = _write_image(src / "img1.s19", dict(IMG1))
    img2 = _write_image(src / "img2.s19", dict(IMG2))
    mac = _write_mac(src / "records.mac")

    async def body(app, pilot):
        _mount_views(app)
        await pilot.pause()
        zero: dict = {}
        outcomes: list = []
        widget_calls: list = []
        if arm.startswith("image-"):
            await _load_image(app, pilot, img1)
            await _typed_attach(app, pilot, old)
            before = _state_snapshot(app)
            if arm == "image-stale-a2l":
                _arm_stale_producer(monkeypatch, a2l_delta=-1)
            else:
                _arm_stale_producer(monkeypatch, image_delta=-1)
            zero = _arm_zero_spies(app, monkeypatch)
            _arm_outcomes(app, monkeypatch, outcomes)
            widget_calls = _arm_thread_spies(app, monkeypatch)
            await _drive_typed_no_assert(app, pilot, img2)
            await settle_workers(pilot)
            await wait_until(pilot, lambda: bool(outcomes), "the superseded outcome", timeout=30.0)
            assert outcomes == [("file_load", SUPERSEDED_OUTCOME)], outcomes
            assert len(zero["_apply_prepared_load"]) == 1, zero  # called once, rejected inside
            assert len(zero["_store_a2l_cache"]) == 0, zero
            assert len(zero["_refresh_a2l_dependent_views"]) == 0
            assert len(zero["_sync_loaded_file_to_project"]) == 0
            assert widget_calls == [], widget_calls
            assert _state_snapshot(app) == before
            assert app.current_file is not None and app.current_file.mem_map == dict(IMG1)
            assert not any(e[1].startswith("Loaded ") for e in outcomes)
        else:
            started = None
            release = None
            if arm in ("pair-mac-stale-a2l", "pair-mac-stale-image"):
                folder = _seed_project3(app.workarea, "proj_a", a2l=old, image=img1, mac=mac)
                if arm.endswith("stale-a2l"):
                    _arm_stale_producer(monkeypatch, a2l_delta=-1)
                else:
                    _arm_stale_producer(monkeypatch, image_delta=-1)
            elif arm in ("only-stale-a2l", "only-live-image"):
                folder = _seed_project3(app.workarea, "proj_a", a2l=old)
                if arm == "only-stale-a2l":
                    _arm_stale_producer(monkeypatch, a2l_delta=-1)
                else:
                    dispatches: list = []
                    started, release = _arm_dispatch_gate(
                        app,
                        monkeypatch,
                        lambda cb: getattr(cb, "__name__", "") == "_on_project_loaded",
                        dispatches,
                    )
            elif arm in ("pair-keyless-a2l", "pair-keyless-image"):
                folder = _seed_project3(app.workarea, "proj_a", a2l=old, image=img1, mac=mac)
                if arm == "pair-keyless-a2l":
                    _arm_keyless_stale(monkeypatch, a2l=True)
                else:
                    _arm_keyless_stale(monkeypatch, image=True)
            elif arm in ("nomac-stale-a2l", "nomac-stale-image"):
                folder = _seed_project3(app.workarea, "proj_a", a2l=old, image=img1)
                if arm.endswith("stale-a2l"):
                    _arm_stale_producer(monkeypatch, a2l_delta=-1)
                else:
                    _arm_stale_producer(monkeypatch, image_delta=-1)
            else:  # pair-live-a2l / pair-live-image
                folder = _seed_project3(app.workarea, "proj_a", a2l=old, image=img1, mac=mac)
                dispatches: list = []
                started, release = _arm_dispatch_gate(
                    app, monkeypatch, lambda cb: getattr(cb, "__name__", "") == "_on_project_loaded", dispatches
                )
            digests = _project_digests(folder)
            before = _state3(app)
            zero = _arm_zero_spies(app, monkeypatch)
            _arm_outcomes(app, monkeypatch, outcomes)
            widget_calls = _arm_thread_spies(app, monkeypatch)
            await _drive_project_load(app, pilot, "proj_a")
            if arm in ("pair-live-a2l", "pair-live-image", "only-live-image"):
                assert started is not None and release is not None
                await wait_until(pilot, started.is_set, "the worker-to-UI dispatch", timeout=30.0)
                if arm == "pair-live-image":
                    app._image_generation += 1
                elif arm == "only-live-image":
                    app._image_generation += 1
                else:
                    app._a2l_view_generation += 1
                release.set()
            await settle_workers(pilot)
            await wait_until(pilot, lambda: bool(outcomes), "the superseded outcome", timeout=30.0)
            assert outcomes == [("project_load", SUPERSEDED_OUTCOME)], outcomes
            assert len(zero["_reset_project_session"]) == 0, zero
            assert len(zero["_apply_prepared_load"]) == 0, zero
            assert len(zero["_refresh_a2l_dependent_views"]) == 0
            assert len(zero["_store_a2l_cache"]) == 0
            assert len(zero["_replace_current_a2l"]) == 0
            assert widget_calls == [], widget_calls
            assert _state3(app) == before
            assert _project_digests(folder) == digests
            assert not any(e[1].startswith("Loaded ") for e in outcomes)
        return None

    _run(base, body)


# ===========================================================================
# R-A2L-REFRESH.040/.041 — the load workers are admitted with a fixed
# description, so Textual never renders the request on the UI thread.
# ===========================================================================


@pytest.mark.parametrize(
    "arm",
    ["image", "project"],
    ids=["R-A2L-REFRESH.040/2", "R-A2L-REFRESH.041/3"],
)
def test_r_a2l_refresh_040_load_workers_never_repr_their_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str
) -> None:
    """R-A2L-REFRESH.040/.041 (E4R): the image+A2L and project load workers
    carry a fixed ``description=``, so Textual never calls ``repr()`` on the
    request (which carries the parsed A2L) on the UI thread at admission.
    ``__repr__`` of the three request classes is replaced with a counting
    recorder and must stay untouched through the load's success outcome."""
    _guard_inc3_interface()

    base = tmp_path / "app"
    src = tmp_path / "src"
    src.mkdir(parents=True)
    old = _old_a2l(src / "old.a2l")
    img1 = _write_image(src / "img1.s19", dict(IMG1))
    img2 = _write_image(src / "img2.s19", dict(IMG2))

    rendered: list = []
    outcomes: list = []

    def counting_repr(self) -> str:
        rendered.append(type(self).__name__)
        return "<request>"

    def _arm_repr_spies() -> None:
        fl = _fl_module()
        pl = _pl_module()
        for cls in (
            getattr(fl, "FileLoadRequest"),
            getattr(fl, "A2LAttachRequest"),
            getattr(pl, "ProjectLoadRequest"),
        ):
            monkeypatch.setattr(cls, "__repr__", counting_repr)

    async def body(app, pilot):
        _mount_views(app)
        await pilot.pause()
        if arm == "image":
            await _load_image(app, pilot, img1)
            await _typed_attach(app, pilot, old)
            _arm_repr_spies()
            rendered.clear()
            _arm_outcomes(app, monkeypatch, outcomes)
            await _drive_typed_no_assert(app, pilot, img2)
            await settle_workers(pilot)
            await wait_until(
                pilot,
                lambda: any(key == "file_load" for key, _ in outcomes),
                "the image success outcome",
                timeout=30.0,
            )
            assert any(
                key == "file_load" and str(outcome).startswith("Loaded ")
                for key, outcome in outcomes
            ), outcomes
        else:
            _seed_project3(app.workarea, "proj_a", a2l=old, image=img1)
            _arm_repr_spies()
            rendered.clear()
            await _load_project(app, pilot, "proj_a")
            await settle_workers(pilot)
            assert app.current_project == "proj_a", list(app.log_lines)
        return None

    _run(base, body)
    assert rendered == [], (
        f"R-A2L-REFRESH.040/.041: the {arm} load worker admission rendered "
        f"its request: {rendered}"
    )


# ===========================================================================
# R-A2L-REFRESH.050/.051 — project worker GC: disabled at entry, no worker
# collection, every outcome re-enables.
# ===========================================================================


def test_r_a2l_refresh_050_project_worker_runs_no_collection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R-A2L-REFRESH.050 (E4R) / D-13: the project worker disables the cycle
    collector at entry, so no collection runs on the worker thread while it
    parses and prepares; the install's one deliberate collection runs on the
    main thread and is allowed. A ``gc.callbacks`` hook records the thread
    name of every ``start`` phase between the load submit and its outcome."""
    import gc

    _guard_project_route()

    base = tmp_path / "app"
    src = tmp_path / "src"
    src.mkdir(parents=True)
    a2l = _mid_a2l(src, count=2000)
    img1 = _write_image(src / "img1.s19", dict(IMG1))

    collection_threads: list = []

    def on_collect(phase: str, info: dict) -> None:
        if phase == "start":
            collection_threads.append(threading.current_thread().name)

    gc.callbacks.append(on_collect)
    try:

        async def body(app, pilot):
            _mount_views(app)
            await pilot.pause()
            main_name = threading.current_thread().name
            _seed_project3(app.workarea, "proj_a", a2l=a2l, image=img1)
            collection_threads.clear()
            await _load_project(app, pilot, "proj_a")
            await settle_workers(pilot)
            assert app.current_project == "proj_a", list(app.log_lines)
            assert all(name == main_name for name in collection_threads), (
                "R-A2L-REFRESH.050: a collection ran off the main thread "
                f"during the project load: {collection_threads}"
            )
            return None

        _run(base, body)
    finally:
        gc.callbacks.remove(on_collect)


@pytest.mark.parametrize(
    "arm",
    ["refusal", "worker-failure", "superseded"],
    ids=[f"R-A2L-REFRESH.051/{i}" for i in range(4, 7)],
)
def test_r_a2l_refresh_051_project_outcomes_gc_enabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arm: str
) -> None:
    """R-A2L-REFRESH.051/4-/6 (E4R): after a project load ends with a
    refusal, a worker failure or a superseded discard, the cycle collector
    is enabled — the worker disabled it at entry and every outcome
    re-enables it."""
    import gc

    _guard_project_route()

    base = tmp_path / "app"
    src = tmp_path / "src"
    src.mkdir(parents=True)
    old = _old_a2l(src / "old.a2l")
    img1 = _write_image(src / "img1.s19", dict(IMG1))

    outcomes: list = []
    gc_at_end: list = []

    async def body(app, pilot):
        _mount_views(app)
        await pilot.pause()
        _arm_outcomes(app, monkeypatch, outcomes)
        if arm == "refusal":
            _seed_project3(app.workarea, "proj_a", a2l=old)
            pl = _pl_module()

            def bad_a2l(*args, **kwargs):
                raise ValueError("synthetic A2L")

            monkeypatch.setattr(pl.deps, "parse_a2l_file", bad_a2l, raising=False)
            await _drive_project_load(app, pilot, "proj_a")
            await settle_workers(pilot)
            await wait_until(pilot, lambda: bool(outcomes), "the refusal outcome", timeout=30.0)
        elif arm == "worker-failure":
            _seed_project3(app.workarea, "proj_a", a2l=old, image=img1)

            def boom(self_, request):
                raise ValueError("worker boom")

            monkeypatch.setattr(app, "_prepare_project_load", boom)
            await _drive_project_load(app, pilot, "proj_a")
            await settle_workers(pilot)
            await wait_until(pilot, lambda: bool(outcomes), "the worker-failure outcome", timeout=30.0)
        else:  # superseded
            _seed_project3(app.workarea, "proj_a", a2l=old, image=img1)
            _arm_stale_producer(monkeypatch, a2l_delta=1)
            await _drive_project_load(app, pilot, "proj_a")
            await settle_workers(pilot)
            await wait_until(pilot, lambda: bool(outcomes), "the superseded outcome", timeout=30.0)
        gc_at_end.append(gc.isenabled())
        return None

    _run(base, body)
    assert gc_at_end == [True], (
        f"R-A2L-REFRESH.051: gc disabled after the {arm} project outcome: {gc_at_end}"
    )
