"""Scratch pytest probe (Inc 9b E4, item 3): the key -> job-start gap, measured in the REAL app.

One test function per process. The external runner picks the scenario with
``Q9B_SCENARIO`` (``a``, ``b``, ``c-press``, ``c-post``, ``d``) and labels the run with
``Q9B_RUN``, then runs this file 10 times per scenario. The test drives the shipped
``S19TuiApp`` under the existing ``run``/``run_test`` helper (never the prototype driver),
stamps ``time.perf_counter()`` at the seven points of the path in E1-slice.md section 5,
and prints exactly one machine-readable line::

    Q9BGAP {json}

with per-event timestamps relative to the key event and the absolute ``os.getloadavg()``.
It asserts the seven required markers are present so an empty trace cannot pass. The
``Q9BGAP`` line is printed on success and failure, with partial markers, missing markers,
and any error, before the error is re-raised. It does not decide causes or timing verdicts.

Assumptions / probe choices (all measurement-side, no product behaviour changed):
  * The target row is ``LARGE`` and the measured key is the arrow key that selects it
    from the row above/below; the key is computed from ``sheet.rows`` at run time.
  * "immediately after ``_active_job`` is set" is stamped at the entry of the ``_run_job``
    scheduling call, which ``_start_next`` makes as its next statement after the
    assignment (one ``generation = self.generation`` read in between).
  * "first compositor paint that actually contains the busy cue" is the first
    ``Compositor.render_update`` after the LARGE decode enqueue whose rendered segments
    contain ``"BUSY · decode LARGE ·"``; a stale SMALL_BLK cue cannot satisfy it. The cue
    keys on the ask, so in scenario ``b`` it appears while the queue is still gated.
  * Scenario ``b`` holds the gate for ``GATE_HOLD_AFTER_KEY_S`` after the key, then stamps
    its release and SMALL_BLK's summary completion at ``_job_done`` entry so the artificial
    hold is separable from K2; the LARGE worker starts before the trace is printed.
  * Scenario ``d`` records every ``gc.callbacks`` ``start``/``stop`` pass for the whole
    body (before and after the key) so a deselect-time GC (K6) is visible as negative dt.
"""
from __future__ import annotations

import gc
import json
import os
import threading
import time

from textual import events, work

from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens_directionb.patch_editor import bench_sheet as bs
from s19_app.tui.screens_directionb.patch_editor import sheet as sh
from tests.support.b103_inc9_w import (  # noqa: F401  (defc_dir is a fixture used by name)
    BODY,
    LARGE_COUNT,
    Gate,
    big_case,
    defc_dir,
    has_values,
    pick,
    run,
    sheet_of,
    wait_for,
)

LARGE = "LARGE"
SMALL = "SMALL_BLK"

SCENARIO = os.environ.get("Q9B_SCENARIO", "a")
RUN_LABEL = os.environ.get("Q9B_RUN", "")

GATE_HOLD_AFTER_KEY_S = 1.0

REQUIRED = (
    "key",
    "action_move",
    "selection_changed",
    "enqueue_decode",
    "active_job",
    "run_job",
    "paint_busy",
)


def loadavg() -> list:
    get = getattr(os, "getloadavg", None)
    if get is None:
        return [0.0, 0.0, 0.0]
    return [float(x) for x in get()]


class Probe:
    """Thread-safe event recorder. Timestamps are ``time.perf_counter()``."""

    def __init__(self) -> None:
        self.armed = False
        self.key = None
        self.events = []
        self.markers = set()
        self._lock = threading.Lock()

    def arm(self, key: str) -> None:
        self.key = key
        self.armed = True

    def stamp(self, marker: str, *, force: bool = False, **extra) -> None:
        if not self.armed and not force:
            return
        with self._lock:
            ev = {"m": marker, "t": time.perf_counter()}
            ev.update(extra)
            self.events.append(ev)
            self.markers.add(marker)

    def has(self, marker: str) -> bool:
        with self._lock:
            return marker in self.markers

    def event_time(self, marker: str):
        with self._lock:
            for ev in self.events:
                if ev["m"] == marker:
                    return ev["t"]
        return None


def install_class_wrappers(probe: Probe, monkeypatch) -> None:
    """Monkeypatch/wrapper hooks on the product classes; pytest restores them."""

    app_on_event = S19TuiApp.on_event

    async def on_event_wrapper(self, event):
        if (
            probe.armed
            and not probe.has("key")
            and isinstance(event, events.Key)
            and event.key == probe.key
        ):
            probe.stamp("key", key=event.key)
        return await app_on_event(self, event)

    monkeypatch.setattr(S19TuiApp, "on_event", on_event_wrapper)

    action_move = sh.StagingSheet.action_move

    def action_move_wrapper(self, delta):
        if probe.armed and probe.has("key") and not probe.has("action_move"):
            probe.stamp("action_move", delta=delta)
        return action_move(self, delta)

    monkeypatch.setattr(sh.StagingSheet, "action_move", action_move_wrapper)

    selection_changed = bs.ArrayBenchSheet.on_staging_sheet_selection_changed

    def selection_changed_wrapper(self, event):
        if (
            probe.armed
            and probe.has("key")
            and getattr(event, "name", None) == LARGE
            and not probe.has("selection_changed")
        ):
            probe.stamp("selection_changed", name=event.name)
        return selection_changed(self, event)

    monkeypatch.setattr(
        bs.ArrayBenchSheet, "on_staging_sheet_selection_changed", selection_changed_wrapper
    )

    enqueue = bs.ArrayBenchSheet._enqueue

    def enqueue_wrapper(self, kind, name, edit=None):
        if (
            probe.armed
            and probe.has("key")
            and kind == "decode"
            and name == LARGE
            and not probe.has("enqueue_decode")
        ):
            probe.stamp("enqueue_decode", kind=kind, name=name)
        return enqueue(self, kind, name, edit)

    monkeypatch.setattr(bs.ArrayBenchSheet, "_enqueue", enqueue_wrapper)

    original_factory = bs.ArrayBenchSheet._run_job
    original_inner = getattr(original_factory, "__wrapped__", None)
    assert original_inner is not None, "_run_job lost its __wrapped__"

    def traced_inner(self, kind, name, generation, definition, snapshot, edit):
        if (
            probe.armed
            and probe.has("key")
            and kind == "decode"
            and name == LARGE
            and not probe.has("run_job")
        ):
            probe.stamp("run_job", kind=kind, name=name)
        return original_inner(self, kind, name, generation, definition, snapshot, edit)

    traced_factory = work(thread=True, group="bench", exit_on_error=False)(traced_inner)

    def run_job_wrapper(self, kind, name, generation, definition, snapshot, edit):
        # ``_start_next`` assigns ``_active_job`` and then calls ``_run_job`` as its
        # next statement, so this entry is "immediately after ``_active_job`` is set".
        if (
            probe.armed
            and probe.has("key")
            and kind == "decode"
            and name == LARGE
            and not probe.has("active_job")
        ):
            probe.stamp("active_job", kind=kind, name=name)
        return traced_factory(self, kind, name, generation, definition, snapshot, edit)

    monkeypatch.setattr(bs.ArrayBenchSheet, "_run_job", run_job_wrapper)

    job_done = bs.ArrayBenchSheet._job_done

    def job_done_wrapper(self, kind, name, generation, result, derived):
        if (
            SCENARIO == "b"
            and probe.has("gate_release")
            and kind == "summary"
            and name == SMALL
            and not probe.has("summary_complete")
        ):
            probe.stamp("summary_complete", kind=kind, name=name)
        return job_done(self, kind, name, generation, result, derived)

    monkeypatch.setattr(bs.ArrayBenchSheet, "_job_done", job_done_wrapper)


def install_paint_hook(app, probe: Probe, monkeypatch) -> None:
    """Stamp the first post-enqueue paint carrying LARGE's specific decode cue."""
    compositor = app.screen._compositor
    real_render_update = compositor.render_update

    def render_update_wrapper(full=False, screen_stack=None, simplify=False):
        update = real_render_update(full=full, screen_stack=screen_stack, simplify=simplify)
        if (
            probe.armed
            and probe.has("key")
            and probe.has("enqueue_decode")
            and not probe.has("paint_busy")
            and update is not None
        ):
            try:
                text = update.render_segments(app.console)
            except Exception as exc:
                probe.stamp("paint_error", error=f"{type(exc).__name__}: {exc}")
                raise
            if "BUSY · decode LARGE ·" in text:
                probe.stamp("paint_busy")
        return update

    monkeypatch.setattr(compositor, "render_update", render_update_wrapper)


def install_gc_hook(probe: Probe):
    """Record every ``gc.callbacks`` pass (phase start/stop) for the whole body."""

    def cb(phase, info):
        probe.stamp("gc_" + phase, force=True, gen=info.get("generation"))

    gc.callbacks.append(cb)
    return cb


async def _focus_body(pilot, sheet) -> None:
    sheet.query_one(BODY).focus()
    await pilot.pause()


async def _run_idle(app, pilot, sheet, probe: Probe, posted: bool) -> None:
    """Scenario a / c-press / c-post / d: LARGE -> SMALL_BLK -> re-select LARGE (idle queue)."""
    names = [row.name for row in sheet.rows]
    assert LARGE in names and SMALL in names, names

    await wait_for(pilot, lambda: has_values(sheet, LARGE), "LARGE decoded", 120)
    await pick(pilot, sheet, SMALL)
    await wait_for(pilot, lambda: has_values(sheet, SMALL), "SMALL_BLK decoded", 60)
    await _focus_body(pilot, sheet)

    current = sheet.selected_name
    key = "up" if names.index(LARGE) < names.index(current) else "down"
    probe.arm(key)
    if posted:
        app.post_message(events.Key(key, None))
    else:
        await pilot.press(key)

    await wait_for(pilot, lambda: sheet.selected_name == LARGE, "LARGE selected", 10)
    await wait_for(pilot, lambda: probe.has("run_job"), "run_job", 30)
    await wait_for(pilot, lambda: probe.has("paint_busy"), "paint_busy", 30)
    assert sheet.selected_name == LARGE


async def _run_gated(app, pilot, sheet, probe: Probe, gate) -> None:
    """Scenario b: LARGE re-selected while another row's summary decode is gated running."""
    names = [row.name for row in sheet.rows]
    assert LARGE in names and SMALL in names, names

    # The page build queues SMALL_BLK's summary decode first; it is held in the worker.
    await wait_for(pilot, gate.entered.is_set, "SMALL_BLK summary held", 30)

    # LARGE is selected on page build (row 0); move away, then measure the re-selection.
    await pick(pilot, sheet, SMALL)
    await wait_for(pilot, lambda: sheet.selected_name == SMALL, "SMALL_BLK selected", 10)
    await _focus_body(pilot, sheet)

    current = sheet.selected_name
    key = "up" if names.index(LARGE) < names.index(current) else "down"
    probe.arm(key)
    await pilot.press(key)

    await wait_for(pilot, lambda: sheet.selected_name == LARGE, "LARGE selected", 10)
    await wait_for(pilot, lambda: probe.has("enqueue_decode"), "decode enqueued", 10)
    await wait_for(pilot, lambda: probe.has("paint_busy"), "busy cue painted", 10)

    key_t = probe.event_time("key")
    if key_t is not None:
        remaining = GATE_HOLD_AFTER_KEY_S - (time.perf_counter() - key_t)
        if remaining > 0:
            await pilot.pause(remaining)

    gate.release()
    probe.stamp("gate_release", name=SMALL)
    await wait_for(pilot, lambda: probe.has("summary_complete"), "summary complete", 30)
    await wait_for(pilot, lambda: probe.has("run_job"), "run_job", 30)
    assert sheet.selected_name == LARGE


def test_q9b_gap(tmp_path, defc_dir, monkeypatch):
    probe = Probe()
    gate = None
    gc_cb = None
    error = None

    try:
        install_class_wrappers(probe, monkeypatch)
        if SCENARIO == "b":
            gate = Gate(monkeypatch, "decode_values", hold={SMALL})

        a2l, s19 = big_case(tmp_path, LARGE_COUNT, rows=(LARGE,))

        async def body(app, pilot, panel):
            nonlocal gc_cb
            sheet = sheet_of(panel)
            install_paint_hook(app, probe, monkeypatch)
            if SCENARIO == "d":
                gc_cb = install_gc_hook(probe)
            try:
                if SCENARIO == "b":
                    await _run_gated(app, pilot, sheet, probe, gate)
                else:
                    await _run_idle(app, pilot, sheet, probe, posted=(SCENARIO == "c-post"))
            finally:
                if gc_cb is not None:
                    try:
                        gc.callbacks.remove(gc_cb)
                    except ValueError:
                        pass

        run(tmp_path, defc_dir, body, a2l=a2l, image=s19)

        missing = [m for m in REQUIRED if m not in probe.markers]
        assert not missing, f"missing markers {missing}; events={probe.events}"
        assert probe.event_time("key") is not None, "no key event stamped"
    except BaseException as exc:
        error = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        if gate is not None:
            gate.release()

        missing = [m for m in REQUIRED if m not in probe.markers]
        key_t = probe.event_time("key")
        events = sorted(probe.events, key=lambda ev: ev["t"])
        for ev in events:
            ev["dt"] = ev["t"] - key_t if key_t is not None else None

        payload = {
            "scenario": SCENARIO,
            "run": RUN_LABEL,
            "target": LARGE,
            "key": probe.key,
            "loadavg": loadavg(),
            "markers": sorted(probe.markers),
            "missing": missing,
            "error": error,
            "events": events,
        }
        print("Q9BGAP " + json.dumps(payload, sort_keys=True))
