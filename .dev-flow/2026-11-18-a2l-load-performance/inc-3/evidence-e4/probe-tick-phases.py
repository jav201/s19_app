"""Probe (G-T-I3-repair, evidence-e4): one case_06 image run with tick
lateness bucketed by phase, to distinguish worker-CPU starvation from
external host contention behind the ``tick_failures == 0`` oracle. Reuses
the perf test's instruments verbatim (read-only duplication for diagnosis).
Transcript: probe-tick-phases.txt."""

import sys
import tempfile
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))

from tests.test_alp_inc3_load_responsiveness import (  # noqa: E402
    CASE06,
    CASE06_IMAGE,
    TickTimer,
    TimedGate,
    _arm_route_recorders,
    _timed,
)
from tests.test_alp_inc2_a2l_attach import _run, _submit_typed, _typed_attach  # noqa: E402
from tests.support.b100_workers import settle_workers  # noqa: E402
from tests.support.timing import wait_until  # noqa: E402
from s19_app.tui.screens import ConfirmQuestionScreen  # noqa: E402

monkeypatch = pytest.MonkeyPatch()
base = Path(tempfile.mkdtemp(prefix="tick-phases-"))

for round_no in range(1, 4):
    with monkeypatch.context():
        async def body(app, pilot, round_no=round_no):
            await _typed_attach(app, pilot, CASE06)
            await settle_workers(pilot)
            phases = []
            outcomes = []
            fanouts = []
            dispatches = []
            _timed(monkeypatch, app, "_parse_loaded_file", phases)
            _timed(monkeypatch, app, "_prepare_load_payload", phases)
            _arm_route_recorders(app, monkeypatch, "_complete_prepared_load", outcomes, fanouts, dispatches)
            gate = TimedGate(monkeypatch)
            timer = TickTimer(app)
            timer.start()
            total_start = time.perf_counter()
            await _submit_typed(app, pilot, str(CASE06_IMAGE))
            try:
                await wait_until(
                    pilot,
                    lambda: isinstance(app.screen, ConfirmQuestionScreen),
                    "the typed-load confirm modal",
                    timeout=10.0,
                )
                await pilot.press("y")
            except AssertionError:
                pass
            await wait_until(pilot, gate.entered.is_set, "the producer gate", timeout=180.0)
            loop_t0 = time.perf_counter()
            while True:
                ticks = timer.gate_ticks(gate.gate_started, time.perf_counter())
                if ticks >= 3 and time.perf_counter() - gate.gate_started >= 0.20:
                    break
                await pilot.pause(0.02)
            loop_t1 = time.perf_counter()
            gate.release.set()
            await settle_workers(pilot)
            await wait_until(pilot, lambda: bool(outcomes), "the image outcome", timeout=180.0)
            timer.stop()
            await pilot.pause()
            failures = sum(1 for _d, _f, lateness in timer.observations if lateness > 0.1)
            total = outcomes[0][2] - total_start
            parse_entry = next(r for r in phases if r[0] == "_parse_loaded_file")
            prepare = next(r for r in phases if r[0] == "_prepare_load_payload")
            buckets = {"admission": [0, 0], "parse": [0, 0], "prep": [0, 0], "gate": [0, 0], "install/pub": [0, 0]}
            for _due, fired, lateness in timer.observations:
                if fired < parse_entry[1]:
                    phase = "admission"
                elif fired < parse_entry[2]:
                    phase = "parse"
                elif fired < prepare[1]:
                    phase = "prep"
                elif fired < gate.gate_released:
                    phase = "gate"
                else:
                    phase = "install/pub"
                buckets[phase][0] += 1
                buckets[phase][1] += 1 if lateness > 0.1 else 0
            dist = " ".join(f"{p}={n}/{late}" for p, (n, late) in buckets.items())
            print(
                f"ROUND {round_no}: total={total:.2f}s tick_obs={len(timer.observations)} "
                f"tick_failures={failures} tickloop={loop_t1 - loop_t0:.3f}s {dist}"
            )

        _run(base / f"r{round_no}", body)
