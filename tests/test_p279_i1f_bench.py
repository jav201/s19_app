"""P-279 I1f E4, group G-BENCH: staging-sheet paints per page (F3).

Requirements: R-PE-BENCH.109 (repaint when the last page decode ends), R-PE-BENCH.110 (one repaint per paint
window while page decodes are pending, no later than the window's end), R-PE-BENCH.111 (a stale page result
repaints nothing), R-PE-BENCH.113 (a decode, preview or record-stage job end repaints before the next job starts).
R-PE-BENCH.112 is withdrawn (E3-6). Cases: ``records/2026-11-20-p279/I1f/02-test-cases-BENCH.md``.

Harness: the real ``ArrayBenchSheet`` mounted alone in a minimal app, over a real page of the public demos
(page = 200 names of the picker's list in tag order, definitions from ``describe_definitions``, a zero image over
every record). The decodes run in the product's own worker threads. Observation (no product hook): the instance's
``_paint``, ``_job_done``, ``_run_job`` and ``set_timer`` are wrapped to log events; the wrappers never change a result.
Clock seam: the module's ``time`` (``bench_sheet.time.monotonic``) is replaced by a stand-in clock. It also drives the
busy cue (E3-14), so no test here asserts busy-cue state and the busy-cue tests (R-PE-BENCH.94-.105) are not run
frozen. The deferred paint is captured by the ``set_timer`` wrapper and fired by the test; no wall-clock wait.

The oracle for "the sheet text after the decodes end equals base's" (R-PE-BENCH.109) is a fresh full paint of the final
state in the same run: base paints after every result, so its final text is a paint of the final state. A skipped
drain paint leaves the last strips unpainted and the two texts differ.

Private seams (``_painted_at``, ``_window_timer``, ``_paint_after_page_result``) are reached lazily inside each test
body, so the module collects on base and each node fails on its own.
"""
from __future__ import annotations

import asyncio
import dataclasses
import functools
import importlib
import threading
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from textual.app import App
from textual.widgets import Static

from tests.support.timing import wait_until

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = ROOT / "examples" / "case_00_public"
D171 = PUBLIC / "ASAP2_Demo_V171.a2l"
BALANCE = PUBLIC / "BalanceTube_STMicro.a2l"
BS = "s19_app.tui.screens_directionb.patch_editor.bench_sheet"
PAGE = 200
SIZE = (118, 54)
# R-PE-BENCH.113 names ASAM.C.CURVE.STD_AXIS, but that row is refused by the A2L alignment check (kind "none"), so no
# bench job ever runs for it; the first decodable curve of the same page stands in (reported to the conductor).
CURVE = "ASAM.C.CURVE.FIX_AXIS.PAR"
PAGE_KINDS = ("summary", "staged")
T0 = 100.0
STEP = 0.3
RESULT_5 = 5
PENDING_FLOOR = 10  # R-PE-BENCH.113: 10 page decodes still pending
V171_PAGE1_DECODES = 20  # R-PE-BENCH.110: ASAP2_Demo_V171 page 1 (20 decodes)


def _mod(name: str):
    return importlib.import_module(name)


# ----------------------------------------------------------------------------- the real page


@functools.lru_cache(maxsize=None)
def _parsed(path: Path) -> dict:
    return _mod("s19_app.tui.a2l_parse").parse_a2l_file(path)


def _rows(a2l: dict) -> list:
    """The picker rows of an A2L: one per tag with an integer address, in tag order."""
    seen, rows = set(), []
    for tag in a2l["tags"]:
        name, address = tag.get("name"), tag.get("address")
        if not isinstance(address, int) or isinstance(address, bool) or name in seen:
            continue
        seen.add(name)
        rows.append({"name": name, "address": address, "datatype": tag.get("datatype"),
                     "char_type": tag.get("char_type"), "compu_method_unit": tag.get("compu_method_unit")})
    return rows


@functools.lru_cache(maxsize=None)
def _page(path: Path, index: int, size: int = PAGE):
    """(a2l, names, definitions, zero image) of page ``index`` of the picker's list of ``path`` (tag order, ``size`` per page)."""
    a2l = _parsed(path)
    names = [row["name"] for row in _rows(a2l)][index * size:(index + 1) * size]
    defs = _mod("s19_app.tui.a2l_definition").describe_definitions(names, a2l)
    image = {}
    for definition in defs.values():
        start, size = definition.address, definition.byte_length
        if isinstance(start, int) and isinstance(size, int) and 0 < size <= 1 << 16:
            image.update({start + i: 0 for i in range(size)})
    return a2l, names, defs, image


def _expected_results(sheet) -> int:
    """The page decodes show_page queues: bench rows no larger than BENCH_LARGE elements."""
    bs = _mod(BS)
    return sum(1 for r in sheet.rows if r.kind in bs.BENCH_KINDS and r.definition.element_count <= bs.BENCH_LARGE)


# ----------------------------------------------------------------------------- clock, timer, probe


class _Clock:
    """Stand-in for the module's ``time``: only ``monotonic`` is read by bench_sheet."""

    def __init__(self, now: float) -> None:
        self.now = now

    def monotonic(self) -> float:
        return self.now


class _Timer:
    """A captured deferred paint: the test fires it; ``stop`` marks it stopped."""

    def __init__(self, delay, callback) -> None:
        self.delay, self.callback, self.stopped, self.fired = delay, callback, False, False

    def stop(self) -> None:
        self.stopped = True

    @property
    def active(self) -> bool:
        return not (self.stopped or self.fired)


@dataclasses.dataclass
class _Done:
    kind: str
    name: str
    generation: int
    pending: int
    before: int
    timers_before: int
    paints: int = 0
    timers_after: int = 0


class _Probe:
    """Event log of one sheet: paints, job starts, job ends, captured deferred paints."""

    def __init__(self, sheet, clock, step: float = 0.0, fire_after: int | None = None) -> None:
        self.sheet, self.clock, self.step, self.fire_after = sheet, clock, step, fire_after
        self.log, self.timers, self.dones, self.fired_paints = [], [], [], []
        self.paints, self.page_seen = 0, 0
        self._paint0, self._done0, self._run0 = sheet._paint, sheet._job_done, sheet._run_job
        self._timer0 = sheet.set_timer
        sheet._paint, sheet._job_done, sheet._run_job = self._paint, self._done, self._run
        sheet.set_timer = self._set_timer

    def active(self) -> int:
        return sum(1 for t in self.timers if t.active)

    def _paint(self) -> None:
        self.paints += 1
        self.log.append(("paint",))
        self._paint0()

    def _run(self, kind, *args, **kwargs):
        self.log.append(("start", kind))
        return self._run0(kind, *args, **kwargs)

    def _set_timer(self, delay, callback, *args, **kwargs):
        if getattr(callback, "__name__", "") != "_paint_window_end":
            return self._timer0(delay, callback, *args, **kwargs)
        timer = _Timer(delay, callback)
        self.timers.append(timer)
        self.log.append(("timer", delay))
        return timer

    def _done(self, kind, name, generation, result, derived) -> None:
        page = kind in PAGE_KINDS
        if page:
            self.page_seen += 1
            self.clock.now += self.step
        rec = _Done(kind, name, generation, len(self.sheet._page), self.paints, self.active())
        self.log.append(("done", kind, name))
        self._done0(kind, name, generation, result, derived)
        rec.paints, rec.timers_after = self.paints - rec.before, self.active()
        self.dones.append(rec)
        if page and self.fire_after == self.page_seen:
            self.fire_first()

    def fire_first(self) -> None:
        live = [t for t in self.timers if t.active]
        if live:
            live[0].fired = True
            before = self.paints
            live[0].callback()
            self.fired_paints.append(self.paints - before)

    def page_dones(self) -> list:
        return [d for d in self.dones if d.kind in PAGE_KINDS]

    def page_paints(self) -> int:
        return sum(d.paints for d in self.page_dones()) + sum(self.fired_paints)


class _Hold:
    """Holds the first ``decode_values`` call of the worker until released (the page's first summary)."""

    def __init__(self, monkeypatch, bs) -> None:
        self.release, self.entered, self._lock, self._calls = threading.Event(), threading.Event(), threading.Lock(), 0
        real = bs.decode_values

        def wrapper(*args, **kwargs):
            with self._lock:
                first = self._calls == 0
                self._calls += 1
            if first:
                self.entered.set()
                self.release.wait(30)
            return real(*args, **kwargs)

        monkeypatch.setattr(bs, "decode_values", wrapper)


def _host(cls):
    class Host(App):
        CSS = "ArrayBenchSheet { height: 1fr; width: 1fr; }"

        def compose(self):
            yield cls(id="patch_sheet")

        def on_array_bench_sheet_record_stage_requested(self, event) -> None:
            sheet = self.query_one("#patch_sheet")
            sheet.record_staged(event.name, event.edit)
            sheet.record_done(event.name)

    return Host()


@asynccontextmanager
async def _session(monkeypatch, *, start=T0, step=0.0, fire_after=None, hold=False, cls=None):
    """Mount the bench sheet alone with the injected clock: yields (pilot, sheet, probe, hold)."""
    bs = _mod(BS)
    clock = _Clock(start)
    monkeypatch.setattr(bs, "time", clock)
    gate = _Hold(monkeypatch, bs) if hold else None
    app = _host(cls or bs.ArrayBenchSheet)
    try:
        async with app.run_test(size=SIZE) as pilot:
            await pilot.pause()
            sheet = app.query_one("#patch_sheet")
            yield pilot, sheet, _Probe(sheet, clock, step, fire_after), gate
    finally:
        if gate is not None:
            gate.release.set()


def _drained(sheet) -> bool:
    return not (sheet._active_job or sheet._page or sheet._slot or sheet._records or sheet._held)


async def _drain(pilot, sheet) -> None:
    await wait_until(pilot, lambda: _drained(sheet), lambda: f"queue not drained: {sheet._active_job}")
    await pilot.pause()


def _text(sheet) -> str:
    content = sheet.query_one("#patch_sheet_body", Static).content
    return content.plain if hasattr(content, "plain") else str(content)


def _show(sheet, path: Path, index: int = 0, size: int = PAGE) -> None:
    a2l, names, defs, image = _page(path, index, size)
    sheet.show_page(names, defs, a2l, image)


# ----------------------------------------------------------------------------- R-PE-BENCH.109


async def _settle(pilot, probe) -> None:
    """Pump until the layout's own paints stop (two quiet pauses in a row)."""
    quiet = 0
    while quiet < 2:
        seen = probe.paints
        await pilot.pause()
        quiet = quiet + 1 if probe.paints == seen else 0


async def _final_state_matches(monkeypatch, path, index, size=PAGE, cls=None):
    async with _session(monkeypatch, hold=True, cls=cls) as (pilot, sheet, probe, gate):
        _show(sheet, path, index, size)
        expected = _expected_results(sheet)
        if expected:
            await wait_until(pilot, gate.entered.is_set, "the first summary did not start")
        await _settle(pilot, probe)
        quiet = probe.paints
        gate.release.set()
        await _drain(pilot, sheet)
        pages = probe.page_dones()
        assert len(pages) == expected, (len(pages), expected)
        last = pages[-1] if pages else None
        settled = probe.active() == 0 and probe.paints == (last.before + last.paints if last else quiet)
        before, bench = _text(sheet), [r.name for r in sheet.rows if r.kind in _mod(BS).BENCH_KINDS]
        sheet._paint()
        equal = before == _text(sheet)
        return expected, last.paints if last else 0, settled, equal, [sheet.states[n].job for n in bench]


PAGES_109 = [(D171, 0, 59), (D171, 1, 59), (BALANCE, 0, PAGE)]


@pytest.mark.parametrize("path,index,size", PAGES_109, ids=["v171-p1", "v171-p2", "balance-p1"])
def test_r_pe_bench_109_1_the_last_decode_repaints_once_and_the_sheet_equals_a_fresh_paint(monkeypatch, path, index, size):
    """Frozen clock: the last page result repaints exactly once, nothing repaints after it, and the sheet text after
    the decodes end equals a fresh full paint of the final state (base paints after every result). BalanceTube
    page 1 queues no page decode: nothing is pending, so nothing paints for it and the text still equals."""
    expected, painted, settled, equal, jobs = asyncio.run(_final_state_matches(monkeypatch, path, index, size))
    assert expected >= 1 or path == BALANCE, "a V171 page queues no page decode: the case would be vacuous"
    assert painted == min(expected, 1), (expected, painted)
    assert settled, "a paint or an armed timer outlived the last result"
    assert equal, "the sheet text after the last result differs from a full paint of the final state"
    assert all(job is None for job in jobs), jobs


def _skip_drain_cls():
    class SkipDrain(_mod(BS).ArrayBenchSheet):
        def _paint_after_page_result(self):
            return False

    return SkipDrain


def test_r_pe_bench_109_2_control_a_skipped_drain_paint_leaves_the_last_strips_unpainted(monkeypatch):
    """Oracle control: a sheet that never paints a page result after the paint stamp shows a text that differs
    from a fresh paint of the final state, so 109/1 can fail. (Inert on base, where the seam does not exist.)"""
    _, painted, _, equal, _ = asyncio.run(_final_state_matches(monkeypatch, D171, 0, 59, cls=_skip_drain_cls()))
    assert painted == 0 and not equal, (painted, equal)


async def _vanished_row(monkeypatch):
    async with _session(monkeypatch, hold=True) as (pilot, sheet, probe, gate):
        _show(sheet, D171, 0)
        await wait_until(pilot, gate.entered.is_set, "the first summary did not start")
        sheet._page = [("summary", "NO_SUCH_ROW")]
        gate.release.set()
        await wait_until(pilot, lambda: bool(probe.dones), "the held summary did not end")
        return probe.dones[0].kind, probe.dones[0].paints


def test_r_pe_bench_109_3_a_result_whose_queue_rows_vanished_repaints_at_once(monkeypatch):
    """E3-13: the rest of the queue vanishes while the first summary is held; after it nothing page-related is
    active or queued, so its own result repaints at once (clock frozen: no window has passed)."""
    kind, painted = asyncio.run(_vanished_row(monkeypatch))
    assert kind == "summary" and painted == 1, (kind, painted)


# ----------------------------------------------------------------------------- R-PE-BENCH.110


async def _run_page(monkeypatch, **session):
    """V171 page 1 with its first summary held until the layout has settled, then drained."""
    async with _session(monkeypatch, hold=True, **session) as (pilot, sheet, probe, gate):
        _show(sheet, D171, 0)
        expected = _expected_results(sheet)
        await wait_until(pilot, gate.entered.is_set, "the first summary did not start")
        await _settle(pilot, probe)
        gate.release.set()
        await _drain(pilot, sheet)
        return probe, expected, sheet


def test_r_pe_bench_110_a_frozen_clock_never_fired_paints_nothing_until_the_drain(monkeypatch):
    """Arm (a): frozen clock, timer never fired: 0 repaints before the last result, exactly 1 pending deferred paint
    (delay in (0, 0.25]), then the drain repaint cancels it: 1 repaint in total."""
    probe, expected, _ = asyncio.run(_run_page(monkeypatch))
    pages = probe.page_dones()
    assert expected == V171_PAGE1_DECODES and len(pages) == expected, (expected, len(pages))
    assert [d.paints for d in pages[:-1]] == [0] * (expected - 1)
    assert len(probe.timers) == 1 and pages[-1].timers_before == 1, len(probe.timers)
    assert 0 < probe.timers[0].delay <= 0.25, probe.timers[0].delay
    assert pages[-1].paints == 1 and probe.timers[0].stopped and probe.active() == 0
    assert probe.page_paints() == 1, probe.page_paints()


def test_r_pe_bench_110_b_a_timer_fired_after_result_5_paints_once_and_no_more_until_the_next_window(monkeypatch):
    """Arm (b): frozen clock, the captured timer fired after result 5: exactly 1 repaint at the timer, showing
    results 1-5 (and not later ones); no second repaint until the next window's end or the drain."""
    probe, expected, _ = asyncio.run(_run_page(monkeypatch, fire_after=RESULT_5))
    pages = probe.page_dones()
    assert probe.fired_paints == [1], probe.fired_paints
    assert [d.paints for d in pages[:-1]] == [0] * (expected - 1), "a result repainted outside a window end"
    assert pages[-1].paints == 1 and probe.active() == 0
    assert probe.page_paints() == 2, probe.page_paints()
    assert len(probe.timers) == 2 and pages[-1].timers_before == 1, "the second window did not arm its own deferred paint"


async def _shows_results_1_to_5(monkeypatch):
    async with _session(monkeypatch, fire_after=RESULT_5, hold=True) as (pilot, sheet, probe, gate):
        _show(sheet, D171, 0)
        await wait_until(pilot, gate.entered.is_set, "the first summary did not start")
        await _settle(pilot, probe)
        seen = {}
        original = probe.fire_first

        def spy() -> None:
            names = [d.name for d in probe.page_dones()]
            seen["stored"] = [sheet.states[n].job for n in names]
            seen["later"] = [r.name for r in sheet.rows if sheet.states.get(r.name) and sheet.states[r.name].job == "summary"]
            seen["names"] = names
            original()

        probe.fire_first = spy
        gate.release.set()
        await _drain(pilot, sheet)
        return seen, probe


def test_r_pe_bench_110_b2_the_timer_paint_shows_exactly_the_stored_results(monkeypatch):
    """Arm (b), content: at the timer, results 1-5 are stored (job cleared) and the later rows still wait; the
    timer's paint is the one repaint (a paint-at-the-end-only sheet arms nothing and fails 110/b)."""
    seen, probe = asyncio.run(_shows_results_1_to_5(monkeypatch))
    assert len(seen["names"]) == RESULT_5 and all(job is None for job in seen["stored"]), seen
    assert not set(seen["names"]) & set(seen["later"]) and len(seen["later"]) >= 1, seen
    assert probe.fired_paints == [1], probe.fired_paints


def test_r_pe_bench_110_c_a_clock_stepping_past_the_window_paints_every_result_on_arrival(monkeypatch):
    """Arm (c): clock +0.3 s per result: every result repaints on arrival, no timer is ever armed."""
    probe, expected, _ = asyncio.run(_run_page(monkeypatch, step=STEP))
    pages = probe.page_dones()
    assert [d.paints for d in pages] == [1] * expected, [d.paints for d in pages]
    assert probe.timers == [] and probe.page_paints() == expected


UNIT_CASES = [
    ("idle", 0, 0.0, False, True, 1, 0),
    ("inside-window", 3, 0.10, False, False, 0, 1),
    ("after-window", 3, 0.30, False, True, 1, 0),
    ("boundary", 3, "interval", False, True, 1, 0),
    ("armed", 3, 0.20, True, False, 0, 0),
]


async def _decide(monkeypatch, queued, elapsed, armed):
    async with _session(monkeypatch) as (pilot, sheet, probe, _):
        bs = _mod(BS)
        gap = bs.BENCH_PAINT_INTERVAL_S if elapsed == "interval" else elapsed
        sheet._page, sheet._active_job = [("summary", f"r{i}") for i in range(queued)], None
        sheet._painted_at = probe.clock.now - gap
        if armed:
            sheet._window_timer = _Timer(0.05, sheet._paint_window_end)
        painted = sheet._paint_after_page_result()
        return painted, probe.paints, len(probe.timers), [t.delay for t in probe.timers], gap, bs.BENCH_PAINT_INTERVAL_S


@pytest.mark.parametrize("case,queued,elapsed,armed,painted,paints,timers", UNIT_CASES, ids=[c[0] for c in UNIT_CASES])
def test_r_pe_bench_110_d_the_paint_decision_at_the_window_edges(monkeypatch, case, queued, elapsed, armed, painted, paints, timers):
    """Node cases of the decision (R-PE-BENCH.109/.110): idle queue paints; inside the window one deferred paint is
    armed with the remaining time; at or after the window's end it paints; an armed timer is not re-armed."""
    got = asyncio.run(_decide(monkeypatch, queued, elapsed, armed))
    assert got[:3] == (painted, paints, timers), (case, got)
    if timers:
        assert got[3] == [pytest.approx(got[5] - got[4])], got


async def _stamps(monkeypatch):
    async with _session(monkeypatch, start=5.0) as (pilot, sheet, probe, _):
        timer = _Timer(0.1, sheet._paint_window_end)
        sheet._window_timer = timer
        sheet._paint()
        return sheet._painted_at, timer.stopped, sheet._window_timer


def test_r_pe_bench_110_e_a_paint_stamps_the_clock_and_stops_an_armed_deferred_paint(monkeypatch):
    """T-110: a paint at clock 5.0 stamps 5.0 and cancels the armed deferred paint (the paint covers it)."""
    stamp, stopped, left = asyncio.run(_stamps(monkeypatch))
    assert stamp == 5.0 and stopped and left is None, (stamp, stopped, left)


async def _unmounted(monkeypatch):
    async with _session(monkeypatch) as (pilot, sheet, probe, _):
        sheet._page, sheet._active_job, sheet._painted_at = [("summary", "r0")], None, probe.clock.now
        sheet._paint_after_page_result()
        timer = probe.timers[0]
        before = probe.paints
        await sheet.remove()
        await pilot.pause()
        return timer.stopped, probe.paints - before


def test_r_pe_bench_110_f_removing_the_sheet_stops_the_deferred_paint(monkeypatch):
    """T-110: a deferred paint armed, then the sheet is removed: the timer is stopped, 0 paints after the removal."""
    stopped, after = asyncio.run(_unmounted(monkeypatch))
    assert stopped and after == 0, (stopped, after)


# ----------------------------------------------------------------------------- R-PE-BENCH.111


async def _stale_result(monkeypatch, change, cls=None):
    async with _session(monkeypatch, hold=True, cls=cls) as (pilot, sheet, probe, gate):
        _show(sheet, D171, 0)
        await wait_until(pilot, gate.entered.is_set, "the first summary did not start")
        shown = change(sheet)
        gate.release.set()
        await wait_until(pilot, lambda: bool(probe.dones), "the held summary did not end")
        held = probe.dones[0]
        return held, shown, sheet


def _change_page(sheet):
    a2l, names, defs, image = _page(D171, 1)
    sheet.show_page(names, defs, a2l, image)
    return {r.name for r in sheet.rows}


def _change_document(sheet):
    sheet.set_document([], sheet._image)
    return None


def test_r_pe_bench_111_1_a_result_for_a_page_no_longer_shown_repaints_nothing(monkeypatch):
    """Arm 1: the page changes during the held decode; the stale result is discarded with 0 repaints."""
    held, shown, _ = asyncio.run(_stale_result(monkeypatch, _change_page))
    assert held.kind == "summary" and held.name not in shown, (held.name, len(shown))
    assert held.paints == 0 and held.timers_after == held.timers_before, held


def test_r_pe_bench_111_2_a_result_for_a_changed_document_repaints_nothing(monkeypatch):
    """Arm 2: the document changes (generation grows) during the held decode; the stale result repaints nothing."""
    held, _, sheet = asyncio.run(_stale_result(monkeypatch, _change_document))
    assert held.generation != sheet.generation, (held.generation, sheet.generation)
    assert held.paints == 0 and held.timers_after == held.timers_before, held


def _paint_first_cls():
    class PaintFirst(_mod(BS).ArrayBenchSheet):
        def _job_done(self, *args):
            self._paint()
            super()._job_done(*args)

    return PaintFirst


@pytest.mark.parametrize("change", [_change_page, _change_document], ids=["page", "document"])
def test_r_pe_bench_111_3_control_a_paint_before_the_stale_check_is_counted(monkeypatch, change):
    """Oracle control: a sheet that repaints before the stale check gives 1 for the stale result, so 111/1 and
    111/2 can fail."""
    held, _, _ = asyncio.run(_stale_result(monkeypatch, change, cls=_paint_first_cls()))
    assert held.paints == 1, held


async def _unmounted_result(monkeypatch):
    async with _session(monkeypatch, hold=True) as (pilot, sheet, probe, gate):
        _show(sheet, D171, 0)
        await wait_until(pilot, gate.entered.is_set, "the first summary did not start")
        await sheet.remove()
        await pilot.pause()
        kind, name, _token, _definition, _edit = sheet._active_job
        sheet._held = True  # the removed sheet starts no further job: only the held result is delivered
        paints_before = probe.paints
        sheet._job_done(kind, name, sheet.generation, None, {})
        return sheet, probe, kind, probe.paints - paints_before


def test_r_pe_bench_111_3_a_result_after_unmount_arms_no_timer(monkeypatch):
    """Arm 3 (P-354 b): the sheet is unmounted while a page decode is held, then the result is delivered
    (the job-done seam, as the worker calls it): 0 paints and 0 deferred paints armed by it."""
    sheet, probe, kind, paints = asyncio.run(_unmounted_result(monkeypatch))
    assert kind == "summary" and not sheet.is_attached and sheet._page, (kind, sheet.is_attached)
    assert paints == 0, paints
    assert probe.timers == [] and sheet._window_timer is None, (len(probe.timers), sheet._window_timer)


# ----------------------------------------------------------------------------- R-PE-BENCH.113


def _queue_user_job(sheet, kind: str) -> None:
    if kind == "decode":
        return  # selecting the row already queued its decode
    row = next(r for r in sheet.rows if r.name == CURVE)
    definition_bench = _mod("s19_app.tui.definition_bench")
    grid = definition_bench.bench_grid(row.definition)
    state = sheet._state_for(CURVE)
    cell = definition_bench.selection_cells(state, grid)[0]
    edit = {cell: "1"}
    if kind == "record":
        sheet._enqueue("record", CURVE, tuple(edit.items()))
    else:
        sheet._edit_changed(CURVE, state, dataclasses.replace(state, edit=edit))


async def _user_job(monkeypatch, kind: str, cls=None):
    async with _session(monkeypatch, hold=True, cls=cls) as (pilot, sheet, probe, gate):
        _show(sheet, D171, 0)
        await wait_until(pilot, gate.entered.is_set, "the first summary did not start")
        names = [r.name for r in sheet.rows]
        assert CURVE in names, f"{CURVE} is not on page 1"
        for _ in range(names.index(CURVE) - sheet.selected):
            sheet.action_move(1)
        await pilot.pause()
        assert sheet.selected_name == CURVE
        _queue_user_job(sheet, kind)
        gate.release.set()
        wanted = ("done", kind, CURVE)
        await wait_until(pilot, lambda: wanted in probe.log, f"the {kind} job did not end")
        await wait_until(pilot, lambda: not sheet._held, "the record hold was not released")
        await pilot.pause()
        return probe, probe.log.index(wanted)


def _before_next_start(probe, at: int) -> list:
    """The events between the job's end marker and the next job start."""
    rest = probe.log[at + 1:]
    stop = next((i for i, e in enumerate(rest) if e[0] == "start"), len(rest))
    return rest[:stop]


@pytest.mark.parametrize("kind", ["decode", "preview"])
def test_r_pe_bench_113_1_a_decode_or_preview_end_repaints_once_before_the_next_job(monkeypatch, kind):
    """Frozen clock, 10+ page decodes pending: the job's own result repaints once, in the result call, before the
    next job starts (a throttle on user jobs would give 0 here)."""
    probe, at = asyncio.run(_user_job(monkeypatch, kind))
    between = _before_next_start(probe, at)
    done = next(d for d in probe.dones if d.kind == kind and d.name == CURVE)
    assert done.pending >= PENDING_FLOOR, done
    assert done.paints == 1 and between[:1] == [("paint",)], (done, between)
    assert probe.clock.now == T0


def test_r_pe_bench_113_2_a_record_stage_end_repaints_once_before_the_held_queue_resumes(monkeypatch):
    """Frozen clock, 10+ page decodes pending: the record result paints 0 (held), the host's record_staged paints 1,
    and that paint comes before the next job starts. The staging step is the host stand-in of the test app."""
    probe, at = asyncio.run(_user_job(monkeypatch, "record"))
    between = _before_next_start(probe, at)
    done = next(d for d in probe.dones if d.kind == "record" and d.name == CURVE)
    assert done.pending >= PENDING_FLOOR and done.paints == 0, done
    assert between == [("paint",)], between


def _folded_cls():
    class Folded(_mod(BS).ArrayBenchSheet):
        """Folds the user jobs into the page throttle: with a frozen clock their result paints nothing."""

        def _job_done(self, kind, *args):
            if kind not in ("decode", "preview"):
                return super()._job_done(kind, *args)
            kept = self._paint
            self._paint = lambda: None
            try:
                super()._job_done(kind, *args)
            finally:
                self._paint = kept

    return Folded


@pytest.mark.parametrize("kind", ["decode", "preview"])
def test_r_pe_bench_113_3_control_a_throttled_user_job_paints_nothing_with_a_frozen_clock(monkeypatch, kind):
    """Oracle control: a sheet that folds decode and preview results into the throttle gives 0 repaints at the
    job's end under the frozen clock, so 113/1 can fail."""
    probe, _ = asyncio.run(_user_job(monkeypatch, kind, cls=_folded_cls()))
    done = next(d for d in probe.dones if d.kind == kind and d.name == CURVE)
    assert done.paints == 0, done
