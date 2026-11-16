"""Batch-103 Inc 9 E4 (tester T9b): the size-bound and timing ATs of the bench worker - LARGE (1,048,576 elements).

Requirements: R-PE-BENCH.20, .23/2, .26/2, .28, .29, .82/1. Widget ``ArrayBenchSheet`` (B30, B33, B34, B28) over the real
I-2 decode of LARGE (about 11 s and 200 MiB per decode, Inc 3a's [B1]).

LOAD-SENSITIVE (HT-08, E3A-13): every ``serial_timing`` node here is decided on a QUIET host only. A run on a
shared host is a record, not a verdict: the message of each timing assertion carries ``os.getloadavg()``, and the
record in ``inc-9/E4-test-w.md`` names the host load beside every number. Run them apart:
``-m serial_timing`` with ``-n 0``. They are ``slow`` as well (one LARGE decode is about 11 s).

A LARGE decode is held by ``Gate`` (a wrapper of I-2's ``decode_values`` that waits in the worker) where the claim
is "while the decode runs"; it is never released into a stand-in result, so the product's own decode is what
finally runs. Keys are ``pilot.press``; a key's time is the time ``pilot.press`` takes to return, except while a
worker thread computes (29_2, 82_1): there ``keys_until`` sends the key from a thread, as a terminal's input thread
does, and times it from that send to the sheet's key action returning (FX9: ``pilot.press`` then reads Textual's own
idle wait, about 2.2 s whatever the UI does; X9: a send from the UI loop cannot see a stall when a result arrives).
"""
from __future__ import annotations

import gc
import os
import re
import threading
import time
import tracemalloc
from pathlib import Path

import pytest
from textual import events

from s19_app.tui import definition_sheet as ds
from s19_app.tui.a2l_definition import describe_definition
from s19_app.tui.a2l_parse import parse_a2l_file
from tests.support.b103_inc8_s2 import softa_page  # noqa: F401  (a session fixture used by name)
from tests.support.b103_inc9_w import (  # noqa: F401  (defc_dir is a fixture used by name)
    BIG_COUNT, LARGE_COUNT, Gate, apply_tool, big_case, body_text, defc_dir, entries_of, has_values, hand_case, need,
    open_bench, pick, run, sheet_of, st, valblk_block, wait_for,
)
from tests.support.timing import report_margin, timing_bound

LARGE = "LARGE"
KEY_LIMIT_S = timing_bound(0.5)
# R-PE-BENCH.29/2 and .82/1 only: operator decision F-X9-2 (relevo-14) relaxed the bound while a LARGE preview or record encode runs.
RELAXED_KEY_LIMIT_S = timing_bound(1.0)
WINDOW_LINE = re.compile(r"rows 0\.\.\d+ of 65536 · cols 0\.\.15 of 16 · pgup/pgdn page")
slow = pytest.mark.slow


def load() -> str:
    return "load " + " ".join(f"{x:.2f}" for x in os.getloadavg())


def previewed(sheet) -> bool:
    """LARGE's preview RESULT is in: ``preview`` is ``"encoding"`` (a placeholder) from the apply until the result
    arrives, so ``is not None`` is true at once and proves nothing (MW9: the three nodes below waited on it)."""
    preview = st(sheet, LARGE).preview
    return preview is not None and not isinstance(preview, str)


async def timed_press(pilot, key: str) -> float:
    start = time.perf_counter()
    await pilot.press(key)
    return time.perf_counter() - start


KEY_ACTIONS = {"right": "action_choose", "left": "action_choose", "down": "action_move", "up": "action_move"}


KEY_GAP_S = 0.05


def _typist(driver, key: str, sent: list, handled: list, stop: threading.Event) -> None:
    """The terminal's input thread, one key at a time: ``key`` through ``Driver.send_message`` (thread-safe: it posts
    with ``run_coroutine_threadsafe``), the next one KEY_GAP_S after the last was handled. Each send time is taken
    HERE, off the UI thread, so a key sent while the UI thread is busy (a result arriving, a paint) waits in the app's
    queue and that wait counts; one key in flight, so no key waits behind another key (a flood measures throughput)."""
    while not stop.is_set():
        if len(handled) < len(sent):
            stop.wait(0.005)
            continue
        stop.wait(KEY_GAP_S)
        sent.append(time.perf_counter())
        driver.send_message(events.Key(key, None))


async def large_with_selection(pilot, sheet, operand: str = "7"):
    """LARGE decoded, a 4,096-cell selection (16 columns x 256 rows) by shift+arrows, Set ``operand`` applied."""
    await open_bench(pilot, sheet, LARGE)
    await pilot.press(*(["shift+right"] * 15 + ["shift+down"] * 255))
    await apply_tool(pilot, sheet, "s", operand)


async def keys_until(pilot, sheet, key: str, done, limit_s: float = 180.0) -> list:
    """``key`` pressed by ``_typist`` until ``done()``; per key, the time from its send to the sheet's key action
    returning (the cursor moved and the sheet repainted).

    Not ``pilot.press`` (FX9, ``inc-9/E4-fixes-fx9.md``): while a worker thread computes, Textual's ``_press_keys``
    waits twice per key for the whole PROCESS to go idle (at most 1 s each), about 2.2 s whatever the UI does. Nor a
    send from the test coroutine (X9, ``inc-9/E5-review.md`` F-X9-1): that coroutine runs on the UI thread's loop, so
    it can only send once the arrival's UI work is over, and a 0.8 s UI stall when the preview arrives went unseen."""
    action = KEY_ACTIONS[key]
    real_action, sent, handled, stop = getattr(sheet, action), [], [], threading.Event()

    def timed(*args):
        real_action(*args)
        handled.append(time.perf_counter())

    setattr(sheet, action, timed)
    typist = threading.Thread(target=_typist, args=(pilot.app._driver, key, sent, handled, stop), daemon=True)
    end = time.monotonic() + limit_s
    typist.start()
    try:
        while not done() and time.monotonic() < end:
            await pilot.pause(0.05)
        stop.set()
        typist.join()
        settle = time.monotonic() + 30
        while len(handled) < len(sent) and time.monotonic() < settle:
            await pilot.pause(0.05)
    finally:
        stop.set()
        delattr(sheet, action)
    assert len(handled) == len(sent), f"{len(sent)} {key!r} sent, {len(handled)} reached the sheet's {action}"
    return [h - s for s, h in zip(sent, handled)]


# ------------------------------------------------------------------ R-PE-BENCH.20


@pytest.mark.serial_timing
@slow
def test_r_pe_bench_20_1_a_key_is_handled_within_half_a_second_while_a_large_decode_runs(tmp_path, defc_dir, monkeypatch):
    """LARGE selected and its decode held in the worker; `down` (or `up` from the last row) is handled in 0.5 s.
    Negative control: a decode on the UI thread holds the key for the whole hold (20 s) - RED."""
    gate = Gate(monkeypatch, "decode_values", hold={LARGE})
    a2l, s19 = big_case(tmp_path, LARGE_COUNT, rows=(LARGE,))

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        try:
            await pick(pilot, sheet, LARGE)
            await wait_for(pilot, gate.entered.is_set, "LARGE's decode held", 30)
            names = [row.name for row in sheet.rows]
            elapsed = await timed_press(pilot, "down" if names.index(LARGE) < len(names) - 1 else "up")
            return elapsed, has_values(sheet, LARGE)
        finally:
            gate.release()

    elapsed, finished = run(tmp_path, defc_dir, body, a2l=a2l, image=s19)
    assert finished is False, "the decode ended before the key: the claim 'while it runs' is not shown"
    assert elapsed <= report_margin("R-PE-BENCH.20/1 key during a LARGE decode", elapsed, KEY_LIMIT_S), f"key took {elapsed:.3f} s ({load()}); load-sensitive, unverified on a loaded host"


@slow
def test_r_pe_bench_20_2_the_bench_shows_its_values_when_the_decode_ends(tmp_path, defc_dir):
    """LARGE selected: `decoding 1048576 values …` first (control), then the window line of EX-H5."""
    a2l, s19 = big_case(tmp_path, LARGE_COUNT, rows=(LARGE,))

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await pick(pilot, sheet, LARGE)
        seen = f"decoding {LARGE_COUNT} values …" in body_text(app)
        await wait_for(pilot, lambda: has_values(sheet, LARGE), "LARGE's values", 120)
        await pilot.pause(0.3)
        return seen, body_text(app)

    seen, painted = run(tmp_path, defc_dir, body, a2l=a2l, image=s19)
    assert seen, "control: the decoding line was shown while the decode ran"
    assert WINDOW_LINE.search(painted), painted
    assert "decoding" not in painted


def test_r_pe_bench_20_3_a_page_holding_large_decodes_nothing_on_the_ui_thread(tmp_path, defc_dir, monkeypatch):
    """EX-I1: `build_row` over LARGE makes 0 `decode_values` calls; the page and the selection of LARGE decode off
    the UI thread only (the decode itself is held, so it never ends)."""
    gate = Gate(monkeypatch, "decode_values", hold={LARGE})
    a2l, s19 = big_case(tmp_path, LARGE_COUNT, rows=(LARGE,))
    parsed = parse_a2l_file(a2l)
    definition = describe_definition(LARGE, parsed)
    ds.build_row(definition, parsed, {0x100000: 0}, ds.StagedOverlay({0x100000: 0}, ()))
    assert gate.calls == [], f"build_row decoded on the UI thread: {gate.calls}"

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        try:
            await pick(pilot, sheet, LARGE)
            await wait_for(pilot, gate.entered.is_set, "LARGE's decode held", 30)
            return list(gate.calls)
        finally:
            gate.release()

    calls = run(tmp_path, defc_dir, body, a2l=a2l, image=s19)
    assert [c for c in calls if c[1] == LARGE and c[2]] == []
    assert any(c[1] == LARGE and not c[2] for c in calls)


# ------------------------------------------------------------------ R-PE-BENCH.23/2 (EX-C2)


@pytest.mark.serial_timing
def test_r_pe_bench_23_2_the_page_paint_of_200_names_stays_within_half_a_second(tmp_path, defc_dir, softa_page):
    """software_a's first 200 names through the bench sheet's `show_page` (R-PE-DEF.12's bound, median of 3)."""
    a2l, names, defs, image = softa_page

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        times = []
        for _ in range(3):
            start = time.perf_counter()
            sheet.show_page(names, defs, a2l, image)
            times.append(time.perf_counter() - start)
        return sorted(times)[1]

    median = run(tmp_path, defc_dir, body)
    assert median <= report_margin("R-PE-BENCH.23/2 page paint of 200 names", median, KEY_LIMIT_S), f"median {median:.3f} s ({load()}); load-sensitive, unverified on a loaded host"


# ------------------------------------------------------------------ R-PE-BENCH.26/2 (EX-B1)


DECODE_WAIT_S = 240  # the time bound of the decode: LARGE's values show within it (untraced)
TRACED_WAIT_S = 1800  # a hang guard for the traced run only; `tracemalloc` makes the decode ~8.5x slower (F-I9b-1)


@slow
def test_r_pe_bench_26_2_a_deselected_large_row_keeps_none_of_its_values(tmp_path, defc_dir):
    """LARGE decoded, then SMALL_BLK selected: LARGE's values and staged values are None and the retained memory
    (`tracemalloc` on the allocations of `s19_app`, after `gc.collect()`) is at most 1 MiB above the level before LARGE. Control: with LARGE
    selected the retained memory is well above that (the numbers are kept).

    Two runs of the same decode (F-I9b-1, ruling P-077): run 1 is untraced and holds the time bound (the values
    show within ``DECODE_WAIT_S``, then deselecting drops them); run 2 is traced and holds the 1 MiB memory bound
    with no time bound of its own (``TRACED_WAIT_S`` only guards a hang). Neither bound is loosened."""
    a2l, s19 = big_case(tmp_path, LARGE_COUNT, rows=(LARGE,))

    async def untraced(app, pilot, panel):
        sheet = sheet_of(panel)
        await pick(pilot, sheet, LARGE)
        await wait_for(pilot, lambda: has_values(sheet, LARGE), "LARGE's values", DECODE_WAIT_S)
        await pick(pilot, sheet, "SMALL_BLK")
        await wait_for(pilot, lambda: has_values(sheet, "SMALL_BLK"), "SMALL_BLK's values", 60)
        return st(sheet, LARGE)

    def product_bytes() -> int:
        """Bytes traced from allocation sites in ``s19_app`` only. The Textual internals (message queue, caches)
        grow by about 4 MiB over a traced decode of several minutes whatever the row; they are not LARGE's."""
        shot = tracemalloc.take_snapshot().filter_traces([tracemalloc.Filter(True, "*/s19_app/*")])
        return sum(stat.size for stat in shot.statistics("filename"))

    async def traced(app, pilot, panel):
        sheet = sheet_of(panel)
        gc.collect()
        tracemalloc.start()
        try:
            base, base_all = product_bytes(), tracemalloc.get_traced_memory()[0]
            await pick(pilot, sheet, LARGE)
            await wait_for(pilot, lambda: has_values(sheet, LARGE), "LARGE's values (traced)", TRACED_WAIT_S)
            gc.collect()
            held = product_bytes() - base
            await pick(pilot, sheet, "SMALL_BLK")
            await wait_for(pilot, lambda: has_values(sheet, "SMALL_BLK"), "SMALL_BLK's values", 600)
            gc.collect()
            return held, product_bytes() - base, tracemalloc.get_traced_memory()[0] - base_all, st(sheet, LARGE)
        finally:
            tracemalloc.stop()

    first = run(tmp_path, defc_dir, untraced, a2l=a2l, image=s19)
    assert first.values is None and first.staged is None, "run 1: LARGE kept values after SMALL_BLK was selected"
    held, after, after_all, state = run(tmp_path, defc_dir, traced, a2l=a2l, image=s19)
    assert held > 1 << 20, "control: LARGE's values were held while selected"
    assert state.values is None and state.staged is None
    assert after <= 1 << 20, (
        f"{after / (1 << 20):.1f} MiB allocated by s19_app are still retained after deselecting LARGE "
        f"(all allocations: {after_all / (1 << 20):.1f} MiB)"
    )


# ------------------------------------------------------------------ R-PE-BENCH.28 (EX-J1)


def test_r_pe_bench_28_1_at_most_one_bench_job_runs_at_any_time(tmp_path, defc_dir, monkeypatch):
    """Six BIG rows, six `down` at key repeat: the most I-2 calls ever running at once is 1. PARTIAL: BIG rows for
    20 LARGE rows. Negative control: one worker per selection overlaps the decodes (peak > 1)."""
    gate = Gate(monkeypatch, "decode_values", "encode_values")
    rows = tuple(f"BIG{i}" for i in range(6))
    a2l, s19 = big_case(tmp_path, BIG_COUNT, rows=rows)

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await pick(pilot, sheet, rows[0])
        await pilot.press(*(["down"] * 6))
        await wait_for(pilot, lambda: gate.running == 0 and has_values(sheet, sheet.selected_name), "the last decode", 90)
        await pilot.pause(0.5)
        return gate.peak, len(gate.calls)

    peak, calls = run(tmp_path, defc_dir, body, a2l=a2l, image=s19)
    assert calls >= 2, "control: more than one decode was requested"
    assert peak == 1, f"{peak} bench jobs ran at once"


def vm_kib(field: str) -> int:
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith(field + ":"):
            return int(line.split()[1])
    raise AssertionError(field)


@slow
def test_r_pe_bench_28_2_twenty_large_rows_and_twenty_down_keys_stay_within_320_mib(tmp_path, defc_dir):
    """20 LARGE rows over one shared image, 20 `down` at key repeat: peak RSS above the idle sheet <= 320 MiB.
    Linux only (`/proc/self/clear_refs` resets the peak). Load-sensitive in time, not in memory; the load is
    recorded."""
    if not Path("/proc/self/clear_refs").exists():
        pytest.skip("needs /proc/self/clear_refs (Linux): the peak RSS cannot be reset here")
    rows = tuple(f"LARGE{i:02d}" for i in range(20))
    a2l, s19 = big_case(tmp_path, LARGE_COUNT, rows=rows)

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await pick(pilot, sheet, rows[0])
        await pilot.pause(0.5)
        gc.collect()
        Path("/proc/self/clear_refs").write_text("5")
        idle = vm_kib("VmRSS")
        await pilot.press(*(["down"] * 20))
        await wait_for(pilot, lambda: has_values(sheet, sheet.selected_name), "the last row's decode", 240)
        return (vm_kib("VmHWM") - idle) / 1024

    above = run(tmp_path, defc_dir, body, a2l=a2l, image=s19)
    assert above <= 320, f"peak RSS {above:.0f} MiB above the idle sheet ({load()})"


# ------------------------------------------------------------------ R-PE-BENCH.29 (EX-J2), .82/1


@pytest.mark.serial_timing
@slow
def test_r_pe_bench_29_1_a_cursor_key_over_a_previewed_large_edit_is_handled_within_half_a_second(tmp_path, defc_dir):
    """Set `7` previewed over 4,096 cells of LARGE; `right` is handled in 0.5 s (quiet host, load recorded)."""
    a2l, s19 = big_case(tmp_path, LARGE_COUNT, rows=(LARGE,))

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await large_with_selection(pilot, sheet)
        await wait_for(pilot, lambda: previewed(sheet), "the preview result", 240)
        await pilot.pause(0.3)
        return await timed_press(pilot, "right"), await timed_press(pilot, "left")

    right, left = run(tmp_path, defc_dir, body, a2l=a2l, image=s19)
    assert max(right, left) <= report_margin(
        "R-PE-BENCH.29/1 cursor key over a LARGE preview", max(right, left), KEY_LIMIT_S
    ), f"right {right:.3f} s, left {left:.3f} s ({load()}); load-sensitive"


@pytest.mark.serial_timing
@slow
def test_r_pe_bench_29_2_a_cursor_key_while_the_preview_result_arrives_is_handled_within_one_second(tmp_path, defc_dir):
    """`right` pressed again and again while the preview result of LARGE is on its way: every press <= 1.0 s (relaxed from 0.5 s, operator decision F-X9-2),
    and more than two presses were made before the result arrived (so the arrival was inside the loop)."""
    a2l, s19 = big_case(tmp_path, LARGE_COUNT, rows=(LARGE,))

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await open_bench(pilot, sheet, LARGE)
        await pilot.press(*(["shift+right"] * 15 + ["shift+down"] * 255))
        await apply_tool(pilot, sheet, "s", "7")
        return await keys_until(pilot, sheet, "right", lambda: previewed(sheet))

    times = run(tmp_path, defc_dir, body, a2l=a2l, image=s19)
    assert len(times) > 2, f"the preview arrived after {len(times)} presses: the arrival was not exercised"
    assert max(times) <= report_margin(
        "R-PE-BENCH.29/2 cursor key while the preview arrives", max(times), RELAXED_KEY_LIMIT_S
    ), f"slowest press {max(times):.3f} s ({load()}); load-sensitive"


@pytest.mark.serial_timing
@slow
def test_r_pe_bench_82_1_a_key_is_handled_within_one_second_while_a_record_encode_runs(tmp_path, defc_dir):
    """LARGE, Set `7` on 256 x 16 cells, alt+s: `down` / `up` pressed until the record is written, each <= 1.0 s (relaxed from 0.5 s, operator decision F-X9-2)."""
    a2l, s19 = big_case(tmp_path, LARGE_COUNT, rows=(LARGE,))

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await large_with_selection(pilot, sheet)
        await wait_for(pilot, lambda: previewed(sheet), "the preview result", 240)
        await pilot.press("alt+s")
        times = await keys_until(pilot, sheet, "down", lambda: len(entries_of(app)) == 1)
        return times, entries_of(app)

    times, entries = run(tmp_path, defc_dir, body, a2l=a2l, image=s19)
    assert len(entries) == 1 and len(entries[0][1]) == LARGE_COUNT
    assert len(times) >= 1, "no press was measured while the record was written"
    assert max(times) <= report_margin(
        "R-PE-BENCH.82/1 key during a record encode", max(times), RELAXED_KEY_LIMIT_S
    ), f"slowest press {max(times):.3f} s ({load()}); load-sensitive"
