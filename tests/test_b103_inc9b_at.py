"""Batch-103 Inc 9b E4 (tester T9b-AT): the busy cue through the real app - the black-box cases of group AT.

Requirements: R-PE-BENCH.94/1-3, .97/1, .97/3, .98/1, .99/1, .100/3, .101/2, .101/5 (`inc-9b/02-test-cases.md`).
Operator need (P-127, verbatim): "Sobre el indicador de progreso, necesitamos tenerlo, de otra manera los usuarios
forzarán terminado de la aplicación." While the bench decodes, previews or stages a large object, the staging sheet
window must show that it is working (amber border and the BUSY pill with a moving spinner), stay live through the
record-stage write and refresh, and go back to its idle look on every way the job ends - or the user closes it.

Black box: the real ``S19TuiApp`` at 118 x 54 (``SIZE``), the Patch Editor as the operator opens it, keys sent
the way a terminal's input thread sends them (``Driver.send_message``; ``pilot.press`` waits for the whole process
to go idle, about 2.2 s while a worker thread computes, and would hide the very latency under test). The cue is
read from the compositor's painted top border row of ``#patch_sheet_win`` (never from ``border_title`` or
``styles``): the title text, and the colour of the painted top-left corner. The busy colour is
``Style.parse(definition_bench_view.EDIT).color`` (``EDIT`` is the style string ``"bold #f5c26b"``, not a colour).

Held jobs use Inc 9's ``Gate`` (a wrapper of I-2's ``encode_values``; the test releases it, the product's own encode
is what finally runs); LARGE (1,048,576 elements) runs its real decode. No sleep is an oracle: every wait is on a
painted state or an event the test controls.

LOAD-SENSITIVE (HT-08): every node here is a wall-clock arm (``serial_timing``) and is DECIDED only on a quiet
host, alone (``-n 0``); on any other host it is a record, not a verdict. The failure message carries the load.
The sampler reads the screen every ``SAMPLE_S`` seconds, so a measured gap is the true gap plus at most that.

Coverage of the AT group: 94/1, 94/2, 94/3, 97/1, 97/3, 98/1, 99/1, 100/3, 101/2, 101/5 (10 of 10). Not asserted
here (other groups): .94/4, .95-.96, .97/2, .98/2, .100/1-2, .101/1, /3, /4, /6, .102-.106.
"""
from __future__ import annotations

import asyncio
import dataclasses
import os
import re
import statistics
import threading
import time

import pytest
from rich.style import Style
from textual import events
from textual.geometry import Region
from textual.strip import Strip

from s19_app.tui.definition_bench_view import EDIT
from tests.support.b103_inc9_w import (  # noqa: F401  (defc_dir is a fixture used by name)
    INPUT, SIZE, VB, Gate, apply_tool, big_case, defc_dir, entries_of, has_values, need, open_bench, pick, run,
    service_of, sheet_of, st, wait_for,
)
from tests.support.timing import report_margin, timing_bound

LARGE = "LARGE"
SMALL = "SMALL_BLK"
LARGE_COUNT = 1048576
WIN = "#patch_sheet_win"
BUSY_HEX = Style.parse(EDIT).color.triplet.hex  # "#f5c26b": the colour of the bench's edit style, no new literal
SAMPLE_S = 0.01
IDLE_TITLE = "STAGING SHEET"
PILL = re.compile(r"([◐◓◑◒]) BUSY · (stage|decode|preview) (.+?) · (\d+\.\d) s · keys still work")
slow = pytest.mark.slow
timing = pytest.mark.serial_timing


def load() -> str:
    return "load " + " ".join(f"{x:.2f}" for x in os.getloadavg())


# ------------------------------------------------------------------ the painted top border row


@dataclasses.dataclass(frozen=True)
class Snap:
    """One reading of the painted screen: the time, the top border row of the staging sheet window, the colour of
    its painted top-left corner, the number of entries in the change document, and the rows of the whole screen
    except that border row (``screen``, only when asked for)."""

    t: float
    row: str
    corner: str
    entries: int
    screen: tuple = ()


def take(app, full: bool = False) -> Snap:
    """Read the painted screen now. The top border row is rendered through the compositor's own line path for that
    one row (0.8 ms; the whole screen is 5 ms and a query 5 ms, which would load the UI thread the cue ticks on);
    ``full`` renders the whole screen."""
    win = getattr(app, "_t9b_sheet_win", None)
    if win is None or win.app is not app:
        win = app._t9b_sheet_win = need(app.screen, WIN)
    region, compositor = win.region, app.screen._compositor
    chops = compositor._render_chops(Region(region.x, region.y, region.width, 1), lambda y: y == region.y)
    top = Strip.join(chops[region.y].values())
    row = "".join(seg.text for seg in top.crop(region.x, region.x + region.width))
    corner = ""
    for seg in top.crop(region.x, region.x + 1):
        if seg.text and seg.style is not None and seg.style.color is not None and seg.style.color.triplet:
            corner = seg.style.color.triplet.hex
    screen = ()
    if full:
        strips = compositor.render_strips()
        screen = tuple("".join(seg.text for seg in strip) for y, strip in enumerate(strips) if y != region.y)
    return Snap(time.monotonic(), row, corner, len(service_of(app).document.entries), screen)


def title_of(row: str) -> str:
    """The painted top border row without its corners and rule glyphs."""
    return row.strip("╭╮─ ")


def is_idle(s: Snap) -> bool:
    """The idle look: the title is exactly `STAGING SHEET` and the border is not the busy colour."""
    return title_of(s.row) == IDLE_TITLE and s.corner != BUSY_HEX


def titled(s: Snap, job: str, name: str) -> bool:
    """The busy title of ``job`` ``name`` is painted."""
    return "BUSY" in s.row and f"{job} {name}" in s.row


async def watch(app, until, end: float, full: bool = False) -> list:
    """Read the painted screen every ``SAMPLE_S`` seconds until ``until(snap, snaps)`` or the monotonic time ``end``."""
    out: list = []
    while True:
        out.append(take(app, full))
        if until(out[-1], out) or out[-1].t >= end:
            return out
        await asyncio.sleep(SAMPLE_S)


def send(app, key: str) -> float:
    """``key`` sent from a thread, as the terminal's input thread does (thread-safe: it posts with
    ``run_coroutine_threadsafe``); returns the monotonic time taken in that thread just before the send."""
    stamp: list = []

    def go() -> None:
        stamp.append(time.monotonic())
        app._driver.send_message(events.Key(key, None))

    thread = threading.Thread(target=go, daemon=True)
    thread.start()
    thread.join()
    return stamp[0]


class WriteWatch:
    """A thread that notes the monotonic time the change document first holds an entry (the record's write landed
    on the UI thread) and, when ``key`` is given, sends that key at once - 'pressed when the write step ends'."""

    def __init__(self, app, key: str | None = None):
        self.app, self.key, self.t_write = app, key, None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        while not self._stop.is_set():
            if len(service_of(self.app).document.entries) >= 1:
                self.t_write = time.monotonic()
                if self.key:
                    self.app._driver.send_message(events.Key(self.key, None))
                return
            time.sleep(0.0005)

    def start(self) -> "WriteWatch":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()


# ------------------------------------------------------------------ scenario drivers


def previewed(sheet, name: str) -> bool:
    """``name``'s preview RESULT is in (``"encoding"`` is the placeholder string from the apply until it arrives)."""
    preview = st(sheet, name).preview
    return preview is not None and not isinstance(preview, str)


async def vb_edit(pilot, sheet, key: str, operand: str) -> None:
    """VAL_BLK_DEF_0001's bench opened, ``key`` ``operand`` applied (focus back on the bench), its preview in."""
    await open_bench(pilot, sheet, VB)
    await apply_tool(pilot, sheet, key, operand)
    await wait_for(pilot, lambda: bool(st(sheet, VB).edit), f"the bench edit of {VB}")
    await wait_for(pilot, lambda: previewed(sheet, VB), f"the preview of {VB}", 60)


async def settled_idle(pilot, app, what: str) -> None:
    await wait_for(pilot, lambda: is_idle(take(app)), f"the idle look before {what}", 60)


async def large_decode_window(pilot, app, sheet, window_s: float):
    """SMALL_BLK selected and decoded, then LARGE selected by ONE `up` sent from a thread: its real decode runs
    (about 11 s). Reads the painted top border until the first LARGE busy title has been shown for ``window_s``
    seconds (0: until it is first shown), or the decode ends, or 6 s pass without any. Returns
    ``(t_send, snaps, t_first_title)``."""
    await pick(pilot, sheet, SMALL)
    await wait_for(pilot, lambda: has_values(sheet, SMALL), f"the values of {SMALL}", 90)
    await settled_idle(pilot, app, "the key to LARGE")
    first: list = []

    def until(s: Snap, out: list) -> bool:
        if not first and titled(s, "decode", LARGE):
            first.append(s.t)
        return bool(first) and (s.t - first[0] >= window_s or is_idle(s))

    t_send = send(app, "up")
    snaps = await watch(app, until, time.monotonic() + 6.0 + window_s)
    assert sheet.selected_name == LARGE, f"`up` did not select {LARGE}: {sheet.selected_name}"
    return t_send, snaps, (first[0] if first else None)


def title_changes(snaps: list, job: str, name: str) -> list:
    """``(t, row)`` of every reading whose busy title for ``job`` ``name`` differs from the previous busy one."""
    changes: list = []
    for s in snaps:
        if titled(s, job, name) and (not changes or changes[-1][1] != s.row):
            changes.append((s.t, s.row))
    return changes


# ------------------------------------------------------------------ R-PE-BENCH.94 (EX-BC1)


@pytest.mark.serial_timing
@slow
def test_r_pe_bench_94_1_large_selected_shows_the_busy_border_and_title_within_half_a_second(tmp_path, defc_dir):
    """R-PE-BENCH.94/1. LARGE selected by a key (its real decode runs): the painted top border holds a busy title
    with `decode LARGE` and the border corner is the busy colour #f5c26b, first painted 0.2-0.5 s after the key.
    Operator need (P-127): while LARGE decodes the window must say it is working, or the user forces the app closed.
    Negative control: no cue tick -> never shown (RED); grace 0 -> shown before 0.2 s (RED)."""
    a2l, s19 = big_case(tmp_path, LARGE_COUNT, rows=(LARGE,))

    async def body(app, pilot, panel):
        return await large_decode_window(pilot, app, sheet_of(panel), 0.0)

    t_send, snaps, first = run(tmp_path, defc_dir, body, size=SIZE, a2l=a2l, image=s19)
    last = snaps[-1]
    assert first is not None, f"no `decode LARGE` busy title within 6 s of the key; last top row {last.row!r} ({load()})"
    seen = next(s for s in snaps if s.t == first)
    assert seen.corner == BUSY_HEX, f"title shown but the painted corner is {seen.corner}, not {BUSY_HEX}: {seen.row!r}"
    latency = first - t_send
    assert 0.2 <= latency, f"cue shown {latency:.3f} s after the key, before the 0.2 s grace ({load()})"
    assert latency <= report_margin("R-PE-BENCH.94/1 cue after the key", latency, timing_bound(0.5)), (
        f"cue shown {latency:.3f} s after the key ({load()}); load-sensitive, unverified on a loaded host"
    )


@pytest.mark.serial_timing
def test_r_pe_bench_94_2_a_gated_preview_shows_the_busy_title_within_half_a_second_of_enter(tmp_path, defc_dir, monkeypatch):
    """R-PE-BENCH.94/2. VAL_BLK_DEF_0001 with +Delta 5 applied by Enter, its preview encode held by the test: the
    painted top border holds `preview VAL_BLK_DEF_0001` with the busy corner within 0.5 s of that Enter.
    Operator need (P-127): a held preview must not look like a frozen window. Negative control: a cue keyed
    only on the decode job shows nothing for a preview (RED)."""
    gate = Gate(monkeypatch, "encode_values")

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        try:
            await open_bench(pilot, sheet, VB)
            gate.hold.add(VB)
            await pilot.press("d", "enter")
            await pilot.pause()
            assert getattr(app.focused, "id", None) == "patch_sheet_input", "Enter did not reach the op input"
            need(sheet, INPUT).value = "5"
            await pilot.pause()
            t_enter = send(app, "enter")
            snaps = await watch(app, lambda s, o: titled(s, "preview", VB), t_enter + 1.0)
            return t_enter, snaps, gate.entered.is_set()
        finally:
            gate.release()

    t_enter, snaps, held = run(tmp_path, defc_dir, body)
    seen = next((s for s in snaps if titled(s, "preview", VB)), None)
    assert held, "control: the preview's encode never reached the gate, so no preview job was running"
    assert seen is not None, f"no `preview {VB}` busy title within 1.0 s of Enter; last top row {snaps[-1].row!r} ({load()})"
    assert seen.corner == BUSY_HEX, f"title shown but the painted corner is {seen.corner}: {seen.row!r}"
    latency = seen.t - t_enter
    assert latency <= report_margin("R-PE-BENCH.94/2 preview cue after Enter", latency, timing_bound(0.5)), (
        f"preview cue {latency:.3f} s after Enter ({load()}); load-sensitive, unverified on a loaded host"
    )


@pytest.mark.serial_timing
def test_r_pe_bench_94_3_a_gated_record_stage_shows_the_busy_title_within_half_a_second_of_alt_s(tmp_path, defc_dir, monkeypatch):
    """R-PE-BENCH.94/3. VAL_BLK_DEF_0001 with Set `10` previewed, then alt+s with the record's encode held by the
    test: the painted top border holds `stage VAL_BLK_DEF_0001` with the busy corner within 0.5 s of alt+s.
    Operator need (P-127): a record stage must show it is working from its first second. Negative control: a cue
    that only covers decode and preview shows nothing (RED)."""
    gate = Gate(monkeypatch, "encode_values")

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        try:
            await vb_edit(pilot, sheet, "s", "10")
            gate.hold.add(VB)
            t_key = send(app, "alt+s")
            snaps = await watch(app, lambda s, o: titled(s, "stage", VB), t_key + 1.0)
            return t_key, snaps, gate.entered.is_set(), entries_of(app)
        finally:
            gate.release()

    t_key, snaps, held, entries = run(tmp_path, defc_dir, body)
    seen = next((s for s in snaps if titled(s, "stage", VB)), None)
    assert held, "control: the record's encode never reached the gate, so no record stage was running"
    assert entries == [], f"control: the record was written while its encode was held: {entries}"
    assert seen is not None, f"no `stage {VB}` busy title within 1.0 s of alt+s; last top row {snaps[-1].row!r} ({load()})"
    assert seen.corner == BUSY_HEX, f"title shown but the painted corner is {seen.corner}: {seen.row!r}"
    latency = seen.t - t_key
    assert latency <= report_margin("R-PE-BENCH.94/3 stage cue after alt+s", latency, timing_bound(0.5)), (
        f"stage cue {latency:.3f} s after alt+s ({load()}); load-sensitive, unverified on a loaded host"
    )


# ------------------------------------------------------------------ R-PE-BENCH.97 (EX-BC5)


@timing
@slow
def test_r_pe_bench_97_1_every_tick_of_larges_real_decode_paints_a_different_title(tmp_path, defc_dir):
    """R-PE-BENCH.97/1. LARGE's real decode, 5 s from the cue's first tick: the painted busy titles keep changing
    - at least one change per 0.5 s (the max-gap bound of .97/3, so at least 10 in 5 s), and between any two
    successive painted titles the spinner glyph differs and the pending time does not go back.
    Operator need (P-127): a cue painted once looks like a frozen window and the user forces the app closed.
    Negative control: the title painted once when the cue appears -> 1 change (RED); the decode on the UI
    thread -> max gap about 10 s (RED)."""
    a2l, s19 = big_case(tmp_path, LARGE_COUNT, rows=(LARGE,))

    async def body(app, pilot, panel):
        return await large_decode_window(pilot, app, sheet_of(panel), 5.0)

    _, snaps, first = run(tmp_path, defc_dir, body, size=SIZE, a2l=a2l, image=s19)
    assert first is not None, f"no `decode LARGE` busy title within 6 s of the key; last top row {snaps[-1].row!r} ({load()})"
    window = [s for s in snaps if s.t >= first]
    changes = title_changes(window, "decode", LARGE)
    span = window[-1].t - first
    assert span >= 4.5, f"the window ended after {span:.1f} s (the decode ended early?); {len(changes)} changes ({load()})"
    assert len(changes) >= int(5.0 / 0.5), f"{len(changes)} distinct busy titles in {span:.1f} s: the cue is not ticking ({load()})"
    for (_, before), (_, after) in zip(changes, changes[1:]):
        b, a = PILL.search(before), PILL.search(after)
        assert b and a, f"a busy title does not hold the pill: {before!r} / {after!r}"
        assert b.group(1) != a.group(1), f"two successive titles keep the spinner frame {a.group(1)}: {before!r} / {after!r}"
        assert float(a.group(4)) >= float(b.group(4)), f"the pending time went back: {before!r} / {after!r}"


@pytest.mark.serial_timing
@slow
def test_r_pe_bench_97_3_the_gaps_between_changed_titles_stay_within_the_bounds(tmp_path, defc_dir):
    """R-PE-BENCH.97/3. LARGE's real decode, 5 s from the cue's first tick: the gaps between successive changed
    painted titles have a median <= 0.2 s and a maximum <= 0.5 s (prototype: median 0.12-0.17, max 0.38-0.45).
    Operator need (P-127): the spinner must move steadily so the user can see the window is alive.
    Negative control: the decode run on the UI thread -> max gap about 10 s (RED)."""
    a2l, s19 = big_case(tmp_path, LARGE_COUNT, rows=(LARGE,))

    async def body(app, pilot, panel):
        return await large_decode_window(pilot, app, sheet_of(panel), 5.0)

    _, snaps, first = run(tmp_path, defc_dir, body, size=SIZE, a2l=a2l, image=s19)
    assert first is not None, f"no `decode LARGE` busy title within 6 s of the key; last top row {snaps[-1].row!r} ({load()})"
    changes = title_changes([s for s in snaps if s.t >= first], "decode", LARGE)
    assert len(changes) >= 2, f"{len(changes)} distinct busy titles: no gap to measure ({load()})"
    gaps = [b[0] - a[0] for a, b in zip(changes, changes[1:])]
    median, worst = statistics.median(gaps), max(gaps)
    assert median <= report_margin("R-PE-BENCH.97/3 median gap", median, timing_bound(0.2)), (
        f"median gap {median:.3f} s over {len(gaps)} gaps ({load()}); load-sensitive, unverified on a loaded host"
    )
    assert worst <= report_margin("R-PE-BENCH.97/3 max gap", worst, timing_bound(0.5)), (
        f"max gap {worst:.3f} s over {len(gaps)} gaps ({load()}); load-sensitive, unverified on a loaded host"
    )


# ------------------------------------------------------------------ R-PE-BENCH.98 (EX-BC6), .99 (EX-BC7)


async def large_record_ready(pilot, sheet) -> None:
    """LARGE decoded, a 4,096-cell selection (16 columns x 256 rows), Set `7` applied and previewed."""
    await open_bench(pilot, sheet, LARGE)
    await pilot.press(*(["shift+right"] * 15 + ["shift+down"] * 255))
    await apply_tool(pilot, sheet, "s", "7")
    await wait_for(pilot, lambda: previewed(sheet, LARGE), "the preview result", 240)
    await pilot.pause(0.3)


@pytest.mark.serial_timing
@slow
def test_r_pe_bench_98_1_the_cue_keeps_ticking_through_the_write_and_refresh_of_a_large_record(tmp_path, defc_dir):
    """R-PE-BENCH.98/1. LARGE, Set `7` on 256 x 16 cells, alt+s: from the moment the record's write lands in the
    change document until the cue leaves, the painted busy title changes at least once (a tick runs between the
    write and the end of the refresh) and no gap between the write, the changed titles and the leave exceeds 0.5 s.
    Operator need (P-127): the 0.67 s one-call refresh froze the cue at its end; the user must see it alive.
    Negative control: the write and refresh in one UI-thread call (base: 0.674 s) -> max gap >= 0.67 s (RED)."""
    a2l, s19 = big_case(tmp_path, LARGE_COUNT, rows=(LARGE,))

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await large_record_ready(pilot, sheet)
        watcher = WriteWatch(app).start()
        mark: dict = {}

        def until(s: Snap, out: list) -> bool:
            if s.entries >= 1:
                mark.setdefault("t", s.t)
            busy = any("BUSY" in o.row for o in out)
            return s.entries >= 1 and is_idle(s) and (busy or s.t - mark["t"] > 1.5)

        try:
            send(app, "alt+s")
            return await watch(app, until, time.monotonic() + 180.0), watcher
        finally:
            watcher.stop()

    snaps, watcher = run(tmp_path, defc_dir, body, size=SIZE, a2l=a2l, image=s19)
    assert watcher.t_write is not None, "the record was never written"
    after = [s for s in snaps if s.t >= watcher.t_write]
    assert any("BUSY" in s.row for s in after), f"no busy title after the write; last top row {after[-1].row!r} ({load()})"
    changes = title_changes(after, "stage", LARGE)
    assert len(changes) >= 2, f"no second painted busy title ran between the write and the end of the refresh ({load()})"
    leave = next((s.t for s in after if is_idle(s)), after[-1].t)
    marks = [watcher.t_write] + [t for t, _ in changes] + [leave]
    gaps = [b - a for a, b in zip(marks, marks[1:])]
    worst = max(gaps)
    assert worst <= report_margin("R-PE-BENCH.98/1 max gap write-to-leave", worst, timing_bound(0.5)), (
        f"max gap {worst:.3f} s over {len(gaps)} gaps from the write to the leave ({load()}); load-sensitive"
    )


@pytest.mark.serial_timing
@slow
def test_r_pe_bench_99_1_a_key_pressed_when_the_write_step_ends_is_handled_within_one_second(tmp_path, defc_dir):
    """R-PE-BENCH.99/1. R-PE-BENCH.98/1's scenario, `down` sent the moment the record's write lands in the change
    document: the bench handles it (the sheet's key action returns) within 1.0 s of that write.
    Operator need (P-127): the pill says "keys still work"; a window that ignores keys through the refresh makes
    the user force the app closed. The base's one-call block is 0.67 s, inside the bound, so this node is a
    guard on base; its negative control is a 1.3 s stall added to one refresh step (RED)."""
    a2l, s19 = big_case(tmp_path, LARGE_COUNT, rows=(LARGE,))

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await large_record_ready(pilot, sheet)
        handled: list = []
        real = sheet.action_move

        def timed(*args):
            real(*args)
            handled.append(time.monotonic())

        sheet.action_move = timed
        watcher = WriteWatch(app, "down").start()
        try:
            send(app, "alt+s")
            await wait_for(pilot, lambda: bool(handled), "the `down` sent at the write to be handled", 180)
        finally:
            watcher.stop()
            del sheet.action_move
        return watcher.t_write, handled[0]

    t_write, t_handled = run(tmp_path, defc_dir, body, size=SIZE, a2l=a2l, image=s19)
    latency = t_handled - t_write
    assert latency <= report_margin("R-PE-BENCH.99/1 key at the write step", latency, timing_bound(1.0)), (
        f"`down` handled {latency:.3f} s after the write ({load()}); load-sensitive, unverified on a loaded host"
    )


# ------------------------------------------------------------------ R-PE-BENCH.100/3 (EX-BC8), .101/2 and /5 (EX-BC9)


@pytest.mark.serial_timing
def test_r_pe_bench_100_3_a_written_record_returns_the_window_to_its_idle_look_within_0_3_s_of_the_last_step(tmp_path, defc_dir, monkeypatch):
    """R-PE-BENCH.100/3. VAL_BLK_DEF_0001 with Set `10` previewed, alt+s with its encode held past the grace (the
    `stage VAL_BLK_DEF_0001` cue is painted), then released: the document gets its entry and the window is idle
    (border not amber, title exactly `STAGING SHEET`) within 0.3 s of the last change the screen painted before it.
    Operator need (P-127): a cue left on after the job ended says the window is still working.
    Negative control: the inline border left or the last busy title left -> never idle (RED)."""
    gate = Gate(monkeypatch, "encode_values")

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        try:
            await vb_edit(pilot, sheet, "s", "10")
            gate.hold.add(VB)
            t_key = send(app, "alt+s")
            cue = await watch(app, lambda s, o: titled(s, "stage", VB), t_key + 2.0)
            held = gate.entered.is_set()
            if not titled(cue[-1], "stage", VB):
                return cue, [], entries_of(app), held
        finally:
            gate.release()
        done = await watch(app, lambda s, o: s.entries >= 1 and is_idle(s), time.monotonic() + 30.0, full=True)
        return cue, done, entries_of(app), held

    cue, done, entries, held = run(tmp_path, defc_dir, body)
    assert held, "control: the record's encode never reached the gate, so no record stage was running"
    assert titled(cue[-1], "stage", VB), f"precondition: no `stage {VB}` cue while held; last top row {cue[-1].row!r} ({load()})"
    assert cue[-1].corner == BUSY_HEX, f"precondition: cue title without the busy corner: {cue[-1].corner}"
    assert len(entries) == 1, f"the record was not written: {entries}"
    leave = done[-1]
    assert is_idle(leave), f"the window never returned to its idle look; last top row {leave.row!r}, corner {leave.corner}"
    assert title_of(leave.row) == IDLE_TITLE
    changed = [b.t for a, b in zip(done, done[1:]) if a.screen != b.screen]
    last_step = max([t for t in changed if t <= leave.t], default=done[0].t)
    lag = leave.t - last_step
    assert lag <= report_margin("R-PE-BENCH.100/3 idle after the last step", lag, timing_bound(0.3)), (
        f"idle look {lag:.3f} s after the last painted change ({load()}); load-sensitive, unverified on a loaded host"
    )


async def idle_after_release(app, gate) -> tuple:
    """The gate released: the time of the release, and the screen read until the idle look is painted."""
    t_release = time.monotonic()
    gate.release()
    done = await watch(app, lambda s, o: is_idle(s), t_release + 5.0)
    return t_release, done


@pytest.mark.serial_timing
def test_r_pe_bench_101_2_a_record_refused_by_its_encode_returns_the_window_to_its_idle_look_within_0_3_s(tmp_path, defc_dir, monkeypatch):
    """R-PE-BENCH.101/2. VAL_BLK_DEF_0001 with Set `60` (outside the limits -50..50, R-PE-BENCH.74), alt+s with
    the record's encode held past the grace (the `stage` cue is painted), then released: the encode refuses and
    the window is back to its idle look within 0.3 s of the release and stays idle.
    Operator need (P-127): a cue left on after a refusal looks like a hung stage and the user forces the app closed.
    Negative control: the cue cleared only on success -> still busy after the refusal (RED)."""
    gate = Gate(monkeypatch, "encode_values")

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        try:
            await vb_edit(pilot, sheet, "s", "60")
            gate.hold.add(VB)
            t_key = send(app, "alt+s")
            cue = await watch(app, lambda s, o: titled(s, "stage", VB), t_key + 2.0)
            held = gate.entered.is_set()
            if not titled(cue[-1], "stage", VB):
                return cue, 0.0, [], [], entries_of(app), held
            t_release, done = await idle_after_release(app, gate)
            after = await watch(app, lambda s, o: False, time.monotonic() + 0.5)
            return cue, t_release, done, after, entries_of(app), held
        finally:
            gate.release()

    result = run(tmp_path, defc_dir, body)
    cue, t_release, done = result[0], result[1], result[2]
    assert result[5], "control: the record's encode never reached the gate, so no record stage was running"
    assert titled(cue[-1], "stage", VB), f"precondition: no `stage {VB}` cue while held; last top row {cue[-1].row!r} ({load()})"
    assert is_idle(done[-1]), f"no idle look within 5 s of the release; last top row {done[-1].row!r}, corner {done[-1].corner}"
    lag = done[-1].t - t_release
    assert lag <= report_margin("R-PE-BENCH.101/2 idle after a refused record", lag, timing_bound(0.3)), (
        f"idle look {lag:.3f} s after the release ({load()}); load-sensitive, unverified on a loaded host"
    )
    assert all(is_idle(s) for s in result[3]), "the cue came back after the refusal (the record hold was kept?)"
    assert result[4] == [], f"a refused record was written: {result[4]}"


@pytest.mark.serial_timing
def test_r_pe_bench_101_5_a_record_made_stale_by_an_undo_returns_the_window_to_its_idle_look_within_0_3_s(tmp_path, defc_dir, monkeypatch):
    """R-PE-BENCH.101/5. A first record staged (Set `10`), then Set `12` with its encode held past the grace (the
    `stage` cue is painted), the Undo button pressed while it encodes (R-PE-BENCH.78), the encode released: the
    stale result is dropped and the window is back to its idle look within 0.3 s of the release and stays idle.
    Operator need (P-127): a cue left on after a stale record looks like a hung stage.
    Negative control: the cue cleared only on a written record -> still busy (RED)."""
    gate = Gate(monkeypatch, "encode_values")

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        try:
            await vb_edit(pilot, sheet, "s", "10")
            await pilot.press("alt+s")
            await wait_for(pilot, lambda: len(entries_of(app)) == 1, "the first record staged", 60)
            await pilot.pause(1.5)
            await apply_tool(pilot, sheet, "s", "12")
            await wait_for(pilot, lambda: dict(st(sheet, VB).edit) == {(0, 0): "12"}, "the Set 12 edit")
            await wait_for(pilot, lambda: previewed(sheet, VB), "the Set 12 preview", 60)
            await settled_idle(pilot, app, "the second alt+s")
            gate.hold.add(VB)
            t_key = send(app, "alt+s")
            cue = await watch(app, lambda s, o: titled(s, "stage", VB), t_key + 2.0)
            held = gate.entered.is_set()
            if not titled(cue[-1], "stage", VB):
                return cue, 0.0, [], [], entries_of(app), held
            need(panel, "#patch_undo_button").press()
            await wait_for(pilot, lambda: entries_of(app) == [], "the undo", 30)
            t_release, done = await idle_after_release(app, gate)
            after = await watch(app, lambda s, o: False, time.monotonic() + 0.5)
            return cue, t_release, done, after, entries_of(app), held
        finally:
            gate.release()

    result = run(tmp_path, defc_dir, body)
    cue, t_release, done = result[0], result[1], result[2]
    assert result[5], "control: the record's encode never reached the gate, so no record stage was running"
    assert titled(cue[-1], "stage", VB), f"precondition: no `stage {VB}` cue while held; last top row {cue[-1].row!r} ({load()})"
    assert is_idle(done[-1]), f"no idle look within 5 s of the release; last top row {done[-1].row!r}, corner {done[-1].corner}"
    lag = done[-1].t - t_release
    assert lag <= report_margin("R-PE-BENCH.101/5 idle after a stale record", lag, timing_bound(0.3)), (
        f"idle look {lag:.3f} s after the release ({load()}); load-sensitive, unverified on a loaded host"
    )
    assert all(is_idle(s) for s in result[3]), "the cue came back after the stale result (the record hold was kept?)"
    assert result[4] == [], f"the stale record's bytes were written: {result[4]}"
