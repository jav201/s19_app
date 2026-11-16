"""Batch-103 Inc 9b E4 (tester T9b-W): the bench busy cue - the border and the BUSY pill of the staging sheet window.

Requirements: R-PE-BENCH.94/4, .95, .96, .97/2, .100/1-2, .101/1, .101/6, .102, .103, .104, .105 (Group W of
``inc-9b/02-test-cases.md``). The operator's need (P-127, verbatim): "necesitamos tenerlo [el indicador de
progreso], de otra manera los usuarios forzarán terminado de la aplicación" - while the bench decodes or previews a
large object the window must say that it is working, and it must stop saying so the moment the job is over.

Every node drives the shipped chain (the real ``S19TuiApp`` under Textual Pilot, the Patch Editor as the operator
opens it, keys through ``pilot.press``) and reads the PAINTED top border of ``#patch_sheet_win`` through
``tests.b97_probes`` (``painted_rows`` / ``painted_style``), never ``styles`` alone: a cleared inline rule shows the
stylesheet value in ``styles`` while the screen still paints amber (E4-pilots.md P2). Nothing is read from the product's
new functions (``busy_job``, ``busy_title``, ``_busy_tick``): they are exercised through the existing entry points
(selection keys, the apply keys, ``show_page``, ``record_done`` by the stage) so a base without them fails by
assertion, not by import.

Jobs are held by ``Gate`` (Inc 9's wrapper of I-2's ``decode_values`` / ``encode_values``) and released by the test;
no sleep is an oracle. A timing bound is the case's own number (0.3 s, 0.5 s), never a looser one; the result of a job
is timed from the entry of the sheet's own ``_job_done`` (a stamp taken by a wrapper of that method), the ask from
``_enqueue``. LOAD-SENSITIVE (HT-08): the timing nodes are ``serial_timing`` and are decided on a quiet host only;
each timing message carries ``os.getloadavg()``.

Pill style and room (``E4-pilots.md`` P3): busy colour ``#f5c26b``, pill foreground ``#0a0e1b``, room B = the window's
content width - 4 = 66 / 106 / 190 at 80 / 118 / 220 columns.
"""
from __future__ import annotations

import os
import re
import threading
import time

import pytest
from textual import events

from s19_app.tui.a2l_definition import describe_definitions
from tests.b97_probes import painted_rows, painted_style
from tests.support.b103_inc8_p import MIN_SIZE, SIZE, WIDE
from tests.support.b103_inc9_w import (  # noqa: F401  (defc_dir is a fixture used by name)
    CURVE, DISPLAY, MAP, VB, Gate, apply_tool, defc_dir, entries_of, has_values, hand_case, need, open_bench, pick, run,
    sheet_of, st, valblk_block, wait_for,
)
from tests.support.timing import report_margin, timing_bound

WIN = "#patch_sheet_win"
FILTER = "#patch_param_filter"
BUSY_HEX = "#f5c26b"
PILL_FG = "#0a0e1b"
FRAMES = "◐◓◑◒"
IDLE_TITLE = "STAGING SHEET"
COUNT = 5000  # a bench-sized VAL_BLK: the job logic is what is under test, and a held job is released by the test
GRACE_S = 0.2
TITLE = re.compile(r"STAGING SHEET {3}([◐◓◑◒]) BUSY · (decode|preview|stage) (.*?) · (\d+\.\d) s · keys still work ")


def load() -> str:
    return "load " + " ".join(f"{x:.2f}" for x in os.getloadavg())


# ------------------------------------------------------------------ the painted window (never ``styles`` alone)


def win_of(app):
    return need(app.screen, WIN)


def top_row(app) -> str:
    """The painted top border row of the staging sheet window (compositor strips)."""
    win = win_of(app)
    rows = painted_rows(app, win)
    row = rows[0] if rows and win.region.height else ""
    if "╭" not in row:  # the panel scrolled by the focus under the ribbon (80x24): bring the window's top into view
        win.scroll_visible(animate=False, top=True)
    return row


def border_hex(app):
    """The painted foreground of the window's top-left corner cell, as ``#rrggbb`` (None when unpainted)."""
    win = win_of(app)
    style = painted_style(app, win.region.x, win.region.y)
    if style is None or style.color is None or style.color.triplet is None:
        return None
    return style.color.triplet.hex.lower()


def cell_style(app, needle: str):
    """The painted style of the first cell of ``needle`` in the top border row, else None."""
    win, row = win_of(app), top_row(app)
    at = row.find(needle)
    return None if at < 0 else painted_style(app, win.region.x + at, win.region.y)


def busy_now(app) -> bool:
    return "BUSY" in top_row(app)


def cue_now(app, word: str, name: str) -> bool:
    """The painted cue names ``word name`` and the border is the busy colour."""
    return f"BUSY · {word} {name} · " in top_row(app) and border_hex(app) == BUSY_HEX


def idle_now(app) -> bool:
    """The idle look: the title ``STAGING SHEET`` with no pill, and a border that is not the busy colour."""
    row = top_row(app)
    return IDLE_TITLE in row and "BUSY" not in row and border_hex(app) != BUSY_HEX


def prime(app) -> None:
    """The window in view (at 80x24 the panel scrolls, R-TUI-064.3)."""
    win_of(app).scroll_visible(animate=False)


async def until(pilot, predicate, bound: float, step: float = 0.01):
    """Seconds until ``predicate()`` held, polling the painted screen every ``step``; None at ``bound``."""
    start = time.monotonic()
    while True:
        if predicate():
            return time.monotonic() - start
        if time.monotonic() - start >= bound:
            return None
        await pilot.pause(step)


# ------------------------------------------------------------------ the sheet's own clock (stamps, no product hook)


class Stamps:
    """Wrappers of the sheet's ``_enqueue`` (the ask) and ``_job_done`` (the result handling): ``asked`` and ``done``
    hold the monotonic time of the LAST call per (kind, name). ``on_ask`` maps a (kind, name) to a function called at
    that ask (a gate released by a timer started AT the ask, whatever the test coroutine is doing). Instance
    attributes, removed by ``close``."""

    def __init__(self, sheet, on_ask=None):
        self.sheet, self.asked, self.done = sheet, {}, {}
        real_enqueue, real_done = sheet._enqueue, sheet._job_done
        on_ask = on_ask or {}

        def enqueue(kind, name, *args, **kwargs):
            self.asked[(kind, name)] = time.monotonic()
            if (kind, name) in on_ask:
                on_ask[(kind, name)]()
            return real_enqueue(kind, name, *args, **kwargs)

        def job_done(kind, name, *args, **kwargs):
            self.done[(kind, name)] = time.monotonic()
            return real_done(kind, name, *args, **kwargs)

        sheet._enqueue, sheet._job_done = enqueue, job_done

    def close(self) -> None:
        for attribute in ("_enqueue", "_job_done"):
            self.sheet.__dict__.pop(attribute, None)


class RaisingGate(Gate):
    """``Gate`` whose held call RAISES after its release for the names in ``boom`` (a worker that raises: the job
    hands back ``None``, ``bench_sheet.py`` ``except Exception``)."""

    def __init__(self, monkeypatch, *functions, hold=(), boom=()):
        self.boom = set(boom)
        super().__init__(monkeypatch, *functions, hold=hold)

    def _begin(self, function: str, name: str) -> bool:
        outer = super()._begin(function, name)
        if outer and name in self.boom:
            self._end(True)
            raise RuntimeError("the worker raises (T9b-W)")
        return outer


# ------------------------------------------------------------------ scenario builders


def case(tmp_path, *names, count: int = COUNT):
    """A hand A2L of ``names`` (VAL_BLK rows of ``count`` UBYTE over one zero image) and its S19 image."""
    return hand_case(tmp_path, [valblk_block(name, 0x100000, count) for name in names], [(0x100000, bytes(count))])


async def decoded(pilot, sheet, *names) -> None:
    """The page's startup work is over: a row of the page has its values and the job queue is empty, so no job of the
    page starts under a later hold (a scalar first row, as DEFC's ENUM_0001, never has values)."""
    await pilot.pause(1.0)
    await wait_for(pilot, lambda: any(has_values(sheet, row.name) for row in sheet.rows), "a row with its values", 90)
    await wait_for(
        pilot, lambda: sheet._active_job is None and not sheet._slot and not sheet._page, "the job queue idle", 90
    )
    await pilot.pause(0.3)


async def reselect(pilot, sheet, target: str, away: str) -> None:
    """Select ``away``, then ``target`` with the arrow keys: the selection of ``target`` asks its decode afresh."""
    await pick(pilot, sheet, away)
    await pick(pilot, sheet, target)


async def move_to(pilot, sheet, name: str) -> float:
    """Arrow keys to ``name``; the monotonic time just before the last key press."""
    names = [row.name for row in sheet.rows]
    at = time.monotonic()
    for _ in range(len(names) + 2):
        if sheet.selected_name == name:
            return at
        at = time.monotonic()
        await pilot.press("down" if names.index(name) > names.index(sheet.selected_name) else "up")
        await pilot.pause()
    assert sheet.selected_name == name, f"could not select {name}"
    return at


async def cue_shown(pilot, app, word: str, name: str, bound: float = 3.0) -> float:
    took = await until(pilot, lambda: cue_now(app, word, name), bound)
    assert took is not None, (
        f"no busy cue `{word} {name}` (colour {BUSY_HEX}) within {bound} s of the ask; "
        f"top border {top_row(app)!r}, painted corner {border_hex(app)} ({load()})"
    )
    return took


async def idle_after_result(pilot, app, stamps, key, bound: float) -> float:
    """Seconds from the entry of ``_job_done(*key)`` to the first poll that sees the idle look (the job must have
    ended: the caller released its gate). The stamp is taken BEFORE the sheet handles the result, so the figure is
    never shorter than the truth."""
    await wait_for(pilot, lambda: key in stamps.done, f"the result of {key}", 60)
    done_at = stamps.done[key]
    took = await until(pilot, lambda: idle_now(app), max(0.0, done_at + bound - time.monotonic()) + 0.5)
    seen_at = time.monotonic()
    assert took is not None and seen_at - done_at <= report_margin(
        f"R-PE-BENCH idle after {key[0]} {key[1]}", seen_at - done_at, bound
    ), (
        f"the idle look came {seen_at - done_at:.3f} s after the result of {key} (bound {bound} s, {load()}); "
        f"top border {top_row(app)!r}, painted corner {border_hex(app)}"
    )
    return seen_at - done_at


# ------------------------------------------------------------------ R-PE-BENCH.94/4 (EX-BC2)


@pytest.mark.serial_timing
def test_r_pe_bench_94_4_a_queued_decode_shows_its_cue_while_another_rows_summary_runs(tmp_path, defc_dir, monkeypatch):
    """R-PE-BENCH.94/4, EX-BC2: LARGE is selected while another row's summary decode is gated running, so LARGE's own
    decode has not started: the cue still shows `decode LARGE`, within 0.5 s of the ask. Operator need (P-127): the
    window that waits for a queued decode must still say it is working. Negative control: a cue keyed on the running
    job shows nothing for the queued row."""
    a2l, s19 = case(tmp_path, "LARGE", "MID", "ZZZ")
    gate = Gate(monkeypatch, "decode_values")

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        prime(app)
        await decoded(pilot, sheet, "LARGE", "MID", "ZZZ")
        stamps = Stamps(sheet)
        try:
            # a page turn that drops LARGE and MID: both are new on the next page, their summaries are held
            definitions = describe_definitions(["ZZZ"], app.current_a2l_data)
            sheet.show_page(["ZZZ"], definitions, app.current_a2l_data, app.current_file.mem_map)
            await pilot.pause(0.2)
            gate.hold.update({"LARGE", "MID"})
            both = ["LARGE", "MID"]
            sheet.show_page(both, describe_definitions(both, app.current_a2l_data), app.current_a2l_data,
                            app.current_file.mem_map)
            await wait_for(pilot, gate.entered.is_set, "a summary held in its worker", 20)
            running = gate.calls[-1][1]
            target = "MID" if running == "LARGE" else "LARGE"
            assert gate.running == 1 and running in both, (gate.calls, gate.running)
            if sheet.selected_name != target:
                await pick(pilot, sheet, target)
            asked = stamps.asked.get(("decode", target))
            assert asked is not None, f"selecting {target} did not ask its decode: {sorted(stamps.asked)}"
            deadline = timing_bound(0.5)
            took = await until(pilot, lambda: cue_now(app, "decode", target), max(0.0, asked + deadline - time.monotonic()))
            seen = time.monotonic() - asked
            return took, seen, target, running, top_row(app), border_hex(app), gate.running
        finally:
            gate.release()
            stamps.close()

    took, seen, target, running, row, colour, running_now = run(tmp_path, defc_dir, body, a2l=a2l, image=s19)
    assert took is not None and seen <= report_margin(
        "R-PE-BENCH.94/4 queued decode cue", seen, timing_bound(0.5)
    ), (
        f"no cue `decode {target}` within 0.5 s of its ask while {running}'s summary ran (running={running_now}, {load()}); "
        f"top border {row!r}, painted corner {colour}"
    )
    assert f"decode {running}" not in row, row


# ------------------------------------------------------------------ R-PE-BENCH.95 (EX-BC3): idle below the grace


@pytest.mark.serial_timing
def test_r_pe_bench_95_0_control_a_decode_held_past_the_grace_does_paint_the_cue(tmp_path, defc_dir, monkeypatch):
    """Oracle control for R-PE-BENCH.95: the reader used by 95/1 and 95/2 CAN see a cue. MAP_DEF_0001's decode is held
    0.6 s (> the 0.2 s grace): the painted border is the busy colour with `BUSY` in the title, then the idle look.
    Without this node 95/1 and 95/2 pass on any product whose reader never sees amber (a vacuous idle check)."""
    gate = Gate(monkeypatch, "decode_values")

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        prime(app)
        await decoded(pilot, sheet, MAP)
        stamps = Stamps(sheet)
        try:
            gate.hold.add(MAP)
            await reselect(pilot, sheet, MAP, DISPLAY)
            await cue_shown(pilot, app, "decode", MAP)
            gate.release()
            await idle_after_result(pilot, app, stamps, ("decode", MAP), 5.0)
        finally:
            gate.release()
            stamps.close()

    run(tmp_path, defc_dir, body)


def test_r_pe_bench_95_1_a_decode_that_ends_inside_the_grace_never_paints_the_cue(tmp_path, defc_dir, monkeypatch):
    """R-PE-BENCH.95/1, EX-BC3: MAP_DEF_0001's decode is gated 0.15 s after its ask, then released: at no paint
    of the screen (the cue tick is every 0.1 s) nor 0.6 s later is the border the busy colour or the title anything but `STAGING SHEET`.
    Operator need (P-127): a blink of amber on every quick selection would teach the user to ignore the cue.
    Negative control: grace 0 shows the cue at the 0.1 s tick."""
    gate = Gate(monkeypatch, "decode_values")

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        prime(app)
        await decoded(pilot, sheet, MAP)
        screen, seen = app.screen, []
        real_refresh = screen._compositor_refresh

        def hooked():  # every paint of the screen from the ask on: the cue would have to be painted to be seen
            real_refresh()
            seen.append((time.monotonic(), top_row(app), border_hex(app)))

        timer = threading.Timer(0.15, gate.release)
        stamps = Stamps(sheet, on_ask={("decode", MAP): lambda: None if timer.is_alive() or timer.finished.is_set() else timer.start()})
        try:
            gate.hold.add(MAP)
            screen._compositor_refresh = hooked
            await reselect(pilot, sheet, MAP, DISPLAY)
            await wait_for(pilot, lambda: ("decode", MAP) in stamps.done, "the decode's result", 30)
            asked, done = stamps.asked[("decode", MAP)], stamps.done[("decode", MAP)]
            end = time.monotonic() + 0.6  # the cue's tick would have shown by 0.3 s of pending time
            while time.monotonic() < end:
                await pilot.pause(0.01)
            final = (time.monotonic(), top_row(app), border_hex(app))
            return asked, done, [s for s in seen if s[0] >= asked] + [final]
        finally:
            screen.__dict__.pop("_compositor_refresh", None)
            timer.cancel()
            gate.release()
            stamps.close()

    asked, done, seen = run(tmp_path, defc_dir, body)
    assert done - asked < GRACE_S, f"the decode lasted {done - asked:.3f} s, not inside the 0.2 s grace ({load()})"
    for at, row, colour in seen:
        assert "BUSY" not in row and IDLE_TITLE in row and colour != BUSY_HEX, (
            f"cue painted {at - asked:.3f} s after the ask of a decode that lasted {done - asked:.3f} s: {row!r}, corner {colour}"
        )


def test_r_pe_bench_95_2_summaries_of_a_page_turn_are_not_busy_jobs(tmp_path, defc_dir, monkeypatch):
    """R-PE-BENCH.95/2, EX-BC3: a page turn whose summary decodes are gated for 1 s shows the idle look at every poll
    (a page row's summary decode is not a busy job). Operator need (P-127): a page turn must not look like a stuck
    window. Negative control: summaries counted as busy jobs paint the cue after 0.2 s."""
    gate = Gate(monkeypatch, "decode_values")

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        prime(app)
        await decoded(pilot, sheet, CURVE, MAP, VB)
        a2l, image = app.current_a2l_data, app.current_file.mem_map
        seen = []
        try:
            sheet.show_page([VB], describe_definitions([VB], a2l), a2l, image)
            await pilot.pause(0.2)
            gate.hold.update({CURVE, MAP, VB})
            page = [CURVE, VB, MAP]
            sheet.show_page(page, describe_definitions(page, a2l), a2l, image)
            await wait_for(pilot, gate.entered.is_set, "a summary of the new page held", 20)
            start = time.monotonic()
            while time.monotonic() < start + 1.0:
                seen.append((time.monotonic() - start, top_row(app), border_hex(app)))
                await pilot.pause(0.01)
            return seen, gate.running
        finally:
            gate.release()

    seen, running = run(tmp_path, defc_dir, body)
    assert running >= 1, "no summary was running during the observation"
    assert len(seen) >= 8, f"only {len(seen)} polls in 1 s"
    for at, row, colour in seen:
        assert "BUSY" not in row and IDLE_TITLE in row and colour != BUSY_HEX, (
            f"cue painted {at:.3f} s into a page turn's gated summaries: {row!r}, corner {colour}"
        )


# ------------------------------------------------------------------ R-PE-BENCH.96 (EX-BC4): the busy title


@pytest.mark.serial_timing
def test_r_pe_bench_96_1_the_busy_title_reads_spinner_busy_job_name_seconds_and_keys_still_work(tmp_path, defc_dir, monkeypatch):
    """R-PE-BENCH.96/1, EX-BC4: LARGE's decode held until its pending time reaches 1.7 s: the painted title is
    `STAGING SHEET` + two spaces + ` <f> BUSY · decode LARGE · 1.7 s · keys still work ` (one space before <f> and
    after `work`, the seconds with one decimal and NO padding). Operator need (P-127): the user reads what runs, on
    what, for how long, and that the keys are not lost. Negative control: `{s:4.1f}` pads to ` 1.7`."""
    a2l, s19 = case(tmp_path, "LARGE", "OTHER")
    gate = Gate(monkeypatch, "decode_values")

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        prime(app)
        await decoded(pilot, sheet, "LARGE", "OTHER")
        try:
            gate.hold.add("LARGE")
            await reselect(pilot, sheet, "LARGE", "OTHER")
            await cue_shown(pilot, app, "decode", "LARGE")
            took = await until(pilot, lambda: (m := TITLE.search(top_row(app))) is not None and float(m.group(4)) >= 1.7, 8.0)
            return took, top_row(app)
        finally:
            gate.release()

    took, row = run(tmp_path, defc_dir, body, a2l=a2l, image=s19)
    found = TITLE.search(row)
    assert took is not None and found is not None, f"no busy title with a pending time of 1.7 s: {row!r}"
    assert found.group(2) == "decode" and found.group(3) == "LARGE", row
    assert 1.7 <= float(found.group(4)) <= 2.4, row
    assert "·  " not in row, f"the seconds are padded: {row!r}"
    assert f"STAGING SHEET   {found.group(1)} BUSY" in row, row  # the title, two spaces, the pill's own leading space


@pytest.mark.serial_timing
def test_r_pe_bench_96_2_the_pill_is_bold_dark_on_amber_and_the_title_keeps_its_colour(tmp_path, defc_dir, monkeypatch):
    """R-PE-BENCH.96/2, EX-BC4: the painted pill is bold, foreground #0a0e1b on background #f5c26b; `STAGING SHEET`
    keeps the title colour it has in the idle look and does not take the pill's background. Operator need (P-127):
    amber on dark is what shows from across the room that the window is working. Negative control: a pill without its
    background."""
    a2l, s19 = case(tmp_path, "LARGE", "OTHER")
    gate = Gate(monkeypatch, "decode_values")

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        prime(app)
        await decoded(pilot, sheet, "LARGE", "OTHER")
        await pilot.pause(0.2)
        idle_title = cell_style(app, IDLE_TITLE)
        try:
            gate.hold.add("LARGE")
            await reselect(pilot, sheet, "LARGE", "OTHER")
            await cue_shown(pilot, app, "decode", "LARGE")
            await pilot.pause(0.15)
            return idle_title, cell_style(app, "BUSY"), cell_style(app, IDLE_TITLE), top_row(app)
        finally:
            gate.release()

    idle_title, pill, title, row = run(tmp_path, defc_dir, body, a2l=a2l, image=s19)
    assert idle_title is not None and idle_title.color is not None, "the idle title was not painted"
    assert pill is not None and pill.bgcolor is not None and pill.color is not None, f"no painted pill: {row!r}"
    assert pill.bgcolor.triplet.hex.lower() == BUSY_HEX, (pill, row)
    assert pill.color.triplet.hex.lower() == PILL_FG, (pill, row)
    assert pill.bold, (pill, row)
    assert title is not None and title.color is not None and title.color.triplet == idle_title.color.triplet, (idle_title, title)
    assert title.bgcolor is None or title.bgcolor.triplet.hex.lower() != BUSY_HEX, title


@pytest.mark.serial_timing
def test_r_pe_bench_96_3_the_job_words_are_preview_and_stage(tmp_path, defc_dir, monkeypatch):
    """R-PE-BENCH.96/3: a preview held in its encode paints `preview VAL_BLK_DEF_0001`, a record stage held in its
    encode paints `stage VAL_BLK_DEF_0001`. Operator need (P-127): the user tells a harmless preview from a write.
    Negative control: one word for every job."""
    gate = Gate(monkeypatch, "encode_values")

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        prime(app)
        await open_bench(pilot, sheet, VB)
        gate.hold.add(VB)
        try:
            await apply_tool(pilot, sheet, "s", "10")
            await cue_shown(pilot, app, "preview", VB)
            preview_row = top_row(app)
            gate.release()
            await wait_for(pilot, lambda: st(sheet, VB).job is None, "the preview result", 30)
            await pilot.pause(0.3)
            gate.entered.clear()
            gate.released.clear()
            await pilot.press("alt+s")
            await cue_shown(pilot, app, "stage", VB)
            stage_row = top_row(app)
            gate.release()
            await wait_for(pilot, lambda: len(entries_of(app)) == 1, "the stage", 60)
            return preview_row, stage_row
        finally:
            gate.release()

    preview_row, stage_row = run(tmp_path, defc_dir, body)
    assert "decode" not in preview_row and "stage" not in preview_row, preview_row
    assert "BUSY · stage VAL_BLK_DEF_0001 · " in stage_row, stage_row


# ------------------------------------------------------------------ R-PE-BENCH.97/2 (EX-BC5): the spinner turns


@pytest.mark.serial_timing
def test_r_pe_bench_97_2_the_frames_follow_the_cycle_one_step_per_tick_none_skipped(tmp_path, defc_dir, monkeypatch):
    """R-PE-BENCH.97/2, EX-BC5: while a decode is held 3.5 s the frames painted in the title are ◐ ◓ ◑ ◒ in that
    order, cyclically, each change one step, none skipped, and the pending time never goes back. Every compositor
    refresh is read (the app's own paints), not a poll. Operator need (P-127): a spinner that stands still is
    indistinguishable from a hung window. Negative control: the frame fixed or advanced by two."""
    a2l, s19 = case(tmp_path, "LARGE", "OTHER")
    gate = Gate(monkeypatch, "decode_values")

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        prime(app)
        await decoded(pilot, sheet, "LARGE", "OTHER")
        screen, seen = app.screen, []
        real_refresh = screen._compositor_refresh

        def hooked():
            real_refresh()
            seen.append((time.monotonic(), top_row(app)))

        try:
            gate.hold.add("LARGE")
            await reselect(pilot, sheet, "LARGE", "OTHER")
            await cue_shown(pilot, app, "decode", "LARGE")
            screen._compositor_refresh = hooked
            end = time.monotonic() + 3.5
            while time.monotonic() < end:
                await pilot.pause(0.05)
        finally:
            screen.__dict__.pop("_compositor_refresh", None)
            gate.release()
        return seen

    seen = run(tmp_path, defc_dir, body, a2l=a2l, image=s19)
    titles = [m.groups() for _, row in seen if (m := TITLE.search(row))]
    frames = []
    for frame, _word, _name, seconds in titles:
        if not frames or frames[-1][0] != frame:
            frames.append((frame, float(seconds)))
    assert len(frames) >= 12, f"only {len(frames)} distinct frames painted in 3.5 s: {[f for f, _ in frames]}"
    for (a, sa), (b, sb) in zip(frames, frames[1:]):
        assert FRAMES[(FRAMES.index(a) + 1) % 4] == b, f"frame {a} was followed by {b}: {''.join(f for f, _ in frames)}"
        assert sb >= sa, f"the pending time went back from {sa} to {sb}"


# ------------------------------------------------------------------ R-PE-BENCH.100 (EX-BC8): the cue leaves with the result


@pytest.mark.serial_timing
def test_r_pe_bench_100_1_the_cue_leaves_within_0_3_s_of_a_decode_result_and_the_values_show(tmp_path, defc_dir, monkeypatch):
    """R-PE-BENCH.100/1, EX-BC8: LARGE's gated decode is released: within 0.3 s of the result's handling the window is
    in its idle look (border back to the rule colour, title `STAGING SHEET`) and the bench shows the values.
    Operator need (P-127): an amber border that stays after the job ends is the lie that makes users kill the app.
    Negative control: the inline border left, or the last busy title left."""
    a2l, s19 = case(tmp_path, "LARGE", "OTHER")
    gate = Gate(monkeypatch, "decode_values")

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        prime(app)
        await decoded(pilot, sheet, "LARGE", "OTHER")
        stamps = Stamps(sheet)
        try:
            gate.hold.add("LARGE")
            await reselect(pilot, sheet, "LARGE", "OTHER")
            await cue_shown(pilot, app, "decode", "LARGE")
            gate.release()
            lag = await idle_after_result(pilot, app, stamps, ("decode", "LARGE"), timing_bound(0.3))
            await pilot.pause(0.2)
            return lag, has_values(sheet, "LARGE"), top_row(app), border_hex(app)
        finally:
            gate.release()
            stamps.close()

    lag, values, row, colour = run(tmp_path, defc_dir, body, a2l=a2l, image=s19)
    assert values, "the bench shows no values after the decode"
    assert IDLE_TITLE in row and "BUSY" not in row and colour != BUSY_HEX, (row, colour)


@pytest.mark.serial_timing
def test_r_pe_bench_100_2_the_cue_leaves_within_0_3_s_of_a_preview_result(tmp_path, defc_dir, monkeypatch):
    """R-PE-BENCH.100/2, EX-BC8: VAL_BLK_DEF_0001's gated preview (Set `10`) is released: within 0.3 s of the
    result's handling the idle look is back and the title is `STAGING SHEET`. Operator need (P-127): the same lie
    after a preview. Negative control: the cue cleared only for decodes."""
    gate = Gate(monkeypatch, "encode_values")

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        prime(app)
        await open_bench(pilot, sheet, VB)
        stamps = Stamps(sheet)
        try:
            gate.hold.add(VB)
            await apply_tool(pilot, sheet, "s", "10")
            await cue_shown(pilot, app, "preview", VB)
            gate.release()
            lag = await idle_after_result(pilot, app, stamps, ("preview", VB), timing_bound(0.3))
            return lag, top_row(app), border_hex(app)
        finally:
            gate.release()
            stamps.close()

    lag, row, colour = run(tmp_path, defc_dir, body)
    assert IDLE_TITLE in row and "BUSY" not in row and colour != BUSY_HEX, (row, colour)


# ------------------------------------------------------------------ R-PE-BENCH.101 (EX-BC9): refusals and errors


@pytest.mark.serial_timing
def test_r_pe_bench_101_1_a_preview_refusal_returns_the_idle_look_within_0_3_s(tmp_path, defc_dir, monkeypatch):
    """R-PE-BENCH.101/1, EX-BC9: Set `60` on VAL_BLK_DEF_0001 (outside -50..50): the preview, held past the grace,
    ends in a refusal: the idle look is back within 0.3 s of its handling. Operator need (P-127): a job that is
    refused must not leave the window looking busy. Negative control: the cue cleared only on success."""
    gate = Gate(monkeypatch, "encode_values")

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        prime(app)
        await open_bench(pilot, sheet, VB)
        stamps = Stamps(sheet)
        try:
            gate.hold.add(VB)
            await apply_tool(pilot, sheet, "s", "60")
            await cue_shown(pilot, app, "preview", VB)
            gate.release()
            lag = await idle_after_result(pilot, app, stamps, ("preview", VB), timing_bound(0.3))
            return lag, top_row(app), border_hex(app), st(sheet, VB).preview
        finally:
            gate.release()
            stamps.close()

    lag, row, colour, preview = run(tmp_path, defc_dir, body)
    assert IDLE_TITLE in row and "BUSY" not in row and colour != BUSY_HEX, (row, colour)


@pytest.mark.serial_timing
def test_r_pe_bench_101_6_a_decode_whose_worker_raises_returns_the_idle_look_within_0_3_s(tmp_path, defc_dir, monkeypatch):
    """R-PE-BENCH.101/6, EX-BC9: MAP_DEF_0001's decode is held, then its worker raises (the job hands back `None`):
    the idle look is back within 0.3 s of the result's handling. Operator need (P-127): an error must not leave an
    amber window that never ends. Negative control: a cue keyed on the result being a value."""
    gate = RaisingGate(monkeypatch, "decode_values")

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        prime(app)
        await decoded(pilot, sheet, MAP)
        stamps = Stamps(sheet)
        try:
            gate.hold.add(MAP)
            gate.boom.add(MAP)
            await reselect(pilot, sheet, MAP, DISPLAY)
            await cue_shown(pilot, app, "decode", MAP)
            gate.release()
            lag = await idle_after_result(pilot, app, stamps, ("decode", MAP), timing_bound(0.3))
            return lag, top_row(app), border_hex(app), app.is_running
        finally:
            gate.release()
            stamps.close()

    lag, row, colour, running = run(tmp_path, defc_dir, body)
    assert running, "the app stopped after a raising worker"
    assert IDLE_TITLE in row and "BUSY" not in row and colour != BUSY_HEX, (row, colour)


# ------------------------------------------------------------------ R-PE-BENCH.102 (EX-BC10): the cue follows the selection


@pytest.mark.serial_timing
def test_r_pe_bench_102_1_leaving_the_row_for_a_scalar_returns_the_idle_look_while_the_worker_runs(tmp_path, defc_dir, monkeypatch):
    """R-PE-BENCH.102/1, EX-BC10: VAL_BLK_DEF_0001's decode is held running; `down`/`up` to DISPLAY_0001 (a scalar
    row): the idle look is back within 0.3 s of the key, while the worker is still held. Operator need (P-127): the
    cue describes what the user is looking at; amber over a scalar row says nothing true. Negative control: a cue
    keyed on the running worker stays until the gate opens. The compositor hook timestamps the actual idle paint;
    Pilot's return after its own pause is not the paint time."""
    gate = Gate(monkeypatch, "decode_values")

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        screen = app.screen
        real_refresh = screen._compositor_refresh
        paints = []

        def record_paint():
            real_refresh()
            if sheet.selected_name == DISPLAY:
                paints.append((time.monotonic(), idle_now(app)))

        prime(app)
        await decoded(pilot, sheet, VB)
        try:
            gate.hold.add(VB)
            await reselect(pilot, sheet, VB, DISPLAY)
            await cue_shown(pilot, app, "decode", VB)
            screen._compositor_refresh = record_paint
            key_at = await move_to(pilot, sheet, DISPLAY)
            deadline = key_at + timing_bound(0.3)
            while time.monotonic() < deadline and not any(at >= key_at and idle for at, idle in paints):
                await pilot.pause(0.01)
            lag = next((at - key_at for at, idle in paints if at >= key_at and idle), None)
            return lag, gate.released.is_set(), gate.running, top_row(app), border_hex(app)
        finally:
            screen.__dict__.pop("_compositor_refresh", None)
            gate.release()

    lag, released, running, row, colour = run(tmp_path, defc_dir, body)
    assert not released and running == 1, f"the worker did not run on while the selection moved (running={running})"
    assert lag is not None and lag <= timing_bound(0.3), (
        f"idle paint {lag!r} s after the key (bound 0.3 s, {load()}); top border {row!r}, corner {colour}"
    )


@pytest.mark.serial_timing
def test_r_pe_bench_102_2_a_filter_that_drops_the_row_returns_the_idle_look_within_0_3_s(tmp_path, defc_dir, monkeypatch):
    """R-PE-BENCH.102/2, EX-BC10: MAP_DEF_0001's decode is held; typing `c` in the filter leaves MAP_DEF_0001 off the page:
    the idle look is back within 0.3 s of the real key event while the worker is held. Operator need (P-127): a row that
    left the page cannot be the thing the window is working on. Negative control: the cue keyed on the running
    worker."""
    gate = Gate(monkeypatch, "decode_values")

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        prime(app)
        await decoded(pilot, sheet, MAP)
        try:
            gate.hold.add(MAP)
            await reselect(pilot, sheet, MAP, DISPLAY)
            await cue_shown(pilot, app, "decode", MAP)
            need(panel, FILTER).focus()
            await pilot.pause()
            key_at = time.monotonic()
            sender = threading.Thread(target=lambda: app._driver.send_message(events.Key("c", None)))
            sender.start()
            sender.join()
            took = await until(pilot, lambda: idle_now(app), max(0.0, key_at + timing_bound(0.3) - time.monotonic()))
            seen_after = time.monotonic() - key_at
            return took, seen_after, MAP in [r.name for r in sheet.rows], gate.released.is_set(), top_row(app), border_hex(app)
        finally:
            gate.release()

    took, after, still, released, row, colour = run(tmp_path, defc_dir, body)
    assert not still, "the filter did not leave MAP_DEF_0001 off the page"
    assert not released, "the held worker ended before the check"
    assert took is not None and after <= report_margin(
        "R-PE-BENCH.102/2 idle after the filter keystroke", after, timing_bound(0.3)
    ), (
        f"idle look {after:.3f} s after the filter keystroke (bound 0.3 s, {load()}); top border {row!r}, corner {colour}"
    )


# ------------------------------------------------------------------ R-PE-BENCH.103 / .104 (EX-BC11, EX-BC12): hostile names


async def held_cue_of(app, pilot, sheet, gate, name: str, away: str):
    """The decode of ``name`` held, its cue painted: returns the painted top border row."""
    await decoded(pilot, sheet, name, away)
    gate.hold.add(name)
    await reselect(pilot, sheet, name, away)
    assert name in [row.name for row in sheet.rows], f"the sheet lists no row named {name!r}"
    await until(pilot, lambda: busy_now(app), 3.0)
    assert busy_now(app), (
        f"no busy cue for the row {name[:40]!r}: top border {top_row(app)!r}, window region {win_of(app).region}, "
        f"painted corner {border_hex(app)} ({load()})"
    )
    await pilot.pause(0.15)
    return top_row(app)


def test_r_pe_bench_103_1_a_markup_name_is_shown_literally_with_no_link(tmp_path, defc_dir, monkeypatch):
    """R-PE-BENCH.103/1, EX-BC11: a row named `[@click=app.quit]X[/]` with its decode held: the title shows the name
    literally, a click on it runs no action and the app keeps running. Operator need (P-127): a row name from an A2L is
    data, never a link that quits the window. Negative control: the title set as a markup `str` parses the name."""
    name = "[@click=app.quit]X[/]"
    a2l, s19 = case(tmp_path, name, "OTHER")
    gate = Gate(monkeypatch, "decode_values")

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        prime(app)
        try:
            row = await held_cue_of(app, pilot, sheet, gate, name, "OTHER")
            at = row.find("[@click")
            if at >= 0:
                await pilot.click(WIN, offset=(at + 2, 0))
                await pilot.pause(0.3)
            return row, top_row(app), app.is_running, getattr(app, "_exit", False)
        finally:
            gate.release()

    row, after, running, exited = run(tmp_path, defc_dir, body, a2l=a2l, image=s19)
    assert f"decode {name} · " in row, f"the name is not shown literally: {row!r}"
    assert running and not exited, "a click on the title quit the app"
    assert f"decode {name} · " in after, after


def test_r_pe_bench_103_2_brackets_in_a_name_are_shown_literally(tmp_path, defc_dir, monkeypatch):
    """R-PE-BENCH.103/2, EX-BC11: a row named `A[b]B`: the title shows `A[b]B`, not `AB` in bold. Operator need
    (P-127): the name the user reads is the name in the A2L. Negative control: the name parsed as markup."""
    name = "A[b]B"
    a2l, s19 = case(tmp_path, name, "OTHER")
    gate = Gate(monkeypatch, "decode_values")

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        prime(app)
        try:
            return await held_cue_of(app, pilot, sheet, gate, name, "OTHER")
        finally:
            gate.release()

    row = run(tmp_path, defc_dir, body, a2l=a2l, image=s19)
    assert f"decode {name} · " in row, f"the name is not shown literally: {row!r}"


def test_r_pe_bench_104_1_an_escape_sequence_in_a_name_is_painted_as_fffd(tmp_path, defc_dir, monkeypatch):
    """R-PE-BENCH.104/1, EX-BC12: a row named `A` + ESC + `[2J` with its decode held: the title shows `A` U+FFFD
    `[2J` and no ESC is painted. Operator need (P-127): a hostile A2L name cannot clear or repaint the terminal.
    Negative control: the raw name in the title."""
    name = "A\x1b[2J"
    a2l, s19 = case(tmp_path, name, "OTHER")
    gate = Gate(monkeypatch, "decode_values")

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        prime(app)
        try:
            return await held_cue_of(app, pilot, sheet, gate, name, "OTHER")
        finally:
            gate.release()

    row = run(tmp_path, defc_dir, body, a2l=a2l, image=s19)
    assert "decode A�[2J · " in row, f"the title does not show `A\\ufffd[2J`: {row!r}"
    assert "\x1b" not in row, row


def test_r_pe_bench_104_2_a_c1_control_in_a_name_is_painted_as_fffd(tmp_path, defc_dir, monkeypatch):
    """R-PE-BENCH.104/2, EX-BC12: a row named `B` + U+0085 + `C` with its decode held: the title shows `B` U+FFFD `C`.
    Operator need (P-127): C1 controls are as hostile as ESC. Negative control: the raw name in the title."""
    name = "B\x85C"
    a2l, s19 = case(tmp_path, name, "OTHER")
    gate = Gate(monkeypatch, "decode_values")

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        prime(app)
        try:
            return await held_cue_of(app, pilot, sheet, gate, name, "OTHER")
        finally:
            gate.release()

    row = run(tmp_path, defc_dir, body, a2l=a2l, image=s19)
    assert "decode B�C · " in row, f"the title does not show `B\\ufffdC`: {row!r}"
    assert "\x85" not in row, row


# ------------------------------------------------------------------ R-PE-BENCH.105 (EX-BC13): a long name is cut to fit


PILL_FIXED = len(IDLE_TITLE) + 2 + len(" ◐ BUSY · decode ") + len(" · 0.0 s · keys still work ")  # F, the title without the name


async def long_name_row(app, pilot, sheet, gate, name: str, room: int):
    prime(app)
    win = win_of(app)
    assert win.size.width - 4 == room, f"the window's content width is {win.size.width}: room B is {win.size.width - 4}, not {room}"
    return await held_cue_of(app, pilot, sheet, gate, name, "OTHER")


@pytest.mark.parametrize(
    ("size", "room"), [(MIN_SIZE, 66), (SIZE, 106), (WIDE, 190)], ids=["80x24", "118x54", "220x60"]
)
def test_r_pe_bench_105_1_to_3_a_300_character_name_is_cut_with_an_ellipsis_and_the_title_fits(tmp_path, defc_dir, monkeypatch, size, room):
    """R-PE-BENCH.105/1-3, EX-BC13 (80, 118 and 220 columns): a 300-character name with its decode held: the painted
    top border row holds `BUSY`, the name cut to B - F characters ending in `…`, the pending time and ` keys still
    work ` (B = the window's content width - 4 = 66 / 106 / 190, E4-pilots.md P3). Operator need (P-127): the border
    must not crop the end of the pill, where `keys still work` sits. Negative control: no cut, so the border crops the
    end and ` keys still work` is missing."""
    name = "N" * 300
    a2l, s19 = case(tmp_path, name, "OTHER")
    gate = Gate(monkeypatch, "decode_values")

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        try:
            return await long_name_row(app, pilot, sheet, gate, name, room)
        finally:
            gate.release()

    row = run(tmp_path, defc_dir, body, size=size, a2l=a2l, image=s19)
    cut = room - PILL_FIXED
    assert "BUSY" in row and " keys still work " in row, f"the pill's end is missing at {size[0]} columns: {row!r}"
    assert f"decode {'N' * (cut - 1)}… · " in row, f"the name is not cut to {cut} characters ending in `…`: {row!r}"
    assert re.search(r" · \d+\.\d s · keys still work ", row), row


def test_r_pe_bench_105_4_a_one_character_name_is_not_cut(tmp_path, defc_dir, monkeypatch):
    """R-PE-BENCH.105/4, EX-BC13: a 1-character name `N` at 80 columns with its decode held: the title shows
    `decode N · ` whole, no `…`, and ` keys still work `. Operator need (P-127): a short name is the name. Negative
    control: a cut applied to every name."""
    a2l, s19 = case(tmp_path, "N", "OTHER")
    gate = Gate(monkeypatch, "decode_values")

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        try:
            return await long_name_row(app, pilot, sheet, gate, "N", 66)
        finally:
            gate.release()

    row = run(tmp_path, defc_dir, body, size=MIN_SIZE, a2l=a2l, image=s19)
    assert "decode N · " in row and " keys still work " in row, row
    assert "…" not in row, f"a 1-character name was cut: {row!r}"


def test_e5_9b_busy_title_cuts_wide_names_by_painted_cells(tmp_path, defc_dir, monkeypatch):
    """E5 regression of R-PE-BENCH.105: at 118 columns, B - F is 47 cells.

    A wide name therefore leaves 23 CJK characters plus one ellipsis; counting
    characters instead of cells crops the seconds and the pill's suffix.
    """
    name = "界" * 300
    a2l, s19 = case(tmp_path, name, "OTHER")
    gate = Gate(monkeypatch, "decode_values")

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        try:
            return await long_name_row(app, pilot, sheet, gate, name, 106)
        finally:
            gate.release()

    row = run(tmp_path, defc_dir, body, size=SIZE, a2l=a2l, image=s19)
    assert f"decode {'界' * 23}… · " in row, row
    assert " keys still work " in row, row
    assert re.search(r" · \d+\.\d s · keys still work ", row), row


def test_e5_9b_busy_title_does_not_cut_combining_text_that_fits(tmp_path, defc_dir, monkeypatch):
    """E5 regression of R-PE-BENCH.105: 60 code points can occupy 30 cells.

    The whole painted name fits in the 47-cell name room and must not gain an
    ellipsis merely because its Python string length is greater than 47.
    """
    name = "e\u0301" * 30
    a2l, s19 = case(tmp_path, name, "OTHER")
    gate = Gate(monkeypatch, "decode_values")

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        try:
            return await long_name_row(app, pilot, sheet, gate, name, 106)
        finally:
            gate.release()

    row = run(tmp_path, defc_dir, body, size=SIZE, a2l=a2l, image=s19)
    assert f"decode {name} · " in row, row
    assert "…" not in row, row
    assert " keys still work " in row, row


def test_e5_9b_staging_sheet_on_mount_runs_exactly_once(tmp_path, defc_dir, monkeypatch):
    """E5 / HOLD-MOUNT: framework MRO dispatch calls the base mount once.

    Counting the actual base method distinguishes this from a cue test: an
    added ``super().on_mount()`` in ArrayBenchSheet runs it a second time.
    """
    from s19_app.tui.screens_directionb.patch_editor.sheet import StagingSheet

    calls = []
    real_mount = StagingSheet.on_mount

    def counted_mount(self):
        calls.append(self)
        return real_mount(self)

    monkeypatch.setattr(StagingSheet, "on_mount", counted_mount)

    async def body(app, pilot, panel):
        await pilot.pause()
        sheet = sheet_of(panel)
        return len(calls), calls[0] is sheet, sheet._busy_timer is not None

    assert run(tmp_path, defc_dir, body) == (1, True, True)
