"""Batch-103 Inc 9 E4 (tester MW9): the nodes the widget / A9 / I mutant run asked for.

Each test below was added because a mutant of ``bench_sheet.py`` (or the app's record handler) survived every
original node of the six Inc 9 widget files; each is RED on that mutant and GREEN on the tree (the record
``inc-9/E4-mutants-w.md`` names the mutant of every test). They drive the shipped route (the real app under Pilot, the
operator's keys, the sheet's own methods the app itself calls) and assert what the operator sees or what the document
holds, never a call sequence.

Rows: R-PE-BENCH.5, .6, .22, .24, .25, .27, .48, .49, and the stale-decode requeue of the I9 rulings.
"""
from __future__ import annotations

import dataclasses
import re
import threading

import pytest

from s19_app.tui import definition_sheet as ds
from s19_app.tui.a2l_definition import (
    Refusal, decode_values, describe_definition, describe_definitions, encode_values,
)
from s19_app.tui.a2l_parse import parse_a2l_file
from s19_app.tui.screens_directionb.patch_editor import bench_sheet
from tests.support import b103_a2l_arrays as arrays
from tests.support.b103_inc8_s1 import defc  # noqa: F401  (a session fixture used by name)
from s19_app.tui import definition_bench_view as dv
from tests.support.b103_inc9_b import EX
from tests.support.b103_inc8b_r import fact
from tests.test_b103_inc9_b_detail import _windowed_cases
from tests.support.b103_inc9_w import (  # noqa: F401  (defc_dir is a fixture used by name)
    BIG_COUNT, CURVE, DISPLAY, MAP, VB, WIDE, Gate, apply_tool, big_case, body_text, defc_dir, entries_of, has_values,
    hand_case, need, open_bench, pick, record_statuses, run, service_of, sheet_of, st, valblk_block, wait_for,
)

BIG, NUM = "BIG", "NUM_ROW"


def row_text(app, name: str) -> str:
    return next(line for line in body_text(app).splitlines() if name[:12] in line)


def focused_id(app):
    return getattr(app.focused, "id", None)


class HoldCalls(Gate):
    """A ``Gate`` that holds the 1st and the 2nd outermost call on ``name`` (counted from ``arm()``), each until
    its own ``release(n)``. ``entered_n[n]`` is set when call ``n`` is waiting."""

    def __init__(self, monkeypatch, function: str, name: str):
        self._name, self._count, self._armed = name, 0, False
        self.entered_n = {1: threading.Event(), 2: threading.Event()}
        self.free_n = {1: threading.Event(), 2: threading.Event()}
        super().__init__(monkeypatch, function)

    def arm(self) -> None:
        self._count, self._armed = 0, True

    def release_call(self, n: int) -> None:
        self.free_n[n].set()

    def _begin(self, function: str, name: str) -> bool:
        outer = super()._begin(function, name)
        if outer and self._armed and name == self._name:
            self._count += 1
            if self._count in self.free_n:
                self.entered_n[self._count].set()
                self.free_n[self._count].wait(20.0)
        return outer


async def settle(pilot, sheet) -> int:
    """Wait until the sheet's document generation stops moving (the opening pushes the document and the image once),
    so that a decode started after it can only go stale through the selection or the page key."""
    last = -1
    for _ in range(100):
        await pilot.pause(0.3)
        if sheet.generation == last:
            return last
        last = sheet.generation
    raise AssertionError("the sheet's generation never settled")


async def reshow(sheet, app, names):
    """The page of ``names`` shown again, as the app does when the page or the filter changes."""
    a2l, image = app.current_a2l_data, app.current_file.mem_map
    sheet.show_page(names, describe_definitions(names, a2l), a2l, image)


# ------------------------------------------------------------------ R-PE-BENCH.22 and the stale-decode requeue


async def arm_big(pilot, sheet, gate) -> tuple[int, int]:
    """The page opens with BIG selected, so its first decode runs at the start: let it end, settle the document
    generation, select SMALL_BLK (BIG's values are dropped) and only then hold BIG. Returns (generation, BIG decodes
    so far)."""
    await wait_for(pilot, lambda: has_values(sheet, BIG), "BIG's first decode", 60)
    generation = await settle(pilot, sheet)
    await pick(pilot, sheet, "SMALL_BLK")
    await wait_for(pilot, lambda: has_values(sheet, "SMALL_BLK"), "SMALL_BLK's values", 30)
    assert not has_values(sheet, BIG), "control: BIG's values were dropped when SMALL_BLK was selected"
    gate.hold = {BIG}
    return generation, gate.names("decode_values").count(BIG)


def test_r_pe_bench_22_3_a_decode_made_stale_by_the_selection_key_alone_runs_again_for_the_selected_row(
    tmp_path, defc_dir, monkeypatch
):
    """BIG selected again, its decode held, the page shown again (the selection key moves, the document and the image
    do not), the decode released: BIG is still the selected row, so its values show, from a SECOND decode (the first
    ended stale and was discarded). Kills: the stale decode painted at once (one decode), the requeue removed (the
    values never show)."""
    gate = Gate(monkeypatch, "decode_values")
    a2l, s19 = big_case(tmp_path, BIG_COUNT, rows=(BIG,))

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        generation, base = await arm_big(pilot, sheet, gate)
        try:
            await pick(pilot, sheet, BIG)
            await wait_for(pilot, gate.entered.is_set, "BIG's decode held")
            await reshow(sheet, app, [row.name for row in sheet.rows])
            await pilot.pause()
        finally:
            gate.release()
        await wait_for(pilot, lambda: has_values(sheet, BIG), "BIG's values after its stale decode", 60)
        await pilot.pause(0.5)
        return sheet.selected_name, gate.names("decode_values").count(BIG) - base, sheet.generation == generation

    selected, decodes, same_generation = run(tmp_path, None, body, a2l=a2l, image=s19)
    assert same_generation, "control: the document and the image did not change, only the selection key moved"
    assert selected == BIG
    assert decodes == 2, f"the stale decode must be discarded and run again: {decodes} decode(s)"


def test_r_pe_bench_22_4_a_stale_decode_of_a_row_no_longer_selected_is_not_run_again(tmp_path, defc_dir, monkeypatch):
    """BIG selected again, its decode held, NUM_ROW (a number row: nothing is queued for it) selected, the decode
    released: BIG's values stay dropped and BIG is decoded once more only. Kills: the requeue of any stale decode,
    selected or not."""
    gate = Gate(monkeypatch, "decode_values")
    a2l, s19 = hand_case(
        tmp_path,
        [valblk_block(BIG, 0x100000, BIG_COUNT), valblk_block("SMALL_BLK", 0x400000, 4), arrays.meas(NUM, "UBYTE", addr="0x500000")],
        [(0x100000, bytes(BIG_COUNT)), (0x400000, bytes([1, 2, 3, 4])), (0x500000, bytes([7]))],
    )

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        assert NUM in [row.name for row in sheet.rows], "control: the number row is on the page"
        generation, base = await arm_big(pilot, sheet, gate)
        try:
            await pick(pilot, sheet, BIG)
            await wait_for(pilot, gate.entered.is_set, "BIG's decode held")
            await pick(pilot, sheet, NUM)
        finally:
            gate.release()
        await pilot.pause(2.0)
        return (has_values(sheet, BIG), gate.names("decode_values").count(BIG) - base, sheet.selected_name,
                sheet.generation == generation)

    big_values, decodes, selected, same_generation = run(tmp_path, None, body, a2l=a2l, image=s19)
    assert same_generation, "control: only the selection key moved"
    assert selected == NUM and big_values is False
    assert decodes == 1, f"BIG is no longer selected: no second decode, got {decodes}"


def test_r_pe_bench_22_5_a_stale_decode_of_the_selected_row_adds_no_second_queued_decode(tmp_path, defc_dir, monkeypatch):
    """BIG selected again and held, SMALL_BLK selected, BIG selected again (its new decode is queued), the first
    released: two decodes of BIG in all since the hold (the held one and the queued one). Kills: a requeue on top of
    a decode already queued (three)."""
    gate = Gate(monkeypatch, "decode_values")
    a2l, s19 = big_case(tmp_path, BIG_COUNT, rows=(BIG,))

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        generation, base = await arm_big(pilot, sheet, gate)
        try:
            await pick(pilot, sheet, BIG)
            await wait_for(pilot, gate.entered.is_set, "BIG's decode held")
            await pick(pilot, sheet, "SMALL_BLK")
            await pick(pilot, sheet, BIG)
        finally:
            gate.release()
        await wait_for(pilot, lambda: has_values(sheet, BIG), "BIG's values", 60)
        await pilot.pause(2.5)
        return gate.names("decode_values").count(BIG) - base, sheet.generation == generation

    decodes, same_generation = run(tmp_path, None, body, a2l=a2l, image=s19)
    assert same_generation, "control: only the selection key moved"
    assert decodes == 2, f"{decodes} decodes of BIG since the hold"


# ------------------------------------------------------------------ R-PE-BENCH.24


def test_r_pe_bench_24_2_a_summary_ended_after_the_page_turned_is_not_painted(tmp_path, defc_dir, monkeypatch):
    """CURVE_DEF_0001 is new on a page (its state was dropped by the page before): its summary is held, the same page
    is shown again (a new page key), the first summary is released and the second one is held: at that moment the
    row holds no values (the first result was discarded). Kills: a summary of an older page painted at once."""
    hold = HoldCalls(monkeypatch, "decode_values", CURVE)

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await reshow(sheet, app, [VB])
        await wait_for(pilot, lambda: has_values(sheet, VB), "the first page's summary")
        assert st(sheet, CURVE) is None, "control: the page without CURVE dropped its state"
        hold.arm()
        try:
            await reshow(sheet, app, [CURVE])
            await wait_for(pilot, hold.entered_n[1].is_set, "the first summary of CURVE held")
            await reshow(sheet, app, [CURVE])
            hold.release_call(1)
            await wait_for(pilot, hold.entered_n[2].is_set, "the second summary of CURVE started")
            await pilot.pause(0.3)
            return st(sheet, CURVE).values is None, fact("S.after.CURVE_DEF_0001") in body_text(app)  # Inc 8b: the 7-level strip (R-PE-BENCH.11)
        finally:
            hold.release_call(1)
            hold.release_call(2)

    no_values, painted = run(tmp_path, defc_dir, body)
    assert no_values is True and painted is False, "the first page's summary was painted after the page turned"


# ------------------------------------------------------------------ R-PE-BENCH.25 (the staged cells of a row that is not selected)


def test_r_pe_bench_25_3_a_raw_entry_over_a_row_that_is_not_selected_gives_it_a_staged_delta(tmp_path, defc_dir):
    """A raw bytes entry at 0x800090 (inside VAL_BLK_DEF_0001 only), DISPLAY_0001 selected: the VB row shows a Δ with
    the word `staged`; control: before the entry it shows neither. Kills: no recompute for a row whose span holds an
    entry but whose staged values are not yet decoded."""

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await pick(pilot, sheet, DISPLAY)
        await wait_for(pilot, lambda: has_values(sheet, VB), "VAL_BLK_DEF_0001's summary", 30)
        await pilot.pause(0.3)
        before = row_text(app, VB)
        service_of(app).add_entry("0x800090", "", "AA 55")
        app._refresh_patch_history_view()
        await wait_for(pilot, lambda: "staged" in row_text(app, VB), "the staged delta on the row", 30)
        return before, row_text(app, VB)

    before, after = run(tmp_path, defc_dir, body, size=WIDE)
    assert "staged" not in before and "max |Δ|" not in before, before
    assert "max |Δ|" in after and "staged" in after, after


# ------------------------------------------------------------------ R-PE-BENCH.27


def test_r_pe_bench_27_3_a_tool_applied_to_a_row_whose_decode_was_refused_changes_nothing_and_does_not_fail(
    tmp_path, defc_dir, monkeypatch
):
    """MAP_DEF_0001's decode is refused (no values, no job running): Enter in the op input with +Δ 5 leaves the bench
    edit empty and the app running. Kills: the values check dropped from the apply (an exception on no values)."""
    real = bench_sheet.decode_values
    monkeypatch.setattr(
        bench_sheet, "decode_values",
        lambda definition, *a, **k: Refusal("test", "refused for the test") if definition.name == MAP else real(definition, *a, **k),
    )

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await open_bench(pilot, sheet, MAP, decoded=False)
        await wait_for(pilot, lambda: st(sheet, MAP).refusal is not None and st(sheet, MAP).job is None, "the refusal", 30)
        await pilot.press("d", "enter")
        need(sheet, "#patch_sheet_input").value = "5"
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause(0.5)
        return dict(st(sheet, MAP).edit), entries_of(app), app.is_running

    edit, entries, running = run(tmp_path, defc_dir, body)
    assert edit == {} and entries == [] and running is True


# ------------------------------------------------------------------ R-PE-BENCH.6


def test_r_pe_bench_6_2_a_record_stage_keeps_the_selection_on_a_row_that_has_another_row_below_it(tmp_path, defc_dir):
    """The first bench row of the page that is not the last row is staged: it stays selected. (VAL_BLK_DEF_0001 is
    the last row of the DEFC page, where the advance has no row to go to.) Kills: the stage advancing the selection."""

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        names = [row.name for row in sheet.rows]
        target = next((n for n in (CURVE, MAP, VB) if names.index(n) < len(names) - 1), None)
        assert target is not None, "control: a bench row with a row below it"
        await open_bench(pilot, sheet, target)
        await apply_tool(pilot, sheet, "s", "10")
        await wait_for(pilot, lambda: bool(st(sheet, target).edit), "the edit")
        await pilot.press("alt+s")
        await wait_for(pilot, lambda: len(entries_of(app)) == 1, "the stage", 60)
        await pilot.pause(0.5)
        return target, sheet.selected_name

    target, selected = run(tmp_path, defc_dir, body)
    assert selected == target


# ------------------------------------------------------------------ R-PE-BENCH.48 / .49 (alt+s)


def test_r_pe_bench_48_3_alt_s_from_an_op_input_the_bench_does_not_hold_the_focus_on_still_stages(tmp_path, defc_dir):
    """Escape to the rows (the bench focus is off), then the op input focused as a click would: alt+s stages the
    record. Kills: alt+s answered only while the bench holds the focus."""

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await open_bench(pilot, sheet, VB)
        await apply_tool(pilot, sheet, "s", "10")
        await wait_for(pilot, lambda: dict(st(sheet, VB).edit) == {(0, 0): "10"}, "the edit")
        await pilot.press("escape")
        await pilot.pause()
        assert st(sheet, VB).focus is False, "control: the bench focus is off"
        need(sheet, "#patch_sheet_input").focus()
        await pilot.pause()
        where = focused_id(app)
        await pilot.press("alt+s")
        await pilot.pause(1.5)
        return where, st(sheet, VB).focus, entries_of(app)

    where, bench_focus, entries = run(tmp_path, defc_dir, body)
    assert where == "patch_sheet_input" and bench_focus is False
    assert len(entries) == 1


def test_r_pe_bench_49_3_alt_s_off_the_bench_and_off_the_op_input_stages_nothing(tmp_path, defc_dir):
    """A bench edit pending, Escape to the rows: alt+s has no bench meaning there. Kills: the record stage enabled on
    any bench row."""

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await open_bench(pilot, sheet, VB)
        await apply_tool(pilot, sheet, "s", "10")
        await wait_for(pilot, lambda: dict(st(sheet, VB).edit) == {(0, 0): "10"}, "the edit")
        await pilot.press("escape")
        await pilot.pause()
        assert st(sheet, VB).focus is False and focused_id(app) == "patch_sheet_body", "control: the rows hold the focus"
        await pilot.press("alt+s")
        await pilot.pause(1.5)
        return entries_of(app), dict(st(sheet, VB).edit)

    entries, edit = run(tmp_path, defc_dir, body)
    assert entries == [] and edit == {(0, 0): "10"}


# ------------------------------------------------------------------ R-PE-BENCH.5 (the cursor stays on the painted window)


def test_r_pe_bench_5_2_the_cursor_stays_on_a_painted_row_while_it_walks_down_a_tall_grid(tmp_path, defc_dir):
    """BIG (70,000 values, a window line shows) at 118x54, bench focus: `down` 40 times; after every key the painted
    sheet shows the cursor mark. Kills: the widget scrolling by a different room than the painted canvas."""
    a2l, s19 = big_case(tmp_path, BIG_COUNT, rows=(BIG,))

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await open_bench(pilot, sheet, BIG)
        await pilot.pause(0.3)
        lost = []
        for step in range(1, 41):
            await pilot.press("down")
            await pilot.pause()
            if "▸" not in body_text(app):
                lost.append(step)
        return lost

    assert run(tmp_path, None, body, a2l=a2l, image=s19) == []


# ------------------------------------------------------------------ the second round: R-PE-BENCH.28, .62, .66, .70, .74, .78, .92


def test_r_pe_bench_70_5_no_bench_job_starts_between_the_encode_ending_and_the_documents_write(tmp_path, defc_dir, monkeypatch):
    """While the app writes a record stage (the sheet holds its queue until `record_done`), a request for another
    decode (what a selection or a preview does) starts no job; after the write it runs. White box on one point: the
    request is made inside the app's own handler, the only place where it could interleave, and the sheet's running-job
    slot is read (the UI thread cannot also run the worker there). Kills: the hold not set or not honoured."""
    gate = Gate(monkeypatch, "decode_values")
    seen = {}

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await wait_for(pilot, lambda: has_values(sheet, MAP), "the page summaries", 30)
        await open_bench(pilot, sheet, VB)
        await apply_tool(pilot, sheet, "s", "10")
        await wait_for(pilot, lambda: st(sheet, VB).preview not in (None, "encoding"), "the preview", 60)
        original = type(app)._stage_bench_record

        def wrapped(self, event, sheet_):
            sheet_._enqueue("decode", MAP)
            seen["active_during"] = sheet_._active_job
            return original(self, event, sheet_)

        monkeypatch.setattr(type(app), "_stage_bench_record", wrapped)
        before = gate.names("decode_values").count(MAP)
        await pilot.press("alt+s")
        await wait_for(pilot, lambda: len(entries_of(app)) == 1, "the stage", 60)
        await wait_for(pilot, lambda: gate.names("decode_values").count(MAP) - before >= 1, "the decode after the write", 30)
        return gate.names("decode_values").count(MAP) - before

    after = run(tmp_path, defc_dir, body)
    assert seen["active_during"] is None, "a bench job started while the record was being written"
    assert after == 1, "the requested decode runs once the write is done"


def test_r_pe_bench_66_5_undoing_the_only_edit_clears_the_bytes_line(tmp_path, defc_dir):
    """Set 10 applied (the bytes line shows `... B differ`), `u` (the edit is empty again): the bytes line is the
    no-edit line. Kills: the preview and its runs kept when the edit empties."""

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await open_bench(pilot, sheet, VB)
        before = body_text(app)
        await apply_tool(pilot, sheet, "s", "10")
        await wait_for(pilot, lambda: "B differ" in body_text(app), "the bytes line with the runs", 60)
        await pilot.press("u")
        await wait_for(pilot, lambda: not st(sheet, VB).edit, "the undo")
        await pilot.pause(0.5)
        return before, body_text(app)

    before, after = run(tmp_path, defc_dir, body)
    assert "no edit yet" in before and "B differ" not in before
    assert "no edit yet" in after and "B differ" not in after, after


def test_r_pe_bench_66_6_the_bytes_line_says_encoding_while_the_preview_runs(tmp_path, defc_dir, monkeypatch):
    """Set 10 applied while the preview's encode is held: the bytes line reads `encoding ...`; released: the runs show.
    Kills: no placeholder while the preview job runs."""
    gate = Gate(monkeypatch, "encode_values")

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await open_bench(pilot, sheet, VB)
        gate.hold.add(VB)
        try:
            await apply_tool(pilot, sheet, "s", "10")
            await wait_for(pilot, gate.entered.is_set, "the preview encode held")
            await pilot.pause(0.3)
            held = body_text(app)
        finally:
            gate.release()
        await wait_for(pilot, lambda: "B differ" in body_text(app), "the bytes line with the runs", 60)
        return held

    assert "encoding …" in run(tmp_path, defc_dir, body)


def test_r_pe_bench_70_6_a_second_alt_s_before_the_first_record_starts_stages_the_newer_edit(tmp_path, defc_dir, monkeypatch):
    """The preview of Set 10 held, alt+s (queued behind it), Set 20 applied, alt+s again, released: ONE record is
    staged and it is the one of Set 20 (what I-2 encodes for {(0,0): `20`}). Kills: the first queued request kept
    over the newer one."""
    gate = Gate(monkeypatch, "encode_values")

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await open_bench(pilot, sheet, VB)
        gate.hold.add(VB)
        try:
            await apply_tool(pilot, sheet, "s", "10")
            await wait_for(pilot, gate.entered.is_set, "the first preview held")
            await pilot.press("alt+s")
            await pilot.pause(0.2)
            await apply_tool(pilot, sheet, "s", "20")
            await wait_for(pilot, lambda: dict(st(sheet, VB).edit) == {(0, 0): "20"}, "the second edit")
            await pilot.press("alt+s")
            await pilot.pause(0.2)
        finally:
            gate.release()
        await wait_for(pilot, lambda: len(entries_of(app)) >= 1, "the stage", 60)
        await pilot.pause(1.0)
        a2l = app.current_a2l_data
        want = {
            text: encode_values(describe_definition(VB, a2l), a2l, {(0, 0): text}, dict(app.current_file.mem_map))
            for text in ("10", "20")
        }
        return entries_of(app), want

    entries, want = run(tmp_path, defc_dir, body)
    assert [bytes(data) for _, data in entries] == [bytes(want["20"].data)], (entries, want)
    assert bytes(want["10"].data) != bytes(want["20"].data), "control: the two edits encode differently"


def _stage_message(app, sheet, **change):
    """The record request the sheet posts for VAL_BLK_DEF_0001 with Set 10, with fields of it replaced by ``change``."""
    a2l = app.current_a2l_data
    definition = describe_definition(VB, a2l)
    outcome = encode_values(definition, a2l, {(0, 0): "10"}, dict(app.current_file.mem_map))
    fields = dict(name=VB, definition=definition, count=1, outcome=outcome, generation=sheet.generation, edit=(((0, 0), "10"),))
    fields.update(change)
    return bench_sheet.ArrayBenchSheet.RecordStageRequested(**fields)


def test_r_pe_bench_74_2_a_record_encoded_outside_its_span_is_not_staged(tmp_path, defc_dir, monkeypatch):
    """The sheet's own request message, its encoded record moved one byte: the app stages nothing and says so.
    Control: the same request unchanged stages one entry. Kills: the span check dropped."""
    statuses = record_statuses(monkeypatch)

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await open_bench(pilot, sheet, VB)
        good = _stage_message(app, sheet)
        moved = _stage_message(app, sheet, outcome=dataclasses.replace(good.outcome, address=good.outcome.address + 1))
        sheet.post_message(moved)
        await pilot.pause(1.0)
        refused = entries_of(app)
        sheet.post_message(good)
        await wait_for(pilot, lambda: len(entries_of(app)) == 1, "the control stage", 30)
        return refused, entries_of(app)

    refused, after = run(tmp_path, defc_dir, body)
    assert refused == [] and len(after) == 1
    assert any("nothing staged" in text and "outside its span" in text for text in statuses), statuses[-5:]


def test_r_pe_bench_78_3_a_request_made_for_an_older_document_is_not_staged(tmp_path, defc_dir, monkeypatch):
    """The sheet's own request message carrying the generation of the document before the last change: stale status,
    nothing staged (the check the app makes when the message was queued before a change). Kills: the generation not
    checked in the handler."""
    statuses = record_statuses(monkeypatch)

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await open_bench(pilot, sheet, VB)
        sheet.post_message(_stage_message(app, sheet, generation=sheet.generation - 1))
        await pilot.pause(1.0)
        return entries_of(app)

    entries = run(tmp_path, defc_dir, body)
    assert entries == []
    assert "Patch Editor: the change document or the image changed while VAL_BLK_DEF_0001 was encoding — stage it again." in statuses


@pytest.mark.parametrize("operand", ["abc", "\x1b" + "9" * 300])
def test_r_pe_bench_62_6_a_refused_operand_shows_its_status_with_the_operand_echo(tmp_path, defc_dir, monkeypatch, operand):
    """+Delta with a text that is not a number: the status `Patch Editor: '<operand echo>' is not a number.` (the echo
    replaces the control character and cuts at 256 characters, R-PE-BENCH.92/2); the bench edit stays empty. Kills:
    the apply request not showing the status."""
    statuses = record_statuses(monkeypatch)

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await open_bench(pilot, sheet, VB)
        await apply_tool(pilot, sheet, "d", operand)
        await pilot.pause(0.5)
        return dict(st(sheet, VB).edit)

    edit = run(tmp_path, defc_dir, body)
    want = f"Patch Editor: '{ds.name_echo(operand)}' is not a number."
    assert edit == {} and want in statuses, statuses[-5:]


def _long_name_case(tmp_path):
    name = "V" + "x" * 299
    a2l_path, _ = hand_case(tmp_path, [valblk_block(name, 0x100000, 4)], [(0x100000, bytes([1, 2, 3, 4]))])
    return name, parse_a2l_file(a2l_path), {0x100000 + i: i + 1 for i in range(4)}


def test_r_pe_bench_92_2_the_stale_record_status_echoes_a_300_character_name_in_256(tmp_path, defc_dir, monkeypatch):
    """A record encode held, the document changed meanwhile, released: the stale-record status carries the name echo
    (256 characters and an ellipsis). Kills: the raw name in that status."""
    statuses = record_statuses(monkeypatch)
    name, a2l, image = _long_name_case(tmp_path)
    gate = Gate(monkeypatch, "encode_values")

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        sheet.show_page([name], {name: describe_definition(name, a2l)}, a2l, image)
        await pilot.pause()
        await open_bench(pilot, sheet, name)
        await apply_tool(pilot, sheet, "s", "9")
        await wait_for(pilot, lambda: st(sheet, name).preview not in (None, "encoding"), "the preview", 30)
        gate.hold.add(name)
        try:
            await pilot.press("alt+s")
            await wait_for(pilot, gate.entered.is_set, "the record encode held")
            service_of(app).add_entry("0x700000", "", "AA")
            app._refresh_patch_history_view()
            await pilot.pause(0.3)
        finally:
            gate.release()
        await pilot.pause(1.5)

    run(tmp_path, defc_dir, body)
    want = f"Patch Editor: the change document or the image changed while {ds.name_echo(name)} was encoding — stage it again."
    assert want in statuses, [t[:80] for t in statuses[-4:]]
    assert len(ds.name_echo(name)) == 257


def test_r_pe_bench_92_3_the_still_decoding_status_of_a_stage_echoes_a_300_character_name_in_256(tmp_path, defc_dir, monkeypatch):
    """alt+s on a row whose values are still decoding: the status carries the name echo. Kills: the raw name."""
    statuses = record_statuses(monkeypatch)
    name, a2l, image = _long_name_case(tmp_path)
    gate = Gate(monkeypatch, "decode_values", hold={name})

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        try:
            sheet.show_page([name], {name: describe_definition(name, a2l)}, a2l, image)
            await pilot.pause()
            await open_bench(pilot, sheet, name, decoded=False)
            await wait_for(pilot, gate.entered.is_set, "the decode held")
            await pilot.press("alt+s")
            await pilot.pause(0.5)
        finally:
            gate.release()

    run(tmp_path, defc_dir, body)
    want = f"Patch Editor: {ds.name_echo(name)} is still decoding — try again when its values show."
    assert want in statuses, [t[:80] for t in statuses[-4:]]


def test_r_pe_bench_92_4_the_changed_in_the_a2l_status_echoes_a_300_character_name_in_256(tmp_path, defc_dir, monkeypatch):
    """The A2L loaded when alt+s acts describes the row differently from the page's: the status carries the name echo.
    Kills: the raw name in that status."""
    statuses = record_statuses(monkeypatch)
    name, a2l, image = _long_name_case(tmp_path)
    other_path, _ = hand_case(tmp_path, [valblk_block(name, 0x100010, 4)], [(0x100010, bytes([1, 2, 3, 4]))])
    other = parse_a2l_file(other_path)

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        sheet.show_page([name], {name: describe_definition(name, a2l)}, a2l, image)
        await pilot.pause()
        await open_bench(pilot, sheet, name)
        await apply_tool(pilot, sheet, "s", "9")
        await wait_for(pilot, lambda: st(sheet, name).preview not in (None, "encoding"), "the preview", 30)
        assert describe_definition(name, other) != describe_definition(name, a2l), "control: the definitions differ"
        app.current_a2l_data = other
        await pilot.press("alt+s")
        await pilot.pause(1.0)

    run(tmp_path, defc_dir, body)
    want = f"Patch Editor: {ds.name_echo(name)} changed in the A2L — select it again to reload its values."
    assert want in statuses, [t[:80] for t in statuses[-4:]]


# ------------------------------------------------------------------ _staged_pair (the decode job's staged values)


def _delta_over_entry(app, address_text: str, data_hex: str) -> str:
    """max |Delta| of VAL_BLK_DEF_0001 between the image and the image with a raw entry written (the I-2 decodes)."""
    a2l = app.current_a2l_data
    definition = describe_definition(VB, a2l)
    image = dict(app.current_file.mem_map)
    overlay = dict(image)
    start = int(address_text, 16)
    for i, byte in enumerate(bytes.fromhex(data_hex)):
        overlay[start + i] = byte
    cur, new = decode_values(definition, a2l, image), decode_values(definition, a2l, overlay)
    best = max(abs(float(b.value) - float(a.value)) for a, b in zip(cur.values, new.values))
    return ds.short_number(best)


def test_r_pe_bench_22_6_a_selected_row_over_a_raw_entry_shows_the_staged_delta_of_that_entry(tmp_path, defc_dir):
    """A raw entry at 0x800090 over VAL_BLK_DEF_0001 (DISPLAY_0001 selected), then VAL_BLK_DEF_0001 selected: its row
    shows `max |Delta| <the I-2 delta of that entry> staged`. Kills: the decode job's staged values taken as the
    current ones, an entry that starts at the record not counting as inside it."""

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await pick(pilot, sheet, DISPLAY)
        await wait_for(pilot, lambda: has_values(sheet, VB), "VAL_BLK_DEF_0001's summary", 30)
        service_of(app).add_entry("0x800090", "", "AA 55")
        app._refresh_patch_history_view()
        await wait_for(pilot, lambda: "staged" in row_text(app, VB), "the staged cell of the unselected row", 30)
        await pick(pilot, sheet, VB)
        await wait_for(pilot, lambda: st(sheet, VB).job is None and has_values(sheet, VB), "the decode of the selected row", 30)
        await pilot.pause(0.5)
        return row_text(app, VB), _delta_over_entry(app, "0x800090", "AA55")

    row, delta = run(tmp_path, defc_dir, body, size=WIDE)
    assert f"max |Δ| {delta} staged" in row, (row, delta)


@pytest.mark.parametrize("where", ["0x80008E", "0x80009C", "0x700000"])
def test_r_pe_bench_28_3_an_entry_outside_the_record_costs_the_decode_job_no_second_decode(tmp_path, defc_dir, monkeypatch, where):
    """An entry that ends where the record starts, one that starts where it ends, and one far away: selecting
    VAL_BLK_DEF_0001 decodes it once (R-PE-BENCH.28/2: the staged values are the current ones, no second decode).
    Control: an entry inside the record costs two. Kills: the overlap test widened to touching or to any entry."""
    gate = Gate(monkeypatch, "decode_values")

    async def one(app, pilot, panel, address):
        sheet = sheet_of(panel)
        await pick(pilot, sheet, DISPLAY)
        await wait_for(pilot, lambda: has_values(sheet, VB), "VAL_BLK_DEF_0001's summary", 30)
        service_of(app).add_entry(address, "", "AA 55")
        app._refresh_patch_history_view()
        await pilot.pause(1.0)
        before = gate.names("decode_values").count(VB)
        await pick(pilot, sheet, VB)
        await wait_for(pilot, lambda: st(sheet, VB).job is None and has_values(sheet, VB), "the decode of the selected row", 30)
        await pilot.pause(0.5)
        return gate.names("decode_values").count(VB) - before

    async def outside(app, pilot, panel):
        return await one(app, pilot, panel, where)

    async def inside(app, pilot, panel):
        return await one(app, pilot, panel, "0x800090")

    assert run(tmp_path, defc_dir, outside) == 1
    assert run(tmp_path, defc_dir, inside) == 2, "control: an entry inside the record makes the staged decode"


@pytest.mark.parametrize("room", [8, 12, 20, 30])
def test_r_pe_bench_5_3_a_windowed_tall_grid_fills_its_room_and_its_window_line_counts_the_painted_rows(defc, tmp_path, room):
    """LARGE (65,536 grid rows, the window line shows) in `room` lines at 118: the bench uses all of them (definition
    line, `room - 5` canvas lines of which one is the label line, the window line, the legend, the tool row, the bytes line), and the window line's
    `rows a..b` counts exactly the canvas rows painted. Kills: a canvas shape that reserves too many or too few lines,
    and a window line built from the shape before the window line took its line."""
    label, row, state, width = _windowed_cases(defc, tmp_path)[0]
    assert label == "LARGE"
    text = [line.plain for line in dv.bench_detail(row, None, width, state, room)]
    assert len(text) == room, (room, len(text))
    window = next(t for t in text if re.match(r"rows \d+\.\.\d+ of 65536", t))
    first, last = (int(n) for n in re.match(r"rows (\d+)\.\.(\d+) of", window).groups())
    assert last - first + 1 == room - 6, (room, window)
