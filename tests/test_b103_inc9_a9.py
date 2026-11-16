"""Batch-103 Inc 9 E4 (tester T9b): group A9 - staging a record: ``ChangeService.stage_record`` and the app's record-stage handler.

Nodes: A1 ``ChangeService.stage_record`` (``services/change_service.py``) and A2
``PatchMixin.on_array_bench_sheet_record_stage_requested`` (``app/patch.py``), reached through the shipped route:
the real ``S19TuiApp`` under Pilot, the bench keys, alt+s. Rows R-PE-BENCH.6, .70 ... .83 and Inc 8's R-PE-DEF.60/5.
Cases: ``inc-9/02-test-cases-W.md``. Expected bytes, texts and messages are I-2's own (``encode_values`` /
``decode_values`` over the app's A2L and image) or the literal the requirement prints; none is hand-counted.

The service tests call ``stage_record`` directly (the interface I-9.2 pins); the rest go through ``alt+s``.
``stage_record`` and the handler do not exist on the base revision, so a RED there is an AttributeError / a missing
status (see the record): it proves the feature is absent, not that a defect was caught.
Binding rulings: P-054 F-2 (an apply replaces the edit), W-1 ... W-7 of ``E4-integration-b.md``.
"""
from __future__ import annotations

import dataclasses
import logging

import pytest

from s19_app.tui.a2l_definition import Encoded, Refusal, decode_values, describe_definition, encode_values
from s19_app.tui.a2l_parse import parse_a2l_file
from s19_app.tui.app.shell import _BUSY_LINE
from s19_app.tui.services.change_service import ChangeService
from tests.support import b103_a2l_arrays as arrays
from tests.support.b103_inc8_p import build_defc_variant
from tests.support.b103_inc8_s1 import defc  # noqa: F401  (a session fixture used by name)
from tests.support.b103_inc9_w import (  # noqa: F401  (defc_dir is a fixture used by name)
    CURVE, DISPLAY, MAP, VB, Gate, apply_tool, body_text, defc_dir, entries_of, hand_case, need, open_bench, pick,
    record_statuses, run, service_of, sheet_of, st, wait_for,
)

CHANGED = "Patch Editor: {} changed in the A2L — select it again to reload its values."
STALE = "Patch Editor: the change document or the image changed while {} was encoding — stage it again."
NO_A2L = "Patch Editor: no A2L is loaded — nothing staged."
VB_ADDRESS, MAP_ADDRESS = 0x800090, 0x800070
STAGED_VB = "Patch Editor: VAL_BLK_DEF_0001 staged as 1 value (12 B at 0x800090)."
STAGED_MAP = "Patch Editor: MAP_DEF_0001 staged as 4 values (32 B at 0x800070)."


def model(app, name: str, edit: dict):
    """The I-2 encode of ``edit`` for ``name`` over the app's own A2L and image."""
    a2l = app.current_a2l_data
    return encode_values(describe_definition(name, a2l), a2l, edit, dict(app.current_file.mem_map))


def model_over(app, name: str, edit: dict):
    """The I-2 encode of ``edit`` over the staged overlay (the image with every document entry written)."""
    over = dict(app.current_file.mem_map)
    for address, data in entries_of(app):
        over.update({address + i: b for i, b in enumerate(data)})
    a2l = app.current_a2l_data
    return encode_values(describe_definition(name, a2l), a2l, edit, over)


async def preview_of(pilot, app, sheet, name: str, edit: dict) -> None:
    """Wait until the bench's preview is the I-2 encode of ``edit`` over the overlay (a stale one is not enough)."""
    want = model_over(app, name, edit)
    assert isinstance(want, Encoded), want

    def done() -> bool:
        got = st(sheet, name).preview
        return isinstance(got, Encoded) and bytes(got.data) == bytes(want.data)

    await wait_for(pilot, done, f"the preview of {name} for {edit}", 60)


async def make_edit(pilot, sheet, name, key, operand, moves=()):
    """``name``'s bench opened, the selection ``moves`` made, ``key`` ``operand`` applied, its preview done."""
    await open_bench(pilot, sheet, name)
    if moves:
        await pilot.press(*moves)
    await apply_tool(pilot, sheet, key, operand)
    await wait_for(pilot, lambda: bool(st(sheet, name).edit), f"the bench edit of {name}")
    await wait_for(pilot, lambda: st(sheet, name).preview is not None, f"the preview of {name}", 60)


async def stage(pilot, app, count: int) -> None:
    """alt+s, then wait until the document holds ``count`` entries."""
    await pilot.press("alt+s")
    await wait_for(pilot, lambda: len(entries_of(app)) == count, f"{count} staged entries", 60)
    await pilot.pause(0.3)


async def stage_refused(pilot) -> None:
    """alt+s for a stage that must be refused: let the job and the handler run."""
    await pilot.press("alt+s")
    await pilot.pause(1.0)


# ------------------------------------------------------------------ the service (A1): R-PE-BENCH.70 .72 .73 .80 .81


def stage_record_of(defc, name, edit, service=None, count=1):
    service = service or ChangeService()
    encoded = encode_values(defc["defs"][name], defc["a2l"], edit, defc["image"])
    assert isinstance(encoded, Encoded), encoded
    return service, encoded, service.stage_record(name, encoded, count)


def test_r_pe_bench_72_1_and_70_1_stage_record_writes_one_bytes_entry_and_words_the_status(defc):
    service, encoded, result = stage_record_of(defc, VB, {(0, 0): "10"})
    (entry,) = service.document.entries
    assert result.ok and result.message == STAGED_VB
    assert (entry.entry_type, entry.address, bytes(entry.encoded_bytes), entry.symbol) == ("bytes", VB_ADDRESS, encoded.data, VB)
    assert len(entry.encoded_bytes) == 12


def test_r_pe_bench_72_2_the_value_word_is_plural_from_two_values(defc):
    _, _, result = stage_record_of(defc, MAP, {(0, 0): "572", (1, 0): "232", (0, 1): "809", (1, 1): "-790"}, count=4)
    assert result.ok and result.message == STAGED_MAP
    _, _, one = stage_record_of(defc, MAP, {(1, 2): "0"}, count=1)
    assert one.message == "Patch Editor: MAP_DEF_0001 staged as 1 value (32 B at 0x800070)."


def test_r_pe_bench_80_1_stage_record_adds_one_undo_step_and_undo_restores_the_document(defc):
    service = ChangeService()
    before = service.history_depths()["back"]
    stage_record_of(defc, VB, {(0, 0): "10"}, service)
    assert service.history_depths()["back"] == before + 1 and len(service.document.entries) == 1
    service.undo()
    assert service.document.entries == [] and service.history_depths()["back"] == before


def test_r_pe_bench_70_2_a_second_stage_of_the_same_span_replaces_the_entry(defc):
    service, _, _ = stage_record_of(defc, VB, {(0, 0): "10"})
    _, second, result = stage_record_of(defc, VB, {(1, 1): "-5"}, service)
    (entry,) = service.document.entries
    assert result.ok and bytes(entry.encoded_bytes) == second.data and entry.symbol == VB


def test_r_pe_bench_73_1_two_notices_make_one_line_with_the_count_of_the_rest(defc):
    """PARTIAL: the Encoded's notices are a stand-in (`dataclasses.replace`): I-2 gives at most one per encode."""
    service = ChangeService()
    encoded = encode_values(defc["defs"][VB], defc["a2l"], {(0, 0): "10"}, defc["image"])
    result = service.stage_record(VB, dataclasses.replace(encoded, notices=("first notice", "second notice")), 2)
    assert result.ok and result.notices == ("Patch Editor: first notice (+1 more)",)


def test_r_pe_bench_73_2_one_notice_has_no_suffix(defc):
    """PARTIAL: stand-in notices as in 73/1. Control: no notice -> no notice line."""
    service = ChangeService()
    encoded = encode_values(defc["defs"][VB], defc["a2l"], {(0, 0): "10"}, defc["image"])
    one = service.stage_record(VB, dataclasses.replace(encoded, notices=("only notice",)), 1)
    none = ChangeService().stage_record(VB, dataclasses.replace(encoded, notices=()), 1)
    assert one.notices == ("Patch Editor: only notice",) and none.notices == ()


def test_r_pe_bench_81_1_a_partial_overlap_is_refused_with_inc_8s_status(defc):
    service = ChangeService()
    service.add_entry("0x800092", "", "AA BB")
    entries = list(service.document.entries)
    _, _, result = stage_record_of(defc, VB, {(0, 0): "10"}, service)
    assert result.ok is False
    assert result.message == "Patch Editor: VAL_BLK_DEF_0001 overlaps the entry at 0x800092 — remove that entry first."
    assert service.document.entries == entries


# ------------------------------------------------------------------ the handler (A2): R-PE-BENCH.6, .70 .71 .74 .76 .77


@pytest.mark.parametrize("case", ["R-PE-BENCH.6/1", "R-PE-DEF.60/5"])
def test_r_pe_bench_6_1_and_def_60_5_a_record_stage_keeps_the_row_selected_and_its_bench_shown(tmp_path, defc_dir, monkeypatch, case):
    """VAL_BLK_DEF_0001 staged: it stays selected (no advance to the next row), its bench stays shown (the legend
    line), the stage is reported once."""
    statuses = record_statuses(monkeypatch)

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await make_edit(pilot, sheet, VB, "s", "10")
        before = sheet.selected_name
        await stage(pilot, app, 1)
        return before, sheet.selected_name, body_text(app), bool(st(sheet, VB)), panel.is_dirty

    before, after, painted, state, dirty = run(tmp_path, defc_dir, body)
    assert before == after == VB and state and "shade" in painted
    assert STAGED_VB in statuses and dirty is True


def test_r_pe_bench_70_1_set_10_stages_the_whole_record_with_its_symbol(tmp_path, defc_dir):
    async def body(app, pilot, panel):
        await make_edit(pilot, sheet_of(panel), VB, "s", "10")
        await stage(pilot, app, 1)
        return entries_of(app), service_of(app).document.entries[0].symbol, model(app, VB, {(0, 0): "10"})

    entries, symbol, expected = run(tmp_path, defc_dir, body)
    assert entries == [(VB_ADDRESS, bytes.fromhex("00c800db027cfe63fe75ff2a"))] == [(expected.address, bytes(expected.data))]
    assert symbol == VB


def test_r_pe_bench_70_2_set_0_on_a_map_cell_stages_the_32_byte_record(tmp_path, defc_dir):
    async def body(app, pilot, panel):
        await make_edit(pilot, sheet_of(panel), MAP, "s", "0", moves=["right", "down", "down"])
        await stage(pilot, app, 1)
        return entries_of(app), model(app, MAP, {(1, 2): "0"})

    entries, expected = run(tmp_path, defc_dir, body)
    assert entries == [(MAP_ADDRESS, bytes(expected.data))] and len(entries[0][1]) == 32


def test_r_pe_bench_70_3_set_40000_on_curve_points_stages_the_whole_curve_record(tmp_path, defc_dir):
    """W-1 / W-2: a selection is a rectangle, so points 1 and 3 alone need two applies and the second replaces the
    first; the reachable case is points 1..3: bytes `9c 40` (40000 big-endian) at points 1, 2, 3, the first
    and last point as in the image. The requirement's literal bytes (point 2 unchanged) are not reachable."""

    async def body(app, pilot, panel):
        await make_edit(pilot, sheet_of(panel), CURVE, "s", "40000", moves=["right", "shift+right", "shift+right"])
        await stage(pilot, app, 1)
        image = dict(app.current_file.mem_map)
        return entries_of(app), [image[0x800050 + i] for i in range(10)], model(app, CURVE, {(k,): "40000" for k in (1, 2, 3)})

    entries, original, expected = run(tmp_path, defc_dir, body)
    forty = (40000).to_bytes(2, "big")
    assert entries == [(0x800050, bytes(expected.data))]
    assert entries[0][1] == bytes(original[:2]) + forty * 3 + bytes(original[8:])


def test_r_pe_bench_70_4_a_second_stage_asked_during_the_first_ones_held_encode_is_staged_too(tmp_path, defc_dir, monkeypatch):
    """EX-Q1: alt+s on VAL_BLK_DEF_0001, then on MAP_DEF_0001 while the first record's encode is held: both are
    staged (2 entries) and no `changed` status appears (the next job's snapshot follows the write, R2-01)."""
    gate = Gate(monkeypatch, "encode_values")
    statuses = record_statuses(monkeypatch)

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await make_edit(pilot, sheet, VB, "s", "10")
        await make_edit(pilot, sheet, MAP, "s", "0", moves=["right", "down", "down"])
        await open_bench(pilot, sheet, VB)
        gate.hold.add(VB)
        try:
            await pilot.press("alt+s")
            await wait_for(pilot, gate.entered.is_set, "the first record encode held")
            await open_bench(pilot, sheet, MAP)
            await pilot.press("alt+s")
            await pilot.pause(0.3)
        finally:
            gate.release()
        await wait_for(pilot, lambda: len(entries_of(app)) == 2, "both records staged", 90)
        return sorted(address for address, _ in entries_of(app))

    addresses = run(tmp_path, defc_dir, body)
    assert addresses == [MAP_ADDRESS, VB_ADDRESS]
    assert not [s for s in statuses if "changed in the A2L" in s or "changed while" in s], statuses


def test_r_pe_bench_71_1_and_2_the_second_stage_encodes_over_the_first_one(tmp_path, defc_dir):
    """AT: Set `10` on (0,0), stage; Set `-5` on (1,1), stage: one entry, decoded `10.0 11.0 31.8 -20.7 -5.0 -10.7`.
    71/2: the first edit survives (an encode over the image would read (0,0) as `36.9`)."""

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await make_edit(pilot, sheet, VB, "s", "10")
        await stage(pilot, app, 1)
        first = entries_of(app)[0]
        await pilot.press("right", "down")
        await apply_tool(pilot, sheet, "s", "-5")
        await wait_for(pilot, lambda: dict(st(sheet, VB).edit) == {(1, 1): "-5"}, "the second edit")
        await preview_of(pilot, app, sheet, VB, {(1, 1): "-5"})
        await pilot.press("alt+s")
        await wait_for(pilot, lambda: entries_of(app)[0] != first, "the second record written", 60)
        await pilot.pause(0.5)
        (address, data), a2l = entries_of(app)[0], app.current_a2l_data
        over = dict(app.current_file.mem_map)
        over.update({address + i: b for i, b in enumerate(data)})
        decoded = decode_values(describe_definition(VB, a2l), a2l, over)
        return len(entries_of(app)), [v.text for v in decoded.values]

    count, texts = run(tmp_path, defc_dir, body)
    assert count == 1
    assert " ".join(texts) == "10.0 11.0 31.8 -20.7 -5.0 -10.7"
    assert texts[0] == "10.0" != "36.9", "the first edit was lost: the second record was encoded over the image"


@pytest.mark.parametrize(
    "operand, cell, moves",
    [("60", (0, 0), []), ("abc", (1, 1), ["right", "down"]), ("10.03", (0, 0), [])],
    ids=["74-1-limits", "74-2-not-a-number", "74-3-not-integral"],
)
def test_r_pe_bench_74_a_refused_encode_shows_its_message_and_leaves_document_and_edit_unchanged(
    tmp_path, defc_dir, monkeypatch, operand, cell, moves
):
    statuses = record_statuses(monkeypatch)

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await make_edit(pilot, sheet, VB, "s", operand, moves=moves)
        edit = dict(st(sheet, VB).edit)
        await stage_refused(pilot)
        return edit, dict(st(sheet, VB).edit), entries_of(app), panel.is_dirty, model(app, VB, {cell: operand})

    edit, after, entries, dirty, refusal = run(tmp_path, defc_dir, body)
    assert isinstance(refusal, Refusal)
    assert f"Patch Editor: {refusal.message}" in statuses, statuses[-5:]
    assert edit == after == {cell: operand} and entries == [] and dirty is False


def test_r_pe_bench_76_1_no_a2l_when_the_stage_acts_says_so(tmp_path, defc_dir, monkeypatch):
    statuses = record_statuses(monkeypatch)

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await make_edit(pilot, sheet, VB, "s", "10")
        app.current_a2l_data = None
        await stage_refused(pilot)
        return entries_of(app), dict(st(sheet, VB).edit)

    entries, edit = run(tmp_path, defc_dir, body)
    assert NO_A2L in statuses and entries == [] and edit == {(0, 0): "10"}


@pytest.mark.parametrize(
    "which, old, new",
    [("77-1-moved", "VAL_BLK 0x00800090 RL_DEF_S16_ROW", "VAL_BLK 0x008000A0 RL_DEF_S16_ROW"),
     ("77-2-reshaped", "MATRIX_DIM 3 2", "MATRIX_DIM 2 3")],
)
def test_r_pe_bench_77_a_definition_changed_since_the_bench_was_built_is_refused(tmp_path, defc_dir, monkeypatch, which, old, new):
    """The loaded A2L (the reload) holds VAL_BLK_DEF_0001 moved / reshaped; the page's definition is the old one."""
    statuses = record_statuses(monkeypatch)
    reloaded = parse_a2l_file(build_defc_variant(defc_dir, tmp_path / f"{which}.a2l", old, new))

    async def body(app, pilot, panel):
        await make_edit(pilot, sheet_of(panel), VB, "s", "10")
        app.current_a2l_data = reloaded
        await stage_refused(pilot)
        return entries_of(app), panel.is_dirty

    entries, dirty = run(tmp_path, defc_dir, body)
    assert CHANGED.format(VB) in statuses and entries == [] and dirty is False


def test_r_pe_bench_77_3_the_conversion_alone_changing_is_a_change(tmp_path, defc_dir, monkeypatch):
    """EX-F7 (the payload pair of Inc 8's EX-R12 on VAL_BLK_DEF_0001: the page's A2L has CM_DEF_FINE's factor 0.05,
    the A2L loaded now 0.025, same span): +Δ 5 applied, alt+s -> the `changed` status, document unchanged.
    Negative control: comparing address, length and shape only would write bytes encoded under the other factor."""
    statuses = record_statuses(monkeypatch)
    other = parse_a2l_file(build_defc_variant(defc_dir, tmp_path / "factor.a2l", "COEFFS_LINEAR 0.05 0", "COEFFS_LINEAR 0.025 0"))

    async def body(app, pilot, panel):
        await make_edit(pilot, sheet_of(panel), VB, "d", "5", moves=["shift+right"])
        page = describe_definition(VB, app.current_a2l_data)
        app.current_a2l_data = other
        assert describe_definition(VB, other) != page, "control: the two definitions differ"
        await stage_refused(pilot)
        return entries_of(app)

    entries = run(tmp_path, defc_dir, body)
    assert CHANGED.format(VB) in statuses and entries == []


# ------------------------------------------------------------------ R-PE-BENCH.78 (EX-F5, EX-F8), .83 (EX-F6, EX-F9)


async def held_record(pilot, app, sheet, gate):
    """VAL_BLK_DEF_0001 with a Set `12` edit, its record encode held (alt+s pressed, encode entered)."""
    await make_edit(pilot, sheet, VB, "s", "12")
    gate.hold.add(VB)
    await pilot.press("alt+s")
    await wait_for(pilot, gate.entered.is_set, "the record encode held")


def test_r_pe_bench_78_1_an_undo_during_the_held_encode_makes_the_result_stale(tmp_path, defc_dir, monkeypatch):
    """A first stage (Set `10`), then Set `12` with its encode held, Undo pressed, encode released: the stale
    status, and the document is the undone one (no entry): the stale record's bytes are not written."""
    gate = Gate(monkeypatch, "encode_values")
    statuses = record_statuses(monkeypatch)

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await make_edit(pilot, sheet, VB, "s", "10")
        await stage(pilot, app, 1)
        await apply_tool(pilot, sheet, "s", "12")
        await preview_of(pilot, app, sheet, VB, {(0, 0): "12"})
        gate.hold.add(VB)
        try:
            await pilot.press("alt+s")
            await wait_for(pilot, gate.entered.is_set, "the second record encode held")
            need(panel, "#patch_undo_button").press()
            await wait_for(pilot, lambda: entries_of(app) == [], "the undo")
        finally:
            gate.release()
        await pilot.pause(1.5)
        return entries_of(app)

    entries = run(tmp_path, defc_dir, body)
    assert STALE.format(VB) in statuses and entries == [], (entries, statuses[-5:])


def test_r_pe_bench_78_2_an_image_push_during_the_held_encode_makes_the_result_stale(tmp_path, defc_dir, monkeypatch):
    """An Apply ends with the panel's image push (`set_image_mem_map`): the same stale status, document unchanged."""
    gate = Gate(monkeypatch, "encode_values")
    statuses = record_statuses(monkeypatch)

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        try:
            await held_record(pilot, app, sheet, gate)
            panel.set_image_mem_map(dict(app.current_file.mem_map))
            await pilot.pause()
        finally:
            gate.release()
        await pilot.pause(1.5)
        return entries_of(app), dict(st(sheet, VB).edit)

    entries, edit = run(tmp_path, defc_dir, body)
    assert STALE.format(VB) in statuses and entries == [] and edit == {(0, 0): "12"}


def test_r_pe_bench_83_1_a_session_action_running_refuses_the_stage_with_the_busy_line(tmp_path, defc_dir, monkeypatch):
    statuses = record_statuses(monkeypatch)

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await make_edit(pilot, sheet, VB, "s", "10")
        app._busy_begin_action("file_load", "x.s19")
        label = app._running_session_action().label
        await stage_refused(pilot)
        return label, entries_of(app), panel.is_dirty, dict(st(sheet, VB).edit)

    label, entries, dirty, edit = run(tmp_path, defc_dir, body)
    assert _BUSY_LINE.format(label=label) in statuses
    assert entries == [] and dirty is False and edit == {(0, 0): "10"}


def test_r_pe_bench_83_2_a_session_action_started_during_the_held_encode_refuses_when_it_ends(tmp_path, defc_dir, monkeypatch):
    """The busy check is made when the encode ends (E3S-04), not only before it: with only the early check this
    stage would write an entry."""
    gate = Gate(monkeypatch, "encode_values")
    statuses = record_statuses(monkeypatch)

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        try:
            await held_record(pilot, app, sheet, gate)
            app._busy_begin_action("file_load", "x.s19")
            label = app._running_session_action().label
        finally:
            gate.release()
        await pilot.pause(1.5)
        return label, entries_of(app), panel.is_dirty, dict(st(sheet, VB).edit)

    label, entries, dirty, edit = run(tmp_path, defc_dir, body)
    assert _BUSY_LINE.format(label=label) in statuses
    assert entries == [] and dirty is False and edit == {(0, 0): "12"}


# ------------------------------------------------------------------ R-PE-BENCH.80/2 and E4 addendum E3S-08


def test_r_pe_bench_80_2_the_dirty_flag_and_one_undo_step_follow_a_stage_from_clear(tmp_path, defc_dir):
    """R-PE-BENCH.80/1 and /2 through the handler: the dirty flag is False before and True after; the undo depth
    goes 0 -> 1; the Undo button restores the document before (no entry)."""

    async def body(app, pilot, panel):
        await make_edit(pilot, sheet_of(panel), VB, "s", "10")
        before = (panel.is_dirty, service_of(app).history_depths()["back"])
        await stage(pilot, app, 1)
        after = (panel.is_dirty, service_of(app).history_depths()["back"])
        need(panel, "#patch_undo_button").press()
        await wait_for(pilot, lambda: entries_of(app) == [], "the undo")
        return before, after, entries_of(app)

    before, after, entries = run(tmp_path, defc_dir, body)
    assert before == (False, 0) and after == (True, 1) and entries == []


def test_r_pe_bench_72_2_e2e_a_four_cell_stage_says_4_values(tmp_path, defc_dir, monkeypatch):
    """EX-M2 through the keys: MAP_DEF_0001 x0..1, y0..1, +Δ 100 -> `staged as 4 values (32 B at 0x800070).`"""
    statuses = record_statuses(monkeypatch)

    async def body(app, pilot, panel):
        await make_edit(pilot, sheet_of(panel), MAP, "d", "100", moves=["shift+right", "shift+down"])
        await stage(pilot, app, 1)
        return entries_of(app)

    entries = run(tmp_path, defc_dir, body)
    assert STAGED_MAP in statuses and entries[0][0] == MAP_ADDRESS and len(entries[0][1]) == 32


def test_r_pe_bench_81_1_e2e_a_raw_entry_overlapping_the_record_refuses_the_stage(tmp_path, defc_dir, monkeypatch):
    """A raw 2-byte entry at 0x800092 (inside the VAL_BLK_DEF_0001 span), then the record stage: Inc 8's overlap
    status, the document is the raw entry only."""
    statuses = record_statuses(monkeypatch)

    async def body(app, pilot, panel):
        await make_edit(pilot, sheet_of(panel), VB, "s", "10")
        service_of(app).add_entry("0x800092", "", "AA BB")
        app._refresh_patch_history_view()
        await pilot.pause(0.5)
        await stage_refused(pilot)
        return entries_of(app)

    entries = run(tmp_path, defc_dir, body)
    assert "Patch Editor: VAL_BLK_DEF_0001 overlaps the entry at 0x800092 — remove that entry first." in statuses
    assert entries == [(0x800092, bytes([0xAA, 0xBB]))]


def test_e3s_08_an_apply_and_a_stage_log_nothing_of_the_operand(tmp_path, defc_dir, caplog):
    """E4 addendum E3S-08: operand `12345` (a ULONG VAL_BLK takes it) applied and staged: `12345` is in no
    log record. Control: the operand reached the bench edit and the document, so the paths ran."""
    name = "U32_BLK"
    block = arrays.valblk(name, "0x100000", "RL_U32", "NO_COMPU_METHOD", "0", "4294967295", "MATRIX_DIM 4")
    a2l_path, _ = hand_case(tmp_path, [block], [(0x100000, bytes(16))])
    a2l, image = parse_a2l_file(a2l_path), {0x100000 + i: 0 for i in range(16)}
    caplog.set_level(logging.DEBUG)

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        sheet.show_page([name], {name: describe_definition(name, a2l)}, a2l, image)
        await pilot.pause()
        await open_bench(pilot, sheet, name)
        await apply_tool(pilot, sheet, "s", "12345")
        await wait_for(pilot, lambda: dict(st(sheet, name).edit) == {(0,): "12345"}, "the edit")
        await wait_for(pilot, lambda: st(sheet, name).preview is not None, "the preview", 30)
        app.current_a2l_data = a2l
        await pilot.press("alt+s")
        await wait_for(pilot, lambda: len(entries_of(app)) == 1, "the staged record", 30)
        return entries_of(app)

    entries = run(tmp_path, defc_dir, body)
    assert entries[0][1][:4] == (12345).to_bytes(4, "big")
    leaked = [r.getMessage() for r in caplog.records if "12345" in r.getMessage()]
    assert leaked == [], leaked
