"""Batch-103 Inc 9 E4 (tester T9b): the widget side of apply, verdict and record stage - R-PE-BENCH.51, .66, .75, .79/2, .92/1.

Widget ``ArrayBenchSheet`` (``bench_sheet.py``: B28 ``action_stage_record``, B29 ``on_array_bench_sheet_bench_apply_requested``,
B33 / B34 the jobs, B35 ``record_staged``, B36 ``record_done``). Cases: ``inc-9/02-test-cases-W.md``; the app-level
handler and the service are ``test_b103_inc9_a9.py``.

Binding rulings: P-054 F-2 (an apply starts from the CURRENT value and REPLACES the bench edit; the edit before it
goes to the undo stack) and W9's wording W-1 ... W-7 (`E4-integration-b.md`): the +Δ of a second apply is not added
to the first one's pending value.
"""
from __future__ import annotations

from s19_app.tui import definition_sheet as ds
from s19_app.tui.a2l_definition import Encoded, Refusal, describe_definition, encode_values
from s19_app.tui.a2l_parse import parse_a2l_file
from tests.support.b103_inc9_b import EX
from tests.support.b103_inc9_w import (  # noqa: F401  (defc_dir is a fixture used by name)
    CURVE, VB, WIDE, Gate, apply_tool, body_text, defc_dir, entries_of, hand_case, need, open_bench, pick,
    record_statuses, run, sheet_of, st, tail_text, valblk_block, wait_for,
)

NO_EDIT = "Patch Editor: {} has no bench edit to stage."


def model_encode(app, name: str, edit: dict):
    """What I-2 encodes ``edit`` to for ``name`` over the app's own A2L and image (the oracle of every byte)."""
    a2l = app.current_a2l_data
    return encode_values(describe_definition(name, a2l), a2l, edit, dict(app.current_file.mem_map))


# ------------------------------------------------------------------ R-PE-BENCH.51


def test_r_pe_bench_51_1_enter_in_the_op_input_applies_and_the_focus_stays(tmp_path, defc_dir):
    """VAL_BLK_DEF_0001 Set `10` on (0,0): bench edit {(0,0): `10`}, the focus stays in the op input, nothing is
    staged (Negative control: staging instead of applying would write an entry)."""

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await open_bench(pilot, sheet, VB)
        await apply_tool(pilot, sheet, "s", "10", back=False)
        await wait_for(pilot, lambda: dict(st(sheet, VB).edit) == {(0, 0): "10"}, "the Set edit")
        await pilot.pause(0.3)
        return getattr(app.focused, "id", None), entries_of(app)

    focused, entries = run(tmp_path, defc_dir, body)
    assert focused == "patch_sheet_input" and entries == []


def test_r_pe_bench_51_2_a_second_apply_replaces_the_edit_and_undo_restores_the_first(tmp_path, defc_dir):
    """P-054 F-2: Set `10` on (0,0), then +Δ 5 on (0,0): the edit is {(0,0): 36.85+5 = `41.9`} (from the CURRENT value,
    not from the pending 10), the undo stack's last item is the Set edit, `u` restores it."""

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await open_bench(pilot, sheet, VB)
        await apply_tool(pilot, sheet, "s", "10")
        await wait_for(pilot, lambda: dict(st(sheet, VB).edit) == {(0, 0): "10"}, "the Set edit")
        await apply_tool(pilot, sheet, "d", "5")
        want = {(0, 0): EX.result_text(EX.VB[0] + 5, 1)}
        await wait_for(pilot, lambda: dict(st(sheet, VB).edit) == want, "the +Δ edit from the current value")
        last = dict(st(sheet, VB).undo[-1])
        await pilot.press("u")
        await pilot.pause()
        return want, last, dict(st(sheet, VB).edit)

    want, last, restored = run(tmp_path, defc_dir, body)
    assert want == {(0, 0): "41.9"}
    assert last == {(0, 0): "10"} and restored == {(0, 0): "10"}


# ------------------------------------------------------------------ R-PE-BENCH.66 (verdict of the preview in the op line)


async def verdict_of(app, pilot, sheet, name: str, moves, key: str, operand: str) -> str:
    """The op line's tail after the preview job of ``key`` ``operand`` over the selection ``moves`` made."""
    await open_bench(pilot, sheet, name)
    if moves:
        await pilot.press(*moves)
    await apply_tool(pilot, sheet, key, operand)
    await wait_for(pilot, lambda: st(sheet, name).edit, "the bench edit")
    await wait_for(pilot, lambda: any(m in tail_text(app) for m in (" ✓", " ✗", " ▲")), "the verdict", 60)
    return tail_text(app)


def test_r_pe_bench_66_1_a_preview_without_notices_is_a_tick(tmp_path, defc_dir):
    async def body(app, pilot, panel):
        return await verdict_of(app, pilot, sheet_of(panel), VB, ["shift+right"], "d", "5")

    tail = run(tmp_path, defc_dir, body, size=WIDE)
    assert " ✓" in tail and "+Δ on 2 cells" in tail, tail


def test_r_pe_bench_66_2_a_refused_preview_shows_its_message(tmp_path, defc_dir):
    """Set `60` on (0,0): ` ✗ <the I-2 refusal message>`; the message is I-2's own, read back by a model encode."""

    async def body(app, pilot, panel):
        tail = await verdict_of(app, pilot, sheet_of(panel), VB, [], "s", "60")
        return tail, model_encode(app, VB, {(0, 0): "60"})

    tail, refusal = run(tmp_path, defc_dir, body, size=WIDE)
    assert isinstance(refusal, Refusal) and "outside the limits" in refusal.message
    assert f" ✗ {refusal.message}" in tail, tail


def test_r_pe_bench_66_3_a_percent_refusal_names_the_element(tmp_path, defc_dir):
    """CURVE_DEF_0001 ×% 50 on every point: the first refused element, by I-2's own message."""

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        tail = await verdict_of(app, pilot, sheet, CURVE, ["shift+right"] * 4, "p", "50")
        return tail, model_encode(app, CURVE, dict(st(sheet, CURVE).edit))

    tail, refusal = run(tmp_path, defc_dir, body, size=WIDE)
    assert isinstance(refusal, Refusal), refusal
    assert f" ✗ {refusal.message}" in tail, tail


# ------------------------------------------------------------------ R-PE-BENCH.75, .92/1


def test_r_pe_bench_75_1_alt_s_with_an_empty_bench_edit_says_so_and_writes_nothing(tmp_path, defc_dir, monkeypatch):
    statuses = record_statuses(monkeypatch)

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await open_bench(pilot, sheet, VB)
        await pilot.press("alt+s")
        await pilot.pause(0.5)
        return entries_of(app), app._change_service.history_depths()["back"]

    entries, depth = run(tmp_path, defc_dir, body)
    assert entries == [] and depth == 0
    assert NO_EDIT.format(VB) in statuses, statuses[-5:]


def test_r_pe_bench_92_1_a_300_character_name_is_echoed_as_256_characters_and_an_ellipsis(tmp_path, defc_dir, monkeypatch):
    """R-PE-BENCH.75's status with a 300-character object name: the name echo of Inc 8 (`ds.name_echo`), not the
    whole name. The row is a hand VAL_BLK shown through the sheet's own `show_page`."""
    statuses = record_statuses(monkeypatch)
    name = "V" + "x" * 299
    a2l_path, _ = hand_case(tmp_path, [valblk_block(name, 0x100000, 4)], [(0x100000, bytes([1, 2, 3, 4]))])
    a2l = parse_a2l_file(a2l_path)
    image = {0x100000 + i: i + 1 for i in range(4)}

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        definition = describe_definition(name, a2l)
        sheet.show_page([name], {name: definition}, a2l, image)
        await pilot.pause()
        await open_bench(pilot, sheet, name)
        await pilot.press("alt+s")
        await pilot.pause(0.5)
        return entries_of(app)

    entries = run(tmp_path, defc_dir, body)
    want = NO_EDIT.format(ds.name_echo(name))
    assert entries == [] and want in statuses, statuses[-5:]
    assert ds.name_echo(name) == name[:256] + "…" and len(want) < len(name)


# ------------------------------------------------------------------ R-PE-BENCH.79/2 (EX-Q2), R2-02, R2-03


def test_r_pe_bench_79_2_an_edit_made_while_the_record_encodes_is_kept_with_its_diamond(tmp_path, defc_dir, monkeypatch):
    """alt+s on VAL_BLK_DEF_0001 with Set `10` on (0,0) and the encode held; +Δ 1 on (1,1) meanwhile; released: the
    entry holds the staged edit only (what I-2 encodes for {(0,0): `10`}); the bench keeps the newer edit
    {(1,1): -19.75+1 = `-18.8`} (an apply replaces, P-054 F-2), `◆` in the mark column, its undo (the staged
    edit on top). Negative control: clearing whatever the edit is would leave edit {} and no diamond."""
    gate = Gate(monkeypatch, "encode_values")

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await open_bench(pilot, sheet, VB)
        await apply_tool(pilot, sheet, "s", "10")
        await wait_for(pilot, lambda: st(sheet, VB).preview is not None, "the first preview")
        staged_edit = dict(st(sheet, VB).edit)
        gate.hold.add(VB)
        try:
            await pilot.press("alt+s")
            await wait_for(pilot, gate.entered.is_set, "the record encode held")
            await pilot.press("right", "down")
            await apply_tool(pilot, sheet, "d", "1")
            newer = {(1, 1): EX.result_text(EX.VB[4] + 1, 1)}
            await wait_for(pilot, lambda: dict(st(sheet, VB).edit) == newer, "the newer edit")
        finally:
            gate.release()
        await wait_for(pilot, lambda: len(entries_of(app)) == 1, "the staged record", 60)
        await pilot.pause(0.5)
        line = next(l for l in body_text(app).splitlines() if VB[:12] in l)
        return staged_edit, newer, dict(st(sheet, VB).edit), [dict(u) for u in st(sheet, VB).undo], line[:2], \
            entries_of(app), model_encode(app, VB, staged_edit)

    staged_edit, newer, edit, undo, mark, entries, expected = run(tmp_path, defc_dir, body)
    assert isinstance(expected, Encoded) and entries == [(expected.address, bytes(expected.data))]
    assert edit == newer and "◆" in mark
    assert undo and undo[-1] == staged_edit


def test_r_pe_bench_79_3_record_staged_and_record_done_are_no_ops_for_a_name_with_no_state(tmp_path, defc_dir):
    """E4 addendum R2-03: a row the sheet holds no state for (a page turn dropped it) takes both calls without
    an exception and without creating a state."""

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        sheet.record_staged("NO_SUCH_ROW", (((0, 0), "1"),))
        sheet.record_done("NO_SUCH_ROW")
        await pilot.pause()
        return st(sheet, "NO_SUCH_ROW")

    assert run(tmp_path, defc_dir, body) is None


def test_r_pe_bench_79_4_a_page_turn_during_a_held_record_encode_still_stages(tmp_path, defc_dir, monkeypatch):
    """E4 addendum R2-03: the page turns while the record encode is held; released -> the record is staged, no
    exception (the record job is not dropped by a page turn: only a document or image change makes it stale)."""
    gate = Gate(monkeypatch, "encode_values")

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        a2l, image = app.current_a2l_data, app.current_file.mem_map
        await open_bench(pilot, sheet, VB)
        await apply_tool(pilot, sheet, "s", "10")
        await wait_for(pilot, lambda: st(sheet, VB).preview is not None, "the first preview")
        gate.hold.add(VB)
        try:
            await pilot.press("alt+s")
            await wait_for(pilot, gate.entered.is_set, "the record encode held")
            other = describe_definition("DISPLAY_0001", a2l)
            sheet.show_page(["DISPLAY_0001"], {"DISPLAY_0001": other}, a2l, image)
            await pilot.pause()
        finally:
            gate.release()
        await wait_for(pilot, lambda: len(entries_of(app)) == 1, "the staged record", 60)
        return st(sheet, VB), entries_of(app)

    state, entries = run(tmp_path, defc_dir, body)
    assert len(entries) == 1 and len(entries[0][1]) == 12
    assert state is None, "the page turn dropped the row's state, and the late record_staged did not recreate it"


# ------------------------------------------------------------------ I9 ruling C9b F-W1 (P-070, DF-04 a)


def _row_of(app, name: str) -> str:
    return next(line for line in body_text(app).splitlines() if name[:12] in line)


def test_r_pe_bench_15_16_18_the_painted_row_shows_mark_new_count_and_delta_after_an_apply_and_a_stage(tmp_path, defc_dir):
    """R-PE-BENCH.15 / .16 / .18 end to end (I9, ruling C9b F-W1: the sheet hands the row's bench state to the
    row cells, I-8.5 unchanged). VAL_BLK_DEF_0001 at 220x60 (the Δ column holds `max |Δ| … staged`), Set `10`
    on (0,0): the painted row's mark (its second cell; the first is the selection `▶`) is `◆`, with `1 cell` and `max |Δ| <|10 - 36.85|>`; after alt+s it shows `●` and
    `max |Δ| <the same> staged`. Control: before the apply the row has no mark and no Δ."""
    delta = ds.short_number(abs(10 - EX.VB[0]))

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await open_bench(pilot, sheet, VB)
        await pilot.pause(0.3)
        before = _row_of(app, VB)
        await apply_tool(pilot, sheet, "s", "10")
        await wait_for(pilot, lambda: dict(st(sheet, VB).edit) == {(0, 0): "10"}, "the Set edit")
        await pilot.pause(0.3)
        edited = _row_of(app, VB)
        await pilot.press("alt+s")
        await wait_for(pilot, lambda: len(entries_of(app)) == 1, "the stage", 60)
        await wait_for(pilot, lambda: not st(sheet, VB).edit and st(sheet, VB).staged is not None, "the staged decode", 30)
        await pilot.pause(0.3)
        return before, edited, _row_of(app, VB)

    before, edited, staged = run(tmp_path, defc_dir, body, size=WIDE)
    assert before[1] == " " and "max |Δ|" not in before, before
    assert edited[1] == "◆", edited
    # Inc 8b grid: each cell is followed by its `│` gutter, so the New cell reads `1 cell` between gutters.
    assert "1 cell" in [c.strip() for c in edited.split("│")] and "1 cells" not in edited, edited  # FX9b F-X9-7: k = 1 is singular
    assert f"max |Δ| {delta}" in edited, edited
    assert staged[1] == "●", staged
    assert f"max |Δ| {delta} staged" in staged, staged
