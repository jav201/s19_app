"""Batch-103 Inc 9 E4 (tester T9b): the bench state and the bench jobs of the widget - selection side.

Widget ``ArrayBenchSheet`` (``bench_sheet.py``: B23 ``register_bench_kinds``, B29 / B28 statuses, B30
``on_staging_sheet_selection_changed``, B31 ``show_page``, B32 ``set_document``, B33 ``_run_job``, B34
``_job_done``). Requirements: R-PE-DEF.1.2/2, R-PE-BENCH.3/4, .9, .22 ... .25, .27. Cases:
``inc-9/02-test-cases-W.md``. The real app under Pilot at 118x54.

A job is held or counted by ``Gate`` (I-2 wrapper). ``BIG`` (70,000 elements, ``MATRIX_DIM 70000``) stands for
LARGE where only the job LOGIC matters (22, 23, 24, 27): every such test is PARTIAL on that point; the size-bound
cases (20, 26, 28, 29, 82) use the real 1,048,576-element LARGE in ``test_b103_inc9_w_jobs.py``.
Interface readings: see ``tests/support/b103_inc9_w.py``.
"""
from __future__ import annotations

import re
import threading

import pytest

from s19_app.tui import a2l_definition
from s19_app.tui import definition_bench as db
from s19_app.tui import definition_sheet as ds
from s19_app.tui.a2l_definition import describe_definitions
from tests.support.b103_inc8_s1 import defc  # noqa: F401  (a session fixture used by name)
from tests.support.b103_inc9_b import EX
from tests.support.b103_inc8b_r import fact
from tests.support.b103_inc9_w import (  # noqa: F401  (defc_dir is a fixture used by name)
    BIG_COUNT, CURVE, DISPLAY, MAP, VB, Gate, apply_tool, big_case, body_text, defc_dir, entries_of, hand_case,
    has_values, need, open_bench, pick, record_statuses, run, service_of, sheet_of, st, valblk_block, wait_for,
)

BIG = "BIG"
FILTER = "#patch_param_filter"
STILL_DECODING = "Patch Editor: {} is still decoding — try again when its values show."


STRIP_CURVE = fact("S.after.current.CURVE_DEF_0001")
STRIP_MAP = fact("S.after.current.MAP_DEF_0001")
STRIP_VB = fact("S.after.current.VAL_BLK_DEF_0001")


def row_text(app, name: str) -> str:
    return next(line for line in body_text(app).splitlines() if name[:12] in line)


async def set_filter(pilot, panel, sheet, text: str) -> None:
    """Type ``text`` in the picker's filter (as Inc 8's AT does: the value) and wait for the page to change."""
    before = [row.name for row in sheet.rows]
    need(panel, FILTER).value = text
    await wait_for(pilot, lambda: [row.name for row in sheet.rows] != before, f"the page for filter {text!r}", 15)
    await pilot.pause()


# ------------------------------------------------------------------ R-PE-DEF.1.2/2 (Inc 8's row, with a real bench)


def test_r_pe_def_1_2_2_a_bench_row_sets_the_bench_class_and_the_landing_pane_gets_6_rows(tmp_path, defc_dir):
    """118x54: a number row -> LANDS IN 9 rows, no `-bench`; MAP_DEF_0001 -> `-bench`, LANDS IN 6, the sheet window
    3 rows taller; back on the number row the class leaves."""

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)

        def read():
            return (panel.has_class("-bench"), need(panel, "#patch_inspector").region.height,
                    need(panel, "#patch_sheet_win").region.height)

        await pick(pilot, sheet, DISPLAY)
        await pilot.pause()
        number = read()
        await pick(pilot, sheet, MAP)
        await pilot.pause()
        bench = read()
        await pick(pilot, sheet, DISPLAY)
        await pilot.pause()
        return number, bench, read()

    number, bench, back = run(tmp_path, defc_dir, body)
    assert number[:2] == (False, 9) and back[:2] == (False, 9)
    assert bench[:2] == (True, 6) and bench[2] - number[2] == 3, (number, bench)


# ------------------------------------------------------------------ R-PE-BENCH.3/4 (EX-I1)


def test_r_pe_bench_3_4_after_import_the_three_bench_kinds_are_registered(defc):
    """`ops_for("map")` is a KindOps, `editable(MAP_DEF_0001)` is True, its build-time decode gives None; calling
    the registration twice leaves the same three keys; a kind outside I-2's three keeps no entry (EX-R9)."""
    from s19_app.tui.screens_directionb.patch_editor import bench_sheet

    ops = ds.ops_for("map")
    assert isinstance(ops, ds.KindOps)
    assert ops.editable(defc["defs"]["MAP_DEF_0001"]) is True
    assert ops.decode(defc["defs"]["MAP_DEF_0001"], defc["a2l"], defc["image"]) is None
    keys_before = {k for k in ds._KIND_OPS if k in ("curve", "map", "array")}
    bench_sheet.register_bench_kinds()
    bench_sheet.register_bench_kinds()
    assert {k for k in ds._KIND_OPS if k in ("curve", "map", "array")} == keys_before == {"curve", "map", "array"}
    assert all(ds.ops_for(kind).label == "op =" for kind in keys_before)
    assert "" not in ds._KIND_OPS


# ------------------------------------------------------------------ R-PE-BENCH.9 (EX-B1)


async def bench_with_edit(pilot, sheet):
    """MAP_DEF_0001: +Δ 100 on (0,0) applied, then the cursor moved to (1,0) so a reset would show."""
    await open_bench(pilot, sheet, MAP)
    await apply_tool(pilot, sheet, "d", "100")
    want = {(0, 0): EX.result_text(EX.MAP[0] + 100, 0)}
    await wait_for(pilot, lambda: dict(st(sheet, MAP).edit) == want, "the +Δ 100 edit")
    await pilot.press("right")
    await pilot.pause()
    assert st(sheet, MAP).cursor == (1, 0)
    return want


def test_r_pe_bench_9_1_a_filter_keystroke_that_keeps_the_row_keeps_its_state(tmp_path, defc_dir):
    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        want = await bench_with_edit(pilot, sheet)
        await set_filter(pilot, panel, sheet, "MAP_DEF")
        return want, [row.name for row in sheet.rows], dict(st(sheet, MAP).edit), st(sheet, MAP).cursor

    want, rows, edit, cursor = run(tmp_path, defc_dir, body)
    assert MAP in rows and edit == want and cursor == (1, 0)


def test_r_pe_bench_9_2_selecting_another_row_and_back_keeps_the_state(tmp_path, defc_dir):
    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        want = await bench_with_edit(pilot, sheet)
        await pick(pilot, sheet, DISPLAY)
        await pick(pilot, sheet, MAP)
        return want, dict(st(sheet, MAP).edit), st(sheet, MAP).cursor, st(sheet, MAP).tool

    want, edit, cursor, tool = run(tmp_path, defc_dir, body)
    assert edit == want and cursor == (1, 0) and tool == "d"


def test_r_pe_bench_9_3_a_page_without_the_row_drops_its_state(tmp_path, defc_dir):
    """A page whose definitions no longer hold MAP_DEF_0001, then the row back -> cursor (0,0), tool Set, edit {};
    control: before the page the state held the edit, so the fresh state is not the default of a never-used row."""

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        want = await bench_with_edit(pilot, sheet)
        held = dict(st(sheet, MAP).edit)
        await set_filter(pilot, panel, sheet, "CURVE")
        assert MAP not in [row.name for row in sheet.rows]
        await set_filter(pilot, panel, sheet, "")
        await pick(pilot, sheet, MAP)
        await wait_for(pilot, lambda: st(sheet, MAP) is not None, "the fresh state of MAP_DEF_0001")
        state = st(sheet, MAP)
        return want, held, state.cursor, state.tool, dict(state.edit)

    want, held, cursor, tool, edit = run(tmp_path, defc_dir, body)
    assert held == want
    assert cursor == (0, 0) and tool == "s" and edit == {}


# ------------------------------------------------------------------ R-PE-BENCH.22 (EX-H5, BIG for LARGE)


def test_r_pe_bench_22_1_and_2_a_decode_ended_after_the_selection_moved_is_discarded(tmp_path, defc_dir, monkeypatch):
    """BIG selected and held, SMALL_BLK selected, BIG's decode released: SMALL_BLK's values show, BIG's are
    dropped (22/1). BIG selected again: a second decode of BIG starts (22/2). PARTIAL: BIG for LARGE."""
    gate = Gate(monkeypatch, "decode_values", hold={BIG})
    a2l, s19 = big_case(tmp_path, BIG_COUNT, rows=(BIG,))

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        try:
            await pick(pilot, sheet, BIG)
            await wait_for(pilot, gate.entered.is_set, "BIG's decode held in the worker")
            await pick(pilot, sheet, "SMALL_BLK")
        finally:
            gate.release()
        await wait_for(pilot, lambda: has_values(sheet, "SMALL_BLK"), "SMALL_BLK's values")
        await pilot.pause(0.3)
        first = (has_values(sheet, BIG), all(str(v) in body_text(app) for v in (1, 2, 3, 4)),
                 f"decoding {BIG_COUNT}" in body_text(app))
        before = gate.names("decode_values").count(BIG)
        await pick(pilot, sheet, BIG)
        await wait_for(pilot, lambda: has_values(sheet, BIG), "BIG's second decode", 60)
        return first, before, gate.names("decode_values").count(BIG)

    (big_values, small_shown, stale_row), before, after = run(tmp_path, None, body, a2l=a2l, image=s19)
    assert big_values is False, "the older result was painted"
    assert small_shown and stale_row is False
    assert (before, after) == (1, 2), "re-selecting BIG must start a new decode"


# ------------------------------------------------------------------ R-PE-BENCH.23, .24 (EX-A1, EX-H6)


def test_r_pe_bench_23_1_the_page_is_summarised_off_the_ui_thread_in_page_order(tmp_path, defc_dir, monkeypatch):
    """The three DEFC bench rows show their strips and counts; every decode ran off the UI thread; the page order
    holds (the selected row's own decode may go first)."""
    gate = Gate(monkeypatch, "decode_values")

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        # Inc 8b (R-PE-BENCH.11, F-R14-1): seven levels, column-mean levels, Current 20 wide
        want = {CURVE: STRIP_CURVE, MAP: STRIP_MAP, VB: STRIP_VB}
        await wait_for(pilot, lambda: all(text in body_text(app) for text in want.values()), "the three strips", 30)
        return [row.name for row in sheet.rows], want, {n: row_text(app, n) for n in want}

    page, want, painted = run(tmp_path, defc_dir, body)
    for name, text in want.items():
        assert text in painted[name], (name, painted[name])
    assert gate.on_ui_thread() == [], gate.on_ui_thread()
    seen = list(dict.fromkeys(n for n in gate.names("decode_values") if n in want))
    expected = [n for n in page if n in want]
    assert seen == expected or (seen[1:] == [n for n in expected if n != seen[0]]), (seen, expected)


def test_r_pe_bench_11_a_strip_of_more_columns_than_its_room_keeps_the_count_visible(tmp_path, defc_dir):
    """FX9b F-X9-5 (X9 capture `v2`): a 40-element 1-D array (16 grid columns) on the sheet. CTX-PE-BENCH array row
    cells: strip width = the Current width - 1 - the count's width - 1, every k-th column, k = ceil(nx / that width).
    The painted Current cell is that many strip blocks then ` 100`: the count is the operator's only size cue, so a
    strip drawn at the whole Current width (the count cut away) is the defect.

    Retargeted at Inc 8b (R-PE-BENCH.11): the Current width is 20 and the blocks are the seven levels, never `█`.
    A 2-digit count would leave the strip 16 cells, as many as the 16 flat-grid columns, so the case uses 100
    elements (a 3-digit count: room 15 < 16 columns, k = 2)."""
    a2l, s19 = hand_case(tmp_path, [valblk_block("VB1D", 0x100000, 100)], [(0x100000, bytes(range(100)))])

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await wait_for(pilot, lambda: st(sheet, "VB1D") is not None and st(sheet, "VB1D").strip is not None,
                       "the summary of VB1D", 30)
        await pilot.pause(0.2)
        row = next(r for r in sheet.rows if r.name == "VB1D")
        width = need(panel, "#patch_sheet_body").content_size.width
        return row_text(app, "VB1D"), db.bench_grid(row.definition).nx, ds.sheet_widths(width).current

    painted, nx, current = run(tmp_path, defc_dir, body, a2l=a2l, image=s19)
    room = current - 1 - len("100") - 1
    k = -(-nx // room)
    blocks = len(range(0, nx, k))
    assert nx > room, f"the case needs more grid columns ({nx}) than the strip's room ({room})"
    found = re.search(r"([▁▂▃▄▅▆▇]+) 100", painted)
    assert found is not None, painted
    assert len(found.group(1)) == blocks, (found.group(1), blocks, painted)


def test_r_pe_bench_24_1_a_page_turn_during_a_held_summary_shows_no_old_strip(tmp_path, defc_dir, monkeypatch):
    """CURVE_DEF_0001's summary is held, the page turns to [VAL_BLK_DEF_0001], the decode is released: the new page
    shows VAL_BLK_DEF_0001's own strip and nothing of CURVE_DEF_0001's (`▄▆▃▇▁`)."""
    gate = Gate(monkeypatch, "decode_values", hold={CURVE})

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        a2l, image = app.current_a2l_data, app.current_file.mem_map
        try:
            sheet.show_page([CURVE, VB, MAP], describe_definitions([CURVE, VB, MAP], a2l), a2l, image)
            await wait_for(pilot, gate.entered.is_set, "CURVE_DEF_0001's summary held")
            sheet.show_page([VB], describe_definitions([VB], a2l), a2l, image)
            await pilot.pause()
        finally:
            gate.release()
        await wait_for(pilot, lambda: STRIP_VB in body_text(app), "the new page's strip", 30)
        await pilot.pause(0.3)
        return body_text(app)

    painted = run(tmp_path, defc_dir, body)
    old_strip = fact("S.after.CURVE_DEF_0001")
    assert old_strip not in painted and CURVE not in painted
    assert STRIP_VB in painted


# ------------------------------------------------------------------ R-PE-BENCH.25 (EX-T1, EX-F4)


def mark_of(app, name: str) -> str:
    return row_text(app, name)[:2]


def test_r_pe_bench_25_1_undo_of_a_record_stage_removes_the_staged_dot(tmp_path, defc_dir):
    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await open_bench(pilot, sheet, VB)
        await apply_tool(pilot, sheet, "s", "10")
        await wait_for(pilot, lambda: dict(st(sheet, VB).edit) == {(0, 0): "10"}, "the edit")
        await pilot.press("alt+s")
        await wait_for(pilot, lambda: len(entries_of(app)) == 1, "the stage", 60)
        await wait_for(pilot, lambda: "●" in mark_of(app, VB), "the staged dot", 30)
        need(panel, "#patch_undo_button").press()
        await wait_for(pilot, lambda: entries_of(app) == [], "the undo")
        await wait_for(pilot, lambda: "●" not in mark_of(app, VB), "the dot leaving", 30)
        return mark_of(app, VB)

    assert "●" not in run(tmp_path, defc_dir, body)


def test_r_pe_bench_25_2_a_raw_entry_over_one_row_marks_that_row_and_decodes_no_other(tmp_path, defc_dir, monkeypatch):
    """A raw bytes entry at 0x800090 (inside VAL_BLK_DEF_0001 only): `●` on that row, MAP_DEF_0001 not decoded again."""
    gate = Gate(monkeypatch, "decode_values")

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await wait_for(pilot, lambda: STRIP_VB in body_text(app) and STRIP_MAP in body_text(app), "the page summaries", 30)
        await pilot.pause(0.5)
        before = gate.names("decode_values").count(MAP)
        service_of(app).add_entry("0x800090", "", "AA 55")
        app._refresh_patch_history_view()
        await wait_for(pilot, lambda: "●" in mark_of(app, VB), "the dot on VAL_BLK_DEF_0001", 30)
        await pilot.pause(0.5)
        return mark_of(app, MAP), before, gate.names("decode_values").count(MAP), gate.names("decode_values").count(VB)

    map_mark, before, after, vb_calls = run(tmp_path, defc_dir, body)
    assert "●" not in map_mark and before == after
    assert vb_calls >= 2, "VAL_BLK_DEF_0001 must have been decoded again over the entry"


# ------------------------------------------------------------------ R-PE-BENCH.27


@pytest.mark.parametrize("route", ["apply", "stage"])
def test_r_pe_bench_27_apply_or_stage_while_the_values_decode_shows_the_still_decoding_status(
    tmp_path, defc_dir, monkeypatch, route
):
    """27/1 Enter in the op input; 27/2 alt+s: `Patch Editor: BIG is still decoding - try again ...`; the bench
    edit and the document are unchanged. PARTIAL: BIG for LARGE."""
    gate = Gate(monkeypatch, "decode_values", hold={BIG})
    statuses = record_statuses(monkeypatch)
    a2l, s19 = big_case(tmp_path, BIG_COUNT, rows=(BIG,))

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        try:
            await open_bench(pilot, sheet, BIG, decoded=False)
            await wait_for(pilot, gate.entered.is_set, "BIG's decode held")
            if route == "apply":
                await pilot.press("d", "enter")
                need(sheet, "#patch_sheet_input").value = "5"
                await pilot.pause()
                await pilot.press("enter")
            else:
                await pilot.press("alt+s")
            await pilot.pause(0.3)
            return dict(st(sheet, BIG).edit), entries_of(app)
        finally:
            gate.release()

    edit, entries = run(tmp_path, None, body, a2l=a2l, image=s19)
    assert edit == {} and entries == []
    assert STILL_DECODING.format(BIG) in statuses, statuses[-5:]


# ------------------------------------------------------------------ control of the instrument (runs on the base revision too)


def test_control_the_gate_counts_nests_and_holds_without_changing_a_result(defc, monkeypatch):
    """The oracle of 20, 22, 23, 24, 28, 70/4, 78, 79 and 83 is the I-2 wrapper `Gate`; it must be able to fail.
    Shown here against the real I-2: a call from the main thread is counted as such; the decode that
    `encode_values` makes inside is NOT a second job (peak 1, no `decode_values` entry); a held call blocks its
    thread until released; and the wrapped result equals the unwrapped one."""
    definition, a2l, image = defc["defs"][VB], defc["a2l"], defc["image"]
    plain_result = a2l_definition.decode_values(definition, a2l, image)
    original = a2l_definition.decode_values
    gate = Gate(monkeypatch, "decode_values", "encode_values", hold=set())
    assert a2l_definition.decode_values is not original, "the wrapper must replace the I-2 function"
    assert [v.text for v in a2l_definition.decode_values(definition, a2l, image).values] == [v.text for v in plain_result.values]
    a2l_definition.encode_values(definition, a2l, {(0, 0): "10"}, image)
    assert gate.calls == [("decode_values", VB, True), ("encode_values", VB, True)], gate.calls
    assert gate.peak == 1 and gate.running == 0
    gate.hold.add(VB)
    worker = threading.Thread(target=lambda: a2l_definition.decode_values(definition, a2l, image), daemon=True)
    worker.start()
    assert gate.entered.wait(10), "the held call never entered"
    worker.join(0.3)
    assert worker.is_alive(), "a held call must wait for the release"
    gate.release()
    worker.join(10)
    assert not worker.is_alive() and gate.calls[-1] == ("decode_values", VB, False)
