"""Batch-103 Inc 9 E4, group B - the bench model, part 3: the array row cells, the mark, the strip.

Design under test: ``.dev-flow/2026-11-05-batch-103/inc-9/01-requirements.md`` (rows R-PE-BENCH.10 ... .19,
.26/1, .66 preview, .79/1 mark) through ``s19_app/tui/definition_bench.py`` (new): nodes B2
``BenchValues.from_decoded``, B12 ``bench_cells``, B12a ``bench_mark``, B13 ``summary_strip``, B13a
``bench_preview``. One test per case of ``inc-9/02-test-cases-B.md``.

``bench_cells(row, state, widths)`` answers the five Inc 8 cells (Kind, Current, New, Limits, Δ); the row is
Inc 8's ``build_row`` over the DEFC definition, the widths ``sheet_widths(118)`` (Current 20 since Inc 8b, R-PE-DEF.89).
Retargeted at Inc 8b (T8b-R): R-PE-BENCH.11 (seven levels, column-mean levels, F-R14-1), R-PE-BENCH.17 (the range
form at fixed offsets) and the strips of R-PE-BENCH.19, with expected cells from ``tests/support/b103_inc8b_r.py``
(``fact``, ``EXB``). The Current strip
is the one stored in ``state.strip`` at ``_job_done`` (E3R1, E3S-06), so these tests store ``summary_strip``'s
output there. A running summary is ``state.job == "summary"``. Expected texts are the requirement's own, or are
computed by the example oracle ``EX`` / I-2.
"""

from __future__ import annotations

import dataclasses
import gc
import math
import tracemalloc

import pytest

from s19_app.tui import definition_bench as db
from s19_app.tui import definition_sheet as ds
from s19_app.tui.a2l_definition import Limits, Refusal, decode_values
from tests.support.b103_inc8b_r import EXB, fact
from tests.support.b103_inc9_b import (  # noqa: F401  (fixtures are used by name)
    EX,
    blank_state,
    big_values,
    decoded_of,
    defc,
    defc_obj,
    finite_lo_hi,
    hand_object,
    large_definition,
    numbers_of,
    ramp_id,
    same_partition,
    sheet_row,
    staged_entry,
    staged_values,
    view_state,
)

KIND, CURRENT, NEW, LIMITS, DELTA = range(5)
WIDTHS = ds.sheet_widths(118)


def strip_width(o, widths=WIDTHS) -> int:
    """The Current cell's strip width: the Current width - 1 - the count's width - 1."""
    return widths.current - 1 - len(str(o.grid.count)) - 1


def cells_of(o, state, entries=(), widths=WIDTHS):
    row = sheet_row(o.d, o.a2l, o.image, entries)
    return [cell.plain.strip() for cell in db.bench_cells(row, state, widths)], row


def summarised(o, **over):
    """A state after the summary job: the values and the stored strip of the Current cell."""
    return view_state(o, strip=db.summary_strip(o.values, o.grid, strip_width(o)), **over)


# ==========================================================================
# B12 bench_cells: Kind, Current, New, Δ, Limits
# ==========================================================================


@pytest.mark.parametrize("name, kind", [("MAP_DEF_0001", "MAP 4x3"), ("CURVE_DEF_0001", "CURVE"),
                                         ("VAL_BLK_DEF_0001", "VAL_BLK")])
def test_r_pe_bench_10_the_kind_cell(defc, name, kind):
    """R-PE-BENCH.10/1..3 - MAP_DEF_0001 `MAP 4x3`; CURVE_DEF_0001 `CURVE`; VAL_BLK_DEF_0001 `VAL_BLK`."""
    o = defc_obj(defc, name)
    assert cells_of(o, summarised(o))[0][KIND] == kind


def test_r_pe_bench_11_1_the_curve_strip_and_its_count(defc):
    """R-PE-BENCH.11/1 (changed at Inc 8b E1, F-R14-1) - CURVE_DEF_0001 -> `▄▆▃▇▁ 5` (`S.after.current.CURVE_DEF_0001`).

    Why: with eight levels the tallest block `█` filled its cell and the strips of two stacked rows fused
    into a white bar; seven levels keep a gap. The Current width is 20 now, so the strip is 17 cells wide.
    """
    o = defc_obj(defc, "CURVE_DEF_0001")
    assert strip_width(o) == fact("S.strip_width.CURVE_DEF_0001") == 17
    current = cells_of(o, summarised(o))[0][CURRENT]
    assert current == fact("S.after.current.CURVE_DEF_0001") == "▄▆▃▇▁ 5"
    assert "█" not in current


def test_r_pe_bench_11_2_the_map_strip_has_four_shaded_blocks(defc):
    """R-PE-BENCH.11/2 (changed at Inc 8b E1) - MAP_DEF_0001 -> `▆▃▅▃ 12`: one block per grid column at the level of its mean (`S.after.current.MAP_DEF_0001`)."""
    o = defc_obj(defc, "MAP_DEF_0001")
    row = sheet_row(o.d, o.a2l, o.image)
    cell = db.bench_cells(row, summarised(o), WIDTHS)[CURRENT]
    assert cell.plain.strip() == fact("S.after.current.MAP_DEF_0001") == "▆▃▅▃ 12"
    assert "█" not in cell.plain


def test_r_pe_bench_11_3_the_array_strip_has_three_shaded_blocks(defc):
    """R-PE-BENCH.11/3 (changed at Inc 8b E1) - VAL_BLK_DEF_0001 -> `▄▃▄ 6` (`S.after.current.VAL_BLK_DEF_0001`)."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    row = sheet_row(o.d, o.a2l, o.image)
    cell = db.bench_cells(row, summarised(o), WIDTHS)[CURRENT]
    assert cell.plain.strip() == fact("S.after.current.VAL_BLK_DEF_0001") == "▄▃▄ 6"
    assert "█" not in cell.plain


def test_r_pe_bench_12_1_a_large_row_whose_values_are_not_decoded(tmp_path):
    """R-PE-BENCH.12/1 - LARGE (1,048,576 elements), nothing decoded -> `1048576 values` (state and no state)."""
    a2l, d = large_definition(tmp_path)
    row = sheet_row(d, a2l, {})
    for state in (None, blank_state()):
        assert db.bench_cells(row, state, WIDTHS)[CURRENT].plain.strip() == "1048576 values"


@pytest.mark.parametrize("case", ["no image", "last byte missing"])
def test_r_pe_bench_14_a_refused_decode_shows_two_dashes(defc, case):
    """R-PE-BENCH.14/1,2 - the bench decode of VAL_BLK_DEF_0001 is a refusal: no image; an image missing the
    last byte (`A2L-DEF-BYTES`) -> Current `--`, never `refused`. The refusal is carried by ``BenchState.refusal``
    with ``values`` None (graph-inc9 §Interfaces, ruling P-056 T9 F-1); Inc 8's ``row.current`` is None for a bench
    row (no I-2 call at ``build_row``, E3A-01), so it cannot carry it."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    last = o.d.address + o.d.byte_length - 1
    image = {} if case == "no image" else {a: b for a, b in o.image.items() if a != last}
    refusal = decode_values(o.d, o.a2l, image)
    assert isinstance(refusal, Refusal) and refusal.code == "A2L-DEF-BYTES"
    row = sheet_row(o.d, o.a2l, image)
    assert row.current is None, "Inc 8 does not decode a bench row"
    assert db.bench_cells(row, blank_state(refusal=refusal), WIDTHS)[CURRENT].plain.strip() == "--"
    assert db.bench_cells(row, blank_state(), WIDTHS)[CURRENT].plain.strip() == "6 values", "the field decides"


def test_r_pe_bench_12_2_the_summary_limit_is_4096_elements(tmp_path):
    """R-PE-BENCH.12/2 - 4,097 elements -> `4097 values`; 4,096 elements are summarised (strip, ` 4096`)."""
    a2l, big = hand_object(tmp_path, "ARR_4097", "RL_U8", 4097, lo="0", hi="255")
    row = sheet_row(big, a2l, {})
    assert db.bench_cells(row, blank_state(), WIDTHS)[CURRENT].plain.strip() == "4097 values"
    a2l, edge = hand_object(tmp_path, "ARR_4096", "RL_U8", 4096, lo="0", hi="255")
    grid = db.bench_grid(edge)
    values = big_values(4096)
    state = blank_state(values=values, strip=db.summary_strip(values, grid, WIDTHS.current - 2 - 4))
    current = db.bench_cells(sheet_row(edge, a2l, {}), state, WIDTHS)[CURRENT].plain.strip()
    assert current.endswith(" 4096") and "values" not in current


def test_r_pe_bench_13_1_a_running_summary_shows_dots_and_the_count(defc):
    """R-PE-BENCH.13/1 - a summary decode held: MAP_DEF_0001 Current `… 12`."""
    o = defc_obj(defc, "MAP_DEF_0001")
    state = blank_state(job="summary")
    assert cells_of(o, state)[0][CURRENT] == "… 12"


def test_r_pe_bench_15_1_no_edit_shows_a_dot(defc):
    """R-PE-BENCH.15/1 - VAL_BLK_DEF_0001, no edit -> New `·`."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    assert cells_of(o, summarised(o))[0][NEW] == "·"


def test_r_pe_bench_15_2_the_new_cell_counts_the_changed_cells(defc):
    """R-PE-BENCH.15/2 - VAL_BLK_DEF_0001 +Δ 5 on (0,0), (1,0) -> `2 cells`; a cell whose text is unchanged is not counted."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    edit = {(0, 0): "41.9", (1, 0): "16.0"}
    assert cells_of(o, summarised(o, edit=edit))[0][NEW] == "2 cells"
    same_text = {**edit, (2, 0): "31.8"}  # 31.8 is the current text of (2,0)
    assert cells_of(o, summarised(o, edit=same_text))[0][NEW] == "2 cells", "count the changed cells, not the selection"


def test_r_pe_bench_15_3_a_curve_counts_points(defc):
    """R-PE-BENCH.15/3 - CURVE_DEF_0001 Set 40000 on points 1, 3 -> `2 pts`."""
    o = defc_obj(defc, "CURVE_DEF_0001")
    assert cells_of(o, summarised(o, edit={(1,): "40000", (3,): "40000"}))[0][NEW] == "2 pts"


def test_r_pe_bench_15_one_changed_cell_or_point_is_singular(defc):
    """FX9b F-X9-7 (X9 captures `v2`, `v12-staged`): k = 1 reads `1 cell` / `1 pt`, not `1 cells` / `1 pts`."""
    vb = defc_obj(defc, "VAL_BLK_DEF_0001")
    assert cells_of(vb, summarised(vb, edit={(0, 0): "41.9"}))[0][NEW] == "1 cell"
    curve = defc_obj(defc, "CURVE_DEF_0001")
    assert cells_of(curve, summarised(curve, edit={(1,): "40000"}))[0][NEW] == "1 pt"


def test_r_pe_bench_16_1_the_delta_is_the_largest_magnitude(defc):
    """R-PE-BENCH.16/1 - VAL_BLK_DEF_0001 +Δ 5 pending -> `max |Δ| 5`; a negative Δ is a magnitude."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    pending = cells_of(o, summarised(o, edit={(0, 0): "41.9", (1, 0): "16.0"}))[0][DELTA]
    assert pending == "max |Δ| 5"
    down = cells_of(o, summarised(o, edit={(2, 0): "21.8"}))[0][DELTA]
    assert down == "max |Δ| 10", "21.8 - 31.8 is -10: a signed Δ would show -10"


def test_r_pe_bench_16_2_staged_and_no_edit_says_staged(defc):
    """R-PE-BENCH.16/2 - the record of +Δ 5 staged, no edit -> `max |Δ| <n> staged`, n from the staged decode."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    staged, entry = staged_values(o, {(0, 0): "41.9", (1, 0): "16.0"})
    now = numbers_of(o.decoded)
    new = [x for x in staged.numbers]
    biggest = max(abs(a - b) for a, b in zip(new, now))
    got = cells_of(o, summarised(o, staged=staged), entries=[entry])[0][DELTA]
    assert got == f"max |Δ| {EX.short(biggest)} staged"
    # Ruling P-056 T9 F-3: CTX "Δ" is over the shown value, here the staged decode 838 * 0.05 = 41.900000000000006,
    # so |Δ| = 5.05...04 -> `5.1`; the case literal `5 staged` is on the Inc 9 wording list.
    assert got == "max |Δ| 5.1 staged"


def test_r_pe_bench_16_3_a_map_delta(defc):
    """R-PE-BENCH.16/3 - MAP_DEF_0001 +Δ 100 on x0..1, y0..1 -> `max |Δ| 100`."""
    o = defc_obj(defc, "MAP_DEF_0001")
    edit = {(0, 0): "572", (1, 0): "232", (0, 1): "809", (1, 1): "-790"}
    assert cells_of(o, summarised(o, edit=edit))[0][DELTA] == "max |Δ| 100"


@pytest.mark.parametrize("name", ["CURVE_DEF_0001", "MAP_DEF_0001"])
def test_r_pe_bench_17_the_limits_cell(defc, name):
    """R-PE-BENCH.17/1,2 (changed at Inc 8b E1) - the range form: both slots, `…` at offset 16 (`L.bench.CURVE_DEF_0001`, `L.bench.MAP_DEF_0001`).

    Why: the operator asked for the Limits column to stay aligned for every row kind; Inc 9's `0 … 65.5k`
    started at the column start while scalar rows put their lower limit in a right-aligned slot.
    """
    o = defc_obj(defc, name)
    row = sheet_row(o.d, o.a2l, o.image)
    cell = db.bench_cells(row, summarised(o), WIDTHS)[LIMITS].plain
    assert cell == fact(f"L.bench.{name}") and len(cell) == 34 and cell.index("…") == 16


def test_r_pe_bench_17_3_an_array_with_no_limits_shows_a_dash(defc):
    """R-PE-BENCH.17/3 (changed at Inc 8b E1) - an array with no limits -> the no-limits form: `-` at offset 16 of 34 cells."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    none = dataclasses.replace(o.d, limits=Limits(None, None, "", ""))
    row = sheet_row(none, o.a2l, o.image)
    cell = db.bench_cells(row, summarised(o), WIDTHS)[LIMITS].plain
    assert cell.strip() == "-" and cell.index("-") == 16 and len(cell) == 34


# ==========================================================================
# B12a bench_mark - R-PE-BENCH.18 (and the mark half of .79/1)
# ==========================================================================


def _mark(o, state, entries=()):
    return db.bench_mark(sheet_row(o.d, o.a2l, o.image, entries), state)


def test_r_pe_bench_18_1_a_pending_edit_shows_the_diamond(defc):
    """R-PE-BENCH.18/1 - a bench edit pending -> `◆`."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    assert _mark(o, blank_state(edit={(0, 0): "41.9"})) == "◆"


def test_r_pe_bench_18_2_staged_without_an_edit_shows_the_dot(defc):
    """R-PE-BENCH.18/2 - staged, no edit -> `●` (a byte of the span differs between the overlay and the image)."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    entry = staged_entry(o, {(0, 0): "10"})
    assert _mark(o, blank_state(), entries=[entry]) == "●"


def test_r_pe_bench_18_3_staged_and_a_new_edit_shows_the_diamond(defc):
    """R-PE-BENCH.18/3 - staged and a new edit -> `◆` (the edit wins)."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    entry = staged_entry(o, {(0, 0): "10"})
    assert _mark(o, blank_state(edit={(1, 1): "-5"}), entries=[entry]) == "◆"


def test_r_pe_bench_18_4_a_typed_operand_without_enter_shows_no_diamond(defc):
    """R-PE-BENCH.18/4 - EX-T9: operand `5` typed in the op input, no Enter: the state has no edit -> ` `."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    assert _mark(o, blank_state(edit={})) == " "


def test_r_pe_bench_79_1_after_a_stage_the_mark_is_the_dot_while_the_edit_is_empty(defc):
    """R-PE-BENCH.79/1 (the mark half; the clear is the widget's) - EX-T9: edit {} and the row staged -> `●`."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    entry = staged_entry(o, {(0, 0): "10"})
    assert _mark(o, blank_state(edit={}, undo=()), entries=[entry]) == "●"


# ==========================================================================
# B13 summary_strip - R-PE-BENCH.11 and .19
# ==========================================================================


def test_r_pe_bench_11_summary_strip_of_a_curve_is_the_oracle_strip(defc):
    """R-PE-BENCH.11 (B13, changed at Inc 8b E1) - width 17 -> the 7-level oracle strip `▄▆▃▇▁`; wider than the points: one block per point."""
    o = defc_obj(defc, "CURVE_DEF_0001")
    assert db.summary_strip(o.values, o.grid, 17).plain.rstrip() == EXB.chart_strip(EX.CURVE, 17, EXB.BLOCKS7)
    assert db.summary_strip(o.values, o.grid, 17).plain.rstrip() == fact("S.after.CURVE_DEF_0001")
    assert db.summary_strip(o.values, o.grid, 40).plain.rstrip() == EXB.chart_strip(EX.CURVE, 40, EXB.BLOCKS7)


def test_r_pe_bench_11_summary_strip_samples_every_kth_point(defc):
    """R-PE-BENCH.11 (B13) - 5 points in a strip of width 2: every k-th point, k = ceil(5 / 2) = 3 (the oracle's rule)."""
    o = defc_obj(defc, "CURVE_DEF_0001")
    assert db.summary_strip(o.values, o.grid, 2).plain.rstrip() == EXB.chart_strip(EX.CURVE, 2, EXB.BLOCKS7)


def test_r_pe_bench_19_1_nan_column_is_a_space_in_the_strip(tmp_path):
    """R-PE-BENCH.19/1 - EX-N1: F32_BLK `1`, `nan`, `3` -> the strip: block, space, block, no exception."""
    o = hand_object(tmp_path, "F32_BLK", "RL_F32", 3, bytes.fromhex("3F800000FFFFFFFF40400000"))
    strip = db.summary_strip(o.values, o.grid, 40)
    assert strip.plain[:3] == "▁ ▇", "levels 1 and 7 (lo 1, hi 3 over the finite values only), a space for the NaN"


def test_r_pe_bench_19_2_a_curve_strip_leaves_a_space_for_a_point_that_is_not_finite(defc):
    """R-PE-BENCH.19/2 - EX-N2: a CURVE of 3 points 1, inf, 3 -> seven-level blocks `▁`, space, `▇` (Inc 8b: never `█`)."""
    o = defc_obj(defc, "CURVE_DEF_0001")
    grid = db.bench_grid(dataclasses.replace(o.d, shape=(3,), element_count=3))
    values = db.BenchValues.from_decoded(decoded_of((1.0, "1"), (math.inf, "inf"), (3.0, "3")))
    assert db.summary_strip(values, grid, 15).plain.rstrip() == "▁ ▇"


def test_r_pe_bench_19_3_every_value_not_finite_gives_a_blank_strip(tmp_path):
    """R-PE-BENCH.19/3 - three `FFFFFFFF` floats: no exception, nothing shaded (lo = hi = 0)."""
    o = hand_object(tmp_path, "F32_BLK", "RL_F32", 3, bytes.fromhex("FFFFFFFF" * 3))
    strip = db.summary_strip(o.values, o.grid, 40)
    assert strip.plain.strip() == ""
    assert finite_lo_hi(numbers_of(o.decoded)) == (0.0, 0.0)


def test_r_pe_bench_19_equal_values_do_not_divide_by_zero(defc):
    """R-PE-BENCH.19 / EX-G13 (Inc 8b: seven levels) - values all `7`: a grid strip and a chart are all level 1 (`▁`)."""
    vb = defc_obj(defc, "VAL_BLK_DEF_0001")
    values = db.BenchValues.from_decoded(decoded_of(*[(7.0, "7")] * 6))
    strip = db.summary_strip(values, vb.grid, 15)
    assert strip.plain.strip() == "▁▁▁", "lo = hi: every block at level 1 (t = 0)"
    cv = defc_obj(defc, "CURVE_DEF_0001")
    flat = db.BenchValues.from_decoded(decoded_of(*[(7.0, "7")] * 5))
    assert db.summary_strip(flat, cv.grid, 15).plain.rstrip() == EXB.chart_strip([7.0] * 5, 15, EXB.BLOCKS7) == "▁▁▁▁▁"


# ==========================================================================
# B2 BenchValues.from_decoded - R-PE-BENCH.26 (compact copy)
# ==========================================================================


def test_r_pe_bench_26_from_decoded_keeps_the_element_numbers(defc):
    """R-PE-BENCH.26 (B2) - EX-A1: numbers 36.85 10.95 31.8 -20.65 -19.75 -10.7, nothing missing."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    assert [round(x, 2) for x in o.values.numbers] == [36.85, 10.95, 31.8, -20.65, -19.75, -10.7]
    assert o.values.missing == frozenset()


def test_r_pe_bench_26_from_decoded_marks_a_refused_element_missing(defc):
    """R-PE-BENCH.26 / .64 (B2) - EX-R11: a refusal at element index 2 -> missing {2}."""
    items = [(1.0, "1"), (2.0, "2"), Refusal("A2L-DEF-BYTES", "x"), (4.0, "4"), (5.0, "5"), (6.0, "6")]
    values = db.BenchValues.from_decoded(decoded_of(*items))
    assert values.missing == frozenset({2})


@pytest.mark.slow
def test_r_pe_bench_26_1_a_large_decode_is_retained_in_at_most_64_mib(tmp_path):
    """R-PE-BENCH.26/1 (partial: the compact copy only; the sheet's page and selection are B3) - LARGE decoded ->
    `tracemalloc` retained after `gc.collect()` <= 64 MiB (I-2's DecodedValues alone is about 156 MiB)."""
    a2l, d = large_definition(tmp_path)
    image = {d.address + i: i & 0xFF for i in range(d.byte_length)}
    tracemalloc.start()
    try:
        decoded = decode_values(d, a2l, image)
        kept = db.BenchValues.from_decoded(decoded)
        del decoded
        gc.collect()
        retained, _peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert len(kept.numbers) == 1048576
    assert retained <= 64 * 1024 * 1024, f"{retained / 2**20:.1f} MiB retained"


# ==========================================================================
# B13a bench_preview - R-PE-BENCH.66 (the bench never previews on a keystroke)
# ==========================================================================


def test_r_pe_bench_66_the_kind_preview_gives_no_result(defc):
    """R-PE-BENCH.66 (B13a) - EX-T2: VB, text `5` -> a Preview with no result and no decode."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    overlay = ds.StagedOverlay(o.image, [])
    preview = db.bench_preview(o.d, o.a2l, "5", overlay)
    assert isinstance(preview, ds.Preview)
    assert preview.result is None and preview.decoded is None


# ==========================================================================
# M9 (relevo-10) survivors of the group B mutant run: tests added RED on the mutant, GREEN on the product
# ==========================================================================


def test_r_pe_bench_16_4_a_staged_delta_is_a_magnitude_too(defc):
    """R-PE-BENCH.16 (M9, mutant m16b: signed staged delta) - the record of VAL_BLK_DEF_0001 staged with +5.05 on
    (0,0) and -10 on (2,0): the largest magnitude is 10, a signed maximum would show 5.1."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    staged, entry = staged_values(o, {(0, 0): "41.9", (2, 0): "21.8"})
    got = cells_of(o, summarised(o, staged=staged), entries=[entry])[0][DELTA]
    assert got == "max |Δ| 10 staged"


@pytest.mark.parametrize("limits", [Limits(0.0, None, "", ""), Limits(None, 5.0, "", "")])
def test_r_pe_bench_17_4_one_limit_alone_shows_a_dash(defc, limits):
    """R-PE-BENCH.17 (M9, mutant m17: `or` for `and`) - `-` without BOTH limits: only a lower, only an upper."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    row = sheet_row(dataclasses.replace(o.d, limits=limits), o.a2l, o.image)
    cell = db.bench_cells(row, summarised(o), WIDTHS)[LIMITS].plain
    assert cell.strip() == "-" and cell.index("-") == 16 and len(cell) == 34


def test_r_pe_bench_26_2_the_compact_values_keep_at_most_24_bytes_per_element():
    """R-PE-BENCH.26 (M9, mutant m26: a list of floats for the array) - the 64 MiB bound holds the current AND the
    staged values of a 1,048,576-element row, so one set may keep at most 32 B per element; a layout over 24 B per
    element cannot meet it with the page's other rows. 100,000 elements, retained after the decode is dropped."""
    count = 100_000

    def build():
        decoded = decoded_of(*[(i + 0.5, "x") for i in range(count)])
        return db.BenchValues.from_decoded(decoded)

    tracemalloc.start()
    try:
        before, _ = tracemalloc.get_traced_memory()
        kept = build()
        gc.collect()
        after, _ = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert len(kept.numbers) == count
    assert (after - before) / count <= 24, f"{(after - before) / count:.1f} B per element retained"
