"""Batch-103 Inc 9 E4, group B - the bench model, part 2: operand, tools, result text, undo.

Design under test: ``.dev-flow/2026-11-05-batch-103/inc-9/01-requirements.md`` (rows R-PE-BENCH.51 ... .59,
.61 ... .65, .67, .92/2) through ``s19_app/tui/definition_bench.py`` (new): nodes B8 ``parse_operand``,
B9 ``apply_tool``, B10 ``result_text``, B11 ``undo``. One test per case of ``inc-9/02-test-cases-B.md``.

Interface readings (graph + E1-slice §5 E3A-12): ``apply_tool`` and ``undo`` return one ``BenchState``; a
refusal returns the state with ``.status`` set and ``edit`` / ``undo`` unchanged. An apply REPLACES the bench
edit with the tool's results over the selection, computed from the CURRENT values; the edit before it goes to
the undo stack (R-PE-BENCH.51, EX-K5; orchestrator ruling P-054 F-2, P-056 T9 F-2). A cell whose result equals
its current value leaves the edit (R-PE-BENCH.58). A tool key is the
letter of the tool row: ``s`` Set, ``d`` +Δ, ``p`` ×%, ``i`` Interpolate, ``m`` Smooth. Expected values are
computed by the example oracle ``EX`` (``examples_inc9.py``) from the DEFC values, or are the requirement's text.
"""

from __future__ import annotations

import dataclasses
import struct

import pytest

from s19_app.tui import definition_bench as db
from s19_app.tui import definition_sheet as ds
from s19_app.tui.a2l_definition import Refusal, element_name
from tests.support.b103_a2l_arrays import cm, vtab
from tests.support.b103_inc9_b import (  # noqa: F401  (fixtures are used by name)
    EX,
    blank_state,
    decoded_of,
    defc,
    defc_obj,
    hand_object,
)

NOT_A_NUMBER = "Patch Editor: '{}' is not a number."


def run(o, tool, operand, cursor, anchor=None, values=None, **over):
    """apply_tool over ``o`` with the tool letter, the operand and the selection cursor..anchor."""
    shown = values if values is not None else o.values
    state = blank_state(tool=tool, cursor=cursor, anchor=anchor or cursor, values=shown, **over)
    return db.apply_tool(o.d, state, o.grid, shown, operand)


def edit_of(state) -> dict:
    return dict(state.edit)


def vb_text(index, delta, decimals=1):
    return EX.result_text(EX.VB[index] + delta, decimals)


# ==========================================================================
# B8 parse_operand - R-PE-BENCH.62 (EX-H8, EX-N3)
# ==========================================================================


@pytest.mark.parametrize("text, number", [(" +1.5e2 ", 150.0), (".5", 0.5), ("-3", -3.0), ("2.", 2.0), ("1E2", 100.0)])
def test_r_pe_bench_62_parse_operand_reads_the_number_text(text, number):
    """R-PE-BENCH.62 (B8) - the operand number text: spaces, sign, digits with a point, an exponent."""
    assert db.parse_operand(text) == number


@pytest.mark.parametrize("text", ["abc", "", "1_0", "1e999", "9" * 400, "1 2", "--1", "0x10", "1e", "nan", "inf"])
def test_r_pe_bench_62_parse_operand_rejects_everything_else(text):
    """R-PE-BENCH.62 (B8) - EX-H8, EX-N3: not a number text, or a double that is not finite -> None."""
    assert db.parse_operand(text) is None


# ==========================================================================
# B9 apply_tool - the five tools, R-PE-BENCH.51 ... .56, .58
# ==========================================================================


def test_r_pe_bench_51_1_set_on_one_cell_makes_the_edit(defc):
    """R-PE-BENCH.51/1 (apply half; the Enter key is the widget's) - VAL_BLK_DEF_0001 Set `10` on (0,0)."""
    after = run(defc_obj(defc, "VAL_BLK_DEF_0001"), "s", "10", (0, 0))
    assert edit_of(after) == {(0, 0): "10"}
    assert len(after.undo) == 1 and dict(after.undo[-1]) == {}, "the edit before the apply is on the undo stack"


def test_r_pe_bench_52_1_set_on_curve_points_one_and_three(defc):
    """R-PE-BENCH.52/1 - CURVE_DEF_0001 `40000` on point 1, then on point 3: each selected point gets the operand
    text; the second apply REPLACES the edit (R-PE-BENCH.51, ruling P-054 F-2), the first edit goes to undo."""
    o = defc_obj(defc, "CURVE_DEF_0001")
    first = run(o, "s", "40000", (1, 0))
    assert edit_of(first) == {(1,): "40000"}
    second = run(o, "s", "40000", (3, 0), edit=dict(first.edit), undo=first.undo)
    assert edit_of(second) == {(3,): "40000"}, "a new apply replaces the bench edit, it does not merge"
    assert dict(second.undo[-1]) == {(1,): "40000"}, "the replaced edit is on the undo stack"
    span = run(o, "s", "40000", (3, 0), (1, 0))
    assert edit_of(span) == {(1,): "40000", (2,): "40000", (3,): "40000"}, "points 1..3 in one apply"


def test_r_pe_bench_52_2_set_gives_the_operand_text_unrounded(defc):
    """R-PE-BENCH.52/2 - MAP_DEF_0001 (1,2) `0`; and the text is kept as typed (`10.03` is not rounded)."""
    mp = defc_obj(defc, "MAP_DEF_0001")
    assert edit_of(run(mp, "s", "0", (1, 2))) == {(1, 2): "0"}
    vb = defc_obj(defc, "VAL_BLK_DEF_0001")
    assert edit_of(run(vb, "s", "10.03", (0, 0))) == {(0, 0): "10.03"}


def test_r_pe_bench_53_1_delta_adds_to_the_physical_value(defc):
    """R-PE-BENCH.53/1 - VAL_BLK_DEF_0001 (0,0),(1,0) +Δ 5 -> `41.9`, `16.0` (physical 36.85 + 5, not raw + 5)."""
    after = run(defc_obj(defc, "VAL_BLK_DEF_0001"), "d", "5", (1, 0), (0, 0))
    assert edit_of(after) == {(0, 0): vb_text(0, 5), (1, 0): vb_text(1, 5)}
    assert edit_of(after) == {(0, 0): "41.9", (1, 0): "16.0"}


def test_r_pe_bench_53_2_delta_over_a_map_rectangle(defc):
    """R-PE-BENCH.53/2 - MAP_DEF_0001 x0..1, y0..1 +Δ 100 -> 572, 232, 809, -790 (EX-M2)."""
    after = run(defc_obj(defc, "MAP_DEF_0001"), "d", "100", (1, 1), (0, 0))
    want = {(c, r): EX.result_text(EX.MAP[c + 4 * r] + 100, 0) for c in (0, 1) for r in (0, 1)}
    assert edit_of(after) == want
    assert want == {(0, 0): "572", (1, 0): "232", (0, 1): "809", (1, 1): "-790"}


def test_r_pe_bench_54_1_percent_multiplies_by_one_plus_a_over_100(defc):
    """R-PE-BENCH.54/1 - VAL_BLK_DEF_0001 (1,0),(2,0) ×% 10 -> `12.0`, `35.0` (10.95 × 1.1 = 12.045)."""
    after = run(defc_obj(defc, "VAL_BLK_DEF_0001"), "p", "10", (2, 0), (1, 0))
    want = {(1, 0): EX.result_text(EX.VB[1] * 1.10, 1), (2, 0): EX.result_text(EX.VB[2] * 1.10, 1)}
    assert edit_of(after) == want == {(1, 0): "12.0", (2, 0): "35.0"}


def test_r_pe_bench_55_1_interpolate_runs_between_the_end_columns(defc):
    """R-PE-BENCH.55/1 - VAL_BLK_DEF_0001 row 0, columns 0..2 -> (1,0) `34.3`; the end cells keep their values."""
    after = run(defc_obj(defc, "VAL_BLK_DEF_0001"), "i", "", (2, 0), (0, 0))
    mid = EX.result_text(EX.VB[0] + (EX.VB[2] - EX.VB[0]) * 1 / 2, 1)
    assert edit_of(after) == {(1, 0): mid} == {(1, 0): "34.3"}


def test_r_pe_bench_55_2_interpolate_on_one_column_changes_nothing(defc):
    """R-PE-BENCH.55/2 - a 1-column selection -> no change (the status is R-PE-BENCH.65/1)."""
    vb = defc_obj(defc, "VAL_BLK_DEF_0001")
    after = run(vb, "i", "", (1, 0), edit={(0, 1): "1.0"})
    assert edit_of(after) == {(0, 1): "1.0"}
    assert after.status is not None


def test_r_pe_bench_55_interpolate_runs_by_column_not_by_axis_value(defc):
    """R-PE-BENCH.55 (negative control: by axis value) - MAP_DEF_0001 row 0, columns 0..3 (X axis `224 577 648 909`)."""
    after = run(defc_obj(defc, "MAP_DEF_0001"), "i", "", (3, 0), (0, 0))
    row0 = EX.MAP[0:4]
    want = {(c, 0): EX.result_text(row0[0] + (row0[3] - row0[0]) * c / 3, 0) for c in (1, 2)}
    assert edit_of(after) == want, "the columns are equally spaced whatever the axis points are"


def test_r_pe_bench_56_1_smooth_averages_three_columns(defc):
    """R-PE-BENCH.56/1 - VAL_BLK_DEF_0001 row 0, columns 0..2 -> (1,0) `26.5`; the ends are kept."""
    after = run(defc_obj(defc, "VAL_BLK_DEF_0001"), "m", "", (2, 0), (0, 0))
    assert edit_of(after) == {(1, 0): EX.result_text(sum(EX.VB[0:3]) / 3, 1)} == {(1, 0): "26.5"}


def test_r_pe_bench_56_2_smooth_reads_the_values_before_the_tool(defc):
    """R-PE-BENCH.56/2 - MAP_DEF_0001 row 0, columns 0..3 -> (1,0) `405`, (2,0) `357` (EX-G11, not in place)."""
    after = run(defc_obj(defc, "MAP_DEF_0001"), "m", "", (3, 0), (0, 0))
    row0 = EX.MAP[0:4]
    want = {(1, 0): EX.result_text(sum(row0[0:3]) / 3, 0), (2, 0): EX.result_text(sum(row0[1:4]) / 3, 0)}
    assert edit_of(after) == want == {(1, 0): "405", (2, 0): "357"}


def test_r_pe_bench_56_smooth_of_a_curve_is_one_grid_row(defc):
    """R-PE-BENCH.56 / CTX result - a chart is one grid row, a point is a column: CURVE points 0..2 -> point 1."""
    after = run(defc_obj(defc, "CURVE_DEF_0001"), "m", "", (2, 0), (0, 0))
    assert edit_of(after) == {(1,): EX.result_text(sum(EX.CURVE[0:3]) / 3, 0)}


# ==========================================================================
# B10 result_text - R-PE-BENCH.57 (EX-G9)
# ==========================================================================


def test_r_pe_bench_57_1_result_text_rounds_half_away_from_zero_to_the_decimals(defc):
    """R-PE-BENCH.57/1 - VAL_BLK_DEF_0001 (decimals 1): 12.045 -> `12.0`."""
    vb = defc_obj(defc, "VAL_BLK_DEF_0001").d
    assert db.result_text(vb, 12.045) == "12.0"


def test_r_pe_bench_57_2_result_text_of_a_half(defc):
    """R-PE-BENCH.57/2 - 34.325 -> `34.3`; 41.85 -> `41.9`, 15.95 -> `16.0` (the half is not a binary float tie)."""
    vb = defc_obj(defc, "VAL_BLK_DEF_0001").d
    assert db.result_text(vb, 34.325) == "34.3"
    assert db.result_text(vb, 41.85) == EX.result_text(41.85, 1) == "41.9"


def test_r_pe_bench_57_3_an_integer_map_rounds_half_away_not_half_even(defc):
    """R-PE-BENCH.57/3 - MAP_DEF_0001 (SWORD, IDENTICAL): 572.5 -> `573`, -572.5 -> `-573` (not Python's 572)."""
    mp = defc_obj(defc, "MAP_DEF_0001").d
    assert db.result_text(mp, 572.5) == "573"
    assert db.result_text(mp, -572.5) == "-573"


def test_r_pe_bench_57_no_decimals_writes_fifteen_significant_digits(defc):
    """R-PE-BENCH.57 (EX-G9) - a definition with no decimals: 0.30000000000000004 -> `0.3`."""
    plain = dataclasses.replace(defc_obj(defc, "VAL_BLK_DEF_0001").d, decimals=None)
    assert db.result_text(plain, 0.1 + 0.2) == "0.3"


# ==========================================================================
# B9 apply_tool - no-op cells, refusals; B11 undo
# ==========================================================================


def test_r_pe_bench_58_1_a_zero_delta_leaves_the_edit_empty(defc):
    """R-PE-BENCH.58/1 - MAP_DEF_0001 x0..1 (row 0) +Δ `0` -> edit {} (results equal the current values)."""
    after = run(defc_obj(defc, "MAP_DEF_0001"), "d", "0", (1, 0), (0, 0))
    assert edit_of(after) == {}


def test_r_pe_bench_58_2_a_zero_delta_on_a_rounded_cell_leaves_the_edit_empty(defc):
    """R-PE-BENCH.58/2 - VAL_BLK_DEF_0001 (0,0) shown 36.9 (physical 36.85) +Δ `0` -> edit {} (no byte changes)."""
    after = run(defc_obj(defc, "VAL_BLK_DEF_0001"), "d", "0", (0, 0))
    assert edit_of(after) == {}, "36.85 + 0 equals the current value: the rounded text `36.9` would change the byte"


def test_r_pe_bench_58_a_pending_cell_brought_back_to_its_current_value_leaves_the_edit(defc):
    """R-PE-BENCH.58 - MAP (0,0) pending `572` (472 + 100), +Δ `0`: the arithmetic starts from the current 472
    (R-PE-BENCH.51, ruling P-054 F-2), the result equals it -> edit {}; the pending edit goes to undo."""
    after = run(defc_obj(defc, "MAP_DEF_0001"), "d", "0", (0, 0), edit={(0, 0): "572"})
    assert edit_of(after) == {}
    assert dict(after.undo[-1]) == {(0, 0): "572"}
    again = run(defc_obj(defc, "MAP_DEF_0001"), "d", "-100", (0, 0), edit={(0, 0): "572"})
    assert edit_of(again) == {(0, 0): "372"}, "-100 acts on the current 472, not on the pending 572"


def test_r_pe_bench_59_1_undo_restores_the_edit_before_each_apply(defc):
    """R-PE-BENCH.59/1 - EX-K5: Set `10`, then +Δ 5 (from the current 36.85 -> `41.9`): `u` -> the Set edit; `u` -> {}."""
    vb = defc_obj(defc, "VAL_BLK_DEF_0001")
    one = run(vb, "s", "10", (0, 0))
    two = db.apply_tool(vb.d, dataclasses.replace(one, tool="d"), vb.grid, vb.values, "5")
    assert edit_of(two) == {(0, 0): vb_text(0, 5)} == {(0, 0): "41.9"}, "+Δ acts on the current value (EX-K5)"
    back = db.undo(two)
    assert edit_of(back) == {(0, 0): "10"}
    assert edit_of(db.undo(back)) == {}


def test_r_pe_bench_59_2_the_undo_stack_keeps_thirty_two_edits(defc):
    """R-PE-BENCH.59/2 - 33 applies: the 32nd `u` restores apply 1's edit, the 33rd refuses (R-PE-BENCH.61)."""
    vb = defc_obj(defc, "VAL_BLK_DEF_0001")
    state = blank_state(tool="s", values=vb.values)
    for k in range(1, 34):
        state = db.apply_tool(vb.d, state, vb.grid, vb.values, str(k))
        assert edit_of(state) == {(0, 0): str(k)}
    assert len(state.undo) == 32, "at most 32, the oldest dropped"
    for step in range(1, 33):
        state = db.undo(state)
        assert edit_of(state) == {(0, 0): str(33 - step)}, f"undo {step}"
    assert edit_of(state) == {(0, 0): "1"}
    refused = db.undo(state)
    assert refused.status == "Patch Editor: nothing to undo on the bench."


def test_r_pe_bench_61_1_undo_with_an_empty_stack_says_so(defc):
    """R-PE-BENCH.61/1 - an empty stack -> `Patch Editor: nothing to undo on the bench.`; the edit is unchanged."""
    state = blank_state(edit={(1, 0): "12.0"})
    after = db.undo(state)
    assert after.status == "Patch Editor: nothing to undo on the bench."
    assert edit_of(after) == {(1, 0): "12.0"}
    assert len(after.undo) == 0


@pytest.mark.parametrize("operand", ["abc", "", "1_0", "1e999", "9" * 400])
def test_r_pe_bench_62_a_bad_operand_is_refused_and_keeps_the_edit(defc, operand):
    """R-PE-BENCH.62/1..5 - `abc`, empty, `1_0`, `1e999`, 400 × `9`: the status echoes the operand (<= 256), edit kept."""
    vb = defc_obj(defc, "VAL_BLK_DEF_0001")
    before = blank_state(tool="d", edit={(1, 0): "12.0"})
    after = db.apply_tool(vb.d, before, vb.grid, vb.values, operand)
    assert after.status == NOT_A_NUMBER.format(ds.name_echo(operand))
    assert edit_of(after) == {(1, 0): "12.0"}
    assert len(after.undo) == 0, "a refusal pushes nothing on the undo stack"


def test_r_pe_bench_62_the_percent_tool_checks_the_operand_too(defc):
    """R-PE-BENCH.62 - ×% with `1e999` is refused with the same status as +Δ."""
    after = run(defc_obj(defc, "VAL_BLK_DEF_0001"), "p", "1e999", (0, 0))
    assert after.status == NOT_A_NUMBER.format("1e999")


def test_r_pe_bench_62_set_takes_any_text_as_its_operand(defc):
    """R-PE-BENCH.62 (the grammar is for +Δ and ×% only) - Set `abc` is not refused here (the encode refuses, .74)."""
    after = run(defc_obj(defc, "VAL_BLK_DEF_0001"), "s", "abc", (1, 1))
    assert edit_of(after) == {(1, 1): "abc"}
    assert after.status is None


def test_r_pe_bench_63_1_a_tool_on_texts_needs_numbers(tmp_path):
    """R-PE-BENCH.63/1 - a TAB_VERB VAL_BLK, +Δ `1` -> `Patch Editor: +Δ needs numbers — <name> holds texts.`"""
    blocks = (cm("CM_E", "TAB_VERB", fmt='"%.0"', ref="VT_E"), vtab("VT_E", "2", '0 "OFF"', '1 "ON"'))
    o = hand_object(tmp_path, "TAB_VB", "RL_U8", 2, bytes([1, 0]), conv="CM_E", lo="0", hi="255", blocks=blocks)
    after = run(o, "d", "1", (0, 0), edit={})
    assert after.status == "Patch Editor: +Δ needs numbers — TAB_VB holds texts."
    assert edit_of(after) == {}


def test_r_pe_bench_64_1_a_refused_element_has_no_value_to_change(defc):
    """R-PE-BENCH.64/1 - a grid with one element refused (index 2), +Δ `1` over it -> the no-value status."""
    vb = defc_obj(defc, "VAL_BLK_DEF_0001")
    items = [(36.85, "36.9"), (10.95, "11.0"), Refusal("A2L-DEF-BYTES", "x"), (-20.65, "-20.7"), (-19.75, "-19.8"),
             (-10.7, "-10.7")]
    values = db.BenchValues.from_decoded(decoded_of(*items))
    after = run(vb, "d", "1", (2, 0), values=values, edit={(0, 1): "1.0"})
    assert after.status == f"Patch Editor: {element_name(vb.d, (2, 0))} has no value to change."
    assert edit_of(after) == {(0, 1): "1.0"}


def test_r_pe_bench_64_2_a_nan_element_has_no_value_to_change(tmp_path):
    """R-PE-BENCH.64/2 - EX-N1: F32_BLK `1`, `nan`, `3`, +Δ `1` over (1,) -> `Patch Editor: F32_BLK[1] has no value to change.`"""
    o = hand_object(tmp_path, "F32_BLK", "RL_F32", 3, bytes.fromhex("3F800000FFFFFFFF40400000"))
    after = run(o, "d", "1", (1, 0))
    assert after.status == "Patch Editor: F32_BLK[1] has no value to change."
    assert edit_of(after) == {}


def test_r_pe_bench_64_set_may_replace_a_cell_that_has_no_value(tmp_path):
    """R-PE-BENCH.64 (only a tool other than Set refuses) - Set `2` over the `nan` element of F32_BLK is accepted."""
    o = hand_object(tmp_path, "F32_BLK", "RL_F32", 3, bytes.fromhex("3F800000FFFFFFFF40400000"))
    after = run(o, "s", "2", (1, 0))
    assert edit_of(after) == {(1,): "2"}


def test_r_pe_bench_65_1_interpolate_needs_two_columns(defc):
    """R-PE-BENCH.65/1 - Interpolate on 1 column -> `Patch Editor: Interpolate needs at least 2 columns in the selection.`"""
    after = run(defc_obj(defc, "VAL_BLK_DEF_0001"), "i", "", (1, 0))
    assert after.status == "Patch Editor: Interpolate needs at least 2 columns in the selection."
    assert edit_of(after) == {}


def test_r_pe_bench_65_2_smooth_needs_three_columns(defc):
    """R-PE-BENCH.65/2 - Smooth on 2 columns -> `Patch Editor: Smooth needs at least 3 columns in the selection.`"""
    after = run(defc_obj(defc, "VAL_BLK_DEF_0001"), "m", "", (1, 0), (0, 0))
    assert after.status == "Patch Editor: Smooth needs at least 3 columns in the selection."
    assert edit_of(after) == {}


def test_r_pe_bench_67_1_a_result_that_is_not_finite_is_refused(tmp_path):
    """R-PE-BENCH.67/1 - EX-N4: F64_BLK `1.7e308` at (0,), ×% `100` -> the not-finite status, edit unchanged."""
    o = hand_object(tmp_path, "F64_BLK", "RL_F64", 2, struct.pack(">dd", 1.7e308, 2.0))
    after = run(o, "p", "100", (0, 0))
    assert after.status == "Patch Editor: ×% gives a value that is not finite for F64_BLK[0]."
    assert edit_of(after) == {}


def test_r_pe_bench_92_2_the_operand_echo_is_cleaned_and_bounded(defc):
    """R-PE-BENCH.92/2 - operand ESC + 300 × `9` -> `'` U+FFFD, 255 × `9`, `…` `' is not a number.`"""
    operand = "\x1b" + "9" * 300
    after = run(defc_obj(defc, "VAL_BLK_DEF_0001"), "d", operand, (0, 0))
    assert after.status == "Patch Editor: '" + "�" + "9" * 255 + "…' is not a number."


@pytest.mark.parametrize("tool", ["d", "p", "i", "m"])
def test_r_pe_bench_53_a_flat_selection_over_the_short_last_row_leaves_out_the_cells_past_the_count(tmp_path, tool):
    """R-PE-BENCH.53 ... .56 (CTX-PE-BENCH grid: a flat grid's last row may be short) - a 1-D FLOAT32 array of 18
    elements (rows of 16 and 2), selection (15,0)..(1,1): no exception, no position past element 17. Integrator
    finding W9-F1: the tools read the rectangle's cells past the count (IndexError on base 3d345667)."""
    o = hand_object(tmp_path, "F32_18", "RL_F32", 18, struct.pack(">18f", *(k * k for k in range(1, 19))))
    after = run(o, tool, "1", (1, 1), (15, 0))
    assert after.status is None
    assert after.edit and all(position[0] < 18 for position in after.edit)
    if tool in ("d", "p"):
        assert (17,) in after.edit and (16,) not in after.edit, "row 1 keeps its one selected cell (col 1)"
    else:
        assert all(position[0] < 16 for position in after.edit), "a row whose last selected column is past the count is left out"


# ==========================================================================
# M9 (relevo-10) survivors of the group B mutant run: tests added RED on the mutant, GREEN on the product
# ==========================================================================


def test_r_pe_bench_57_4_an_integer_datatype_with_no_conversion_writes_no_decimals(defc):
    """R-PE-BENCH.57 (M9, mutant m57b: the integer rule dropped) - MAP_DEF_0001 (SWORD, IDENTICAL) even with
    decimals 2 -> `3` for 3.456; the same definition as FLOAT32_IEEE keeps the decimals -> `3.46`."""
    mp = defc_obj(defc, "MAP_DEF_0001").d
    assert db.result_text(dataclasses.replace(mp, decimals=2), 3.456) == "3"
    as_float = dataclasses.replace(mp, decimals=2, datatype="FLOAT32_IEEE")
    assert db.result_text(as_float, 3.456) == "3.46"


def test_r_pe_bench_58_4_a_set_to_the_current_text_leaves_the_edit_empty(defc):
    """R-PE-BENCH.58 (M9, mutant m58b: Set keeps a no-op cell) - MAP_DEF_0001 (0,0) shows 472: Set `472` -> edit {},
    the old edit on undo; Set `473` -> {(0,0): `473`}."""
    mp = defc_obj(defc, "MAP_DEF_0001")
    same = run(mp, "s", "472", (0, 0))
    assert edit_of(same) == {}
    assert dict(same.undo[-1]) == {}
    assert edit_of(run(mp, "s", "473", (0, 0))) == {(0, 0): "473"}
