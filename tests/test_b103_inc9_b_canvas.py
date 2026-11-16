"""Batch-103 Inc 9 E4, group B - the bench render, part 1: canvases, axis labels, legend, tool row, window line.

Design under test: ``.dev-flow/2026-11-05-batch-103/inc-9/01-requirements.md`` (rows R-PE-BENCH.19, .30 ... .35,
.37, .90, .91, and the geometry half of .5 / .7) through ``s19_app/tui/definition_bench_view.py`` (new): nodes
B15 ``grid_canvas``, B16 ``chart_canvas``, B17 ``axis_labels``, B18 ``legend_line``, B19 ``tool_row``,
B20 ``window_line``. One test per case of ``inc-9/02-test-cases-B.md``.

How a painted value is read: the ramp colours are not pinned, so a ramp step is read as an equivalence class
(two cells have the same step exactly when their colours are equal) against the step the example oracle
``EX.step`` computes; a bold, an edit colour or an unshaded cell is read the same way (the style at the offset
of the text that was found, never at a counted offset). A chart bar is read as the sum of its eighth blocks per
screen column.
"""

from __future__ import annotations

import dataclasses
import math

import pytest

from s19_app.tui import definition_bench as db
from s19_app.tui import definition_bench_view as dv
from s19_app.tui.a2l_definition import Decoded, DecodedAxis, Refusal
from tests.support.b103_inc9_b import (  # noqa: F401  (fixtures are used by name)
    EX,
    FFFD,
    bg_at,
    blank_state,
    big_values,
    decoded_of,
    defc,
    defc_obj,
    hand_object,
    large_definition,
    linked,
    locate,
    max_cells,
    plain_of,
    ramp_id,
    same_partition,
    style_at,
    view_state,
)

EIGHTHS = "▁▂▃▄▅▆▇█"


def grid_lines(o, width=114, room=20, staged=None, **over):
    state = view_state(o, **over)
    return dv.grid_canvas(o.d, o.grid, state.values, staged, state, width, room)


def chart_lines(o, width=114, room=20, staged=None, **over):
    state = view_state(o, **over)
    return dv.chart_canvas(o.d, o.grid, state.values, staged, state, width, room)


def bar_groups(lines):
    """[(first x, last x, height in eighths)] of the bars: runs of equal positive height per screen column."""
    wide = max((len(line.plain) for line in lines), default=0)
    height = [0] * wide
    for line in lines:
        for x, ch in enumerate(line.plain):
            if ch in EIGHTHS:
                height[x] += EIGHTHS.index(ch) + 1
    groups, x = [], 0
    while x < wide:
        if height[x] == 0:
            x += 1
            continue
        start = x
        while x + 1 < wide and height[x + 1] == height[start]:
            x += 1
        groups.append((start, x, height[start]))
        x += 1
    return groups


def bottom_bar_line(lines):
    return max(i for i, line in enumerate(lines) if any(ch in EIGHTHS for ch in line.plain))


def large_object(tmp_path):
    a2l, d = large_definition(tmp_path)
    grid = db.bench_grid(d)
    values = big_values(grid.count)
    labels = dv.axis_labels(d, (), grid)
    return d, grid, values, blank_state(values=values, labels=labels)


# ==========================================================================
# B15 grid_canvas - R-PE-BENCH.31, .19, .90, .91
# ==========================================================================


def test_r_pe_bench_31_1_map_cells_in_element_order_with_their_ramp_steps(defc):
    """R-PE-BENCH.31/1 - MAP_DEF_0001: 4 x 3 cells in element order, (1,1) `-890` on step 0, (0,2) `843` on step 11."""
    o = defc_obj(defc, "MAP_DEF_0001")
    lines = grid_lines(o, width=114)
    where = {}
    for i, value in enumerate(EX.MAP):
        where[i] = locate(lines, str(value))
    for i in range(12):
        c, r = i % 4, i // 4
        assert where[i][0] == where[r * 4][0], f"cell ({c},{r}) is on its row's line"
        if c:
            assert where[i][1] > where[i - 1][1], f"cell ({c},{r}) is right of ({c - 1},{r})"
        if r:
            assert where[i][0] > where[i - 4][0], f"row {r} is below row {r - 1}"
    steps = [EX.step(v, min(EX.MAP), max(EX.MAP)) for v in EX.MAP]
    assert (steps[1 + 4 * 1], steps[0 + 4 * 2]) == (0, 11)
    ids = [bg_at(lines[where[i][0]], where[i][1]) for i in range(12)]
    assert same_partition(steps, ids), "the cell background is the ramp step of its value"
    assert ids[5] != ids[8]


def test_r_pe_bench_31_2_array_cells(defc):
    """R-PE-BENCH.31/2 - VAL_BLK_DEF_0001: 3 x 2 cells `36.9 11.0 31.8 / -20.7 -19.8 -10.7`."""
    lines = grid_lines(defc_obj(defc, "VAL_BLK_DEF_0001"), width=114)
    squeezed = [" ".join(plain.split()) for plain in plain_of(lines)]
    assert any("36.9 11.0 31.8" in text for text in squeezed)
    assert any("-20.7 -19.8 -10.7" in text for text in squeezed)
    row0, row1 = (next(i for i, t in enumerate(squeezed) if key in t) for key in ("36.9 11.0", "-20.7 -19.8"))
    assert row0 < row1


def test_r_pe_bench_31_3_an_edited_cell_is_bold_with_a_star(defc):
    """R-PE-BENCH.31/3 - +Δ 5 on (0,0), (1,0): `41.9*`, `16.0*` bold; the other cells plain."""
    lines = grid_lines(defc_obj(defc, "VAL_BLK_DEF_0001"), width=114, edit={(0, 0): "41.9", (1, 0): "16.0"})
    for token in ("41.9*", "16.0*"):
        index, at = locate(lines, token)
        assert style_at(lines[index], at).bold, token
    index, at = locate(lines, "31.8")
    assert not style_at(lines[index], at).bold
    assert "31.8*" not in "".join(plain_of(lines))
    assert "36.9" not in "".join(plain_of(lines)), "the pending text replaces the current text in the cell"


@pytest.mark.parametrize("width", [96, 118, 200])
def test_r_pe_bench_31_the_grid_geometry_follows_the_examples(tmp_path, width):
    """R-PE-BENCH.31 / EX-G6 - LARGE (nx 16): nc = min(nx, (W-6)//6) columns, cell width max(5, min(20, (W-6)//nc-1))."""
    d, grid, values, state = large_object(tmp_path)
    lines = dv.grid_canvas(d, grid, values, None, state, width, 20)
    nc = min(16, (width - 6) // 6)
    cw = max(5, min(20, (width - 6) // nc - 1))
    header = next(line.plain for line in lines if "+0" in line.plain)
    assert header.count("+") == nc
    expected = 6 + nc * cw + (nc - 1)
    assert max_cells(lines) in (expected, width), f"nc {nc} cw {cw}"
    assert max_cells(lines) <= width


def test_r_pe_bench_5_a_wide_cell_width_for_few_columns(defc):
    """R-PE-BENCH.31 / EX-G6 - MAP (nx 4) and VAL_BLK (nx 3) at W 118: cell width 20 (no more than 20 cells per cell)."""
    for name, nx in (("MAP_DEF_0001", 4), ("VAL_BLK_DEF_0001", 3)):
        lines = grid_lines(defc_obj(defc, name), width=118)
        expected = 6 + nx * 20 + (nx - 1)
        assert max_cells(lines) in (expected, 118), name


def test_r_pe_bench_19_1_a_nan_cell_is_unshaded(tmp_path):
    """R-PE-BENCH.19/1 - EX-N1: F32_BLK `1`, `nan`, `3`: cells `1`, `nan`, `3`, the `nan` cell has no shade, no exception."""
    o = hand_object(tmp_path, "F32_BLK", "RL_F32", 3, bytes.fromhex("3F800000FFFFFFFF40400000"))
    lines = grid_lines(o, width=114)
    index, at = locate(lines, "nan")
    assert bg_at(lines[index], at) is None, "a value that is not finite shows its text plainly"
    first = lines[index].plain.index("1", lines[index].plain.index("0") + 1)
    last = lines[index].plain.rindex("3")
    assert first < at < last
    shaded = {bg_at(lines[index], first), bg_at(lines[index], last)}
    assert None not in shaded and len(shaded) == 2, "the finite cells are shaded (steps 0 and 11)"


def test_r_pe_bench_19_3_every_value_not_finite_gives_no_shade_and_no_exception(tmp_path):
    """R-PE-BENCH.19/3 - three `FFFFFFFF`: lo = hi = 0, every cell `nan` and unshaded."""
    o = hand_object(tmp_path, "F32_BLK", "RL_F32", 3, bytes.fromhex("FFFFFFFF" * 3))
    lines = grid_lines(o, width=114)
    index, at = locate(lines, "nan")
    assert lines[index].plain.count("nan") == 3
    assert bg_at(lines[index], at) is None


def test_r_pe_bench_90_3_an_element_text_is_not_markup(defc):
    """R-PE-BENCH.90/3 - an element text `[@click=app.quit]OFF[/]` is shown literally, with no action link."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    hostile = "[@click=app.quit]OFF[/]"
    values = db.BenchValues.from_decoded(decoded_of(*[Decoded(None, hostile, hostile)] * 6))
    lines = grid_lines(o, width=114, values=values)
    assert "[@click=app.quit]" in "".join(plain_of(lines)), "the brackets are text, not parsed"
    assert not any(linked(line) for line in lines)


def test_r_pe_bench_90_1_an_axis_text_is_not_markup(defc):
    """R-PE-BENCH.90/1 - an axis point text `A[/x]B` is shown literally (axis_labels and the painted header)."""
    o = defc_obj(defc, "MAP_DEF_0001")
    axes = (DecodedAxis("X", (Decoded(0, 224, "A[/x]B"),) + o.axes[0].points[1:]), o.axes[1])
    labels = dv.axis_labels(o.d, axes, o.grid)
    assert labels[0][0] == "A[/x]B"
    lines = grid_lines(o, width=114, axes=axes, labels=labels)
    assert "A[/x]B" in "".join(plain_of(lines))
    assert not any(linked(line) for line in lines)


def test_r_pe_bench_91_1_a_control_character_in_an_element_text_becomes_fffd(defc):
    """R-PE-BENCH.91/1 - an element text `A\\x1b[2J` -> `A` U+FFFD `[2J` in the cell."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    text = "A\x1b[2J"
    values = db.BenchValues.from_decoded(decoded_of(*[Decoded(None, text, text)] * 6))
    plain = "".join(plain_of(grid_lines(o, width=114, values=values)))
    assert "A" + FFFD + "[2J" in plain
    assert "\x1b" not in plain


# ==========================================================================
# the minimum widths and rooms of the grid - R-PE-BENCH.5/4,5 (canvas half), .7
# ==========================================================================


def test_r_pe_bench_7_the_grid_clamps_below_the_bench_minimum_width(tmp_path):
    """R-PE-BENCH.7 / EX-W2 - LARGE (nx 16) at W 12 -> one column of 5 cells; at W 10 no ZeroDivisionError."""
    d, grid, values, state = large_object(tmp_path)
    at_12 = dv.grid_canvas(d, grid, values, None, state, 12, 20)
    assert at_12 and max_cells(at_12) <= 12
    dv.grid_canvas(d, grid, values, None, state, 10, 20)  # clamped geometry: nc 1, cw 5, no exception
    dv.grid_canvas(d, grid, values, None, state, 0, 20)


def test_r_pe_bench_5_the_grid_paints_nothing_without_room(defc):
    """R-PE-BENCH.5/5 (canvas half) - room 0 -> no line; a small room never raises. R-PE-BENCH.5 bounds every bench
    line, the canvas included (ruling P-056 T9 F-5): never more lines than ``room``."""
    o = defc_obj(defc, "MAP_DEF_0001")
    assert grid_lines(o, room=0) == []
    for room in (1, 2, 3, 4, 5, 6, 7, 20):
        lines = grid_lines(o, room=room)
        assert lines and len(lines) <= room, room


def test_r_pe_bench_5_the_chart_paints_nothing_without_room(defc):
    """R-PE-BENCH.5/5 (canvas half) - EX-W3: room 0 -> no line; rooms 1 ... 5 (h = 1) paint without exception and,
    edited or not, never more lines than ``room`` (ruling P-056 T9 F-5)."""
    o = defc_obj(defc, "CURVE_DEF_0001")
    assert chart_lines(o, room=0) == []
    for room in (1, 2, 3, 4, 5, 8, 30):
        for edit in ({}, {(1,): "40000"}):
            lines = chart_lines(o, room=room, edit=edit)
            assert lines and len(lines) <= room, (room, edit)


# ==========================================================================
# B16 chart_canvas - R-PE-BENCH.30, .19/2
# ==========================================================================


def test_r_pe_bench_30_1_the_chart_has_five_columns_and_the_fourth_is_tallest(defc):
    """R-PE-BENCH.30/1 - CURVE_DEF_0001 at 118: 5 columns, heights follow the values (58106 tallest, 11719 shortest)."""
    o = defc_obj(defc, "CURVE_DEF_0001")
    lines = chart_lines(o, width=114, room=20)
    groups = bar_groups(lines)
    assert len(groups) == 5
    heights = [g[2] for g in groups]
    assert heights.index(max(heights)) == 3 and heights.index(min(heights)) == 4
    lo, hi = min(EX.CURVE), max(EX.CURVE)
    base = lo - (hi - lo) / 10
    total = max(heights)
    for height, value in zip(heights, EX.CURVE):
        want = (value - base) / (hi - base) * total
        assert abs(height - want) <= 1.5, "bars by value from the base 10 % of the span under lo, not by rank"


def test_r_pe_bench_30_2_the_chart_labels_hi_on_top_and_lo_at_the_bottom(defc):
    """R-PE-BENCH.30/2 - top label `58106`, bottom label `11719` (hi on the top row, lo on the bottom row)."""
    lines = chart_lines(defc_obj(defc, "CURVE_DEF_0001"), width=114, room=20)
    top, bottom = locate(lines, "58106")[0], locate(lines, "11719")[0]
    assert top < bottom
    assert lines[top].plain.split()[0] == "58106"
    assert lines[bottom].plain.split()[0] == "11719"
    assert bottom == bottom_bar_line(lines)


def test_r_pe_bench_30_3_an_edited_point_has_the_edit_colour_its_text_above_and_the_old_level(defc):
    """R-PE-BENCH.30/3 - Set 40000 on points 1, 3: edit colour, `40000` above the chart, `─` at the old levels."""
    o = defc_obj(defc, "CURVE_DEF_0001")
    lines = chart_lines(o, width=114, room=20, edit={(1,): "40000", (3,): "40000"})
    groups = bar_groups(lines)
    assert len(groups) == 5
    base_line = bottom_bar_line(lines)
    ids = [ramp_id(lines[base_line], g[0]) for g in groups]
    assert ids[1] == ids[3] and ids[0] == ids[2] == ids[4], "the two edited points share the edit colour"
    assert ids[1] != ids[0], "the edit colour is not the base colour"
    assert "".join(plain_of(lines)).count("40000") == 2
    assert locate(lines, "40000")[0] < locate(lines, "58106")[0], "the value text is above the chart"
    assert sum(line.plain.count("─") + line.plain.count("━") for line in lines) >= 2


def test_r_pe_bench_19_2_a_point_that_is_not_finite_has_no_bar_and_a_question_mark(defc):
    """R-PE-BENCH.19/2 - EX-N2: a CURVE copy 1, inf, 3: point 1 drawn `?` on the base line, top label 3, bottom label 1."""
    o = defc_obj(defc, "CURVE_DEF_0001")
    d = dataclasses.replace(o.d, shape=(3,), element_count=3)
    grid = db.bench_grid(d)
    values = db.BenchValues.from_decoded(decoded_of((1.0, "1"), (math.inf, "inf"), (3.0, "3")))
    state = blank_state(values=values, lo=1.0, hi=3.0, labels=dv.axis_labels(d, (), grid))
    lines = dv.chart_canvas(d, grid, values, None, state, 114, 20)
    mark_line, mark_at = locate(lines, "?")
    bottom = bottom_bar_line(lines)
    groups = bar_groups(lines)
    assert len(groups) == 2, "points 0 and 2 have bars, point 1 has none"
    assert mark_line == bottom, "the `?` sits on the base line"
    assert groups[0][1] < mark_at < groups[1][0], "between the bars of points 0 and 2"
    assert lines[0].plain.split()[0] == "3" and lines[bottom].plain.split()[0] == "1", "top label hi, bottom label lo"


def test_r_pe_bench_90_a_chart_tick_label_is_not_markup(defc):
    """R-PE-BENCH.90 - a COM axis point text `A[/x]B` under the chart is shown literally."""
    o = defc_obj(defc, "CURVE_DEF_0001")
    axes = (DecodedAxis("X", (Decoded(0, 242.5, "A[/x]B"),) + o.axes[0].points[1:]),)
    labels = dv.axis_labels(o.d, axes, o.grid)
    lines = chart_lines(o, width=114, room=20, axes=axes, labels=labels)
    assert "A[/x]B" in "".join(plain_of(lines))
    assert not any(linked(line) for line in lines)


# ==========================================================================
# B17 axis_labels - R-PE-BENCH.32, .33, .91
# ==========================================================================


def test_r_pe_bench_32_1_a_map_is_labelled_by_its_axis_points(defc):
    """R-PE-BENCH.32/1 - MAP_DEF_0001 columns `224 577 648 909` (STD), rows `10 15 20` (FIX)."""
    o = defc_obj(defc, "MAP_DEF_0001")
    columns, rows = dv.axis_labels(o.d, o.axes, o.grid)
    assert columns == ["224", "577", "648", "909"]
    assert rows == ["10", "15", "20"]
    assert columns == [p.text for p in o.axes[0].points]


def test_r_pe_bench_32_2_a_curve_is_labelled_by_its_com_axis(defc):
    """R-PE-BENCH.32/2 - CURVE_DEF_0001 ticks `242.500` at point 0 and `450.500` at point 4 (COM axis AXIS_DEF_0001)."""
    o = defc_obj(defc, "CURVE_DEF_0001")
    columns, _rows = dv.axis_labels(o.d, o.axes, o.grid)
    assert columns[0] == "242.500" and columns[4] == "450.500"
    assert columns == ["242.500", "317.500", "348.000", "414.000", "450.500"]


def test_r_pe_bench_32_3_a_two_dimensional_array_is_labelled_by_index(defc):
    """R-PE-BENCH.32/3 - VAL_BLK_DEF_0001 columns `0 1 2`, rows `0 1`."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    assert dv.axis_labels(o.d, o.axes, o.grid) == (["0", "1", "2"], ["0", "1"])


def test_r_pe_bench_32_a_flat_array_labels_columns_plus_c_and_rows_by_first_element(tmp_path):
    """R-PE-BENCH.32 / EX-G12 - LARGE: columns `+0` .. `+15`, rows `0`, `16`, `32`, ... (the first element of the row)."""
    d, grid, _values, _state = large_object(tmp_path)
    columns, rows = dv.axis_labels(d, (), grid)
    assert columns == [f"+{c}" for c in range(16)]
    assert len(rows) == 65536 and rows[:3] == ["0", "16", "32"] and rows[-1] == str(16 * 65535)


def test_r_pe_bench_33_1_an_axis_with_no_points_is_labelled_by_index(defc):
    """R-PE-BENCH.33/1 - EX-R10: an axis whose points are None -> `x0 x1 …` (the other axis keeps its texts)."""
    o = defc_obj(defc, "MAP_DEF_0001")
    columns, rows = dv.axis_labels(o.d, (DecodedAxis("X", None), o.axes[1]), o.grid)
    assert columns == ["x0", "x1", "x2", "x3"]
    assert rows == ["10", "15", "20"]
    _, rows_none = dv.axis_labels(o.d, (o.axes[0], DecodedAxis("Y", None)), o.grid)
    assert rows_none == ["y0", "y1", "y2"]


def test_r_pe_bench_33_2_a_point_that_is_a_refusal_is_labelled_by_index(defc):
    """R-PE-BENCH.33/2 - EX-R10: a COM axis whose object's bytes are missing -> `x<c>`; a single refused point only itself."""
    o = defc_obj(defc, "CURVE_DEF_0001")
    gone = DecodedAxis("X", tuple(Refusal("A2L-DEF-BYTES", "x") for _ in range(5)))
    assert dv.axis_labels(o.d, (gone,), o.grid)[0] == ["x0", "x1", "x2", "x3", "x4"]
    points = list(o.axes[0].points)
    points[1] = Refusal("A2L-DEF-BYTES", "x")
    mixed = dv.axis_labels(o.d, (DecodedAxis("X", tuple(points)),), o.grid)[0]
    assert mixed == ["242.500", "x1", "348.000", "414.000", "450.500"]


def test_r_pe_bench_91_a_control_character_in_an_axis_text_becomes_fffd(defc):
    """R-PE-BENCH.91 - an axis point text `A\\x1b[2J` is labelled `A` U+FFFD `[2J`."""
    o = defc_obj(defc, "CURVE_DEF_0001")
    point = Decoded(0, 242.5, "A\x1b[2J")
    labels = dv.axis_labels(o.d, (DecodedAxis("X", (point,) + o.axes[0].points[1:]),), o.grid)[0]
    assert labels[0] == "A" + FFFD + "[2J"


# ==========================================================================
# B18 legend_line - R-PE-BENCH.34, .19, .90/2, .91/2
# ==========================================================================


def test_r_pe_bench_34_1_the_map_legend(defc):
    """R-PE-BENCH.34/1 - MAP_DEF_0001, selection (0,0): `shade ████████████ -890 … 843   sel x0,y0   * / bold = edited` (EX-G4)."""
    o = defc_obj(defc, "MAP_DEF_0001")
    state = view_state(o)
    legend = dv.legend_line(o.d, o.grid, o.values, state)
    assert legend.plain.strip() == "shade ████████████ -890 … 843   sel x0,y0   * / bold = edited"
    start = legend.plain.index("█")
    assert len({ramp_id(legend, start + i) for i in range(12)}) == 12, "twelve distinct ramp steps"


def test_r_pe_bench_34_2_the_curve_legend(defc):
    """R-PE-BENCH.34/2 - CURVE_DEF_0001: `scale 7.08k … 58.1k   █ edited  ─ old level` (base = lo - (hi - lo) / 10)."""
    o = defc_obj(defc, "CURVE_DEF_0001")
    legend = dv.legend_line(o.d, o.grid, o.values, view_state(o))
    lo, hi = min(EX.CURVE), max(EX.CURVE)
    base = lo - (hi - lo) / 10
    assert legend.plain.strip() == f"scale {EX.short(base)} … {EX.short(hi)}   █ edited  ─ old level"
    assert legend.plain.strip() == "scale 7.08k … 58.1k   █ edited  ─ old level"


def test_r_pe_bench_34_the_unit_word_follows_the_range(defc):
    """R-PE-BENCH.34 (negative control: no unit word) - VAL_BLK_DEF_0001: `… <hi> units   sel x0,y0   …`."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    text = dv.legend_line(o.d, o.grid, o.values, view_state(o)).plain.strip()
    lo, hi = min(EX.VB), max(EX.VB)
    assert text == f"shade ████████████ {EX.short(lo)} … {EX.short(hi)} units   sel x0,y0   * / bold = edited"


def test_r_pe_bench_34_the_legend_names_the_selection(defc):
    """R-PE-BENCH.34 / .42 - the `sel` text is the where without brackets: a 4-cell selection `x0..1,y0..1`."""
    o = defc_obj(defc, "MAP_DEF_0001")
    state = view_state(o, cursor=(1, 1), anchor=(0, 0))
    assert "   sel x0..1,y0..1   " in dv.legend_line(o.d, o.grid, o.values, state).plain


def test_r_pe_bench_19_a_legend_over_finite_values_only(tmp_path):
    """R-PE-BENCH.19 / EX-N1 - F32_BLK `1`, `nan`, `3`, selection (0,): `shade ████████████ 1 … 3   sel 0   * / bold = edited`."""
    o = hand_object(tmp_path, "F32_BLK", "RL_F32", 3, bytes.fromhex("3F800000FFFFFFFF40400000"))
    text = dv.legend_line(o.d, o.grid, o.values, view_state(o)).plain.strip()
    assert text == "shade ████████████ 1 … 3   sel 0   * / bold = edited"


def test_r_pe_bench_19_3_a_legend_with_no_finite_value(tmp_path):
    """R-PE-BENCH.19/3 - every value not finite (lo = hi = 0): the legend shows `0 … 0`, no exception."""
    o = hand_object(tmp_path, "F32_BLK", "RL_F32", 3, bytes.fromhex("FFFFFFFF" * 3))
    assert "0 … 0" in dv.legend_line(o.d, o.grid, o.values, view_state(o)).plain


def test_r_pe_bench_90_2_a_unit_is_not_markup(defc):
    """R-PE-BENCH.90/2 - a unit `Map[b]x` is shown literally in the legend, with no link."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    d = dataclasses.replace(o.d, unit="Map[b]x")
    legend = dv.legend_line(d, o.grid, o.values, view_state(o))
    assert " Map[b]x   sel " in legend.plain
    assert not linked(legend)


def test_r_pe_bench_91_2_a_control_character_in_a_unit_becomes_fffd(defc):
    """R-PE-BENCH.91/2 - a unit with U+0085 -> U+FFFD in the legend."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    d = dataclasses.replace(o.d, unit="a\x85b")
    plain = dv.legend_line(d, o.grid, o.values, view_state(o)).plain
    assert "a" + FFFD + "b" in plain and "\x85" not in plain


# ==========================================================================
# B19 tool_row, B20 window_line - R-PE-BENCH.35, .37
# ==========================================================================

TOOLS = (("s", "Set"), ("d", "+Δ"), ("p", "×%"), ("i", "Interpolate"), ("m", "Smooth"))


def _selected(row, label):
    """The style of the label of the tool row and whether it differs from the unselected `Undo` label."""
    return style_at(row, row.plain.index(label)) != style_at(row, row.plain.index("Undo"))


def test_r_pe_bench_35_1_the_tool_row_selects_set_at_open(defc):
    """R-PE-BENCH.35/1 - at open: ` s  Set` is in the selected style, the other four tools are not."""
    row = dv.tool_row("s")
    assert [_selected(row, label) for _key, label in TOOLS] == [True, False, False, False, False]
    assert style_at(row, row.plain.index("s  Set")) == style_at(row, row.plain.index("Set")), "key and label together"


def test_r_pe_bench_35_2_the_tool_row_selects_the_current_tool(defc):
    """R-PE-BENCH.35/2 - after `d`: ` d  +Δ` is selected and ` s  Set` is not; the same for each tool key."""
    row = dv.tool_row("d")
    assert [_selected(row, label) for _key, label in TOOLS] == [False, True, False, False, False]
    for index, (key, _label) in enumerate(TOOLS):
        marks = [_selected(dv.tool_row(key), label) for _k, label in TOOLS]
        assert marks == [i == index for i in range(5)], key


def test_r_pe_bench_35_the_tool_row_names_every_tool_and_the_selection_keys():
    """R-PE-BENCH.35 - the row lists s Set, d +Δ, p ×%, i Interpolate, m Smooth, u Undo and `shift+arrows select`."""
    plain = dv.tool_row("s").plain
    for key, label in TOOLS + (("u", "Undo"),):
        assert f" {key}  {label}" in plain, label
    assert plain.rstrip().endswith("shift+arrows select")


def test_r_pe_bench_37_1_the_window_line_of_a_large_object_from_the_definition(tmp_path):
    """R-PE-BENCH.37/1 - LARGE: `rows 0..19 of 65536 · cols 0..15 of 16 · pgup/pgdn page` (b = rows shown - 1)."""
    _d, grid, _values, _state = large_object(tmp_path)
    line = dv.window_line(grid, (0, 0), 20, 16)
    assert line is not None
    assert line.plain.strip() == "rows 0..19 of 65536 · cols 0..15 of 16 · pgup/pgdn page"


def test_r_pe_bench_37_2_a_grid_that_fits_has_no_window_line(defc):
    """R-PE-BENCH.37/2 - MAP_DEF_0001 (4 x 3) with 3 rows and 4 columns shown: no window line."""
    o = defc_obj(defc, "MAP_DEF_0001")
    assert dv.window_line(o.grid, (0, 0), 3, 4) is None


# ==========================================================================
# M9 (relevo-10) survivors of the group B mutant run: tests added RED on the mutant, GREEN on the product
# ==========================================================================


def test_r_pe_bench_34_3_the_curve_legend_carries_the_unit_word(defc):
    """R-PE-BENCH.34 (M9, mutant m34: no unit word on the chart legend) - CURVE_DEF_0001 with a unit `rpm`:
    `scale 7.08k … 58.1k rpm   █ edited  ─ old level` (the unit and its space only when not empty)."""
    o = defc_obj(defc, "CURVE_DEF_0001")
    d = dataclasses.replace(o.d, unit="rpm")
    legend = dv.legend_line(d, o.grid, o.values, view_state(o)).plain.strip()
    assert legend == "scale 7.08k … 58.1k rpm   █ edited  ─ old level"
    assert "  " not in legend.split("█")[0].strip(), "no double space when the unit is empty"


def test_r_pe_bench_37_3_a_chart_window_line_only_while_a_point_is_hidden(defc):
    """R-PE-BENCH.37 (M9, mutant m37b: chart window line always shown) - CURVE_DEF_0001 (5 points): all 5 shown
    from point 0 -> no line; 3 shown -> `points 0..2 of 5 · pgup/pgdn page`; a window moved to point 2 shows it."""
    o = defc_obj(defc, "CURVE_DEF_0001")
    assert dv.window_line(o.grid, (0, 0), 1, 5) is None
    assert dv.window_line(o.grid, (0, 0), 1, 3).plain.strip() == "points 0..2 of 5 · pgup/pgdn page"
    assert dv.window_line(o.grid, (0, 2), 1, 3).plain.strip() == "points 2..4 of 5 · pgup/pgdn page"
