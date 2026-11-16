"""Batch-103 Inc 9 E4, group B - the bench model, part 1: grid, cursor, window, selection, where.

Design under test: ``.dev-flow/2026-11-05-batch-103/inc-9/01-requirements.md`` through
``s19_app/tui/definition_bench.py`` (new): nodes B1 ``bench_grid``, B3 ``move_cursor``, B4 ``page_cursor``,
B5 ``window_for``, B6 ``selection_cells``, B7 ``where_text``. One test per case of
``inc-9/02-test-cases-B.md``; the cases name R-PE-BENCH.30, .31, .36, .41, .42, .43 and .50 (the where).

Conventions read from the graph (``codewire/graph-inc9.md``): a cursor is ``(column, row)`` (EX-K2: right
-> (1,0), down -> (1,1)); a chart is one grid row, point k = column k; ``window_for`` answers ``(row, col)``.
Expected values come from I-2 (the DEFC decode) and the committed example oracle (``EX``).
"""

from __future__ import annotations

import dataclasses

import pytest

from s19_app.tui import definition_bench as db
from tests.support.b103_inc9_b import (  # noqa: F401  (fixtures are used by name)
    blank_state,
    defc,
    defc_obj,
    large_definition,
)


@pytest.fixture(scope="module")
def large(tmp_path_factory):
    a2l, definition = large_definition(tmp_path_factory.mktemp("b103_inc9_model_large"))
    return definition, db.bench_grid(definition)


def _move(state, grid, dx, dy, extend=False):
    return db.move_cursor(state, grid, dx, dy, extend)


# ==========================================================================
# B1 bench_grid - R-PE-BENCH.30, .31 (the geometry half of the canvas cases)
# ==========================================================================


def test_r_pe_bench_30_31_bench_grid_of_the_three_defc_kinds(defc):
    """R-PE-BENCH.30/1 and .31/1, .31/2 (grid shape) - EX-A3 chart 5 x 1, EX-A2 map 4 x 3, EX-A1 array 3 x 2."""
    curve = defc_obj(defc, "CURVE_DEF_0001").grid
    assert (curve.mode, curve.nx, curve.ny) == ("chart", 5, 1)
    mp = defc_obj(defc, "MAP_DEF_0001").grid
    assert (mp.mode, mp.nx, mp.ny, mp.layout) == ("grid", 4, 3, "2d")
    vb = defc_obj(defc, "VAL_BLK_DEF_0001").grid
    assert (vb.mode, vb.nx, vb.ny, vb.layout) == ("grid", 3, 2, "2d")
    assert mp.count == 12 and vb.count == 6


def test_r_pe_bench_31_bench_grid_of_a_one_dimensional_array_is_sixteen_columns(large):
    """R-PE-BENCH.31 (grid definition) - EX-G12: 1,048,576 elements -> 16 columns, 65,536 rows, flat."""
    _, grid = large
    count = 1048576
    assert (grid.nx, grid.ny, grid.layout) == (16, count // 16, "flat")
    assert grid.count == count


# ==========================================================================
# B5 window_for, B4 page_cursor - R-PE-BENCH.36, .43
# ==========================================================================


def test_r_pe_bench_36_1_the_window_moves_one_row_when_the_cursor_leaves_it(large):
    """R-PE-BENCH.36/1 - LARGE, 20 rows shown: cursor on row 19 -> origin row 0; down to row 20 -> origin row 1."""
    _, grid = large
    on_last = blank_state(cursor=(0, 19), anchor=(0, 19))
    assert db.window_for(on_last, grid, 20, 16)[0] == 0
    past = _move(on_last, grid, 0, 1)
    assert past.cursor == (0, 20)
    assert db.window_for(past, grid, 20, 16)[0] == 1, "the least move that shows the cursor (+1 row)"


def test_r_pe_bench_36_2_pagedown_moves_the_window_the_least(large):
    """R-PE-BENCH.36/2 - pagedown from row 0 with a 20-row window: cursor row 20, window rows 1..20."""
    _, grid = large
    paged = db.page_cursor(blank_state(), grid, 20, 1)
    assert paged.cursor[1] == 20
    first = db.window_for(paged, grid, 20, 16)[0]
    assert first == 1, "rows 1..20: the least move, not a re-centred window (which starts at row 10)"
    assert first + 20 - 1 == 20


def test_r_pe_bench_36_3_a_grid_that_fits_keeps_its_window(defc):
    """R-PE-BENCH.36/3 - MAP_DEF_0001 (4 x 3) with 3 rows and 4 columns shown: every cursor keeps origin (0,0)."""
    grid = defc_obj(defc, "MAP_DEF_0001").grid
    for cursor in ((0, 0), (3, 0), (0, 2), (3, 2)):
        state = blank_state(cursor=cursor, anchor=cursor)
        assert tuple(db.window_for(state, grid, 3, 4)) == (0, 0), cursor


def test_r_pe_bench_36_window_for_below_one_row_counts_as_one(large):
    """R-PE-BENCH.36 / E3S-05 (EX-W3) - rows_shown 0 and cursor row 7: the origin is the cursor's own row."""
    _, grid = large
    state = blank_state(cursor=(0, 7), anchor=(0, 7))
    assert db.window_for(state, grid, 0, 0)[0] == 7


def test_r_pe_bench_36_window_for_answers_row_then_column(large):
    """R-PE-BENCH.36 - ``window_for`` answers ``(row, col)`` and ``BenchState.origin`` is ``(row, col)`` (graph-inc9
    B5, pinned by ruling P-056 T9 F-4), while the cursor is ``(col, row)``: cursor (13, 40), 20 rows x 4 columns
    shown from the origin (0, 0) -> origin row 21, column 10; from that origin the window stays."""
    _, grid = large
    state = blank_state(cursor=(13, 40), anchor=(13, 40))
    assert tuple(db.window_for(state, grid, 20, 4)) == (21, 10)
    moved = dataclasses.replace(state, origin=(21, 10))
    assert tuple(db.window_for(moved, grid, 20, 4)) == (21, 10)


def test_r_pe_bench_43_1_pagedown_moves_the_cursor_by_the_window_rows(large):
    """R-PE-BENCH.43/1 - LARGE from row 0, a 20-row window: pagedown -> row 20 (not row 1), anchor = cursor."""
    _, grid = large
    after = db.page_cursor(blank_state(), grid, 20, 1)
    assert after.cursor == (0, 20)
    assert after.anchor == after.cursor


def test_r_pe_bench_43_2_pageup_returns_to_row_zero_and_never_below(large):
    """R-PE-BENCH.43/2 - pageup from row 20 -> row 0; from row 0 it stays on row 0 (clamped)."""
    _, grid = large
    down = db.page_cursor(blank_state(), grid, 20, 1)
    up = db.page_cursor(down, grid, 20, -1)
    assert up.cursor == (0, 0)
    assert db.page_cursor(up, grid, 20, -1).cursor == (0, 0)


def test_r_pe_bench_43_pagedown_is_clamped_at_the_last_row(large):
    """R-PE-BENCH.43 - from the row before the last, pagedown ends on the last grid row (clamped)."""
    _, grid = large
    near = blank_state(cursor=(5, grid.ny - 2), anchor=(5, grid.ny - 2))
    assert db.page_cursor(near, grid, 20, 1).cursor == (5, grid.ny - 1)


# ==========================================================================
# B3 move_cursor - R-PE-BENCH.41, .42
# ==========================================================================


def test_r_pe_bench_41_1_right_moves_one_cell(defc):
    """R-PE-BENCH.41/1 - MAP_DEF_0001 from (0,0): right -> (1,0), anchor (1,0)."""
    grid = defc_obj(defc, "MAP_DEF_0001").grid
    after = _move(blank_state(), grid, 1, 0)
    assert (after.cursor, after.anchor) == ((1, 0), (1, 0))


def test_r_pe_bench_41_2_down_moves_one_cell(defc):
    """R-PE-BENCH.41/2 - from (1,0): down -> (1,1)."""
    grid = defc_obj(defc, "MAP_DEF_0001").grid
    after = _move(_move(blank_state(), grid, 1, 0), grid, 0, 1)
    assert after.cursor == (1, 1)


def test_r_pe_bench_41_3_a_plain_arrow_selects_one_cell(defc):
    """R-PE-BENCH.41/3 - after right then down the selection is exactly cell (1,1)."""
    grid = defc_obj(defc, "MAP_DEF_0001").grid
    after = _move(_move(blank_state(), grid, 1, 0), grid, 0, 1)
    assert db.selection_cells(after, grid) == [(1, 1)]


def test_r_pe_bench_41_4_left_at_column_zero_stays(defc):
    """R-PE-BENCH.41/4 - left at column 0 stays at (0,0), and up at row 0 stays (no wrap)."""
    grid = defc_obj(defc, "MAP_DEF_0001").grid
    assert _move(blank_state(), grid, -1, 0).cursor == (0, 0)
    assert _move(blank_state(), grid, 0, -1).cursor == (0, 0)


def test_r_pe_bench_41_the_last_column_and_row_do_not_wrap(defc):
    """R-PE-BENCH.41 (negative control: wrap at the edge) - MAP at (3,2): right and down stay."""
    grid = defc_obj(defc, "MAP_DEF_0001").grid
    corner = blank_state(cursor=(3, 2), anchor=(3, 2))
    assert _move(corner, grid, 1, 0).cursor == (3, 2)
    assert _move(corner, grid, 0, 1).cursor == (3, 2)


def test_r_pe_bench_42_1_shift_arrows_keep_the_anchor(defc):
    """R-PE-BENCH.42/1 - MAP from (0,0): shift+right, shift+down -> cursor (1,1), anchor (0,0), 4 cells."""
    grid = defc_obj(defc, "MAP_DEF_0001").grid
    state = _move(_move(blank_state(), grid, 1, 0, True), grid, 0, 1, True)
    assert (state.cursor, state.anchor) == ((1, 1), (0, 0))
    assert len(db.selection_cells(state, grid)) == 4


def test_r_pe_bench_42_2_where_of_the_four_cell_selection(defc):
    """R-PE-BENCH.42/2 (and .50's where) - `[x0..1,y0..1]`; one cell `[x0,y0]` (EX-M2, EX-K2)."""
    grid = defc_obj(defc, "MAP_DEF_0001").grid
    four = blank_state(cursor=(1, 1), anchor=(0, 0))
    assert db.where_text(four, grid) == "[x0..1,y0..1]"
    assert db.where_text(blank_state(), grid) == "[x0,y0]"


# ==========================================================================
# B6 selection_cells, B7 where_text - R-PE-BENCH.50 (EX-M2, EX-C1, EX-G8)
# ==========================================================================


def test_r_pe_bench_50_selection_cells_are_in_element_order(defc):
    """R-PE-BENCH.50 / .52 .. .56 (B6) - EX-M2: anchor (0,0), cursor (1,1) -> x fastest."""
    grid = defc_obj(defc, "MAP_DEF_0001").grid
    state = blank_state(cursor=(1, 1), anchor=(0, 0))
    assert db.selection_cells(state, grid) == [(0, 0), (1, 0), (0, 1), (1, 1)]
    reverse = blank_state(cursor=(0, 0), anchor=(1, 1))
    assert db.selection_cells(reverse, grid) == [(0, 0), (1, 0), (0, 1), (1, 1)], "the rectangle, not the drag order"


def test_r_pe_bench_50_a_curve_selection_is_points(defc):
    """R-PE-BENCH.50/2 (B6, B7) - EX-C1: CURVE point 3 -> [(3,)], `[3]`; points 1..3 -> `[1..3]`."""
    grid = defc_obj(defc, "CURVE_DEF_0001").grid
    one = blank_state(cursor=(3, 0), anchor=(3, 0))
    assert db.selection_cells(one, grid) == [(3,)]
    assert db.where_text(one, grid) == "[3]"
    span = blank_state(cursor=(3, 0), anchor=(1, 0))
    assert db.selection_cells(span, grid) == [(1,), (2,), (3,)]
    assert db.where_text(span, grid) == "[1..3]"


def test_r_pe_bench_50_where_of_a_flat_array_names_the_first_and_last_element(large):
    """R-PE-BENCH.50 (B7) - EX-G8: LARGE elements 36..43 (row 2, columns 4..11) -> `[36..43]`; one cell `[i]`."""
    _, grid = large
    state = blank_state(cursor=(11, 2), anchor=(4, 2))
    assert db.where_text(state, grid) == "[36..43]"
    assert db.selection_cells(state, grid)[0] == (36,)
    assert db.where_text(blank_state(cursor=(4, 2), anchor=(4, 2)), grid) == "[36]"
