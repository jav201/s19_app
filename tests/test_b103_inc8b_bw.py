"""Batch-103 Inc 8b E4, tester T8b-BW: groups B (bench strip, bench limits, rule text) and W (scroller,
body height, bench geometry, filter icon, help).

Design under test: ``.dev-flow/2026-11-05-batch-103/inc-8b/01-requirements.md`` rows R-PE-BENCH.11, .17,
.107, .108, .36 (cases /4 and /5) and R-PE-DEF.92, .93, .81 (cases /5 and /6, E3-8b-05 and E3-8b-11),
.101 (the rule's statement in ``insight_style.py``), .113 and .85. Cases: ``02-test-cases.md``.

Expected values are the requirement's own text or keys of the committed transcript
``evidence-e1/examples_inc8b-transcript.txt`` (loaded by ``T`` below, never retyped); a position or a width
is searched in the painted text, never counted by hand. The three expected hues are the literals of
R-PE-DEF.97 (dim #969aad, selected ground #1c2547, zebra ground #131a2c, expanded ground #1b233a).

Drivers: the pure model (``definition_bench`` / ``definition_sheet``), one ``StagingSheet`` alone in a host
that carries no CSS of its own for the body (so the product's ``DEFAULT_CSS`` decides its height), and the
shipped chain (``S19TuiApp`` under Pilot, the Patch Editor as the operator opens it). Nothing here touches
the operator's clipboard, files or state.
"""

from __future__ import annotations

import ast
import asyncio
import re
import sys
from contextlib import asynccontextmanager
from pathlib import Path

if "." not in sys.path:
    sys.path.insert(0, ".")
import s19_app

print(f"s19_app.__file__ = {s19_app.__file__}", flush=True)

import pytest
from rich.cells import cell_len
from rich.text import Text
from textual.containers import Container
from textual.widgets import Static

from s19_app.tui import definition_bench as db
from s19_app.tui import definition_sheet as ds
from s19_app.tui import insight_style
from s19_app.tui.screens_directionb.patch_editor import bench_sheet as _bench_sheet  # noqa: F401  (registers the bench ops)
from s19_app.tui.screens_directionb.patch_editor.sheet import StagingSheet
from s19_app.tui.window_help import section_body_text
from tests.support.b103_inc8_s2 import SheetApp, body_lines, softa_page  # noqa: F401  (fixture used by name)
from tests.support.b103_inc9_b import (  # noqa: F401  (defc is a session fixture, used by name)
    blank_state,
    defc,
    defc_obj,
    sheet_row,
    style_at,
    view_state,
)
from tests.support.b103_inc9_w import (  # noqa: F401  (defc_dir is a session fixture, used by name)
    BIG_COUNT,
    CURVE,
    MAP,
    VB,
    big_case,
    body_text,
    defc_dir,
    need,
    open_bench,
    run,
    sheet_of,
    st,
)

ROOT = Path(__file__).resolve().parents[1]
TRANSCRIPT = (
    ROOT / ".dev-flow" / "2026-11-05-batch-103" / "inc-8b" / "evidence-e1" / "examples_inc8b-transcript.txt"
)

#: R-PE-DEF.97 (the requirement's own literals).
DIM, SELECTED_GROUND, ZEBRA_GROUND, EXPANDED_GROUND = "#969aad", "#1c2547", "#131a2c", "#1b233a"
BAR = "  ┊ "
KIND, CURRENT, NEW, LIMITS, DELTA = range(5)
SIZE_118, SIZE_80, SIZE_220 = (118, 54), (80, 24), (220, 60)


def _load_transcript() -> dict:
    """``key -> value`` of every ``key = <python literal>`` line of the committed E1 transcript."""
    found = {}
    for raw in TRANSCRIPT.read_text(encoding="utf-8").splitlines():
        key, sep, value = raw.partition(" = ")
        if not sep:
            continue
        try:
            found[key.strip()] = ast.literal_eval(value.strip())
        except (ValueError, SyntaxError):
            continue
    return found


T = _load_transcript()


def hex_of(color) -> str | None:
    """The ``#rrggbb`` of a rich colour, None for no colour."""
    return None if color is None else color.get_truecolor().hex.lower()


def cell_styles(text: Text, start: int, count: int) -> list[tuple]:
    """(foreground hex, ground hex) of ``count`` cells of ``text`` from ``start``, as painted."""
    out = []
    for offset in range(start, start + count):
        style = style_at(text, offset)
        out.append((hex_of(style.color), hex_of(style.bgcolor)))
    return out


# ==========================================================================
# Group B - the summary strip and the bench Limits cell
# ==========================================================================


def strip_state(o, name):
    """A state after the summary job: the values and the strip stored at the transcript's strip width."""
    return view_state(o, strip=db.summary_strip(o.values, o.grid, T[f"S.strip_width.{name}"]))


@pytest.mark.parametrize(
    "name", ["CURVE_DEF_0001", "MAP_DEF_0001", "VAL_BLK_DEF_0001"],
    ids=["1-curve", "2-map", "3-valblk"],
)
def test_r_pe_bench_11_the_strip_and_its_count_use_seven_levels(defc, name):
    """R-PE-BENCH.11/1..3 - the Current cell is the strip then the element count: `▄▆▃▇▁ 5`, `▆▃▅▃ 12`,
    `▄▃▄ 6`. Why it matters: Inc 9's eight levels drew `█` in every column and the ramp shades turned
    neighbouring rows into one block (F-R14-1); the operator reads the summary as a shape, so the levels
    must be the seven that never fill the cell."""
    o = defc_obj(defc, name)
    strip = db.summary_strip(o.values, o.grid, T[f"S.strip_width.{name}"])
    assert strip.plain.rstrip() == T[f"S.after.{name}"]
    row = sheet_row(o.d, o.a2l, o.image)
    cell = db.bench_cells(row, strip_state(o, name), ds.sheet_widths(118))[CURRENT]
    assert cell.plain.strip() == T[f"S.after.current.{name}"]


def test_r_pe_bench_107_1_the_three_strips_hold_only_seven_levels_and_spaces(defc):
    """R-PE-BENCH.107/1 - the DEFC CURVE, MAP and VAL_BLK strips hold only `▁ … ▇` and spaces: a cell
    never filled to its top edge, so two rows of strips never join into one block."""
    allowed = set("▁▂▃▄▅▆▇ ")
    for name in ("CURVE_DEF_0001", "MAP_DEF_0001", "VAL_BLK_DEF_0001"):
        o = defc_obj(defc, name)
        strip = db.summary_strip(o.values, o.grid, T[f"S.strip_width.{name}"])
        assert strip.plain, name
        assert set(strip.plain) <= allowed, (name, strip.plain)
        assert "█" not in strip.plain, name


def test_r_pe_bench_107_2_forty_points_in_seventeen_cells(tmp_path):
    """R-PE-BENCH.107/2 (EX-8B-F2) - 40 rising points in 17 cells -> `S.wide.40_points_in_17`, the top
    level `▇` (never `█`); and 3 equal points -> `S.flat.all_equal` (a flat curve is the lowest level)."""
    from array import array

    ramp = db.BenchValues(numbers=array("d", range(40)), texts=None, missing=frozenset())
    got = db.summary_strip(ramp, db.Grid("chart", 40, 1, 40, "2d"), 17)
    assert got.plain.rstrip() == T["S.wide.40_points_in_17"]
    assert "█" not in got.plain
    flat = db.BenchValues(numbers=array("d", [7.0, 7.0, 7.0]), texts=None, missing=frozenset())
    assert db.summary_strip(flat, db.Grid("chart", 3, 1, 3, "2d"), 17).plain.rstrip() == T["S.flat.all_equal"]


@pytest.mark.parametrize("name", ["CURVE_DEF_0001", "MAP_DEF_0001", "VAL_BLK_DEF_0001"])
def test_r_pe_bench_108_1_the_strip_is_dim_with_no_ground_of_its_own(defc, name):
    """R-PE-BENCH.108/1 - every strip cell is #969aad and has no background: the strip takes the row's
    ground (selected, zebra) instead of painting its own patch over it."""
    o = defc_obj(defc, name)
    strip = db.summary_strip(o.values, o.grid, T[f"S.strip_width.{name}"])
    shown = [i for i, ch in enumerate(strip.plain) if ch != " "]
    assert shown, name
    for offset, (colour, ground) in zip(shown, [cell_styles(strip, i, 1)[0] for i in shown]):
        assert (colour, ground) == (DIM, None), (name, offset, colour, ground)


@pytest.mark.parametrize(
    ("selected", "odd", "ground"),
    [(True, False, SELECTED_GROUND), (False, True, ZEBRA_GROUND), (False, False, None)],
    ids=["selected", "zebra", "even-control"],
)
def test_r_pe_bench_108_2_the_strip_cells_show_the_rows_ground(defc, selected, odd, ground):
    """R-PE-BENCH.108/2 - on the selected row the strip cells sit on #1c2547, on an odd (zebra) row on
    #131a2c, on an even row on no ground; the foreground stays dim #969aad. Painted through the row line
    the sheet paints (``ds.row_line``), not the strip alone."""
    o = defc_obj(defc, "CURVE_DEF_0001")
    state = strip_state(o, "CURVE_DEF_0001")
    row = sheet_row(o.d, o.a2l, o.image)
    kwargs = {"odd": odd} if odd else {}
    line = ds.row_line(row, ds.sheet_widths(118), selected, None, None, state, **kwargs)
    strip = T["S.after.CURVE_DEF_0001"]
    assert strip in line.plain, line.plain
    start = line.plain.index(strip)
    for colour, got in cell_styles(line, start, len(strip)):
        assert colour == DIM, colour
        assert got == ground, (selected, odd, got)


@pytest.mark.parametrize("name", ["CURVE_DEF_0001", "MAP_DEF_0001", "VAL_BLK_DEF_0001"],
                         ids=["1-curve", "2-map", "3-valblk"])
def test_r_pe_bench_17_the_limits_cell_is_the_range_form(defc, name):
    """R-PE-BENCH.17/1,2 - a bench row's Limits cell is the range form of CTX-PE-DEF (the same 34 cells as
    a scalar row, `…` at offset 16): CURVE_DEF_0001 `L.bench.CURVE_DEF_0001`, MAP_DEF_0001 and VAL_BLK
    the same way. Why: Inc 9's `0 … 65.5k` broke the column the operator scans down."""
    o = defc_obj(defc, name)
    row = sheet_row(o.d, o.a2l, o.image)
    cell = db.bench_cells(row, strip_state(o, name), ds.sheet_widths(118))[LIMITS].plain
    assert cell == T[f"L.bench.{name}"]
    assert {ch: cell.index(ch) for ch in T[f"L.bench.{name}.offsets"]} == T[f"L.bench.{name}.offsets"]


def test_r_pe_bench_17_3_an_array_without_limits_shows_a_dash_at_offset_16(defc):
    """R-PE-BENCH.17/3 - an array with no limits -> the no-limits form: `-` at offset 16 (`L.cell.no_limits`)."""
    from s19_app.tui.a2l_definition import Limits
    import dataclasses

    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    none = dataclasses.replace(o.d, limits=Limits(None, None, "", ""))
    row = sheet_row(none, o.a2l, o.image)
    cell = db.bench_cells(row, strip_state(o, "VAL_BLK_DEF_0001"), ds.sheet_widths(118))[LIMITS].plain
    assert cell.index("-") == T["L.cell.no_limits.offsets"]["-"]
    assert cell == T["L.cell.no_limits"]


def test_r_pe_def_101_the_hue_rule_is_stated_next_to_the_magenta_constant():
    """R-PE-DEF.101 / E3-8b-12 (group B, ``insight_style.py:75-84``, a comment only): the comment above
    MAGENTA states the verdict-hue rule of CTX-PE-DEF - GREEN rides `✓` or `●`, YELLOW `▲`, RED `✗`, each
    only on a line that carries its glyph. PARTIAL: it reads a comment, because the rule's behaviour (spans
    on glyph lines) is group S's case R-PE-DEF.101/1..4; this node keeps the next editor of
    ``insight_style.py`` from re-reading GREEN as 'a check passed' only (the base's text)."""
    source = Path(insight_style.__file__).read_text(encoding="utf-8")
    comment = source.split("\nMAGENTA = ", 1)[0].rsplit("\n#: Magenta accent", 1)[1]
    for glyph in ("✓", "●", "▲", "✗"):
        assert glyph in comment, (glyph, "is not in the verdict-hue comment")
    assert "glyph" in comment.lower()


# ==========================================================================
# Group W - the scroller, the body height, the bench geometry
# ==========================================================================


class _GridHost(SheetApp):
    """One StagingSheet alone, with NO rule for the body: the product's own CSS decides its height (E3-8b-05)."""

    CSS = "StagingSheet { height: 1fr; width: 1fr; }"


@asynccontextmanager
async def grid_ctx(size):
    """Mount the sheet alone in ``_GridHost``: yields (app, pilot, sheet)."""
    app = _GridHost()
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        yield app, pilot, app.query_one(StagingSheet)


def grid_of(sheet):
    """The one ``#patch_sheet_grid`` of a sheet, or a named failure (R-PE-DEF.92)."""
    found = list(sheet.query("#patch_sheet_grid"))
    assert len(found) == 1, f"the sheet holds {len(found)} #patch_sheet_grid widgets (the grid scroller of R-PE-DEF.92)"
    return found[0]


def test_r_pe_def_92_scroller_is_a_plain_container_that_takes_no_focus_and_no_key():
    """R-PE-DEF.92 / E3-8b-03 - `#patch_sheet_grid` is a plain `Container`: not focusable, no bindings,
    holding the body, with the formula bar outside it. Why: the prototype's focusable `ScrollableContainer`
    added a Tab stop and its own `right` binding scrolled the grid instead of choosing an enum entry."""

    async def drive():
        async with grid_ctx(SIZE_118) as (app, pilot, sheet):
            grid = grid_of(sheet)
            assert type(grid) is Container, type(grid)
            assert grid.can_focus is False and grid.focusable is False
            assert not list(grid.BINDINGS), list(grid.BINDINGS)
            assert grid.parent is sheet
            body = sheet.query_one("#patch_sheet_body")
            assert body.parent is grid
            bar = sheet.query_one("#patch_sheet_bar")
            assert grid not in bar.ancestors and bar not in grid.ancestors

    asyncio.run(drive())


def test_r_pe_def_81_5_the_body_fills_the_scroller_less_its_scrollbar_row(softa_page):
    """R-PE-DEF.81/5 (E3-8b-05) - the host at 118x54 with no chrome and no body rule: the sheet is
    `W.harness_118x54.sheet` rows, the grid scroller `.grid`, the body `.body`, and 200 names paint
    `.visible` rows under the header and its rule. Why: without a height rule for the body under the
    scroller it is as tall as its own text, the window paints every row and the selection runs off screen."""
    a2l, names, defs, image = softa_page

    async def drive():
        async with grid_ctx(SIZE_118) as (app, pilot, sheet):
            sheet.show_page(names, defs, a2l, image)
            sheet.set_document([], image)
            await pilot.pause()
            await pilot.pause()
            body = sheet.query_one("#patch_sheet_body")
            grids = list(sheet.query("#patch_sheet_grid"))
            return (sheet.size.height, grids[0].size.height if grids else None, body.size.height,
                    len(body_lines(sheet)))

    sheet_h, grid_h, body_h, painted = asyncio.run(drive())
    assert body_h == T["W.harness_118x54.body"], body_h
    assert painted - 2 == T["W.harness_118x54.visible"], (painted, "lines: header, rule and the visible rows")
    assert sheet_h == T["W.harness_118x54.sheet"], sheet_h
    assert grid_h == T["W.harness_118x54.grid"], f"grid scroller height {grid_h}"


def test_r_pe_def_91_1_the_sheet_paints_the_header_rule_as_its_second_line(softa_page):
    """R-PE-DEF.91/1 (E5, X8b: the model node checks ``header_rule`` alone, so a sheet that stopped painting it
    survived) - the sheet alone at 118x54 with 200 names: body line 1 is the header, line 2 is ``G.header_rule``."""
    a2l, names, defs, image = softa_page

    async def drive():
        async with grid_ctx(SIZE_118) as (app, pilot, sheet):
            sheet.show_page(names, defs, a2l, image)
            sheet.set_document([], image)
            await pilot.pause()
            await pilot.pause()
            return body_lines(sheet)

    lines = asyncio.run(drive())
    assert lines[0].lstrip().startswith("Parameter"), lines[:2]
    assert lines[1] == T["G.header_rule"], lines[:2]


@pytest.fixture(scope="module")
def panel_dir(defc_dir):
    return defc_dir


@pytest.mark.parametrize(
    ("size", "key", "case"),
    [(SIZE_118, "118cols", "1"), (SIZE_80, "80cols", "2"), (SIZE_220, "220cols", "0")],
    ids=["92-1-118x54", "92-2-80x24", "93-1-220x60"],
)
def test_r_pe_def_92_93_the_scrollbar_shows_only_when_the_grid_is_wider_than_the_view(
    tmp_path, defc_dir, size, key, case
):
    """R-PE-DEF.92/1, /2 and .93/1 (EX-8B-G3, G4) - through the Patch Editor as the operator opens it, on
    DEFC: at 118x54 and 80x24 the grid scroller shows its horizontal scrollbar and the grid is 143 cells
    wide; at 220x60 it shows none. The scroll range is the grid minus the view (`G.end.*`: 33, 73, 0; E4 measured V = 110, 70, 194)."""

    async def body(app, pilot, panel):
        await pilot.pause()
        grid = grid_of(need(panel, "#patch_sheet"))
        return grid.show_horizontal_scrollbar, grid.virtual_size.width, grid.max_scroll_x

    shown, virtual, end = run(tmp_path, defc_dir, body, size=size)
    assert shown is T[f"G.scrollbar.{key}"], (key, shown)
    assert end == T[f"G.end.{key}"], (key, end)
    if shown:
        assert virtual == T["G.grid_width"], virtual


def test_r_pe_def_92_3_the_scroller_is_never_a_tab_stop(tmp_path, defc_dir):
    """R-PE-DEF.92/3 (EX-8B-G6) - 118x54 with the scrollbar shown: the focus ring of the screen never lists
    `#patch_sheet_grid`, Tab through the whole ring never lands on it, and the sheet body stays in the ring
    (the control: the test can see a stop). PARTIAL: it compares to the rule, not to a base Tab list."""

    async def body(app, pilot, panel):
        grid = grid_of(need(panel, "#patch_sheet"))
        ring = list(app.screen.focus_chain)
        stops = []
        for _ in range(len(ring) + 2):
            await pilot.press("tab")
            stops.append(app.focused)
        return grid in ring, [w.id for w in ring], [w.id for w in stops if w is not None], grid in stops

    in_ring, ring_ids, stop_ids, landed = run(tmp_path, defc_dir, body, size=SIZE_118)
    assert "patch_sheet_body" in ring_ids, ring_ids
    assert not in_ring and not landed, (ring_ids, stop_ids)


def expanded_lines(sheet) -> list[Text]:
    """The painted lines of the selected row's expanded object: the lines after the `▶` row that carry the bar."""
    content = sheet.query_one("#patch_sheet_body", Static).content
    lines = content.split("\n", allow_blank=True) if isinstance(content, Text) else [Text(s) for s in str(content).split("\n")]
    at = next(i for i, line in enumerate(lines) if line.plain.startswith("▶"))
    out = []
    for line in lines[at + 1:]:
        if not line.plain.startswith(BAR):
            break
        out.append(line)
    assert out, f"no line after the selected row carries the bar {BAR!r}: {[l.plain for l in lines[at:at + 4]]}"
    return out


def check_bench_lines(sheet, view: int):
    """Every expanded line is cut at ``view`` cells once its trailing ground is removed; each runs on the
    expanded ground to ``max(G, view)`` cells."""
    padded = max(T["G.grid_width"], view)
    for line in expanded_lines(sheet):
        assert cell_len(line.plain.rstrip()) <= view, (view, cell_len(line.plain.rstrip()), line.plain)
        assert cell_len(line.plain) == padded, (padded, cell_len(line.plain), line.plain)
        assert hex_of(style_at(line, len(line.plain) - 1).bgcolor) == EXPANDED_GROUND, line.plain


def test_r_pe_def_81_6_a_resize_that_only_widens_relays_the_expanded_bench(tmp_path, defc_dir):
    """R-PE-DEF.81/6 (E3-8b-11) - MAP_DEF_0001 expanded at 118x54, then the terminal widened to 220x54: every
    bench line is <= V (194) cells once rstripped and the expanded ground runs to V (and to 143 before).
    Why: a resize that changes only the width can leave the body at 143 x h; the bench canvas re-lays out
    only if the body's resize repaints the sheet."""

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await open_bench(pilot, sheet, MAP)
        await pilot.pause()
        check_bench_lines(sheet, T["G.view.118cols"])
        await pilot.resize_terminal(220, 54)
        for _ in range(4):
            await pilot.pause()
        check_bench_lines(sheet, T["G.view.220cols"])
        return True

    assert run(tmp_path, defc_dir, body, size=SIZE_118)


def test_r_pe_def_81_6_b_a_width_only_resize_with_no_scrollbar_change_relays_the_expanded_bench(tmp_path, defc_dir):
    """R-PE-DEF.81/6 (E5, X8b) - MAP_DEF_0001 expanded at 200x54, then widened to 220x54: both views are wider
    than the grid, so no scrollbar shows either side and the body keeps its height; every expanded line then runs
    on the ground to the new V. Why: the node above also drops the scrollbar (118 -> 220), so the body's own
    height change repaints it and deleting `StagingSheet.on_resize` survived it; here only that handler can."""

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        grid, sheet_body = grid_of(sheet), sheet.query_one("#patch_sheet_body")
        await open_bench(pilot, sheet, MAP)
        await pilot.pause()
        v1, h1 = grid.scrollable_content_region.width, sheet_body.size.height
        check_bench_lines(sheet, v1)
        await pilot.resize_terminal(220, 54)
        for _ in range(4):
            await pilot.pause()
        v2, h2 = grid.scrollable_content_region.width, sheet_body.size.height
        return v1, h1, v2, h2, sorted({cell_len(line.plain) for line in expanded_lines(sheet)})

    v1, h1, v2, h2, widths = run(tmp_path, defc_dir, body, size=(200, 54))
    assert T["G.grid_width"] < v1 < v2, (v1, v2, "both views wider than the grid: no scrollbar on either side")
    assert h1 == h2, (h1, h2, "the body's height is unchanged, so the body itself gets no resize")
    assert widths == [v2], (widths, v2, "every expanded line runs on the ground to the new view width")


WINDOW = re.compile(r"rows (\d+)\.\.(\d+) of (\d+) · cols (\d+)\.\.(\d+) of (\d+)")


def window_of(app) -> tuple[int, ...]:
    found = WINDOW.search(body_text(app))
    assert found, body_text(app)
    return tuple(int(n) for n in found.groups())


def walk_off_the_window(tmp_path, defc_dir, size, axis):
    """LARGE-like (70,000 elements, 16 columns, many rows) opened at ``size``: the window line, then the
    cursor moved with the arrow key past its last painted row (axis `y`) or column (`x`); returns
    (first window, window after, cursor (col, row))."""
    a2l, s19 = big_case(tmp_path, BIG_COUNT, rows=("LARGE",))

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await open_bench(pilot, sheet, "LARGE")
        await pilot.pause(0.3)
        first = window_of(app)
        rows_a, rows_b, ny, cols_a, cols_b, nx = first
        last = cols_b if axis == "x" else rows_b
        for _ in range(last + 1):
            await pilot.press("right" if axis == "x" else "down")
        await pilot.pause(0.3)
        return first, window_of(app), st(sheet, "LARGE").cursor

    return run(tmp_path, defc_dir, body, size=size, a2l=a2l, image=s19)


@pytest.mark.parametrize("axis", ["x", "y"], ids=["right", "down"])
def test_r_pe_bench_36_4_at_80x24_the_window_follows_the_cursor_and_paints_its_cell(tmp_path, defc_dir, axis):
    """R-PE-BENCH.36/4 (EX-8B-W2, V = 73) - LARGE-like at 80x24, the cursor moved past the last painted
    column (right) or row (down): the window's first column (row) moves by 1 and the cursor's cell lies in
    the painted window. Why: the window must be shaped for the detail the sheet paints; shaped for the
    body's 143 cells it leaves the cursor in a column the canvas does not draw (E3-8b-02).
    NOTE: this holds on the base too (no scroller yet), so it is a guard, not a RED."""
    first, after, (col, row) = walk_off_the_window(tmp_path, defc_dir, SIZE_80, axis)
    a0, b0, ny, c0, d0, nx = first
    a1, b1, _, c1, d1, _ = after
    assert a1 <= row <= b1 and c1 <= col <= d1, (first, after, (col, row))
    if axis == "x":
        assert d0 < nx - 1, f"the first window already shows every column: {first}"
        assert (c1, col) == (c0 + 1, d0 + 1), (first, after, col)
    else:
        assert (a1, row) == (a0 + 1, b0 + 1), (first, after, row)


@pytest.mark.parametrize("axis", ["x", "y"], ids=["right", "down"])
def test_r_pe_bench_36_5_at_118x54_the_window_follows_the_cursor_and_paints_its_cell(tmp_path, defc_dir, axis):
    """R-PE-BENCH.36/5 (EX-8B-W2, V = 111) - the same at 118x54. DEVIATION from the case text ("cursor right"):
    at V = 111 a 16-column grid shows all its columns (`grid_geometry(107)` -> 16), so no column lies past
    the last painted one; `right` is checked as 'the cursor stays painted, the first column stays 0' and the
    row direction (`down`, the axis with a window at 118) carries the 'first row +1' check.
    NOTE: this holds on the base too, so it is a guard, not a RED."""
    first, after, (col, row) = walk_off_the_window(tmp_path, defc_dir, SIZE_118, axis)
    a0, b0, ny, c0, d0, nx = first
    a1, b1, _, c1, d1, _ = after
    assert a1 <= row <= b1 and c1 <= col <= d1, (first, after, (col, row))
    if axis == "x":
        if d0 < nx - 1:
            assert (c1, col) == (c0 + 1, d0 + 1), (first, after, col)
        else:
            assert (c1, d1) == (c0, d0)
    else:
        assert (a1, row) == (a0 + 1, b0 + 1), (first, after, row)


# ==========================================================================
# Group W - the filter icon and the help line
# ==========================================================================


def test_r_pe_def_113_1_the_include_control_is_painted_as_a_filter_icon(tmp_path, defc_dir):
    """R-PE-DEF.113/1 (V-2) - the Patch Editor's Include parameter control reads `▽ Pick` at 118x54; the
    Check Editor's keeps `Include parameter` (the compact label is the Patch Editor's alone)."""

    async def body(app, pilot, panel):
        return (str(need(panel, "#patch_param_include_button").label),
                str(need(app.screen, "#check_param_include_button").label))

    patch_label, check_label = run(tmp_path, defc_dir, body, size=SIZE_118)
    assert patch_label == "▽ Pick", patch_label
    assert check_label == "Include parameter", check_label


FILTER_ROW_CONTROLS = (
    "patch_param_filter", "patch_param_status", "patch_param_page_prev_button", "patch_param_page_label",
    "patch_param_page_next_button", "patch_param_include_button", "patch_param_bulk_button",
)


def test_r_pe_def_113_2_at_80x24_the_seven_filter_row_controls_keep_a_region(tmp_path, defc_dir):
    """R-PE-DEF.113/2 (R-PICKER-CORRECT.020) - 80x24: the longer label `▽ Pick` must not squeeze a control
    off the filter row: all seven keep a non-zero region and stay on the row's own lines."""

    async def body(app, pilot, panel):
        row = need(panel, "#patch_filter_row")
        out = {}
        for control_id in FILTER_ROW_CONTROLS:
            widget = need(panel, f"#{control_id}")
            out[control_id] = (widget.region.area, widget.size.width,
                               row.region.y <= widget.region.y < row.region.y + row.region.height)
        return out

    for control_id, (area, width, on_row) in run(tmp_path, defc_dir, body, size=SIZE_80).items():
        assert area > 0 and width > 0, (control_id, area, width)
        assert on_row, control_id


def test_r_pe_def_85_1_the_help_line_names_the_scroll_keys():
    """R-PE-DEF.85/1 (EX-8B-P2) - the `STAGING SHEET — …` help effect holds `↑↓`, `enter`, `←→`, `home`, `end`
    and `esc`, and says they scroll. Why: Home and End are new keys of the sheet; a key the help does not
    list is a key the operator never finds."""
    lines = {}
    for raw in section_body_text("patch").split("\n"):
        text = raw.strip()
        text = text.split(". ", 1)[1] if text[:1].isdigit() and ". " in text else text
        if " — " in text:
            label, effect = text.split(" — ", 1)
            lines[label.strip()] = effect.strip()
    assert "STAGING SHEET" in lines, sorted(lines)
    effect = lines["STAGING SHEET"]
    for word in ("↑↓", "←→"):
        assert word in effect, (word, effect)
    for word in ("enter", "esc", "home", "end", "scroll"):
        assert re.search(rf"\b{word}", effect.lower()), (word, effect)
    assert re.search(r"\bhome\b", effect.lower()) and re.search(r"\bend\b", effect.lower()), effect
