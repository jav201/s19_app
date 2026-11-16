"""Batch-103 Inc 8b — acceptance tests of the staging sheet's grid, scroller, card and filter icon (E4, AT tester).

Cases: ``.dev-flow/2026-11-05-batch-103/inc-8b/02-test-cases-AT.md`` (AT-B103-I8B-1 ... AT-B103-I8B-8).
Requirements: ``01-requirements.md``. Requirement ids verified end to end here (one name per case row):
R-PE-DEF.33, R-PE-DEF.92, R-PE-DEF.93, R-PE-DEF.94, R-PE-DEF.95, R-PE-DEF.108, R-PE-DEF.113, R-PE-DEF.114.

Black-box. The real app (``S19TuiApp`` under Textual's pilot) loads the synthetic definitions case (DEFC, seed
20260001) through its own loaders; the operator route is driven by keys (Tab, Up/Down, Left/Right, Home/End,
Enter, typed characters) and the shipped widgets are read back through their ids. No product module of Inc 8b is
imported. The only ids read are the ones the requirements and the graph pin as the shipped surface:
``#patch_sheet_grid`` (the horizontal scroller, I-8b), ``#patch_sheet_body``, ``#patch_sheet_bar``,
``#patch_sheet_tail``, ``#patch_sheet_input`` and the picker's existing ``#patch_param_*`` ids.

Every expected number or card line is a key of ``evidence-e1/examples_inc8b-transcript.txt`` (the E1 examples,
loaded here and never retyped): ``G.*`` (grid widths, scrollbar, End position), ``E.card.*`` / ``B.card.*``
(cards), ``L.cell.float32_erased`` (the no-position Limits cell).

Controls (per file): the card test also asserts a number row (DISPLAY_0001) gets exactly one expanded line (no
card); the Home/End-in-the-formula-input test asserts the grid keeps a non-zero x it was given by End; the
size tests assert the scrollbar flag both ways (shown at 80 and 118, absent at 220).

Every test is RED on the base tree 48af05ff: the grid tests on the missing ``#patch_sheet_grid``, the card tests on
the missing frame, the icon test on the label ``Pick``, the NaN test on the base's own ValueError.
"""
from __future__ import annotations

import ast
import asyncio
import re
import sys
from pathlib import Path

import pytest
from textual.widgets import Button, Input

from s19_app.tui.app import S19TuiApp
from tests.support.b100_workers import settle_workers

REPO_ROOT = Path(__file__).resolve().parent.parent
SYNTH_DIR = REPO_ROOT / "tools" / "synth"
if str(SYNTH_DIR) not in sys.path:
    sys.path.insert(0, str(SYNTH_DIR))

import make_release_case as gen  # noqa: E402

TRANSCRIPT = (
    REPO_ROOT / ".dev-flow" / "2026-11-05-batch-103" / "inc-8b" / "evidence-e1" / "examples_inc8b-transcript.txt"
)

SEED = 20260001
SIZE_80 = (80, 24)
SIZE_118 = (118, 54)
SIZE_220 = (220, 60)

SHEET = "#patch_sheet"
GRID = "#patch_sheet_grid"
BODY = "#patch_sheet_body"
BAR = "#patch_sheet_bar"
TAIL = "#patch_sheet_tail"
INPUT = "#patch_sheet_input"
FILTER = "#patch_param_filter"
INCLUDE = "#patch_param_include_button"
# The filter row's seven controls (R-PE-DEF.113/2, R-PICKER-CORRECT.020): filter, status, page prev / label / next,
# include, bulk.
FILTER_ROW = [
    "#patch_param_filter",
    "#patch_param_status",
    "#patch_param_page_prev_button",
    "#patch_param_page_label",
    "#patch_param_page_next_button",
    INCLUDE,
    "#patch_param_bulk_button",
]

MARKS = "▶●◆"

# The Tab ring of the app with the Patch Editor open and the sheet body focused, on the BASE revision 48af05ff,
# starting at the stop after the body (captured by this file's own base run, transcript in `E4-t8b-at.md`).
# R-PE-DEF.92/3: the scrollbar adds no stop to it.
BASE_TAB_ORDER: tuple = (
    "patch_sheet_input",
    "patch_tab_script",
    "patch_tab_inspector",
    "patch_tab_json",
    "patch_tab_checks",
    "patch_doc_file_select",
    "patch_doc_path_input",
    "patch_doc_load_button",
    "patch_doc_refresh_button",
    "patch_doc_validate_button",
    "patch_doc_apply_button",
    "patch_doc_save_button",
    "rail_item_workspace",
    "rail_item_a2l",
    "rail_item_mac",
    "rail_item_map",
    "rail_item_issues",
    "rail_item_patch",
    "rail_item_check_editor",
    "rail_item_diff",
    "rail_item_flow",
    "rail_item_flow_execution",
    "rail_item_checks",
    "rail_item_crc_designer",
    "window_help_patch",
    "open_folder_patch",
    "patch_editor_panel",
    "patch_param_filter",
    "patch_param_include_button",
    "patch_param_bulk_button",
    "patch_sheet_body",
)


# --------------------------------------------------------------------------- #
# Examples (loaded, never retyped)
# --------------------------------------------------------------------------- #


def load_examples() -> dict:
    """``key = value`` lines of the E1 examples transcript; a value is a Python literal when it parses."""
    found: dict = {}
    for line in TRANSCRIPT.read_text(encoding="utf-8").splitlines():
        key, sep, raw = line.partition(" = ")
        if not sep:
            continue
        try:
            found[key] = ast.literal_eval(raw)
        except (ValueError, SyntaxError):
            found[key] = raw
    return found


EX = load_examples()


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def defc(tmp_path_factory):
    """The definitions case written by the shipped generator; its A2L text names the parameters."""
    out = tmp_path_factory.mktemp("defc")
    paths = gen.generate_definitions_case(out, SEED)
    text = paths["a2l"].read_text(encoding="utf-8")
    names = re.findall(r"/begin (?:CHARACTERISTIC|MEASUREMENT|AXIS_PTS) (\w+)", text)
    return {"a2l": paths["a2l"], "s19": paths["s19"], "names": names}


def _s3_with_erased_word(line: str) -> str:
    """The same S3 record with its first four data bytes replaced by ``FF FF FF FF`` and the checksum redone."""
    count = int(line[2:4], 16)
    body = bytearray(bytes.fromhex(line[2:-2]))  # count, address(4), data..., (checksum cut)
    body[5:9] = b"\xff\xff\xff\xff"
    checksum = (~sum(body)) & 0xFF
    assert body[0] == count
    return "S3" + body.hex().upper() + f"{checksum:02X}"


@pytest.fixture(scope="module")
def erased(tmp_path_factory, defc):
    """DEFC with DISPLAY_0001 read as a FLOAT32_IEEE word whose image bytes are erased flash, ``FF FF FF FF``
    (current NaN, `L.float32.FFFFFFFF` of the E1 examples; R-PE-DEF.114/1). Only the A2L's record layout of
    DISPLAY_0001 and the four image bytes at its address change; limits -40 ... 150 stay."""
    out = tmp_path_factory.mktemp("erased")
    a2l = defc["a2l"].read_text(encoding="utf-8")
    old_char = "VALUE 0x00800020 RL_S16 0 CM_DEF_LIN -40 150"
    assert a2l.count(old_char) == 1, "the DEFC generator no longer writes DISPLAY_0001 as expected"
    a2l = a2l.replace(old_char, "VALUE 0x00800020 RL_F32_ERASED 0 CM_DEF_LIN -40 150")
    layout = (
        "    /begin RECORD_LAYOUT RL_F32_ERASED\n"
        "      FNC_VALUES 1 FLOAT32_IEEE COLUMN_DIR DIRECT\n"
        "    /end RECORD_LAYOUT\n"
    )
    marker = "    /begin RECORD_LAYOUT RL_DEF_AXIS\n"
    assert a2l.count(marker) == 1
    a2l = a2l.replace(marker, layout + marker)
    s19_lines = defc["s19"].read_text(encoding="utf-8").splitlines()
    hit = [i for i, line in enumerate(s19_lines) if line.startswith("S325" + "00800020")]
    assert len(hit) == 1, "the DEFC image no longer has one S3 record at 0x00800020"
    s19_lines[hit[0]] = _s3_with_erased_word(s19_lines[hit[0]])
    a2l_path, s19_path = out / "definitions.a2l", out / "definitions.s19"
    a2l_path.write_text(a2l, encoding="utf-8", newline="\n")
    s19_path.write_text("\n".join(s19_lines) + "\n", encoding="utf-8", newline="\n")
    return {"a2l": a2l_path, "s19": s19_path, "names": defc["names"]}


# --------------------------------------------------------------------------- #
# Driver and readers
# --------------------------------------------------------------------------- #


def run(tmp_path: Path, case, body, *, size=SIZE_118):
    """Open the Patch Editor with ``case``'s A2L and image loaded through the app's loaders at ``size`` and
    return ``await body(app, pilot, panel)``."""

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await settle(pilot)
            app.load_a2l_from_path(Path(case["a2l"]))
            await settle_workers(pilot)
            assert app._compute_a2l_enriched_tags(), f"the A2L did not load: {list(app.log_lines)[-3:]}"
            app.load_from_path(Path(case["s19"]))
            for _ in range(100):
                if app.current_file is not None:
                    break
                await pilot.pause(0.05)
            assert app.current_file is not None, "the image did not load"
            app.action_show_screen("patch")
            await settle(pilot, 6)
            return await body(app, pilot, app.query_one("#patch_editor_panel"))

    return asyncio.run(_drive())


async def settle(pilot, rounds: int = 4) -> None:
    for _ in range(rounds):
        await pilot.pause()


async def wait_for(pilot, predicate, description: str, attempts: int = 150, delay: float = 0.02) -> None:
    """Bounded real-delay pump-until (the filter debounce needs wall time)."""
    for _ in range(attempts):
        await pilot.pause(delay)
        if predicate():
            return
    raise AssertionError(f"did not settle: {description}")


def need(root, selector: str, kind=None):
    """The one widget ``selector`` names, or a named assertion failure."""
    found = list(root.query(selector))
    assert len(found) == 1, f"{selector}: expected exactly 1 widget, found {len(found)}"
    if kind is not None:
        assert isinstance(found[0], kind), f"{selector}: expected {kind.__name__}, got {type(found[0]).__name__}"
    return found[0]


def plain(widget) -> str:
    """The painted plain text of a static-like widget."""
    rendered = widget.render()
    text = getattr(rendered, "plain", None)
    return text if text is not None else str(rendered)


def parse_rows(text: str, names) -> list[tuple[str, str, str]]:
    """(mark, parameter name, full line) of each sheet row in ``text``, in painted order; a name clipped with
    ``…`` is matched by its start against the A2L's names. Header, rule, detail and card lines match no name."""
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        mark = line[:2].ljust(2)
        if any(ch not in MARKS + " " for ch in mark):
            continue
        rest = line[2:]
        token = rest.split()[0].split("…")[0] if rest.split() else ""
        if len(token) < 4:
            continue
        hits = [n for n in names if n.startswith(token)]
        if len(hits) == 1:
            rows.append((mark, hits[0], line))
    return rows


def body_rows(panel, names):
    return parse_rows(plain(need(panel, BODY)), names)


def row_names(panel, names) -> list[str]:
    return [name for _, name, _ in body_rows(panel, names)]


def page_names(panel) -> list[str]:
    """The names of the sheet's page rows, painted or not."""
    return [row.name for row in need(panel, SHEET).rows]


def selected(panel, names):
    """The one row carrying ``▶``, or None."""
    marked = [name for mark, name, _ in body_rows(panel, names) if mark[0] == "▶"]
    assert len(marked) <= 1, f"more than one selected row: {marked}"
    return marked[0] if marked else None


def row_line(panel, names, name: str) -> str:
    lines = [line for _, n, line in body_rows(panel, names) if n == name]
    assert len(lines) == 1, f"row {name}: expected one painted line, found {len(lines)}"
    return lines[0]


def expanded_lines(panel, names, name: str) -> list[str]:
    """The lines painted under ``name``'s row that belong to its expanded object (each starts ``  ┊``)."""
    lines = plain(need(panel, BODY)).splitlines()
    start = [i for i, line in enumerate(lines) if any(n == name for _, n, _ in parse_rows(line, [name]))]
    assert len(start) == 1, f"row {name}: expected one painted line, found {len(start)}"
    out = []
    for line in lines[start[0] + 1 :]:
        if not line.startswith("  ┊"):
            break
        out.append(line)
    return out


async def focus_filter_and_type(pilot, panel, text: str) -> None:
    need(panel, FILTER, Input).focus()
    await settle(pilot, 2)
    await pilot.press(*text)


async def tab_to(pilot, app, widget_id: str, limit: int = 25) -> None:
    """Move the focus with Tab, as the operator does, until ``widget_id`` holds it."""
    for _ in range(limit):
        if app.focused is not None and app.focused.id == widget_id:
            return
        await pilot.press("tab")
        await settle(pilot, 1)
    assert app.focused is not None and app.focused.id == widget_id, (
        f"Tab never reached #{widget_id} in {limit} presses; focus is on {getattr(app.focused, 'id', app.focused)!r}"
    )


async def open_sheet(
    pilot, app, panel, names, filter_text: str = "_0001", present: str = "DISPLAY_0001", absent: str = "CURVE_DEF_0002"
) -> list[str]:
    """Filter the picker, wait for the page (``present`` painted, ``absent`` gone), Tab to the sheet body; return
    the painted row order."""
    assert list(panel.query(BODY)), f"{BODY}: the staging sheet is not mounted in the Patch Editor"
    await focus_filter_and_type(pilot, panel, filter_text)
    # The page is read from the sheet's rows, not the painted lines: at 80x24 the selected ENUM_0001's card fills
    # the row window (room = body height - 3), so the other rows of the page are not painted (R-PE-DEF.81).
    await wait_for(
        pilot,
        lambda: bool(list(panel.query(BODY)))
        and present in page_names(panel)
        and absent not in page_names(panel),
        f"the sheet paints the page of filter {filter_text!r}",
    )
    await tab_to(pilot, app, "patch_sheet_body")
    return row_names(panel, names)


async def select_row(pilot, panel, names, target: str, limit: int = 30) -> None:
    """Press down (or up) on the sheet until ``target`` carries ``▶`` (the selected row is always painted)."""
    order = page_names(panel)
    assert target in order, f"{target} is not on the page {order}"
    for _ in range(limit):
        current = selected(panel, names)
        if current == target:
            return
        key = "down" if current is None or order.index(current) < order.index(target) else "up"
        await pilot.press(key)
        await settle(pilot, 2)
    assert selected(panel, names) == target, f"could not select {target}: selected {selected(panel, names)}"


# --------------------------------------------------------------------------- #
# AT-B103-I8B-1 / -2 / -3 — the grid scrolls: scrollbar, End, Home, per width
# --------------------------------------------------------------------------- #


def _scroll_chain(size, cols: int, tmp_path: Path, defc):
    """Open the sheet at ``size``; read the scroller, press End, then Home, each time reading x right after the
    key (no pause: R-PE-DEF.94/6)."""

    async def body(app, pilot, panel):
        names = defc["names"]
        await open_sheet(pilot, app, panel, names)
        grid, sheet_body = need(panel, GRID), need(panel, BODY)
        before = (grid.scroll_x, grid.show_horizontal_scrollbar, grid.virtual_size.width)
        view = grid.scrollable_content_region.width
        gutter = grid.region.height - grid.scrollable_content_region.height
        body_height, grid_inner_height = sheet_body.region.height, grid.scrollable_content_region.height
        await pilot.press("end")
        after_end = grid.scroll_x  # no wait, no pause: the scroll must not animate
        await settle(pilot, 3)
        after_end_settled = grid.scroll_x
        focus_after_end = app.focused.id if app.focused is not None else None
        await pilot.press("home")
        after_home = grid.scroll_x
        return before, view, gutter, body_height, grid_inner_height, after_end, after_end_settled, after_home, focus_after_end

    return run(tmp_path, defc, body, size=size)


def test_at_b103_i8b_1_grid_118x54_shows_scrollbar_end_goes_to_last_columns_home_back(tmp_path: Path, defc) -> None:
    """AT-B103-I8B-1 (US-103-05; R-PE-DEF.92/1, R-PE-DEF.94/1, /2, /6). The operator needs to read the Limits and
    Δ columns the 143-cell grid pushes past the 110-cell view at 118 columns: the scroller shows a horizontal
    scrollbar over the 143-cell grid, End (body focused) puts the grid at its last columns at once (`G.end.118cols`,
    read right after the key: no animation), Home returns it to the first column, and the body keeps the focus."""
    before, view, gutter, body_h, grid_h, after_end, settled, after_home, focus = _scroll_chain(
        SIZE_118, 118, tmp_path, defc
    )
    scroll_x, shown, virtual = before
    assert shown is True and virtual == EX["G.grid_width"], (shown, virtual, "R-PE-DEF.92/1: bar shown, virtual 143")
    assert scroll_x == 0, before
    assert gutter == 1 and body_h == grid_h, (gutter, body_h, grid_h, "the body fills the scroller less the bar row")
    assert view == EX["G.view.118cols"], (view, "the sheet window's view at 118 columns")
    assert after_end == EX["G.end.118cols"], (after_end, "R-PE-DEF.94/1 + .94/6: x right after End, no wait")
    assert settled == after_end, (after_end, settled, "R-PE-DEF.94/6: the scroll did not animate on")
    assert after_end == max(0, virtual - view), (after_end, virtual, view)
    assert after_home == 0, after_home
    assert focus == "patch_sheet_body", focus


def test_at_b103_i8b_2_grid_80x24_shows_scrollbar_and_end_goes_to_last_columns(tmp_path: Path, defc) -> None:
    """AT-B103-I8B-2 (R-PE-DEF.92/2, R-PE-DEF.94/3). At 80×24 the view is only 70 cells, so the operator relies
    on the scrollbar and End to reach Δ: the scrollbar shows over 143 cells and End lands at `G.end.80cols`."""
    before, view, gutter, body_h, grid_h, after_end, settled, after_home, focus = _scroll_chain(
        SIZE_80, 80, tmp_path, defc
    )
    scroll_x, shown, virtual = before
    assert shown is True and virtual == EX["G.grid_width"], (shown, virtual)
    assert gutter == 1, gutter
    assert view == EX["G.view.80cols"], (view, "the sheet window's view at 80 columns")
    assert after_end == EX["G.end.80cols"] and settled == after_end, (after_end, settled)
    assert after_home == 0, after_home


def test_at_b103_i8b_3_grid_220x60_has_no_scrollbar_and_end_does_not_move(tmp_path: Path, defc) -> None:
    """AT-B103-I8B-3 (R-PE-DEF.93/1, R-PE-DEF.94/4). At 220×60 the 143-cell grid fits the 194-cell view, so no
    scrollbar is drawn, the body takes the bar's row, and End has nowhere to go (x stays 0): a scrollbar shown
    anyway, or an End that scrolls into blank space, would waste a row or lose the first columns."""
    before, view, gutter, body_h, grid_h, after_end, settled, after_home, focus = _scroll_chain(
        SIZE_220, 220, tmp_path, defc
    )
    scroll_x, shown, virtual = before
    assert shown is False, (shown, "R-PE-DEF.93/1: no horizontal scrollbar")
    assert view == EX["G.view.220cols"], (view, "the sheet window's view at 220 columns")
    assert gutter == 0 and body_h == grid_h, (gutter, body_h, grid_h, "the body takes the scrollbar's row")
    assert after_end == EX["G.end.220cols"] == 0, after_end
    assert after_home == 0, after_home


def test_r_pe_def_94_6_end_and_home_move_the_grid_at_once_with_no_animation(tmp_path: Path, defc) -> None:
    """R-PE-DEF.94/6 (E5, X8b: Pilot's `press` waits for the animator before it returns, so the AT nodes above read
    x only after any animation has ended and `scroll_to(..., animate=True)` survived them). The End and Home
    actions are run with no event-loop turn after them: x is already `G.end.118cols`, then already 0. An animated
    scroll is still at its start here, and on a real terminal the operator would watch the grid slide."""

    async def body(app, pilot, panel):
        await open_sheet(pilot, app, panel, defc["names"])
        grid = need(panel, GRID)
        sheet = grid.parent
        sheet.action_scroll_grid("end")
        at_once = grid.scroll_x
        await settle(pilot, 3)
        settled = grid.scroll_x
        sheet.action_scroll_grid("home")
        return at_once, settled, grid.scroll_x

    at_once, settled, back = run(tmp_path, defc, body)
    assert settled == EX["G.end.118cols"] != 0, (settled, "control: the End action reaches the last columns")
    assert at_once == settled, (at_once, settled, "x right after the End action, before any loop turn")
    assert back == 0, (back, "x right after the Home action, before any loop turn")


def test_at_b103_i8b_4_home_end_in_the_formula_input_move_its_cursor_not_the_grid(tmp_path: Path, defc) -> None:
    """AT-B103-I8B-4 (R-PE-DEF.94/5). The operator is typing `25.5` and presses Home: the cursor goes to the start
    of the text and the grid stays where End put it (x = `G.end.118cols`), then End moves the cursor to the end,
    still without scrolling. A sheet-level Home/End binding that wins over the input would snap the grid to x 0
    under the operator's typing."""

    async def body(app, pilot, panel):
        names = defc["names"]
        await open_sheet(pilot, app, panel, names)
        grid = need(panel, GRID)
        await select_row(pilot, panel, names, "DISPLAY_0001")
        await pilot.press("end")
        x_set = grid.scroll_x
        await pilot.press("enter")
        await settle(pilot, 2)
        focus_in_input = app.focused.id if app.focused is not None else None
        await pilot.press(*"25.5")
        await settle(pilot, 2)
        field = need(panel, INPUT, Input)
        await pilot.press("home")
        after_home = (field.cursor_position, grid.scroll_x, field.value)
        await pilot.press("end")
        after_end = (field.cursor_position, grid.scroll_x)
        return x_set, focus_in_input, after_home, after_end

    x_set, focus_in_input, after_home, after_end = run(tmp_path, defc, body)
    assert x_set == EX["G.end.118cols"] != 0, (x_set, "control: the grid was scrolled by End before the test")
    assert focus_in_input == "patch_sheet_input", focus_in_input
    assert after_home == (0, x_set, "25.5"), after_home
    assert after_end == (len("25.5"), x_set), after_end


# --------------------------------------------------------------------------- #
# AT-B103-I8B-5 — Tab order and focus with the scrollbar shown
# --------------------------------------------------------------------------- #


def test_at_b103_i8b_5_scrollbar_adds_no_tab_stop_and_the_grid_never_holds_the_focus(tmp_path: Path, defc) -> None:
    """AT-B103-I8B-5 (R-PE-DEF.92/3). The operator tabs through the Patch Editor with the scrollbar shown: the
    stops are exactly the base revision's, and the scroller is never the focused widget. A focusable scroller
    (Textual's ScrollableContainer) would add a Tab stop the operator must press past and would steal the arrow
    keys that choose enum entries."""

    async def body(app, pilot, panel):
        names = defc["names"]
        await open_sheet(pilot, app, panel, names)
        grids = list(panel.query(GRID))
        shown = [g.show_horizontal_scrollbar for g in grids]
        seen: list = []
        await pilot.press("tab")
        await settle(pilot, 1)
        first = app.focused.id if app.focused is not None else None
        seen.append(first)
        for _ in range(60):
            await pilot.press("tab")
            await settle(pilot, 1)
            now = app.focused.id if app.focused is not None else None
            if now == first:
                break
            seen.append(now)
        return seen, shown

    seen, shown = run(tmp_path, defc, body)
    assert None not in seen, seen
    assert tuple(seen) == BASE_TAB_ORDER, (tuple(seen), "the base's Tab stops")
    assert shown == [True], (shown, "control: the scroller exists and its scrollbar is shown for this case")
    assert "patch_sheet_grid" not in seen, seen


# --------------------------------------------------------------------------- #
# AT-B103-I8B-6 — an enum row: the arrows choose, they do not scroll; Enter-less expand shows the card
# --------------------------------------------------------------------------- #


def test_at_b103_i8b_6_enum_row_shows_its_card_and_left_right_choose_without_scrolling(tmp_path: Path, defc) -> None:
    """AT-B103-I8B-6 (R-PE-DEF.108/1 and /4, R-PE-DEF.33/1 ... /3). Selecting ENUM_0001 opens its framed card
    after the definition line (`E.card.ENUM_0001.line0` ... `line3`: `(●) 1 IDLE`, `↔ choose · enter stage`);
    at 118×54, where the grid is wider than the view, → moves the choice to `(●) 2 RUN` and ← back, and the
    grid's x stays 0 both times. The operator needs the arrows to choose an entry; if they scrolled the grid
    (the prototype's focusable scroller) the entry would not change. Control: a number row (DISPLAY_0001) gets
    exactly one expanded line and no card."""

    async def body(app, pilot, panel):
        names = defc["names"]
        await open_sheet(pilot, app, panel, names)
        grid = need(panel, GRID)
        await select_row(pilot, panel, names, "DISPLAY_0001")
        number_lines = expanded_lines(panel, names, "DISPLAY_0001")
        await select_row(pilot, panel, names, "ENUM_0001")
        start = expanded_lines(panel, names, "ENUM_0001")
        x0 = grid.scroll_x
        await pilot.press("right")
        await settle(pilot, 2)
        right = expanded_lines(panel, names, "ENUM_0001")
        x_right = grid.scroll_x
        await pilot.press("left")
        await settle(pilot, 2)
        left = expanded_lines(panel, names, "ENUM_0001")
        x_left = grid.scroll_x
        return number_lines, start, x0, right, x_right, left, x_left

    number_lines, start, x0, right, x_right, left, x_left = run(tmp_path, defc, body)
    # R-PE-DEF.108/4 (control): a number row has one expanded line and no frame
    assert len(number_lines) == 1 and not any(ch in number_lines[0] for ch in "╭╰"), number_lines
    # R-PE-DEF.108/1 + R-PE-DEF.33/1: the card, line by line, from the examples
    card = [EX[f"E.card.ENUM_0001.line{n}"].rstrip() for n in range(4)]
    assert len(start) == 1 + len(card), (len(start), start)
    for want, got in zip(card, start[1:]):
        assert got.rstrip().endswith(want), (want, got)
    assert "(●) 1 IDLE" in start[2] and "↔ choose · enter stage" in start[3], start
    # R-PE-DEF.33/2 + /3: → chooses RUN, the grid does not scroll; ← chooses IDLE again
    assert "(●) 2 RUN" in right[2] and "(●) 1 IDLE" not in right[2], right
    assert "(●) 1 IDLE" in left[2] and "(●) 2 RUN" not in left[2], left
    assert x0 == x_right == x_left == 0, (x0, x_right, x_left)


def test_at_b103_i8b_7_mask_field_row_shows_the_bit_card(tmp_path: Path, defc) -> None:
    """AT-B103-I8B-7 (R-PE-DEF.108/2). Selecting MASK_FIELD_0001 shows the bit card after its definition line:
    the title bar (`B.card.MASK_FIELD_0001.line0`), the register table with its `bit`, `before`, `mask`, `after`
    rows, the mask row of the A2L's 0FF0 (`line3`) and the closing bar (`line5`), all 73 cells. The before and
    after bytes depend on the image and are checked only by their row labels."""

    async def body(app, pilot, panel):
        names = defc["names"]
        await open_sheet(pilot, app, panel, names)
        await select_row(pilot, panel, names, "MASK_FIELD_0001")
        return expanded_lines(panel, names, "MASK_FIELD_0001")

    lines = run(tmp_path, defc, body)
    card = [EX[f"B.card.MASK_FIELD_0001.line{n}"].rstrip() for n in range(6)]
    assert len(lines) == 1 + len(card), (len(lines), lines)
    cards = [line.rstrip() for line in lines[1:]]
    for n in (0, 3, 5):
        assert cards[n].endswith(card[n]), (n, card[n], cards[n])
    for n, label in ((1, "│ bit "), (2, "│ before "), (4, "│ after ")):
        assert label in cards[n], (n, label, cards[n])
        assert cards[n].endswith("│") and len(card[n]) == EX["B.card.MASK_FIELD_0001.width"], (n, cards[n])


# --------------------------------------------------------------------------- #
# AT-B103-I8B-8 — the filter icon, the formula bar width, a NaN row
# --------------------------------------------------------------------------- #


def test_at_b103_i8b_8_include_parameter_control_shows_the_filter_icon(tmp_path: Path, defc) -> None:
    """AT-B103-I8B-8 (R-PE-DEF.113/1 and /2). At 118×54 the Include parameter control of the filter row reads
    `▽ Pick`, so the operator sees it as the filter's action; at 80×24 every control of the filter row keeps a
    visible (non-zero) region, the icon not pushing one off the 80-cell row."""

    async def body(app, pilot, panel):
        await settle(pilot, 2)
        out = {}
        include = need(panel, INCLUDE, Button)
        out["label"] = str(include.label)
        out["regions"] = [
            (sel, need(panel, sel).region.width, need(panel, sel).region.height, need(panel, sel).region.right)
            for sel in FILTER_ROW
        ]
        out["panel_right"] = panel.region.right
        return out

    wide = run(tmp_path, defc, body, size=SIZE_118)
    narrow = run(tmp_path, defc, body, size=SIZE_80)
    assert wide["label"] == "▽ Pick", wide["label"]
    assert narrow["label"] == "▽ Pick", narrow["label"]
    assert len(narrow["regions"]) == 7, narrow["regions"]
    assert all(w > 0 and h > 0 for _, w, h, _ in narrow["regions"]), narrow["regions"]
    assert all(right <= narrow["panel_right"] for _, _, _, right in narrow["regions"]), narrow


@pytest.mark.parametrize("size", [SIZE_80, SIZE_118, SIZE_220], ids=["80x24", "118x54", "220x60"])
def test_at_b103_i8b_9_formula_bar_stays_inside_the_sheet_window_and_the_long_refusal_ends_in_an_ellipsis(
    tmp_path: Path, defc, size
) -> None:
    """AT-B103-I8B-9 (R-PE-DEF.95/1 ... /3, R-PE-DEF.41). Typing 300 `x` into the formula input of DISPLAY_0001
    shows a refusal tail that ends in `…`, and the formula bar is no wider than the sheet window at 80, 118 and
    220 columns, outside the scrolling grid (so it never has the grid's 143 cells and never scrolls away). The
    bar-outside-grid check is the part that needs the new scroller."""

    async def body(app, pilot, panel):
        names = defc["names"]
        await open_sheet(pilot, app, panel, names)
        grid, sheet, bar, tail = need(panel, GRID), need(panel, SHEET), need(panel, BAR), need(panel, TAIL)
        await select_row(pilot, panel, names, "DISPLAY_0001")
        await pilot.press("enter")
        await settle(pilot, 2)
        await pilot.press(*("x" * 300))
        await settle(pilot, 3)
        return {
            "inside_grid": grid in bar.ancestors,
            "bar_width": bar.region.width,
            "sheet_content_width": sheet.content_region.width,
            "bar_right": bar.region.right,
            "sheet_right": sheet.content_region.right,
            "tail": plain(tail),
        }

    out = run(tmp_path, defc, body, size=size)
    assert out["inside_grid"] is False, "the formula bar must sit outside the scrolling grid"
    assert out["bar_width"] <= out["sheet_content_width"], out
    assert out["bar_right"] <= out["sheet_right"], out
    assert out["tail"].rstrip().endswith("…"), out["tail"]


def test_at_b103_i8b_10_a_nan_current_value_paints_the_no_position_limits_cell_and_does_not_crash(
    tmp_path: Path, erased
) -> None:
    """AT-B103-I8B-10 (R-PE-DEF.114/1). DISPLAY_0001 read as a FLOAT32 word of erased flash (`FF FF FF FF`, current
    NaN) must not take the app down: the sheet paints the row and its Limits cell is the no-position form
    `L.cell.float32_erased` (`?` where the current marker would be, no `●`), both while the row is selected
    and after the selection moved off it. On the base the track position of NaN is rounded and raises."""

    async def body(app, pilot, panel):
        names = erased["names"]
        await open_sheet(pilot, app, panel, names)
        selected_line = row_line(panel, names, "DISPLAY_0001")
        await select_row(pilot, panel, names, "ENUM_0001")
        unselected_line = row_line(panel, names, "DISPLAY_0001")
        return selected_line, unselected_line

    selected_line, unselected_line = run(tmp_path, erased, body)
    start = EX["G.start.Limits"]
    want = EX["L.cell.float32_erased"]
    for line in (selected_line, unselected_line):
        cell = line[start : start + EX["L.cell.float32_erased.len"]]
        assert cell == want, (cell, want)
        assert "●" not in cell and cell[EX["L.cell.float32_erased.marks"]["?"]] == "?", cell
