"""Batch-103 Inc 8b E4, group S1 - the sheet's render rows (grid D, styles, Limits column, summary strip).

Design under test: ``.dev-flow/2026-11-05-batch-103/inc-8b/01-requirements.md``
(R-PE-DEF.5, .21, .76, .89 ... .91, .96 ... .101, .103 ... .106, .114; R-PE-BENCH.11, .17, .107, .108)
through ``s19_app/tui/definition_sheet.py`` (``sheet_widths``, ``header_line``, ``header_rule``,
``row_line``, ``limits_cell``, ``formula_tail``) and ``s19_app/tui/definition_bench.py`` (``bench_cells``,
``summary_strip``). Black-box: every test calls the shipped entry point and reads the painted ``Text``.

Why it matters to the operator (proto8 verdict, variant D): the sheet is a fixed 143-cell grid whose
columns line up on every row, every colour carries a glyph, and the Limits column keeps its marks,
values and units on the same cells down the whole column. A row that shifts a gutter, a hostile
A2L text that widens a cell, a NaN that raises in the paint path, or a hue without its glyph each break
that promise, and each has a case below.

Expected values are never retyped: they are keys of
``evidence-e1/examples_inc8b-transcript.txt`` (parsed below) or are recomputed by the spec-side oracle
``evidence-e1/examples_inc8b.py`` (stdlib only, imported as ``EX8``). A position or a width is
searched in the painted text, never counted by hand (tester rule 2).

Not in this file (other testers own them): the card, the expanded object and ``detail_lines`` (T8b-S2),
the scroller, body height, ``_bench_geometry``, picker and help (T8b-BW), the pilot ATs (T8b-AT),
R-PE-DEF.97 cases 10 .. 12 (mask mark, expanded ground, card ground: the card is S2's).

Cases whose behaviour does not exist on the base ``48af05ff`` fail there by an assertion; where the
entry point itself is new (``header_rule``, the ``odd`` keyword) the test says so in its message.
"""

from __future__ import annotations

import ast
import dataclasses
import importlib.util
import io
import math
import re
from pathlib import Path

import pytest
from rich.cells import cell_len
from rich.color import ColorType
from rich.console import Console
from rich.text import Text

from s19_app.tui import definition_bench as db
from s19_app.tui import definition_sheet as ds
from s19_app.tui.a2l_definition import Decoded, Limits, describe_definition
from tests.support.b103_inc8_s1 import defc, stage_entry, v171  # noqa: F401  (fixtures used by name)
from tests.support.b103_inc9_b import blank_state, decoded_of, defc_obj, sheet_row, staged_entry, staged_values, view_state

ROOT = Path(__file__).resolve().parents[1]
INC8B = ROOT / ".dev-flow" / "2026-11-05-batch-103" / "inc-8b" / "evidence-e1"
replace = dataclasses.replace
_CONSOLE = Console(color_system="truecolor", force_terminal=True, width=400)


def _load_oracle():
    spec = importlib.util.spec_from_file_location("b103_inc8b_examples", INC8B / "examples_inc8b.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # a main guard keeps it silent
    return module


def _load_transcript() -> dict:
    out = {}
    for line in (INC8B / "examples_inc8b-transcript.txt").read_text(encoding="utf-8").splitlines():
        key, sep, value = line.partition(" = ")
        if not sep:
            continue
        try:
            out[key] = ast.literal_eval(value)
        except (ValueError, SyntaxError):
            out[key] = value  # `nan` and the like: kept as the text
    return out


EX8 = _load_oracle()
TR = _load_transcript()

# The colour tokens of the sheet styles table (01-requirements.md, "Sheet styles").
VALUE, DGRAY, HILITE = "#e9e9e9", "#969aad", "#91abec"
GREEN, YELLOW, RED, PURPLE = "#54efae", "#f6ff8f", "#fd8383", "#b565f3"
SELECTED_GROUND, ODD_GROUND, KEY_INK = "#1c2547", "#131a2c", "#0a0e1b"

LABELS = [label for label, _ in EX8.COLUMNS]
START = {label: TR[f"G.start.{label}"] for label in LABELS}
WIDTH = dict(EX8.COLUMNS)
GUTTERS = [TR[f"G.gutter_after.{label}"] for label in LABELS]
GRID = TR["G.grid_width"]
LIMITS_W = WIDTH["Limits"]
VIEWS = (73, 111, 195)  # the view widths at 80, 118 and 220 columns (the cases' V)

KIND, CURRENT, NEW, LIMITS, DELTA = range(5)  # bench_cells order

# ------------------------------------------------------------------------------------ helpers


def cell_slice(plain: str, start: int, width: int) -> str:
    """The characters of ``plain`` whose cells lie in ``[start, start + width)``."""
    out, pos = "", 0
    for char in plain:
        w = cell_len(char)
        if pos >= start and pos + w <= start + width:
            out += char
        pos += w
        if pos >= start + width:
            break
    return out


def gutter_cells(plain: str) -> list[int]:
    out, pos = [], 0
    for char in plain:
        if char == "│":
            out.append(pos)
        pos += cell_len(char)
    return out


def index_of_cell(plain: str, cell: int) -> int:
    pos = 0
    for index, char in enumerate(plain):
        if pos >= cell:
            return index
        pos += cell_len(char)
    return len(plain)


def style_at(text: Text, cell: int):
    return text.get_style_at_offset(_CONSOLE, index_of_cell(text.plain, cell))


def fg(text: Text, cell: int):
    color = style_at(text, cell).color
    return None if color is None else color.get_truecolor().hex


def bg(text: Text, cell: int):
    color = style_at(text, cell).bgcolor
    return None if color is None else color.get_truecolor().hex


def bold(text: Text, cell: int) -> bool:
    return bool(style_at(text, cell).bold)


def underline(text: Text, cell: int) -> bool:
    return bool(style_at(text, cell).underline)


def char_cell(plain: str, char: str) -> int:
    """The cell where ``char`` first appears; the test fails when it is absent."""
    assert char in plain, f"{char!r} is not in the painted text {plain!r}"
    return cell_len(plain[: plain.index(char)])


def need(name: str):
    """A name the design adds: its absence on the base is a RED of this assertion, not an import error."""
    assert hasattr(ds, name), f"definition_sheet.{name} is absent (new in Inc 8b)"
    return getattr(ds, name)


def make_row(definition, a2l, image, entries=()):
    overlay = ds.StagedOverlay(image, list(entries))
    return ds.build_row(definition, a2l, image, overlay), overlay


def paint(case, definition, *, text=None, entries=(), selected=False, odd=None, view=111, state=None):
    """(line, row, preview): one sheet row through ``row_line`` at the grid widths of view width ``view``."""
    row, overlay = make_row(definition, case["a2l"], case["image"], entries)
    pv = ds.preview(definition, case["a2l"], text, overlay) if text is not None else None
    extra = {} if odd is None else {"odd": odd}
    line = ds.row_line(row, ds.sheet_widths(view), selected, text, pv, state=state, **extra)
    return line, row, pv


def display(case, **over):
    return replace(case["defs"]["DISPLAY_0001"], **over)


def with_current(row, number):
    """The row with its current value replaced (``None``: no current value)."""
    if number is None:
        return replace(row, current=None)
    return replace(row, current=Decoded(stored=number, value=number, text=str(number)))


_KEEP = object()


def limits_of(case, name, *, lower=_KEEP, upper=_KEEP, current=_KEEP, value=None, limits_width=LIMITS_W):
    """The Limits cell of ``name`` (a DEFC definition, its limits and current optionally replaced)."""
    d = case["defs"][name]
    if lower is not _KEEP:
        d = replace(d, limits=Limits(lower, upper, "", ""))
    row, _ = make_row(d, case["a2l"], case["image"])
    if current is not _KEEP:
        row = with_current(row, current)
    return ds.limits_cell(row, value, limits_width)


def offsets_of(plain: str) -> dict:
    return EX8.offsets(plain)


def marks_of(plain: str) -> dict:
    return EX8.marks(plain)


def all_fg_hues(text: Text) -> set:
    """Every foreground hex painted in ``text`` over characters that are not blank."""
    hues = set()
    for index, char in enumerate(text.plain):
        if char == " ":
            continue
        color = text.get_style_at_offset(_CONSOLE, index).color
        if color is not None:
            hues.add(color.get_truecolor().hex)
    return hues


def rich_named(text: Text) -> set:
    """Rich's own ``green``, ``yellow`` and ``red`` used anywhere in ``text`` (base's state hues)."""
    named = set()
    for index in range(len(text.plain)):
        color = text.get_style_at_offset(_CONSOLE, index).color
        if color is not None and color.type == ColorType.STANDARD and color.name in ("green", "yellow", "red"):
            named.add(color.name)
    return named


# ==================================================================================================
# R-PE-DEF.5 - the header line (3 cases, one per view width)
# ==================================================================================================


@pytest.mark.parametrize("view", VIEWS)
def test_r_pe_def_5_header_line_is_the_grid_header_at_every_view_width(view):
    """R-PE-DEF.5/1..3 (V = 111, 73, 195): the header line is ``G.header_line`` whatever the width.

    Operator need: Kind and Unit stay visible and the labels sit where the columns are; the grid does not
    stretch or hide columns with the window."""
    assert ds.header_line(ds.sheet_widths(view)).plain == TR["G.header_line"]


# ==================================================================================================
# R-PE-DEF.89 - the grid widths and column starts (3 cases) ; .90 gutters (2) ; .91 header rule (1)
# ==================================================================================================


@pytest.mark.parametrize("view", VIEWS)
def test_r_pe_def_89_every_defc_row_has_its_cells_at_the_column_starts(defc, view):
    """R-PE-DEF.89/1..3 - on the DEFC page every row line is 143 cells and its cells start at ``G.start.*``.

    Operator need: columns line up down the page at every window width (no width classes)."""
    for name, definition in defc["defs"].items():
        line, row, _ = paint(defc, definition, view=view)
        plain = line.plain
        assert cell_len(plain) == GRID == TR["G.grid_width"], (name, cell_len(plain))
        assert cell_slice(plain, START["Parameter"], WIDTH["Parameter"]).rstrip() == name, name
        if row.kind in ("number", "bit mask", "enum", "text"):
            assert cell_slice(plain, START["Kind"], WIDTH["Kind"]).rstrip() == ds.kind_word(definition), name
        unit = definition.unit or ""
        assert cell_slice(plain, START["Unit"], WIDTH["Unit"]).rstrip() == unit, name


@pytest.mark.parametrize("view", VIEWS)
def test_r_pe_def_89_the_widths_do_not_depend_on_the_view(view):
    """R-PE-DEF.89 (unit) - ``sheet_widths(V)`` gives the grid widths: no hidden Kind at V = 73, no stretch at 195."""
    got = ds.sheet_widths(view)
    assert (got.name, got.kind, got.current, got.new, got.unit, got.limits, got.delta) == tuple(
        WIDTH[label] for label in LABELS
    )


def test_r_pe_def_90_1_gutters_stand_after_every_column_of_every_defc_row(defc):
    """R-PE-DEF.90/1 - V = 111: ``│`` at 28, 39, 60, 77, 86, 121, 142 (``G.gutter_after.*``) on every DEFC row."""
    for name, definition in defc["defs"].items():
        line, _, _ = paint(defc, definition, view=111)
        assert gutter_cells(line.plain) == GUTTERS, name


def test_r_pe_def_90_2_a_long_name_does_not_move_the_first_gutter(defc):
    """R-PE-DEF.90/2 - a row named with 40 characters keeps ``│`` at 28 (the clip keeps the gutter)."""
    line, _, _ = paint(defc, display(defc, name="N" * 40))
    assert gutter_cells(line.plain) == GUTTERS
    assert gutter_cells(line.plain)[0] == TR["G.gutter_after.Parameter"]


def test_r_pe_def_91_1_the_header_rule_is_the_grid_rule():
    """R-PE-DEF.91/1 - ``header_rule(widths)`` is ``G.header_rule``: 143 cells, ``┿`` at each gutter.

    Operator need: the rule under the labels shows where each column ends. On the base the function is
    absent (RED = absent); the body's second line through the app is T8b-AT's case."""
    rule = need("header_rule")(ds.sheet_widths(111)).plain
    assert rule == TR["G.header_rule"]
    assert cell_len(rule) == TR["G.header_rule.len"]
    assert [i for i, c in enumerate(rule) if c == "┿"] == GUTTERS


# ==================================================================================================
# R-PE-DEF.96 - the clip of hostile cells (6 cases)
# ==================================================================================================


def test_r_pe_def_96_1_a_wide_name_is_cut_by_cells(defc):
    """R-PE-DEF.96/1 - a name of 14 x ``温度`` (56 cells) -> ``C.name_wide.fit26`` (25 cells + ``…``, 26 with the pad)."""
    line, _, _ = paint(defc, display(defc, name="温度" * 14))
    assert cell_slice(line.plain, START["Parameter"], WIDTH["Parameter"]) == TR["C.name_wide.fit26"]
    assert gutter_cells(line.plain) == GUTTERS


def test_r_pe_def_96_2_a_wide_unit_is_cut_by_cells(defc):
    """R-PE-DEF.96/2 - a unit ``温度温度温度`` -> ``C.unit_wide.fit8``."""
    line, _, _ = paint(defc, display(defc, unit="温度温度温度"))
    assert cell_slice(line.plain, START["Unit"], WIDTH["Unit"]) == TR["C.unit_wide.fit8"]


def test_r_pe_def_96_3_a_300_character_enum_entry_is_cut_in_the_current_cell(defc):
    """R-PE-DEF.96/3 - the enum entry of the current value reads 300 x ``X`` -> Current ``C.enum_long.current20``."""
    enum = defc["defs"]["ENUM_0001"]
    entries = tuple(replace(e, text="X" * 300) if e.raw == 1 else e for e in enum.enum_entries)
    line, _, _ = paint(defc, replace(enum, enum_entries=entries, _table_form=None))
    assert cell_slice(line.plain, START["Current"], WIDTH["Current"]) == TR["C.enum_long.current20"]
    assert gutter_cells(line.plain) == GUTTERS


def test_r_pe_def_96_4_a_10000_character_name_is_clipped_without_cleaning_it_whole(defc, monkeypatch):
    """R-PE-DEF.96/4 - a 10,000-character name -> ``C.name_10000.fit26``; ``plain`` never sees more than 120 characters.

    Operator need: a hostile A2L with a huge name must not stall the paint (the clip reads a bounded prefix)."""
    seen = []
    original = ds.plain

    def spy(text):
        seen.append(len(text))
        return original(text)

    monkeypatch.setattr(ds, "plain", spy)
    line, _, _ = paint(defc, display(defc, name="N" * 10_000))
    assert cell_slice(line.plain, START["Parameter"], WIDTH["Parameter"]) == TR["C.name_10000.fit26"]
    assert max(seen) <= 120, f"plain() saw {max(seen)} characters"


def test_r_pe_def_96_5_a_40_character_unit_keeps_the_limits_column_in_place(defc):
    """R-PE-DEF.96/5 - a unit of 40 characters -> ``C.unit_40.fit8`` and the Limits column still starts at 87."""
    line, row, _ = paint(defc, display(defc, unit="U" * 40))
    assert cell_slice(line.plain, START["Unit"], WIDTH["Unit"]) == TR["C.unit_40.fit8"]
    assert START["Limits"] == 87
    assert cell_slice(line.plain, START["Limits"], LIMITS_W) == ds.limits_cell(row, None, LIMITS_W).plain


def test_r_pe_def_96_6_a_name_that_only_holds_a_control_character_is_cleaned_not_cut(defc):
    """R-PE-DEF.96/6 - boundary: ``A\\x1b[2JB`` (6 cells, not wider) -> ``C.name_esc.fit26``: cleaned, no ``…``, padded."""
    line, _, _ = paint(defc, display(defc, name="A\x1b[2JB"))
    got = cell_slice(line.plain, START["Parameter"], WIDTH["Parameter"])
    assert got == TR["C.name_esc.fit26"]
    assert "…" not in got and "\x1b" not in line.plain


# ==================================================================================================
# R-PE-DEF.97 - the sheet styles, one case per state-independent row of the table (1 .. 9)
# ==================================================================================================


def test_r_pe_def_97_1_text_style_names_and_current_values(defc):
    """R-PE-DEF.97/1 - names and current values are #e9e9e9; the selected name is bold."""
    line, row, _ = paint(defc, display(defc))
    assert fg(line, START["Parameter"]) == VALUE
    assert fg(line, START["Current"]) == VALUE
    assert not bold(line, START["Parameter"])
    picked, _, _ = paint(defc, display(defc), selected=True)
    assert bold(picked, START["Parameter"]) and fg(picked, START["Parameter"]) == VALUE


def test_r_pe_def_97_2_dim_style_kind_unit_limits_text_and_the_empty_new_mark(defc):
    """R-PE-DEF.97/2 - kind word, unit, the ``·`` of a row with no edit and the Limits text are #969aad."""
    line, row, _ = paint(defc, display(defc))
    assert fg(line, START["Kind"]) == DGRAY
    assert fg(line, START["Unit"]) == DGRAY
    assert cell_slice(line.plain, START["New"], 1) == "·" and fg(line, START["New"]) == DGRAY
    limits = cell_slice(line.plain, START["Limits"], LIMITS_W)
    digit = START["Limits"] + limits.index("4")  # the lower limit -40
    assert fg(line, digit) == DGRAY


def test_r_pe_def_97_3_header_labels_are_bold_dim():
    """R-PE-DEF.97/3 - the header labels are bold #969aad."""
    header = ds.header_line(ds.sheet_widths(111))
    for label in LABELS:
        assert fg(header, START[label]) == DGRAY, label
        assert bold(header, START[label]), label


def test_r_pe_def_97_4_rule_style_gutters_are_hilite(defc):
    """R-PE-DEF.97/4 - the gutters ``│`` of a row and of the header, and the header rule, are #91abec."""
    line, _, _ = paint(defc, display(defc))
    header = ds.header_line(ds.sheet_widths(111))
    for cell in GUTTERS:
        assert fg(line, cell) == HILITE, cell
        assert fg(header, cell) == HILITE, cell
    rule = need("header_rule")(ds.sheet_widths(111))
    assert all(fg(rule, i) == HILITE for i in range(cell_len(rule.plain)))


def test_r_pe_def_97_5_the_selected_row_has_its_ground_and_a_bold_hilite_marker(defc):
    """R-PE-DEF.97/5 - selected: ground #1c2547 over every cell of the row; ``▶`` bold #91abec."""
    line, _, _ = paint(defc, display(defc), selected=True)
    assert line.plain[0] == "▶" and fg(line, 0) == HILITE and bold(line, 0)
    assert {bg(line, c) for c in range(GRID)} == {SELECTED_GROUND}
    unselected, _, _ = paint(defc, display(defc))
    assert all(bg(unselected, c) is None for c in range(GRID))


def test_r_pe_def_97_6_zebra_ground_on_odd_positions_only(defc):
    """R-PE-DEF.97/6 - the ground #131a2c is on an odd page position, none on an even one.

    On the base ``row_line`` has no ``odd`` keyword (RED = absent keyword)."""
    odd, _, _ = paint(defc, display(defc), odd=True)
    even, _, _ = paint(defc, display(defc), odd=False)
    assert {bg(odd, c) for c in range(GRID)} == {ODD_GROUND}
    assert all(bg(even, c) is None for c in range(GRID))


def test_r_pe_def_97_7_the_current_marker_on_the_track_is_bold_value(defc):
    """R-PE-DEF.97/7 - the track's ``●`` is bold #e9e9e9."""
    line, _, _ = paint(defc, display(defc))
    cell = START["Limits"] + char_cell(cell_slice(line.plain, START["Limits"], LIMITS_W), "●")
    assert fg(line, cell) == VALUE and bold(line, cell)


def test_r_pe_def_97_8_the_after_bytes_of_the_formula_tail_are_pending_without_underline(defc):
    """R-PE-DEF.97/8 - the after bytes of ``<before> → <after>`` are bold #b565f3 and not underlined."""
    _, row, pv = paint(defc, display(defc), text="25.5")
    tail = ds.formula_tail(row, pv, 118)
    after = " ".join(f"{b:02X}" for b in pv.result.data[:8])
    assert after == TR["S.after_bytes.DISPLAY_0001.25.5"], "the row's own preview bytes (the case's example)"
    arrow = tail.plain.index(" → ", tail.plain.index(" · ")) + 3
    assert tail.plain[arrow : arrow + len(after)] == after
    cell = cell_len(tail.plain[:arrow])
    assert fg(tail, cell) == PURPLE and bold(tail, cell) and not underline(tail, cell)


def test_r_pe_def_97_9_the_key_hint_is_ink_on_hilite(defc):
    """R-PE-DEF.97/9 - ``enter stage ↓`` is bold #0a0e1b on #91abec."""
    _, row, pv = paint(defc, display(defc), text="25.5")
    tail = ds.formula_tail(row, pv, 118)
    cell = char_cell(tail.plain, "enter stage")
    assert fg(tail, cell) == KEY_INK and bg(tail, cell) == HILITE and bold(tail, cell)


# ==================================================================================================
# R-PE-DEF.98 / .99 / .100 / .101 - the staged, pending and refused styles and the verdict hues
# ==================================================================================================


def _staged_line(case, name, text):
    definition = case["defs"][name]
    entries = [stage_entry(definition, case["a2l"], text, case["image"])]
    return paint(case, definition, entries=entries)


def _new_delta_cells(line):
    return (cell_slice(line.plain, START["New"], WIDTH["New"]).rstrip(),
            cell_slice(line.plain, START["Δ"], WIDTH["Δ"]).rstrip())


def _assert_style_over(line, first_cell, text, hue):
    for offset in range(len(text)):
        assert fg(line, first_cell + offset) == hue and bold(line, first_cell + offset), (text, offset)


@pytest.mark.parametrize(
    ("name", "text", "new", "delta"),
    [("DISPLAY_0001", "25.5", "25.5", "-118.0 staged"), ("MASK_FIELD_0001", "255", "255 (0xFF)", "+81")],
)
def test_r_pe_def_98_staged_scalar_is_painted_green_with_its_dot(defc, name, text, new, delta):
    """R-PE-DEF.98/1, /2 - a staged, not pending row: New, Δ, the mark's ``●`` and the track's ``◆`` bold #54efae.

    Operator need: staged edits read as staged without colour (``●``, ``staged``) and with the operator's green."""
    line, _, _ = _staged_line(defc, name, text)
    shown_new, shown_delta = _new_delta_cells(line)
    assert shown_new == new and shown_delta.startswith(delta)
    _assert_style_over(line, START["New"], new, GREEN)
    _assert_style_over(line, START["Δ"], delta, GREEN)
    assert line.plain[1] == "●" and fg(line, 1) == GREEN and bold(line, 1)
    track = START["Limits"] + char_cell(cell_slice(line.plain, START["Limits"], LIMITS_W), "◆")
    assert fg(line, track) == GREEN and bold(line, track)


def test_r_pe_def_98_3_a_staged_array_without_an_edit_shows_the_green_dot_and_staged_delta(defc):
    """R-PE-DEF.98/3 - VAL_BLK_DEF_0001 staged, no bench edit: ``●`` green and Δ ``max |Δ| … staged`` green."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    staged, entry = staged_values(o, {(0, 0): "10"})
    row = sheet_row(o.d, o.a2l, o.image, [entry])
    # The bench reads the staged Δ from the state's values and staged decode (R-PE-BENCH.16/2).
    line = ds.row_line(row, ds.sheet_widths(111), False, None, None, state=view_state(o, staged=staged))
    assert line.plain[1] == "●" and fg(line, 1) == GREEN
    delta = cell_slice(line.plain, START["Δ"], WIDTH["Δ"]).rstrip()
    assert delta.startswith("max |Δ|") and delta.endswith("staged")
    _assert_style_over(line, START["Δ"], delta, GREEN)


@pytest.mark.parametrize(
    ("text", "new", "delta_prefix"), [("25.5", "25.5", "-118.0 (-62.1%)"), ("175", "175.0", "")]
)
def test_r_pe_def_99_1_2_pending_scalar_is_painted_purple_with_its_diamond(defc, text, new, delta_prefix):
    """R-PE-DEF.99/1, /2 - a pending row (an encode with a notice included): New, Δ, ``◆`` bold #b565f3, not YELLOW."""
    line, _, _ = paint(defc, display(defc), text=text)
    shown_new, shown_delta = _new_delta_cells(line)
    # New shows the preview's value text (R-PE-DEF.24): `175` decodes to `175.0`.
    assert shown_new == new and shown_delta.startswith(delta_prefix) and shown_delta
    _assert_style_over(line, START["New"], shown_new, PURPLE)
    _assert_style_over(line, START["Δ"], shown_delta, PURPLE)
    # The mark column is 2 cells: the selector at 0, the glyph at 1.
    assert line.plain[1] == "◆" and fg(line, 1) == PURPLE and bold(line, 1)
    track = START["Limits"] + char_cell(cell_slice(line.plain, START["Limits"], LIMITS_W), "◆") if text == "25.5" else None
    if track is not None:
        assert fg(line, track) == PURPLE and bold(line, track)
    assert YELLOW not in all_fg_hues(line), "a notice does not turn the New cell YELLOW (no ▲ on this line)"


def test_r_pe_def_99_3_a_pending_bench_edit_is_purple(defc):
    """R-PE-DEF.99/3 - VAL_BLK_DEF_0001 with a bench edit: ``◆`` and New ``2 cells`` in the pending style."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    row = sheet_row(o.d, o.a2l, o.image)
    state = view_state(o, edit={(0, 0): "41.9", (1, 0): "16.0"})
    line = ds.row_line(row, ds.sheet_widths(111), False, None, None, state=state)
    assert line.plain[1] == "◆" and fg(line, 1) == PURPLE and bold(line, 1)
    new = cell_slice(line.plain, START["New"], WIDTH["New"]).rstrip()
    assert new == "2 cells"
    _assert_style_over(line, START["New"], new, PURPLE)


def test_r_pe_def_100_1_a_refused_preview_is_red_with_its_cross(defc):
    """R-PE-DEF.100/1 - DISPLAY_0001 ``250``: New ``250``, Δ ``✗ refused``, bold #fd8383."""
    line, _, _ = paint(defc, display(defc), text="250")
    shown_new, shown_delta = _new_delta_cells(line)
    assert (shown_new, shown_delta) == ("250", "✗ refused")
    _assert_style_over(line, START["New"], shown_new, RED)
    _assert_style_over(line, START["Δ"], shown_delta, RED)


def _verdict_lines(case):
    """Every painted line of the DEFC page the verdict rule covers, each with its formula tail."""
    d = case["defs"]["DISPLAY_0001"]
    out = []
    staged_line, staged_row, _ = _staged_line(case, "DISPLAY_0001", "25.5")
    out += [staged_line, ds.formula_tail(staged_row, None, 118)]
    for text in ("25.5", "175", "250"):
        line, row, pv = paint(case, d, text=text)
        out += [line, ds.formula_tail(row, pv, 118)]
    return out


def _glyph_in_hue(text: Text, glyphs: str, hue: str) -> bool:
    """A line rides its state hue only when the glyph itself is painted in it (E5, X8b: the track's own ``●`` at
    the current value is in the text style, so ``"●" in plain`` held on a staged line whose mark was cleared)."""
    return any(char in glyphs and fg(text, cell_len(text.plain[:i])) == hue for i, char in enumerate(text.plain))


def test_r_pe_def_101_1_green_only_beside_a_dot_or_a_check(defc):
    """R-PE-DEF.101/1 - a #54efae span lies on a line holding ``●`` or ``✓``."""
    seen = False
    for text in _verdict_lines(defc):
        if GREEN in all_fg_hues(text):
            seen = True
            assert _glyph_in_hue(text, "●✓", GREEN), text.plain
    assert seen, "no GREEN anywhere: the staged row and the passed check must be green"


def test_r_pe_def_101_2_yellow_only_beside_a_notice_triangle(defc):
    """R-PE-DEF.101/2 - a #f6ff8f span lies on a line holding ``▲``."""
    for text in _verdict_lines(defc):
        if YELLOW in all_fg_hues(text):
            assert _glyph_in_hue(text, "▲", YELLOW), text.plain
    _, row, pv = paint(defc, display(defc), text="175")
    tail = ds.formula_tail(row, pv, 118)
    assert "▲" in tail.plain and YELLOW in all_fg_hues(tail), "the notice itself is YELLOW with its ▲"


def test_r_pe_def_101_3_red_only_beside_a_cross(defc):
    """R-PE-DEF.101/3 - a #fd8383 span lies on a line holding ``✗``."""
    for text in _verdict_lines(defc):
        if RED in all_fg_hues(text):
            assert _glyph_in_hue(text, "✗", RED), text.plain
    _, row, pv = paint(defc, display(defc), text="250")
    tail = ds.formula_tail(row, pv, 118)
    assert "✗" in tail.plain and RED in all_fg_hues(tail)


def test_r_pe_def_101_4_no_span_uses_riches_own_state_colours(defc):
    """R-PE-DEF.101/4 - no span is rich ``green``, ``yellow`` or ``red`` (their hex hues replace them)."""
    for text in _verdict_lines(defc):
        assert rich_named(text) == set(), text.plain


# ==================================================================================================
# R-PE-DEF.103 - the colour-free cues (1 case)
# ==================================================================================================


def test_r_pe_def_103_1_every_cue_survives_without_colour(defc):
    """R-PE-DEF.103/1 (partial: the row model; ``■`` and underlines are the card's, S2 / AT) - with ``NO_COLOR``
    the staged, pending and refused rows still carry ``●``, ``◆``, ``▶`` and ``✗ refused`` and keep bold.

    Operator need: the meaning must survive a terminal that paints no colour. Plain text is equal with and
    without colour; the glyphs are in it; the selected name is still bold in the no-colour render."""
    lines = [
        _staged_line(defc, "DISPLAY_0001", "25.5")[0],
        paint(defc, display(defc), text="25.5")[0],
        paint(defc, display(defc), text="250", selected=True)[0],
    ]
    plain = "\n".join(line.plain for line in lines)
    for cue in ("●", "◆", "▶", "✗ refused"):
        assert cue in plain, cue
    shown = {}
    for label, no_color in (("colour", False), ("mono", True)):
        sink = io.StringIO()
        console = Console(file=sink, color_system="truecolor", force_terminal=True, width=400, no_color=no_color)
        for line in lines:
            console.print(line, end="\n")
        shown[label] = sink.getvalue()
    strip_ansi = re.compile(r"\x1b\[[0-9;]*m")
    assert strip_ansi.sub("", shown["mono"]) == strip_ansi.sub("", shown["colour"])
    assert "38;2;" in shown["colour"], "the colour render does paint colour (the control is live)"
    assert "38;2;" not in shown["mono"] and "48;2;" not in shown["mono"], "no colour escape under NO_COLOR"
    assert "\x1b[1m" in shown["mono"], "bold survives NO_COLOR (the selected name)"
    mono_lines = strip_ansi.sub("", shown["mono"]).split("\n")
    assert [line[1] for line in mono_lines[:3]] == ["●", "◆", "◆"], (
        "E5 (X8b): the mark column itself carries the glyph; the track's own ● and ◆ do not stand for it",
        [line[:3] for line in mono_lines[:3]],
    )


_SGR = re.compile(r"\x1b\[([0-9;]*)m")


def _mono_cues(rendered: str) -> tuple[str, set]:
    """(plain text, {(line, char index)} of the underlined characters) of a Rich render, read from its SGR codes."""
    plain, cells, under, line, column, at = [], set(), False, 0, 0, 0
    for match in list(_SGR.finditer(rendered)) + [None]:
        for char in rendered[at:match.start() if match else len(rendered)]:
            if char == "\n":
                line, column = line + 1, 0
            else:
                if under:
                    cells.add((line, column))
                column += 1
            plain.append(char)
        if match is None:
            break
        at = match.end()
        codes = match.group(1).split(";") if match.group(1) else ["0"]
        skip = 0
        for index, code in enumerate(codes):
            if skip:
                skip -= 1
            elif code in ("38", "48"):
                skip = 4 if codes[index + 1:index + 2] == ["2"] else 2
            elif code in ("0", "24"):
                under = False
            elif code == "4":
                under = True
    return "".join(plain), cells


def test_r_pe_def_103_1_the_card_cues_survive_without_colour(defc):
    """R-PE-DEF.103/1 (the card half; E5, X8b - the integrator's open item) - MASK_FIELD_0001 expanded with New 255
    (current 174): painted with ``NO_COLOR`` and with colour, the bit card shows the same text with ``■`` on the mask
    row and the same underlined cells (the after bits that differ), and only the colour render paints colour.

    Operator need: on a terminal with no colour, the mask bits and the bits the edit changes must still be told
    apart; a cue drawn as colour only (``■`` replaced by a coloured space, an underline replaced by a hue) is lost."""
    definition = defc["defs"]["MASK_FIELD_0001"]
    row, overlay = make_row(definition, defc["a2l"], defc["image"])
    pv = ds.preview(definition, defc["a2l"], "255", overlay)
    lines = ds.detail_lines(row, pv, 111, None, 50)
    raw = {}
    for label, no_color in (("colour", False), ("mono", True)):
        sink = io.StringIO()
        console = Console(file=sink, color_system="truecolor", force_terminal=True, width=400, no_color=no_color)
        for line in lines:
            console.print(line, end="\n")
        raw[label] = sink.getvalue()
    assert "38;2;" in raw["colour"] and "38;2;" not in raw["mono"], "the control is live: colour in one render only"
    (mono_text, mono_under), (colour_text, colour_under) = _mono_cues(raw["mono"]), _mono_cues(raw["colour"])
    assert mono_text == colour_text
    assert "■" in mono_text, "the mask row's ■ is a glyph, not a colour"
    assert mono_under, "the changed after bits are underlined (a cue that is not a colour)"
    assert mono_under == colour_under


# ==================================================================================================
# R-PE-DEF.21 / .76 / .104 / .105 / .106 / .114 - the Limits cell (alignment, slots, hostile numbers)
# ==================================================================================================


def _the_cell(case, key):
    """The Limits cell of the transcript key ``L.cell.<key>``, built from its DEFC row and numbers."""
    spec = {
        "DISPLAY_0001.cur143.5.new25.5": ("DISPLAY_0001", {}, 25.5),
        "DISPLAY_0001.cur143.5": ("DISPLAY_0001", {}, None),
        "DISPLAY_0001.new175": ("DISPLAY_0001", {}, 175),
        "DISPLAY_0001.new-45": ("DISPLAY_0001", {}, -45),
        "MASK_FIELD_0001.cur174.new255": ("MASK_FIELD_0001", {}, 255),
        "MASK_BIT_0001.cur1.new0": ("MASK_BIT_0001", {}, 0),
        "ENUM_0001.cur1": ("ENUM_0001", {}, None),
        "limits_5_5": ("DISPLAY_0001", {"lower": 5.0, "upper": 5.0}, None),
        "limits_9_1": ("DISPLAY_0001", {"lower": 9.0, "upper": 1.0}, None),
        "lower_-inf": ("DISPLAY_0001", {"lower": -math.inf, "upper": 150.0}, None),
        "upper_nan": ("DISPLAY_0001", {"lower": 0.0, "upper": math.nan}, None),
        "huge": ("DISPLAY_0001", {"lower": -1.7e308, "upper": 4.29e12, "current": 0}, None),
        "neg_big": ("DISPLAY_0001", {"lower": -655350.0, "upper": -1000.0, "current": None}, None),
        "no_limits": ("DISPLAY_0001", {"lower": None, "upper": None}, None),
        "span_overflow": ("DISPLAY_0001", {"lower": -1.7e308, "upper": 1.7e308, "current": 1e308}, None),
        "span_overflow.lower_end": ("DISPLAY_0001", {"lower": -1.7e308, "upper": 1.7e308, "current": -1.7e308}, None),
        "DISPLAY_0001.new_inf": ("DISPLAY_0001", {}, math.inf),
        "DISPLAY_0001.cur150.new149.9": ("DISPLAY_0001", {"current": 150}, 149.9),
    }[key]
    name, over, value = spec
    return limits_of(case, name, value=value, **over)


@pytest.mark.parametrize(
    "key",
    ["DISPLAY_0001.cur143.5.new25.5", "MASK_FIELD_0001.cur174.new255", "ENUM_0001.cur1",
     "DISPLAY_0001.new175", "DISPLAY_0001.new-45"],
)
def test_r_pe_def_21_the_limits_cell_is_the_aligned_cell_of_the_transcript(defc, key):
    """R-PE-DEF.21/1 .. /5 - the five Limits cells: ``<slot> <track> <slot>`` in 34 cells, marks on the ruler rule.

    Operator need: the mark of the current value sits where the value is between the limits, and the cell is
    always the same 34 cells (D's aligned Limits column)."""
    cell = _the_cell(defc, key)
    assert cell.plain == TR[f"L.cell.{key}"]
    assert cell_len(cell.plain) == TR[f"L.cell.{key}.len"] == LIMITS_W
    assert offsets_of(cell.plain) == TR[f"L.cell.{key}.offsets"]


def test_r_pe_def_21_1_the_cell_in_its_row_sits_at_the_limits_column(defc):
    """R-PE-DEF.21/1 (in the row) - DISPLAY_0001 pending 25.5: columns 87 .. 120 of the row line are the transcript cell."""
    line, _, _ = paint(defc, display(defc), text="25.5")
    key = "DISPLAY_0001.cur143.5.new25.5"
    assert cell_slice(line.plain, START["Limits"], LIMITS_W) == TR[f"L.cell.{key}"]


@pytest.mark.parametrize("name", ["DISPLAY_0001", "MASK_FIELD_0001", "MASK_BIT_0001", "ENUM_0001"])
def test_r_pe_def_104_1_the_track_ends_stand_at_8_and_25_on_every_scalar_kind(defc, name):
    """R-PE-DEF.104/1 - ``├`` at 8 and ``┤`` at 25 on DISPLAY, MASK_FIELD, MASK_BIT and ENUM rows."""
    plain = limits_of(defc, name).plain
    assert plain.index("├") == TR["L.offset.track_start"]
    assert plain.index("┤") == TR["L.offset.track_end"]
    assert cell_len(plain) == LIMITS_W


@pytest.mark.parametrize("key", ["neg_big", "huge"])
def test_r_pe_def_104_2_the_track_ends_stand_at_8_and_25_on_extreme_limits(defc, key):
    """R-PE-DEF.104/2 - ``├`` 8 and ``┤`` 25 when the limits are -655k .. -1.00k or -1.7e308 .. 4.29e12."""
    plain = _the_cell(defc, key).plain
    assert plain == TR[f"L.cell.{key}"]
    assert plain.index("├") == TR["L.offset.track_start"] and plain.index("┤") == TR["L.offset.track_end"]


@pytest.mark.parametrize("key", ["limits_5_5", "limits_9_1", "lower_-inf", "upper_nan"])
def test_r_pe_def_104_3_the_range_mark_stands_at_16_when_the_limits_have_no_track(defc, key):
    """R-PE-DEF.104/3 - ``…`` at 16 on limits 5 5, 9 1, lower -inf, upper nan (the range form)."""
    plain = _the_cell(defc, key).plain
    assert plain.index("…") == TR["L.offset.range_mark"] and cell_len(plain) == LIMITS_W
    assert "├" not in plain and "┤" not in plain


@pytest.mark.parametrize("name", ["CURVE_DEF_0001", "MAP_DEF_0001", "VAL_BLK_DEF_0001"])
def test_r_pe_def_104_4_bench_rows_show_the_range_form_at_the_same_offsets(defc, name):
    """R-PE-DEF.104/4 - ``…`` at 16 on the three bench rows (``L.bench.*``), through ``bench_cells``."""
    o = defc_obj(defc, name)
    row = sheet_row(o.d, o.a2l, o.image)
    cell = db.bench_cells(row, view_state(o), ds.sheet_widths(111))[LIMITS].plain
    assert cell == TR[f"L.bench.{name}"]
    assert offsets_of(cell) == TR[f"L.bench.{name}.offsets"]


def test_r_pe_def_104_5_the_no_limits_dash_stands_at_16_on_text_and_refused_rows(defc, v171):
    """R-PE-DEF.104/5 - ``-`` at 16 on V171 ASCII (a text row) and on a refused row."""
    row, _ = make_row(v171["def"], v171["a2l"], v171["image"])
    refused = describe_definition("NO_SUCH_PARAMETER_0001", defc["a2l"])
    refused_row, _ = make_row(refused, defc["a2l"], defc["image"])
    for shown in (row, refused_row):
        plain = ds.limits_cell(shown, None, LIMITS_W).plain
        assert plain == TR["L.cell.no_limits"] and plain.index("-") == TR["L.offset.range_mark"]
        assert cell_len(plain) == LIMITS_W


@pytest.mark.parametrize(
    ("lower", "upper", "lower_unit", "upper_unit"),
    [(-1000.0, 1000.0, "k", "k"), (0.0, 65535.0, None, "k"), (-655350.0, -1000.0, "k", "k")],
)
def test_r_pe_def_104_6_the_unit_letter_is_the_last_cell_of_its_slot(defc, lower, upper, lower_unit, upper_unit):
    """R-PE-DEF.104/6 - ``  65.5k``, `` -1.00k``, ``  -655k``: the unit letter at offset 6 (lower) or 33 (upper)."""
    plain = limits_of(defc, "DISPLAY_0001", lower=lower, upper=upper, current=None).plain
    if lower_unit:
        assert plain[TR["L.offset.lower_unit_cell"]] == lower_unit
    else:
        assert plain[TR["L.offset.lower_unit_cell"]] == " "
    assert plain[TR["L.offset.upper_unit_cell"]] == upper_unit
    assert plain[:7] == EX8.slot(lower) and plain[-7:] == EX8.slot(upper)


def test_r_pe_def_104_7_a_second_mark_on_cell_16_moves_left_and_never_onto_the_end(defc):
    """R-PE-DEF.104/7 - current 150 and a value of 149.9 both on cell 16: ``◆`` 23, ``●`` 24, ``┤`` 25 (E3-8b-07).

    Operator need: the track's right end must stay visible; no mark may cover ``┤``."""
    key = "DISPLAY_0001.cur150.new149.9"
    plain = _the_cell(defc, key).plain
    assert plain == TR[f"L.cell.{key}"]
    assert marks_of(plain) == TR[f"L.cell.{key}.marks"] == {"●": 24, "◆": 23}
    assert plain[TR["L.offset.track_end"]] == "┤"


@pytest.mark.parametrize(
    "x", [4.29e12, 999.6e9, -1.7e308, 999.4e9],
)
def test_r_pe_def_105_a_wide_limit_is_written_in_its_exponent_form(defc, x):
    """R-PE-DEF.105/1 .. /4 - 4.29e12 -> ``  4e12 ``; 999.6e9 -> ``  1e12 ``; -1.7e308 -> ``-2e308 ``; 999.4e9 -> ``   999G``."""
    expected = TR[f"L.slot.{x!r}"]
    if x < 0:
        cell = limits_of(defc, "DISPLAY_0001", lower=x, upper=0.0, current=None).plain
        assert cell[:7] == expected
    else:
        cell = limits_of(defc, "DISPLAY_0001", lower=0.0, upper=x, current=None).plain
        assert cell[-7:] == expected
    assert cell_len(cell) == LIMITS_W and cell.index("├") == TR["L.offset.track_start"]


def test_r_pe_def_106_1_a_lower_limit_that_is_not_finite_gives_the_range_form(defc):
    """R-PE-DEF.106/1 - a Definition built directly with lower -inf -> ``L.cell.lower_-inf``, no exception (E3-8b-09)."""
    d = display(defc, limits=Limits(-math.inf, 150.0, "", ""))
    row, _ = make_row(d, defc["a2l"], defc["image"])
    assert ds.limits_cell(row, None, LIMITS_W).plain == TR["L.cell.lower_-inf"]


def test_r_pe_def_106_2_an_upper_limit_that_is_not_finite_gives_the_range_form(defc):
    """R-PE-DEF.106/2 - a Definition built directly with upper nan (lower 0, as the transcript) -> ``L.cell.upper_nan``."""
    d = display(defc, limits=Limits(0.0, math.nan, "", ""))
    row, _ = make_row(d, defc["a2l"], defc["image"])
    assert ds.limits_cell(row, 25.5, LIMITS_W).plain == TR["L.cell.upper_nan"]


def _float32_erased_row(case):
    d = display(case, datatype="FLOAT32_IEEE", byte_length=4)
    image = dict(case["image"])
    for index in range(4):
        image[d.address + index] = 0xFF
    row, _ = make_row(d, case["a2l"], image)
    return row


def test_r_pe_def_114_1_an_erased_float_current_gives_the_no_position_form(defc):
    """R-PE-DEF.114/1 - a FLOAT32 row whose image is ``FF FF FF FF`` (current NaN) -> ``L.cell.float32_erased``.

    Operator need: erased flash must not crash the paint; the cell says "unknown position" with ``?``."""
    row = _float32_erased_row(defc)
    assert isinstance(row.current, Decoded) and math.isnan(row.current.value), "the fixture reads NaN"
    cell = ds.limits_cell(row, None, LIMITS_W).plain
    assert cell == TR["L.cell.float32_erased"]
    assert marks_of(cell) == TR["L.cell.float32_erased.marks"] == {"?": 16}
    assert "●" not in cell


@pytest.mark.parametrize(("key", "mark"), [("span_overflow", 21), ("span_overflow.lower_end", 9)])
def test_r_pe_def_117_1_3_a_span_wider_than_the_float_range_places_the_mark_by_its_proportion(defc, key, mark):
    """R-PE-DEF.117/1, /3 (E4 ruling; was .114/2) - limits -1.7e308 .. 1.7e308: current 1e308 -> ``●`` at 21 (its
    proportion 0.79 of the span), current -1.7e308 -> ``●`` at 9 (cell 1); ``┤`` at 25, no ``?``.

    Operator need: a hostile A2L with the widest float limits still shows where the value stands. The direct
    (v - lower)/(upper - lower) overflows the span to inf: the position would be 0 (cell 1) or not finite (``?``)."""
    cell = _the_cell(defc, key).plain
    assert cell == TR[f"L.cell.{key}"]
    assert marks_of(cell) == TR[f"L.cell.{key}.marks"] == {"●": mark}
    assert cell[TR["L.offset.track_end"]] == "┤"


def test_r_pe_def_117_2_an_enum_bound_beyond_the_float_range_gives_the_range_form(defc):
    """R-PE-DEF.117/2 (E4 ruling) - ENUM_0001 with its last entry's raw 2**1100 -> ``L.cell.enum_beyond_float``
    (`inf` in the upper slot, ``…`` at 16) and its row line paints, no OverflowError from ``isfinite``."""
    d = defc["defs"]["ENUM_0001"]
    entries = list(d.enum_entries)
    entries[-1] = replace(entries[-1], raw=2**1100)
    row, _ = make_row(replace(d, enum_entries=tuple(entries)), defc["a2l"], defc["image"])
    cell = ds.limits_cell(row, None, LIMITS_W).plain
    assert cell == TR["L.cell.enum_beyond_float"]
    assert offsets_of(cell) == TR["L.cell.enum_beyond_float.offsets"]
    line = ds.row_line(row, ds.sheet_widths(111), True, None, None)
    assert cell_slice(line.plain, START["Limits"], LIMITS_W) == cell


@pytest.mark.parametrize(("current", "mark"), [(0.0, 9), (5e-324, 24)])
def test_r_pe_def_117_4_a_span_whose_halves_vanish_places_the_mark_by_its_proportion(defc, current, mark):
    """R-PE-DEF.117/4 (E5, X8b finding) - limits 0 .. 5e-324 (the smallest subnormal span: its halves are both 0):
    current 0 -> ``●`` at 9, current 5e-324 -> ``●`` at 24; no ``?``, no exception.

    Operator need: a hostile A2L limit pair must never stop the paint. Computing the position on halves only
    divides by 0 here (``ZeroDivisionError`` in the paint path); the span itself is finite and nonzero."""
    cell = limits_of(defc, "DISPLAY_0001", lower=0.0, upper=5e-324, current=current).plain
    assert marks_of(cell) == {"●": mark}, cell
    assert "?" not in cell and cell[TR["L.offset.track_end"]] == "┤", cell


def test_r_pe_def_114_3_a_new_value_of_plus_infinity_gives_the_no_position_form_not_a_right_arrow(defc):
    """R-PE-DEF.114/3 - current 143.5, new +inf -> ``L.cell.DISPLAY_0001.new_inf`` (``?`` at 16, no ``▶``)."""
    cell = _the_cell(defc, "DISPLAY_0001.new_inf").plain
    assert cell == TR["L.cell.DISPLAY_0001.new_inf"]
    assert "▶" not in cell and marks_of(cell) == {"?": 16}


@pytest.mark.parametrize("key", ["limits_5_5", "limits_9_1"])
def test_r_pe_def_76_limits_not_ascending_give_the_range_form_without_a_division(defc, key):
    """R-PE-DEF.76/1, /2 - limits ``5 5`` and ``9 1`` -> ``L.cell.limits_5_5`` / ``_9_1``, no ZeroDivisionError,
    also when a preview value is asked."""
    row, _ = make_row(
        display(defc, limits=Limits(*{"limits_5_5": (5.0, 5.0), "limits_9_1": (9.0, 1.0)}[key], "", "")),
        defc["a2l"], defc["image"],
    )
    for value in (None, 25.5):
        assert ds.limits_cell(row, value, LIMITS_W).plain == TR[f"L.cell.{key}"]


# ==================================================================================================
# R-PE-BENCH.11 / .17 / .107 / .108 - the bench row's Current strip and Limits (F-R14-1)
# ==================================================================================================

BENCH = ("CURVE_DEF_0001", "MAP_DEF_0001", "VAL_BLK_DEF_0001")


def _bench_state(case, name):
    o = defc_obj(case, name)
    strip = db.summary_strip(o.values, o.grid, TR[f"S.strip_width.{name}"])
    return o, view_state(o, strip=strip)


@pytest.mark.parametrize("name", BENCH)
def test_r_pe_bench_11_the_current_cell_is_the_strip_and_its_count(defc, name):
    """R-PE-BENCH.11/1 .. /3 - CURVE ``▄▆▃▇▁ 5``, MAP ``▆▃▅▃ 12``, VAL_BLK ``▄▃▄ 6`` (``S.after.current.*``) at Current 20."""
    o, state = _bench_state(defc, name)
    row = sheet_row(o.d, o.a2l, o.image)
    cell = db.bench_cells(row, state, ds.sheet_widths(111))[CURRENT].plain
    assert cell.rstrip() == TR[f"S.after.current.{name}"]
    line = ds.row_line(row, ds.sheet_widths(111), False, None, None, state=state)
    assert cell_slice(line.plain, START["Current"], WIDTH["Current"]).rstrip() == TR[f"S.after.current.{name}"]


@pytest.mark.parametrize("name", BENCH)
def test_r_pe_bench_107_1_the_defc_strips_use_no_full_block(defc, name):
    """R-PE-BENCH.107/1 - the three DEFC strips hold only ``▁ .. ▇`` and spaces: no ``█`` (F-R14-1).

    Operator need: a full block fills its cell to the row above and below, so two strips join into one
    shape (the defect seen at 118x54); one eighth of headroom keeps rows apart."""
    o, state = _bench_state(defc, name)
    row = sheet_row(o.d, o.a2l, o.image)
    strip = db.bench_cells(row, state, ds.sheet_widths(111))[CURRENT].plain.rstrip().rsplit(" ", 1)[0]
    assert "█" not in strip and set(strip) <= set(EX8.BLOCKS7) | {" "}, strip
    assert strip.strip(), "a strip with no block is not a strip"


def test_r_pe_bench_107_2_forty_points_in_seventeen_cells_end_at_the_seventh_level(defc):
    """R-PE-BENCH.107/2 - a ramp of 40 points in 17 cells -> ``S.wide.40_points_in_17``; the top level is ``▇``."""
    o = defc_obj(defc, "CURVE_DEF_0001")
    grid = db.bench_grid(replace(o.d, shape=(40,), element_count=40))
    values = db.BenchValues.from_decoded(decoded_of(*[(float(i), str(i)) for i in range(40)]))
    strip = db.summary_strip(values, grid, 17).plain.rstrip()
    assert strip == TR["S.wide.40_points_in_17"] and strip[-1] == "▇" and "█" not in strip


@pytest.mark.parametrize("name", BENCH)
def test_r_pe_bench_108_1_the_strip_is_dim_with_no_ground(defc, name):
    """R-PE-BENCH.108/1 - the three strips: colour #969aad and no background."""
    o, state = _bench_state(defc, name)
    row = sheet_row(o.d, o.a2l, o.image)
    cell = db.bench_cells(row, state, ds.sheet_widths(111))[CURRENT]
    strip = cell.plain.rstrip().rsplit(" ", 1)[0]
    painted = [index for index, char in enumerate(strip) if char != " "]
    assert painted, "the strip has blocks to read"
    for index in painted:
        assert fg(cell, index) == DGRAY and bg(cell, index) is None, (name, index)


@pytest.mark.parametrize("name", BENCH)
@pytest.mark.parametrize(("selected", "odd", "ground"), [(True, None, SELECTED_GROUND), (False, True, ODD_GROUND)])
def test_r_pe_bench_108_2_the_row_ground_shows_through_the_strip(defc, name, selected, odd, ground):
    """R-PE-BENCH.108/2 - on the selected row and on a zebra row the strip cells show the row's ground.

    The zebra case passes ``odd``, which the base ``row_line`` does not have (RED = absent keyword)."""
    o, state = _bench_state(defc, name)
    row = sheet_row(o.d, o.a2l, o.image)
    extra = {} if odd is None else {"odd": odd}
    line = ds.row_line(row, ds.sheet_widths(111), selected, None, None, state=state, **extra)
    current = cell_slice(line.plain, START["Current"], WIDTH["Current"])
    blocks = [offset for offset, char in enumerate(current) if char in EX8.BLOCKS7]
    assert len(blocks) == len(TR[f"S.after.current.{name}"].rsplit(" ", 1)[0].strip()), (
        "every strip block is found in the Current column (no vacuous pass)", current)
    for offset in blocks:
        assert bg(line, START["Current"] + offset) == ground, (name, offset)
        assert fg(line, START["Current"] + offset) == DGRAY


@pytest.mark.parametrize(("name", "lower_text"), [("CURVE_DEF_0001", None), ("MAP_DEF_0001", None)])
def test_r_pe_bench_17_1_2_the_bench_limits_are_the_range_form(defc, name, lower_text):
    """R-PE-BENCH.17/1, /2 - CURVE_DEF_0001 and MAP_DEF_0001 -> ``L.bench.*`` (``…`` at 16), in the row at column 87."""
    o = defc_obj(defc, name)
    row = sheet_row(o.d, o.a2l, o.image)
    line = ds.row_line(row, ds.sheet_widths(111), False, None, None, state=view_state(o))
    assert cell_slice(line.plain, START["Limits"], LIMITS_W) == TR[f"L.bench.{name}"]


def test_r_pe_bench_17_3_an_array_without_limits_shows_the_dash_at_16(defc):
    """R-PE-BENCH.17/3 - an array with no limits -> ``-`` at offset 16 of the 34-cell Limits cell."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    none = replace(o.d, limits=Limits(None, None, "", ""))
    row = sheet_row(none, o.a2l, o.image)
    cell = db.bench_cells(row, view_state(o), ds.sheet_widths(111))[LIMITS].plain
    assert cell == TR["L.cell.no_limits"] and cell.index("-") == TR["L.offset.range_mark"]
