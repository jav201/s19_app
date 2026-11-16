"""Batch-103 Inc 8 E4, group S1 - the pure sheet model, part 1 (columns, rows, limits, window).

Design under test: ``.dev-flow/2026-11-05-batch-103/inc-8/01-requirements.md``
(rows R-PE-DEF.5 ... .7, .15 ... .28, .36, .37, .70 ... .72, .75 ... .77, .81, .88)
as retargeted at Inc 8b (T8b-R: ``inc-8b/01-requirements.md`` rows R-PE-DEF.5, .21, .76, .81, .89 ... .96; R-PE-DEF.6 and
.7 are retired and re-aimed at their replacements, ``inc-8b/E1-rulings.md`` section 2) through ``s19_app/tui/definition_sheet.py`` (new): I-8.1 (``StagedOverlay``) and
I-8.5 (``KindOps``, ``ops_for``), nodes S1 ... S12, S3', S4', S7'/S8', S9', S20.
One test per case of ``inc-8/02-test-cases-S1.md``; names start
``test_r_pe_def_<row>_`` so ``trace_check`` binds them.

Expected values are the requirement's texts or come from the committed examples
file (``evidence-e2/examples_inc8.py``, loaded by ``tests/support/b103_inc8_s1.py``)
or from I-2 itself; no width, position or length is counted by hand: a cell is
read back by the column widths of the model's own ``sheet_widths`` (R-PE-DEF.89, with the gutter
after each column skipped by ``cells``) and a position is searched in the painted text. Inc 8b's
expected cells come from ``evidence-e1/examples_inc8b.py`` and its transcript, loaded by
``tests/support/b103_inc8b_r.py`` (``EXB``, ``fact``).

Pure tests: no textual app. The module is imported as ``ds`` so a missing name
fails only the tests that use it.
"""

from __future__ import annotations

import pytest
from rich.cells import cell_len

from s19_app.tui import definition_sheet as ds
from s19_app.tui.a2l_definition import Limits, Refusal, describe_definition
from tests.support.b103_inc8_s1 import (  # noqa: F401  (fixtures are used by name)
    EX,
    FFFD,
    SpanImage,
    cells,
    defc,
    hex_bytes,
    replace,
    span_bytes,
    stage_entry,
    v171,
    widen,
)
from tests.support.b103_inc8b_r import COLUMNS, EXB, GRID_WIDTH, GUTTER_AT, fact

W118 = 118
V171_NAME = "ASAM.C.ASCII.UBYTE.NUMBER_42"


def make_row(definition, a2l, image, entries=()):
    overlay = ds.StagedOverlay(image, list(entries))
    return ds.build_row(definition, a2l, image, overlay), overlay


def paint(definition, a2l, image, entries=(), *, width=W118, selected=False, pending="", text=None):
    """Build the row, optionally a preview of ``text``, and return (cells, widths, row, preview)."""
    row, overlay = make_row(definition, a2l, image, entries)
    widths = ds.sheet_widths(width)
    pv = ds.preview(definition, a2l, text, overlay) if text is not None else None
    line = ds.row_line(row, widths, selected, pending if text is None else text, pv)
    return cells(line, widths), widths, row, pv


# ==========================================================================
# R-PE-DEF.6 (retired -> R-PE-DEF.89) / .5 - the columns and the header (S1, S9)
# ==========================================================================

_COLUMN_KEYS = {"Parameter": "name", "Kind": "kind", "Current": "current", "New": "new", "Unit": "unit",
                "Limits": "limits", "Δ": "delta"}


@pytest.mark.parametrize("w", [73, 80, 96, 99, 100, 111, 118, 159, 160, 195, 200, 220])
def test_r_pe_def_6_widths_follow_the_examples_of_every_class(w):
    """R-PE-DEF.6 (retired at Inc 8b E1, replaced by R-PE-DEF.89; E1-rulings section 2) - the columns do not depend on the view.

    Why: the operator chose the grid (variant D): fixed natural widths at every view width, with the
    sheet scrolling sideways instead of hiding Kind and Unit. The width classes of Inc 8 (96 -> Kind and
    Unit hidden, 200 -> Limits capped at 64) must be gone: the widths are the oracle's, whatever W is.
    """
    expect = {"mark": EXB.MARK, **{_COLUMN_KEYS[label]: width for label, width in EXB.COLUMNS}}
    assert ds.sheet_widths(w)._asdict() == expect
    assert sum(expect.values()) + len(EXB.COLUMNS) == GRID_WIDTH == fact("G.grid_width")


@pytest.mark.parametrize("w", [73, 111, 195])
def test_r_pe_def_5_header_labels_start_where_the_widths_put_them(w):
    """R-PE-DEF.5/1..3 (changed at Inc 8b E1) - the header line is the oracle's `G.header_line` at V = 73, 111, 195.

    Why: the labels sit at the fixed column starts with a `│` after each column; Kind and Unit are shown at
    every width (Inc 8 hid them below W 100).
    """
    line = ds.header_line(ds.sheet_widths(w)).plain
    assert line == fact("G.header_line") == EXB.header_line()
    for label, start, width in COLUMNS:
        assert line[start:start + len(label)] == label, (label, start, line)
        assert line[start + width] == "│"
    assert [i for i, ch in enumerate(line) if ch == "│"] == list(GUTTER_AT)
    assert list(GUTTER_AT) == [fact(f"G.gutter_after.{label}") for label, _, _ in COLUMNS]
    assert line[:EXB.MARK].strip() == ""


# ==========================================================================
# R-PE-DEF.21 - the short number (S7)
# ==========================================================================


@pytest.mark.parametrize("x", [-40, 150, 0, 255, 655350, 4294967295, 65.349, -50, 200])
def test_r_pe_def_21_short_number_matches_the_examples(x):
    """R-PE-DEF.21 (short number of CTX-PE-DEF) - the rule of the examples file."""
    assert ds.short_number(x) == EX.short(x)


def test_r_pe_def_21_short_number_requirement_anchors():
    """The two spellings the CTX-PE-DEF rule states in words."""
    assert ds.short_number(655350) == "655k"
    assert ds.short_number(4294967295) == "4.29G"


@pytest.mark.parametrize(
    ("x", "text"),
    [
        (1000, "1.00k"),
        (-1000, "-1.00k"),
        (1500, "1.50k"),
        (65535, "65.5k"),
        (655350, "655k"),
        (-655350, "-655k"),
        (1000000, "1.00M"),
        (-1000000, "-1.00M"),
        (4294967295, "4.29G"),
        (1000000000, "1.00G"),
    ],
)
def test_r_pe_def_21_short_number_keeps_three_significant_digits(x, text):
    """R-PE-DEF.21 (F-1): from 1000 up the short number keeps 3 significant digits, trailing zeros included."""
    assert ds.short_number(x) == text


@pytest.mark.parametrize(
    ("x", "text"),
    [(999500, "1.00M"), (-999500, "-1.00M"), (999999, "1.00M"), (999999999, "1.00G")],
)
def test_r_pe_def_21_short_number_rounding_carries_into_the_next_unit(x, text):
    """R-PE-DEF.21 (F-1): a mantissa that rounds to 1000 is written in the next unit, never as 1.00e+03k or 1000k."""
    assert ds.short_number(x) == text


@pytest.mark.parametrize(
    ("x", "text"),
    [(0, "0"), (0.04, "0"), (-0.04, "0"), (0.5, "0.5"), (999.5, "999.5"), (-999, "-999")],
)
def test_r_pe_def_21_short_number_below_1000_stays_one_decimal(x, text):
    """R-PE-DEF.21: |x| < 1000 is rounded to one decimal with a trailing .0 dropped (the F-1 fix leaves it untouched)."""
    assert ds.short_number(x) == text


def test_r_pe_def_21_short_number_past_the_last_unit_uses_an_exponent():
    """R-PE-DEF.21: beyond 999G no unit is left; the 3-digit mantissa takes an exponent."""
    assert ds.short_number(1.5e12) == "1.50e+03G"


# ==========================================================================
# I-8.1 - the staged overlay (S2)
# ==========================================================================


def test_i81_overlay_gives_the_last_document_order_entry_byte_else_the_image():
    """I-8.1 - __getitem__: the last entry byte at the address, else the image's; KeyError otherwise."""
    image = {0x10: 0xA0, 0x11: 0xA1, 0x12: 0xA2}
    overlay = ds.StagedOverlay(image, [(0x10, [1, 2]), (0x11, [9])])
    assert overlay[0x10] == 1
    assert overlay[0x11] == 9, "a later entry wins over an earlier one"
    assert overlay[0x12] == 0xA2, "outside every entry the image's byte"
    with pytest.raises(KeyError):
        overlay[0x99]


def test_r_pe_def_18_overlay_without_image_holds_only_the_entry_bytes():
    """R-PE-DEF.18 / I-8.1 - image None: only the entries' bytes; no byte elsewhere."""
    overlay = ds.StagedOverlay(None, [(0x20, b"\x05\x06")])
    assert (overlay[0x20], overlay[0x21]) == (5, 6)
    with pytest.raises(KeyError):
        overlay[0x22]
    with pytest.raises(KeyError):
        ds.StagedOverlay(None, [])[0x800020]


def test_i81_overlay_iter_and_len_are_the_union_and_the_image_is_not_copied():
    """I-8.1 - __iter__/__len__ over the union; read-only view: an image change shows through."""
    image = {1: 0, 2: 0}
    overlay = ds.StagedOverlay(image, [(2, [5, 6])])
    assert set(overlay) == {1, 2, 3}
    assert len(overlay) == 3
    image[9] = 7
    assert overlay[9] == 7 and len(overlay) == 4, "the overlay never copies the image"


# ==========================================================================
# R-PE-DEF.16 / .36 / .37 - kinds, kind words and the per-kind operations (S3, S3')
# ==========================================================================


def test_r_pe_def_16_kind_word_is_the_char_type_or_measurement(defc, v171):
    """R-PE-DEF.16/1..3 - ENUM_0001 VALUE, V171 ASCII ASCII, a measurement MEASUREMENT."""
    assert ds.kind_word(defc["defs"]["ENUM_0001"]) == "VALUE"
    assert ds.kind_word(v171["def"]) == "ASCII"
    assert ds.kind_word(v171["measurement"]) == "MEASUREMENT"


def test_r_pe_def_16_kind_word_is_a_question_mark_when_the_definition_gives_neither(defc):
    """CTX kind word - `?` when the definition gives neither a char type nor a measurement."""
    bare = replace(defc["defs"]["DISPLAY_0001"], char_type=None)
    assert ds.kind_word(bare) == "?"


def test_r_pe_def_36_row_kind_names_the_four_kinds_and_passes_other_words(defc, v171):
    """S3 / R-PE-DEF.36 - number, bit mask, enum, text; any other kind is I-2's kind word."""
    d = defc["defs"]
    assert ds.row_kind(d["DISPLAY_0001"]) == "number"
    assert ds.row_kind(d["MASK_FIELD_0001"]) == "bit mask"
    assert ds.row_kind(d["MASK_BIT_0001"]) == "bit mask"
    assert ds.row_kind(d["ENUM_0001"]) == "enum"
    assert ds.row_kind(v171["def"]) == "text"
    assert ds.row_kind(d["CURVE_DEF_0001"]) == "curve"
    assert ds.row_kind(d["VAL_BLK_DEF_0001"]) == "array"
    assert ds.row_kind(replace(d["DISPLAY_0001"], kind="cuboid")) == "cuboid"


def test_r_pe_def_36_a_refused_definition_has_row_kind_none(defc):
    """R-PE-DEF.36/1 / R-PE-DEF.19 - a definition I-2 refused (unknown name) is `none`."""
    refused = describe_definition("NO_SUCH_PARAMETER_0001", defc["a2l"])
    assert refused.refusal is not None
    assert ds.row_kind(refused) == "none"


@pytest.mark.parametrize("kind, label", [("number", "new ="), ("enum", "new ="), ("bit mask", "field ="), ("text", "text =")])
def test_r_pe_def_37_formula_label_per_kind(kind, label):
    """R-PE-DEF.37/1..4 - new =, new =, field =, text =."""
    assert ds.ops_for(kind).label == label


def test_r_pe_def_37_labels_of_the_four_scalar_rows_through_their_definitions(defc, v171):
    """R-PE-DEF.37/1..4 - the label of the row's own kind: DISPLAY_0001, ENUM_0001, MASK_FIELD_0001, V171 ASCII."""
    d = defc["defs"]
    got = [ds.ops_for(ds.row_kind(x)).label for x in (d["DISPLAY_0001"], d["ENUM_0001"], d["MASK_FIELD_0001"], v171["def"])]
    assert got == ["new =", "new =", "field =", "text ="]


def test_r_pe_def_36_scalar_kinds_are_editable_and_the_text_span_bound_is_4096(defc, v171):
    """R-PE-DEF.36/3, /4 - editable up to 4,096 bytes, not at 4,097; number, bit mask, enum always."""
    d = defc["defs"]
    assert ds.ops_for("number").editable(d["DISPLAY_0001"]) is True
    assert ds.ops_for("bit mask").editable(d["MASK_FIELD_0001"]) is True
    assert ds.ops_for("enum").editable(d["ENUM_0001"]) is True
    text = ds.ops_for("text")
    assert text.editable(v171["def"]) is True
    assert text.editable(widen(v171["def"], 4096)) is True
    assert text.editable(widen(v171["def"], 4097)) is False


def test_r_pe_def_36_unknown_kinds_take_the_fallback_operations_with_no_editor(defc):
    """R-PE-DEF.36/1, /2 - cuboid, none: label empty, never editable; one shared fallback entry.

    `curve`, `map` and `array` are Inc 9's bench kinds: R-PE-BENCH.3 (Inc 9 C-9 moved the curve case there)
    registers them in the per-kind table, editable, once the patch editor is imported.
    """
    display = defc["defs"]["DISPLAY_0001"]
    for kind in ("cuboid", "none", "no such kind"):
        ops = ds.ops_for(kind)
        assert ops.label == ""
        assert ops.editable(display) is False
        assert ops is ds.ops_for("cuboid"), "every other kind shares the fallback"
    for kind in ("number", "bit mask", "enum", "text"):
        assert ds.ops_for(kind) is not ds.ops_for("cuboid")


# ==========================================================================
# R-PE-DEF.17 ... .20, .75, .88 - the Current column (S4', S5)
# ==========================================================================


def test_r_pe_def_17_current_value_texts_of_the_four_scalar_rows(defc, v171):
    """R-PE-DEF.17/1..4 - 143.5; `1 IDLE`; `174 (0xAE)`; `"Hello ASAM"`."""
    d, img, a2l = defc["defs"], defc["image"], defc["a2l"]
    got = {
        "number": paint(d["DISPLAY_0001"], a2l, img)[0]["current"].strip(),
        "enum": paint(d["ENUM_0001"], a2l, img)[0]["current"].strip(),
        "mask": paint(d["MASK_FIELD_0001"], a2l, img)[0]["current"].strip(),
        "text": paint(v171["def"], v171["a2l"], v171["image"])[0]["current"].strip(),
    }
    assert got == {
        "number": str(EX.cur),
        "enum": "1 IDLE",
        "mask": f"{EX.field} (0x{EX.field:02X})",
        "text": '"' + EX.before.rstrip(b"\0").decode("ascii") + '"',
    }


def test_r_pe_def_17_a_bit_mask_row_of_one_bit_shows_two_hex_digits(defc):
    """CTX value text - bit mask `<field> (0x<field>)` in upper-case hex with at least 2 digits (MASK_BIT_0001)."""
    cur = paint(defc["defs"]["MASK_BIT_0001"], defc["a2l"], defc["image"])[0]["current"].strip()
    assert cur == f"{EX.image_word & 1} (0x{EX.image_word & 1:02X})"


def test_r_pe_def_18_no_image_shows_dashes(defc):
    """R-PE-DEF.18/1 - no image: `--` in Current."""
    cur = paint(defc["defs"]["DISPLAY_0001"], defc["a2l"], None)[0]["current"].strip()
    assert cur == "--"


def test_r_pe_def_18_an_image_missing_the_second_byte_shows_dashes(defc):
    """R-PE-DEF.18/2 - an image missing DISPLAY_0001's second byte: `--`, not a zero-filled value."""
    display = defc["defs"]["DISPLAY_0001"]
    short = {a: b for a, b in defc["image"].items() if a != display.address + 1}
    assert display.address in short and display.address + 1 not in short
    assert paint(display, defc["a2l"], short)[0]["current"].strip() == "--"


def test_r_pe_def_19_a_refused_definition_shows_refused(defc):
    """R-PE-DEF.19/1 (partial: one real I-2 refusal, the unknown name) - `refused`, no exception."""
    refused = describe_definition("NO_SUCH_PARAMETER_0001", defc["a2l"])
    assert paint(refused, defc["a2l"], defc["image"])[0]["current"].strip() == "refused"


def test_r_pe_def_19_a_second_refusal_code_shows_refused_too(defc):
    """R-PE-DEF.19/2 (partial: the refusal is a stand-in copy carrying A2L-DEF-MASK) - `refused`."""
    standin = replace(defc["defs"]["MASK_FIELD_0001"], refusal=Refusal("A2L-DEF-MASK", "mask is not readable"))
    assert paint(standin, defc["a2l"], defc["image"])[0]["current"].strip() == "refused"


def test_r_pe_def_19_a_refused_definition_is_never_decoded_so_its_row_holds_no_value(defc):
    """R-PE-DEF.19 (negative control: decode a refused definition) - `refused` comes from the refusal, not from a decode.

    A row whose definition carries a refusal reads no bytes: current and staged hold nothing, the row is
    not staged, and the Current cell says `refused`. A decode of the refusal would leave a value in the row.
    """
    a2l, img = defc["a2l"], defc["image"]
    real = describe_definition("NO_SUCH_PARAMETER_0001", a2l)
    standin = replace(defc["defs"]["MASK_FIELD_0001"], refusal=Refusal("A2L-DEF-MASK", "mask is not readable"))
    for refused in (real, standin):
        assert refused.refusal is not None
        row, _ = make_row(refused, a2l, img)
        assert (row.kind, row.current, row.staged, row.is_staged) == ("none", None, None, False)
        assert paint(refused, a2l, img)[0]["current"].strip() == "refused"


def test_r_pe_def_75_fallback_rows_show_the_element_count_or_dashes(defc):
    """R-PE-DEF.75/1, /2 - a `cuboid` copy with element count 24 -> `24 values`; with none -> `--`."""
    base = defc["defs"]["DISPLAY_0001"]
    with_count = replace(base, kind="cuboid", element_count=24)
    without = replace(base, kind="cuboid", element_count=None)
    assert paint(with_count, defc["a2l"], defc["image"])[0]["current"].strip() == "24 values"
    assert paint(without, defc["a2l"], defc["image"])[0]["current"].strip() == "--"


@pytest.mark.parametrize("length", [4097, 1048576])
def test_r_pe_def_88_a_text_span_over_4096_shows_its_length_and_is_not_decoded(v171, length):
    """R-PE-DEF.88/1, /2 - `4097 B`, `1048576 B`; a lazy image of that span proves no walk of it."""
    definition = widen(v171["def"], length)
    image = SpanImage(definition.address, length, 0x41)
    cur = paint(definition, v171["a2l"], image)[0]["current"].strip()
    assert cur == f"{length} B"
    assert image.lookups < 1000, "the work is bounded by the document, not by the span"


# ==========================================================================
# R-PE-DEF.15, .20, .22, .28, .70 ... .72 - name, unit, mark, plain text (S9, S12)
# ==========================================================================


def test_r_pe_def_15_a_long_name_is_clipped_with_an_ellipsis(v171):
    """R-PE-DEF.15/1 - `ASAM.C.ASCII.UBYTE.NUMBER_42` (28 characters) in the 26-cell Parameter column -> its first 25 cells and `…`.

    Why: Inc 8b widened Parameter from 18 to 26 (R-PE-DEF.89); the clip rule is the one of R-PE-DEF.96, the
    oracle's ``fit`` (a name that fits is shown whole, a longer one ends in one `…`).
    """
    got = paint(v171["def"], v171["a2l"], v171["image"])[0]["name"].strip()
    assert got == EXB.fit(V171_NAME, 26).strip()
    assert got.endswith("…") and cell_len(got) == 26 and got.startswith(V171_NAME[:25])


def test_r_pe_def_15_a_name_with_brackets_is_shown_literally(defc):
    """R-PE-DEF.15/2 - a name holding `[b]` -> shown literally (a Text, no markup parse); R-PE-DEF.70/5 model side."""
    renamed = replace(defc["defs"]["DISPLAY_0001"], name="A[b]")
    row, _ = make_row(renamed, defc["a2l"], defc["image"])
    line = ds.row_line(row, ds.sheet_widths(W118), False, "", None)
    assert hasattr(line, "plain") and "A[b]" in line.plain
    renamed = replace(defc["defs"]["DISPLAY_0001"], name="A[/x]B")
    row, _ = make_row(renamed, defc["a2l"], defc["image"])
    assert "A[/x]B" in ds.row_line(row, ds.sheet_widths(W118), False, "", None).plain


def test_r_pe_def_7_wide_characters_are_clipped_by_cells_not_by_length(defc):
    """R-PE-DEF.7/4 (retired at Inc 8b E1; its wide-character case moves to R-PE-DEF.96/1, /2).

    Why: a name or unit of wide characters must stop inside its column in terminal cells, never in
    characters (a `len()` clip leaves it twice as wide and pushes the gutter and the next cell right).
    The columns are the grid's (Parameter 26, Unit 8): `温度`x14 -> `C.name_wide.fit26`, `温度温度温度` -> `C.unit_wide.fit8`.
    """
    renamed = replace(defc["defs"]["DISPLAY_0001"], name="温度" * 14, unit="温度温度温度")
    got = paint(renamed, defc["a2l"], defc["image"])[0]
    assert got["name"].rstrip() == fact("C.name_wide.fit26").rstrip() and cell_len(got["name"].rstrip()) <= 26
    assert got["unit"].rstrip() == fact("C.unit_wide.fit8").rstrip() and cell_len(got["unit"].rstrip()) <= 8
    assert got["name"].rstrip().endswith("…") and got["unit"].rstrip().endswith("…")


def test_r_pe_def_20_unit_column_is_the_unit(defc):
    """R-PE-DEF.20/1 - DISPLAY_0001 -> `deg C`."""
    assert paint(defc["defs"]["DISPLAY_0001"], defc["a2l"], defc["image"])[0]["unit"].strip() == "deg C"


def test_r_pe_def_20_a_control_character_in_a_unit_becomes_fffd(defc):
    """R-PE-DEF.20/2, R-PE-DEF.71/3 - a unit `%\\x1b` -> `%` + U+FFFD; a unit with U+0085 likewise."""
    for raw in ("%\x1b", "%\x85"):
        got = paint(replace(defc["defs"]["DISPLAY_0001"], unit=raw), defc["a2l"], defc["image"])[0]
        assert got["unit"].strip() == "%" + FFFD


def test_r_pe_def_71_a_control_character_in_a_name_becomes_fffd(defc):
    """R-PE-DEF.71/2 - a name with NUL -> U+FFFD in the Parameter cell; no raw control byte in the line."""
    renamed = replace(defc["defs"]["DISPLAY_0001"], name="DISP\x00LAY")
    row, _ = make_row(renamed, defc["a2l"], defc["image"])
    line = ds.row_line(row, ds.sheet_widths(W118), False, "", None).plain
    assert "DISP" + FFFD + "LAY" in line
    assert not any(ord(c) < 32 or 0x7F <= ord(c) <= 0x9F for c in line)


def test_r_pe_def_70_a_unit_with_markup_shows_every_character(defc):
    """R-PE-DEF.70/3 (model side) - a unit `Map[b]x` -> all characters shown, in a Text."""
    got = paint(replace(defc["defs"]["DISPLAY_0001"], unit="Map[b]x"), defc["a2l"], defc["image"], width=200)[0]
    assert got["unit"].strip() == "Map[b]x"


def test_r_pe_def_22_the_selected_row_has_the_pointer_in_its_mark_cell(defc):
    """R-PE-DEF.22/1, /2 - `▶` on the selected row, a space on the others."""
    d, a2l, img = defc["defs"]["DISPLAY_0001"], defc["a2l"], defc["image"]
    assert paint(d, a2l, img, selected=True)[0]["mark"][0] == "▶"
    assert paint(d, a2l, img, selected=False)[0]["mark"][0] == " "


def test_r_pe_def_28_an_untouched_row_shows_a_dot_and_no_delta(defc):
    """R-PE-DEF.28/1 - DISPLAY_0001 at start: New `·`, Δ empty, no second mark."""
    got = paint(defc["defs"]["DISPLAY_0001"], defc["a2l"], defc["image"])[0]
    assert got["new"].strip() == "·"
    assert got["delta"].strip() == ""
    assert got["mark"] == "  "


@pytest.mark.parametrize("w", [73, 111, 195])
def test_r_pe_def_7_no_painted_line_is_wider_than_the_sheet(defc, v171, w):
    """R-PE-DEF.7/1..3 (retired at Inc 8b E1; replaced by R-PE-DEF.89, .96) - every row line and the header are exactly the grid's 143 cells.

    Why: the grid is wider than the view at 118 and scrolls sideways; what must hold now is that no row,
    whatever its text (wide names, a 300-character refusal tail), grows past the grid or ends short of it,
    or the gutters and the horizontal scroll range would move row by row.
    """
    widths = ds.sheet_widths(w)
    assert cell_len(ds.header_line(widths).plain) == GRID_WIDTH
    d = defc["defs"]
    for definition, a2l, img, text in (
        (d["DISPLAY_0001"], defc["a2l"], defc["image"], "25.5"),
        (d["ENUM_0001"], defc["a2l"], defc["image"], "RUN"),
        (d["MASK_FIELD_0001"], defc["a2l"], defc["image"], "255"),
        (v171["def"], v171["a2l"], v171["image"], "ABC"),
        (d["DISPLAY_0001"], defc["a2l"], defc["image"], "x" * 300),
        (replace(d["DISPLAY_0001"], name="温度" * 20, unit="温度" * 9), defc["a2l"], defc["image"], "25.5"),
    ):
        row, overlay = make_row(definition, a2l, img)
        pv = ds.preview(definition, a2l, text, overlay)
        for selected in (False, True):
            assert cell_len(ds.row_line(row, widths, selected, text, pv).plain) == GRID_WIDTH
            assert cell_len(ds.row_line(row, widths, selected, "", None).plain) == GRID_WIDTH


# ==========================================================================
# R-PE-DEF.21, .76 - the limits cell (S8, S8')
# ==========================================================================


def _limits(definition, a2l, image, value=None, width=None):
    row, _ = make_row(definition, a2l, image)
    return ds.limits_cell(row, value, ds.sheet_widths(W118).limits if width is None else width).plain


def test_r_pe_def_21_limits_cell_holds_the_short_limits_and_the_current_mark_on_its_cell(defc):
    """R-PE-DEF.21/1 (changed at Inc 8b E1) - DISPLAY_0001 at its current 143.5: `L.cell.DISPLAY_0001.cur143.5`.

    Why: the operator asked for every Limits cell to line up down the column: two 7-cell slots (number
    right-aligned, unit letter last) and an 18-cell track at fixed offsets, `├` at 8 whatever the lower
    limit's width. Inc 8's cell started the track after the lower limit's own text.
    """
    cell = _limits(defc["defs"]["DISPLAY_0001"], defc["a2l"], defc["image"])
    assert cell == fact("L.cell.DISPLAY_0001.cur143.5") and len(cell) == fact("L.cell.DISPLAY_0001.cur143.5.len") == 34
    assert cell.index("├") == fact("L.offset.track_start") and cell.index("┤") == fact("L.offset.track_end")
    assert "◆" not in cell and cell.count("●") == 1


def test_r_pe_def_21_limits_cell_puts_the_preview_mark_on_its_cell(defc):
    """R-PE-DEF.21/1 - a preview of 25.5 -> `L.cell.DISPLAY_0001.cur143.5.new25.5` (`◆` on its cell, `●` on the current value's)."""
    cell = _limits(defc["defs"]["DISPLAY_0001"], defc["a2l"], defc["image"], EX.new)
    marks = fact("L.cell.DISPLAY_0001.cur143.5.new25.5.marks")
    assert cell == fact("L.cell.DISPLAY_0001.cur143.5.new25.5")
    assert cell.index("◆") == marks["◆"] and cell.index("●") == marks["●"]


def test_r_pe_def_21_a_value_above_the_upper_limit_sits_on_the_right_end(defc):
    """R-PE-DEF.21/4 - a preview of 175 (above 150) -> `▶` at offset 25 (the track's right end), no `◆`; `L.cell.DISPLAY_0001.new175`."""
    cell = _limits(defc["defs"]["DISPLAY_0001"], defc["a2l"], defc["image"], 175)
    assert cell == fact("L.cell.DISPLAY_0001.new175")
    assert cell.index("▶") == fact("L.offset.track_end") and "◆" not in cell


def test_r_pe_def_21_a_value_below_the_lower_limit_sits_on_the_left_end(defc):
    """R-PE-DEF.21/5 - below the lower limit -> `◀` at offset 8 (the track's left end); `L.cell.DISPLAY_0001.new-45`."""
    cell = _limits(defc["defs"]["DISPLAY_0001"], defc["a2l"], defc["image"], -45)
    assert cell == fact("L.cell.DISPLAY_0001.new-45")
    assert cell.index("◀") == fact("L.offset.track_start") and "◆" not in cell


def test_r_pe_def_21_a_track_under_six_cells_gives_the_dots_form(defc):
    """R-PE-DEF.21/2 (the case is gone at Inc 8b E1; E3-8b-10) - the Limits width is fixed, so the `width` argument changes nothing.

    Why: Inc 8 drew `-40 … 150` when the Limits column was narrower than 18. The column is 34 cells at
    every view width now: asking for width 16, 34 or 200 must give the same aligned cell, never the old
    dots form.
    """
    display = defc["defs"]["DISPLAY_0001"]
    narrow = _limits(display, defc["a2l"], defc["image"], None, 16)
    assert narrow == _limits(display, defc["a2l"], defc["image"], None, 34)
    assert narrow == _limits(display, defc["a2l"], defc["image"], None, 200)
    assert narrow == fact("L.cell.DISPLAY_0001.cur143.5") and narrow.strip() != "-40 … 150"


def test_r_pe_def_21_no_limits_shows_a_dash(defc):
    """R-PE-DEF.21/3 - an object with no lower or upper limit -> the no-limits form: 34 cells, `-` at offset 16 (`L.cell.no_limits`)."""
    nolimits = replace(defc["defs"]["DISPLAY_0001"], limits=Limits(None, None, "", ""))
    cell = _limits(nolimits, defc["a2l"], defc["image"])
    assert cell == fact("L.cell.no_limits") and cell.strip() == "-" and cell.index("-") == 16


@pytest.mark.parametrize("lower, upper, key", [(5.0, 5.0, "L.cell.limits_5_5"), (9.0, 1.0, "L.cell.limits_9_1")])
def test_r_pe_def_76_limits_not_ascending_paint_the_dots_form_without_a_division(defc, lower, upper, key):
    """R-PE-DEF.76/1, /2 (changed at Inc 8b E1) - limits `5 5` and `9 1` -> the range form (both slots, `…` at offset 16); no ZeroDivisionError.

    Why: an upper limit that is not above the lower gives no scale to place a value on, so the cell shows
    the limits only; Inc 8 wrote `5 … 5` from the column start, which broke the column's alignment.
    """
    flat = replace(defc["defs"]["DISPLAY_0001"], limits=Limits(lower, upper, str(int(lower)), str(int(upper))))
    for value in (None, EX.new):
        cell = _limits(flat, defc["a2l"], defc["image"], value)
        assert cell == fact(key) and cell.index("…") == 16


# ==========================================================================
# R-PE-DEF.23 ... .27, .77 - New and Δ of staged and pending rows (S4', S7', S9')
# ==========================================================================


def _staged(definition, a2l, image, text):
    return [stage_entry(definition, a2l, text, image)]


def test_r_pe_def_23_a_staged_number_shows_the_dot_mark_and_its_value_text(defc):
    """R-PE-DEF.23/1 - DISPLAY_0001 staged `25.5` -> `●` in the mark, New `25.5`."""
    d, a2l, img = defc["defs"]["DISPLAY_0001"], defc["a2l"], defc["image"]
    got = paint(d, a2l, img, _staged(d, a2l, img, "25.5"))[0]
    assert got["mark"][1] == "●" and got["new"].strip() == "25.5"


def test_r_pe_def_23_a_staged_bit_mask_shows_the_field_in_hex(defc):
    """R-PE-DEF.23/2 - MASK_FIELD_0001 staged `255` -> `255 (0xFF)`."""
    d, a2l, img = defc["defs"]["MASK_FIELD_0001"], defc["a2l"], defc["image"]
    got = paint(d, a2l, img, _staged(d, a2l, img, "255"))[0]
    assert got["mark"][1] == "●" and got["new"].strip() == "255 (0xFF)"


def test_r_pe_def_23_a_staged_enum_shows_stored_value_and_text(defc):
    """R-PE-DEF.23/3 - ENUM_0001 staged `RUN` -> `2 RUN`."""
    d, a2l, img = defc["defs"]["ENUM_0001"], defc["a2l"], defc["image"]
    got = paint(d, a2l, img, _staged(d, a2l, img, "RUN"))[0]
    assert got["mark"][1] == "●" and got["new"].strip() == "2 RUN"


def test_r_pe_def_23_a_fallback_row_with_a_raw_entry_over_its_span_is_staged(defc):
    """R-PE-DEF.23/4 - the `cuboid` copy with a raw entry `AA BB` over its span -> `●`; untouched -> no mark."""
    cuboid = replace(defc["defs"]["DISPLAY_0001"], kind="cuboid", element_count=24)
    plain = paint(cuboid, defc["a2l"], defc["image"])[0]
    assert plain["mark"][1] == " "
    entry = (cuboid.address, bytes([0xAA, 0xBB]))
    assert span_bytes(cuboid, defc["image"]) != entry[1]
    got = paint(cuboid, defc["a2l"], defc["image"], [entry])[0]
    assert got["mark"][1] == "●" and got["current"].strip() == "24 values"


def test_r_pe_def_23_an_entry_equal_to_the_image_is_not_staged_for_a_fallback_row(defc):
    """R-PE-DEF.23 (staged = a byte differs from the image's) - an entry that rewrites the image's own bytes leaves it unstaged."""
    cuboid = replace(defc["defs"]["DISPLAY_0001"], kind="cuboid", element_count=24)
    same = (cuboid.address, span_bytes(cuboid, defc["image"]))
    assert paint(cuboid, defc["a2l"], defc["image"], [same])[0]["mark"][1] == " "


def test_r_pe_def_23_i85_mark_field_none_keeps_inc8_rule_and_a_kind_mark_overrides(defc, monkeypatch):
    """I-8.5 amendment (Inc 9 E3A-05, ruled at Inc 8 E4): `KindOps.mark(row, state)` is optional.

    Why: Inc 9's bench rows paint `◆`/`●` from their bench state, not from the formula text; Inc 8's
    own kinds must keep the R-PE-DEF.23/.24 rule. A `row_line` that ignores the field fails the override
    half; a default other than None (or a mark set on an Inc 8 kind) fails the first half.
    """
    # Inc 8's own four kinds; the bench kinds (R-PE-BENCH.3) carry Inc 9's `mark` by design.
    inc8_kinds = ("number", "bit mask", "enum", "text")
    assert all(ds._KIND_OPS[kind].mark is None for kind in inc8_kinds), "Inc 8 kinds keep their mark rule"
    assert ds._FALLBACK_OPS.mark is None
    a2l, img = defc["a2l"], defc["image"]
    d = defc["defs"]["DISPLAY_0001"]
    assert paint(d, a2l, img, _staged(d, a2l, img, "25.5"))[0]["mark"][1] == "●"
    assert paint(d, a2l, img, text="25.50")[0]["mark"][1] == "◆"
    seen = []

    def bench_like(row, state):
        seen.append((row.name, state))
        return None if state is None else ("◆" if state.get("edit") else " ")

    monkeypatch.setitem(ds._KIND_OPS, "cuboid", ds._FALLBACK_OPS._replace(mark=bench_like))
    cuboid = replace(d, kind="cuboid", element_count=24)
    raw = [(cuboid.address, bytes([0xAA, 0xBB]))]
    row, _ = make_row(cuboid, a2l, img, raw)
    widths = ds.sheet_widths(W118)
    assert row.is_staged
    # state None -> the kind's mark answers None -> Inc 8's rule (`●` for the staged span)
    assert cells(ds.row_line(row, widths, False, "", None, None), widths)["mark"][1] == "●"
    # a bench edit -> `◆` though no formula text is pending; an empty edit -> blank though staged
    assert cells(ds.row_line(row, widths, True, "", None, {"edit": {(0,): "5"}}), widths)["mark"] == "▶◆"
    assert cells(ds.row_line(row, widths, False, "", None, {"edit": {}}), widths)["mark"][1] == " "
    assert seen == [(cuboid.name, None), (cuboid.name, {"edit": {(0,): "5"}}), (cuboid.name, {"edit": {}})]


def test_r_pe_def_62_a_staged_row_follows_the_image_it_is_built_over(defc):
    """R-PE-DEF.62/4 - MASK_FIELD `255` staged over word 1A E7, then an image with 1A E6 -> MASK_BIT `●`, New `1 (0x01)`."""
    a2l, img = defc["a2l"], defc["image"]
    field, bit = defc["defs"]["MASK_FIELD_0001"], defc["defs"]["MASK_BIT_0001"]
    entries = _staged(field, a2l, img, "255")
    new_img = dict(img)
    new_img[bit.address + 1] = (img[bit.address + 1] & 0xFE) | 0
    assert new_img[bit.address + 1] != img[bit.address + 1]
    got = paint(bit, a2l, new_img, entries)[0]
    assert got["current"].strip() == "0 (0x00)"
    assert got["mark"][1] == "●" and got["new"].strip() == "1 (0x01)"
    assert paint(bit, a2l, img, [])[0]["mark"][1] == " ", "no entry, no mark"


def test_r_pe_def_24_a_pending_number_shows_the_diamond_and_the_previews_text_not_the_typed_one(defc):
    """R-PE-DEF.24/1 - DISPLAY_0001 typed `25.50` -> `◆`, New `25.5` (the preview's text)."""
    got = paint(defc["defs"]["DISPLAY_0001"], defc["a2l"], defc["image"], text="25.50")[0]
    assert got["mark"][1] == "◆" and got["new"].strip() == "25.5"


def test_r_pe_def_24_a_pending_text_equal_to_the_rows_own_text_is_not_pending(v171):
    """R-PE-DEF.24/3 at the model - a text row whose formula text is its own base text shows no `◆` and `·` in New.

    The sheet never hands the model such a text (it drops a pending text equal to the base text), so the
    model is driven through `row_line` directly. Control arm: one more character and the row IS pending.
    """
    d, a2l, img = v171["def"], v171["a2l"], v171["image"]
    row, _ = make_row(d, a2l, img)
    base = row.current.text
    assert base
    same = paint(d, a2l, img, pending=base)[0]
    assert same["mark"][1] != "◆" and same["new"].strip() == "·"
    changed = paint(d, a2l, img, pending=base + "!")[0]
    assert changed["mark"][1] == "◆" and changed["new"].strip() == base + "!"


def test_r_pe_def_24_a_pending_enum_shows_stored_value_and_text(defc):
    """R-PE-DEF.24/2 - ENUM_0001 `RUN` -> `2 RUN`."""
    got = paint(defc["defs"]["ENUM_0001"], defc["a2l"], defc["image"], text="RUN")[0]
    assert got["mark"][1] == "◆" and got["new"].strip() == "2 RUN"


def test_r_pe_def_25_a_refused_preview_shows_the_typed_text_in_new(defc):
    """R-PE-DEF.25/1 - DISPLAY_0001 `abc` -> New `abc` (not the refusal code)."""
    got = paint(defc["defs"]["DISPLAY_0001"], defc["a2l"], defc["image"], text="abc")[0]
    assert got["new"].strip() == "abc" and "A2L-DEF" not in got["new"]


def test_r_pe_def_25_a_long_refused_text_is_clipped_with_an_ellipsis(defc):
    """R-PE-DEF.25/2 - `x`x300 -> its start and `…`, inside the New column."""
    got, widths, _, _ = paint(defc["defs"]["DISPLAY_0001"], defc["a2l"], defc["image"], text="x" * 300)
    new = got["new"].strip()
    assert new.startswith("xxx") and new.endswith("…") and cell_len(got["new"]) <= widths.new
    assert set(new[:-1]) == {"x"}


def _expect_pct():
    return f"{EX.signed(f'{EX.d:.1f}')} ({EX.signed(f'{100 * EX.d / (EX.hi - EX.lo):.1f}')}%)"


def test_r_pe_def_26_pending_number_delta_is_taken_over_the_definitions_limits(defc):
    """R-PE-DEF.26/1 - DISPLAY_0001 pending 25.5 -> `-118.0 (-62.1%)`; the extended limits' `-47.2%` is the negative control."""
    got = paint(defc["defs"]["DISPLAY_0001"], defc["a2l"], defc["image"], text="25.5")[0]
    assert got["delta"].strip() == _expect_pct() == "-118.0 (-62.1%)"
    assert "-47.2" not in got["delta"]


def test_r_pe_def_26_staged_number_delta_says_staged(defc):
    """R-PE-DEF.26/2 - DISPLAY_0001 staged 25.5 -> `-118.0 staged`."""
    d, a2l, img = defc["defs"]["DISPLAY_0001"], defc["a2l"], defc["image"]
    got = paint(d, a2l, img, _staged(d, a2l, img, "25.5"))[0]
    assert got["delta"].strip() == f"{EX.signed(f'{EX.d:.1f}')} staged"


def test_r_pe_def_26_enum_delta_is_old_stored_to_new_stored(defc):
    """R-PE-DEF.26/3 - ENUM_0001 RUN -> `1 → 2`."""
    got = paint(defc["defs"]["ENUM_0001"], defc["a2l"], defc["image"], text="RUN")[0]
    assert got["delta"].strip() == "1 → 2"


def test_r_pe_def_26_bit_mask_delta_is_the_signed_field_difference(defc):
    """R-PE-DEF.26/4 - MASK_FIELD_0001 255 -> `+81`."""
    got = paint(defc["defs"]["MASK_FIELD_0001"], defc["a2l"], defc["image"], text="255")[0]
    assert got["delta"].strip() == EX.signed(str(255 - EX.field)) == "+81"


def test_r_pe_def_26_text_delta_counts_the_positions_whose_byte_changes(v171):
    """R-PE-DEF.26/5 - V171 ASCII `ABC` -> `10 chars` (the examples file's own count of changed positions)."""
    changed = sum(1 for a, b in zip(EX.before, EX.after) if a != b)
    got = paint(v171["def"], v171["a2l"], v171["image"], text="ABC")[0]
    assert got["delta"].strip() == f"{changed} chars"


def test_r_pe_def_27_a_refused_preview_shows_refused_in_the_delta_column(defc):
    """R-PE-DEF.27/1 - DISPLAY_0001 `250` -> `✗ refused`, not the previous Δ."""
    got = paint(defc["defs"]["DISPLAY_0001"], defc["a2l"], defc["image"], text="250")[0]
    assert got["delta"].strip() == "✗ refused"


@pytest.mark.parametrize("lower, upper", [(5.0, 5.0), (9.0, 1.0)])
def test_r_pe_def_77_limits_not_ascending_leave_the_percent_out_of_the_delta(defc, lower, upper):
    """R-PE-DEF.77/1, /2 - limits `5 5` and `9 1`, pending 25.5 -> `-118.0` with no percent and no exception."""
    flat = replace(defc["defs"]["DISPLAY_0001"], limits=Limits(lower, upper, str(int(lower)), str(int(upper))))
    got = paint(flat, defc["a2l"], defc["image"], text="25.5")[0]
    assert got["delta"].strip() == EX.signed(f"{EX.d:.1f}") == "-118.0"


# ==========================================================================
# R-PE-DEF.81 - the row window (S20)
# ==========================================================================


def _reference_window(selected, top, visible, detail):
    """CTX-PE-DEF `row window`, written from the requirement text only."""
    cut = min(detail, visible - 1)
    need = 1 + cut
    if selected < top:
        top = selected
    elif selected + need > top + visible:
        top = selected + need - visible
    return top, cut


@pytest.mark.parametrize("selected, top, visible, detail, expect", [
    (40, 0, 20, 1, (22, 1)),    # EX-K4: 40 downs from row 0
    (39, 22, 20, 1, (22, 1)),   # EX-K4: still inside
    (21, 22, 20, 1, (21, 1)),   # EX-K4: above the first painted row -> it becomes the first
    (5, 0, 20, 3, (0, 3)),      # EX-K4
    (18, 0, 20, 3, (2, 3)),     # EX-K4: an enum row (3 detail lines) on the last line
    (3, 0, 3, 3, (3, 2)),       # EX-K6: detail taller than the window
    (10, 0, 8, 10, (10, 7)),    # EX-K6: 10 detail lines at visible 8 -> cut to 7
    (10, 0, 6, 10, (10, 5)),    # Inc 8b R-PE-DEF.81/4: grid body 8 -> visible 6 (header line and rule) -> cut to 5
])
def test_r_pe_def_81_row_window_examples(selected, top, visible, detail, expect):
    """R-PE-DEF.81/1..4 - the worked windows of EX-K4 and EX-K6 (graph-inc8.md) and Inc 8b's `W.standin_10_detail.h8.painted`.

    Why: the header rule takes a body line, so the 12-row minimum sheet (grid body 8) paints 6 sheet lines
    and a 10-line detail is cut to 5; the pure window rule itself is unchanged.
    """
    if (visible, detail) == (6, 10):
        assert expect[1] == fact("W.standin_10_detail.h8.painted")
    assert ds.row_window(selected, top, visible, detail) == expect


def test_r_pe_def_81_row_window_sweep_keeps_the_selected_row_painted_and_matches_the_rule():
    """R-PE-DEF.81 - over a grid, the window equals the CTX rule and the selected row and its cut detail are inside."""
    for visible in (1, 2, 3, 8, 20):
        for detail in (0, 1, 3, 10):
            for top in (0, 1, 5, 22):
                for selected in range(0, 60, 3):
                    got = ds.row_window(selected, top, visible, detail)
                    assert got == _reference_window(selected, top, visible, detail), (selected, top, visible, detail)
                    new_top, painted = got
                    assert new_top <= selected and selected + 1 + painted <= new_top + visible
                    assert painted <= detail


# ==========================================================================
# R-PE-DEF.71, .72 - plain text and name echo (S12)
# ==========================================================================


def test_r_pe_def_71_plain_replaces_every_control_character_and_keeps_brackets():
    """R-PE-DEF.71/1..3 - ESC, NUL, U+0085 -> U+FFFD; brackets kept; U+0020 and U+00A0 untouched."""
    assert ds.plain("A\x1b[2J") == "A" + FFFD + "[2J"
    assert ds.plain("%\x85") == "%" + FFFD
    assert ds.plain("N\x00UL") == "N" + FFFD + "UL"
    assert ds.plain("A[/x]B") == "A[/x]B"
    assert ds.plain("[@click=app.quit]OFF[/]") == "[@click=app.quit]OFF[/]"
    for code in list(range(0x00, 0x20)) + [0x7F] + list(range(0x80, 0xA0)):
        assert ds.plain(chr(code)) == FFFD, hex(code)
    assert ds.plain(" \xa0~") == " \xa0~"


def test_r_pe_def_72_name_echo_caps_at_256_characters_and_cleans_controls():
    """R-PE-DEF.72/1, /2 - 300 characters -> 256 + `…`; ESC -> U+FFFD; short and exactly-256 names unchanged."""
    assert ds.name_echo("N" * 300) == "N" * 256 + "…"
    assert ds.name_echo("A\x1bB") == "A" + FFFD + "B"
    assert ds.name_echo("N" * 256) == "N" * 256
    assert ds.name_echo("N" * 257) == "N" * 256 + "…"
    assert ds.name_echo("x" * 300) == "x" * 256 + "…"


# ==========================================================================
# Purity of the model (slice S: "pure: rich Text and I-2 only, no textual")
# ==========================================================================


def _module_level_imports(tree):
    """Import names outside any function or lambda body (a function-local import is allowed by ruling)."""
    import ast

    names = []

    def visit(node):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue
            if isinstance(child, ast.Import):
                names.extend(a.name for a in child.names)
            elif isinstance(child, ast.ImportFrom):
                names.append(("." * child.level) + (child.module or ""))
            visit(child)

    visit(tree)
    return names


def test_s1_module_has_no_module_level_textual_import():
    """Slice S1 purity - by the module's own import statements (AST), never by sys.modules: s19_app.tui already loads textual."""
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(ds))
    bad = [n for n in _module_level_imports(tree) if n == "textual" or n.startswith("textual.")]
    assert bad == [], bad
