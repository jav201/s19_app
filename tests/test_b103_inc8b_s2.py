"""Batch-103 Inc 8b E4, tester T8b-S2 - group S, the card and the expanded object (``detail_lines``).

Design under test: ``.dev-flow/2026-11-05-batch-103/inc-8b/01-requirements.md`` rows R-PE-DEF.33, .34, .35,
.79 (kept), .102, .107, .108, .109, .110, .111, .112, .115, .116 and R-PE-BENCH.5, through the one entry point
the base already has, ``s19_app.tui.definition_sheet.detail_lines`` (the kind's ``_detail_enum`` / ``_detail_mask``
/ ``_detail_text`` and the new ``card_lines`` / ``bit_table`` / ``hex_grid`` are reached through it, never
imported: a missing function is an assertion RED on the base, not an import error).

Operator need (V-8, V-9, V-11): the selected row's expanded object stands apart from the table (the ``┊`` bar,
the expanded ground) and an enum, a bit mask or a text row shows its editor as a framed card whose nibble
guides and ASCII column line up, whatever hostile text an A2L carries.

Expected values: ``evidence-e1/examples_inc8b-transcript.txt`` (the spec-side oracle of E1, stdlib only,
independent of the product), loaded by key and never retyped; positions are found in the painted text, never
counted by hand (tester rule 2). The Definition copies are ``dataclasses.replace`` copies of I-2's output.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest
from rich.cells import cell_len
from rich.console import Console
from rich.text import Text

from s19_app.tui import definition_sheet as ds
from s19_app.tui.a2l_definition import EnumEntry
from tests.support.b103_inc8_s1 import (  # noqa: F401  (fixtures are used by name)
    SpanImage,
    defc,
    replace,
    v171,
    widen,
)
from tests.support.b103_inc9_b import (
    big_values,
    blank_state,
    defc_obj,
    large_definition,
    sheet_row,
    view_state,
)

ROOT = Path(__file__).resolve().parents[1]
TRANSCRIPT = ROOT / ".dev-flow" / "2026-11-05-batch-103" / "inc-8b" / "evidence-e1" / "examples_inc8b-transcript.txt"
BAR = "  ┊ "  # R-PE-DEF.107: the bar every expanded line starts with
EXPANDED_GROUND = "#1b233a"  # R-PE-DEF.97 / .107
PENDING_COLOUR = "#b565f3"  # R-PE-DEF.97: the pending style
V = 111  # the view width of the 118-column sheet
ROOM = 50
_CONSOLE = Console(color_system="truecolor", force_terminal=True, width=400)


def _load_transcript() -> dict:
    values: dict = {}
    for line in TRANSCRIPT.read_text(encoding="utf-8").splitlines():
        key, sep, raw = line.partition(" = ")
        if not sep:
            continue
        try:
            values[key] = ast.literal_eval(raw)
        except (ValueError, SyntaxError):
            continue  # `nan` and `inf` values: not used here
    return values


OT = _load_transcript()
GRID = OT["G.grid_width"]


# ----------------------------------------------------------------------------- helpers


def make_row(definition, a2l, image, entries=()):
    overlay = ds.StagedOverlay(image, list(entries))
    return ds.build_row(definition, a2l, image, overlay), overlay


def row_and_preview(definition, a2l, image, text):
    row, overlay = make_row(definition, a2l, image)
    return row, ds.preview(definition, a2l, text, overlay)


def painted(row, pv=None, width=V, room=ROOM, state=None):
    return ds.detail_lines(row, pv, width, state, room)


def style_at(text: Text, offset: int):
    return text.get_style_at_offset(_CONSOLE, offset)


def hex_of(color) -> str | None:
    return None if color is None else color.get_truecolor().hex.lower()


def at(lines, index) -> str:
    """The plain text of ``lines[index]``; a missing line is an assertion, not an IndexError."""
    assert -len(lines) <= index < len(lines), f"{len(lines)} expanded lines only: {[ln.plain for ln in lines]}"
    return lines[index].plain


def assert_card(lines, first: int, keys: list[str]) -> None:
    """``lines[first:]`` are the card lines of ``keys``, each after the bar, padded to the grid width."""
    assert len(lines) >= first + len(keys), [ln.plain for ln in lines]
    for offset, key in enumerate(keys):
        plain = lines[first + offset].plain
        expected = BAR + OT[key]
        assert plain.startswith(expected), (key, plain)
        assert plain[len(expected):].strip() == "", f"{key}: nothing after the card but the ground"
        assert cell_len(plain) == max(GRID, V), f"{key}: the line is padded to the grid width in cells"


def with_pending(defc, name, text):
    d, a2l, img_ = defc["defs"][name], defc["a2l"], defc["image"]
    row, pv = row_and_preview(d, a2l, img_, text)
    return row, pv


def enum_row(defc, name="ENUM_0001", **changes):
    d = replace(defc["defs"]["ENUM_0001"], **changes) if changes else defc["defs"]["ENUM_0001"]
    d = replace(d, name=name) if name != d.name else d
    row, _ = make_row(d, defc["a2l"], defc["image"])
    return row


def enum_with_first_text(defc, text):
    d = defc["defs"]["ENUM_0001"]
    first = replace(d.enum_entries[0], text=text)
    return enum_row(defc, enum_entries=(first,) + tuple(d.enum_entries[1:]))


def mask_after_style_columns(lines):
    """(bit number -> column) read from the card's `bit` header row, and the `after` row's Text."""
    header = next((ln for ln in lines if ln.plain.startswith(BAR + "│ bit")), None)
    after = next((ln for ln in lines if ln.plain.startswith(BAR + "│ after")), None)
    assert header is not None and after is not None, f"no framed bit table: {[ln.plain for ln in lines]}"
    start = header.plain.index("bit") + 3
    columns = {int(m.group()): start + m.end() - 1 for m in re.finditer(r"\d+", header.plain[start:])}
    return columns, after


def hex_rows(lines):
    """The card's hex rows (`+XX │ …`), each with its guide column and the byte columns, from the text."""
    out = []
    for ln in lines:
        match = re.match(re.escape(BAR) + r"│ \+([0-9A-F]{2}) │", ln.plain)
        if not match:
            continue
        plain = ln.plain.rstrip()
        frame = len(plain) - 1
        guide = plain.rfind("│", 0, frame)
        assert guide > 0, f"no ASCII guide in {plain!r}"
        hex_cols = [m.start() for m in re.finditer(r"(?<= )[0-9A-F]{2}(?= )", plain[:guide])]
        out.append((int(match.group(1), 16), guide, hex_cols, guide + 2, ln))
    return out


# ============================================================================== R-PE-DEF.108, .33 - the card


def test_r_pe_def_108_1_an_enum_row_shows_its_definition_line_then_a_framed_card(defc):
    """R-PE-DEF.108/1 (EX-8B-K1) - ENUM_0001 -> the definition line, then `E.card.ENUM_0001.line0..3` after the bar.

    Operator need V-8/V-9/V-11: the options sit in a frame under the table row, not as loose text.
    """
    row, _ = make_row(defc["defs"]["ENUM_0001"], defc["a2l"], defc["image"])
    lines = painted(row)
    assert at(lines, 0).startswith(BAR + "└ TAB_VERB ")
    assert len(lines) == 5, [ln.plain for ln in lines]
    assert_card(lines, 1, [f"E.card.ENUM_0001.line{n}" for n in range(4)])


def test_r_pe_def_108_2_a_bit_mask_row_shows_a_six_line_card_of_73_cells(defc):
    """R-PE-DEF.108/2 (EX-8B-K1) - MASK_FIELD_0001 pending 255 -> `B.card.MASK_FIELD_0001.line0..5` (73 cells)."""
    row, pv = with_pending(defc, "MASK_FIELD_0001", "255")
    lines = painted(row, pv)
    assert len(lines) == 7, [ln.plain for ln in lines]
    assert_card(lines, 1, [f"B.card.MASK_FIELD_0001.line{n}" for n in range(6)])
    assert cell_len(OT["B.card.MASK_FIELD_0001.line0"]) == OT["B.card.MASK_FIELD_0001.width"] == 73


def test_r_pe_def_108_3_a_text_row_shows_its_card_top_line_of_78_cells(v171):
    """R-PE-DEF.108/3 (EX-8B-K1) - V171 ASCII pending `ABC` -> the top line `T.card.V171.line0` (78 cells)."""
    d, a2l, image = v171["def"], v171["a2l"], v171["image"]
    row, pv = row_and_preview(d, a2l, image, "ABC")
    lines = painted(row, pv)
    assert_card(lines, 1, ["T.card.V171.line0"])
    assert cell_len(OT["T.card.V171.line0"]) == OT["T.card.V171.width"] == 78
    assert at(lines, -1).startswith(BAR + "╰") and at(lines, -1).rstrip().endswith("╯")


def test_r_pe_def_108_4_a_number_row_has_no_card(defc):
    """R-PE-DEF.108/4 (EX-8B-K1, negative) - DISPLAY_0001 -> exactly one expanded line and no frame glyph."""
    row, _ = make_row(defc["defs"]["DISPLAY_0001"], defc["a2l"], defc["image"])
    lines = painted(row)
    assert len(lines) == 1, [ln.plain for ln in lines]
    assert not any(ch in at(lines, 0) for ch in "╭╮╰╯")


def test_r_pe_def_33_1_the_enum_options_sit_in_the_card_with_the_choose_hint(defc):
    """R-PE-DEF.33/1 (EX-8B-K2) - ENUM_0001 at start: card row 1 holds `(●) 1 IDLE`, row 2 `↔ choose · enter stage`.

    The two rows are lines 2 and 3 of the expanded object, framed by `│ … │` (they were bare lines 2 and 3 on base).
    """
    row, _ = make_row(defc["defs"]["ENUM_0001"], defc["a2l"], defc["image"])
    lines = painted(row)
    options, hint = at(lines, 2), at(lines, 3)
    assert options.startswith(BAR + "│ ") and "(●) 1 IDLE" in options and 'default "UNKNOWN_STATE"' in options
    assert hint.startswith(BAR + "│ ↔ choose · enter stage")
    assert options.rstrip().endswith("│") and hint.rstrip().endswith("│")


def test_r_pe_def_33_2_after_choosing_run_the_mark_moves_to_run(defc):
    """R-PE-DEF.33/2 (EX-8B-K2) - the preview of `RUN` -> `(●) 2 RUN`, no mark left on IDLE; the frame is unchanged."""
    row, pv = with_pending(defc, "ENUM_0001", "RUN")
    lines = painted(row, pv)
    expected = OT["E.card.ENUM_0001.line1"].replace("(●) 1 IDLE", "( ) 1 IDLE").replace("( ) 2 RUN", "(●) 2 RUN")
    assert expected != OT["E.card.ENUM_0001.line1"], "the derivation changes the oracle line"
    assert at(lines, 2).startswith(BAR + expected)
    assert "(●) 1 IDLE" not in at(lines, 2)
    assert at(lines, 1).startswith(BAR + OT["E.card.ENUM_0001.line0"]), "the frame does not move with the choice"


def test_r_pe_def_97_12_the_card_is_on_the_expanded_ground(defc):
    """R-PE-DEF.97/12 (CTX-PE-DEF card ground): the card interior is on the expanded ground (operator verdict V8b-14)."""
    row, pv = with_pending(defc, "MASK_FIELD_0001", "255")
    lines = painted(row, pv)
    assert len(lines) == 7, [ln.plain for ln in lines]  # the definition line, then the six card lines
    for line in lines[2:6]:  # the card's middle rows: bit, before, mask, after
        plain = line.plain
        card = plain[len(BAR):].rstrip()  # the card without the ground padding
        assert card[0] == card[-1] == "│", plain
        grounds = {hex_of(style_at(line, len(BAR) + i).bgcolor) for i in range(1, len(card) - 1)}
        assert grounds == {EXPANDED_GROUND}, (plain, grounds)


# ============================================================================== R-PE-DEF.34, .102, .109 - the bit table


def test_r_pe_def_34_1_the_bit_table_at_start_shows_before_mask_after(defc):
    """R-PE-DEF.34/1 (EX-8B-B1) - MASK_FIELD_0001 at start -> `B.MASK_FIELD_0001.start.line0..3` inside the card."""
    row, _ = make_row(defc["defs"]["MASK_FIELD_0001"], defc["a2l"], defc["image"])
    lines = painted(row)
    for n in range(4):
        assert at(lines, 2 + n).startswith(BAR + "│ " + OT[f"B.MASK_FIELD_0001.start.line{n}"]), (n, at(lines, 2 + n))


def test_r_pe_def_34_2_the_after_row_reads_the_whole_word_not_the_field(defc):
    """R-PE-DEF.34/2 (EX-8B-B1) - pending 255 -> `after … │ 1F F7` (the unmasked word, not the field value)."""
    row, pv = with_pending(defc, "MASK_FIELD_0001", "255")
    lines = painted(row, pv)
    after = next((ln.plain for ln in lines if ln.plain.startswith(BAR + "│ after")), "")
    assert after.startswith(BAR + "│ " + OT["B.MASK_FIELD_0001.pending255.line3"])
    assert OT["B.MASK_FIELD_0001.pending255.line3"].endswith("1F F7")


def test_r_pe_def_34_3_a_single_bit_mask_marks_one_bit_and_keeps_the_other_bits(defc):
    """R-PE-DEF.34/3 (EX-8B-B1) - MASK_BIT_0001 pending 0 -> mask row with one `■` (bit 0), after `… 1A E6`."""
    row, pv = with_pending(defc, "MASK_BIT_0001", "0")
    lines = painted(row, pv)
    for n in (2, 3):
        assert at(lines, 2 + n).startswith(BAR + "│ " + OT[f"B.MASK_BIT_0001.pending0.line{n}"]), at(lines, 2 + n)
    assert sum(ln.plain.count("■") for ln in lines) == 1
    assert OT["B.MASK_BIT_0001.pending0.line3"].endswith("1A E6")


def test_r_pe_def_102_2_the_after_bits_that_differ_from_the_image_are_underlined(defc):
    """R-PE-DEF.102/2 (EX-8B-B1) - MASK_FIELD_0001 pending 255 -> bits 10, 8, 4 of the after row underlined, no other.

    The pending style needs a cue that is not a colour (colour-blind operator, NO_COLOR): the underline is it.
    """
    row, pv = with_pending(defc, "MASK_FIELD_0001", "255")
    columns, after = mask_after_style_columns(painted(row, pv))
    underlined = sorted((b for b, c in columns.items() if style_at(after, c).underline), reverse=True)
    assert underlined == OT["B.MASK_FIELD_0001.pending255.changed_bits"] == [10, 8, 4]
    assert len(columns) == 16


def test_r_pe_def_102_2_nothing_is_underlined_before_an_edit(defc):
    """R-PE-DEF.102/2 negative control - MASK_FIELD_0001 at start: no bit of the after row is underlined."""
    row, _ = make_row(defc["defs"]["MASK_FIELD_0001"], defc["a2l"], defc["image"])
    columns, after = mask_after_style_columns(painted(row))
    assert len(columns) == 16 and not [b for b, c in columns.items() if style_at(after, c).underline]


def _ulong_mask_case(defc, text):
    base = defc["defs"]["MASK_FIELD_0001"]
    d = replace(base, datatype="ULONG", byte_length=4, bit_mask=0x00FF0000, bit_mask_text="0x00FF0000")
    image = dict(defc["image"])
    image.update({d.address + i: b for i, b in enumerate(bytes.fromhex("12345678"))})
    row, pv = row_and_preview(d, defc["a2l"], image, text)
    return painted(row, pv)


def test_r_pe_def_109_1_a_32_bit_mask_word_is_two_blocks_of_16_high_bits_first(defc):
    """R-PE-DEF.109/1 (EX-8B-B2) - a ULONG copy, mask 0x00FF0000, word `12 34 56 78`, pending 0x12 -> 8 lines.

    A 32-bit word on one row is 123 cells wide and would be cut; one block per 16 bits, hex on the first block only.
    """
    lines = _ulong_mask_case(defc, "18")
    table = [ln.plain for ln in lines if ln.plain.startswith(BAR + "│ ") and not ln.plain.startswith(BAR + "│ ↔")]
    assert len(table) == 8, [ln.plain for ln in lines]
    for n in range(8):
        assert table[n].startswith(BAR + "│ " + OT[f"B.ULONG_FF0000.pending0x12.line{n}"]), (n, table[n])
    assert OT["B.ULONG_FF0000.pending0x12.width"] == 75
    assert "hex" in table[0] and "hex" not in table[4], "the hex column is on the first block only"


# ============================================================================== R-PE-DEF.35, .102, .110, .111, .79 - the hex grid


def test_r_pe_def_35_1_a_text_row_at_start_shows_the_hex_grid_16_per_row(v171):
    """R-PE-DEF.35/1 (EX-8B-T1) - V171 ASCII at start -> `T.V171.start.line0..3` inside the card (head + 3 rows)."""
    row, _ = make_row(v171["def"], v171["a2l"], v171["image"])
    lines = painted(row)
    for n in range(4):
        assert at(lines, 2 + n).startswith(BAR + "│ " + OT[f"T.V171.start.line{n}"]), (n, at(lines, 2 + n))


def test_r_pe_def_35_2_pending_bytes_are_in_the_pending_colour_and_the_others_are_not(v171):
    """R-PE-DEF.35/2 (EX-8B-T2) - pending `ABC` -> row `+00` is `T.V171.pendingABC.line1`; offsets 0..9 bold #b565f3."""
    row, pv = row_and_preview(v171["def"], v171["a2l"], v171["image"], "ABC")
    lines = painted(row, pv)
    assert at(lines, 3).startswith(BAR + "│ " + OT["T.V171.pendingABC.line1"])
    changed = OT["T.V171.pendingABC.changed_offsets"]
    assert changed == list(range(10))
    for offset, guide, cols, ascii_col, ln in hex_rows(lines):
        for index, column in enumerate(cols):
            style = style_at(ln, column)
            pending = offset + index in changed
            assert (hex_of(style.color) == PENDING_COLOUR and bool(style.bold)) == pending, (offset + index, ln.plain)


def test_r_pe_def_102_1_the_changed_bytes_and_their_ascii_are_underlined(v171):
    """R-PE-DEF.102/1 (EX-8B-T2) - V171 pending `ABC` -> offsets 0..9 and their ASCII characters underlined, no other."""
    row, pv = row_and_preview(v171["def"], v171["a2l"], v171["image"], "ABC")
    rows = hex_rows(painted(row, pv))
    assert len(rows) == 3
    under_hex, under_ascii = [], []
    for offset, guide, cols, ascii_col, ln in rows:
        for index, column in enumerate(cols):
            if style_at(ln, column).underline:
                under_hex.append(offset + index)
        count = len(cols)
        for index in range(count):
            if style_at(ln, ascii_col + index).underline:
                under_ascii.append(offset + index)
    expected = OT["T.V171.pendingABC.changed_offsets"]
    assert under_hex == expected and under_ascii == expected


def test_r_pe_def_102_1_nothing_is_underlined_before_an_edit(v171):
    """R-PE-DEF.102/1 negative control - V171 at start: no byte and no ASCII character is underlined."""
    row, _ = make_row(v171["def"], v171["a2l"], v171["image"])
    rows = hex_rows(painted(row))
    assert len(rows) == 3
    assert not any(style_at(ln, c).underline for _, _, cols, a, ln in rows for c in cols + [a])


def test_r_pe_def_110_1_the_ascii_guide_is_on_the_same_column_of_every_row_of_a_short_last_row(v171):
    """R-PE-DEF.110/1 (EX-8B-T1) - V171 (42 B, a last row of 10) -> the `│` before the ASCII column at 56 on all 4 lines.

    Positions are read from the painted text: the guide column, less the card's `  ┊ │ ` lead, is the oracle's 56.
    """
    row, _ = make_row(v171["def"], v171["a2l"], v171["image"])
    lines = painted(row)
    lead = len(BAR + "│ ")
    guides = []
    for ln in lines[2:6]:
        plain = ln.plain.rstrip()
        guides.append(plain.rfind("│", 0, len(plain) - 1) - lead)
    assert guides == OT["T.V171.start.ascii_guide_cols"] == [56, 56, 56, 56]


def test_r_pe_def_111_1_a_byte_outside_the_printable_range_shows_a_dot_in_the_ascii_column(v171):
    """R-PE-DEF.111/1 (EX-8B-T3) - bytes `00 1B 7F 80 FF 41 20 7E` -> `·····A ~`; no ESC or DEL reaches the screen."""
    d = widen(v171["def"], 8)
    hostile = bytes([0x00, 0x1B, 0x7F, 0x80, 0xFF, 0x41, 0x20, 0x7E])
    image = {d.address + i: b for i, b in enumerate(hostile)}
    row, _ = make_row(d, v171["a2l"], image)
    lines = painted(row)
    found = hex_rows(lines)
    assert len(found) == 1, [ln.plain for ln in lines]
    (offset, guide, cols, ascii_col, ln), = found
    assert ln.plain[ascii_col:ascii_col + 8] == OT["T.hostile.ascii"] == "·····A ~"
    for line in lines:
        assert not any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in line.plain), line.plain


def test_r_pe_def_79_4_a_span_over_64_bytes_ends_its_card_with_the_cut_line(v171):
    """R-PE-DEF.79 kept (EX-8B-T3) - 65 bytes -> the last card row is `… 1 more B`, then the bottom frame."""
    d = widen(v171["def"], 65)
    row, _ = make_row(d, v171["a2l"], SpanImage(d.address, 65, 0x41))
    lines = painted(row)
    assert at(lines, -2).startswith(BAR + "│ " + OT["T.span65.more"])
    assert at(lines, -1).startswith(BAR + "╰")
    assert len(hex_rows(lines)) == 4, "4 rows of 16 bytes, never the 65th"


# ============================================================================== R-PE-DEF.112, .115, .116 - hostile card text


def test_r_pe_def_112_1_a_300_entry_enum_is_cut_at_the_card_cap_with_one_ellipsis(defc):
    """R-PE-DEF.112/1 (EX-8B-K3) - an enum of 300 entries -> the options row is 139 cells and ends `… │`.

    Without a cap the row is thousands of cells and the sheet's scroller would run to the end of it.
    """
    d = defc["defs"]["ENUM_0001"]
    entries = tuple(EnumEntry(float(i), None, f"STATE_{i}") for i in range(300))
    row = enum_row(defc, name="BIG_ENUM", enum_entries=entries, default_text=None)
    lines = painted(row)
    expected = OT["E.card.300_entries.line1"].replace("( ) 1 STATE_1", "(●) 1 STATE_1")  # ENUM_0001's image holds 1
    assert expected != OT["E.card.300_entries.line1"] and d.enum_entries
    assert at(lines, 2).startswith(BAR + expected)
    assert cell_len(expected) == OT["E.card.300_entries.width"] == OT["E.card.cap.V111"] == 139
    assert expected.endswith("… │") and expected.count("…") == 1
    assert len(lines) == 5, "cut, never wrapped"


def test_r_pe_def_112_2_a_300_character_name_cuts_the_title_not_the_frame(defc):
    """R-PE-DEF.112/2 (EX-8B-K3) - a 300-character name -> the card's top line is 139 cells, the title ends `…`."""
    row = enum_row(defc, name="N" * 300)
    top = at(painted(row), 1)
    assert top.startswith(BAR + "╭─ NNN")
    card = top[len(BAR):].rstrip()
    assert cell_len(card) == OT["E.card.cap.V111"] == 139
    assert card.endswith("─╮") and "… ─" in card and card.count("…") == 1
    assert "choose one" not in card, "the suffix was cut away with the tail of the title"


def test_r_pe_def_115_1_an_escape_in_the_card_title_is_painted_as_the_replacement_character(defc):
    """R-PE-DEF.115/1 (EX-8B-K4) - an enum named `A\\x1b[2J` -> `E.card.name_esc.line0` (`A�[2J`), no ESC painted."""
    row = enum_row(defc, name="A\x1b[2J")
    lines = painted(row)
    assert at(lines, 1).startswith(BAR + OT["E.card.name_esc.line0"])
    assert all("\x1b" not in ln.plain for ln in lines)


def test_r_pe_def_115_2_an_escape_in_a_card_row_is_painted_as_the_replacement_character(defc):
    """R-PE-DEF.115/2 (EX-8B-K4) - an enum entry text `A\\x1b[2J` -> `E.card.row_esc.line1`, no ESC painted."""
    lines = painted(enum_with_first_text(defc, "A\x1b[2J"))
    assert at(lines, 2).startswith(BAR + OT["E.card.row_esc.line1"])
    assert all("\x1b" not in ln.plain for ln in lines)


def test_r_pe_def_115_2_card_lines_cleans_a_raw_row_it_is_handed():
    """R-PE-DEF.115/2 (E5, X8b: the shipped enum rows are cleaned before they reach the card, so a card that left
    its rows raw survived every node) - ``card_lines`` handed a row holding ``\x1b`` paints ``A�[2J``, no ESC.
    Why: the card is the contract that every row it paints is plain text, whoever builds the rows."""
    lines = ds.card_lines("T", [Text("A\x1b[2J")], 60)
    assert "A\ufffd[2J" in lines[1].plain, lines[1].plain
    assert all("\x1b" not in line.plain for line in lines)


def test_r_pe_def_115_3_a_markup_tag_in_a_card_row_is_literal_text_with_no_action(defc):
    """R-PE-DEF.115/3 (EX-8B-K4) - an entry text `[@click=app.quit]OFF[/]` -> `E.card.markup.line1`, literally, no link."""
    lines = painted(enum_with_first_text(defc, "[@click=app.quit]OFF[/]"))
    assert at(lines, 2).startswith(BAR + OT["E.card.markup.line1"])
    for ln in lines:
        for span in ln.spans:
            style = span.style
            assert "@click" not in str(style)
            assert not (getattr(style, "link", None) or getattr(style, "meta", None)), ln.plain


def test_r_pe_def_116_1_a_wide_character_title_is_cut_by_cells_to_the_card_cap(defc):
    """R-PE-DEF.116/1 (EX-8B-K5) - an enum named `温度`×200 -> `E.card.name_wide200.line0`: 139 cells in 73 characters."""
    row = enum_row(defc, name="温度" * 200)
    top = at(painted(row), 1)
    card = OT["E.card.name_wide200.line0"]
    assert top.startswith(BAR + card)
    assert cell_len(card) == OT["E.card.name_wide200.line0.cells"] == 139
    assert len(card) == OT["E.card.name_wide200.line0.chars"] == 73
    assert OT["E.card.name_wide200.title_ends_with_ellipsis"] is True
    assert cell_len(top) == max(GRID, V), "the painted line is not a cell wider than the grid"


def test_r_pe_def_116_2_a_wide_row_keeps_the_frame_square_in_79_cells(defc):
    """R-PE-DEF.116/2 (EX-8B-K5) - an entry text `温度` -> `E.card.enum_wide.line0..3`, 79 cells each (`│` under `╮`)."""
    lines = painted(enum_with_first_text(defc, "温度"))
    for n in range(4):
        card = OT[f"E.card.enum_wide.line{n}"]
        assert OT[f"E.card.enum_wide.line{n}.cells"] == 79 == cell_len(card)
        assert at(lines, 1 + n).startswith(BAR + card), (n, at(lines, 1 + n))
        assert cell_len(at(lines, 1 + n).rstrip()) == len(BAR) + 79
    assert len(OT["E.card.enum_wide.line1"]) == OT["E.card.enum_wide.line1.chars"] == 77, "77 characters, 79 cells"


def test_r_pe_def_116_3_a_wide_row_longer_than_the_cap_is_cut_by_cells(defc):
    """R-PE-DEF.116/3 (EX-8B-K5) - an entry text `温度`×100 -> `E.card.enum_wide100.line1`, 139 cells, ends `… │`."""
    lines = painted(enum_with_first_text(defc, "温度" * 100))
    expected = OT["E.card.enum_wide100.line1"]
    assert at(lines, 2).startswith(BAR + expected)
    assert cell_len(expected) == OT["E.card.enum_wide100.line1.cells"] == 139 and expected.endswith("… │")
    assert cell_len(at(lines, 2)) == max(GRID, V)


# ============================================================================== R-PE-DEF.107, R-PE-BENCH.5 - the expanded object


def test_r_pe_def_107_1_the_one_line_of_a_number_row_is_on_the_bar_and_the_expanded_ground(defc):
    """R-PE-DEF.107/1 (EX-8B-E1) - DISPLAY_0001 at V = 111 -> `  ┊ └ LINEAR …`, ground #1b233a over cells 0..142.

    V-11: the expanded object stands apart from the table; a ground that stops with the text leaves a ragged edge.
    """
    d = defc["defs"]["DISPLAY_0001"]
    row, _ = make_row(d, defc["a2l"], defc["image"])
    found = painted(row)
    assert len(found) == 1, [ln.plain for ln in found]
    (line,) = found
    assert line.plain.startswith(
        BAR + f"└ LINEAR phys = 0.5*raw · SWORD s16 big-endian · 0x{d.address:08X} · {d.byte_length} B"
    )
    assert cell_len(line.plain) == len(line.plain) == OT["G.grid_width"] == 143
    grounds = {hex_of(style_at(line, i).bgcolor) for i in range(len(line.plain))}
    assert grounds == {EXPANDED_GROUND}, "every cell 0..142 carries the expanded ground, the padding included"


def test_r_pe_def_107_2_every_card_line_of_a_mask_row_follows_the_bar(defc):
    """R-PE-DEF.107/2 (EX-8B-E1) - MASK_FIELD_0001 -> the definition line and every card line start with the bar."""
    row, pv = with_pending(defc, "MASK_FIELD_0001", "255")
    lines = painted(row, pv)
    assert len(lines) == 7
    assert all(ln.plain.startswith(BAR) and cell_len(ln.plain) == 143 for ln in lines)


def test_r_pe_def_107_3_every_bench_line_of_an_array_row_follows_the_bar(defc):
    """R-PE-DEF.107/3 (EX-8B-E1) - MAP_DEF_0001 (bench) -> every bench line after `  ┊ `, the first being `└ `."""
    o = defc_obj(defc, "MAP_DEF_0001")
    lines = painted(sheet_row(o.d, o.a2l, o.image), None, V, ROOM, view_state(o))
    assert len(lines) > 1 and at(lines, 0).startswith(BAR + "└ ")
    assert all(ln.plain.startswith(BAR) for ln in lines), [ln.plain[:8] for ln in lines]
    assert all(cell_len(ln.plain) == 143 for ln in lines), "the expanded ground runs to the grid width"


def test_r_pe_def_107_4_a_definition_line_wider_than_the_cut_is_cut_at_139_cells(defc):
    """R-PE-DEF.107/4 (EX-8B-E1) - a 250-character record layout name -> the content is 139 cells and ends `…`."""
    d = replace(defc["defs"]["DISPLAY_0001"], record_layout="R" * 250)
    row, _ = make_row(d, defc["a2l"], defc["image"])
    found = painted(row)
    assert len(found) == 1
    (line,) = found
    content = line.plain[len(BAR):].rstrip()
    assert cell_len(content) == OT["G.detail_cap.V111"] == 139
    assert content.endswith("…") and content.count("…") == 1
    assert cell_len(line.plain) == 143


@pytest.mark.parametrize("view, key", [(70, "80"), (110, "118"), (194, "220")])
def test_r_pe_bench_5_1_2_3_no_bench_line_is_wider_than_the_view(defc, tmp_path, view, key):
    """R-PE-BENCH.5/1..3 (EX-8B-E2) - at 80, 118 and 220 columns (V 70, 110, 194, measured at E4): MAP_DEF_0001 and LARGE, bar + fit."""
    assert OT[f"G.view.{key}cols"] == view
    o = defc_obj(defc, "MAP_DEF_0001")
    lines = painted(sheet_row(o.d, o.a2l, o.image), None, view, ROOM, view_state(o))
    assert lines and all(ln.plain.startswith(BAR) for ln in lines)
    assert max(cell_len(ln.plain.rstrip()) for ln in lines) <= view
    a2l, d = large_definition(tmp_path)
    from s19_app.tui import definition_bench as db
    from s19_app.tui import definition_bench_view as dv

    state = blank_state(values=big_values(db.bench_grid(d).count), labels=dv.axis_labels(d, (), db.bench_grid(d)))
    lines = painted(sheet_row(d, a2l, {}), None, view, ROOM, state)
    assert lines and all(ln.plain.startswith(BAR) for ln in lines)
    assert max(cell_len(ln.plain.rstrip()) for ln in lines) <= view


def test_r_pe_bench_5_4_room_one_shows_the_definition_line_only(defc):
    """R-PE-BENCH.5/4 (EX-8B-E2) - room 1 -> the definition line only (after the bar)."""
    o = defc_obj(defc, "MAP_DEF_0001")
    lines = painted(sheet_row(o.d, o.a2l, o.image), None, V, 1, view_state(o))
    assert len(lines) == 1 and at(lines, 0).startswith(BAR + "└ ")


def test_r_pe_bench_5_5_room_zero_shows_no_bench_line_and_no_exception(defc):
    """R-PE-BENCH.5/5 (EX-8B-E2) - room 0 -> no line at all. Holds on base too (a regression guard, not a RED)."""
    o = defc_obj(defc, "MAP_DEF_0001")
    assert painted(sheet_row(o.d, o.a2l, o.image), None, V, 0, view_state(o)) == []


def test_r_pe_bench_5_5_room_zero_at_a_narrow_view_shows_no_bench_line(defc):
    """R-PE-BENCH.5/5 (E5, X8b: at V = 111 every return path is cut to ``room`` anyway, so the room guard was not
    observable) - room 0 at a 12-cell view (the kind lays out for 8 cells, under the 12-cell narrow path) -> no line."""
    o = defc_obj(defc, "MAP_DEF_0001")
    assert painted(sheet_row(o.d, o.a2l, o.image), None, 12, 0, view_state(o)) == []
