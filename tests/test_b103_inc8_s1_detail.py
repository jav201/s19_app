"""Batch-103 Inc 8 E4, group S1 - the pure sheet model, part 2 (preview, detail, formula bar).

Design under test: ``.dev-flow/2026-11-05-batch-103/inc-8/01-requirements.md``
(rows R-PE-DEF.24, .25, .31 ... .36, .38 ... .41, .51, .78 ... .80, .88) through
``s19_app/tui/definition_sheet.py`` (new): nodes S6 ``preview``, S10/S10'
``detail_lines``, S11 ``formula_tail``, S21 ``formula_fill``, and the I-8.5 text
row bound. One test per case of ``inc-8/02-test-cases-S1.md``.

Expected values: the requirement's texts, the committed examples file (via
``tests/support/b103_inc8_s1.py``) and I-2 (``encode_definition`` results); no
position is counted by hand.
"""

from __future__ import annotations

import re

import pytest
from rich.cells import cell_len
from rich.console import Console

from s19_app.tui import definition_sheet as ds
from s19_app.tui.a2l_definition import Encoded, Refusal
from tests.support.b103_inc8_s1 import (  # noqa: F401  (fixtures are used by name)
    EX,
    SpanImage,
    defc,
    hex_bytes,
    replace,
    span_bytes,
    stage_entry,
    v171,
    widen,
)
from tests.support.b103_inc8b_r import EXB, GRID_WIDTH, content, fact

CONSOLE = Console(force_terminal=True, color_system="truecolor", width=400)
ROOM = 50  # body lines left for a detail: never the limit in these cases
WIDE = 200


def make_row(definition, a2l, image, entries=()):
    overlay = ds.StagedOverlay(image, list(entries))
    return ds.build_row(definition, a2l, image, overlay), overlay


def row_and_preview(definition, a2l, image, text, entries=()):
    row, overlay = make_row(definition, a2l, image, entries)
    return row, ds.preview(definition, a2l, text, overlay)


def lines_of(row, pv, width=WIDE):
    """The expanded object's lines as content: Inc 8b puts the bar `  ┊ ` and the ground on every one (R-PE-DEF.107)."""
    return [content(t.plain) for t in ds.detail_lines(row, pv, width, None, ROOM)]


def cap_of(width=WIDE):
    return max(GRID_WIDTH, width) - 4


# ==========================================================================
# R-PE-DEF.24, .25, .40, .51 - the preview (S6)
# ==========================================================================


def test_r_pe_def_24_preview_of_a_number_is_the_i2_encode_and_its_decode_text(defc):
    """R-PE-DEF.24/1 - DISPLAY_0001 `25.5` and `25.50` -> the I-2 Encoded; decoded text `25.5`."""
    d, a2l, img = defc["defs"]["DISPLAY_0001"], defc["a2l"], defc["image"]
    address, data = stage_entry(d, a2l, "25.5", img)
    for typed in ("25.5", "25.50"):
        _, pv = row_and_preview(d, a2l, img, typed)
        assert isinstance(pv.result, Encoded)
        assert (pv.result.address, bytes(pv.result.data)) == (address, data)
        assert pv.decoded.text == "25.5", "the preview's text, not the typed text"


def test_r_pe_def_24_preview_of_an_enum_text_decodes_to_stored_and_text(defc):
    """R-PE-DEF.24/2 - ENUM_0001 `RUN` -> Encoded, decoded stored 2 and text `RUN`."""
    _, pv = row_and_preview(defc["defs"]["ENUM_0001"], defc["a2l"], defc["image"], "RUN")
    assert isinstance(pv.result, Encoded)
    assert (pv.decoded.stored, pv.decoded.value) == (2, "RUN")


@pytest.mark.parametrize("name, text, code", [
    ("DISPLAY_0001", "abc", "A2L-DEF-NUMBER"),
    ("DISPLAY_0001", "250", "A2L-DEF-EXTENDED"),
    ("ENUM_0001", "WALK", "A2L-DEF-ENUM"),
    ("ENUM_0001", "2", "A2L-DEF-ENUM"),
])
def test_r_pe_def_56_preview_of_a_refused_text_carries_the_refusal_and_no_decode(defc, name, text, code):
    """R-PE-DEF.25/1, .27, .47 - `abc`, `250`, `WALK` and a stored number `2` refuse; decoded is None."""
    _, pv = row_and_preview(defc["defs"][name], defc["a2l"], defc["image"], text)
    assert isinstance(pv.result, Refusal) and pv.result.code == code
    assert pv.decoded is None


def test_r_pe_def_40_preview_of_a_175_keeps_the_notice(defc):
    """R-PE-DEF.40/2 - DISPLAY_0001 `175` -> an Encoded that carries I-2's one notice."""
    _, pv = row_and_preview(defc["defs"]["DISPLAY_0001"], defc["a2l"], defc["image"], "175")
    assert isinstance(pv.result, Encoded) and len(pv.result.notices) == 1


def test_r_pe_def_51_the_second_masked_field_is_encoded_over_the_first_staged_one(defc):
    """R-PE-DEF.51/1 - MASK_FIELD `255` staged, then MASK_BIT `0` -> `1F F6`, not the bare image's `1A E6`."""
    a2l, img = defc["a2l"], defc["image"]
    field, bit = defc["defs"]["MASK_FIELD_0001"], defc["defs"]["MASK_BIT_0001"]
    entries = [stage_entry(field, a2l, "255", img)]
    _, pv = row_and_preview(bit, a2l, img, "0", entries)
    assert hex_bytes(pv.result.data) == hex_bytes(EX.after_both.to_bytes(2, "big")) == "1F F6"
    _, over_image = row_and_preview(bit, a2l, img, "0")
    assert hex_bytes(over_image.result.data) != "1F F6", "negative control: over the bare image the field reverts"
    assert pv.decoded.text == "0"


def test_r_pe_def_51_the_reverse_order_gives_the_same_word(defc):
    """R-PE-DEF.51/2 - MASK_BIT `0` staged, then MASK_FIELD `255` -> `1F F6`; the bit stays 0."""
    a2l, img = defc["a2l"], defc["image"]
    field, bit = defc["defs"]["MASK_FIELD_0001"], defc["defs"]["MASK_BIT_0001"]
    entries = [stage_entry(bit, a2l, "0", img)]
    _, pv = row_and_preview(field, a2l, img, "255", entries)
    assert hex_bytes(pv.result.data) == "1F F6"
    assert pv.decoded.text == "255"


# ==========================================================================
# R-PE-DEF.31 ... .35, .79 - the detail lines (S10, S10')
# ==========================================================================


def test_r_pe_def_31_definition_line_of_a_number(defc):
    """R-PE-DEF.31/1 - DISPLAY_0001 -> `└ LINEAR phys = 0.5*raw · SWORD s16 big-endian · 0x00800020 · 2 B`."""
    d = defc["defs"]["DISPLAY_0001"]
    row, _ = make_row(d, defc["a2l"], defc["image"])
    assert lines_of(row, None) == [f"└ LINEAR phys = 0.5*raw · SWORD s16 big-endian · 0x{d.address:08X} · {d.byte_length} B"]


def test_r_pe_def_31_definition_line_of_an_enum(defc):
    """R-PE-DEF.31/2 - ENUM_0001 -> `└ TAB_VERB 4 pairs · UBYTE u8 big-endian · 0x00800000 · 1 B` first."""
    d = defc["defs"]["ENUM_0001"]
    row, _ = make_row(d, defc["a2l"], defc["image"])
    assert lines_of(row, None)[0] == f"└ TAB_VERB {len(d.enum_entries)} pairs · UBYTE u8 big-endian · 0x{d.address:08X} · 1 B"


def test_r_pe_def_31_definition_line_of_a_bit_mask_names_the_masked_word(defc):
    """R-PE-DEF.31/3 - MASK_FIELD_0001 -> `└ IDENTICAL phys = (word & 0x0FF0) >> 4 · UWORD u16 big-endian · 0x00800010 · 2 B`."""
    d = defc["defs"]["MASK_FIELD_0001"]
    row, _ = make_row(d, defc["a2l"], defc["image"])
    shift = (d.bit_mask & -d.bit_mask).bit_length() - 1
    assert lines_of(row, None)[0] == (
        f"└ IDENTICAL phys = (word & 0x{d.bit_mask:04X}) >> {shift} · UWORD u16 big-endian · 0x{d.address:08X} · 2 B"
    )


def test_r_pe_def_31_definition_line_of_a_text_row(v171):
    """R-PE-DEF.31/4 - V171 ASCII -> `└ text · 0x00810200 · 42 B` first."""
    d = v171["def"]
    row, _ = make_row(d, v171["a2l"], v171["image"])
    assert lines_of(row, None)[0] == f"└ text · 0x{d.address:08X} · {d.byte_length} B"


def test_r_pe_def_31_a_named_record_layout_comes_after_the_byte_order(defc):
    """R-PE-DEF.31/5 - a DISPLAY_0001 copy naming record layout `RL_U16` -> `… big-endian · RL_U16 · 0x00800020 · 2 B`."""
    d = replace(defc["defs"]["DISPLAY_0001"], record_layout="RL_U16")
    row, _ = make_row(d, defc["a2l"], defc["image"])
    assert lines_of(row, None) == [
        f"└ LINEAR phys = 0.5*raw · SWORD s16 big-endian · RL_U16 · 0x{d.address:08X} · 2 B"
    ]


def test_r_pe_def_32_a_refused_row_shows_its_message_as_the_detail(defc):
    """R-PE-DEF.32/1 (real I-2 refusal: an unknown name) - the one detail line `└ <message>`."""
    from s19_app.tui.a2l_definition import describe_definition

    refused = describe_definition("NO_SUCH_PARAMETER_0001", defc["a2l"])
    row, _ = make_row(refused, defc["a2l"], defc["image"])
    assert lines_of(row, None) == ["└ " + ds.plain(refused.refusal.message)]


def _enum_options(d, chosen):
    parts = [f"({'●' if e.raw == chosen else ' '}) {int(e.raw)} {e.text}" for e in d.enum_entries]
    return "   ".join(parts) + f'   default "{d.default_text}"'


def test_r_pe_def_33_enum_options_mark_the_current_entry_and_end_with_the_hint(defc):
    """R-PE-DEF.33/1 (changed at Inc 8b E1) - ENUM_0001 at start: the definition line, then the card `E.card.ENUM_0001.line0..3`.

    Why: the operator wants the enum choice set apart in B's frame; the options row still marks the
    current entry `(●) 1 IDLE`, shows the default, and the second row is the key hint.
    """
    d = defc["defs"]["ENUM_0001"]
    row, _ = make_row(d, defc["a2l"], defc["image"])
    lines = lines_of(row, None)
    assert len(lines) == 5
    assert lines[1:] == [fact(f"E.card.ENUM_0001.line{n}") for n in range(4)]
    assert lines[1:] == EXB.card(f"{d.name} · choose one", [_enum_options(d, 1), "↔ choose · enter stage"], cap_of())
    assert "(●) 1 IDLE" in lines[2] and 'default "UNKNOWN_STATE"' in lines[2] and "↔ choose · enter stage" in lines[3]


def test_r_pe_def_33_enum_options_follow_the_previewed_choice(defc):
    """R-PE-DEF.33/2 - after choosing RUN the card's options row marks `(●) 2 RUN` and not IDLE."""
    d, a2l, img = defc["defs"]["ENUM_0001"], defc["a2l"], defc["image"]
    row, pv = row_and_preview(d, a2l, img, "RUN")
    lines = lines_of(row, pv)
    assert lines[1:] == EXB.card(f"{d.name} · choose one", [_enum_options(d, 2), "↔ choose · enter stage"], cap_of())
    assert "(●) 2 RUN" in lines[2] and "(●) 1 IDLE" not in lines[2]


def _mask_card(d, before, after):
    """The oracle's bit-mask card for a masked word (bytes before, bytes after)."""
    return EXB.card(f"{d.name} · bit editor · other bits kept", EXB.bit_table(before, after, d.bit_mask), cap_of())


def test_r_pe_def_34_bit_strip_shows_the_word_before_and_after(defc):
    """R-PE-DEF.34/1 (changed at Inc 8b E1) - MASK_FIELD_0001 at start -> the bit table in its card (`B.MASK_FIELD_0001.start.line0..3`).

    Why: bit by bit the operator must see the word before, the mask and the word after, with nibble guides;
    Inc 8's one-line strip (`bit 15…0 …   word 1A E7 → 1A E7`) is retired.
    """
    d, a2l, img = defc["defs"]["MASK_FIELD_0001"], defc["a2l"], defc["image"]
    row, _ = make_row(d, a2l, img)
    lines = lines_of(row, None)
    word = span_bytes(d, img)
    assert hex_bytes(word) == "1A E7"
    table = [fact(f"B.MASK_FIELD_0001.start.line{n}") for n in range(4)]
    assert lines[1] == _mask_card(d, word, word)[0] and lines[0].startswith("└ ")
    assert [ln[2:-2].rstrip() for ln in lines[2:6]] == [t.rstrip() for t in table]
    assert lines[1:] == _mask_card(d, word, word) and len(lines) == 7


def test_r_pe_def_34_bit_strip_after_word_is_the_whole_masked_word_not_the_field(defc):
    """R-PE-DEF.34/2 (changed at Inc 8b E1) - pending 255 -> the card `B.card.MASK_FIELD_0001.line0..5`, its after row ending `1F F7`.

    Why: the after row is the whole word with the field replaced and the other bits kept (1F F7), never the
    field alone (the Inc 8 negative control: reading the unmasked word only gives 1A E7).
    """
    d, a2l, img = defc["defs"]["MASK_FIELD_0001"], defc["a2l"], defc["image"]
    row, pv = row_and_preview(d, a2l, img, "255")
    after = f"{EX.after_field:04X}"
    expect_after = f"{after[:2]} {after[2:]}"
    lines = lines_of(row, pv)
    assert expect_after == "1F F7"
    assert lines[1:] == [fact(f"B.card.MASK_FIELD_0001.line{n}") for n in range(6)]
    assert lines[1:] == _mask_card(d, span_bytes(d, img), bytes.fromhex(after))
    assert lines[-2].rstrip(" │").endswith(expect_after)


_HEX_TOKEN = re.compile(r"(?<= )[0-9A-F]{2}(?= |$)")
_DATA_ROW = re.compile(r"│ \+[0-9A-F]{2} │")


def _token_styles(text):
    """(hex token, resolved style) per byte token of the hex area of one hex-grid row.

    The hex area ends at the ASCII guide (the second `│` from the right, the last is the card frame); the
    style is the one the terminal paints (base style and every span combined), so it does not depend on
    how the card ground is composed.
    """
    plain = text.plain
    area_end = plain.rindex("│", 0, plain.rindex("│"))
    return [(m.group(), text.get_style_at_offset(CONSOLE, m.start()))
            for m in _HEX_TOKEN.finditer(plain[:area_end])]


def _data_rows(out):
    return [t for t in out if _DATA_ROW.match(t.plain.split("┊ ", 1)[-1])]


def _text_card(d, before, after):
    return EXB.card(f"{d.name} · text editor · 16 B per row", EXB.hex_grid(before, after), cap_of())


def test_r_pe_def_35_text_rows_show_the_image_bytes_16_per_row(v171):
    """R-PE-DEF.35/1 (changed at Inc 8b E1) - V171 ASCII at start -> the hex grid in its card (`T.V171.start.line0..3`), no pending style.

    Why: the operator reads a text span as bytes and characters side by side, 16 per row with the ASCII
    guide at one column; Inc 8's `+00 <bytes>` rows had no ASCII column.
    """
    d, img = v171["def"], v171["image"]
    row, _ = make_row(d, v171["a2l"], img)
    out = ds.detail_lines(row, None, WIDE, None, ROOM)
    data = span_bytes(d, img)
    lines = [content(t.plain) for t in out]
    assert lines[1:] == _text_card(d, data, data)
    assert [ln[2:-2].rstrip() for ln in lines[3:-1]] == [fact(f"T.V171.start.line{n}") for n in range(1, 4)]
    rows = _data_rows(out)
    assert [t.plain.split("│")[1].strip() for t in rows] == [f"+{o:02X}" for o in range(0, d.byte_length, 16)]
    for t, o in zip(rows, range(0, d.byte_length, 16)):
        assert [tok for tok, _ in _token_styles(t)] == [f"{b:02X}" for b in data[o:o + 16]]
    # Inc 8b (graph-inc8b `hex_grid`): zero bytes are dim, so with nothing pending each byte class (zero,
    # non-zero) has one style, none underlined.
    by_class: dict = {}
    for t in rows:
        for token, style in _token_styles(t):
            by_class.setdefault(token == "00", set()).add(style)
    assert all(len(styles) == 1 for styles in by_class.values()), "nothing pending, one style per byte class"
    assert not any(style.underline for styles in by_class.values() for style in styles)


def test_r_pe_def_35_pending_text_rows_paint_the_changed_bytes_in_one_other_style(v171):
    """R-PE-DEF.35/2 (changed at Inc 8b E1) - pending `ABC` -> `T.V171.pendingABC.line1` (`+00 │ 41 42 43 00 …`); the 10 changed bytes share a style the others lack."""
    d, a2l, img = v171["def"], v171["a2l"], v171["image"]
    row, pv = row_and_preview(d, a2l, img, "ABC")
    assert bytes(pv.result.data) == EX.after
    out = ds.detail_lines(row, pv, WIDE, None, ROOM)
    rows = _data_rows(out)
    assert content(rows[0].plain)[2:-2].rstrip() == fact("T.V171.pendingABC.line1")
    assert rows[0].plain.split("│")[2].split() [:4] == [f"{b:02X}" for b in EX.after[:4]]
    changed = [i for i, (a, b) in enumerate(zip(EX.before, EX.after)) if a != b]
    assert changed == fact("T.V171.pendingABC.changed_offsets") and len(changed) == 10
    flat = [tok for t in rows for tok in _token_styles(t)]
    assert len(flat) == d.byte_length
    pending_styles = {flat[i][1] for i in changed}
    other_styles = {flat[i][1] for i in range(len(flat)) if i not in changed}
    assert len(pending_styles) == 1 and pending_styles.isdisjoint(other_styles)


@pytest.mark.parametrize("length", [65, 4097, 1048576])
def test_r_pe_def_79_a_long_text_span_shows_four_rows_and_the_cut_line(v171, length):
    """R-PE-DEF.79/1..3 (changed at Inc 8b E1) - 65, 4,097 and 1,048,576 bytes -> 4 hex rows, `… <n-64> more B` as the card's last row, 9 detail lines in all.

    Why: a huge span must never be read or painted whole; the operator sees the first 64 bytes and how
    many more there are, inside the same frame (definition line, top, head, 4 rows, cut row, bottom).
    """
    d = widen(v171["def"], length)
    img = SpanImage(d.address, length, 0x41)
    row, _ = make_row(d, v171["a2l"], img)
    out = lines_of(row, None)
    assert len(out) == 9
    assert out[0] == f"└ text · 0x{d.address:08X} · {length} B"
    assert [ln.split("│")[1].strip() for ln in out[3:7]] == ["+00", "+10", "+20", "+30"]
    assert out[7][2:-2].rstrip() == f"… {length - 64} more B"
    assert img.lookups < 1000, "only the first 64 bytes are read, never the span"


def test_r_pe_def_79_a_span_of_exactly_64_bytes_has_no_cut_line(v171):
    """R-PE-DEF.79 boundary - 64 bytes -> definition line and the card (top, head, 4 rows, bottom) = 8 lines, no cut row."""
    d = widen(v171["def"], 64)
    row, _ = make_row(d, v171["a2l"], SpanImage(d.address, 64, 0x41))
    out = lines_of(row, None)
    assert len(out) == 8 and not any("more B" in ln for ln in out)


def test_r_pe_def_35_text_rows_of_a_refused_row_are_not_painted(defc):
    """R-PE-DEF.32 - a refused row gives its message line only (no kind lines)."""
    from s19_app.tui.a2l_definition import describe_definition

    refused = describe_definition("NO_SUCH_PARAMETER_0001", defc["a2l"])
    row, _ = make_row(refused, defc["a2l"], defc["image"])
    assert len(lines_of(row, None)) == 1


def test_r_pe_def_31_a_fallback_row_gives_the_definition_line_only(defc):
    """I-8.5 fallback detail - the `cuboid` copy: the definition line, nothing else."""
    cuboid = replace(defc["defs"]["DISPLAY_0001"], kind="cuboid", element_count=24)
    row, _ = make_row(cuboid, defc["a2l"], defc["image"])
    assert len(lines_of(row, None)) == 1


# ==========================================================================
# R-PE-DEF.40, .41, .36 - the formula tail (S11)
# ==========================================================================


def test_r_pe_def_40_tail_of_an_encodable_number_names_unit_limits_raw_bytes_and_verdict(defc):
    """R-PE-DEF.40/1 - `25.5` -> `deg C  (-40 … 150)  raw 287→51 · 01 1F → 00 33  ✓ in limits  enter stage ↓`."""
    d, a2l, img = defc["defs"]["DISPLAY_0001"], defc["a2l"], defc["image"]
    row, pv = row_and_preview(d, a2l, img, "25.5")
    before, after = hex_bytes(span_bytes(d, img)), hex_bytes(pv.result.data)
    expect = (
        f"{d.unit}  ({d.limits.lower_text} … {d.limits.upper_text})  "
        f"raw {row.current.stored}→{pv.decoded.stored} · {before} → {after}  ✓ in limits  enter stage ↓"
    )
    assert (before, after) == ("01 1F", "00 33") and (row.current.stored, pv.decoded.stored) == (287, 51)
    assert ds.formula_tail(row, pv, 120).plain == expect


def test_r_pe_def_40_the_limits_words_leave_the_tail_under_110_cells(defc):
    """R-PE-DEF.40/1 - at width 100 the `(<lower> … <upper>)` words are left out, the rest is the same."""
    d, a2l, img = defc["defs"]["DISPLAY_0001"], defc["a2l"], defc["image"]
    row, pv = row_and_preview(d, a2l, img, "25.5")
    wide, narrow = ds.formula_tail(row, pv, 120).plain, ds.formula_tail(row, pv, 100).plain
    assert narrow == wide.replace("(-40 … 150)  ", "") and "(" not in narrow


def test_r_pe_def_40_tail_of_a_notice_shows_the_triangle_and_i2s_notice(defc):
    """R-PE-DEF.40/2 - `175` -> `▲ <the notice of the encode>`."""
    row, pv = row_and_preview(defc["defs"]["DISPLAY_0001"], defc["a2l"], defc["image"], "175")
    assert "▲ " + pv.result.notices[0] in ds.formula_tail(row, pv, WIDE).plain
    assert "✓" not in ds.formula_tail(row, pv, WIDE).plain


def test_r_pe_def_40_tail_of_a_refusal_shows_the_cross_and_its_message(defc):
    """R-PE-DEF.40/3 - `abc` -> `✗ DISPLAY_0001: 'abc' is not a number`."""
    row, pv = row_and_preview(defc["defs"]["DISPLAY_0001"], defc["a2l"], defc["image"], "abc")
    assert ds.formula_tail(row, pv, WIDE).plain == "✗ " + pv.result.message == "✗ DISPLAY_0001: 'abc' is not a number"


def test_r_pe_def_40_tail_of_a_text_names_the_chars_used_of_the_span(v171):
    """R-PE-DEF.40/4 - V171 ASCII `ABC` -> `3/42 chars · NUL-padded  enter stage ↓`."""
    row, pv = row_and_preview(v171["def"], v171["a2l"], v171["image"], "ABC")
    assert ds.formula_tail(row, pv, WIDE).plain == f"3/{v171['def'].byte_length} chars · NUL-padded  enter stage ↓"


@pytest.mark.parametrize("width", [100, 118, 220])
def test_r_pe_def_41_a_long_refusal_is_cut_at_the_bar_edge_with_one_ellipsis(defc, width):
    """R-PE-DEF.41/1, /2 - the `x`x300 refusal (289-character message) fits the bar and ends in `…`."""
    row, pv = row_and_preview(defc["defs"]["DISPLAY_0001"], defc["a2l"], defc["image"], "x" * 300)
    assert len(pv.result.message) == 289
    tail = ds.formula_tail(row, pv, width).plain
    assert tail.endswith("…") and not tail.endswith("……") and cell_len(tail) == width


def test_r_pe_def_36_a_row_with_no_editor_gets_the_inspector_text(defc, v171):
    """R-PE-DEF.36/2, /3 - the `cuboid` copy -> `edit VALUE objects …`; ASCII widened to 4,097 -> `edit ASCII objects …`."""
    cuboid = replace(defc["defs"]["DISPLAY_0001"], kind="cuboid", element_count=24)
    row, _ = make_row(cuboid, defc["a2l"], defc["image"])
    assert ds.formula_tail(row, None, WIDE).plain == "edit VALUE objects in the Inspector tab"
    wide = widen(v171["def"], 4097)
    row, _ = make_row(wide, v171["a2l"], SpanImage(wide.address, 4097, 0x41))
    assert ds.formula_tail(row, None, WIDE).plain == "edit ASCII objects in the Inspector tab"


def test_r_pe_def_36_a_refused_row_gets_the_inspector_text_with_its_kind_word(defc):
    """R-PE-DEF.36/1 - a refused row -> `edit <kind word> objects in the Inspector tab`."""
    from s19_app.tui.a2l_definition import describe_definition

    refused = describe_definition("NO_SUCH_PARAMETER_0001", defc["a2l"])
    row, _ = make_row(refused, defc["a2l"], defc["image"])
    assert ds.formula_tail(row, None, WIDE).plain == f"edit {ds.kind_word(refused)} objects in the Inspector tab"


def test_r_pe_def_36_the_4096_byte_text_row_keeps_its_editor_and_the_text_tail(v171):
    """R-PE-DEF.36/4 - boundary: widened to 4,096 bytes -> an editor (not the Inspector text); the text tail shows."""
    d = widen(v171["def"], 4096)
    img = SpanImage(d.address, 4096, 0x41)
    row, pv = row_and_preview(d, v171["a2l"], img, "ABC")
    tail = ds.formula_tail(row, pv, WIDE).plain
    assert "Inspector" not in tail and tail.startswith("3/4096 chars")


# ==========================================================================
# R-PE-DEF.38, .39, .78, .80 - the row fill (S21)
# ==========================================================================


def test_r_pe_def_38_a_text_row_fills_with_its_current_text_until_edited(v171):
    """R-PE-DEF.38/1, /2 - V171 ASCII -> `Hello ASAM`; with pending `ABC` -> `ABC`."""
    row, _ = make_row(v171["def"], v171["a2l"], v171["image"])
    assert ds.formula_fill(row, None) == EX.before.rstrip(b"\0").decode("ascii") == "Hello ASAM"
    assert ds.formula_fill(row, "ABC") == "ABC"


def test_r_pe_def_39_other_rows_fill_with_their_pending_text_only(defc):
    """R-PE-DEF.39/1, /2 - DISPLAY_0001 never edited -> empty; pending `25.5` -> `25.5`."""
    row, _ = make_row(defc["defs"]["DISPLAY_0001"], defc["a2l"], defc["image"])
    assert ds.formula_fill(row, None) == ""
    assert ds.formula_fill(row, "25.5") == "25.5"
    erow, _ = make_row(defc["defs"]["ENUM_0001"], defc["a2l"], defc["image"])
    assert ds.formula_fill(erow, None) == "", "an enum's base text is empty, not its current text"


@pytest.mark.parametrize("length", [4097, 1048576])
def test_r_pe_def_78_a_row_with_no_editor_fills_empty(v171, length):
    """R-PE-DEF.78/1, /2 - ASCII widened to 4,097 and 1,048,576 bytes -> `""`, never the current text."""
    d = widen(v171["def"], length)
    img = SpanImage(d.address, length, 0x41)
    row, _ = make_row(d, v171["a2l"], img)
    assert ds.formula_fill(row, None) == ""
    assert img.lookups < 1000


def test_r_pe_def_80_a_fill_is_capped_to_4096_characters(defc):
    """R-PE-DEF.80/1 - an enum row with a pending text of 5,000 characters -> its first 4,096."""
    row, _ = make_row(defc["defs"]["ENUM_0001"], defc["a2l"], defc["image"])
    got = ds.formula_fill(row, "E" * 5000)
    assert got == "E" * 4096
