"""Batch-103 Inc 8 E4, group S2: the StagingSheet's formula bar (nodes S14, S18, S19').

Rows R-PE-DEF.37 .. .42, .50 (the request the sheet posts), .78 of
``inc-8/01-requirements.md``; cases in ``inc-8/02-test-cases-S2.md``. The bar's children
are read by their order in the DOM (name, label, input, tail), the input by its pinned id
``#patch_sheet_input``. The paste tests post ``events.Paste`` to the input: the clipboard
itself is stood in by the ``no_os_clipboard`` fixture and never read.
"""
from __future__ import annotations

import asyncio
import sys

if "." not in sys.path:
    sys.path.insert(0, ".")
import s19_app

print(f"s19_app.__file__ = {s19_app.__file__}", flush=True)

import pytest
from rich.cells import cell_len
from textual import events

from tests.support.b103_inc8_s2 import (
    V171_ASCII,
    bar_label,
    bar_name,
    bar_tail,
    defc,
    fill,
    formula_input,
    no_os_clipboard,
    overlay_entries,
    select,
    show,
    sheet_ctx,
    type_keys,
    v171,
    widened,
)

import dataclasses


def run(coro_fn):
    return asyncio.run(coro_fn())


# --------------------------------------------------------------------------- R-PE-DEF.37


@pytest.mark.parametrize(
    "source, name, label",
    [
        ("defc", "DISPLAY_0001", "new ="),
        ("defc", "ENUM_0001", "new ="),
        ("defc", "MASK_FIELD_0001", "field ="),
        ("v171", V171_ASCII, "text ="),
    ],
    ids=["37-1-number", "37-2-enum", "37-3-bit-mask", "37-4-text"],
)
def test_r_pe_def_37_n_the_bar_shows_the_row_name_and_its_kind_label(request, source, name, label):
    case = request.getfixturevalue(source)
    names = tuple(case.defs)

    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, case, names=names)
            await select(pilot, sheet, name)
            assert bar_name(sheet).startswith(name)
            assert bar_label(sheet) == label

    run(drive)


# --------------------------------------------------------------------------- R-PE-DEF.38 / .39


def test_r_pe_def_38_1_a_selected_text_row_fills_the_input_with_its_text(v171):
    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, v171)
            await select(pilot, sheet, V171_ASCII)
            assert formula_input(sheet).value == "Hello ASAM"

    run(drive)


def test_r_pe_def_38_2_an_edited_text_row_keeps_its_edit_when_reselected(v171):
    other = [n for n in v171.defs if n != V171_ASCII][0]

    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, v171)
            await select(pilot, sheet, V171_ASCII)
            formula_input(sheet).value = "ABC"
            await pilot.pause()
            await select(pilot, sheet, other)
            assert formula_input(sheet).value == ""
            await select(pilot, sheet, V171_ASCII)
            assert formula_input(sheet).value == "ABC"

    run(drive)


def test_r_pe_def_39_1_a_row_never_edited_has_an_empty_input(defc):
    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc)
            assert formula_input(sheet).value == ""
            await select(pilot, sheet, "ENUM_0001")
            assert formula_input(sheet).value == ""

    run(drive)


def test_r_pe_def_39_2_a_pending_row_gets_its_pending_text_back(defc):
    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc)
            await type_keys(pilot, sheet, "25.5")
            await select(pilot, sheet, "ENUM_0001")
            assert formula_input(sheet).value == ""
            await select(pilot, sheet, "DISPLAY_0001")
            assert formula_input(sheet).value == "25.5"

    run(drive)


# --------------------------------------------------------------------------- R-PE-DEF.40 / .41


def test_r_pe_def_40_1_a_good_value_shows_the_check_tail(defc):
    expected = "deg C  (-40 … 150)  raw 287→51 · 01 1F → 00 33  ✓ in limits  enter stage ↓"

    async def drive():
        async with sheet_ctx(size=(200, 40)) as (app, pilot, sheet):
            await show(pilot, sheet, defc)
            await type_keys(pilot, sheet, "25.5")
            assert expected in bar_tail(sheet)

    run(drive)


def test_r_pe_def_40_2_a_value_between_limits_and_extended_limits_shows_the_notice(defc):
    expected = "▲ DISPLAY_0001: 175 is outside the limits -40..150 and inside the extended limits -50..200"

    async def drive():
        async with sheet_ctx(size=(200, 40)) as (app, pilot, sheet):
            await show(pilot, sheet, defc)
            await type_keys(pilot, sheet, "175")
            assert expected in bar_tail(sheet)

    run(drive)


def test_r_pe_def_40_3_a_refused_text_shows_the_refusal_message(defc):
    async def drive():
        async with sheet_ctx(size=(200, 40)) as (app, pilot, sheet):
            await show(pilot, sheet, defc)
            await type_keys(pilot, sheet, "abc")
            assert "✗ DISPLAY_0001: 'abc' is not a number" in bar_tail(sheet)

    run(drive)


def test_r_pe_def_40_4_a_text_row_shows_the_character_count_tail(v171):
    async def drive():
        async with sheet_ctx(size=(200, 40)) as (app, pilot, sheet):
            await show(pilot, sheet, v171)
            await select(pilot, sheet, V171_ASCII)
            formula_input(sheet).value = "ABC"
            await pilot.pause()
            assert "3/42 chars · NUL-padded  enter stage ↓" in bar_tail(sheet)

    run(drive)


def test_r_pe_def_40_5_the_tail_previews_over_the_staged_bytes_of_a_shared_word(defc):
    """R-PE-DEF.40 (negative control: preview over the image) - MASK_FIELD `255` is staged; the tail of MASK_BIT `0`
    shows the word as I-2 encodes it over the staged bytes, not over the image."""
    from s19_app.tui.a2l_definition import encode_definition
    from s19_app.tui.definition_sheet import StagedOverlay

    entries = overlay_entries(defc, "MASK_FIELD_0001", "255")
    bit = defc.defs["MASK_BIT_0001"]
    over_staged = encode_definition(bit, defc.a2l, "0", StagedOverlay(defc.image, entries))
    over_image = encode_definition(bit, defc.a2l, "0", defc.image)

    def hex_of(data):
        return " ".join(f"{b:02X}" for b in data)

    after, wrong = hex_of(over_staged.data), hex_of(over_image.data)
    assert after != wrong, "arm setup: the two encodes of the shared word differ"
    before = hex_of(defc.image[bit.address + i] for i in range(len(over_staged.data)))

    async def drive():
        async with sheet_ctx(size=(200, 40)) as (app, pilot, sheet):
            await show(pilot, sheet, defc, entries=entries)
            await select(pilot, sheet, "MASK_BIT_0001")
            await type_keys(pilot, sheet, "0")
            tail = bar_tail(sheet)
            assert f"{before} → {after}" in tail, tail
            assert f"→ {wrong}" not in tail, tail

    run(drive)


@pytest.mark.parametrize("width", [118, 220], ids=["41-1-118-columns", "41-2-220-columns"])
def test_r_pe_def_41_n_a_long_refusal_is_cut_at_the_bars_edge_with_an_ellipsis(defc, width):
    async def drive():
        async with sheet_ctx(size=(width, 40)) as (app, pilot, sheet):
            await show(pilot, sheet, defc)
            await fill(pilot, sheet, "x" * 300)
            tail = bar_tail(sheet)
            assert tail.startswith("✗ DISPLAY_0001: 'xxx")
            assert tail.rstrip().endswith("…")
            assert "\n" not in tail.rstrip()
            assert cell_len(tail.rstrip()) <= sheet.size.width

    run(drive)


# --------------------------------------------------------------------------- R-PE-DEF.42


def test_r_pe_def_42_1_a_paste_over_the_cap_into_an_empty_input_leaves_it_empty(defc):
    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc)
            inp = formula_input(sheet)
            inp.focus()
            await pilot.pause()
            inp.post_message(events.Paste("x" * 65_536))
            await pilot.pause()
            await pilot.pause()
            assert inp.value == ""

    run(drive)


def test_r_pe_def_42_2_a_paste_that_would_pass_the_cap_leaves_the_text_unchanged(defc):
    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc)
            inp = formula_input(sheet)
            inp.focus()
            await pilot.pause()
            inp.value = "y" * 4000
            await pilot.pause()
            inp.cursor_position = len(inp.value)
            inp.post_message(events.Paste("x" * 200))
            await pilot.pause()
            await pilot.pause()
            assert inp.value == "y" * 4000

    run(drive)


def test_r_pe_def_42_3_typing_past_the_cap_keeps_the_first_4096_characters(defc):
    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc)
            inp = formula_input(sheet)
            inp.focus()
            await pilot.pause()
            for _ in range(5000):
                inp.insert_text_at_cursor("x")
            await pilot.pause()
            await pilot.pause()
            assert inp.value == "x" * 4096

    run(drive)


# --------------------------------------------------------------------------- R-PE-DEF.78


@pytest.mark.parametrize(
    "span", [4097, 1_048_576], ids=["78-1-4097-bytes", "78-2-1-mebibyte"]
)
def test_r_pe_def_78_n_a_text_row_without_an_editor_keeps_the_input_empty(v171, span):
    base = v171.defs[V171_ASCII]
    big = dataclasses.replace(widened(base, span), name="BIG_ASCII")
    image = {base.address + i: 0x41 for i in range(span)}

    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            sheet.show_page(["BIG_ASCII"], {"BIG_ASCII": big}, v171.a2l, image)
            sheet.set_document([], image)
            await pilot.pause()
            await pilot.pause()
            assert sheet.selected_name == "BIG_ASCII"
            assert formula_input(sheet).value == ""
            assert formula_input(sheet).disabled is True

    run(drive)


# --------------------------------------------------------------------------- R-PE-DEF.36/1, /2 (input disabled)


@pytest.mark.parametrize("case_id", ["36-1-refused", "36-2-cuboid"])
def test_r_pe_def_36_n_a_row_with_no_editor_disables_the_input(defc, case_id):
    """R-PE-DEF.36/1, /2 (E5: the "input disabled" half had no sheet assertion): a refused row and the
    `cuboid` copy have no editor, so the input is disabled and empty; the editable row before them
    enables it again, so the assertion cannot hold for a sheet that always disables the input."""
    from s19_app.tui.a2l_definition import describe_definition

    if case_id == "36-1-refused":
        name = "NO_SUCH_PARAMETER_0001"
        other = describe_definition(name, defc.a2l)
        assert other.refusal is not None
    else:
        name = "CUBOID_0001"
        other = dataclasses.replace(
            defc.defs["DISPLAY_0001"], name=name, kind="cuboid", element_count=24
        )
    defs = {"DISPLAY_0001": defc.defs["DISPLAY_0001"], name: other}

    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            sheet.show_page(["DISPLAY_0001", name], defs, defc.a2l, defc.image)
            sheet.set_document([], defc.image)
            await pilot.pause()
            assert sheet.selected_name == "DISPLAY_0001"
            assert formula_input(sheet).disabled is False
            await select(pilot, sheet, name)
            assert formula_input(sheet).disabled is True
            assert formula_input(sheet).value == ""
            assert bar_tail(sheet).startswith("edit ") and "objects in the Inspector tab" in bar_tail(sheet)
            await select(pilot, sheet, "DISPLAY_0001")
            assert formula_input(sheet).disabled is False

    run(drive)


# --------------------------------------------------------------------------- R-PE-DEF.50 (the request the sheet posts)


@pytest.mark.parametrize(
    "source, name, text",
    [
        ("defc", "DISPLAY_0001", "25.5"),
        ("defc", "DISPLAY_0001", "250"),
        ("defc", "ENUM_0001", "RUN"),
        ("defc", "MASK_FIELD_0001", "255"),
        ("v171", V171_ASCII, "ABC"),
    ],
    ids=["50-5-display", "50-6-refused-text", "50-7-enum", "50-8-mask-field", "50-9-text"],
)
def test_r_pe_def_50_n_enter_in_the_input_posts_the_request_with_the_text(request, source, name, text):
    case = request.getfixturevalue(source)

    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, case, names=tuple(case.defs))
            await select(pilot, sheet, name)
            if source == "v171":
                formula_input(sheet).value = text
                formula_input(sheet).focus()
                await pilot.pause()
            else:
                await type_keys(pilot, sheet, text)
            assert app.staged == []
            await pilot.press("enter")
            await pilot.pause()
            assert app.staged == [(name, text)]

    run(drive)
