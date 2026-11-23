"""Batch-103 Inc 8 E4, group S2: the StagingSheet's rows (nodes S13, S15', S16, S19').

Rows R-PE-DEF.10 .. .14, .18, .23, .24, .25, .62, .70 of ``inc-8/01-requirements.md``;
cases in ``inc-8/02-test-cases-S2.md``. The widget is mounted alone in a minimal App and
driven through its pinned interface I-8.4 (``show_page``, ``set_document``,
``selected_name``) and the keys; assertions read the painted body text, cut into columns
where the header words start.

Expected values: requirement texts; bytes from I-2's own ``encode_definition``;
text variants of the committed ``definitions`` case for the reload and markup cases.
"""
from __future__ import annotations

import asyncio
import dataclasses
import os
import statistics
import sys
import time

if "." not in sys.path:
    sys.path.insert(0, ".")
import s19_app

print(f"s19_app.__file__ = {s19_app.__file__}", flush=True)

import pytest

from s19_app.tui import a2l_definition as definition_module
from s19_app.tui.a2l_definition import decode_definition, describe_definitions
from tests.support.b103_inc8_s2 import (
    DEFC_NAMES,
    V171_ASCII,
    body_lines,
    body_text,
    bar_name,
    bar_tail,
    cells,
    defc,
    fill,
    formula_input,
    no_os_clipboard,
    overlay_entries,
    plain,
    row_line,
    select,
    softa_page,
    show,
    sheet_ctx,
    type_keys,
    v171,
    variant,
    widened,
)
from tests.support.timing import timing_bound

NO_PAGE = "No parameters on this page: type a filter above."
NO_A2L = "Load an A2L file to edit parameters by definition."


def run(coro_fn):
    return asyncio.run(coro_fn())


# --------------------------------------------------------------------------- R-PE-DEF.10


def test_r_pe_def_10_1_a_population_shows_one_row_per_name_in_page_order(defc):
    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc)
            lines = body_lines(sheet)
            order = [lines.index(row_line(sheet, n)) for n in DEFC_NAMES]
            assert order == sorted(order), order
            assert len(set(order)) == len(DEFC_NAMES)

    run(drive)


def test_r_pe_def_10_2_a_filtered_page_shows_only_its_names(defc):
    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            page = ("MASK_BIT_0001", "MASK_FIELD_0001")
            await show(pilot, sheet, defc, names=page)
            lines = body_lines(sheet)
            assert lines.index(row_line(sheet, page[0])) < lines.index(row_line(sheet, page[1]))
            text = body_text(sheet)
            assert "DISPLAY_0001" not in text and "ENUM_0001" not in text

    run(drive)


def test_r_pe_def_10_3_a_page_turn_replaces_the_rows(defc):
    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc)
            await show(pilot, sheet, defc, names=("MASK_BIT_0001",))
            text = body_text(sheet)
            assert "MASK_BIT_0001" in text
            assert "DISPLAY_0001" not in text and "ENUM_0001" not in text and "MASK_FIELD" not in text

    run(drive)


# --------------------------------------------------------------------------- R-PE-DEF.11


def test_r_pe_def_11_1_a_reload_that_changes_a_table_text_shows_the_new_text(defc, tmp_path):
    changed = variant(defc, tmp_path, ('1 "IDLE"', '1 "IDLEX"'))

    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc)
            assert cells(sheet, "ENUM_0001")["Current"] == "1 IDLE"
            await show(pilot, sheet, changed)
            assert cells(sheet, "ENUM_0001")["Current"] == "1 IDLEX"

    run(drive)


def test_r_pe_def_11_2_page_turns_and_filter_changes_describe_nothing(defc, monkeypatch):
    calls = []
    from s19_app.tui import definition_sheet
    from s19_app.tui.screens_directionb.patch_editor import sheet as sheet_module

    for module in (definition_module, definition_sheet, sheet_module):
        for attr in ("describe_definition", "describe_definitions"):
            real = getattr(module, attr, None)
            if real is not None:
                monkeypatch.setattr(
                    module, attr,
                    lambda *a, _r=real, _n=f"{module.__name__}.{attr}", **k: (calls.append(_n), _r(*a, **k))[1],
                )

    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc)
            await show(pilot, sheet, defc, names=("MASK_BIT_0001", "MASK_FIELD_0001"))
            await show(pilot, sheet, defc, names=("ENUM_0001",))
            sheet.set_document([], defc.image)
            await pilot.pause()

    run(drive)
    assert calls == []


def test_r_pe_def_11_3_the_sheet_uses_the_page_a2l_not_the_apps(defc, tmp_path):
    factor_one = variant(defc, tmp_path, ("COEFFS_LINEAR 0.5 0", "COEFFS_LINEAR 1 0"))
    expected_new = decode_definition(
        factor_one.defs["DISPLAY_0001"], factor_one.a2l, defc.image
    ).text

    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc, names=("DISPLAY_0001",))
            app.current_a2l_data = factor_one.a2l  # the app's A2L replaced, picker not repopulated
            sheet.set_document([], defc.image)
            await pilot.pause()
            assert cells(sheet, "DISPLAY_0001")["Current"] == "143.5"
            await show(pilot, sheet, factor_one, names=("DISPLAY_0001",), image=defc.image)
            current = cells(sheet, "DISPLAY_0001")["Current"]
            assert current == expected_new
            assert float(current) == 287.0

    run(drive)


# --------------------------------------------------------------------------- R-PE-DEF.12


def _median_show(pilot, sheet, names, defs, a2l, image):
    times = []
    for _ in range(5):
        t0 = time.perf_counter()
        sheet.show_page(names, defs, a2l, image)
        sheet._paint()
        times.append(time.perf_counter() - t0)
    return statistics.median(times)


@pytest.mark.serial_timing  # R-TST.2: a timing arm runs serially (E4 integration)
def test_r_pe_def_12_1_a_200_name_software_a_page_paints_within_half_a_second(softa_page):
    """load-sensitive: decide only on a quiet host; the load is printed beside the median."""
    a2l, names, defs, image = softa_page
    assert len(names) == 200

    async def drive():
        async with sheet_ctx(size=(118, 54)) as (app, pilot, sheet):
            sheet.show_page(names, defs, a2l, image)
            await pilot.pause()
            median = _median_show(pilot, sheet, names, defs, a2l, image)
            print(f"R-PE-DEF.12/1 median={median:.4f}s loadavg={os.getloadavg()}", flush=True)
            assert median <= timing_bound(0.5)

    run(drive)


@pytest.mark.serial_timing  # R-TST.2: a timing arm runs serially (E4 integration)
def test_r_pe_def_12_2_a_page_of_200_one_mebibyte_text_spans_paints_within_half_a_second(v171):
    """load-sensitive: decide only on a quiet host; the load is printed beside the median."""
    base = v171.defs[V171_ASCII]
    span = 1_048_576
    names = [f"HOSTILE_{i:03d}" for i in range(200)]
    defs = {n: dataclasses.replace(widened(base, span), name=n) for n in names}
    image = {base.address + i: 0x41 for i in range(span)}
    entries = [(base.address + 64, tuple(b"XYZ" + bytes(39)))]

    async def drive():
        async with sheet_ctx(size=(118, 54)) as (app, pilot, sheet):
            sheet.show_page(names, defs, v171.a2l, image)
            sheet.set_document(entries, image)
            await pilot.pause()
            median = _median_show(pilot, sheet, names, defs, v171.a2l, image)
            print(f"R-PE-DEF.12/2 median={median:.4f}s loadavg={os.getloadavg()}", flush=True)
            assert median <= timing_bound(0.5)
            assert f"{span} B" in body_text(sheet)

    run(drive)


# --------------------------------------------------------------------------- R-PE-DEF.30 (E4 integration)


def _rows_with_detail(sheet) -> list:
    """The names whose row line is followed by detail lines (`┊ └ …`, Inc 8b) before the next row line."""
    lines = body_lines(sheet)
    at = sorted((lines.index(row_line(sheet, n)), n) for n in DEFC_NAMES)
    found = []
    for i, (pos, name) in enumerate(at):
        end = at[i + 1][0] if i + 1 < len(at) else len(lines)
        # Inc 8b (R-PE-DEF.107): every expanded line carries the bar `┊` before its `└` / frame.
        if any(ln.lstrip().startswith("┊ └") for ln in lines[pos + 1:end]):
            found.append(name)
    return found


def test_r_pe_def_30_1_the_detail_moves_with_the_selection(defc):
    """R-PE-DEF.30/1, /2 - select row 1, then row 3: the detail lines sit under the selected row only, and
    row 1 has none after the move. Added at E4 integration (trace_check: no test named R-PE-DEF.30).
    Fails if every expanded row keeps its detail, or if no detail is painted."""

    async def drive():
        async with sheet_ctx(size=(160, 50)) as (app, pilot, sheet):
            await show(pilot, sheet, defc)
            first, third = DEFC_NAMES[0], DEFC_NAMES[2]
            await select(pilot, sheet, first)
            assert _rows_with_detail(sheet) == [first], body_lines(sheet)
            await select(pilot, sheet, third)
            assert _rows_with_detail(sheet) == [third], body_lines(sheet)

    run(drive)


# --------------------------------------------------------------------------- R-PE-DEF.13 / .14


def test_r_pe_def_13_1_a_filter_with_no_match_shows_the_line(defc):
    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc)
            await show(pilot, sheet, defc, names=())
            assert NO_PAGE in body_text(sheet)
            assert "DISPLAY_0001" not in body_text(sheet)

    run(drive)


def test_r_pe_def_13_2_an_a2l_with_no_addressed_tag_shows_the_line(defc):
    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            sheet.show_page([], {}, defc.a2l, defc.image)
            await pilot.pause()
            assert NO_PAGE in body_text(sheet)
            assert NO_A2L not in body_text(sheet)

    run(drive)


def test_r_pe_def_14_1_no_a2l_at_start_shows_the_line():
    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            assert NO_A2L in body_text(sheet)
            sheet.show_page([], {}, None, None)
            await pilot.pause()
            assert NO_A2L in body_text(sheet)

    run(drive)


def test_r_pe_def_14_2_an_unloaded_a2l_shows_the_line(defc):
    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc)
            assert NO_A2L not in body_text(sheet)
            sheet.show_page([], {}, None, defc.image)
            await pilot.pause()
            assert NO_A2L in body_text(sheet)
            assert "DISPLAY_0001" not in body_text(sheet)

    run(drive)


# --------------------------------------------------------------------------- R-PE-DEF.18


def test_r_pe_def_18_1_no_image_shows_dashes(defc):
    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc, image=None)
            assert cells(sheet, "DISPLAY_0001")["Current"] == "--"

    run(drive)


def test_r_pe_def_18_2_an_image_missing_the_second_byte_shows_dashes(defc):
    holed = dict(defc.image)
    del holed[defc.defs["DISPLAY_0001"].address + 1]

    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc, image=holed)
            assert cells(sheet, "DISPLAY_0001")["Current"] == "--"
            assert cells(sheet, "ENUM_0001")["Current"] == "1 IDLE"  # the other rows keep their value

    run(drive)


# --------------------------------------------------------------------------- R-PE-DEF.23


@pytest.mark.parametrize(
    "case_no, name, text, expected_new",
    [
        (1, "DISPLAY_0001", "25.5", "25.5"),
        (2, "MASK_FIELD_0001", "255", "255 (0xFF)"),
        (3, "ENUM_0001", "RUN", "2 RUN"),
    ],
    ids=["23-1-display", "23-2-mask-field", "23-3-enum"],
)
def test_r_pe_def_23_n_a_staged_row_shows_the_dot_and_its_staged_value(defc, case_no, name, text, expected_new):
    entries = overlay_entries(defc, name, text)

    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc, entries=entries)
            got = cells(sheet, name)
            assert got["mark"][1] == "●", got
            assert got["New"] == expected_new

    run(drive)


def test_r_pe_def_23_4_a_raw_entry_over_a_fallback_row_marks_it_staged(defc):
    cuboid = dataclasses.replace(defc.defs["DISPLAY_0001"], name="CUBOID_0001", kind="cuboid", element_count=24)
    address = cuboid.address

    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            sheet.show_page(["CUBOID_0001"], {"CUBOID_0001": cuboid}, defc.a2l, defc.image)
            sheet.set_document([], defc.image)
            await pilot.pause()
            assert cells(sheet, "CUBOID_0001")["mark"][1] != "●"
            assert cells(sheet, "CUBOID_0001")["Current"] == "24 values"
            sheet.set_document([(address, (0xAA, 0xBB))], defc.image)
            await pilot.pause()
            assert cells(sheet, "CUBOID_0001")["mark"][1] == "●"

    run(drive)


def test_r_pe_def_23_5_a_pending_rows_new_cell_belongs_to_its_own_text_after_the_selection_moves(defc):
    """R-PE-DEF.23 (negative control: New read from the formula text) - the pending row keeps `◆` and its New text
    while the formula input holds another row's text."""

    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc)
            await type_keys(pilot, sheet, "25.50")
            await select(pilot, sheet, "ENUM_0001")
            assert formula_input(sheet).value == ""
            got = cells(sheet, "DISPLAY_0001")
            assert got["mark"][1] == "◆" and got["New"] == "25.5", got

    run(drive)


# --------------------------------------------------------------------------- R-PE-DEF.24 / .25


def test_r_pe_def_24_1_a_pending_number_shows_the_diamond_and_the_previews_text(defc):
    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc)
            await type_keys(pilot, sheet, "25.50")
            got = cells(sheet, "DISPLAY_0001")
            assert got["mark"][1] == "◆", got
            assert got["New"] == "25.5"  # the preview's text, not the typed `25.50`

    run(drive)


def test_r_pe_def_24_2_a_pending_enum_shows_the_stored_value_and_text(defc):
    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc)
            await select(pilot, sheet, "ENUM_0001")
            await type_keys(pilot, sheet, "RUN")
            got = cells(sheet, "ENUM_0001")
            assert got["mark"][1] == "◆" and got["New"] == "2 RUN", got

    run(drive)


def test_r_pe_def_24_3_a_text_row_left_with_its_row_fill_unchanged_is_not_pending(v171):
    other = [n for n in v171.defs if n != V171_ASCII][0]

    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, v171, names=(V171_ASCII, other))
            assert formula_input(sheet).value == "Hello ASAM"
            await select(pilot, sheet, other)
            assert cells(sheet, V171_ASCII)["mark"][1] != "◆"

    run(drive)


def test_r_pe_def_24_4_a_text_row_erased_to_empty_is_pending(v171):
    """R-PE-DEF.24 (E5 finding F-3): an empty formula text differs from a text row's base text, so the
    row is pending (CTX-PE-DEF "pending"); Enter would stage it, so the sheet must say so. The New cell
    is the preview's value text `""` and Δ counts every position of the base text (each becomes NUL)."""
    base = decode_definition(v171.defs[V171_ASCII], v171.a2l, v171.image).text
    assert base

    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, v171, names=tuple(v171.defs))
            await select(pilot, sheet, V171_ASCII)
            inp = formula_input(sheet)
            assert inp.value == base
            inp.focus()
            await pilot.pause()
            inp.cursor_position = len(inp.value)
            for _ in base:
                await pilot.press("backspace")
            await pilot.pause()
            assert inp.value == ""
            got = cells(sheet, V171_ASCII)
            assert got["mark"][1] == "◆", got
            assert got["New"] == '""', got
            assert got["Δ"] == f"{len(base)} chars", got

    run(drive)


def test_r_pe_def_25_1_a_refusal_shows_the_formula_text_in_new(defc):
    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc)
            await type_keys(pilot, sheet, "abc")
            got = cells(sheet, "DISPLAY_0001")
            assert got["New"] == "abc" and got["mark"][1] == "◆", got

    run(drive)


def test_r_pe_def_25_2_a_long_refusal_text_is_clipped_with_an_ellipsis(defc):
    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc)
            await fill(pilot, sheet, "x" * 300)
            new = cells(sheet, "DISPLAY_0001")["New"]
            assert new.startswith("xxxx") and new.endswith("…")
            assert 4 < len(new) < 60
            assert "refus" not in new.lower() and "A2L-DEF" not in new

    run(drive)


# --------------------------------------------------------------------------- R-PE-DEF.62


def test_r_pe_def_62_1_an_undo_that_empties_the_document_clears_the_dot(defc):
    entries = overlay_entries(defc, "DISPLAY_0001", "25.5")

    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc, entries=entries)
            assert cells(sheet, "DISPLAY_0001")["mark"][1] == "●"
            sheet.set_document([], defc.image)
            await pilot.pause()
            assert cells(sheet, "DISPLAY_0001")["mark"][1] != "●"

    run(drive)


def test_r_pe_def_62_2_removing_the_masked_entry_unstages_both_masked_rows(defc):
    address = defc.defs["MASK_FIELD_0001"].address
    field = overlay_entries(defc, "MASK_FIELD_0001", "255")[0]
    over_field = dict(defc.image)
    over_field.update({field[0] + i: b for i, b in enumerate(field[1])})
    from s19_app.tui.a2l_definition import encode_definition

    bit = encode_definition(defc.defs["MASK_BIT_0001"], defc.a2l, "0", over_field)
    entries = [(address, tuple(bit.data))]  # one entry: field 255 and bit 0 together (EX-O1)

    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc, entries=entries)
            assert cells(sheet, "MASK_FIELD_0001")["mark"][1] == "●"
            assert cells(sheet, "MASK_BIT_0001")["mark"][1] == "●"
            sheet.set_document([], defc.image)
            await pilot.pause()
            assert cells(sheet, "MASK_FIELD_0001")["mark"][1] != "●"
            assert cells(sheet, "MASK_BIT_0001")["mark"][1] != "●"

    run(drive)


def test_r_pe_def_62_3_a_replaced_document_restages_by_its_own_entries(defc):
    old = overlay_entries(defc, "ENUM_0001", "RUN")
    new = overlay_entries(defc, "DISPLAY_0001", "25.5")

    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc, entries=old)
            assert cells(sheet, "ENUM_0001")["mark"][1] == "●"
            sheet.set_document(new, defc.image)  # a Parse pasted document
            await pilot.pause()
            assert cells(sheet, "DISPLAY_0001")["mark"][1] == "●"
            assert cells(sheet, "ENUM_0001")["mark"][1] != "●"

    run(drive)


def test_r_pe_def_62_4_a_new_image_restages_the_bit_row_over_the_new_word(defc):
    entries = overlay_entries(defc, "MASK_FIELD_0001", "255")
    new_image = dict(defc.image)
    new_image[defc.defs["MASK_BIT_0001"].address + 1] = 0xE6  # the word becomes 1A E6

    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc, entries=entries)
            assert cells(sheet, "MASK_BIT_0001")["mark"][1] != "●"  # 1A E7: the bit already reads 1
            sheet.set_document(entries, new_image)
            await pilot.pause()
            bit = cells(sheet, "MASK_BIT_0001")
            assert bit["mark"][1] == "●" and bit["New"] == "1 (0x01)", bit
            assert cells(sheet, "MASK_FIELD_0001")["New"] == "255 (0xFF)"

    run(drive)


# --------------------------------------------------------------------------- R-PE-DEF.70


def test_r_pe_def_70_1_an_enum_text_with_a_closing_tag_is_shown_literally(defc, tmp_path):
    hostile = variant(defc, tmp_path, ('1 "IDLE"', '1 "A[/x]B"'))

    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, hostile, names=("ENUM_0001",))
            assert cells(sheet, "ENUM_0001")["Current"] == "1 A[/x]B"
            assert "A[/x]B" in body_text(sheet)  # the options line under the selected row too

    run(drive)


def test_r_pe_def_70_2_an_enum_text_with_an_action_link_paints_no_link(defc, tmp_path):
    word = "[@click=app.quit]OFF[/]"
    hostile = variant(defc, tmp_path, ('0 "OFF"', f'0 "{word}"'))

    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, hostile, names=("ENUM_0001",))
            assert word in body_text(sheet)
            content = sheet.query_one("#patch_sheet_body").content
            assert "@click" not in str(getattr(content, "spans", ""))
            assert app.return_code is None

    run(drive)


def test_r_pe_def_70_3_a_unit_with_brackets_shows_every_character(defc, tmp_path):
    hostile = variant(defc, tmp_path, ('PHYS_UNIT "deg C"', 'PHYS_UNIT "Map[b]x"'))

    async def drive():
        async with sheet_ctx(size=(220, 40)) as (app, pilot, sheet):
            await show(pilot, sheet, hostile, names=("DISPLAY_0001",))
            assert cells(sheet, "DISPLAY_0001")["Unit"] == "Map[b]x"

    run(drive)


def test_r_pe_def_70_4_a_refusal_tail_shows_the_formula_text_literally(defc):
    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc)
            await type_keys(pilot, sheet, "A[b]")
            assert "'A[b]' is not a number" in bar_tail(sheet)

    run(drive)


def test_r_pe_def_70_5_a_row_named_like_a_closing_tag_selects_without_an_exception(defc):
    named = dataclasses.replace(defc.defs["DISPLAY_0001"], name="A[/x]B")

    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            sheet.show_page(["A[/x]B"], {"A[/x]B": named}, defc.a2l, defc.image)
            sheet.set_document([], defc.image)
            await pilot.pause()
            assert sheet.selected_name == "A[/x]B"
            assert bar_name(sheet).startswith("A[/x]B")
            assert app.return_code is None

    run(drive)
