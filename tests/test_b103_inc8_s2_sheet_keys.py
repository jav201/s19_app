"""Batch-103 Inc 8 E4, group S2: the StagingSheet's keys, selection and row window
(nodes S13, S15', S17', S18, S19').

Rows R-PE-DEF.45 .. .49, .60, .81, .82 of ``inc-8/01-requirements.md``; cases in
``inc-8/02-test-cases-S2.md``. Keys go through the Textual pilot to the focused body or
input; selection is read from the pinned ``selected_name`` and from the painted `▶` mark.
The Escape cases run under an App that binds Escape as its "back" action and counts it:
R-PE-DEF.48 says the input's Escape is not the screen's back action.
"""
from __future__ import annotations

import asyncio
import dataclasses
import sys

if "." not in sys.path:
    sys.path.insert(0, ".")
import s19_app

print(f"s19_app.__file__ = {s19_app.__file__}", flush=True)

import pytest
from rich.text import Text

from tests.support.b103_inc8b_r import fact
from tests.support.b103_inc8_s2 import (
    body_lines,
    cells,
    defc,
    formula_input,
    no_os_clipboard,
    select,
    show,
    sheet_ctx,
    softa_page,
    type_keys,
)

THREE = ("DISPLAY_0001", "ENUM_0001", "MASK_BIT_0001")


def run(coro_fn):
    return asyncio.run(coro_fn())


def marked(sheet) -> str:
    """The Parameter-column start of the one row painted with the selection mark."""
    lines = body_lines(sheet)
    col = lines[0].index("Parameter")
    hits = [ln for ln in lines[1:] if ln.startswith("▶")]
    assert len(hits) == 1, lines
    return hits[0][col:col + 12].rstrip()


# --------------------------------------------------------------------------- R-PE-DEF.45 / .46


def test_r_pe_def_45_1_down_selects_the_row_below(defc):
    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc, names=THREE)
            assert sheet.selected_name == THREE[0]
            sheet.query_one("#patch_sheet_body").focus()
            await pilot.pause()
            await pilot.press("down")
            assert sheet.selected_name == THREE[1]
            assert marked(sheet) == THREE[1][:12]

    run(drive)


def test_r_pe_def_45_2_down_again_selects_the_third_row(defc):
    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc, names=THREE)
            sheet.query_one("#patch_sheet_body").focus()
            await pilot.pause()
            await pilot.press("down", "down")
            assert sheet.selected_name == THREE[2]
            assert marked(sheet) == THREE[2][:12]

    run(drive)


def test_r_pe_def_45_3_up_selects_the_row_above(defc):
    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc, names=THREE)
            sheet.query_one("#patch_sheet_body").focus()
            await pilot.pause()
            await pilot.press("down", "down", "up")
            assert sheet.selected_name == THREE[1]
            assert marked(sheet) == THREE[1][:12]

    run(drive)


def test_r_pe_def_45_4_up_on_the_first_row_keeps_it(defc):
    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc, names=THREE)
            sheet.query_one("#patch_sheet_body").focus()
            await pilot.pause()
            await pilot.press("up", "up")
            assert sheet.selected_name == THREE[0]
            assert marked(sheet) == THREE[0][:12]

    run(drive)


def test_r_pe_def_45_5_down_on_the_last_row_keeps_it_without_wrapping(defc):
    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc, names=THREE)
            sheet.query_one("#patch_sheet_body").focus()
            await pilot.pause()
            await pilot.press("down", "down", "down", "down")
            assert sheet.selected_name == THREE[2]

    run(drive)


def test_r_pe_def_46_1_enter_on_the_sheet_moves_the_focus_to_the_formula_input(defc):
    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc, names=THREE)
            sheet.query_one("#patch_sheet_body").focus()
            await pilot.pause()
            assert app.focused is sheet.query_one("#patch_sheet_body")
            await pilot.press("enter")
            await pilot.pause()
            assert app.focused is formula_input(sheet)

    run(drive)


# --------------------------------------------------------------------------- R-PE-DEF.47


def test_r_pe_def_47_n_right_and_left_choose_table_entries_without_wrapping(defc):
    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc, names=THREE)
            await select(pilot, sheet, "ENUM_0001")
            seen = []
            for key in ("right", "right", "right", "left"):
                await pilot.press(key)
                seen.append(formula_input(sheet).value)
            # IDLE -> RUN -> FAULT -> FAULT (no wrap) -> RUN; never the stored number
            assert seen == ["RUN", "FAULT", "FAULT", "RUN"]
            got = cells(sheet, "ENUM_0001")
            assert got["mark"][1] == "◆" and got["New"] == "2 RUN"

    run(drive)


# --------------------------------------------------------------------------- R-PE-DEF.48


def test_r_pe_def_48_1_escape_in_the_input_clears_the_row_and_returns_to_the_sheet(defc):
    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc, names=THREE)
            await type_keys(pilot, sheet, "25.5")
            assert cells(sheet, "DISPLAY_0001")["mark"][1] == "◆"
            await pilot.press("escape")
            await pilot.pause()
            assert cells(sheet, "DISPLAY_0001")["mark"][1] != "◆"
            assert formula_input(sheet).value == ""
            assert app.focused is sheet.query_one("#patch_sheet_body")
            assert app.backs == 0  # Escape in the input is not the screen's back action

    run(drive)


# --------------------------------------------------------------------------- R-PE-DEF.49 (the message the sheet posts)


def test_r_pe_def_49_1_selecting_a_row_posts_its_name(defc):
    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc, names=THREE)
            await select(pilot, sheet, THREE[2])
            await pilot.pause()
            assert app.selections[-1] == THREE[2]

    run(drive)


def test_r_pe_def_49_2_a_page_turn_posts_the_new_first_row(defc):
    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc, names=THREE)
            await select(pilot, sheet, THREE[2])
            await show(pilot, sheet, defc, names=("MASK_FIELD_0001", "ENUM_0001"))  # the old selection is not on it
            await pilot.pause()
            assert sheet.selected_name == "MASK_FIELD_0001"
            assert app.selections[-1] == "MASK_FIELD_0001"

    run(drive)


# --------------------------------------------------------------------------- R-PE-DEF.60 / .82 (select_after)


def test_r_pe_def_60_1_select_after_moves_to_the_row_after_the_named_one(defc):
    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc, names=THREE)
            sheet.select_after(THREE[0])
            await pilot.pause()
            assert sheet.selected_name == THREE[1]
            assert marked(sheet) == THREE[1][:12]

    run(drive)


def test_r_pe_def_60_2_select_after_on_the_last_row_stays_on_it(defc):
    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc, names=THREE)
            await select(pilot, sheet, THREE[2])
            sheet.select_after(THREE[2])
            await pilot.pause()
            assert sheet.selected_name == THREE[2]

    run(drive)


def test_r_pe_def_60_3_select_after_goes_by_the_named_row_not_the_current_selection(defc):
    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc, names=THREE)
            await select(pilot, sheet, THREE[2])  # the selection moved two rows down meanwhile
            sheet.select_after(THREE[0])
            await pilot.pause()
            assert sheet.selected_name == THREE[1]

    run(drive)


def test_r_pe_def_60_5_select_after_leaves_the_focus_where_it_was(defc):
    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc, names=THREE)
            await type_keys(pilot, sheet, "25.5")
            assert app.focused is formula_input(sheet)
            sheet.select_after(THREE[0])
            await pilot.pause()
            assert app.focused is formula_input(sheet)
            assert formula_input(sheet).value == ""  # refilled for the new row

    run(drive)


def test_r_pe_def_82_1_select_after_clears_the_staged_rows_pending_text(defc):
    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc, names=THREE)
            await type_keys(pilot, sheet, "25.5")
            assert cells(sheet, "DISPLAY_0001")["mark"][1] == "◆"
            sheet.select_after("DISPLAY_0001")
            await pilot.pause()
            assert cells(sheet, "DISPLAY_0001")["mark"][1] != "◆"  # as after the stage and an Undo

    run(drive)


def test_r_pe_def_82_2_the_staged_row_selected_again_has_an_empty_input(defc):
    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc, names=THREE)
            await type_keys(pilot, sheet, "25.5")
            sheet.select_after("DISPLAY_0001")
            await pilot.pause()
            await select(pilot, sheet, "DISPLAY_0001")
            assert formula_input(sheet).value == ""

    run(drive)


# --------------------------------------------------------------------------- R-PE-DEF.81


def _inside(sheet) -> tuple:
    body = sheet.query_one("#patch_sheet_body")
    return body_lines(sheet), body.content_region.height


def test_r_pe_def_81_1_after_40_downs_the_selected_row_and_its_detail_lie_inside_the_body(softa_page):
    """R-PE-DEF.81/1 (changed at Inc 8b E1: visible = body - 2, the header rule takes a line)."""
    a2l, names, defs, image = softa_page

    async def drive():
        async with sheet_ctx(size=(118, 54), body_height=22) as (app, pilot, sheet):  # visible 20 sheet lines (EX-K4)
            sheet.show_page(names, defs, a2l, image)
            sheet.set_document([], image)
            await pilot.pause()
            sheet.query_one("#patch_sheet_body").focus()
            await pilot.pause()
            for _ in range(40):
                await pilot.press("down")
            assert sheet.selected_name == names[40]
            lines, height = _inside(sheet)
            assert len(lines) <= height, (len(lines), height)
            at = next(i for i, ln in enumerate(lines) if ln.startswith("▶"))
            assert lines[at][lines[0].index("Parameter"):].startswith(names[40][:12])
            assert at >= 2, "the header line and the rule come first"
            assert lines[1].startswith("━"), "the header rule is the body's second line (R-PE-DEF.91)"
            first_painted = 40 - (at - 2)
            assert first_painted > 0  # the window scrolled: row 0 is no longer painted

    run(drive)


def test_r_pe_def_81_2_up_past_the_first_painted_row_makes_it_the_first_painted_row(softa_page):
    """R-PE-DEF.81/2 (changed at Inc 8b E1: the first painted row is the third body line)."""
    a2l, names, defs, image = softa_page

    async def drive():
        async with sheet_ctx(size=(118, 54), body_height=22) as (app, pilot, sheet):  # visible 20 sheet lines (EX-K4)
            sheet.show_page(names, defs, a2l, image)
            sheet.set_document([], image)
            await pilot.pause()
            sheet.query_one("#patch_sheet_body").focus()
            await pilot.pause()
            for _ in range(40):
                await pilot.press("down")
            lines, _height = _inside(sheet)
            at = next(i for i, ln in enumerate(lines) if ln.startswith("▶"))
            first_painted = 40 - (at - 2)
            for _ in range(40 - first_painted + 1):
                await pilot.press("up")
            assert sheet.selected_name == names[first_painted - 1]
            lines, height = _inside(sheet)
            assert len(lines) <= height
            assert lines[2].startswith("▶")  # the selected row is the first painted row (after the header and its rule)

    run(drive)


def test_r_pe_def_81_3_an_enum_row_reached_from_above_paints_its_three_detail_lines(defc):
    """R-PE-DEF.81/3 (changed at Inc 8b E1) - an enum row on the window's last line: its definition line and its 4-line card fit the grid body (8)."""
    clones = {f"DISP_{i:02d}": dataclasses.replace(defc.defs["DISPLAY_0001"], name=f"DISP_{i:02d}") for i in range(8)}
    defs = {**clones, "ENUM_0001": defc.defs["ENUM_0001"]}
    names = list(defs)

    async def drive():
        async with sheet_ctx(size=(118, 54), body_height=8) as (app, pilot, sheet):
            sheet.show_page(names, defs, defc.a2l, defc.image)
            sheet.set_document([], defc.image)
            await pilot.pause()
            sheet.query_one("#patch_sheet_body").focus()
            await pilot.pause()
            for _ in range(len(names) - 1):
                await pilot.press("down")
            assert sheet.selected_name == "ENUM_0001"
            lines, height = _inside(sheet)
            assert len(lines) <= height, (len(lines), height)
            at = next(i for i, ln in enumerate(lines) if ln.startswith("▶"))
            assert len(lines) - at - 1 == 5, lines  # the definition line and the four card lines, none cut
            assert "choose" in lines[-2] and lines[-1].lstrip().startswith("┊ ╰")

    run(drive)


def test_r_pe_def_81_4_a_detail_taller_than_the_window_is_cut_and_the_row_stays_painted(defc, monkeypatch):
    from s19_app.tui import definition_sheet as ds

    ops = ds.ops_for("number")._replace(
        detail=lambda row, preview, width, state, room: [Text(f"detail {i}") for i in range(10)]
    )
    monkeypatch.setitem(ds._KIND_OPS, "standin", ops)
    standin = dataclasses.replace(defc.defs["DISPLAY_0001"], name="STANDIN_0001", kind="standin")

    async def drive():
        async with sheet_ctx(size=(118, 54), body_height=8) as (app, pilot, sheet):  # the 12-row minimum: visible 6
            sheet.show_page(["STANDIN_0001"], {"STANDIN_0001": standin}, defc.a2l, defc.image)
            sheet.set_document([], defc.image)
            await pilot.pause()
            assert sheet.selected_name == "STANDIN_0001"
            lines, height = _inside(sheet)
            visible = height - 2  # the header line and the header rule are not row lines (R-PE-DEF.81)
            assert visible == 6 and fact("W.standin_10_detail.h8.painted") == visible - 1
            at = next(i for i, ln in enumerate(lines) if ln.startswith("▶"))  # the row is painted
            assert len(lines) <= height
            assert len(lines) - at - 1 == visible - 1  # the detail cut to room = visible - 1
            assert lines[-1].strip().endswith(f"detail {visible - 2}")  # the cut keeps the first lines

    run(drive)


def test_r_pe_def_81_5_the_test_host_at_118x54_gives_the_grid_body_the_height_the_rule_says(softa_page):
    """R-PE-DEF.81/5 (E3-8b-05) - the host at 118x54 (no chrome): grid 53, body 52, visible 50 (`W.harness_118x54.*`).

    Why: the body must fill the scroller less its scrollbar row, and the window must paint exactly
    visible = body - 2 sheet lines; a body as tall as its own text would leave the window shorter
    than the room the operator has. The harness gives the body no height of its own.
    """
    a2l, names, defs, image = softa_page

    async def drive():
        async with sheet_ctx(size=(118, 54)) as (app, pilot, sheet):
            sheet.show_page(names, defs, a2l, image)
            sheet.set_document([], image)
            await pilot.pause()
            await pilot.pause()
            grids = list(sheet.query("#patch_sheet_grid"))
            assert len(grids) == 1, "the grid scroller of R-PE-DEF.92"
            body = sheet.query_one("#patch_sheet_body")
            assert grids[0].outer_size.height == fact("W.harness_118x54.grid")
            assert body.outer_size.height == fact("W.harness_118x54.body")
            lines = body_lines(sheet)
            assert len(lines) == fact("W.harness_118x54.visible") + 2

    run(drive)


# --------------------------------------------------------------------------- I-8.4 (pinned attributes, no requirement row)


def test_i_8_4_states_is_a_dict_that_inc8_kinds_leave_empty(defc):
    async def drive():
        async with sheet_ctx() as (app, pilot, sheet):
            await show(pilot, sheet, defc, names=THREE)
            await type_keys(pilot, sheet, "25.5")
            assert isinstance(sheet.states, dict) and sheet.states == {}

    run(drive)
