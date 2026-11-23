"""Batch-103 Inc 8 E4, group P - the landing pane's border subtitle (R-PE.41) and the dirty
writer w6 reached through ``PatchEditorPanel.note_staged`` (R-PE.34, R-PE-DEF.60 selection).

Cases: ``02-test-cases-P.md``.  Entries are added through the shipped service and the app's own
refresh site (``_refresh_patch_history_view``) for the count rows, and through the panel's own
inputs and Add button for the dirty row (the way the operator sets the flag).
"""
from __future__ import annotations

import sys

sys.path.insert(0, ".")
import s19_app

print(f"S19_APP_UNDER_TEST={s19_app.__file__}", flush=True)

import pytest
from textual.widgets import Input

from tests.support.b103_inc8_p import (
    SIZE,
    build_defc,
    click_visible,
    drive,
    names_of,
    need,
    selected_name,
    settle,
    show_tab,
)


@pytest.fixture(scope="module")
def defc(tmp_path_factory):
    return build_defc(tmp_path_factory.mktemp("inc8_p_defc"))


def subtitle(panel) -> str:
    return need(panel, "#patch_inspector").border_subtitle or ""


async def _add_through_the_panel(pilot, app, panel, address: str, bytes_text: str, after: int) -> None:
    await show_tab(pilot, "patch_tab_inspector")
    need(panel, "#patch_entry_address_input", Input).value = address
    need(panel, "#patch_entry_bytes_input", Input).value = bytes_text
    assert await click_visible(pilot, "#patch_entry_add_button")
    for _ in range(40):
        await pilot.pause()
        if len(app._change_service.document.entries) == after:
            break
    assert len(app._change_service.document.entries) == after


# --------------------------------------------------------------------------- #
# R-PE.41 - the ledger subtitle rides the landing pane
# --------------------------------------------------------------------------- #

COUNTS = [(0, "0 entries"), (1, "1 entry"), (3, "3 entries")]


@pytest.mark.parametrize("count,text", COUNTS, ids=["0-entries", "1-entry", "3-entries"])
def test_r_pe_041_the_patch_script_and_inspector_tabs_show_the_entry_count(tmp_path, count, text):
    async def body(app, pilot, panel):
        for index in range(count):
            app._change_service.add_entry(f"0x{0x1000 * (index + 1):08X}", "", "AA")
        if count:
            app._refresh_patch_history_view()
        await settle(pilot)
        await show_tab(pilot, "patch_tab_inspector")
        assert subtitle(panel) == text, f"Inspector tab: {subtitle(panel)!r}"
        await show_tab(pilot, "patch_tab_script")
        assert subtitle(panel) == text, f"Patch script tab: {subtitle(panel)!r}"

    drive(tmp_path, SIZE, body)


def test_r_pe_041_a_dirty_document_adds_the_marker_on_the_inspector_tab(tmp_path):
    async def body(app, pilot, panel):
        await _add_through_the_panel(pilot, app, panel, "0x1000", "AA", 1)
        await _add_through_the_panel(pilot, app, panel, "0x2000", "BB", 2)
        await _add_through_the_panel(pilot, app, panel, "0x3000", "CC", 3)
        await show_tab(pilot, "patch_tab_inspector")
        assert subtitle(panel) == "3 entries ●", subtitle(panel)

    drive(tmp_path, SIZE, body)


def test_r_pe_041_the_json_tab_shows_the_schema_token_and_checks_its_run_state(tmp_path):
    async def body(app, pilot, panel):
        await show_tab(pilot, "patch_tab_json")
        assert subtitle(panel) == "v2 schema", subtitle(panel)
        await show_tab(pilot, "patch_tab_checks")
        run_state = need(panel, "#patch_win_checks").border_subtitle
        assert run_state and subtitle(panel) == run_state, (subtitle(panel), run_state)

    drive(tmp_path, SIZE, body)


# --------------------------------------------------------------------------- #
# R-PE.34 (writer w6) and R-PE-DEF.60 - note_staged
# --------------------------------------------------------------------------- #


def _loaded(defc_dir):
    return dict(a2l=defc_dir / "definitions.a2l", image=defc_dir / "definitions.s19")


def test_r_pe_034_1_note_staged_sets_the_dirty_flag(defc, tmp_path):
    async def body(app, pilot, panel):
        await show_tab(pilot, "patch_tab_script")
        assert "●" not in subtitle(panel)
        panel.note_staged("DISPLAY_0001")
        await settle(pilot)
        assert subtitle(panel).endswith("●"), subtitle(panel)

    drive(tmp_path, SIZE, body, **_loaded(defc))


def test_r_pe_def_60_1_note_staged_selects_the_row_after_the_staged_row(defc, tmp_path):
    async def body(app, pilot, panel):
        sheet = need(panel, "#patch_sheet")
        names = names_of(panel._a2l_picker.visible_params)
        assert "DISPLAY_0001" in names and names.index("DISPLAY_0001") < len(names) - 1, names
        panel.note_staged("DISPLAY_0001")
        await settle(pilot)
        assert selected_name(sheet) == names[names.index("DISPLAY_0001") + 1]

    drive(tmp_path, SIZE, body, **_loaded(defc))


def test_r_pe_def_60_2_note_staged_on_the_last_row_stays(defc, tmp_path):
    async def body(app, pilot, panel):
        sheet = need(panel, "#patch_sheet")
        names = names_of(panel._a2l_picker.visible_params)
        need(panel, "#patch_sheet_body").focus()
        for _ in names:
            await pilot.press("down")
        await settle(pilot)
        assert selected_name(sheet) == names[-1]
        panel.note_staged(names[-1])
        await settle(pilot)
        assert selected_name(sheet) == names[-1]

    drive(tmp_path, SIZE, body, **_loaded(defc))


def test_r_pe_def_60_3_the_row_after_the_named_row_wins_over_where_the_selection_moved(defc, tmp_path):
    async def body(app, pilot, panel):
        sheet = need(panel, "#patch_sheet")
        names = names_of(panel._a2l_picker.visible_params)
        need(panel, "#patch_sheet_body").focus()
        await pilot.press("down", "down", "down")
        await settle(pilot)
        assert selected_name(sheet) == names[3]
        panel.note_staged(names[0])
        await settle(pilot)
        assert selected_name(sheet) == names[1], "the advance starts at the staged row, not at the selection"

    drive(tmp_path, SIZE, body, **_loaded(defc))


def test_r_pe_def_60_4_a_stage_reported_without_advance_keeps_the_selection(defc, tmp_path):
    """PARTIAL: Inc 9's record-stage handler is the product caller; the test calls ``note_staged`` directly."""

    async def body(app, pilot, panel):
        sheet = need(panel, "#patch_sheet")
        names = names_of(panel._a2l_picker.visible_params)
        before = selected_name(sheet)
        assert before == names[0]
        panel.note_staged("DISPLAY_0001", advance=False)
        await settle(pilot)
        assert selected_name(sheet) == before
        assert subtitle(panel).endswith("●"), subtitle(panel)

    drive(tmp_path, SIZE, body, **_loaded(defc))
