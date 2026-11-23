"""Batch-103 Inc 8, group A: the app-level stage handler and its panel effects (E4, tester ``test-a``).

Design under test: ``inc-8/01-requirements.md`` rows R-PE-DEF.50 ... .64, .73, R-PE.34, R-PE.35, R-PE.110 and the
nodes ``PatchMixin.on_staging_sheet_stage_requested`` (A3/A3'), ``PatchEditorPanel.note_staged`` and the sheet's
staged mark of ``codewire/graph-inc8.md``. Cases: ``inc-8/02-test-cases-A.md``.

The shipped route is driven under Textual Pilot: the DEFC A2L and image go through the app's own loaders
(``load_a2l_from_path`` / ``load_from_path``), the Patch Editor is shown, and a stage is a real
``StagingSheet.StageRequested(name, text)`` posted on the real ``#patch_sheet`` so it bubbles to the app's
handler exactly as the sheet's Enter does. Results are read back from the service document, the dirty flag
(``panel.is_dirty``), the app's status log and the painted rows of the sheet.

``StagingSheet`` and ``stage_definition`` do not exist on base ``d5d48685``, so these tests have no RED on base;
the negative control at the end proves the busy oracle can fail.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from s19_app.tui import screens_directionb as sdb
from s19_app.tui.a2l_definition import Encoded, Refusal, decode_definition, encode_definition
from s19_app.tui.a2l_parameter_picker import A2LParameterPicker
from s19_app.tui.a2l_parse import parse_a2l_file
from s19_app.tui.app import S19TuiApp
from s19_app.tui.app.shell import _BUSY_LINE
from s19_app.tui.changes.io import serialize_change_document
from s19_app.tui.services.change_service import ChangeService
from tests.b103_inc8_a_support import (
    DISPLAY_ADDRESS,
    DISPLAY_MOVED_ADDRESS,
    MASK_WORD,
    build_defc,
    entry_tuples,
    moved_display_a2l,
    overlay_of,
)
from tests.b97_probes import painted_rows
from tests.support.b100_workers import settle_workers

SIZE = (118, 54)
NO_A2L_LINE = "Patch Editor: no A2L is loaded — nothing staged."


@pytest.fixture(scope="module")
def defc(tmp_path_factory):
    return build_defc(tmp_path_factory.mktemp("b103_inc8_a2_defc"))


# ------------------------------------------------------------------ drivers and readers


async def settle(pilot, rounds: int = 6) -> None:
    for _ in range(rounds):
        await pilot.pause()


def need(root, selector: str):
    found = list(root.query(selector))
    assert len(found) == 1, f"{selector}: expected exactly 1 widget, found {len(found)}"
    return found[0]


def run(tmp_path: Path, defc: dict, body, *, a2l: bool = True):
    """Open the Patch Editor on the DEFC case (A2L and image through the app's loaders) and await ``body``."""

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=SIZE) as pilot:
            await settle(pilot)
            if a2l:
                app.load_a2l_from_path(defc["a2l_path"])
                await settle_workers(pilot)
                assert app.current_a2l_data is not None, f"the A2L did not load: {list(app.log_lines)[-3:]}"
            app.load_from_path(defc["s19_path"])
            for _ in range(100):
                if app.current_file is not None:
                    break
                await pilot.pause(0.05)
            assert app.current_file is not None, "the image did not load"
            app.action_show_screen("patch")
            await settle(pilot, 8)
            panel = need(app, "#patch_editor_panel")
            return await body(app, pilot, panel)

    return asyncio.run(_drive())


def sheet_of(panel):
    return need(panel, "#patch_sheet")


def page_names(panel) -> list:
    return list(panel.query(A2LParameterPicker).first().visible_params)  # address census law: a name, not an attribute


async def stage(pilot, sheet, name: str, text: str) -> None:
    """The shipped stage: the sheet's own message, bubbling to the app's handler."""
    from s19_app.tui.screens_directionb.patch_editor.sheet import StagingSheet

    sheet.post_message(StagingSheet.StageRequested(name, text))
    await settle(pilot, 8)


async def select_row(pilot, sheet, name: str) -> None:
    body = need(sheet, "#patch_sheet_body")
    body.focus()
    await settle(pilot, 2)
    for _ in range(40):
        if sheet.selected_name == name:
            return
        await pilot.press("down")
        await settle(pilot, 2)
    assert sheet.selected_name == name, f"could not select {name}"


def service_of(app) -> ChangeService:
    return app._change_service


def last_status(app) -> str:
    return list(app.log_lines)[-1]


def sheet_row(app, sheet, name: str) -> str:
    rows = painted_rows(app, need(sheet, "#patch_sheet_body"))
    # A sheet row carries the name in its Parameter cell (after the 2-cell mark); Inc 8b's card title names it too.
    found = [row for row in rows if row[2:].split("│")[0].strip() == name]
    assert len(found) == 1, f"{name}: expected one painted row, found {len(found)} in {rows}"
    return found[0]


def encoded(defc, name, text, image=None):
    result = encode_definition(defc["defs"][name], defc["a2l"], text, defc["image"] if image is None else image)
    assert isinstance(result, Encoded), result
    return result


def refusal(defc, name, text):
    result = encode_definition(defc["defs"][name], defc["a2l"], text, defc["image"])
    assert isinstance(result, Refusal), "arm setup: I-2 refuses this text"
    return result


# ------------------------------------------------------------------ R-PE-DEF.50 / .58 / .61 / R-PE.34 end to end


def test_r_pe_def_50_1_app_display_25_5_through_the_sheet_message(tmp_path, defc):
    want = encoded(defc, "DISPLAY_0001", "25.5")

    async def body(app, pilot, panel):
        service = service_of(app)
        depth = service.history_depths()["back"]
        await stage(pilot, sheet_of(panel), "DISPLAY_0001", "25.5")
        entries = entry_tuples(service)
        status = last_status(app)
        dirty = panel.is_dirty
        depth_after = service.history_depths()["back"]
        need(panel, "#patch_undo_button").press()
        await settle(pilot, 8)
        return entries, status, dirty, depth, depth_after, entry_tuples(service)

    entries, status, dirty, depth, depth_after, after_undo = run(tmp_path, defc, body)
    assert entries == [("bytes", want.address, tuple(want.data), None, "DISPLAY_0001")]
    assert status == "Patch Editor: DISPLAY_0001 staged as 25.5 (2 B at 0x800020)."
    assert dirty is True
    assert depth_after == depth + 1
    assert after_undo == [], "Undo did not restore the document before the stage"


def test_r_pe_034_1_stage_sets_the_dirty_flag(tmp_path, defc):
    async def body(app, pilot, panel):
        before = panel.is_dirty
        await stage(pilot, sheet_of(panel), "DISPLAY_0001", "25.5")
        return before, panel.is_dirty

    before, after = run(tmp_path, defc, body)
    assert (before, after) == (False, True)


# ------------------------------------------------------------------ R-PE-DEF.51 over the overlay and the source view


def test_r_pe_def_51_1_app_field_then_bit_through_the_sheet(tmp_path, defc):
    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await stage(pilot, sheet, "MASK_FIELD_0001", "255")
        await stage(pilot, sheet, "MASK_BIT_0001", "0")
        return list(service_of(app).document.entries)

    entries = run(tmp_path, defc, body)
    assert [(e.address, bytes(e.encoded_bytes), e.symbol) for e in entries] == [
        (MASK_WORD, bytes([0x1F, 0xF6]), "MASK_FIELD_0001")
    ]
    view = overlay_of(defc["image"], entries)
    for name, text in (("MASK_FIELD_0001", "255"), ("MASK_BIT_0001", "0")):
        decoded = decode_definition(defc["defs"][name], defc["a2l"], view)
        assert not isinstance(decoded, Refusal) and decoded.text == text


def test_r_pe_def_51_3_app_handler_encodes_over_the_source_view(tmp_path, defc):
    """E3S-01 at the handler: after Apply and Remove the stage must read the source bytes, not the applied map."""

    async def body(app, pilot, panel):
        sheet, service = sheet_of(panel), service_of(app)
        await stage(pilot, sheet, "MASK_FIELD_0001", "255")
        live = app.current_file.mem_map
        service.apply(live, [(min(live), max(live) + 1)], None, None)
        assert (live[MASK_WORD], live[MASK_WORD + 1]) == (0x1F, 0xF7), "arm setup: the apply wrote the live map"
        service.remove_entry(f"0x{MASK_WORD:X}")
        assert service.document.entries == []
        await stage(pilot, sheet, "MASK_BIT_0001", "0")
        return [(e.address, bytes(e.encoded_bytes)) for e in service.document.entries]

    assert run(tmp_path, defc, body) == [(MASK_WORD, bytes([0x1A, 0xE6]))]


# ------------------------------------------------------------------ R-PE-DEF.57 / .56 / R-PE.35: a refusal


def _refused_status(tmp_path, defc, name, text):
    async def body(app, pilot, panel):
        await stage(pilot, sheet_of(panel), name, text)
        return last_status(app), list(service_of(app).document.entries), panel.is_dirty

    status, entries, dirty = run(tmp_path, defc, body)
    assert entries == [] and dirty is False
    return status


def test_r_pe_def_57_1_250_status_line(tmp_path, defc):
    status = _refused_status(tmp_path, defc, "DISPLAY_0001", "250")
    assert status == "Patch Editor: DISPLAY_0001: 250 is outside the extended limits -50..200"


def test_r_pe_def_57_2_abc_status_line(tmp_path, defc):
    status = _refused_status(tmp_path, defc, "DISPLAY_0001", "abc")
    assert status == f"Patch Editor: {refusal(defc, 'DISPLAY_0001', 'abc').message}"


def test_r_pe_def_57_3_walk_status_line(tmp_path, defc):
    status = _refused_status(tmp_path, defc, "ENUM_0001", "WALK")
    assert status == f"Patch Editor: {refusal(defc, 'ENUM_0001', 'WALK').message}"


def test_r_pe_035_1_refused_stage_keeps_the_flag_clear(tmp_path, defc):
    async def body(app, pilot, panel):
        await stage(pilot, sheet_of(panel), "DISPLAY_0001", "abc")
        return panel.is_dirty

    assert run(tmp_path, defc, body) is False


def test_r_pe_035_2_refused_stage_keeps_the_flag_set(tmp_path, defc):
    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await stage(pilot, sheet, "ENUM_0001", "RUN")
        assert panel.is_dirty is True, "arm setup: the first stage set the flag"
        await stage(pilot, sheet, "DISPLAY_0001", "abc")
        return panel.is_dirty

    assert run(tmp_path, defc, body) is True


# ------------------------------------------------------------------ R-PE-DEF.59: the notice is a line of its own


def test_r_pe_def_59_1_app_notice_is_a_status_line_of_its_own(tmp_path, defc):
    notice = encoded(defc, "DISPLAY_0001", "175").notices
    assert len(notice) == 1

    async def body(app, pilot, panel):
        await stage(pilot, sheet_of(panel), "DISPLAY_0001", "175")
        return list(app.log_lines)[-2:]

    lines = run(tmp_path, defc, body)
    # R-PE-DEF.58: <text> is the staged value's decoded text (decimals 1 → `175.0`), not the typed
    # `175` of example EX-D4 (orchestrator ruling on impl-a finding A-1: the requirement holds).
    assert lines[0] == "Patch Editor: DISPLAY_0001 staged as 175.0 (2 B at 0x800020)."
    assert lines[1] == f"Patch Editor: {notice[0]}"
    assert "warning" not in lines[1]


# ------------------------------------------------------------------ R-PE-DEF.60: the selection after a stage


def test_r_pe_def_60_1_stage_selects_the_next_row(tmp_path, defc):
    async def body(app, pilot, panel):
        sheet, names = sheet_of(panel), page_names(panel)
        await select_row(pilot, sheet, "DISPLAY_0001")
        await stage(pilot, sheet, "DISPLAY_0001", "25.5")
        return names, sheet.selected_name

    names, selected = run(tmp_path, defc, body)
    assert selected == names[names.index("DISPLAY_0001") + 1]


def test_r_pe_def_60_2_stage_on_the_last_row_stays(tmp_path, defc):
    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        picker_filter = need(panel, "#patch_param_filter")
        picker_filter.value = "MASK"
        for _ in range(100):
            await pilot.pause(0.03)
            if page_names(panel) == ["MASK_BIT_0001", "MASK_FIELD_0001"]:
                break
        names = page_names(panel)
        assert names == ["MASK_BIT_0001", "MASK_FIELD_0001"], f"arm setup: the filter gave {names}"
        await select_row(pilot, sheet, "MASK_FIELD_0001")
        await stage(pilot, sheet, "MASK_FIELD_0001", "255")
        return sheet.selected_name, list(service_of(app).document.entries)

    selected, entries = run(tmp_path, defc, body)
    assert len(entries) == 1, "arm setup: the stage wrote"
    assert selected == "MASK_FIELD_0001"


def test_r_pe_def_60_3_selection_moved_before_the_stage_is_handled(tmp_path, defc):
    async def body(app, pilot, panel):
        sheet, names = sheet_of(panel), page_names(panel)
        two_down = names[names.index("DISPLAY_0001") + 2]
        await select_row(pilot, sheet, two_down)
        await stage(pilot, sheet, "DISPLAY_0001", "25.5")
        return names, sheet.selected_name

    names, selected = run(tmp_path, defc, body)
    assert selected == names[names.index("DISPLAY_0001") + 1]


def test_r_pe_def_60_4_note_staged_without_advance_keeps_the_selection(tmp_path, defc):
    async def body(app, pilot, panel):
        sheet, names = sheet_of(panel), page_names(panel)
        await select_row(pilot, sheet, names[0])
        before = sheet.selected_name
        panel.note_staged("DISPLAY_0001", advance=False)
        await settle(pilot, 4)
        return before, sheet.selected_name, panel.is_dirty

    before, after, dirty = run(tmp_path, defc, body)
    assert after == before
    assert dirty is True


# ------------------------------------------------------------------ R-PE-DEF.62: the staged mark follows the document


MARK = "●"


def staged_mark(row: str) -> bool:
    """The staged mark sits in the mark column's second cell (R-PE-DEF.23). The Limits ruler paints
    its own `●` at the current value on every row with limits (R-PE-DEF.21), so `MARK in row` is
    true for an unstaged row too and cannot tell staged from unstaged (E4 integration, test side)."""
    return row[1:2] == MARK


def test_r_pe_def_62_1_undo_of_a_stage_clears_the_mark(tmp_path, defc):
    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        before = sheet_row(app, sheet, "DISPLAY_0001")
        await stage(pilot, sheet, "DISPLAY_0001", "25.5")
        staged = sheet_row(app, sheet, "DISPLAY_0001")
        need(panel, "#patch_undo_button").press()
        await settle(pilot, 8)
        return before, staged, sheet_row(app, sheet, "DISPLAY_0001")

    before, staged, after = run(tmp_path, defc, body)
    assert not staged_mark(before) and staged_mark(staged) and not staged_mark(after)


def test_r_pe_def_62_2_remove_of_the_word_entry_unstages_both_rows(tmp_path, defc):
    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await stage(pilot, sheet, "MASK_FIELD_0001", "255")
        # EX-O1: FIELD 255 then BIT 0 → one word entry (31, 246). The field alone leaves bit 0 at 1,
        # so MASK_BIT_0001's value is unchanged and it is not staged (R-PE-DEF.23: value texts differ).
        await stage(pilot, sheet, "MASK_BIT_0001", "0")
        assert len(service_of(app).document.entries) == 1, "arm setup: the two stages share one word entry"
        staged = [staged_mark(sheet_row(app, sheet, n)) for n in ("MASK_FIELD_0001", "MASK_BIT_0001")]
        need(panel, "#patch_tab_inspector").press()
        await settle(pilot, 3)
        need(panel, "#patch_entry_address_input").value = f"0x{MASK_WORD:X}"
        need(panel, "#patch_entry_remove_button").press()
        await settle(pilot, 8)
        assert service_of(app).document.entries == [], "arm setup: Remove took the entry"
        return staged, [staged_mark(sheet_row(app, sheet, n)) for n in ("MASK_FIELD_0001", "MASK_BIT_0001")]

    staged, after = run(tmp_path, defc, body)
    assert staged == [True, True]
    assert after == [False, False]


def test_r_pe_def_62_3_parse_pasted_marks_the_row(tmp_path, defc):
    source = ChangeService()
    assert source.stage_definition(defc["defs"]["DISPLAY_0001"], defc["a2l"], "25.5", defc["image"]).ok
    pasted = serialize_change_document(source.document).decode("utf-8")

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        before = sheet_row(app, sheet, "DISPLAY_0001")
        need(panel, "#patch_tab_json").press()
        await settle(pilot, 3)
        need(panel, "#patch_paste_text").text = pasted
        need(panel, "#patch_paste_parse_button").press()
        await settle(pilot, 8)
        assert len(service_of(app).document.entries) == 1, "arm setup: Parse pasted loaded the document"
        return before, sheet_row(app, sheet, "DISPLAY_0001")

    before, after = run(tmp_path, defc, body)
    assert not staged_mark(before) and staged_mark(after)


def test_r_pe_def_62_4_new_image_word_changes_the_staged_cue(tmp_path, defc):
    """MASK_FIELD_0001 `255` staged over word 1A E7, then an image whose word is 1A E6: MASK_BIT_0001 now
    differs from the staged word (its bit 1 from the entry), so it shows the mark and New `1 (0x01)`."""
    new_image = dict(defc["image"])
    new_image[MASK_WORD + 1] = 0xE6

    async def body(app, pilot, panel):
        sheet = sheet_of(panel)
        await stage(pilot, sheet, "MASK_FIELD_0001", "255")
        panel.set_image_mem_map(new_image)
        await settle(pilot, 6)
        return sheet_row(app, sheet, "MASK_BIT_0001")

    row = run(tmp_path, defc, body)
    assert staged_mark(row)
    assert "1 (0x01)" in row


# ------------------------------------------------------------------ R-PE.110 / .63 / .64 / .73


def test_r_pe_110_1_stage_refused_while_a_session_action_runs(tmp_path, defc):
    async def body(app, pilot, panel):
        service = service_of(app)
        gen = app._busy_begin_action("file_load", "x.s19")
        assert gen is not None
        label = app._running_session_action().label
        await stage(pilot, sheet_of(panel), "DISPLAY_0001", "25.5")
        return label, last_status(app), list(service.document.entries), panel.is_dirty

    label, status, entries, dirty = run(tmp_path, defc, body)
    assert status == _BUSY_LINE.format(label=label)
    assert entries == [] and dirty is False


def test_r_pe_def_63_1_no_a2l_refuses_the_stage(tmp_path, defc):
    async def body(app, pilot, panel):
        app.current_a2l_data = None  # the A2L is unloaded between the selection and Enter
        await stage(pilot, sheet_of(panel), "DISPLAY_0001", "25.5")
        return last_status(app), list(service_of(app).document.entries), panel.is_dirty

    status, entries, dirty = run(tmp_path, defc, body)
    assert status == NO_A2L_LINE
    assert entries == [] and dirty is False


def test_r_pe_def_64_1_stage_describes_again_with_the_a2l_loaded_now(tmp_path, defc):
    moved = parse_a2l_file(moved_display_a2l(defc, tmp_path / "moved.a2l"))

    async def body(app, pilot, panel):
        # the reload landed but the page has not repainted: the page's definition still says 0x800020
        app.current_a2l_data = moved
        await stage(pilot, sheet_of(panel), "DISPLAY_0001", "25.5")
        return [(e.address, bytes(e.encoded_bytes)) for e in service_of(app).document.entries]

    entries = run(tmp_path, defc, body)
    assert [address for address, _ in entries] == [DISPLAY_MOVED_ADDRESS]
    assert DISPLAY_ADDRESS not in [address for address, _ in entries]


def test_r_pe_def_73_1_status_line_is_plain_text(tmp_path, defc):
    want = f"Patch Editor: {refusal(defc, 'DISPLAY_0001', 'A[b]').message}"

    async def body(app, pilot, panel):
        await stage(pilot, sheet_of(panel), "DISPLAY_0001", "A[b]")
        return last_status(app), str(need(app, "#log_line_4").render())

    status, painted = run(tmp_path, defc, body)
    assert status == want and "[b]" in status
    assert "[b]" in painted, f"the painted status line ate the brackets: {painted!r}"


# ------------------------------------------------------------------ negative control


def test_control_the_busy_gate_is_what_keeps_the_document_unchanged(tmp_path, defc, monkeypatch):
    """The oracle of R-PE.110/1 is not vacuous: with the busy check bypassed the same stage lands in the document,
    so ``entries == []`` in the test above fails exactly when the gate is missing."""
    monkeypatch.setattr(S19TuiApp, "_refuse_if_busy", lambda self: False)

    async def body(app, pilot, panel):
        app._busy_begin_action("file_load", "x.s19")
        await stage(pilot, sheet_of(panel), "DISPLAY_0001", "25.5")
        return list(service_of(app).document.entries)

    assert len(run(tmp_path, defc, body)) == 1
