"""Batch-103 Inc 10, E4 group G2 (app handlers, arms): what Apply and the entry arms do to the prompt.

Cases: ``inc-10/02-test-cases.md`` rows R-PE-EXPORT.3/1..3, .4/1..3, .5/1..3, .6/1..2, .17/1..5 (the hide on
Add, Edit, Remove, a per-entry JSON edit and a stage from Inc 8's sheet: F-R8-3, ruling P-043), R-CHG-003.2/1,
R-CHG-003.5/1, R-TUI-049.1/1..4 and AT-I10-3.  The files the prompt writes are in
``test_b103_inc10_g2_write.py``.

Driven through the shipped route (Load dialog, the entry boxes, ``Apply loaded changes``, the prompt's chips);
results are read from the painted apply line, the status the app set, the app's notifications and the
compositor.  RED on base ``439860c4``: no apply line, no notice, no hide on the entry arms or the stage, and
``show_save_prompt`` takes one argument.
"""
from __future__ import annotations

import shutil

import pytest

from tests.support import b103_inc10 as t
from tests.support.independent_reader import read_s19

# ------------------------------------------------------------------ R-PE-EXPORT.3: a zero apply hides the prompt


@pytest.mark.parametrize("case,size", [("R-PE-EXPORT.3/1", t.SIZE), ("R-PE-EXPORT.3/2", t.WIDE)],
                         ids=["R-PE-EXPORT.3/1", "R-PE-EXPORT.3/2"])
def test_r_pe_export_3_an_apply_that_applies_nothing_hides_the_prompt(tmp_path, case, size):
    """R-PE-EXPORT.3/1,/2: after an apply of 1 entry the entry is removed and 0x00000010 ``AA`` added (outside
    the image), the prompt is shown again through I-10.1, Apply -> status ``Apply: 0 applied, 1 skipped, 0
    blocked`` and the prompt is not a shown widget.  Negative control: the zero-apply path leaves the prompt
    (the base) -> RED."""

    async def body(app, pilot):
        await t.press_entry(pilot, app, "remove", "Patch Editor: entry removed.", t.PATCH_ADDRESS)
        await t.add_entry(pilot, app, "0x00000010", "AA")
        await t.show_prompt_again(app, pilot)
        status = await t.press_apply(pilot, app)
        return status, t.prompt_hidden(app)

    status, hidden = t.run_applied(tmp_path, size, "firmware.s19", "patch_tab_inspector", body)
    assert status == "Apply: 0 applied, 1 skipped, 0 blocked", status
    assert hidden is True, "the prompt is still a shown widget after an apply that applied nothing"


def test_r_pe_export_3_3_an_apply_of_a_blocked_document_hides_the_prompt(tmp_path):
    """R-PE-EXPORT.3/3: the entry 0x8000007D ``00`` added (a collision), the prompt shown again through I-10.1,
    Apply -> ``0 applied, 2 blocked`` and the prompt is not a shown widget.  Negative control: as /1 -> RED."""

    async def body(app, pilot):
        await t.add_entry(pilot, app, "0x8000007D", "00")
        await t.show_prompt_again(app, pilot)
        status = await t.press_apply(pilot, app)
        return status, t.prompt_hidden(app)

    status, hidden = t.run_applied(tmp_path, t.SIZE, "firmware.s19", "patch_tab_inspector", body)
    assert status == "Apply: 0 applied, 0 skipped, 2 blocked", status
    assert hidden is True, "the prompt is still a shown widget after an apply of a blocked document"


# ------------------------------------------------------------------ R-PE-EXPORT.4: the apply line


def test_r_pe_export_4_1_the_apply_line_after_one_applied_entry(tmp_path):
    """R-PE-EXPORT.4/1: the painted apply line reads exactly the text of the requirement.  Negative control:
    no line (the base) / the counts swapped -> RED."""

    async def body(app, pilot):
        return t.painted(app, t.need(app.screen, "#patch_saveback_apply_line"))

    assert t.run_applied(tmp_path, t.SIZE, "firmware.s19", "patch_tab_inspector", body) == t.APPLY_LINE_1


def test_r_pe_export_4_2_the_apply_line_counts_applied_and_skipped(tmp_path):
    """R-PE-EXPORT.4/2: entries 0x8000007C ``DE AD``, 0x80000040 ``11``, 0x00000010 ``AA`` -> ``2 applied, 1
    skipped, 0 blocked``.  Negative control: <a> and <s> swapped -> RED."""

    async def body(app, pilot):
        await t.add_entry(pilot, app, "0x8000007C", "DE AD")
        await t.add_entry(pilot, app, "0x80000040", "11")
        await t.add_entry(pilot, app, "0x00000010", "AA")
        await t.click_tab(pilot, "patch_tab_inspector")
        await t.press_apply(pilot, app)
        return t.painted(app, t.need(app.screen, "#patch_saveback_apply_line"))

    line = t.run_loaded(tmp_path, t.SIZE, "firmware.s19", body)
    assert line == t.APPLY_LINE_1.replace("1 applied, 0 skipped", "2 applied, 1 skipped"), line


def test_r_pe_export_4_3_a_new_apply_refreshes_the_apply_line(tmp_path):
    """R-PE-EXPORT.4/3: after /1, the entry 0x80000040 ``11`` added and Apply pressed again -> ``2 applied, 0
    skipped, 0 blocked``.  Negative control: the line keeps the first apply's counts -> RED."""

    async def body(app, pilot):
        await t.add_entry(pilot, app, "0x80000040", "11")
        await t.press_apply(pilot, app)
        return t.painted(app, t.need(app.screen, "#patch_saveback_apply_line"))

    line = t.run_applied(tmp_path, t.SIZE, "firmware.s19", "patch_tab_inspector", body)
    assert line == t.APPLY_LINE_1.replace("1 applied", "2 applied"), line


# ------------------------------------------------------------------ R-PE-EXPORT.5, .6: the notice


NOTHING = [
    ("R-PE-EXPORT.5/1", None, [("0x100", "AA")], "Apply: 0 applied, 1 skipped, 0 blocked"),
    ("R-PE-EXPORT.5/2", "firmware.s19", [("0x00000010", "AA")], "Apply: 0 applied, 1 skipped, 0 blocked"),
    ("R-PE-EXPORT.5/3", "firmware.s19", [("0x8000007C", "DE AD BE EF"), ("0x8000007D", "00")],
     "Apply: 0 applied, 0 skipped, 2 blocked"),
]


@pytest.mark.parametrize("case,source,entries,text", NOTHING, ids=[c[0] for c in NOTHING])
def test_r_pe_export_5_an_apply_that_applies_nothing_raises_one_warning_notice(tmp_path, case, source, entries, text):
    """R-PE-EXPORT.5/1..3: exactly one new notice, severity warning, title ``Nothing applied``, text
    ``Apply: 0 applied, <s> skipped, <b> blocked``.  Negative control: no notice (the base), or severity
    information -> RED."""

    async def body(app, pilot):
        for address, run in entries:
            await t.add_entry(pilot, app, address, run)
        await t.press_apply(pilot, app)
        return t.notices(app)[app.notices_at_apply:]

    new = t.run_loaded(tmp_path, t.SIZE, source, body, notifications=True)
    assert new == [("Nothing applied", text, "warning")], (case, new)


@pytest.mark.parametrize("case,source", [("R-PE-EXPORT.6/1", "firmware.s19"), ("R-PE-EXPORT.6/2", "firmware.hex")],
                         ids=["R-PE-EXPORT.6/1", "R-PE-EXPORT.6/2"])
def test_r_pe_export_6_a_successful_apply_raises_no_notice(tmp_path, case, source):
    """R-PE-EXPORT.6/1,/2: Apply with 1 applied entry (S19; Intel HEX) raises 0 new notices, and the prompt
    is shown (so the apply did succeed).  GREEN on base by design (C: 0 notices): it guards the change to
    R-PE-EXPORT.5 against an information notice.  Negative control: an information notice on success -> RED."""

    async def body(app, pilot):
        return t.notices(app)[app.notices_at_apply:], t.prompt_is_shown(app), t.status_text(app)

    new, shown, _status = t.run_applied(tmp_path, t.SIZE, source, "patch_tab_inspector", body, notifications=True)
    assert new == [], (case, new)


# ------------------------------------------------------------------ R-PE-EXPORT.17: an entry change hides it


async def prompt_state(app, pilot) -> tuple:
    return t.prompt_hidden(app), t.status_text(app)


def test_r_pe_export_17_1_adding_an_entry_hides_the_prompt(tmp_path):
    """R-PE-EXPORT.17/1: Applied case01 (prompt shown), 0x80000040 ``11`` added -> ``Patch Editor: entry
    added.`` and the prompt is not a shown widget.  Negative control: the hide dropped from the add arm (the
    base) -> RED."""

    async def body(app, pilot):
        assert t.prompt_offered(app), "precondition: the prompt is offered after Apply"
        await t.add_entry(pilot, app, "0x80000040", "11")
        return t.prompt_hidden(app), t.status_text(app)

    hidden, status = t.run_applied(tmp_path, t.SIZE, "firmware.s19", "patch_tab_inspector", body)
    assert status == "Patch Editor: entry added." and hidden is True, (hidden, status)


def test_r_pe_export_17_2_editing_an_entry_hides_the_prompt(tmp_path):
    """R-PE-EXPORT.17/2: the bytes of 0x8000007C typed as ``CA FE BA BE``, Edit -> ``Patch Editor: entry
    updated.`` and the prompt hidden.  Negative control: the hide dropped from the edit arm -> RED."""

    async def body(app, pilot):
        assert t.prompt_offered(app), "precondition: the prompt is offered after Apply"
        await t.press_entry(pilot, app, "edit", "Patch Editor: entry updated.", t.PATCH_ADDRESS, "CA FE BA BE")
        return t.prompt_hidden(app), t.status_text(app)

    hidden, status = t.run_applied(tmp_path, t.SIZE, "firmware.s19", "patch_tab_inspector", body)
    assert status == "Patch Editor: entry updated." and hidden is True, (hidden, status)


def test_r_pe_export_17_3_removing_an_entry_hides_the_prompt(tmp_path):
    """R-PE-EXPORT.17/3: 0x8000007C typed, Remove -> ``Patch Editor: entry removed.`` and the prompt hidden
    (else ``Write file`` would write a copy of the source, E3-1).  Negative control: the hide dropped from the
    remove arm -> RED."""

    async def body(app, pilot):
        assert t.prompt_offered(app), "precondition: the prompt is offered after Apply"
        await t.press_entry(pilot, app, "remove", "Patch Editor: entry removed.", t.PATCH_ADDRESS)
        return t.prompt_hidden(app), t.status_text(app)

    hidden, status = t.run_applied(tmp_path, t.SIZE, "firmware.s19", "patch_tab_inspector", body)
    assert status == "Patch Editor: entry removed." and hidden is True, (hidden, status)


async def paste_and_parse(app, pilot, text: str) -> None:
    """Paste ``text`` into the JSON tab's buffer and press Parse pasted."""
    from textual.widgets import TextArea

    await t.click_tab(pilot, "patch_tab_json")
    t.need(app.screen, "#patch_paste_text").load_text(text)
    assert isinstance(t.need(app.screen, "#patch_paste_text"), TextArea)
    seen = len(app.status_history)
    await t.click_inner(pilot, "#patch_paste_parse_button")
    await t.settle(pilot, 4)
    await t.wait_for(pilot, lambda: any(s.startswith("Loaded change:") for s in app.status_history[seen:]),
                     "the pasted document's parse")


async def per_entry_json_edit(app, pilot, replacement: str) -> None:
    """Choose ledger row 0, open the per-entry Edit JSON popup, replace its text, click Confirm."""
    from textual.widgets import DataTable

    from s19_app.tui.screens import EntryJsonScreen

    await t.click_tab(pilot, "patch_tab_script")
    table = t.need(app.screen, "#patch_doc_entries_table")
    assert isinstance(table, DataTable) and table.row_count == 1, table.row_count
    await t.press_button(pilot, "#patch_doc_entries_table")
    await t.click_tab(pilot, "patch_tab_inspector")
    await t.click_inner(pilot, "#patch_entry_edit_json_button")
    await t.wait_for(pilot, lambda: isinstance(app.screen, EntryJsonScreen)
                     and len(app.screen.query("#entry_json_confirm")) > 0, "the per-entry JSON popup")
    app.screen.query_one("#entry_json_text").load_text(replacement)
    await t.press_button(pilot, "#entry_json_confirm", 8)
    await t.wait_for(pilot, lambda: not isinstance(app.screen, EntryJsonScreen), "the popup to close")
    await t.settle(pilot, 6)


def test_r_pe_export_17_4_a_per_entry_json_edit_hides_the_prompt(tmp_path):
    """R-PE-EXPORT.17/4: case01 loaded, a one-entry change-set pasted and parsed, Apply (prompt shown), the
    per-entry Edit JSON of entry 0 with its bytes changed to ``CA FE BA BE``, Confirm -> the document holds
    the new bytes (the edit reported ok) and the prompt is not a shown widget.  Negative control: the hide
    dropped from ``_apply_entry_json_edit`` (the base) -> RED."""
    import json

    from tests.support import b100_projects

    text = b100_projects.change_document_bytes([b100_projects.address_entry(0x8000007C, t.PATCH_RUN)]).decode()
    edited = json.dumps({"type": "bytes", "address": "0x8000007C", "bytes": "CA FE BA BE"})

    async def body(app, pilot):
        await paste_and_parse(app, pilot, text)
        await t.press_apply(pilot, app)
        assert t.prompt_offered(app), "precondition: the prompt is offered after Apply"
        await per_entry_json_edit(app, pilot, edited)
        entry = app._change_service.document.entries[0]
        return tuple(entry.encoded_bytes), t.prompt_hidden(app)

    got, hidden = t.run_loaded(tmp_path, t.SIZE, "firmware.s19", body)
    assert got == (0xCA, 0xFE, 0xBA, 0xBE), f"the per-entry edit did not land: {got}"
    assert hidden is True, "the prompt is still a shown widget after the per-entry JSON edit"


async def stage_through_the_sheet(app, pilot, name: str, text: str) -> None:
    """Select ``name`` in Inc 8's staging sheet by keys, Enter to the formula input, type, Enter to stage."""
    sheet = t.need(app.screen, "#patch_sheet")
    t.need(sheet, "#patch_sheet_body").focus()
    await t.settle(pilot, 2)
    for _ in range(40):
        if sheet.selected_name == name:
            break
        await pilot.press("down")
        await t.settle(pilot, 2)
    assert sheet.selected_name == name, f"could not select {name}"
    await pilot.press("enter")
    await pilot.press(*text)
    seen = len(app.status_history)
    await pilot.press("enter")
    await t.wait_for(pilot, lambda: len(app.status_history) > seen, "the stage status")
    await t.settle(pilot, 6)


def test_r_pe_export_17_5_a_stage_from_the_staging_sheet_hides_the_prompt(tmp_path):
    """R-PE-EXPORT.17/5 (F-R8-3, ruling P-043): Inc 8's definitions case loaded (A2L and image through the
    app's loaders), an entry added at 0x800010 and applied (prompt shown), DISPLAY_0001 staged with ``25.5``
    through the sheet's formula input -> the stage is in the document and the prompt is not a shown widget.
    Deviation (declared): the DEFC image, not case01 (the staged-able scalar needs Inc 8's fixture).
    Negative control: the hide dropped from ``on_staging_sheet_stage_requested`` (base) -> RED."""
    from tests.b103_inc8_a_support import MASK_WORD, build_defc
    from tests.support.b100_workers import settle_workers

    defc = build_defc(tmp_path / "defc")

    async def body(app, pilot):
        app.load_a2l_from_path(defc["a2l_path"])
        await settle_workers(pilot)
        assert app.current_a2l_data is not None, "the A2L did not load"
        app.load_from_path(defc["s19_path"])
        await t.wait_for(pilot, lambda: app.current_file is not None, "the image load")
        await t.open_patch_editor(pilot, app)
        await t.click_tab(pilot, "patch_tab_inspector")
        await t.add_entry(pilot, app, f"0x{MASK_WORD:X}", "00 01")
        await t.press_apply(pilot, app)
        assert t.prompt_offered(app), "precondition: the prompt is offered after Apply"
        entries_before = len(app._change_service.document.entries)
        await stage_through_the_sheet(app, pilot, "DISPLAY_0001", "25.5")
        return entries_before, len(app._change_service.document.entries), t.prompt_hidden(app)

    before, after, hidden = t.run_scene(tmp_path, t.SIZE, body)
    assert after == before + 1, f"the stage did not add an entry ({before} -> {after})"
    assert hidden is True, "the prompt is still a shown widget after a stage"


# ------------------------------------------------------------------ R-CHG-003.2, .5, R-TUI-049.1


def test_r_chg_003_2_1_dont_save_hides_the_prompt_from_the_inspector_tab(tmp_path):
    """R-CHG-003.2/1: ``Don't save`` -> prompt not a shown widget, status ``Patch Editor: save-back
    declined``, no new file in the work area.  Negative control: the prompt left shown -> RED."""

    async def body(app, pilot):
        before = t.work_files(app)
        await t.press_button(pilot, "#patch_saveback_decline_button", 8)
        return t.prompt_hidden(app), t.status_text(app), before, t.work_files(app)

    hidden, status, before, after = t.run_applied(tmp_path, t.SIZE, "firmware.s19", "patch_tab_inspector", body)
    assert hidden is True and status == "Patch Editor: save-back declined", (hidden, status)
    assert after == before, ("a file was written", before, after)


def test_r_chg_003_5_1_write_file_hides_the_prompt_from_the_checks_tab(tmp_path):
    """R-CHG-003.5/1: Applied case01 (Checks tab), ``Write file`` -> prompt not a shown widget and one new file
    in the work area.  Negative control: the prompt left shown -> RED."""

    async def body(app, pilot):
        assert t.prompt_offered(app), "precondition: the prompt is offered (Checks tab)"
        before = t.work_files(app)
        await t.write_file(pilot, app)
        return t.prompt_hidden(app), before, t.work_files(app)

    hidden, before, after = t.run_applied(tmp_path, t.SIZE, "firmware.s19", "patch_tab_checks", body)
    assert hidden is True, "the prompt is still a shown widget after Write file"
    assert len(after) == len(before) + 1, (before, after)


TUI_49 = [("R-TUI-049.1/1", "patch_tab_inspector"), ("R-TUI-049.1/2", "patch_tab_json"),
          ("R-TUI-049.1/3", "patch_tab_checks"), ("R-TUI-049.1/4", "patch_tab_script")]
SAVED_1 = "Saved + verified: firmware-patched.s19 — 1 entry applied before this save (0x8000007C)"


@pytest.mark.parametrize("case,tab", TUI_49, ids=[c[0] for c in TUI_49])
def test_r_tui_049_1_the_before_after_control_is_shown_after_a_save_back(tmp_path, case, tab):
    """R-TUI-049.1/1..4 (118x54): ``Write file`` from each tab -> the painted status of R-HEX-VERIFY-002.1 and
    ``Write before/after report`` shown at its place.  Negative control: the control left inside the JSON tab
    while the prompt moves -> 3 of 4 RED."""

    async def body(app, pilot):
        await t.write_file(pilot, app)
        control = t.need(app.screen, "#patch_before_after_button")
        return t.at_its_place(app, control), t.painted_log(app)

    place, log = t.run_applied(tmp_path, t.SIZE, "firmware.s19", tab, body)
    assert SAVED_1 in log, (case, log)
    assert place == [], (case, place)


# ------------------------------------------------------------------ AT-I10-3


def test_at_i10_3_an_apply_that_applies_nothing_is_seen(tmp_path):
    """AT-I10-3 (118x54): case01 loaded, applied once (prompt shown); Remove the entry (prompt hidden,
    R-PE-EXPORT.17); add 0x00000010 ``AA``; Apply -> a warning notice ``Nothing applied`` / ``Apply: 0 applied,
    1 skipped, 0 blocked``, the prompt still hidden, and the byte at 0x8000007C back to its source value.
    Negative control: a prompt left after Remove, or no notice, or the patched byte left in the image -> RED."""
    original = read_s19(t.CASE01).data[0x8000007C]

    async def body(app, pilot):
        assert t.prompt_offered(app), "precondition: the prompt is offered after the first Apply"
        await t.press_entry(pilot, app, "remove", "Patch Editor: entry removed.", t.PATCH_ADDRESS)
        after_remove = t.prompt_hidden(app)
        await t.add_entry(pilot, app, "0x00000010", "AA")
        status = await t.press_apply(pilot, app)
        return (after_remove, status, t.notices(app)[app.notices_at_apply:], t.prompt_hidden(app),
                app.current_file.mem_map[0x8000007C])

    after_remove, status, new, hidden, byte = t.run_applied(
        tmp_path, t.SIZE, "firmware.s19", "patch_tab_inspector", body, notifications=True)
    assert after_remove is True, "the prompt survived Remove"
    assert status == "Apply: 0 applied, 1 skipped, 0 blocked", status
    assert new == [("Nothing applied", "Apply: 0 applied, 1 skipped, 0 blocked", "warning")], new
    assert hidden is True and byte == original, (hidden, hex(byte), hex(original))


# ------------------------------------------------------------------ DF-04 (a): the notice is not markup-parsed


def test_the_nothing_applied_notice_is_shown_literally_for_a_markup_file_name(tmp_path):
    """The ``Nothing applied`` notice is raised ``markup=False`` while an image whose name opens a markup tag
    (``[bold]x...``; a name cannot hold the closing ``[/]``, it has a slash) is loaded, so no bracket text in
    a name or in the apply line is read as markup; the app's markup default is True, so the notice flag is
    what keeps a hostile name literal.  Negative control: the notice raised with the default (the base) -> RED."""
    hostile = tmp_path / "sources" / "[bold]xfirmware.s19"
    shutil.copy2(t.copy_source(tmp_path, "firmware.s19"), hostile)

    async def body(app, pilot):
        await t.load_fast(pilot, app, hostile)
        await t.add_entry(pilot, app, "0x00000010", "AA")
        await t.press_apply(pilot, app)
        return [n for n in app._notifications if n.title == "Nothing applied"]

    new = t.run_loaded(tmp_path, t.SIZE, None, body, notifications=True)
    assert [(n.message, n.markup) for n in new] == [("Apply: 0 applied, 1 skipped, 0 blocked", False)], new
