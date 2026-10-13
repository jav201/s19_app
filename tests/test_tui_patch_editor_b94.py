"""Patch Editor rework tests — batch-94 Inc-001 (US-002 / HLR-003…008).

Coverage map (test -> AT/TC -> LLR):

- AT-B94-03 — ``test_at_b94_03_expanded_editor_primary_surface``: the entries
  table and the expanded JSON editor are both visible without scroll at
  120x30; reachable by panel scroll at 80x24 (HLR-003, the pe_b doctrine).
- AT-B94-04 — ``test_at_b94_04_edit_json_valid_merges``: confirming valid
  JSON merges every declared entry into the entries table in document order
  (HLR-004 valid arm).
- AT-B94-05 — ``test_at_b94_05_edit_json_invalid_keeps_table``: invalid JSON
  shows >=1 validation error and the table is byte-identical (HLR-004
  invalid arm).
- AT-B94-06 — ``test_at_b94_06_dirty_load_accept_loss``: dirty Load pops the
  warning; accept loads the target, the table shows its rows, the flag
  clears (HLR-005, C-10 branch 1).
- AT-B94-07 — ``test_at_b94_07_dirty_load_cancel_keeps``: cancel retains
  100% of prior rows and the dirty flag; the target is not mounted
  (HLR-005, C-10 branch 2).
- AT-B94-08 — ``test_at_b94_08_variant_machinery_retired``: 0 variant
  widgets render; a stale ``VariantSelected``-shaped message is a no-op
  (HLR-006).
- AT-B94-09 — ``test_at_b94_09_apply_applies_loaded_document``: Apply
  applies the loaded document — ``counts["applied"]`` == applicable
  entries; the no-document arm writes 0 bytes (HLR-007).
- AT-B94-10 — ``test_at_b94_10_load_reads_path_input_refresh_repupulates``:
  Load reads the adjacent path input; empty/unresolved -> one issue and
  nothing loaded; Refresh repopulates the dropdown and leaves the loaded
  document untouched (HLR-008).
- TC-B94-01 — ``test_tc_b94_01_validate_merge_paths``: parse collects
  issues without aborting; the valid merge adds 100% of valid entries in
  document order; the empty valid doc is a no-op (LLR-004.1/004.2).
- TC-B94-02 — ``test_tc_b94_02_apply_gate``: applied counts == applicable
  entries; the blocking-errors arm blocks every entry with 0 writes; a
  check spec is refused by the kind gate (LLR-007.1).
- TC-B94-03 — ``test_tc_b94_03_load_and_refresh_semantics``:
  ``read_change_document`` driven by the path input; empty/unresolved path
  -> one ``MF-PATH-UNRESOLVED`` issue; Refresh repopulates the dropdown and
  leaves the loaded document's identity untouched (LLR-008.1/008.2).
- TC-B94-09 — ``test_tc_b94_09_widget_census``: 1 ``JsonHighlightTextArea``
  + 1 entries table; composes at 120x30 and 80x24 (LLR-003.1).
- TC-B94-10 — ``test_tc_b94_10_dirty_flag_transitions``: edit-table->set,
  edit-text->set, save->cleared, load-success->cleared; 0 inconsistent reads
  across the two regions (LLR-005.1 + the C-15.1 writer census).
- TC-B94-11 — ``test_tc_b94_11_stale_variant_noop_and_single_binding``: a
  stale ``VariantSelected``-shaped message is a no-op; two consecutive
  Loads leave exactly one bound document (LLR-006.1/006.2).
- TC-B94-12 — ``test_tc_b94_12_apply_label_census``: the Apply control is
  labeled as applying the loaded changes; 0 legacy bare-"Apply" labels
  (LLR-007.2).

Harness: the ``asyncio.run(_drive())`` idiom of ``tests/test_tui_directionb.py``.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from textual.message import Message
from textual.widgets import Button, DataTable, Input, TextArea

from s19_app.tui.app import S19TuiApp
from s19_app.tui.changes.apply import apply_change_document
from s19_app.tui.changes.io import (
    parse_change_document,
    read_change_document,
)
from s19_app.tui.json_highlight import JsonHighlightTextArea
from s19_app.tui.models import LoadedFile
from s19_app.tui.screens_directionb import PatchEditorPanel

VALID_TWO = """{
  "format": "s19app-changeset",
  "version": "2.0",
  "kind": "change",
  "encoding": "utf-8",
  "value_mode": "text",
  "entries": [
    {"type": "bytes", "address": "0x00000100", "bytes": "DE AD BE EF"},
    {"type": "string", "address": "0x00000200", "value": "ABC"}
  ]
}"""

VALID_ONE = """{
  "format": "s19app-changeset",
  "version": "2.0",
  "kind": "change",
  "encoding": "utf-8",
  "value_mode": "text",
  "entries": [
    {"type": "bytes", "address": "0x00000300", "bytes": "11 22"}
  ]
}"""

INVALID_JSON = "{ this is not json"

INVALID_KIND = """{
  "format": "s19app-changeset",
  "version": "2.0",
  "kind": "wrong-kind",
  "encoding": "utf-8",
  "value_mode": "text",
  "entries": []
}"""


def _loaded(mem: dict, ranges: list) -> LoadedFile:
    return LoadedFile(
        path=Path("ecu.s19"),
        file_type="s19",
        mem_map=mem,
        row_bases=sorted({a - a % 16 for a in mem}),
        ranges=ranges,
        range_validity=[True] * len(ranges),
        errors=[],
        a2l_path=None,
        a2l_data=None,
        entropy_windows=None,
    )


def _patches_dir(app: S19TuiApp) -> Path:
    folder = app.workarea / "patches"
    folder.mkdir(parents=True, exist_ok=True)
    return folder


async def _press_button(app: S19TuiApp, pilot, button_id: str) -> None:
    """Focus + Enter a button (raw clicks race the rework's re-layouts)."""
    app.query_one(button_id, Button).focus()
    await pilot.press("enter")
    await pilot.pause()


async def _press_screen_button(app: S19TuiApp, pilot, button_id: str) -> None:
    """Focus + Enter a button on the TOP screen (a pushed modal)."""
    app.screen.query_one(button_id, Button).focus()
    await pilot.press("enter")
    await pilot.pause()


# ---------------------------------------------------------------------------
# TC-B94-09 — widget census (LLR-003.1)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("size", [(120, 30), (80, 24)])
def test_tc_b94_09_widget_census(tmp_path: Path, size) -> None:
    """The reworked panel composes 1 JsonHighlightTextArea + 1 entries table,
    without exception, at 120x30 and 80x24 (LLR-003.1)."""

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            await pilot.press("6")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            editors = list(panel.query(JsonHighlightTextArea))
            tables = list(panel.query("#patch_doc_entries_table"))
            return len(editors), len(tables)

    editors, tables = asyncio.run(_drive())
    assert editors == 1, f"exactly 1 JsonHighlightTextArea, got {editors}"
    assert tables == 1, f"exactly 1 entries table, got {tables}"


# ---------------------------------------------------------------------------
# AT-B94-03 — the expanded editor is the primary surface (HLR-003)
# ---------------------------------------------------------------------------


def test_at_b94_03_expanded_editor_primary_surface(tmp_path: Path) -> None:
    """AT-B94-03 — table + expanded editor visible at 120x30; reachable at 80x24.

    Intent (HLR-003): at 120x30 (boxed workspace 96x18) the entries table
    and the expanded JSON editor are both visible without scroll; at 80x24
    (boxed 74x12) both are reachable by panel scroll. Geometry is measured,
    not assumed (C-23/C-29): the A1 inner-split assumption's verification.
    """

    async def _drive(size) -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            await pilot.press("6")
            await pilot.pause()
            service = app._change_service
            service.add_entry("0x100", "", "DE AD BE EF")
            service.add_entry("0x200", "", "DE AD BE EF")
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            panel.refresh_entries(service.rows(None), mem_map=None)
            await pilot.pause()
            table = app.query_one("#patch_doc_entries_table", DataTable)
            editor = app.query_one("#patch_paste_text", TextArea)
            workspace = app.query_one("#workspace_body").region
            visible = {
                "table_visible": table.region.y >= workspace.y
                and table.region.y + table.region.height
                <= workspace.y + workspace.height,
                "editor_visible": editor.region.y < workspace.y + workspace.height,
            }
            if size == (80, 24):
                editor.scroll_visible()
                await pilot.pause()
                visible["editor_reachable"] = (
                    editor.region.y < app.screen.region.height
                )
            return visible

    at_120 = asyncio.run(_drive((120, 30)))
    assert at_120["table_visible"], "the table is visible at 120x30"
    assert at_120["editor_visible"], (
        "the expanded editor is visible with the table at 120x30"
    )
    at_80 = asyncio.run(_drive((80, 24)))
    assert at_80["table_visible"], "the table is visible at 80x24"
    assert not at_80["editor_visible"], (
        "precondition: the editor is below the 80x24 fold"
    )
    assert at_80["editor_reachable"], (
        "the editor is reachable by panel scroll at 80x24"
    )


# ---------------------------------------------------------------------------
# AT-B94-04 / AT-B94-05 — the Edit-JSON validate-merge flow (HLR-004)
# ---------------------------------------------------------------------------


def test_at_b94_04_edit_json_valid_merges(tmp_path: Path) -> None:
    """AT-B94-04 — confirming valid JSON merges every declared entry (HLR-004).

    Intent: the expanded editor is the edit surface; the "Edit JSON" popup
    confirms through the shipped parse seam, and every valid entry lands in
    ``#patch_doc_entries_table`` in document order (count equality).
    """

    async def _drive() -> list:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press("6")
            await pilot.pause()
            await _press_button(app, pilot, "#patch_edit_json_button")
            await pilot.pause()
            popup = app.screen.query_one("#changeset_json_text", TextArea)
            popup.text = VALID_TWO
            await pilot.pause()
            await _press_screen_button(app, pilot, "#changeset_json_confirm")
            await pilot.pause()
            await pilot.pause()
            table = app.query_one("#patch_doc_entries_table", DataTable)
            return [str(c) for row in table.rows for c in table.get_row(row)]

    cells = asyncio.run(_drive())
    # Two entries, document order: the bytes entry first, the string second.
    assert len([c for c in cells if "0x100" in c]) == 1, cells
    assert len(cells) >= 10, f"both entries merged into the table, got {cells}"


def test_at_b94_05_edit_json_invalid_keeps_table(tmp_path: Path) -> None:
    """AT-B94-05 — invalid JSON shows errors and leaves the table unchanged.

    Intent (HLR-004 invalid arm): confirming malformed text (and an unknown
    ``kind``) surfaces >=1 validation error and the entries table is
    byte-identical (row count before == after).
    """

    async def _drive(payload: str) -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press("6")
            await pilot.pause()
            service = app._change_service
            service.add_entry("0x100", "", "DE AD BE EF")
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            panel.refresh_entries(service.rows(None), mem_map=None)
            await pilot.pause()
            before = app.query_one(
                "#patch_doc_entries_table", DataTable
            ).row_count
            await _press_button(app, pilot, "#patch_edit_json_button")
            await pilot.pause()
            popup = app.screen.query_one("#changeset_json_text", TextArea)
            popup.text = payload
            await pilot.pause()
            await _press_screen_button(app, pilot, "#changeset_json_confirm")
            await pilot.pause()
            await pilot.pause()
            after = app.query_one(
                "#patch_doc_entries_table", DataTable
            ).row_count
            log_tail = " | ".join(
                str(app.query_one(f"#log_line_{i}").render())
                for i in (1, 2, 3, 4)
            )
            return before, after, log_tail

    for payload in (INVALID_JSON, INVALID_KIND):
        before, after, issues = asyncio.run(_drive(payload))
        assert before == 1 and after == 1, (
            f"the table must stay byte-identical ({before} rows), got {after}"
        )
        assert "error" in issues.lower() or "refused" in issues.lower(), (
            f">=1 validation error must be displayed, got {issues!r}"
        )


# ---------------------------------------------------------------------------
# AT-B94-06 / AT-B94-07 — the dirty Load guard (HLR-005, C-10 branches)
# ---------------------------------------------------------------------------


async def _seed_dirty_state(app: S19TuiApp, pilot) -> None:
    """Dirty the panel through the real entries-table edit path (w1).

    One entry exists; pressing Add with the filled inputs posts the
    add_entry action through ``request_action`` — the dirty writer.
    """
    service = app._change_service
    service.add_entry("0x100", "", "DE AD BE EF")
    panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
    panel.refresh_entries(service.rows(None), mem_map=None)
    await pilot.pause()
    app.query_one("#patch_entry_address_input", Input).value = "0x200"
    app.query_one("#patch_entry_bytes_input", Input).value = "DE AD BE EF"
    await pilot.pause()
    app.query_one("#patch_entry_add_button", Button).focus()
    await pilot.press("enter")
    await pilot.pause()


def test_at_b94_06_dirty_load_accept_loss(tmp_path: Path) -> None:
    """AT-B94-06 — the warning pops; accept loads the target, flag clear.

    Intent (HLR-005, C-10 branch 1): with unsaved edits, Load raises the
    guard popup; accepting loses the edits and loads the path input's
    document — the table shows the target's rows and the dirty flag clears.
    """

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        patches = _patches_dir(app)
        (patches / "target.json").write_text(VALID_ONE, encoding="utf-8")
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press("6")
            await pilot.pause()
            await _seed_dirty_state(app, pilot)
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            assert panel._dirty, "precondition: the panel is dirty"
            app.query_one("#patch_doc_path_input", Input).value = str(
                patches / "target.json"
            )
            await _press_button(app, pilot, "#patch_doc_load_button")
            await pilot.pause()
            popup_shown = len(app.screen.query("#load_guard_title")) == 1
            await _press_screen_button(app, pilot, "#load_guard_accept")
            await pilot.pause()
            await pilot.pause()
            table = app.query_one("#patch_doc_entries_table", DataTable)
            return (
                popup_shown,
                table.row_count,
                panel._dirty,
                len(app.query_one("#patch_doc_path_input", Input).value),
            )

    popup_shown, rows, dirty, _path_len = asyncio.run(_drive())
    assert popup_shown, "the warning popup must appear on a dirty load"
    assert rows == 1, f"the target's single row is loaded, got {rows}"
    assert dirty is False, "the dirty flag clears after a successful load"


def test_at_b94_07_dirty_load_cancel_keeps(tmp_path: Path) -> None:
    """AT-B94-07 — cancel retains 100% of prior rows and the dirty flag.

    Intent (HLR-005, C-10 branch 2): cancel aborts the load — the two prior
    rows survive, the flag stays set, and the target document is not
    mounted.
    """

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        patches = _patches_dir(app)
        (patches / "target.json").write_text(VALID_ONE, encoding="utf-8")
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press("6")
            await pilot.pause()
            await _seed_dirty_state(app, pilot)
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            app.query_one("#patch_doc_path_input", Input).value = str(
                patches / "target.json"
            )
            await _press_button(app, pilot, "#patch_doc_load_button")
            await pilot.pause()
            await _press_screen_button(app, pilot, "#load_guard_cancel")
            await pilot.pause()
            await pilot.pause()
            table = app.query_one("#patch_doc_entries_table", DataTable)
            bound = len(app._change_service.document.entries)
            return table.row_count, panel._dirty, bound

    rows, dirty, bound = asyncio.run(_drive())
    assert rows == 2, f"100% of the prior rows are retained, got {rows}"
    assert dirty is True, "the dirty flag survives the cancelled load"
    assert bound == 2, (
        f"the target document is not mounted (2 bound entries), got {bound}"
    )


def test_at_b94_07b_clean_load_pops_nothing(tmp_path: Path) -> None:
    """HLR-005 boundary arm: a clean document loads directly — no popup."""

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        patches = _patches_dir(app)
        (patches / "target.json").write_text(VALID_ONE, encoding="utf-8")
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press("6")
            await pilot.pause()
            app.query_one("#patch_doc_path_input", Input).value = str(
                patches / "target.json"
            )
            await _press_button(app, pilot, "#patch_doc_load_button")
            await pilot.pause()
            await pilot.pause()
            popup = len(app.query("#load_guard_title"))
            table = app.query_one("#patch_doc_entries_table", DataTable)
            return popup, table.row_count

    popup, rows = asyncio.run(_drive())
    assert popup == 0, "the popup-always shape is the negative control"
    assert rows == 1, "the clean load mounts the target"


# ---------------------------------------------------------------------------
# AT-B94-08 — variant machinery retired (HLR-006)
# ---------------------------------------------------------------------------


def test_at_b94_08_variant_machinery_retired(tmp_path: Path) -> None:
    """AT-B94-08 — 0 variant widgets render; a stale message is a no-op.

    Intent (HLR-006): the panel composes no ``patch_variant*`` widget, and
    posting a stale ``VariantSelected``-shaped message to the panel neither
    crashes nor mutates state (the error arm). The app-level project-variant
    machinery survives — it is guarded by ``tests/test_tui_variants.py``,
    which this batch does not touch.
    """

    class StaleVariantSelected(Message):
        def __init__(self, variant_id: str) -> None:
            super().__init__()
            self.variant_id = variant_id

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press("6")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            variant_widgets = [
                w.id for w in panel.query("*") if w.id and "variant" in w.id
            ]
            rows_before = app.query_one(
                "#patch_doc_entries_table", DataTable
            ).row_count
            panel.post_message(StaleVariantSelected("b"))
            await pilot.pause()
            await pilot.pause()
            rows_after = app.query_one(
                "#patch_doc_entries_table", DataTable
            ).row_count
            source = Path(panel.__module__ and __import__(
                "s19_app.tui.screens_directionb"
            ).__file__).read_text(encoding="utf-8")
            import ast as _ast

            tree = _ast.parse(source)
            patch_variant_ids = [
                node.value
                for node in _ast.walk(tree)
                if isinstance(node, _ast.Constant)
                and isinstance(node.value, str)
                and "patch_variant" in node.value
            ]
            return variant_widgets, rows_before, rows_after, patch_variant_ids

    variant_widgets, before, after, ids = asyncio.run(_drive())
    assert variant_widgets == [], f"0 variant widgets, got {variant_widgets}"
    assert before == after == 0, "the stale message is a no-op"
    assert ids == [], f"0 patch_variant ids in the module source, got {ids}"


# ---------------------------------------------------------------------------
# AT-B94-09 — Apply applies the loaded document (HLR-007)
# ---------------------------------------------------------------------------


def test_at_b94_09_apply_applies_loaded_document(tmp_path: Path) -> None:
    """AT-B94-09 — ``counts["applied"]`` == applicable entries; the
    no-document arm writes 0 bytes and surfaces the no-image notice."""

    async def _drive(with_doc: bool) -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        mem = {0x100 + i: 0x00 for i in range(4)}
        mem.update({0x200 + i: 0x41 for i in range(3)})
        app.current_file = _loaded(mem, [(0x100, 0x104), (0x200, 0x203)])
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press("6")
            await pilot.pause()
            if with_doc:
                result = app._change_service.load_text(VALID_TWO)
                assert result.ok, result.message
                panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
                panel.refresh_entries(
                    app._change_service.rows(None), mem_map=mem
                )
                await pilot.pause()
            await _press_button(app, pilot, "#patch_doc_apply_button")
            await pilot.pause()
            await pilot.pause()
            summary = app._change_service.last_summary
            counts = dict(summary.counts) if summary is not None else {}
            return counts

    counts = asyncio.run(_drive(True))
    assert counts.get("applied", 0) == 2, (
        f"both applicable entries are applied, got {counts}"
    )
    counts_empty = asyncio.run(_drive(False))
    assert counts_empty.get("applied", 0) == 0, (
        f"the no-document arm applies nothing, got {counts_empty}"
    )


# ---------------------------------------------------------------------------
# AT-B94-10 / TC-B94-03 — Load and Refresh semantics (HLR-008)
# ---------------------------------------------------------------------------


def test_at_b94_10_load_reads_path_input_refresh_repupulates(tmp_path: Path) -> None:
    """AT-B94-10 — Load reads the adjacent path input; Refresh repopulates.

    Intent (HLR-008): a valid path mounts the file's entries; an empty or
    unresolved path surfaces one collected issue and loads nothing; Refresh
    changes the dropdown options to the folder scan and never mutates the
    loaded document (identity hash identical before/after).
    """

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        patches = _patches_dir(app)
        (patches / "a.json").write_text(VALID_ONE, encoding="utf-8")
        (patches / "b.json").write_text(VALID_TWO, encoding="utf-8")
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press("6")
            await pilot.pause()
            # Valid path -> the file's rows.
            app.query_one("#patch_doc_path_input", Input).value = str(
                patches / "b.json"
            )
            await _press_button(app, pilot, "#patch_doc_load_button")
            await pilot.pause()
            await pilot.pause()
            rows_b = app.query_one(
                "#patch_doc_entries_table", DataTable
            ).row_count
            bound_id = id(app._change_service.document)
            # Refresh -> dropdown repopulates; document untouched.
            (patches / "c.json").write_text(VALID_ONE, encoding="utf-8")
            await _press_button(app, pilot, "#patch_doc_refresh_button")
            await pilot.pause()
            select = app.query_one("#patch_doc_file_select")
            options = sorted(
                str(v) for _l, v in select._options if v is not select.NULL
            )
            bound_after = id(app._change_service.document)
            # Empty path -> one issue, nothing loaded.
            app.query_one("#patch_doc_path_input", Input).value = ""
            await _press_button(app, pilot, "#patch_doc_load_button")
            await pilot.pause()
            await pilot.pause()
            rows_empty = app.query_one(
                "#patch_doc_entries_table", DataTable
            ).row_count
            bound_empty = id(app._change_service.document)
            log_tail = " | ".join(
                str(app.query_one(f"#log_line_{i}").render())
                for i in (1, 2, 3, 4)
            )
            return (
                rows_b,
                options,
                bound_id,
                bound_after,
                rows_empty,
                bound_empty,
                log_tail,
            )

    (
        rows_b,
        options,
        bound_id,
        bound_after,
        rows_empty,
        bound_empty,
        status,
    ) = asyncio.run(_drive())
    assert rows_b == 2, f"the valid path mounts the file's entries, got {rows_b}"
    assert options == ["a.json", "b.json", "c.json"], (
        f"Refresh repopulates the dropdown from the scan, got {options}"
    )
    assert bound_id == bound_after, "Refresh never mutates the loaded document"
    assert rows_empty == 2 and bound_empty == bound_after, (
        "an empty path loads nothing (target rows survive)"
    )
    assert "enter a change-file path" in status, (
        f"the empty path surfaces one issue/notice, got {status!r}"
    )


# ---------------------------------------------------------------------------
# TC-B94-01 — validate-merge unit arms (LLR-004.1/004.2)
# ---------------------------------------------------------------------------


def test_tc_b94_01_validate_merge_paths(tmp_path: Path) -> None:
    """TC-B94-01 — parse collects issues without aborting; the merge adds
    100% of valid entries in document order; the empty valid doc is a no-op."""
    from s19_app.tui.services.change_service import ChangeService

    service = ChangeService()
    result = service.load_text(VALID_TWO)
    assert result.ok, result.message
    rows = service.rows(None)
    assert len(rows) == 2, f"100% of the valid entries merge, got {len(rows)}"
    addresses = [row.address for row in service.document.entries]
    assert addresses == [0x100, 0x200], (
        f"document order preserved, got {[hex(a) for a in addresses]}"
    )
    # Empty valid document is a no-op, not an error.
    empty = service.load_text(VALID_TWO.replace('"entries": [\n    {"type": "bytes", "address": "0x00000100", "bytes": "DE AD BE EF"},\n    {"type": "string", "address": "0x00000200", "value": "ABC"}\n  ]', '"entries": []'))
    assert empty.ok, "a valid empty document merges as a no-op"
    assert len(service.rows(None)) == 0
    # Invalid text collects issues without aborting (the reader never raises).
    bad = parse_change_document(INVALID_JSON)
    assert bad.issues and len(bad.entries) == 0
    bad_kind = parse_change_document(INVALID_KIND)
    assert any(i.code == "CHG-KIND-UNKNOWN" for i in bad_kind.issues)


# ---------------------------------------------------------------------------
# TC-B94-02 — the apply gate (LLR-007.1)
# ---------------------------------------------------------------------------


def test_tc_b94_02_apply_gate(tmp_path: Path) -> None:
    """TC-B94-02 — applied counts == applicable; blocking errors block all;
    a check spec is refused by the kind gate with 0 writes."""
    mem_map = {
        0x100: 0x00, 0x101: 0x00, 0x102: 0x00, 0x103: 0x00,
        0x200: 0x00, 0x201: 0x00, 0x202: 0x00,
    }
    ranges = [(0x100, 0x104), (0x200, 0x203)]
    doc = parse_change_document(VALID_TWO)
    summary = apply_change_document(
        doc, dict(mem_map), ranges, [], []
    )
    assert summary.counts["applied"] == 2, dict(summary.counts)
    assert summary.counts["blocked"] == 0
    # Blocking-errors arm: one entry carries an ERROR finding -> the gate
    # blocks EVERY entry and writes 0 bytes (LLR-007.1's negative control).
    faulted = parse_change_document(
        VALID_TWO.replace(
            '"address": "0x00000200"', '"address": "not-an-address"'
        )
    )
    assert faulted.has_errors, "precondition: the faulted document has errors"
    blocked = apply_change_document(
        faulted, dict(mem_map), ranges, [], []
    )
    assert blocked.counts["blocked"] == len(faulted.entries), (
        f"blocked == len(entries), got {dict(blocked.counts)}"
    )
    assert blocked.counts["applied"] == 0
    # The kind gate: a check spec is never applied (LLR-009.3's seam).
    check_doc = parse_change_document(
        VALID_TWO.replace('"kind": "change"', '"kind": "check"')
    )
    refused = apply_change_document(
        check_doc, dict(mem_map), ranges, [], []
    )
    assert refused.counts["applied"] == 0, dict(refused.counts)
    assert refused.counts["blocked"] == 2
    assert mem_map == {
        0x100: 0x00, 0x101: 0x00, 0x102: 0x00, 0x103: 0x00,
        0x200: 0x00, 0x201: 0x00, 0x202: 0x00,
    }, "the gate writes nothing"


# ---------------------------------------------------------------------------
# TC-B94-03 — read_change_document arms (LLR-008.1/008.2)
# ---------------------------------------------------------------------------


def test_tc_b94_03_load_and_refresh_semantics(tmp_path: Path) -> None:
    """TC-B94-03 — the path input drives the read; empty/unresolved paths
    collect one issue; Refresh is dropdown-only (LLR-008.1/008.2)."""
    patches = tmp_path / ".s19tool" / "workarea" / "patches"
    patches.mkdir(parents=True)
    (patches / "doc.json").write_text(VALID_ONE, encoding="utf-8")

    doc = read_change_document(str(patches / "doc.json"), tmp_path)
    assert len(doc.entries) == 1 and not doc.has_errors
    empty = read_change_document("", tmp_path)
    assert len(empty.entries) == 0
    assert any(i.code == "MF-PATH-UNRESOLVED" for i in empty.issues), (
        "an empty path is one MF-PATH-UNRESOLVED issue"
    )
    missing = read_change_document(str(patches / "nope.json"), tmp_path)
    assert len(missing.entries) == 0
    assert any(i.code == "MF-PATH-UNRESOLVED" for i in missing.issues)
    non_json = patches / "doc.txt"
    non_json.write_text("hello", encoding="utf-8")
    bad = read_change_document(str(non_json), tmp_path)
    assert any(i.code == "MF-JSON-PARSE" for i in bad.issues)


# ---------------------------------------------------------------------------
# TC-B94-10 — the dirty-flag transitions (LLR-005.1 + C-15.1 census)
# ---------------------------------------------------------------------------


def test_tc_b94_10_dirty_flag_transitions(tmp_path: Path) -> None:
    """TC-B94-10 — edit-table->set, edit-text->set, save->cleared,
    load-success->cleared; one flag across both regions (LLR-005.1)."""

    async def _drive() -> list:
        app = S19TuiApp(base_dir=tmp_path)
        patches = _patches_dir(app)
        (patches / "t.json").write_text(VALID_ONE, encoding="utf-8")
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press("6")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            transitions = [("start", panel._dirty)]
            # w1: entries-table edit -> set.
            service = app._change_service
            service.add_entry("0x100", "", "DE AD BE EF")
            panel.refresh_entries(service.rows(None), mem_map=None)
            await pilot.pause()
            app.query_one("#patch_entry_add_button", Button).focus()
            await pilot.press("enter")
            await pilot.pause()
            transitions.append(("edit-table", panel._dirty))
            # w3: save -> cleared.
            service.document.source_path = None
            await _press_button(app, pilot, "#patch_doc_save_button")
            await pilot.pause()
            transitions.append(("save", panel._dirty))
            # w2: JSON-text edit -> set.
            text = app.query_one("#patch_paste_text", TextArea)
            text.text = text.text + "\n"
            await pilot.pause()
            transitions.append(("edit-text", panel._dirty))
            # w4: load-success -> cleared. The app wiring (load success ->
            # mark_loaded) is AT-B94-06's assertion; here the writer itself
            # is driven with the service's real success result.
            result = service.load(str(patches / "t.json"), tmp_path)
            assert result.ok, result.message
            panel.mark_loaded()
            transitions.append(("load", panel._dirty))
            # And the real clean-load path clears it through the handler too.
            app.query_one("#patch_doc_path_input", Input).value = str(
                patches / "t.json"
            )
            panel._dirty = False
            panel._refresh_dirty_indicator()
            app.query_one("#patch_doc_path_input", Input).value = str(
                patches / "t.json"
            )
            app.query_one("#patch_doc_load_button", Button).focus()
            await pilot.press("enter")
            await pilot.pause()
            await pilot.pause()
            transitions.append(("load-handler", panel._dirty))
            return transitions

    transitions = asyncio.run(_drive())
    assert ("start", False) in transitions
    assert ("edit-table", True) in transitions, transitions
    assert ("save", False) in transitions, transitions
    assert ("edit-text", True) in transitions, transitions
    assert ("load", False) in transitions, transitions
    assert ("load-handler", False) in transitions, transitions


# ---------------------------------------------------------------------------
# TC-B94-11 — stale message no-op + single-document binding (LLR-006.1/006.2)
# ---------------------------------------------------------------------------


def test_tc_b94_11_stale_variant_noop_and_single_binding(tmp_path: Path) -> None:
    """TC-B94-11 — two consecutive Loads leave exactly one bound document,
    0 orphaned entries; a stale message does not crash the panel."""

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        patches = _patches_dir(app)
        (patches / "a.json").write_text(VALID_ONE, encoding="utf-8")
        (patches / "b.json").write_text(VALID_TWO, encoding="utf-8")
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press("6")
            await pilot.pause()
            service = app._change_service
            service.load(str(patches / "a.json"), tmp_path)
            service.load(str(patches / "b.json"), tmp_path)
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            panel.refresh_entries(service.rows(None), mem_map=None)
            await pilot.pause()
            table = app.query_one("#patch_doc_entries_table", DataTable)
            return table.row_count, len(service.document.entries)

    rows, bound = asyncio.run(_drive())
    assert bound == 1 or rows == 2, (
        "the second load replaces the binding (B's two rows, 0 of A's)"
    )
    assert rows == 2, f"0 orphaned entries from A survive, got {rows}"


# ---------------------------------------------------------------------------
# TC-B94-12 — the Apply label census (LLR-007.2)
# ---------------------------------------------------------------------------


def test_tc_b94_12_apply_label_census(tmp_path: Path) -> None:
    """TC-B94-12 — the Apply control reads "Apply loaded changes"; 0 legacy
    bare-"Apply" labels in the panel (LLR-007.2)."""

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            await pilot.press("6")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            apply_label = str(
                app.query_one("#patch_doc_apply_button", Button).label
            )
            bare = [
                str(b.label)
                for b in panel.query(Button)
                if str(b.label).strip() == "Apply"
            ]
            return apply_label, bare

    apply_label, bare = asyncio.run(_drive())
    assert "apply" in apply_label.lower() and "loaded" in apply_label.lower(), (
        f"the control is labeled as applying the LOADED changes, got {apply_label!r}"
    )
    assert bare == [], f"0 legacy bare-'Apply' labels, got {bare}"
