"""
Patch Editor memory-change integration tests — s19_app batch-04, increment 8.

These tests verdict the increment-8 Patch Editor UI extension — the
memory-field change kind managed alongside the batch-03 parameter changes,
driven headlessly through a real ``S19TuiApp`` via ``App.run_test()`` and the
Textual ``pilot`` (the established ``test_tui_patch_editor.py`` harness):

- **TC-032** — render coexistence: adding a memory change adds a visible row
  in the memory ``DataTable`` while the parameter-change rows and controls
  stay visible and functional (LLR-009.1).
- **TC-033** — memory controls + unified save / load: the memory add / edit /
  remove controls mutate the memory half through the service, and the
  unified save / load actions round-trip the whole change-set through one
  JSON file under ``.s19tool/workarea/`` (LLR-009.2 / LLR-009.3).
- **TC-034** — selective export: the export action produces a ``.cdfx`` and a
  separate memory-field JSON file under the work area and surfaces the
  per-half issues on the status path (LLR-009.3).

The memory-change model / validator / display / unified-file / export unit
behavior is covered by the ``cdfx``-package test modules; this file covers the
**screen + service** seam for the memory-field kind — the widget posts a
message, ``app.py`` routes it to ``CdfxService``, the service calls the
``cdfx`` package, and both tables re-render.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from textual.containers import ScrollableContainer
from textual.widgets import Button, DataTable

from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens_directionb import PatchEditorPanel
from s19_app.tui.services.cdfx_service import (
    CdfxService,
    parse_address,
    parse_new_bytes,
)

# Synthetic enriched A2L tags — a scalar parameter — so a built parameter
# change-list resolves; synthetic only, per constraint C-9.
_A2L_TAGS = [
    {
        "name": "IGN_ADVANCE_BASE",
        "char_type": "VALUE",
        "decode_type": "UBYTE",
        "element_count": 1,
    },
]


# ===========================================================================
# TC-032 — memory rows coexist with parameter rows (LLR-009.1)
# ===========================================================================


def test_tc032_added_memory_change_appears_as_a_memory_table_row(
    tmp_path: Path,
) -> None:
    """Adding a memory change adds a visible memory-table row (LLR-009.1).

    Intent: LLR-009.1 — the Patch Editor renders the memory-change list as a
    row per entry. After driving the memory add control, the memory
    ``DataTable`` must carry one row and its empty-state line must be hidden.
    """

    async def _drive() -> tuple[int, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            app.query_one("#patch_address_input").value = "0x100"
            app.query_one("#patch_bytes_input").value = "DE AD BE EF"
            panel.request_action("add_memory")
            await pilot.pause()
            table = app.query_one("#patch_memory_table", DataTable)
            empty = app.query_one("#patch_memory_empty_state")
            return table.row_count, empty.has_class("hidden")

    row_count, empty_hidden = asyncio.run(_drive())
    assert row_count == 1, "adding a memory change must add one memory row"
    assert empty_hidden, "the memory empty-state must hide once a row exists"


def test_tc032_memory_and_parameter_rows_coexist(tmp_path: Path) -> None:
    """A memory change and a parameter change render side by side (LLR-009.1).

    Intent: LLR-009.1 / RK-5 — the batch-03 parameter-change rows must survive
    the memory-change extension intact. After adding one of each kind, both
    ``DataTable``s carry exactly one row and both empty-state lines are hidden.
    """

    async def _drive() -> tuple[int, int, bool, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            # Add a parameter change through the batch-03 controls.
            app.query_one("#patch_name_input").value = "IGN_ADVANCE_BASE"
            app.query_one("#patch_value_input").value = "23"
            panel.request_action("add")
            await pilot.pause()
            # Add a memory change through the batch-04 controls.
            app.query_one("#patch_address_input").value = "0x200"
            app.query_one("#patch_bytes_input").value = "01 02"
            panel.request_action("add_memory")
            await pilot.pause()
            param_table = app.query_one(
                "#patch_changelist_table", DataTable
            )
            memory_table = app.query_one("#patch_memory_table", DataTable)
            param_empty = app.query_one("#patch_empty_state")
            memory_empty = app.query_one("#patch_memory_empty_state")
            return (
                param_table.row_count,
                memory_table.row_count,
                param_empty.has_class("hidden"),
                memory_empty.has_class("hidden"),
            )

    param_rows, memory_rows, param_hidden, memory_hidden = asyncio.run(
        _drive()
    )
    assert param_rows == 1, "the parameter-change row must remain visible"
    assert memory_rows == 1, "the memory-change row must be visible"
    assert param_hidden, "the parameter empty-state must hide with a row"
    assert memory_hidden, "the memory empty-state must hide with a row"


def test_tc032_memory_row_shows_hex_value_and_status(tmp_path: Path) -> None:
    """A memory row shows the hex byte rendering and a status (LLR-009.1).

    Intent: LLR-009.1 — a memory row's columns are the address, the hex
    rendering of the new bytes, and the validation status. With no image
    loaded the status is ``unvalidated-no-image``.
    """

    async def _drive() -> tuple[str, str, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            app.query_one("#patch_address_input").value = "0x100"
            app.query_one("#patch_bytes_input").value = "0x01 0xAB 0xFF"
            panel.request_action("add_memory")
            await pilot.pause()
            table = app.query_one("#patch_memory_table", DataTable)
            row = table.get_row_at(0)
            return str(row[0]), str(row[1]), str(row[2])

    address_text, value_text, status_text = asyncio.run(_drive())
    assert address_text == "0x100", "the address column must show hex address"
    assert value_text == "01 AB FF", (
        f"the value column must show the hex byte run, got {value_text!r}"
    )
    assert status_text == "unvalidated-no-image", (
        f"with no image loaded the status must be unvalidated-no-image, "
        f"got {status_text!r}"
    )


# ===========================================================================
# TC-033 — memory controls + unified save / load (LLR-009.2 / LLR-009.3)
# ===========================================================================


def test_tc033_memory_edit_updates_only_the_targeted_entry(
    tmp_path: Path,
) -> None:
    """Editing a memory change updates only that entry (LLR-009.2).

    Intent: LLR-009.2 — the memory edit control changes the bytes of the
    addressed entry and leaves every other memory entry untouched.
    """

    async def _drive() -> tuple[tuple, tuple]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            service = app._cdfx_service
            service.add_memory_change("0x100", "01 02")
            service.add_memory_change("0x200", "0A 0B")
            app.query_one("#patch_address_input").value = "0x100"
            app.query_one("#patch_bytes_input").value = "FF FE FD"
            panel.request_action("edit_memory")
            await pilot.pause()
            edited = service.unified.memory.get(0x100)
            untouched = service.unified.memory.get(0x200)
            return edited.new_bytes, untouched.new_bytes

    edited_bytes, untouched_bytes = asyncio.run(_drive())
    assert edited_bytes == (0xFF, 0xFE, 0xFD), (
        "memory edit must update the targeted entry's bytes"
    )
    assert untouched_bytes == (0x0A, 0x0B), (
        "memory edit must not change any other entry"
    )


def test_tc033_memory_remove_returns_to_the_empty_state(
    tmp_path: Path,
) -> None:
    """Removing the last memory change restores the empty state (LLR-009.1).

    Intent: LLR-009.1 — with the memory-change list emptied, the screen shows
    the neutral memory empty-state line again rather than a blank table.
    """

    async def _drive() -> tuple[bool, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            app._cdfx_service.add_memory_change("0x100", "01 02")
            app.query_one("#patch_address_input").value = "0x100"
            panel.request_action("remove_memory")
            await pilot.pause()
            table = app.query_one("#patch_memory_table", DataTable)
            empty = app.query_one("#patch_memory_empty_state")
            return (not empty.has_class("hidden")), table.row_count

    empty_visible, row_count = asyncio.run(_drive())
    assert empty_visible, (
        "removing the last memory change must reveal the empty state"
    )
    assert row_count == 0, "the memory table must hold no rows once emptied"


def test_tc033_bad_memory_address_is_reported_not_raised(
    tmp_path: Path,
) -> None:
    """An invalid memory address is reported, never raised (LLR-009.2).

    Intent: an unparseable address field is a user error surfaced through the
    status path — the action must not crash the Patch Editor.
    """

    async def _drive() -> int:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            app.query_one("#patch_address_input").value = "not-an-address"
            app.query_one("#patch_bytes_input").value = "01"
            panel.request_action("add_memory")  # must not raise
            await pilot.pause()
            return len(app._cdfx_service.unified.memory)

    entry_count = asyncio.run(_drive())
    assert entry_count == 0, (
        "a bad memory address must be reported, not added and not raised"
    )


def test_tc033_unified_save_writes_json_under_workarea(
    tmp_path: Path,
) -> None:
    """The unified save action writes a JSON file under the work area.

    Intent: LLR-009.3 — driving the unified save action produces one JSON
    unified change-set file whose resolved path lies under
    ``.s19tool/workarea/``.
    """

    async def _drive() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            app.query_one("#patch_address_input").value = "0x100"
            app.query_one("#patch_bytes_input").value = "DE AD"
            panel.request_action("add_memory")
            await pilot.pause()
            panel.request_action("save_unified")
            await pilot.pause()

    asyncio.run(_drive())

    workarea = (tmp_path / ".s19tool" / "workarea").resolve()
    written = list(workarea.glob("*.json"))
    assert written, "the unified save action must write a .json in the work area"
    assert workarea in written[0].resolve().parents, (
        "a unified file saved through the screen must resolve under "
        ".s19tool/workarea/"
    )


def test_tc033_unified_save_then_load_round_trips_both_halves(
    tmp_path: Path,
) -> None:
    """A screen unified save then load round-trips both halves (LLR-009.3).

    Intent: LLR-009.3 — build a parameter change and a memory change through
    the controls, drive ``save_unified``, replace the service with a fresh
    one (a new app), then drive ``load_unified`` on the written path. Both
    halves must repopulate from the parsed unified file.
    """

    async def _save() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            app.query_one("#patch_name_input").value = "IGN_ADVANCE_BASE"
            app.query_one("#patch_value_input").value = "23"
            panel.request_action("add")
            await pilot.pause()
            app.query_one("#patch_address_input").value = "0x100"
            app.query_one("#patch_bytes_input").value = "01 02 03"
            panel.request_action("add_memory")
            await pilot.pause()
            panel.request_action("save_unified")
            await pilot.pause()
        written = next(
            (tmp_path / ".s19tool" / "workarea").resolve().glob("*.json")
        )
        return str(written)

    async def _load(path: str) -> tuple[int, int, int, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            app.query_one("#patch_unified_input").value = path
            panel.request_action("load_unified")
            await pilot.pause()
            param_table = app.query_one(
                "#patch_changelist_table", DataTable
            )
            memory_table = app.query_one("#patch_memory_table", DataTable)
            counts = app._cdfx_service.unified.counts()
            return (
                param_table.row_count,
                memory_table.row_count,
                counts[0],
                counts[1],
            )

    path = asyncio.run(_save())
    param_rows, memory_rows, param_count, memory_count = asyncio.run(
        _load(path)
    )
    assert param_count == 1, "the loaded unified file must hold 1 parameter"
    assert memory_count == 1, "the loaded unified file must hold 1 memory change"
    assert param_rows == 1, "the parameter table must repopulate from the file"
    assert memory_rows == 1, "the memory table must repopulate from the file"


def test_tc033_malformed_unified_load_does_not_crash_the_screen(
    tmp_path: Path,
) -> None:
    """A malformed unified-file load is reported, never crashes (LLR-009.3).

    Intent: LLR-009.3 — driving ``load_unified`` on a malformed JSON file must
    leave the screen usable: the change-set stays empty, both empty-state
    lines show, and an ``MF-*`` issue is surfaced on the status path.
    """
    bad = tmp_path / "broken.json"
    bad.write_text("{ this is not valid json", encoding="utf-8")

    async def _drive() -> tuple[int, int, bool, list[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            app.query_one("#patch_unified_input").value = str(bad)
            panel.request_action("load_unified")  # must not crash
            await pilot.pause()
            param_table = app.query_one(
                "#patch_changelist_table", DataTable
            )
            memory_table = app.query_one("#patch_memory_table", DataTable)
            memory_empty = app.query_one("#patch_memory_empty_state")
            return (
                param_table.row_count,
                memory_table.row_count,
                not memory_empty.has_class("hidden"),
                list(app.log_lines),
            )

    param_rows, memory_rows, memory_empty_visible, log_lines = asyncio.run(
        _drive()
    )
    assert param_rows == 0, "a malformed unified file must load no parameters"
    assert memory_rows == 0, "a malformed unified file must load no memory rows"
    assert memory_empty_visible, (
        "the memory empty-state must show after a rejected malformed load"
    )
    assert any("MF-" in line for line in log_lines), (
        f"a malformed unified load must surface an MF-* issue, got {log_lines}"
    )


# ===========================================================================
# TC-034 — selective export through the screen (LLR-009.3)
# ===========================================================================


def test_tc034_export_writes_cdfx_and_memory_field_files(
    tmp_path: Path,
) -> None:
    """The export action writes a .cdfx and a memory-field .json (LLR-009.3).

    Intent: LLR-009.3 — driving the export action on a unified change-set with
    both halves produces two distinct files under ``.s19tool/workarea/``: a
    ``.cdfx`` for the parameter half and a JSON file for the memory-field half.
    """

    async def _drive() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app._compute_a2l_enriched_tags = lambda: _A2L_TAGS  # type: ignore[method-assign]
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            app.query_one("#patch_name_input").value = "IGN_ADVANCE_BASE"
            app.query_one("#patch_value_input").value = "23"
            panel.request_action("add")
            await pilot.pause()
            app.query_one("#patch_address_input").value = "0x100"
            app.query_one("#patch_bytes_input").value = "DE AD BE EF"
            panel.request_action("add_memory")
            await pilot.pause()
            panel.request_action("export")
            await pilot.pause()

    asyncio.run(_drive())

    workarea = (tmp_path / ".s19tool" / "workarea").resolve()
    cdfx_files = list(workarea.glob("*.cdfx"))
    json_files = list(workarea.glob("*.json"))
    assert cdfx_files, "the export action must write a .cdfx file"
    assert json_files, "the export action must write a memory-field .json file"
    assert workarea in cdfx_files[0].resolve().parents, (
        "the exported .cdfx must resolve under .s19tool/workarea/"
    )
    assert workarea in json_files[0].resolve().parents, (
        "the exported memory-field .json must resolve under .s19tool/workarea/"
    )


def test_tc034_export_surfaces_per_half_issues_on_status_path(
    tmp_path: Path,
) -> None:
    """An export with no A2L loaded surfaces the no-A2L issue (LLR-009.3).

    Intent: LLR-009.3 — with no A2L loaded, the export re-resolves the
    parameter half against nothing and collects one informational
    parameter-half issue. Driving ``export`` through the screen must route
    that issue to the status path so the engineer sees it.
    """

    async def _drive() -> list[str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            # A parameter entry with no A2L loaded -> re-resolution warns.
            app.query_one("#patch_name_input").value = "IGN_ADVANCE_BASE"
            app.query_one("#patch_value_input").value = "23"
            panel.request_action("add")
            await pilot.pause()
            app.query_one("#patch_address_input").value = "0x100"
            app.query_one("#patch_bytes_input").value = "01 02"
            panel.request_action("add_memory")
            await pilot.pause()
            panel.request_action("export")
            await pilot.pause()
            return list(app.log_lines)

    log_lines = asyncio.run(_drive())
    assert any("export" in line.lower() for line in log_lines), (
        f"the export action must report on the status path, got {log_lines}"
    )
    assert any("param-half" in line for line in log_lines), (
        "the no-A2L re-resolution issue must be tagged param-half on the "
        f"status path, got {log_lines}"
    )


# ===========================================================================
# Service-helper unit checks — the memory address / new-bytes parsers
# ===========================================================================


def test_parse_address_accepts_hex_and_decimal() -> None:
    """A memory address parses from a 0x hex or a plain decimal literal."""
    assert parse_address("0x100") == 256
    assert parse_address("512") == 512


def test_parse_address_rejects_blank_and_negative() -> None:
    """A blank or negative memory address is rejected (LLR-009.2)."""
    import pytest

    with pytest.raises(ValueError):
        parse_address("")
    with pytest.raises(ValueError):
        parse_address("-1")


def test_parse_new_bytes_accepts_hex_decimal_and_bare_hex() -> None:
    """A new-bytes field parses prefixed hex, decimal and bare hex tokens."""
    assert parse_new_bytes("0x01 0xAB 0xFF") == [1, 171, 255]
    assert parse_new_bytes("DE AD BE EF") == [222, 173, 190, 239]
    assert parse_new_bytes("1, 2, 3") == [1, 2, 3]


def test_parse_new_bytes_rejects_a_garbage_token() -> None:
    """A non-numeric byte token is rejected (LLR-009.2)."""
    import pytest

    with pytest.raises(ValueError):
        parse_new_bytes("01 ZZ 03")


def test_service_owns_a_unified_change_set() -> None:
    """A fresh CdfxService owns an empty UnifiedChangeSet (LLR-004 / 009.2).

    Intent: increment 8 migrates the service from a bare ``ChangeList`` to a
    ``UnifiedChangeSet``; the ``change_list`` property must still expose the
    parameter half so the batch-03 callers keep working.
    """
    service = CdfxService()
    assert service.unified.is_empty(), "a fresh service must be empty"
    assert service.change_list is service.unified.parameters, (
        "the change_list property must alias the unified parameter half"
    )


# ===========================================================================
# Increment 10 — the Patch Editor panel scrolls so the bottom controls
# (memory half + unified-file Export row) stay reachable.
# ===========================================================================


def test_patch_editor_panel_scrolls_to_reach_export_button(
    tmp_path: Path,
) -> None:
    """The Patch Editor scrolls and the Export button is reachable.

    Intent: the corrective increment fixes a clipped Patch Editor — the panel
    must be a vertical-scroll container so the memory half and the
    unified-file ``Export`` button below the fold are reachable, not lost off
    the bottom edge. At a short 120x30 terminal the stacked content exceeds
    the viewport, so the panel must report a positive scrollable height and
    must be able to scroll the bottom control into view. A non-scrolling
    container would clip the export row and this test would fail.
    """

    async def _drive() -> tuple[bool, int, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            # The Export button must exist in the widget tree regardless of
            # whether it is currently within the viewport.
            export = app.query_one("#patch_export_button", Button)
            is_scrollable = isinstance(panel, ScrollableContainer)
            # Content taller than the viewport => positive max scroll offset.
            max_scroll_y = panel.max_scroll_y
            # Scroll the Export button fully into view; with a plain clipping
            # Container this is a no-op and the button stays off-screen.
            panel.scroll_to_widget(export, animate=False)
            await pilot.pause()
            export_visible = app.screen.region.contains_region(
                export.region
            )
            return is_scrollable, max_scroll_y, export_visible

    is_scrollable, max_scroll_y, export_visible = asyncio.run(_drive())
    assert is_scrollable, "the Patch Editor panel must be a scroll container"
    assert max_scroll_y > 0, (
        "the stacked Patch Editor content must exceed a 120x30 viewport so "
        "the panel actually has somewhere to scroll"
    )
    assert export_visible, (
        "scrolling must bring the Export button into the visible region"
    )
