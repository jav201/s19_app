"""
Functional Patch Editor screen tests — s19_app batch-03, increment 9.

These tests verdict the increment-9 functional Patch Editor:

- **TC-025** — render / edit / empty-state: the change-list table reflects
  added entries, an empty-array-index field yields a ``None``-index scalar
  row, editing an entry updates only its value, and an empty change-list
  shows the neutral empty-state line (LLR-007.1 / LLR-007.2 / LLR-007.6).
- **TC-026** — save / load: the service writes a ``.cdfx`` into the work
  area and reads it back into the change-list (LLR-007.3 / LLR-007.4).
- **TC-028** — inspection: the CDFX handler logic lives in
  ``services.cdfx_service``, not in ``app.py`` (LLR-007.5 / constraint C-8).
- **TC-027a integration arm** — a Patch Editor load of a ``.cdfx`` carrying
  a billion-laughs DOCTYPE is rejected with one ``R-XML-PARSE`` issue and an
  empty change-list, never a crash (the screen-level arm of LLR-006.6).

The change-list-model / writer / reader unit behavior is covered by the
``cdfx``-package test modules; this file covers the **screen + service**
seam — the widget posts a message, ``app.py`` routes it to the service, the
service calls the ``cdfx`` package, and the table re-renders.
"""

from __future__ import annotations

import asyncio
import inspect
from pathlib import Path

import pytest

from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens_directionb import PatchEditorPanel
from s19_app.tui.services.cdfx_service import (
    CdfxService,
    parse_array_index,
    parse_value,
)

# Synthetic enriched A2L tags — a scalar parameter and a 2-element array —
# so a built change-list resolves and the writer emits SW-INSTANCEs (an
# unresolved entry is excluded with W-INSTANCE-EXCLUDED). Synthetic only,
# per constraint C-9 — no client A2L artifact.
_A2L_TAGS = [
    {
        "name": "IGN_ADVANCE_BASE",
        "char_type": "VALUE",
        "decode_type": "UBYTE",
        "element_count": 1,
    },
    {
        "name": "FUEL_TRIM",
        "char_type": "VAL_BLK",
        "decode_type": "UWORD",
        "element_count": 2,
    },
]


# ===========================================================================
# TC-025 — render / edit / empty-state (LLR-007.1 / 007.2 / 007.6)
# ===========================================================================


def test_tc025_added_entry_appears_as_a_table_row(tmp_path: Path) -> None:
    """Adding an entry adds a visible change-list table row (LLR-007.1).

    Intent: LLR-007.1 — the Patch Editor renders the change-list as a row
    per entry. After driving the add control, the change-list ``DataTable``
    must carry one row and the empty-state line must be hidden.
    """
    from textual.widgets import DataTable

    async def _drive() -> tuple[int, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            app.query_one("#patch_name_input").value = "IGN_ADVANCE_BASE"
            app.query_one("#patch_value_input").value = "23"
            panel.request_action("add")
            await pilot.pause()
            table = app.query_one("#patch_changelist_table", DataTable)
            empty = app.query_one("#patch_empty_state")
            return table.row_count, empty.has_class("hidden")

    row_count, empty_hidden = asyncio.run(_drive())
    assert row_count == 1, "adding an entry must add exactly one table row"
    assert empty_hidden, "the empty-state line must hide once a row exists"


def test_tc025_blank_index_field_yields_a_none_index_scalar(
    tmp_path: Path,
) -> None:
    """A blank array-index field yields a None-index scalar entry (LLR-001.1).

    Intent: the index input's None-vs-integer mapping is the UX surface the
    Optional[int] migration created — an empty index field must produce a
    scalar entry (``array_index is None``), never ``array_index = 0``.
    """

    async def _drive() -> object:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            app.query_one("#patch_name_input").value = "IGN_ADVANCE_BASE"
            app.query_one("#patch_index_input").value = ""  # blank => scalar
            app.query_one("#patch_value_input").value = "7"
            panel.request_action("add")
            await pilot.pause()
            entry = app._cdfx_service.change_list.get("IGN_ADVANCE_BASE", None)
            return entry.array_index if entry is not None else "missing"

    array_index = asyncio.run(_drive())
    assert array_index is None, (
        "a blank index field must produce a None-index scalar entry, "
        f"got {array_index!r}"
    )


def test_tc025_typed_index_field_yields_an_array_element(
    tmp_path: Path,
) -> None:
    """A typed array-index field yields an integer-index array entry.

    Intent: LLR-001.1 — a typed non-negative integer index produces an
    array-element entry whose ``array_index`` is that integer.
    """

    async def _drive() -> object:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            app.query_one("#patch_name_input").value = "FUEL_TRIM"
            app.query_one("#patch_index_input").value = "1"
            app.query_one("#patch_value_input").value = "5"
            panel.request_action("add")
            await pilot.pause()
            entry = app._cdfx_service.change_list.get("FUEL_TRIM", 1)
            return entry.array_index if entry is not None else "missing"

    array_index = asyncio.run(_drive())
    assert array_index == 1, (
        f"a typed index '1' must produce array element 1, got {array_index!r}"
    )


def test_tc025_edit_updates_only_the_targeted_entry(tmp_path: Path) -> None:
    """Editing an entry changes only that entry's value (LLR-007.2).

    Intent: LLR-007.2 — the edit control changes the stored value of the
    addressed entry and leaves every other entry untouched.
    """

    async def _drive() -> tuple[object, object]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            service = app._cdfx_service
            service.add_entry("IGN_ADVANCE_BASE", "", "10")
            service.add_entry("FUEL_TRIM", "0", "20")
            app.query_one("#patch_name_input").value = "IGN_ADVANCE_BASE"
            app.query_one("#patch_index_input").value = ""
            app.query_one("#patch_value_input").value = "99"
            panel.request_action("edit")
            await pilot.pause()
            edited = service.change_list.get("IGN_ADVANCE_BASE", None)
            untouched = service.change_list.get("FUEL_TRIM", 0)
            return edited.value, untouched.value

    edited_value, untouched_value = asyncio.run(_drive())
    assert edited_value == 99, "edit must update the targeted entry's value"
    assert untouched_value == 20, "edit must not change any other entry"


def test_tc025_remove_returns_to_the_empty_state(tmp_path: Path) -> None:
    """Removing the last entry restores the empty state (LLR-007.6).

    Intent: LLR-007.6 — with the change-list emptied, the screen shows the
    neutral empty-state line again rather than a blank table.
    """

    async def _drive() -> tuple[bool, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            app._cdfx_service.add_entry("IGN_ADVANCE_BASE", "", "10")
            app.query_one("#patch_name_input").value = "IGN_ADVANCE_BASE"
            app.query_one("#patch_index_input").value = ""
            panel.request_action("remove")
            await pilot.pause()
            from textual.widgets import DataTable

            empty = app.query_one("#patch_empty_state")
            table = app.query_one("#patch_changelist_table", DataTable)
            return (not empty.has_class("hidden")), table.row_count

    empty_visible, row_count = asyncio.run(_drive())
    assert empty_visible, "removing the last entry must reveal the empty state"
    assert row_count == 0, "the table must hold no rows once emptied"


def test_tc025_bad_index_is_reported_not_raised(tmp_path: Path) -> None:
    """A non-integer array index is reported, never raised (LLR-007.2).

    Intent: an invalid index field is a user error surfaced through the
    status path — the action must not crash the Patch Editor.
    """

    async def _drive() -> int:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            app.query_one("#patch_name_input").value = "FUEL_TRIM"
            app.query_one("#patch_index_input").value = "not-an-int"
            app.query_one("#patch_value_input").value = "5"
            panel.request_action("add")  # must not raise
            await pilot.pause()
            return len(app._cdfx_service.change_list)

    entry_count = asyncio.run(_drive())
    assert entry_count == 0, (
        "a bad index must be reported, not added and not raised"
    )


# ===========================================================================
# TC-026 — save / load through the service (LLR-007.3 / 007.4)
# ===========================================================================


def test_tc026_save_writes_cdfx_under_workarea(tmp_path: Path) -> None:
    """The save action writes a .cdfx under .s19tool/workarea/ (LLR-007.3).

    Intent: LLR-007.3 / LLR-007.7 — the Patch Editor save action produces a
    ``.cdfx`` file whose resolved path lies under the work area.
    """
    service = CdfxService()
    service.add_entry("IGN_ADVANCE_BASE", "", "23")
    service.add_entry("FUEL_TRIM", "0", "1")
    service.add_entry("FUEL_TRIM", "1", "2")

    result = service.save(tmp_path, _A2L_TAGS, file_name="patchset.cdfx")

    assert result.ok, f"save must succeed; message was {result.message}"
    workarea = (tmp_path / ".s19tool" / "workarea").resolve()
    written = list(workarea.glob("*.cdfx"))
    assert written, "save must produce a .cdfx file in the work area"
    assert workarea in written[0].resolve().parents, (
        "the written .cdfx must resolve under .s19tool/workarea/"
    )


def test_tc026_save_then_load_round_trips_the_changelist(
    tmp_path: Path,
) -> None:
    """Save then load reproduces the change-list entries (LLR-007.3 / 007.4).

    Intent: a change-list saved as a ``.cdfx`` and loaded back through the
    service yields the same ``(name, array_index, value)`` entry set — the
    scalar entry keeps ``array_index is None`` and the 2-element array
    expands to keys ``(name, 0)`` and ``(name, 1)``.
    """
    service = CdfxService()
    service.add_entry("IGN_ADVANCE_BASE", "", "23")
    service.add_entry("FUEL_TRIM", "0", "11")
    service.add_entry("FUEL_TRIM", "1", "22")

    save_result = service.save(tmp_path, _A2L_TAGS, file_name="rt.cdfx")
    assert save_result.ok, "save must succeed"
    written = next(
        (tmp_path / ".s19tool" / "workarea").resolve().glob("*.cdfx")
    )

    reader = CdfxService()
    load_result = reader.load(str(written), tmp_path, _A2L_TAGS)

    assert load_result.ok, "load must succeed"
    recovered = {
        (e.parameter_name, e.array_index, e.value)
        for e in reader.change_list.entries
    }
    assert recovered == {
        ("IGN_ADVANCE_BASE", None, 23),
        ("FUEL_TRIM", 0, 11),
        ("FUEL_TRIM", 1, 22),
    }, f"the round-trip changed the change-list: {recovered}"


def test_tc026_load_populates_the_screen_rows(tmp_path: Path) -> None:
    """The Patch Editor load action populates the change-list table.

    Intent: LLR-007.4 — driving the load control with a valid ``.cdfx``
    path through the screen repopulates the change-list ``DataTable`` from
    the parsed entries.
    """
    from textual.widgets import DataTable

    seed = CdfxService()
    seed.add_entry("IGN_ADVANCE_BASE", "", "23")
    seed.add_entry("FUEL_TRIM", "0", "1")
    seed.add_entry("FUEL_TRIM", "1", "2")
    seed.save(tmp_path, _A2L_TAGS, file_name="seed.cdfx")
    written = next(
        (tmp_path / ".s19tool" / "workarea").resolve().glob("*.cdfx")
    )

    async def _drive() -> int:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            app.query_one("#patch_path_input").value = str(written)
            panel.request_action("load")
            await pilot.pause()
            table = app.query_one("#patch_changelist_table", DataTable)
            return table.row_count

    row_count = asyncio.run(_drive())
    assert row_count == 3, (
        f"loading a 3-entry .cdfx must populate 3 table rows, got {row_count}"
    )


def test_tc026_save_surfaces_write_issues(tmp_path: Path) -> None:
    """The save action surfaces write-time ValidationIssues (LLR-007.3).

    Intent: an unresolved entry is excluded by the writer with a
    ``W-INSTANCE-EXCLUDED`` warning; the save result must carry that issue
    so the screen can surface it on the status path.
    """
    service = CdfxService()
    # No A2L resolution -> every entry is unresolved -> excluded on write.
    service.add_entry("UNKNOWN_PARAM", "", "1")

    result = service.save(tmp_path, None, file_name="issues.cdfx")

    codes = {issue.code for issue in result.issues}
    assert "W-INSTANCE-EXCLUDED" in codes, (
        f"an unresolved entry must surface W-INSTANCE-EXCLUDED, got {codes}"
    )
    assert all(issue.artifact == "cdfx" for issue in result.issues), (
        "every CDFX issue must carry artifact='cdfx'"
    )


# ===========================================================================
# TC-027a integration arm — malformed .cdfx load is reported, not fatal
# ===========================================================================


def test_tc027a_billion_laughs_load_is_rejected_not_crashed(
    tmp_path: Path,
) -> None:
    """A billion-laughs .cdfx load is rejected with one R-XML-PARSE issue.

    Intent: the screen-level arm of LLR-006.6 — loading a ``.cdfx`` that
    carries a DOCTYPE with nested entity declarations is rejected as one
    ``R-XML-PARSE`` issue and an empty change-list, never a crash or hang.
    """
    payload = (
        '<?xml version="1.0"?>\n'
        "<!DOCTYPE MSRSW [\n"
        '  <!ENTITY a "AAAAAAAAAA">\n'
        '  <!ENTITY b "&a;&a;&a;&a;&a;">\n'
        "]>\n"
        "<MSRSW>&b;</MSRSW>\n"
    )
    bomb = tmp_path / "bomb.cdfx"
    bomb.write_text(payload, encoding="utf-8")

    service = CdfxService()
    result = service.load(str(bomb), tmp_path, None)

    assert len(service.change_list) == 0, (
        "a billion-laughs .cdfx must load an empty change-list"
    )
    codes = {issue.code for issue in result.issues}
    assert codes == {"R-XML-PARSE"}, (
        f"a billion-laughs .cdfx must surface exactly R-XML-PARSE, got {codes}"
    )


# ===========================================================================
# TC-028 — CDFX handler logic lives outside app.py (LLR-007.5, inspection)
# ===========================================================================


def test_tc028_app_py_holds_no_cdfx_xml_logic() -> None:
    """app.py contains no XML / cdfx-format logic (LLR-007.5 / C-8).

    Intent: LLR-007.5 / constraint C-8 — the CDFX read/write and
    change-list model logic resides in ``services.cdfx_service``; ``app.py``
    holds only UI-state wiring. ``app.py`` must not import ``ElementTree``
    or call the ``cdfx``-package read/write functions directly.
    """
    import s19_app.tui.app as app_module

    source = inspect.getsource(app_module)
    # app.py wires the CDFX service, never the format handler directly.
    assert "ElementTree" not in source, (
        "app.py must not parse/serialize XML — that is the cdfx package's job"
    )
    for forbidden in ("write_cdfx", "read_cdfx", "validate_w_rules"):
        assert forbidden not in source, (
            f"app.py must not call {forbidden} directly; it goes through "
            f"CdfxService (LLR-007.5)"
        )


def test_tc028_patch_action_handler_routes_through_the_service() -> None:
    """The Patch Editor action handler delegates to CdfxService (LLR-007.5).

    Intent: AST-confirm that ``on_patch_editor_panel_action_requested``
    drives ``self._cdfx_service`` rather than embedding CDFX logic — the
    handler is UI-state wiring only (constraint C-8).
    """
    handler = inspect.getsource(
        S19TuiApp.on_patch_editor_panel_action_requested
    )
    assert "_cdfx_service" in handler, (
        "the Patch Editor action handler must call self._cdfx_service"
    )


# ===========================================================================
# Service-helper unit checks — the None-vs-integer index mapping
# ===========================================================================


@pytest.mark.parametrize(
    "index_text,expected",
    [("", None), ("   ", None), ("0", 0), ("3", 3)],
)
def test_parse_array_index_maps_blank_to_none(
    index_text: str, expected: object
) -> None:
    """A blank index maps to None; an integer maps to that int (LLR-001.1)."""
    assert parse_array_index(index_text) == expected


def test_parse_array_index_rejects_negative() -> None:
    """A negative array index is rejected (LLR-002.3 precondition)."""
    with pytest.raises(ValueError):
        parse_array_index("-1")


@pytest.mark.parametrize(
    "value_text,expected",
    [("23", 23), ("12.5", 12.5), ("REV_C", "REV_C")],
)
def test_parse_value_coerces_int_float_or_string(
    value_text: str, expected: object
) -> None:
    """A value field coerces to int / float / str as appropriate (LLR-003.3)."""
    parsed = parse_value(value_text)
    assert parsed == expected
    assert type(parsed) is type(expected)


# ===========================================================================
# TC-026 integration depth — save / load driven end-to-end through the screen
# (batch-03 increment 11; LLR-007.3 / 007.4 integration arm, §5.7 method I)
# ===========================================================================
#
# Increment 9 verdicts TC-026 at the service seam (``CdfxService.save`` /
# ``.load`` called directly). The tests below are increment 11's deeper arm:
# they build the change-list **through the Patch Editor widget controls** and
# drive ``"save"`` / ``"load"`` as ``ActionRequested`` messages so the whole
# screen → ``app.py`` handler → ``CdfxService`` → ``cdfx`` package → table path
# is exercised under ``App.run_test()``.


def _patch_a2l_tags(app: S19TuiApp) -> None:
    """Make ``app`` resolve the Patch Editor change-list against ``_A2L_TAGS``.

    The Patch Editor handler resolves through ``_compute_a2l_enriched_tags``;
    with no real A2L file loaded that returns an empty list and every entry is
    ``unresolved-no-a2l`` (the writer then excludes it). The integration
    save/load arms need *resolved* entries to round-trip, so this stubs the
    app's enriched-tag source with the synthetic ``_A2L_TAGS`` — the
    established way to simulate a loaded A2L without a real artifact (C-9).
    """
    app._compute_a2l_enriched_tags = lambda: _A2L_TAGS  # type: ignore[method-assign]


def test_tc026_integration_screen_save_writes_cdfx_under_workarea(
    tmp_path: Path,
) -> None:
    """Driving the screen's save action writes a .cdfx under the work area.

    Intent: LLR-007.3 integration arm — entries built via the Patch Editor
    add control and saved via the ``"save"`` action produce a real ``.cdfx``
    file whose resolved path lies under ``.s19tool/workarea/``. This is the
    end-to-end arm of TC-026: increment 9 proved the service seam, this proves
    the screen → handler → service → file path.
    """

    async def _drive() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _patch_a2l_tags(app)
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            # Build a one-entry change-list through the widget controls.
            app.query_one("#patch_name_input").value = "IGN_ADVANCE_BASE"
            app.query_one("#patch_index_input").value = ""
            app.query_one("#patch_value_input").value = "23"
            panel.request_action("add")
            await pilot.pause()
            panel.request_action("save")
            await pilot.pause()

    asyncio.run(_drive())

    workarea = (tmp_path / ".s19tool" / "workarea").resolve()
    written = list(workarea.glob("*.cdfx"))
    assert written, "the screen save action must write a .cdfx in the work area"
    assert workarea in written[0].resolve().parents, (
        "a .cdfx saved through the screen must resolve under .s19tool/workarea/"
    )


def test_tc026_integration_screen_save_then_load_round_trips_via_pilot(
    tmp_path: Path,
) -> None:
    """A screen save then a screen load round-trips the change-list rows.

    Intent: LLR-007.3 / LLR-007.4 integration arm — build a change-list
    through the widget, drive ``"save"``, clear the table by removing the
    entry, then drive ``"load"`` on the written path. The table must repopulate
    from the parsed ``.cdfx`` — the full save→load cycle through the screen,
    not through a second ``CdfxService`` instance as in the increment-9 arm.
    """
    from textual.widgets import DataTable

    async def _drive() -> tuple[int, int, str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            _patch_a2l_tags(app)
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            table = app.query_one("#patch_changelist_table", DataTable)
            # Build a one-entry change-list through the controls and save it.
            app.query_one("#patch_name_input").value = "IGN_ADVANCE_BASE"
            app.query_one("#patch_index_input").value = ""
            app.query_one("#patch_value_input").value = "23"
            panel.request_action("add")
            await pilot.pause()
            panel.request_action("save")
            await pilot.pause()
            rows_after_save = table.row_count
            written = next(
                (tmp_path / ".s19tool" / "workarea").resolve().glob("*.cdfx")
            )
            # Clear the in-progress change-list, then load the written file.
            app.query_one("#patch_name_input").value = "IGN_ADVANCE_BASE"
            app.query_one("#patch_index_input").value = ""
            panel.request_action("remove")
            await pilot.pause()
            rows_after_remove = table.row_count
            app.query_one("#patch_path_input").value = str(written)
            panel.request_action("load")
            await pilot.pause()
            loaded = app._cdfx_service.change_list.get(
                "IGN_ADVANCE_BASE", None
            )
            loaded_name = (
                loaded.parameter_name if loaded is not None else "missing"
            )
            return rows_after_save, rows_after_remove, loaded_name

    rows_after_save, rows_after_remove, loaded_name = asyncio.run(_drive())
    assert rows_after_save == 1, "the add control must leave one table row"
    assert rows_after_remove == 0, "the remove control must empty the table"
    assert loaded_name == "IGN_ADVANCE_BASE", (
        "the screen load action must repopulate the change-list from the "
        "saved .cdfx"
    )


def test_tc026_integration_screen_load_expands_val_blk_to_element_rows(
    tmp_path: Path,
) -> None:
    """A screen load of a VAL_BLK .cdfx populates the per-element rows.

    Intent: LLR-007.4 / LLR-005.6 integration arm — a ``.cdfx`` carrying a
    coalesced ``VAL_BLK`` ``SW-INSTANCE`` (a 2-element array) must load back
    through the Patch Editor load action as the per-element rows
    ``(FUEL_TRIM, 0)`` and ``(FUEL_TRIM, 1)`` — the writer's coalesce
    (LLR-004.9) and the reader's expand (LLR-005.6) round-trip through the UI.
    """
    from textual.widgets import DataTable

    # Seed a .cdfx with a scalar + a coalesced 2-element VAL_BLK array.
    seed = CdfxService()
    seed.add_entry("IGN_ADVANCE_BASE", "", "23")
    seed.add_entry("FUEL_TRIM", "0", "11")
    seed.add_entry("FUEL_TRIM", "1", "22")
    seed.save(tmp_path, _A2L_TAGS, file_name="valblk.cdfx")
    written = next(
        (tmp_path / ".s19tool" / "workarea").resolve().glob("*.cdfx")
    )

    async def _drive() -> tuple[int, set]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            app.query_one("#patch_path_input").value = str(written)
            panel.request_action("load")
            await pilot.pause()
            table = app.query_one("#patch_changelist_table", DataTable)
            recovered = {
                (e.parameter_name, e.array_index)
                for e in app._cdfx_service.change_list.entries
            }
            return table.row_count, recovered

    row_count, recovered = asyncio.run(_drive())
    assert row_count == 3, (
        f"a scalar + 2-element VAL_BLK .cdfx must load 3 rows, got {row_count}"
    )
    assert recovered == {
        ("IGN_ADVANCE_BASE", None),
        ("FUEL_TRIM", 0),
        ("FUEL_TRIM", 1),
    }, f"the VAL_BLK array did not expand to per-element rows: {recovered}"


def test_tc026_integration_screen_save_surfaces_issues_on_status_path(
    tmp_path: Path,
) -> None:
    """A screen save of an unresolved entry surfaces W-INSTANCE-EXCLUDED.

    Intent: LLR-007.3 issue-surfacing arm — with no A2L loaded, an added
    entry is unresolved and the writer excludes it with a
    ``W-INSTANCE-EXCLUDED`` warning. Driving ``"save"`` through the screen
    must route that issue to the status path (``set_status`` →
    ``app.log_lines``) via ``_report_cdfx_result``, so the engineer sees it
    — it is visible, never silent.
    """

    async def _drive() -> list[str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            app.query_one("#patch_name_input").value = "UNKNOWN_PARAM"
            app.query_one("#patch_index_input").value = ""
            app.query_one("#patch_value_input").value = "1"
            panel.request_action("add")
            await pilot.pause()
            panel.request_action("save")
            await pilot.pause()
            return list(app.log_lines)

    status_lines = asyncio.run(_drive())
    assert any("W-INSTANCE-EXCLUDED" in line for line in status_lines), (
        "a screen save of an unresolved entry must surface "
        f"W-INSTANCE-EXCLUDED on the status path, log lines were {status_lines}"
    )


# ===========================================================================
# TC-027a integration arm — a malformed .cdfx load driven through the screen
# (batch-03 increment 11; LLR-006.6 / 007.4 integration arm, §5.7 method I)
# ===========================================================================


def test_tc027a_integration_billion_laughs_load_keeps_screen_usable(
    tmp_path: Path,
) -> None:
    """A billion-laughs .cdfx load through the screen does not crash the UI.

    Intent: TC-027a integration arm — driving the Patch Editor ``"load"``
    action with a ``.cdfx`` carrying a billion-laughs DOCTYPE must leave the
    screen usable: the change-list stays empty, the empty-state line shows,
    and a follow-up add control still works. No uncaught exception, no hang.
    """
    from textual.widgets import DataTable

    payload = (
        '<?xml version="1.0"?>\n'
        "<!DOCTYPE MSRSW [\n"
        '  <!ENTITY a "AAAAAAAAAA">\n'
        '  <!ENTITY b "&a;&a;&a;&a;&a;">\n'
        '  <!ENTITY c "&b;&b;&b;&b;&b;">\n'
        "]>\n"
        "<MSRSW>&c;</MSRSW>\n"
    )
    bomb = tmp_path / "bomb.cdfx"
    bomb.write_text(payload, encoding="utf-8")

    async def _drive() -> tuple[int, bool, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            app.query_one("#patch_path_input").value = str(bomb)
            panel.request_action("load")  # must not crash or hang
            await pilot.pause()
            table = app.query_one("#patch_changelist_table", DataTable)
            empty = app.query_one("#patch_empty_state")
            rows_after_bomb = table.row_count
            empty_visible = not empty.has_class("hidden")
            # The screen is still usable — a follow-up add still works.
            app.query_one("#patch_name_input").value = "IGN_ADVANCE_BASE"
            app.query_one("#patch_index_input").value = ""
            app.query_one("#patch_value_input").value = "5"
            panel.request_action("add")
            await pilot.pause()
            return rows_after_bomb, empty_visible, table.row_count

    rows_after_bomb, empty_visible, rows_after_add = asyncio.run(_drive())
    assert rows_after_bomb == 0, (
        "a billion-laughs .cdfx must load no rows into the table"
    )
    assert empty_visible, (
        "the empty-state line must show after a rejected malicious load"
    )
    assert rows_after_add == 1, (
        "the Patch Editor must stay usable after a rejected malicious load"
    )


def test_tc027a_integration_billion_laughs_load_surfaces_parse_issue(
    tmp_path: Path,
) -> None:
    """A billion-laughs load through the screen surfaces R-XML-PARSE.

    Intent: TC-027a integration arm — the malicious-load rejection must be
    *visible*: driving ``"load"`` on a billion-laughs ``.cdfx`` routes one
    ``R-XML-PARSE`` issue to the status path (``app.log_lines``), and no
    expanded entity text leaks into any loaded change-list entry — the
    parser never expanded an entity into parsed data.
    """
    payload = (
        '<?xml version="1.0"?>\n'
        "<!DOCTYPE MSRSW [\n"
        '  <!ENTITY a "LOLLOL">\n'
        '  <!ENTITY b "&a;&a;&a;">\n'
        "]>\n"
        "<MSRSW>&b;</MSRSW>\n"
    )
    bomb = tmp_path / "bomb2.cdfx"
    bomb.write_text(payload, encoding="utf-8")

    async def _drive() -> tuple[list[str], list[object]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            app.query_one("#patch_path_input").value = str(bomb)
            panel.request_action("load")
            await pilot.pause()
            entry_values = [
                e.value for e in app._cdfx_service.change_list.entries
            ]
            return list(app.log_lines), entry_values

    status_lines, entry_values = asyncio.run(_drive())
    assert any("R-XML-PARSE" in line for line in status_lines), (
        "a billion-laughs load must surface R-XML-PARSE on the status path, "
        f"log lines were {status_lines}"
    )
    assert all("LOLLOL" not in str(value) for value in entry_values), (
        "no expanded entity text may leak into a loaded change-list entry"
    )
