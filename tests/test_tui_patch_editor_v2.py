"""
Consolidated v2 Patch Editor screen tests — s19_app batch-07, increment E3a.

These tests verdict the single-JSON-flow Patch Editor (HLR-003) at the
screen + router + service seam:

- **TC-015** — panel composition (LLR-003.1): the 6 new ``patch_doc_*`` /
  ``patch_checks_run_button`` ids exist; the 7 retired batch-03/04 ids do
  not (13 queries).
- **TC-016** — action routing (LLR-003.2): the router routes exactly nine
  actions since E6 — the E3a eight plus the single ``execute_scope``
  extension (F-A-15) — the eight with observable effects here (the
  ``execute_scope`` behavior rides ``tests/test_variant_execution.py``); a
  retired action is a status error, never a crash.
- **TC-019** — legacy-load UX (LLR-003.5): a ``.cdfx`` XML path and a v1
  unified JSON each load as exactly one ERROR finding with the app
  responsive.
- **TC-051** — save-back prompt (LLR-002.7 UI half): the post-apply prompt
  appears with the editable ``<variant_id>-patched.s19`` suggestion;
  decline persists nothing (``saved_path`` ``None``); adversarial typed
  names are contained or refused (F-S-01).
- **TC-052** — declaration-fault persistence (LLR-002.8, F-Q-11 3 stages):
  faults render persistently, survive unrelated UI actions, and clear on a
  clean re-validate.
- **TC-024** — check-run display (LLR-004.5) fed by the REAL E4 engine on
  the loaded-image 2-1-2 fixture: per-row ``sev-*`` classes + the
  three-aggregate status line (re-pinned from the E3a stub at E4).

Engine unit behavior is covered by ``tests/test_changes_*``; service unit
behavior by ``tests/test_change_service.py``. This file covers the widget →
``app.py`` router → ``ChangeService`` seam.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

import pytest

import s19_app.tui.services.change_service as change_service_module
from s19_app.compare import DiffRun, DiffStats
from s19_app.core import S19File
from s19_app.hexfile import IntelHexFile
from s19_app.tui.app import PATCH_ACTIONS_V2, S19TuiApp
from s19_app.tui.changes import (
    STATUS_MISMATCH,
    STATUS_VERIFIED,
    VerifyResult,
    emit_s19_from_mem_map,
)
from s19_app.tui.changes.io import emit_intel_hex_from_mem_map
from s19_app.tui.screens_directionb import PatchEditorPanel
from s19_app.tui.services.load_service import build_loaded_hex, build_loaded_s19

NEW_WIDGET_IDS = (
    "patch_doc_path_input",
    "patch_doc_load_button",
    "patch_doc_validate_button",
    "patch_doc_apply_button",
    "patch_doc_save_button",
    "patch_checks_run_button",
)

RETIRED_WIDGET_IDS = (
    "patch_name_input",
    "patch_index_input",
    "patch_changelist_table",
    "patch_path_input",
    "patch_save_button",
    "patch_load_button",
    "patch_export_button",
)


def _write_v2_document(
    path: Path, entries: list[dict], kind: str = "change"
) -> Path:
    """Write a v2 ``s19app-changeset`` JSON document fixture."""
    path.write_text(
        json.dumps(
            {
                "format": "s19app-changeset",
                "version": "2.0",
                "kind": kind,
                "encoding": "utf-8",
                "value_mode": "text",
                "entries": entries,
            }
        ),
        encoding="utf-8",
    )
    return path


def _make_s19_image(tmp_path: Path, name: str = "img.s19") -> Path:
    """Emit a 16-byte synthetic S19 image at 0x100 (public data only)."""
    mem_map = {0x100 + offset: 0x00 for offset in range(16)}
    text = emit_s19_from_mem_map(mem_map, [(0x100, 0x110)])
    path = tmp_path / name
    path.write_text(text, encoding="ascii")
    return path


def _load_image(app: S19TuiApp, s19_path: Path) -> None:
    """Install an S19 ``LoadedFile`` snapshot on the app (test shortcut)."""
    s19 = S19File(str(s19_path))
    app.current_file = build_loaded_s19(s19_path, s19, a2l_path=None, a2l_data=None)


def _set_entry_inputs(
    app: S19TuiApp,
    address: str = "",
    value: str = "",
    bytes_text: str = "",
    path_text: Optional[str] = None,
) -> None:
    """Fill the panel's entry / path inputs."""
    from textual.widgets import Input

    app.query_one("#patch_entry_address_input", Input).value = address
    app.query_one("#patch_entry_value_input", Input).value = value
    app.query_one("#patch_entry_bytes_input", Input).value = bytes_text
    if path_text is not None:
        app.query_one("#patch_doc_path_input", Input).value = path_text


# ===========================================================================
# TC-015 — panel composition (LLR-003.1)
# ===========================================================================


def test_panel_composition(tmp_path: Path) -> None:
    """6 new widget ids exist; 7 retired ids resolve to no widget.

    Intent: LLR-003.1 — the Patch Editor presents exactly one v2 change-flow
    section. The 6 new control ids must be queryable; the batch-03 parameter
    section, the ``.cdfx`` file row, and the export control (7 retired ids)
    must not exist — 13 queries total.
    """

    async def _drive() -> tuple[list[str], list[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            present = [
                wid for wid in NEW_WIDGET_IDS if len(app.query(f"#{wid}")) == 1
            ]
            absent = [
                wid
                for wid in RETIRED_WIDGET_IDS
                if len(app.query(f"#{wid}")) == 0
            ]
            return present, absent

    present, absent = asyncio.run(_drive())
    assert present == list(NEW_WIDGET_IDS), (
        f"missing new widget ids: {set(NEW_WIDGET_IDS) - set(present)}"
    )
    assert absent == list(RETIRED_WIDGET_IDS), (
        f"retired widget ids still present: "
        f"{set(RETIRED_WIDGET_IDS) - set(absent)}"
    )


# ===========================================================================
# TC-016 — action routing (LLR-003.2)
# ===========================================================================


def test_action_routing_pins_exactly_nine_v2_actions() -> None:
    """The routable action set is exactly nine actions at E6.

    Intent: LLR-003.2 + LLR-006.6 (F-A-15) — the E3a eight {add_entry,
    edit_entry, remove_entry, load_doc, validate_doc, apply_doc, save_doc,
    run_checks} extended by exactly ONE further action at increment E6,
    ``execute_scope`` (the stated F-A-15 extension clause — the E3a
    eight-action pin re-asserted as nine here).
    """
    assert PATCH_ACTIONS_V2 == frozenset(
        {
            "add_entry",
            "edit_entry",
            "remove_entry",
            "load_doc",
            "validate_doc",
            "apply_doc",
            "save_doc",
            "run_checks",
            "execute_scope",
        }
    )


def test_action_routing_observable_effects(tmp_path: Path) -> None:
    """Each of the eight v2 actions drives an observable effect; a retired
    action is a status error, not a crash.

    Intent: LLR-003.2 — entry actions mutate the table, load populates from
    a file, validate / apply / run_checks surface their status lines, save
    writes a work-area file; routing a retired batch-04 action (``export``)
    produces one status error and the app stays responsive (9 arms).
    """
    from textual.widgets import DataTable, Static

    doc_path = _write_v2_document(
        tmp_path / "two.json",
        [
            {"type": "bytes", "address": "0x100", "bytes": "AA BB"},
            {"type": "string", "address": "0x200", "value": "REV"},
        ],
    )

    async def _drive() -> dict[str, object]:
        outcomes: dict[str, object] = {}
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            table = app.query_one("#patch_doc_entries_table", DataTable)

            # add_entry
            _set_entry_inputs(app, address="0x100", bytes_text="AA")
            panel.request_action("add_entry")
            await pilot.pause()
            outcomes["add_rows"] = table.row_count

            # edit_entry
            _set_entry_inputs(app, address="0x100", bytes_text="CC DD")
            panel.request_action("edit_entry")
            await pilot.pause()
            outcomes["edited_bytes"] = (
                app._change_service.document.entries[0].encoded_bytes
            )

            # remove_entry
            _set_entry_inputs(app, address="0x100")
            panel.request_action("remove_entry")
            await pilot.pause()
            empty = app.query_one("#patch_doc_empty_state", Static)
            outcomes["empty_visible"] = not empty.has_class("hidden")

            # load_doc
            _set_entry_inputs(app, path_text=str(doc_path))
            panel.request_action("load_doc")
            await pilot.pause()
            outcomes["loaded_rows"] = table.row_count

            # validate_doc
            panel.request_action("validate_doc")
            await pilot.pause()
            outcomes["validate_line"] = any(
                line.startswith("Validate:") for line in app.log_lines
            )

            # apply_doc (no image loaded -> skipped-no-image dispositions)
            panel.request_action("apply_doc")
            await pilot.pause()
            summary = app._change_service.last_summary
            outcomes["apply_counts"] = (
                summary.counts["skipped-no-image"] if summary else None
            )
            outcomes["apply_line"] = any(
                line.startswith("Apply:") for line in app.log_lines
            )

            # save_doc
            panel.request_action("save_doc")
            await pilot.pause()
            workarea = tmp_path / ".s19tool" / "workarea"
            outcomes["saved_files"] = len(list(workarea.glob("changes*.json")))

            # run_checks (real E4 engine; kind="change" document with no
            # image -> not runnable, both entries uncheckable)
            panel.request_action("run_checks")
            await pilot.pause()
            outcomes["checks_line"] = any(
                "Checks: 0 passed, 0 failed, 2 uncheckable" in line
                for line in app.log_lines
            )

            # retired action -> status error, not a crash
            panel.post_message(
                PatchEditorPanel.ActionRequested(action="export")
            )
            await pilot.pause()
            outcomes["retired_line"] = any(
                line.startswith("Patch Editor: unsupported action")
                for line in app.log_lines
            )
            _set_entry_inputs(app, address="0x900", bytes_text="01")
            panel.request_action("add_entry")
            await pilot.pause()
            outcomes["alive_after_retired"] = table.row_count
        return outcomes

    outcomes = asyncio.run(_drive())
    assert outcomes["add_rows"] == 1
    assert outcomes["edited_bytes"] == (0xCC, 0xDD)
    assert outcomes["empty_visible"] is True
    assert outcomes["loaded_rows"] == 2
    assert outcomes["validate_line"] is True
    assert outcomes["apply_counts"] == 2
    assert outcomes["apply_line"] is True
    assert outcomes["saved_files"] == 1
    assert outcomes["checks_line"] is True
    assert outcomes["retired_line"] is True
    assert outcomes["alive_after_retired"] == 3


# ===========================================================================
# TC-019 — legacy .cdfx / v1 JSON load (LLR-003.5)
# ===========================================================================


@pytest.mark.parametrize(
    ("file_name", "content", "expected_code"),
    [
        (
            "legacy.cdfx",
            (
                "<?xml version=\"1.0\"?><MSRSW><SW-INSTANCE-TREE>"
                "</SW-INSTANCE-TREE></MSRSW>"
            ),
            "MF-JSON-PARSE",
        ),
        (
            "legacy-v1.json",
            json.dumps(
                {
                    "format": "s19app-unified-changeset",
                    "version": "1.0",
                    "parameters": [],
                    "memory": [],
                }
            ),
            "CHG-V1-FORMAT",
        ),
    ],
)
def test_legacy_load_rejected(
    tmp_path: Path, file_name: str, content: str, expected_code: str
) -> None:
    """A legacy ``.cdfx`` / v1 JSON load is one ERROR finding, app alive.

    Intent: LLR-003.5 — loading a retired format through the v2 Load
    control surfaces exactly one ERROR-severity unsupported-format finding
    (``MF-JSON-PARSE`` for XML, ``CHG-V1-FORMAT`` for v1 JSON) and the app
    stays responsive — the router's except-arm pattern, never a crash.
    """
    from s19_app.validation.model import ValidationSeverity
    from textual.widgets import DataTable

    legacy = tmp_path / file_name
    legacy.write_text(content, encoding="utf-8")

    async def _drive() -> tuple[list[str], int, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            _set_entry_inputs(app, path_text=str(legacy))
            panel.request_action("load_doc")
            await pilot.pause()
            error_codes = [
                issue.code
                for issue in app._change_service.issues
                if issue.severity is ValidationSeverity.ERROR
            ]
            entry_count = len(app._change_service.document.entries)
            # Responsiveness: a follow-up action still works.
            _set_entry_inputs(app, address="0x100", bytes_text="AA")
            panel.request_action("add_entry")
            await pilot.pause()
            table = app.query_one("#patch_doc_entries_table", DataTable)
            return error_codes, entry_count, table.row_count

    error_codes, entry_count, rows_after = asyncio.run(_drive())
    assert error_codes == [expected_code], (
        f"expected exactly one ERROR ({expected_code}), got {error_codes}"
    )
    assert entry_count == 0, "a faulted envelope must carry zero entries"
    assert rows_after == 1, "the app must stay responsive after the rejection"


# ===========================================================================
# TC-051 — save-back prompt (LLR-002.7 UI half, F-S-01 adversarial names)
# ===========================================================================


def test_save_back_prompt(tmp_path: Path) -> None:
    """The post-apply prompt offers an editable suggestion; decline writes
    nothing; adversarial typed names are contained or refused.

    Intent: LLR-002.7 UI half (F-Q-10) — after an apply with ≥1 applied
    entry on an S19 image the prompt appears pre-filled with
    ``<variant_id>-patched.s19``; declining leaves ``saved_path`` ``None``
    and writes no file; the operator-typed name passes the F-S-01
    sanitizer — a traversal name and an absolute path are neutralised into
    the work area, a reserved device name is refused (3 adversarial cases —
    the v2 replacement for the retired batch-04 containment tests).
    """
    from textual.containers import Container
    from textual.widgets import Button, Input

    image_path = _make_s19_image(tmp_path)

    async def _drive() -> dict[str, object]:
        outcomes: dict[str, object] = {}
        workarea = tmp_path / ".s19tool" / "workarea"
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            _load_image(app, image_path)
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)

            _set_entry_inputs(app, address="0x100", bytes_text="AA BB")
            panel.request_action("add_entry")
            await pilot.pause()

            async def _apply() -> None:
                panel.request_action("apply_doc")
                await pilot.pause()

            prompt = app.query_one("#patch_saveback_row", Container)
            name_input = app.query_one("#patch_saveback_name_input", Input)

            # Stage 1 — prompt appears with the pre-filled suggestion.
            await _apply()
            outcomes["prompt_shown"] = not prompt.has_class("hidden")
            outcomes["suggestion"] = name_input.value

            # Stage 2 — decline: nothing written, saved_path stays None.
            app.query_one("#patch_saveback_decline_button", Button).press()
            await pilot.pause()
            outcomes["prompt_hidden_after_decline"] = prompt.has_class(
                "hidden"
            )
            outcomes["declined_saved_path"] = (
                app._change_service.last_summary.saved_path
            )
            outcomes["s19_after_decline"] = sorted(
                p.name for p in workarea.rglob("*.s19")
            )

            # Stage 3 — the suggestion is editable; adversarial names.
            async def _confirm_with(name: str) -> None:
                await _apply()
                name_input.value = name
                app.query_one(
                    "#patch_saveback_confirm_button", Button
                ).press()
                await pilot.pause()

            await _confirm_with("..\\escape.s19")
            outcomes["traversal_saved_path"] = (
                app._change_service.last_summary.saved_path
            )
            outcomes["traversal_escaped"] = (
                (tmp_path / "escape.s19").exists()
                or (tmp_path.parent / "escape.s19").exists()
            )

            await _confirm_with("C:\\evil\\abs.s19")
            outcomes["absolute_saved_path"] = (
                app._change_service.last_summary.saved_path
            )

            await _confirm_with("CON.s19")
            outcomes["reserved_saved_path"] = (
                app._change_service.last_summary.saved_path
            )
            outcomes["reserved_files"] = sorted(
                p.name for p in workarea.rglob("CON*")
            )
        return outcomes

    outcomes = asyncio.run(_drive())
    workarea = tmp_path / ".s19tool" / "workarea"

    assert outcomes["prompt_shown"] is True
    assert outcomes["suggestion"] == "img-patched.s19"
    assert outcomes["prompt_hidden_after_decline"] is True
    assert outcomes["declined_saved_path"] is None
    assert outcomes["s19_after_decline"] == [], (
        "declining the prompt must write no patched image"
    )

    traversal_path = outcomes["traversal_saved_path"]
    assert traversal_path is not None
    assert traversal_path.name.startswith("escape")
    assert workarea in traversal_path.parents, (
        "a traversal filename must stay contained in the work area"
    )
    assert outcomes["traversal_escaped"] is False

    absolute_path = outcomes["absolute_saved_path"]
    assert absolute_path is not None
    assert workarea in absolute_path.parents, (
        "an absolute filename must be reduced to a contained bare name"
    )

    assert outcomes["reserved_saved_path"] is None, (
        "a Windows reserved device name must be refused"
    )
    assert outcomes["reserved_files"] == []


# ===========================================================================
# TC-052 — declaration-fault persistence (LLR-002.8, F-Q-11)
# ===========================================================================


def test_declaration_faults_visible(tmp_path: Path) -> None:
    """Faults render, survive unrelated UI actions, clear on clean
    re-validate (3 stages).

    Intent: LLR-002.8 (F-Q-11) — declaration faults are widget state, not a
    transient status line: (1) a 2-fault document renders 2 fault lines plus
    the count; (2) a focus move and a table scroll leave them rendered;
    (3) re-validating a corrected document clears the listing and the
    count. The faults also ride ``ChangeSummary.to_dict()["issues"]``.
    """
    from textual.widgets import Label, Static

    faulted = _write_v2_document(
        tmp_path / "faulted.json",
        [
            {"type": "bytes", "address": "0x100", "bytes": "AA"},
            {"type": "bytes", "address": "0xZZ", "bytes": "BB"},
            {"type": "bytes", "address": "0x300", "bytes": "GG"},
        ],
    )
    corrected = _write_v2_document(
        tmp_path / "corrected.json",
        [
            {"type": "bytes", "address": "0x100", "bytes": "AA"},
            {"type": "bytes", "address": "0x200", "bytes": "BB"},
        ],
    )

    async def _drive() -> dict[str, object]:
        outcomes: dict[str, object] = {}
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            count_label = app.query_one("#patch_doc_issue_count", Label)
            listing = app.query_one("#patch_doc_issues", Static)

            # Stage 1 — the 2-fault document renders faults + the count.
            _set_entry_inputs(app, path_text=str(faulted))
            panel.request_action("load_doc")
            await pilot.pause()
            outcomes["stage1_count"] = str(count_label.render())
            outcomes["stage1_listing"] = str(listing.render())
            outcomes["stage1_visible"] = not listing.has_class("hidden")

            # The faults ride the apply summary (report carrier).
            panel.request_action("apply_doc")
            await pilot.pause()
            summary = app._change_service.last_summary
            outcomes["summary_issue_codes"] = sorted(
                issue["code"] for issue in summary.to_dict()["issues"]
            )

            # Stage 2 — unrelated UI actions: focus move + table scroll.
            app.query_one("#patch_doc_entries_table").focus()
            await pilot.pause()
            await pilot.press("down")
            await pilot.pause()
            outcomes["stage2_count"] = str(count_label.render())
            outcomes["stage2_visible"] = not listing.has_class("hidden")

            # Stage 3 — a corrected document re-validates clean.
            _set_entry_inputs(app, path_text=str(corrected))
            panel.request_action("load_doc")
            await pilot.pause()
            panel.request_action("validate_doc")
            await pilot.pause()
            outcomes["stage3_count"] = str(count_label.render())
            outcomes["stage3_visible"] = not listing.has_class("hidden")
        return outcomes

    outcomes = asyncio.run(_drive())
    assert outcomes["stage1_count"] == "Declaration faults: 2"
    assert "CHG-ADDRESS-SYNTAX" in outcomes["stage1_listing"]
    assert "CHG-BYTES-SYNTAX" in outcomes["stage1_listing"]
    assert outcomes["stage1_visible"] is True
    assert outcomes["summary_issue_codes"] == [
        "CHG-ADDRESS-SYNTAX",
        "CHG-BYTES-SYNTAX",
    ]
    assert outcomes["stage2_count"] == "Declaration faults: 2", (
        "faults must persist across unrelated UI actions"
    )
    assert outcomes["stage2_visible"] is True
    assert outcomes["stage3_count"] == ""
    assert outcomes["stage3_visible"] is False


# ===========================================================================
# TC-024 — check-run display (LLR-004.5, fed by the REAL E4 engine)
# ===========================================================================


def test_check_run_display(tmp_path: Path) -> None:
    """A real check run renders coloured rows + the 3-count line.

    Intent: LLR-004.5 re-pinned at E4 — a ``kind="check"`` document loaded
    through the panel and executed by the REAL engine
    (``run_check_document``, the service's default ``check_runner``) on the
    loaded-image 2-1-2 fixture of LLR-004.2 renders one row per entry
    coloured through ``css_class_for_severity`` (pass→``sev-ok``,
    fail→``sev-error``, uncheckable→``sev-warning``) and a status line
    stating the three aggregate counts. No stub is injected anywhere.
    """
    from textual.widgets import Label, Static

    # 2-1-2 against the all-zero 16-byte image at 0x100: two matching
    # expectations, one mismatch (expected 02, actual 00), one PARTIAL
    # straddle at the image edge, one fully OUTSIDE entry.
    check_path = _write_v2_document(
        tmp_path / "checks.json",
        [
            {"type": "bytes", "address": "0x100", "bytes": "00 00"},
            {"type": "bytes", "address": "0x104", "bytes": "00"},
            {"type": "bytes", "address": "0x106", "bytes": "02"},
            {"type": "bytes", "address": "0x10E", "bytes": "01 02 03 04"},
            {"type": "bytes", "address": "0x500", "bytes": "05 06"},
        ],
        kind="check",
    )
    image_path = _make_s19_image(tmp_path)

    async def _drive() -> dict[str, object]:
        outcomes: dict[str, object] = {}
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            _load_image(app, image_path)
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            _set_entry_inputs(app, path_text=str(check_path))
            panel.request_action("load_doc")
            await pilot.pause()
            panel.request_action("run_checks")
            await pilot.pause()
            result_rows = list(
                app.query("#patch_checks_results > Static").results(Static)
            )
            outcomes["row_classes"] = [
                ("sev-ok" if row.has_class("sev-ok") else "")
                + ("sev-error" if row.has_class("sev-error") else "")
                + ("sev-warning" if row.has_class("sev-warning") else "")
                for row in result_rows
            ]
            outcomes["row_count"] = len(result_rows)
            status = app.query_one("#patch_checks_status", Label)
            outcomes["status_line"] = str(status.render())
            result = app._change_service.last_check_result
            outcomes["engine_aggregates"] = dict(result.aggregates)
            outcomes["fail_actual"] = result.entries[2].actual_bytes
        return outcomes

    outcomes = asyncio.run(_drive())
    assert outcomes["row_count"] == 5
    assert outcomes["row_classes"] == [
        "sev-ok",
        "sev-ok",
        "sev-error",
        "sev-warning",
        "sev-warning",
    ]
    assert outcomes["status_line"] == "Checks: 2 passed, 1 failed, 2 uncheckable"
    # The result came from the real engine, not a display stub: the actual
    # bytes of the failing entry were read from the loaded image.
    assert outcomes["engine_aggregates"] == {
        "passed": 2,
        "failed": 1,
        "uncheckable": 2,
    }
    assert outcomes["fail_actual"] == (0x00,)


# ===========================================================================
# I4 — verify-on-save surface (HLR-004) + format-aware filename (LLR-002.3)
# ===========================================================================


def _make_hex_image(tmp_path: Path, name: str = "img.hex") -> Path:
    """Emit a 16-byte synthetic Intel HEX image at 0x100 (public data only)."""
    mem_map = {0x100 + offset: 0x00 for offset in range(16)}
    text = emit_intel_hex_from_mem_map(mem_map, [(0x100, 0x110)])
    path = tmp_path / name
    path.write_text(text, encoding="ascii")
    return path


def _load_hex_image(app: S19TuiApp, hex_path: Path) -> None:
    """Install a HEX ``LoadedFile`` snapshot on the app (test shortcut)."""
    hex_file = IntelHexFile(str(hex_path))
    app.current_file = build_loaded_hex(
        hex_path, hex_file, a2l_path=None, a2l_data=None
    )


async def _apply_one_entry(app: S19TuiApp, pilot, panel: PatchEditorPanel) -> None:
    """Add one entry and apply it so the save-back prompt appears."""
    _set_entry_inputs(app, address="0x100", bytes_text="AA BB")
    panel.request_action("add_entry")
    await pilot.pause()
    panel.request_action("apply_doc")
    await pilot.pause()


# TC-007 — format-aware save filename suggestion (LLR-002.3)
def test_save_back_suggestion_is_format_aware(tmp_path: Path) -> None:
    """The post-apply prompt suggests ``.hex`` for a HEX image, ``.s19`` for
    an S19 image.

    Intent: LLR-002.3 — the suggested default filename suffix tracks
    ``LoadedFile.file_type`` (previously hard-coded ``.s19``); a HEX-loaded
    image must offer a ``.hex`` suggestion so the format-faithful save-back
    of US-008 is the default the operator sees.
    """
    from textual.widgets import Input

    hex_path = _make_hex_image(tmp_path)

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            _load_hex_image(app, hex_path)
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            await _apply_one_entry(app, pilot, panel)
            return app.query_one("#patch_saveback_name_input", Input).value

    suggestion = asyncio.run(_drive())
    assert suggestion.endswith(".hex"), suggestion
    assert suggestion == "img-patched.hex", suggestion


# TC-011a — quiet "saved + verified" status on a faithful save (LLR-004.1)
def test_verify_quiet_pass_on_faithful_hex_save(tmp_path: Path) -> None:
    """A faithful HEX save-back surfaces one "saved + verified" status line
    and raises NO error notification.

    Intent: LLR-004.1 (HLR-004 hybrid) — a clean verify is quiet: a single
    concise status line, no modal/notice. The real emitter + real
    verify_written_image round-trip cleanly here, so the status comes from
    a genuine ``verified`` VerifyResult riding ``last_summary``.
    """
    from textual.widgets import Button

    hex_path = _make_hex_image(tmp_path)
    workarea = tmp_path / ".s19tool" / "workarea"

    async def _drive() -> tuple[list[str], int, object]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            _load_hex_image(app, hex_path)
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            await _apply_one_entry(app, pilot, panel)
            app.query_one("#patch_saveback_confirm_button", Button).press()
            await pilot.pause()
            error_notices = [
                n
                for n in app._notifications
                if getattr(n, "severity", None) == "error"
            ]
            return (
                list(app.log_lines),
                len(error_notices),
                app._change_service.last_summary.verify_result,
            )

    log_lines, error_count, verify_result = asyncio.run(_drive())

    assert verify_result is not None
    assert verify_result.status == STATUS_VERIFIED
    assert any("Saved + verified" in line for line in log_lines), log_lines
    assert error_count == 0, "a clean verify must raise no error notice"
    hex_files = sorted(p.name for p in workarea.rglob("*.hex"))
    assert hex_files == ["img-patched.hex"], hex_files


# TC-011b — loud mismatch notice on an injected verify mismatch (LLR-004.2)
def test_verify_loud_mismatch_notice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A verify mismatch surfaces a prominent error notice naming the file
    and the per-kind run/byte summary, while the written file stays on disk.

    Intent: LLR-004.2 (HLR-004 hybrid) — on a mismatch the surface is loud:
    an error-severity notification that names the written file and carries
    a non-zero run/byte count built from ``DiffStats``. The save is NOT
    aborted (collect-don't-abort): the file written by the real save engine
    remains on disk. The mismatch is injected by substituting
    ``verify_written_image`` so the surfacing logic is exercised against a
    known ``mismatch`` VerifyResult (the file itself is faithfully written).
    """
    from textual.widgets import Button

    hex_path = _make_hex_image(tmp_path)
    workarea = tmp_path / ".s19tool" / "workarea"

    def _mismatch_verify(written_path, intended_mem_map, file_type):
        # One changed run of length 1 — the canonical one-byte-mutation fault.
        runs = [DiffRun(start=0x100, end=0x101, kind="changed")]
        stats = DiffStats(
            run_counts={"changed": 1, "only_a": 0, "only_b": 0},
            byte_counts={"changed": 1, "only_a": 0, "only_b": 0},
        )
        return VerifyResult(
            status=STATUS_MISMATCH,
            runs=runs,
            stats=stats,
            written_path=written_path,
        )

    monkeypatch.setattr(
        change_service_module, "verify_written_image", _mismatch_verify
    )

    async def _drive() -> tuple[list[str], list[str], list[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            _load_hex_image(app, hex_path)
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            await _apply_one_entry(app, pilot, panel)
            app.query_one("#patch_saveback_confirm_button", Button).press()
            await pilot.pause()
            error_notices = [
                str(n.message)
                for n in app._notifications
                if getattr(n, "severity", None) == "error"
            ]
            written = sorted(p.name for p in workarea.rglob("*.hex"))
            return list(app.log_lines), error_notices, written

    log_lines, error_notices, written = asyncio.run(_drive())
    assert any("Verify MISMATCH" in line for line in log_lines), log_lines
    assert len(error_notices) == 1, error_notices
    notice = error_notices[0]
    assert "img-patched.hex" in notice, notice
    assert "changed 1 run / 1 byte" in notice, notice
    # collect-don't-abort: the file the real engine wrote is still on disk.
    assert written == ["img-patched.hex"], written
