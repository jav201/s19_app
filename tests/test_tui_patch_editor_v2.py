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
from s19_app.tui.changes.io import (
    DUMMY_CHANGESET_TEXT,
    emit_intel_hex_from_mem_map,
)
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


def test_action_routing_pins_exactly_eleven_v2_actions() -> None:
    """The routable action set is exactly eleven actions at batch-37.

    Intent: LLR-003.2 + LLR-006.6 (F-A-15) + LLR-014.2 + LLR-064a.1 — the
    E3a eight {add_entry, edit_entry, remove_entry, load_doc, validate_doc,
    apply_doc, save_doc, run_checks} extended by ``execute_scope`` at
    increment E6 (the stated F-A-15 extension clause), by ``parse_paste`` at
    batch-13 (the paste-changeset surface), and by ``refresh_doc`` at
    batch-37 (US-064a re-read of the loaded file's own ``source_path``) — the
    action pin re-asserted as eleven here. Supersedes the batch-13 ten-action
    pin (rewrite-in-place, censused: the additive ``refresh_doc`` is the one
    behavior addition US-064a allows, LLR-064a.2).
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
            "parse_paste",
            "refresh_doc",
        }
    )


# ===========================================================================
# TC-205 — paste TextArea dummy pre-load (LLR-014.1)
# ===========================================================================


def test_paste_textarea_preloads_dummy_changeset(tmp_path: Path) -> None:
    """The paste ``TextArea`` exists on mount, pre-loaded with the dummy.

    Intent: LLR-014.1 (HLR-014) — the Patch Editor presents an editable
    paste field pre-loaded with ``DUMMY_CHANGESET_TEXT`` as a format
    reference, at CRC-surface parity. Compared with ``.rstrip("\\n")``
    tolerance because Textual's ``TextArea`` may normalise a trailing
    newline on init (F-Q-07).
    """
    from textual.widgets import TextArea

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            return app.query_one("#patch_paste_text", TextArea).text

    text = asyncio.run(_drive())
    assert text.rstrip("\n") == DUMMY_CHANGESET_TEXT.rstrip("\n")


# ===========================================================================
# TC-208 — paste parses then drives the EXISTING apply path (LLR-014.2/.3)
# ===========================================================================


def test_paste_parse_then_apply_matches_file_loaded(tmp_path: Path) -> None:
    """A parsed paste replaces the document and drives the existing apply
    path with the SAME save-back prompt name as a file-loaded document.

    Intent: LLR-014.2 — the ``parse_paste`` action routes the paste text
    through ``ChangeService.load_text``, replacing the owned document
    (entries present). LLR-014.3 (F-A-06) — the parsed document then drives
    the EXISTING ``apply_doc`` path, and the post-apply save-back prompt's
    pre-filled name is IDENTICAL to a file-loaded document's, since the
    name is ``<variant_id>-patched.s19`` (driven by the loaded image's stem,
    NOT by ``source_path``). No new write surface — the same apply path.
    """
    from textual.containers import Container
    from textual.widgets import Button, Input, TextArea

    image_path = _make_s19_image(tmp_path)
    # One entry inside the loaded image's [0x100, 0x110) range so apply
    # writes ≥1 entry and the save-back prompt opens (S19).
    entries = [{"type": "bytes", "address": "0x100", "bytes": "AA BB"}]
    paste_text = json.dumps(
        {
            "format": "s19app-changeset",
            "version": "2.0",
            "kind": "change",
            "encoding": "utf-8",
            "value_mode": "text",
            "entries": entries,
        }
    )
    doc_path = _write_v2_document(tmp_path / "patch.json", entries)

    async def _apply_via(source: str) -> dict[str, object]:
        outcomes: dict[str, object] = {}
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            _load_image(app, image_path)
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)

            if source == "paste":
                app.query_one(
                    "#patch_paste_text", TextArea
                ).text = paste_text
                app.query_one(
                    "#patch_paste_parse_button", Button
                ).press()
            else:
                _set_entry_inputs(app, path_text=str(doc_path))
                panel.request_action("load_doc")
            await pilot.pause()

            outcomes["entries"] = len(
                app._change_service.document.entries
            )

            panel.request_action("apply_doc")
            await pilot.pause()

            prompt = app.query_one("#patch_saveback_row", Container)
            name_input = app.query_one("#patch_saveback_name_input", Input)
            outcomes["prompt_shown"] = not prompt.has_class("hidden")
            outcomes["saveback_name"] = name_input.value
        return outcomes

    pasted = asyncio.run(_apply_via("paste"))
    loaded = asyncio.run(_apply_via("file"))

    # parse_paste replaced the document with the parsed entries.
    assert pasted["entries"] == 1
    # The existing apply path opened the S19 save-back prompt.
    assert pasted["prompt_shown"] is True
    assert loaded["prompt_shown"] is True
    # F-A-06: paste-parsed and file-loaded produce the SAME save-back name
    # (source_path does not drive it).
    assert pasted["saveback_name"] == loaded["saveback_name"]
    assert pasted["saveback_name"] == f"{image_path.stem}-patched.s19"


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
            # HLR-031: change-file saves now land in the dedicated patches
            # folder, not the workarea root — assert via recursive glob so the
            # "one file saved" intent survives the placement move.
            outcomes["saved_files"] = len(
                list(workarea.rglob("changes*.json"))
            )

            # run_checks (real E4 engine; kind="change" document -> the
            # batch-33 loud doc-kind run block; the 50-char-capped log line
            # carries the "Checks: not run" prefix — the FULL reason is
            # asserted on #patch_checks_status by AT-051b, not here).
            # Supersedes the pre-batch-33 "0 passed, 0 failed, 2
            # uncheckable" literal (rewrite-in-place, censused).
            panel.request_action("run_checks")
            await pilot.pause()
            outcomes["checks_line"] = any(
                "Checks: not run" in line for line in app.log_lines
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


# ===========================================================================
# AT-015.1 / AT-015.3 — width selector → on-disk record width + S0 policy
# (US-015 / LLR-015.3, C3 black-box pilot). These observe the user-facing
# outcome through the SHIPPED save-back surface: the selector widget is set,
# the confirm button is pressed, then the WRITTEN .s19 file is read off disk
# and verified through the frozen ``S19File`` reader — never a service call.
# ===========================================================================


def _make_wide_s19_image(tmp_path: Path, name: str = "wide.s19") -> Path:
    """Emit a 40-byte contiguous S19 image — wide enough that a 32-byte
    record packs >16 data bytes (and a 16-byte record cannot)."""
    mem_map = {0x80001000 + offset: 0x00 for offset in range(40)}
    text = emit_s19_from_mem_map(mem_map, [(0x80001000, 0x80001000 + 40)])
    path = tmp_path / name
    path.write_text(text, encoding="ascii")
    return path


def _data_record_map(s19: S19File) -> dict[int, int]:
    """Memory map from S1/S2/S3 data records ONLY — the firmware-payload
    oracle that excludes the inert S0 header (§6.5 Amendment B)."""
    mem_map: dict[int, int] = {}
    for record in s19.records:
        if record.type in ("S1", "S2", "S3"):
            for offset, byte in enumerate(record.data):
                mem_map[record.address + offset] = byte
    return mem_map


def _drive_saveback_width(
    tmp_path: Path,
    image_path: Path,
    target_width: int,
    *,
    exercise_toggle: bool = False,
) -> tuple[Path, dict[int, int]]:
    """Drive the real Patch Editor save-back surface to ``target_width`` and
    return ``(written_path, intended_data_map)``.

    Adds one bytes entry inside the loaded image's range, applies it, cycles
    the width selector to ``target_width``, then presses the real confirm
    button. The intended DATA-record map is the post-apply ``mem_map`` the
    written file is checked against.

    When ``exercise_toggle`` is set, the selector is first cycled the whole
    way OFF its current value and back to ``target_width`` before confirming,
    asserting the displayed value actually changed mid-cycle (F1). This makes
    the test exercise the button's press path rather than relying on the
    default-32 value, so a wired-but-dead selector button would fail it.
    """
    from textual.widgets import Button

    async def _drive() -> tuple[Path, dict[int, int]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            _load_image(app, image_path)
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)

            # Patch a run inside the wide range (INSIDE → applied → prompt).
            _set_entry_inputs(
                app, address="0x80001008", bytes_text="DE AD BE EF"
            )
            panel.request_action("add_entry")
            await pilot.pause()
            panel.request_action("apply_doc")
            await pilot.pause()

            # Cycle the SHIPPED width selector to the target (default is 32).
            width_button = app.query_one(
                "#patch_saveback_width_button", Button
            )

            if exercise_toggle:
                # F1 — drive the button OFF its current value and back, so the
                # press path is exercised even when target == the default. A
                # dead button (no state change on press) would fail the
                # mid-cycle assertion below.
                start_width = panel._saveback_width
                width_button.press()
                await pilot.pause()
                assert panel._saveback_width != start_width, (
                    "pressing the width selector must change the displayed "
                    f"value, stayed at {start_width}"
                )

            while panel._saveback_width != target_width:
                width_button.press()
                await pilot.pause()

            app.query_one("#patch_saveback_confirm_button", Button).press()
            await pilot.pause()

            written = app._change_service.last_summary.saved_path
            # The intended firmware map after the apply (the engine mutated
            # loaded.mem_map in place; copy it before the app tears down).
            intended = dict(app.current_file.mem_map)
            return written, intended

    return asyncio.run(_drive())


def test_saveback_width_32_packs_wide_records_and_populates_s0(
    tmp_path: Path,
) -> None:
    """AT-015.1 — selecting 32 bytes/line on the real save-back surface
    writes a .s19 whose S3 data records pack >16 (and ≤32) data bytes, whose
    S0 header is populated, and whose firmware DATA-record map re-parses
    byte-equal to the patched image.

    Intent (C3, two-layer): observe the user-facing US-015 outcome THROUGH the
    shipped Patch Editor save-back widget — cycle the selector OFF 32 and back
    (F1: exercise the button's press path, not the bare default), press the
    real Write-file button, then read the written file off disk and verify it
    with the frozen ``S19File`` reader. A service-level call would not prove
    the operator's selector choice reaches the bytes on disk.
    """
    image_path = _make_wide_s19_image(tmp_path)
    written, intended = _drive_saveback_width(
        tmp_path, image_path, 32, exercise_toggle=True
    )

    assert written is not None, "the 32-byte confirm must write a file"
    assert written.suffix == ".s19"

    reparsed = S19File(str(written))
    assert reparsed.get_errors() == []

    data_records = [r for r in reparsed.records if r.type == "S3"]
    assert data_records, "a >0xFFFFFF image emits S3 data records"
    # (a) at least one record packs >16 and ≤32 data bytes — only 32-byte
    #     mode can do this; 16-byte mode caps every record at 16.
    assert any(16 < len(r.data) <= 32 for r in data_records), (
        f"32-byte mode must pack a wide record, got widths "
        f"{[len(r.data) for r in data_records]}"
    )
    assert all(len(r.data) <= 32 for r in data_records)

    # (b) the S0 header is populated (non-empty data).
    s0 = next(r for r in reparsed.records if r.type == "S0")
    assert len(s0.data) > 0, "32-byte mode must populate the S0 header"

    # (c) the DATA-record map re-parses byte-equal to the patched map.
    assert _data_record_map(reparsed) == intended


def test_saveback_width_16_caps_records_and_empties_s0(tmp_path: Path) -> None:
    """AT-015.3 (reinforcement) — selecting 16 bytes/line on the real
    save-back surface writes a .s19 whose data records each carry ≤16 data
    bytes and whose S0 header is empty (legacy back-compat), still re-parsing
    byte-equal to the patched map.

    Intent: the 16-byte branch of the same shipped selector — confirms the
    operator's choice flips both the record width AND the S0 policy
    (``s0_header=None``) end-to-end, observed off disk.
    """
    image_path = _make_wide_s19_image(tmp_path)
    written, intended = _drive_saveback_width(tmp_path, image_path, 16)

    assert written is not None, "the 16-byte confirm must write a file"
    reparsed = S19File(str(written))
    assert reparsed.get_errors() == []

    data_records = [r for r in reparsed.records if r.type == "S3"]
    assert data_records
    assert all(len(r.data) <= 16 for r in data_records), (
        f"16-byte mode must cap every record at 16, got widths "
        f"{[len(r.data) for r in data_records]}"
    )

    s0 = next(r for r in reparsed.records if r.type == "S0")
    assert len(s0.data) == 0, "16-byte mode must write the legacy empty S0"

    assert _data_record_map(reparsed) == intended


# AT-015.1 PRESERVE-leg (F2) — a content-bearing source S0 must be carried
# through to disk verbatim in 32-byte mode, NOT replaced by the synthesized
# filename header. This is the genuine preserve branch of the save-back S0
# policy (``loaded.source_s0_header or _synth_s0_header_from_filename(...)``),
# observed black-box through the shipped surface rather than at the load seam.

_SOURCE_S0_BYTES = b"SRCHDR_PRESERVE_ME"


def _make_wide_s19_image_with_s0(
    tmp_path: Path, name: str = "wide_s0.s19"
) -> Path:
    """Emit a 40-byte contiguous S19 image carrying a populated source S0
    header (``_SOURCE_S0_BYTES``) — wide enough that a 32-byte record packs
    >16 data bytes, and with a content-bearing S0 the load seam will capture
    into ``LoadedFile.source_s0_header``."""
    mem_map = {0x80001000 + offset: 0x00 for offset in range(40)}
    text = emit_s19_from_mem_map(
        mem_map,
        [(0x80001000, 0x80001000 + 40)],
        bytes_per_line=32,
        s0_header=_SOURCE_S0_BYTES,
    )
    path = tmp_path / name
    path.write_text(text, encoding="ascii")
    return path


def test_saveback_width_32_preserves_source_s0_header(tmp_path: Path) -> None:
    """AT-015.1 (preserve leg, F2) — when the loaded image carries a
    content-bearing S0, saving in 32-byte mode through the shipped selector
    writes that SOURCE S0 verbatim, NOT a header synthesized from the
    destination filename.

    Intent: exercise the genuine preserve branch of the save-back S0 policy
    end-to-end. The synthesize branch is covered by AT-015.1's wide image
    (no source S0). Here the load seam captures ``source_s0_header`` and the
    handler must prefer it over ``_synth_s0_header_from_filename`` — observed
    black-box by reading the written S0 off disk. A regression that always
    synthesized would write the filename bytes and fail this assertion.
    """
    image_path = _make_wide_s19_image_with_s0(tmp_path)

    # Sanity: the load seam actually captured the source S0 (guards against a
    # vacuous pass where source_s0_header is None and the synth path is taken).
    captured = S19File(str(image_path))
    captured_loaded = build_loaded_s19(image_path, captured, None, None)
    assert captured_loaded.source_s0_header == _SOURCE_S0_BYTES

    written, intended = _drive_saveback_width(tmp_path, image_path, 32)

    assert written is not None, "the 32-byte confirm must write a file"
    reparsed = S19File(str(written))
    assert reparsed.get_errors() == []

    s0 = next(r for r in reparsed.records if r.type == "S0")
    # The written S0 is the SOURCE header, byte-for-byte — not the filename.
    assert bytes(s0.data) == _SOURCE_S0_BYTES, (
        f"32-byte save must preserve the source S0, got {bytes(s0.data)!r}"
    )
    # And it is NOT the synthesized-from-filename header (distinct content).
    assert bytes(s0.data) != written.name.encode("ascii", "ignore")

    # The firmware data-record map still round-trips byte-equal.
    assert _data_record_map(reparsed) == intended


# ===========================================================================
# AT-031 — dedicated patches folder (HLR-031 / US-027)
# ===========================================================================


def test_at031a_save_doc_lands_in_patches_folder(tmp_path: Path) -> None:
    """AT-031a (golden gate) — a change-document save lands under patches/.

    Intent: HLR-031 — the Patch Editor's change-document save (``save_doc``,
    NOT the save-back image prompt) must write the ``*.json`` into the
    dedicated ``…/.s19tool/workarea/patches/`` folder, created on demand. This
    drives the save through the shipped ``request_action("save_doc")`` surface
    with an in-memory doc holding one entry and asserts the on-disk file:
    (a) no ``*.json`` exists under patches/ before the save, (b) a ``*.json``
    exists there afterwards, and (c) it parses as an ``s19app-changeset`` v2
    envelope. (The folder itself may pre-exist — ``ensure_workarea`` scaffolds
    it at app startup per LLR-031.1 — so the pre-save witness is the absence of
    a saved file, not the absence of the folder.) Counterfactual: leaving the
    placement at the workarea root drops zero files under patches/ → this goes
    RED.
    """
    patches = tmp_path / ".s19tool" / "workarea" / "patches"

    async def _drive() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)

            _set_entry_inputs(app, address="0x100", bytes_text="AA BB")
            panel.request_action("add_entry")
            await pilot.pause()

            assert not (patches.exists() and list(patches.glob("*.json"))), (
                "no change file may exist under patches/ before the save"
            )

            panel.request_action("save_doc")
            await pilot.pause()

    asyncio.run(_drive())

    assert patches.is_dir(), "save_doc must create the patches folder"
    saved = list(patches.glob("*.json"))
    assert len(saved) == 1, f"expected one saved change file, found {saved}"

    written = json.loads(saved[0].read_bytes())
    assert written["format"] == "s19app-changeset"
    assert written["version"] == "2.0"
    assert isinstance(written["entries"], list) and written["entries"]


def test_at031b_two_saves_are_distinct_no_clobber(tmp_path: Path) -> None:
    """AT-031b (idempotent boundary) — two saves keep both, distinct names.

    Intent: HLR-031 no-clobber — saving the same change document twice must
    produce two on-disk files with DIFFERING names (dedup-suffixed by
    ``copy_into_workarea``), never one clobbered file and never an error. This
    pins the no-clobber contract by exact count + name distinctness rather than
    merely "no exception raised". Counterfactual: dropping the dedup/exist_ok
    guard makes the second save clobber or raise → this goes RED.
    """
    patches = tmp_path / ".s19tool" / "workarea" / "patches"

    async def _drive() -> None:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)

            _set_entry_inputs(app, address="0x100", bytes_text="AA BB")
            panel.request_action("add_entry")
            await pilot.pause()

            panel.request_action("save_doc")
            await pilot.pause()
            panel.request_action("save_doc")
            await pilot.pause()

    asyncio.run(_drive())

    saved = list(patches.glob("*.json"))
    assert len(saved) == 2, f"two saves must keep two files, found {saved}"
    names = {p.name for p in saved}
    assert len(names) == 2, f"the two saved files must differ, got {names}"


# ===========================================================================
# Increment 2 — HLR-030 / US-026 — change-file dropdown
# ===========================================================================


def _select_option_values(select: object) -> list[str]:
    """Return a ``Select``'s real option values, excluding the blank sentinel.

    Textual prepends a ``('', Select.NULL)`` blank entry to the option list
    when ``allow_blank=True``; the dropdown's *change-file* options are the rest
    (each value equals the filename). This reads them through the public
    ``_options`` list, filtering the blank so the assertions see only the
    change files.
    """
    from textual.widgets import Select

    return [
        value
        for _label, value in select._options
        if value is not Select.NULL and value is not Select.BLANK
    ]


def _name_holding_address(patches: Path, address: int) -> str:
    """Return the patches/ change-file whose sole entry declares ``address``.

    The AT selects the SECOND file BY KNOWN FILENAME (not positional ``[1]``,
    since glob order is FS-dependent — F-Q2): we read each on-disk file to
    learn which name carries the distinguishing entry, then drive the dropdown
    with that name.
    """
    for path in sorted(patches.glob("*.json")):
        doc = json.loads(path.read_bytes())
        addresses = {int(entry["address"], 16) for entry in doc["entries"]}
        if addresses == {address}:
            return path.name
    raise AssertionError(f"no patches/ file holds only address {address:#x}")


def test_at030a_dropdown_lists_and_loads_selected_change_file(
    tmp_path: Path,
) -> None:
    """AT-030a (C-12 GATE) — two saved files listed; selecting #2 loads it.

    Intent: HLR-030 end-to-end through the shipped surfaces. Produce TWO
    distinct change files via the REAL change-document save
    (``request_action("save_doc")`` — Inc1's path into ``patches/``, NOT the
    save-back image writer), each with a DISTINCT distinguishing entry (file #1
    holds only 0x100, file #2 holds only 0x200). Re-open the patch editor,
    assert ``#patch_doc_file_select`` lists BOTH names, then select the SECOND
    BY KNOWN FILENAME (read from disk — not positional index) and assert the
    editor's active change document now holds file #2's distinguishing entry
    (0x200), not file #1's (0x100), not a dummy. Sub-assertion (F-Q4/R2): a
    save performed WHILE the patch screen is open appears in the dropdown
    without re-activation.

    Counterfactual (QC-2): if the app never populates the Select from the scan
    (``set_change_files`` call dropped), the second file never lists / never
    loads → this goes RED.
    """
    from textual.widgets import Select

    patches = tmp_path / ".s19tool" / "workarea" / "patches"

    async def _drive() -> tuple[list[str], int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)

            # File #1 — a single entry at 0x100.
            _set_entry_inputs(app, address="0x100", bytes_text="AA BB")
            panel.request_action("add_entry")
            await pilot.pause()
            panel.request_action("save_doc")
            await pilot.pause()

            # R2 (a save while open self-refreshes the dropdown) has its own
            # dedicated test; here we focus on the two-file list + load.

            # File #2 — swap the in-memory doc to a single entry at 0x200 so
            # the two on-disk files carry DISTINCT distinguishing entries.
            _set_entry_inputs(app, address="0x100")
            panel.request_action("remove_entry")
            await pilot.pause()
            _set_entry_inputs(app, address="0x200", bytes_text="CC DD")
            panel.request_action("add_entry")
            await pilot.pause()
            panel.request_action("save_doc")
            await pilot.pause()

            # Re-open the editor and read the fresh option set.
            app.action_show_screen("patch")
            await pilot.pause()
            select = app.query_one("#patch_doc_file_select", Select)
            options = _select_option_values(select)

            # Select file #2 BY KNOWN FILENAME (the name holding only 0x200).
            second_name = _name_holding_address(patches, 0x200)
            select.value = second_name
            await pilot.pause()

            active_addresses = [
                entry.address
                for entry in app._change_service.document.entries
            ]
            return options, active_addresses[0] if active_addresses else -1

    options, loaded_address = asyncio.run(_drive())
    # Sanity: both saves landed as distinct on-disk files.
    saved = sorted(p.name for p in patches.glob("*.json"))
    assert len(saved) == 2, f"expected two saved change files, found {saved}"

    # The dropdown lists BOTH files, sorted deterministically.
    assert set(options) == set(saved), (
        f"dropdown options {options} must list both saved files {saved}"
    )
    assert options == sorted(options), "dropdown options must be sorted"

    # Selecting file #2 by known filename loads ITS distinguishing entry.
    assert loaded_address == 0x200, (
        f"selecting file #2 must load its 0x200 entry, got {loaded_address:#x}"
    )


def test_at030a_r2_save_while_open_appears_without_reactivation(
    tmp_path: Path,
) -> None:
    """AT-030a sub-assertion (F-Q4 / R2) — a save while open self-refreshes.

    Intent: a change-document save performed WHILE the patch editor is already
    open must appear in ``#patch_doc_file_select`` without re-activating the
    screen (the C-12 chain relies on the after-save re-scan, LLR-030.3).
    Counterfactual: drop the ``_prefill_patch_change_files`` call in the
    ``save_doc`` arm ⇒ the option set stays empty until re-activation → RED.
    """
    from textual.widgets import Select

    async def _drive() -> list[str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)

            select = app.query_one("#patch_doc_file_select", Select)
            assert _select_option_values(select) == [], (
                "no options before any save"
            )

            _set_entry_inputs(app, address="0x100", bytes_text="AA BB")
            panel.request_action("add_entry")
            await pilot.pause()
            panel.request_action("save_doc")
            await pilot.pause()

            # NO action_show_screen("patch") here — the dropdown must self-fill.
            return _select_option_values(select)

    options = asyncio.run(_drive())
    assert len(options) == 1, (
        f"a save while open must appear without re-activation, got {options}"
    )


def test_at030b_empty_patches_folder_renders_placeholder_no_crash(
    tmp_path: Path,
) -> None:
    """AT-030b (boundary) — an empty patches folder yields a blank dropdown.

    Intent: HLR-030 empty case — with no change file present, the dropdown
    renders an empty/placeholder state (``Select(allow_blank=True)``, W1), the
    app stays responsive, and nothing raises. Counterfactual: indexing ``[0]``
    on the empty scan would throw on open → RED.
    """
    from textual.widgets import Select

    async def _drive() -> tuple[list[str], object]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            select = app.query_one("#patch_doc_file_select", Select)
            # App still responsive: a follow-up screen switch works.
            app.action_show_screen("workspace")
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            return _select_option_values(select), select.value

    options, value = asyncio.run(_drive())
    assert options == [], f"empty folder must yield no options, got {options}"
    assert value in (Select.BLANK, Select.NULL), (
        "empty dropdown must sit on a blank sentinel, not a concrete file"
    )


def test_at030c_directly_dropped_file_is_listed_and_loadable(
    tmp_path: Path,
) -> None:
    """AT-030c (GUARD, not the gate) — a hand-dropped file lists + loads.

    Intent: pins the SCAN contract independently of the save handler. A valid
    v2 change file dropped DIRECTLY into ``patches/`` (bypassing ``save_doc``)
    must be listed in the dropdown and loadable. This stays green even under a
    reverted save handler, so it is structurally a guard, NOT the C-12 gate.
    """
    from textual.widgets import Select

    patches = tmp_path / ".s19tool" / "workarea" / "patches"
    patches.mkdir(parents=True, exist_ok=True)
    _write_v2_document(
        patches / "dropped.json",
        [{"type": "bytes", "address": "0x300", "bytes": "EE FF"}],
    )

    async def _drive() -> tuple[list[str], int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            select = app.query_one("#patch_doc_file_select", Select)
            options = _select_option_values(select)

            select.value = "dropped.json"
            await pilot.pause()
            active = [
                entry.address
                for entry in app._change_service.document.entries
            ]
            return options, active[0] if active else -1

    options, loaded_address = asyncio.run(_drive())
    assert options == ["dropped.json"], (
        f"a directly-dropped change file must be listed, got {options}"
    )
    assert loaded_address == 0x300, (
        f"selecting the dropped file must load its 0x300 entry, "
        f"got {loaded_address:#x}"
    )


def test_repopulate_blank_reset_posts_no_spurious_load(tmp_path: Path) -> None:
    """Regression — a repopulate's blank reset is NOT a load request.

    Intent: ``Select.set_options`` resets the selection to ``Select.NULL``
    (the ``NoSelection`` sentinel) and emits ``Changed(NULL)``. The panel's
    ``on_select_changed`` must swallow that sentinel. The regressed guard
    compared against ``Select.BLANK`` — which in textual 8.x resolves to the
    inherited ``Widget.BLANK`` bool, never a ``NoSelection`` — so every
    repopulate while a file was selected (patch-screen re-activation, or the
    after-save re-scan) leaked ``ChangeFileSelected("Select.NULL")`` and the
    app issued a spurious ``ChangeService.load`` on ``patches/Select.NULL``
    plus a load-error status.

    Counterfactual (QC-2): restore the ``Select.BLANK`` comparison and the
    re-activation below records a load call ending in ``Select.NULL`` → RED.
    """
    from textual.widgets import Select

    patches = tmp_path / ".s19tool" / "workarea" / "patches"
    patches.mkdir(parents=True, exist_ok=True)
    _write_v2_document(
        patches / "dropped.json",
        [{"type": "bytes", "address": "0x300", "bytes": "EE FF"}],
    )

    async def _drive() -> tuple[list[str], object]:
        app = S19TuiApp(base_dir=tmp_path)

        # Spy on the ONLY load seam the dropdown handler uses — every call
        # (legit pick and any spurious blank-reset leak) lands here.
        load_paths: list[str] = []
        real_load = app._change_service.load

        def _spy_load(path: str, base_dir: Path) -> object:
            load_paths.append(str(path))
            return real_load(path, base_dir)

        app._change_service.load = _spy_load  # type: ignore[method-assign]

        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            select = app.query_one("#patch_doc_file_select", Select)

            # Legit pick — exactly one load expected from this.
            select.value = "dropped.json"
            await pilot.pause()

            # Re-activate the patch screen: _prefill_patch_change_files
            # repopulates the Select, set_options resets the selection to
            # Select.NULL, and Changed(NULL) is emitted.
            app.action_show_screen("patch")
            await pilot.pause()
            return load_paths, select.value

    load_paths, final_value = asyncio.run(_drive())
    spurious = [p for p in load_paths if "Select.NULL" in p]
    assert spurious == [], (
        f"the blank reset must not be forwarded as a load request, "
        f"got spurious load(s) {spurious}"
    )
    assert len(load_paths) == 1 and load_paths[0].endswith("dropped.json"), (
        f"exactly the operator's pick must load, got {load_paths}"
    )
    assert final_value is Select.NULL, (
        "after the repopulate the dropdown must sit on the blank sentinel"
    )


def test_f1_symlink_entry_is_skipped_by_scan(tmp_path: Path) -> None:
    """Security TC (F1) — a symlinked patches/ entry is skipped by the scan.

    Intent: the read-path containment fold (LLR-030.3 / F-S1). The typed-path
    load resolves through ``resolve_input_path`` which has only a size cap (no
    containment/symlink guard); the dropdown closes that asymmetry by SKIPPING
    symlink entries at scan time and re-asserting ``is_relative_to`` before
    load. A symlinked ``patches/`` entry (pointing outside the folder) must not
    appear in the dropdown. Portable fallback: when symlink creation is
    unavailable on the host, assert the ``is_relative_to`` guard rejects a
    crafted ``..``-containing name through the load handler instead.
    """
    from textual.widgets import Select

    patches = tmp_path / ".s19tool" / "workarea" / "patches"
    patches.mkdir(parents=True, exist_ok=True)

    # An out-of-folder v2 file the symlink would point at.
    outside = tmp_path / "outside.json"
    _write_v2_document(
        outside, [{"type": "bytes", "address": "0x400", "bytes": "11"}]
    )

    symlink_made = False
    link = patches / "evil.json"
    try:
        link.symlink_to(outside)
        symlink_made = True
    except (OSError, NotImplementedError):
        symlink_made = False

    async def _drive() -> tuple[list[str], int, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            select = app.query_one("#patch_doc_file_select", Select)
            options = _select_option_values(select)

            # Portable branch: exercise the load-path is_relative_to guard with
            # a crafted escaping name (works with or without symlink support).
            app.on_patch_editor_panel_change_file_selected(
                PatchEditorPanel.ChangeFileSelected("../outside.json")
            )
            await pilot.pause()
            escaped_loaded = [
                entry.address
                for entry in app._change_service.document.entries
            ]
            return options, escaped_loaded[0] if escaped_loaded else -1, True

    options, escaped_address, _ok = asyncio.run(_drive())

    # The escaping ``..`` name must NOT have loaded the outside file's 0x400.
    assert escaped_address != 0x400, (
        "the is_relative_to guard must reject a ..-escaping change-file name"
    )
    if symlink_made:
        assert "evil.json" not in options, (
            "a symlinked patches/ entry must be skipped by the scan"
        )


def test_tc030_scan_returns_sorted_json_set_ignoring_non_change_files(
    tmp_path: Path,
) -> None:
    """TC-030 (white-box) — file discovery + dropdown population.

    Intent: the scan helper returns exactly the ``*.json`` set, sorted, and
    ignores non-change files; population maps one option per file, and an empty
    folder yields a placeholder (no options).
    """
    from textual.widgets import Select

    patches = tmp_path / ".s19tool" / "workarea" / "patches"

    async def _drive() -> tuple[list[str], list[str], list[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()

            # Empty folder → empty scan → placeholder dropdown.
            select = app.query_one("#patch_doc_file_select", Select)
            empty_options = _select_option_values(select)

            # Drop two change files + one non-change file.
            _write_v2_document(
                patches / "beta.json",
                [{"type": "bytes", "address": "0x10", "bytes": "01"}],
            )
            _write_v2_document(
                patches / "alpha.json",
                [{"type": "bytes", "address": "0x20", "bytes": "02"}],
            )
            (patches / "notes.txt").write_text("ignore me", encoding="utf-8")

            scanned = app._scan_patch_change_files()
            app._prefill_patch_change_files()
            await pilot.pause()
            populated = _select_option_values(select)
            return empty_options, scanned, populated

    empty_options, scanned, populated = asyncio.run(_drive())
    assert empty_options == [], "empty folder must yield no options"
    assert scanned == ["alpha.json", "beta.json"], (
        f"scan must return the sorted .json set only, got {scanned}"
    )
    assert populated == ["alpha.json", "beta.json"], (
        f"one option per change file, sorted, got {populated}"
    )


# ===========================================================================
# AT-032 — Checks-button clarity (HLR-032 / US-029)
# ===========================================================================

# The key token span the Checks affordance must state — the WHAT (the loaded
# change document's checks) + the WHICH artifact (the loaded image). Asserted
# as a substring (W3), never the whole punctuated string nor "a Label exists".
_CHECKS_HELP_TOKEN = (
    "runs the loaded change document's checks against the loaded image"
)


def test_at032a_checks_help_states_what_and_which_artifact(
    tmp_path: Path,
) -> None:
    """AT-032a (gate) — the Checks affordance states what it checks + on what.

    Intent: HLR-032 / US-029 — with the Patch Editor open, the operator sees a
    clarity element on the Checks affordance whose rendered text contains the
    key token span naming WHAT is checked (the loaded change document's checks)
    and WHICH artifact it acts on (the loaded image) — not a bare "Run checks".
    Observed through the shipped surface via ``str(widget.render())``, matching
    how the other label-text tests in this file read rendered content (W3:
    assert the substring/token span, not the whole string, not merely
    "a Label exists"). Counterfactual (QC-2): revert to the bare button with no
    description ⇒ the token span is absent → RED.
    """
    from textual.widgets import Label

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            return str(app.query_one("#patch_checks_help", Label).render())

    help_text = asyncio.run(_drive())
    assert _CHECKS_HELP_TOKEN in help_text, (
        f"the Checks help must state what + which artifact, got {help_text!r}"
    )


def test_at032b_clarity_added_action_wiring_unchanged(tmp_path: Path) -> None:
    """AT-032b (regression) — clarity added; the run_checks wiring unchanged.

    Intent: HLR-032 — the clarity fix is label/description ONLY, behavior
    unchanged. Assert two things through the composed tree: (a) the Checks
    affordance is no longer JUST a bare unqualified "Run checks" — the enriched
    ``#patch_checks_help`` element is present with the token span; AND (b) the
    action wiring is intact — ``#patch_checks_run_button`` still exists with its
    ``run_checks`` action, and driving that action still routes (the check-run
    status line appears). This pins "clarity added, behavior unchanged".

    Note: the action wiring lives in a local dict inside the panel's
    ``on_button_pressed`` handler (not a queryable method), so (b) is pinned by
    the observable effect (pressing the button posts the "Checks:" status line)
    per the spec's "drive run_checks and confirm it still routes" option, plus
    the button label staying short. Counterfactual: leaving the bare button with
    no help makes (a) fail; renaming the id makes the button query / the routed
    action fail.
    """
    from textual.widgets import Button, Label

    async def _drive() -> dict[str, object]:
        outcomes: dict[str, object] = {}
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)

            # (a) the enriched clarity element is present, with the token span.
            help_labels = list(app.query("#patch_checks_help").results(Label))
            outcomes["help_present"] = len(help_labels) == 1
            outcomes["help_text"] = str(
                app.query_one("#patch_checks_help", Label).render()
            )

            # (b) the Checks button id is unchanged and still a SHORT label
            # (not made verbose); pressing it routes the run_checks action.
            checks_button = app.query_one("#patch_checks_run_button", Button)
            outcomes["button_present"] = True
            outcomes["button_label"] = str(checks_button.label)

            # Driving the action still routes (behavior unchanged): a
            # kind=change doc with no image posts the "Checks:" status line.
            _set_entry_inputs(app, address="0x100", bytes_text="AA")
            panel.request_action("add_entry")
            await pilot.pause()
            checks_button.press()
            await pilot.pause()
            outcomes["checks_line"] = any(
                line.startswith("Checks:") for line in app.log_lines
            )
        return outcomes

    outcomes = asyncio.run(_drive())
    assert outcomes["button_present"] is True, "the Checks button must still exist"
    assert outcomes["help_present"] is True, (
        "the enriched Checks clarity element must be present (not bare)"
    )
    assert _CHECKS_HELP_TOKEN in outcomes["help_text"], (
        f"the Checks affordance must be qualified, got {outcomes['help_text']!r}"
    )
    # The button stays a SHORT label (clarity went into its own row, not a
    # verbose button that risks the 5-button controls row overflowing at 80).
    assert outcomes["button_label"] == "Run checks", (
        f"the Checks button label must stay short, got "
        f"{outcomes['button_label']!r}"
    )
    assert outcomes["checks_line"] is True, (
        "pressing the Checks button must still route run_checks (behavior "
        "unchanged)"
    )


# ---------------------------------------------------------------------------
# batch-31 (fast-dev-flow P1 quick strike) — Inc-1 geometry, AC-4 (B-05).
# ---------------------------------------------------------------------------


def test_ac4_patch_paste_textarea_min_height(tmp_path: Path) -> None:
    """AC-4 / B-05: the paste-change-set TextArea renders >= 6 lines tall.

    Intent: the operator reported the JSON paste box showed only 1-2 lines
    because `#patch_paste_text` had no CSS height rule and collapsed inside
    its grid cell. The fix pins it to 8 lines; this AT gates the observable
    minimum (>= 6) so a future style tweak cannot silently collapse it again.
    """
    from textual.widgets import TextArea

    async def _drive() -> int:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            return app.query_one("#patch_paste_text", TextArea).outer_size.height

    height = asyncio.run(_drive())
    assert height >= 6, (
        f"#patch_paste_text must render >= 6 lines (fixed height 8); got {height}"
    )


# ---------------------------------------------------------------------------
# batch-33 Inc-3 — Layer-B Pilot ATs through the REAL Run-checks button:
# AT-050a (US-050 through the shipped surface), AT-051a (containment reasons
# in rows), AT-051b (loud doc-kind status + capped log prefix + ok=False),
# AT-051e (hostile kind, three markup surfaces, bisected-token case).
# ---------------------------------------------------------------------------


def test_at050a_pilot_mixed_results_via_real_button(tmp_path: Path) -> None:
    """AT-050a (Layer B, real button): a runnable check doc with a collision
    PAIR yields mixed rows — healthy entries checked, only the pair
    uncheckable with the entry-fault reason visible in its rows (RED-first:
    the pre-change gate rendered all four uncheckable)."""
    from textual.widgets import Label, Static

    check_path = _write_v2_document(
        tmp_path / "coll.json",
        [
            {"type": "bytes", "address": "0x100", "bytes": "00 00"},  # pass
            {"type": "bytes", "address": "0x106", "bytes": "02"},  # fail
            {"type": "bytes", "address": "0x200", "bytes": "DE AD BE EF"},
            {"type": "bytes", "address": "0x202", "bytes": "01 02"},  # collide
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
            rows = list(
                app.query("#patch_checks_results > Static").results(Static)
            )
            outcomes["row_texts"] = [str(row.render()) for row in rows]
            outcomes["status_line"] = str(
                app.query_one("#patch_checks_status", Label).render()
            )
        return outcomes

    outcomes = asyncio.run(_drive())
    texts = outcomes["row_texts"]
    assert len(texts) == 4
    assert "-> pass" in texts[0] and "(" not in texts[0].split("->")[1], (
        "pass rows carry no reason suffix (AT-051d display half)"
    )
    assert "-> fail" in texts[1]
    for tainted_text, addr in ((texts[2], 0x200), (texts[3], 0x202)):
        assert "-> uncheckable" in tainted_text
        assert f"entry at 0x{addr:X} carries" in tainted_text
        assert "CHG-COLLISION" in tainted_text
    assert outcomes["status_line"] == "Checks: 1 passed, 1 failed, 2 uncheckable"


def test_at051a_containment_reasons_visible_in_rows(tmp_path: Path) -> None:
    """AT-051a (Layer B): the PARTIAL and OUTSIDE rows name their specific
    containment reasons through the shipped surface (RED-first: rows ended
    at the bare token pre-change)."""
    from textual.widgets import Static

    check_path = _write_v2_document(
        tmp_path / "contain.json",
        [
            {"type": "bytes", "address": "0x10E", "bytes": "01 02 03 04"},
            {"type": "bytes", "address": "0x500", "bytes": "05 06"},
        ],
        kind="check",
    )
    image_path = _make_s19_image(tmp_path)

    async def _drive() -> list[str]:
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
            return [
                str(row.render())
                for row in app.query(
                    "#patch_checks_results > Static"
                ).results(Static)
            ]

    texts = asyncio.run(_drive())
    assert "range partially outside the loaded image [partial]" in texts[0]
    assert "range outside the loaded image [outside]" in texts[1]


def test_at051b_doc_kind_loud_status_capped_log_and_not_ok(
    tmp_path: Path,
) -> None:
    """AT-051b (Layer B): running checks on a kind='change' document renders
    the FULL loud reason on #patch_checks_status (untruncated), only the
    'Checks: not run' prefix on the 50-char-capped log lines, and the
    service return (the m-3 observation point) reports ok=False."""
    from textual.widgets import Label

    change_path = _write_v2_document(
        tmp_path / "wrongkind.json",
        [
            {"type": "bytes", "address": "0x100", "bytes": "00 00"},
            {"type": "bytes", "address": "0x104", "bytes": "00"},
        ],
        kind="change",
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
            _set_entry_inputs(app, path_text=str(change_path))
            panel.request_action("load_doc")
            await pilot.pause()
            panel.request_action("run_checks")
            await pilot.pause()
            outcomes["status_line"] = str(
                app.query_one("#patch_checks_status", Label).render()
            )
            outcomes["log_lines"] = list(app.log_lines)
            # m-3: ok is observable on the ChangeActionResult return.
            action = app._change_service.run_checks(
                app.current_file.mem_map, app.current_file.ranges
            )
            outcomes["ok"] = action.ok
        return outcomes

    outcomes = asyncio.run(_drive())
    status = outcomes["status_line"]
    assert "Checks: not run" in status
    assert "not a check-set" in status
    assert "needs kind 'check'" in status
    assert "'change'" in status
    assert "(0 passed, 0 failed, 2 uncheckable)" in status
    assert any("Checks: not run" in line for line in outcomes["log_lines"])
    assert all(len(line) <= 50 for line in outcomes["log_lines"])
    assert outcomes["ok"] is False


def test_at051e_hostile_kind_renders_literal_on_all_surfaces(
    tmp_path: Path,
) -> None:
    """AT-051e (C-17, Phase-2 P2): a Rich-markup kind token — sized so the
    50-char log cap BISECTS a markup token — renders literally on all three
    surfaces (rows / status / log labels), no MarkupError, app alive."""
    from textual.widgets import Label, Static

    # 'Checks: not run — this is a change-set (kind ' is ~46 chars; the
    # hostile token lands across the 50-char log boundary (bisected case).
    hostile_kind = "zz[red]boom[/red]"
    payload = {
        "format": "s19app-changeset",
        "version": "2.0",
        "kind": hostile_kind,
        "encoding": "utf-8",
        "value_mode": "text",
        "entries": [{"type": "bytes", "address": "0x100", "bytes": "00"}],
    }
    hostile_path = tmp_path / "hostile.json"
    hostile_path.write_text(json.dumps(payload), encoding="utf-8")
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
            _set_entry_inputs(app, path_text=str(hostile_path))
            panel.request_action("load_doc")
            await pilot.pause()
            panel.request_action("run_checks")
            await pilot.pause()
            outcomes["status_line"] = str(
                app.query_one("#patch_checks_status", Label).render()
            )
            outcomes["log_lines"] = list(app.log_lines)
            outcomes["row_texts"] = [
                str(row.render())
                for row in app.query(
                    "#patch_checks_results > Static"
                ).results(Static)
            ]
            outcomes["log_renders"] = [
                str(app.query_one(f"#log_line_{i}", Label).render())
                for i in range(1, 5)
            ]
        return outcomes

    outcomes = asyncio.run(_drive())
    # Surface 2 (#patch_checks_status): hostile token VERBATIM, untruncated.
    assert "[red]boom[/red]" in outcomes["status_line"]
    # Surface 3 (log labels): capped lines rendered without MarkupError —
    # the render() calls above completing IS the no-crash verdict; the
    # blocked prefix is present.
    assert any("Checks: not run" in text for text in outcomes["log_renders"])
    # Surface 1 (rows): blocked rows carry only the short pointer — the
    # hostile text never reaches them by construction.
    assert all("run blocked [doc-kind]" in text for text in outcomes["row_texts"])
    assert all("[red]" not in text for text in outcomes["row_texts"])


# ---------------------------------------------------------------------------
# batch-33 Inc-4 — help affordance (AT-052a/b) + the hostile-encoding
# sibling through the load path's log funnel (TC-051.4).
# ---------------------------------------------------------------------------


def test_at052a_checks_help_states_semantics(tmp_path: Path) -> None:
    """AT-052a: the checks help names (i) the AT-032a what/which token
    (locked pin, unchanged), (ii) the kind requirement, (iii) the
    per-entry-reasons + healthy-entries-still-checked rule — three DISTINCT
    token spans on the shipped surface."""
    from textual.widgets import Label

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            return str(app.query_one("#patch_checks_help", Label).render())

    text = asyncio.run(_drive())
    assert _CHECKS_HELP_TOKEN in text  # (i) the locked AT-032a span
    assert "Needs kind 'check'" in text  # (ii)
    assert "Uncheckable rows name their reason" in text  # (iii)
    assert "healthy entries are still checked" in text


def test_at052b_checks_help_survives_screen_cycle(tmp_path: Path) -> None:
    """AT-052b (wiring regression): the extended help renders identically
    after cycling away from and back to the Patch Editor screen."""
    from textual.widgets import Label

    async def _drive() -> "tuple[str, str]":
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            first = str(app.query_one("#patch_checks_help", Label).render())
            app.action_show_screen("workspace")
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            second = str(app.query_one("#patch_checks_help", Label).render())
            return first, second

    first, second = asyncio.run(_drive())
    assert first == second
    assert "Needs kind 'check'" in second


def test_tc051_4_hostile_encoding_sibling_through_load_funnel(
    tmp_path: Path,
) -> None:
    """TC-051.4 (Phase-2 F3): a hostile Rich-markup token in the document
    ENCODING flows through the load path's per-issue log lines
    (_report_change_result -> set_status -> #log_line_*) and renders
    LITERALLY — the LLR-051.8 construction-time scrub closes the whole
    five-message class, not just the kind message."""
    from textual.widgets import Label

    hostile_doc = tmp_path / "hostile_enc.json"
    hostile_doc.write_text(
        json.dumps(
            {
                "format": "s19app-changeset",
                "version": "2.0",
                "kind": "check",
                "encoding": "bad[bold]codec[/bold]",
                "value_mode": "text",
                "entries": [],
            }
        ),
        encoding="utf-8",
    )
    image_path = _make_s19_image(tmp_path)

    async def _drive() -> "list[str]":
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            _load_image(app, image_path)
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            _set_entry_inputs(app, path_text=str(hostile_doc))
            panel.request_action("load_doc")
            await pilot.pause()
            # Rendering the four log labels IS the no-MarkupError verdict.
            return [
                str(app.query_one(f"#log_line_{i}", Label).render())
                for i in range(1, 5)
            ]

    renders = asyncio.run(_drive())
    assert any("CHG-ENCODING-UNKNOWN" in text for text in renders), (
        f"the encoding fault must reach the log surface; got {renders}"
    )


# ===========================================================================
# AT-057 — patch-editor control regroup (HLR-057 / US-057, batch-35)
# ===========================================================================

# LLR-057.1 — every pre-batch widget id in the change-file pane
# (screens_directionb.py `#patch_pane_changefile` sub-tree) must survive the
# regroup. This is the LLR's 15-id census, asserted verbatim.
_PRESERVED_REGROUP_IDS = (
    "patch_doc_file_select",
    "patch_doc_path_input",
    "patch_doc_load_button",
    "patch_doc_validate_button",
    "patch_doc_apply_button",
    "patch_doc_save_button",
    "patch_checks_run_button",
    "patch_doc_controls",
    "patch_checks_help",
    "patch_doc_file_row",
    "patch_paste_text",
    "patch_paste_parse_button",
    "patch_paste_controls",
    "patch_paste_row",
    "patch_pane_changefile",
)


def test_at057a_two_labeled_sections_ids_and_parentage(
    tmp_path: Path,
) -> None:
    """AT-057a (gate) — two labeled sections; ids + AT-032a span survive.

    Intent: HLR-057 / LLR-057.1/057.2 — with the Patch Editor open, the
    operator sees a patch-script section label above ``#patch_doc_controls``
    (now holding exactly the Load/Validate/Apply/Save buttons) and a checks
    section label above the new ``#patch_checks_controls`` container holding
    the Run-checks button and its help text. All 15 pre-batch widget ids
    remain queryable and the locked AT-032a token span still renders in
    ``#patch_checks_help`` (the regroup moves the label's container, never
    its text). Counterfactual (QC-2): revert to the batch-22 mixed five-button
    row ⇒ the section labels and ``#patch_checks_controls`` resolve to no
    widget → RED (recorded at increment Inc-5 as the live RED).
    """
    from textual.widgets import Button, Label

    async def _drive() -> dict[str, object]:
        outcomes: dict[str, object] = {}
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            outcomes["script_label"] = str(
                app.query_one("#patch_script_section_label", Label).render()
            )
            outcomes["checks_label"] = str(
                app.query_one("#patch_checks_section_label", Label).render()
            )
            outcomes["present_ids"] = [
                wid
                for wid in _PRESERVED_REGROUP_IDS
                if len(app.query(f"#{wid}")) == 1
            ]
            run_button = app.query_one("#patch_checks_run_button", Button)
            outcomes["run_parent"] = getattr(run_button.parent, "id", None)
            help_label = app.query_one("#patch_checks_help", Label)
            outcomes["help_parent"] = getattr(help_label.parent, "id", None)
            outcomes["help_text"] = str(help_label.render())
            controls = app.query_one("#patch_doc_controls")
            outcomes["controls_button_ids"] = [
                button.id for button in controls.query(Button)
            ]
        return outcomes

    outcomes = asyncio.run(_drive())
    assert outcomes["script_label"] == "Patch script", (
        f"patch-script section label wrong: {outcomes['script_label']!r}"
    )
    assert outcomes["checks_label"] == "Checks", (
        f"checks section label wrong: {outcomes['checks_label']!r}"
    )
    assert outcomes["present_ids"] == list(_PRESERVED_REGROUP_IDS), (
        "missing preserved ids: "
        f"{set(_PRESERVED_REGROUP_IDS) - set(outcomes['present_ids'])}"
    )
    assert outcomes["run_parent"] == "patch_checks_controls", (
        f"Run checks must live under #patch_checks_controls, got "
        f"{outcomes['run_parent']!r}"
    )
    assert outcomes["help_parent"] == "patch_checks_controls", (
        f"the checks help must live under #patch_checks_controls, got "
        f"{outcomes['help_parent']!r}"
    )
    assert _CHECKS_HELP_TOKEN in outcomes["help_text"], (
        "the locked AT-032a token span must survive the regroup, got "
        f"{outcomes['help_text']!r}"
    )
    assert outcomes["controls_button_ids"] == [
        "patch_doc_load_button",
        "patch_doc_refresh_button",
        "patch_doc_validate_button",
        "patch_doc_apply_button",
        "patch_doc_save_button",
    ], (
        # batch-37 (US-064a / LLR-064a.1): Refresh is added to the patch-script
        # controls row after Load (additive; Load/Validate/Apply/Save order and
        # ids preserved, LLR-064a.2). Supersedes the batch-35 four-button pin.
        "#patch_doc_controls must retain Load/Refresh/Validate/Apply/Save, "
        f"got {outcomes['controls_button_ids']}"
    )


def test_at057b_regroup_wiring_and_binding_regression(
    tmp_path: Path,
) -> None:
    """AT-057b (regression) — every button and the `b` binding behave as
    pre-batch after the regroup.

    Intent: HLR-057 / LLR-057.3 — the regroup is compose + CSS only. Press
    each of the five buttons through the shipped widget (``button.press()``,
    the AT-032b idiom) and assert its pre-batch observable per button: Load
    populates the entries table from the typed path, Validate posts the
    ``Validate:`` status line, Apply posts ``Apply:``, Save writes exactly
    one ``changes*.json`` under the work area, and Run checks on a
    kind=change document posts the batch-33 ``Checks: not run`` loud block.
    The app-level ``b`` binding stays bound to ``before_after_report``
    (app.py BINDINGS). Counterfactual: dropping a button id from the
    ``on_button_pressed`` dict or re-keying `b` makes its arm RED.
    """
    from textual.binding import Binding
    from textual.widgets import Button, DataTable

    doc_path = _write_v2_document(
        tmp_path / "changes-at057b.json",
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
            table = app.query_one("#patch_doc_entries_table", DataTable)

            _set_entry_inputs(app, path_text=str(doc_path))
            app.query_one("#patch_doc_load_button", Button).press()
            await pilot.pause()
            outcomes["loaded_rows"] = table.row_count

            app.query_one("#patch_doc_validate_button", Button).press()
            await pilot.pause()
            outcomes["validate_line"] = any(
                line.startswith("Validate:") for line in app.log_lines
            )

            app.query_one("#patch_doc_apply_button", Button).press()
            await pilot.pause()
            outcomes["apply_line"] = any(
                line.startswith("Apply:") for line in app.log_lines
            )

            app.query_one("#patch_doc_save_button", Button).press()
            await pilot.pause()
            workarea = tmp_path / ".s19tool" / "workarea"
            outcomes["saved_files"] = len(
                list(workarea.rglob("changes*.json"))
            )

            app.query_one("#patch_checks_run_button", Button).press()
            await pilot.pause()
            outcomes["checks_line"] = any(
                "Checks: not run" in line for line in app.log_lines
            )
        return outcomes

    outcomes = asyncio.run(_drive())
    assert outcomes["loaded_rows"] == 2, "Load must populate the table"
    assert outcomes["validate_line"] is True, "Validate: line must post"
    assert outcomes["apply_line"] is True, "Apply: line must post"
    assert outcomes["saved_files"] == 1, "Save must write one change file"
    assert outcomes["checks_line"] is True, (
        "Run checks must post the batch-33 loud doc-kind block"
    )
    assert any(
        isinstance(binding, Binding)
        and binding.key == "b"
        and binding.action == "before_after_report"
        for binding in S19TuiApp.BINDINGS
    ), "the `b` binding must stay bound to before_after_report"


# ---------------------------------------------------------------------------
# AT-058b / LLR-058.3 — zero behaviour change: the 15-id census + the
# check-run wiring survive the batch-36 paste-group reparent (US-058).
# ---------------------------------------------------------------------------

# The 15 patch-editor widget ids that the compose+CSS-only reparent must
# preserve (LLR-058.3). #patch_paste_text / #patch_paste_parse_button move to
# a new parent cell but stay globally queryable by the same id.
_PATCH_PRESERVED_IDS = (
    "patch_doc_entries_table",
    "patch_doc_path_input",
    "patch_doc_file_select",
    "patch_doc_load_button",
    "patch_doc_validate_button",
    "patch_doc_apply_button",
    "patch_doc_save_button",
    "patch_checks_run_button",
    "patch_checks_help",
    "patch_paste_text",
    "patch_paste_parse_button",
    "patch_variant_select",
    "patch_execute_run_button",
    "patch_saveback_name_input",
    "patch_saveback_confirm_button",
)


def test_at058b_id_census_and_wiring_survive_reparent(tmp_path: Path) -> None:
    """AT-058b — every patch_* id + the run_checks wiring survive the reparent.

    Intent: LLR-058.3 (US-058) — the batch-36 change is compose-tree + CSS
    only; moving ``#patch_paste_row`` out of ``#patch_pane_changefile`` into its
    own panel cell must not drop any widget id or alter any handler / binding.
    Assert (a) all 15 preserved ids resolve to exactly one widget after the
    reparent (the save-back ids are queried once its hidden row is composed —
    it is composed, just ``.hidden``), (b) the AT-032a locked ``#patch_checks_help``
    token span is unchanged, and (c) the AT-032b run_checks idiom still routes
    (pressing ``#patch_checks_run_button`` posts the "Checks:" status line —
    C-12: the status line is produced by the real handler, not injected).

    Counterfactual: dropping/renaming any id fails (a); a handler regression
    fails (c).
    """
    from textual.widgets import Button, Label

    async def _drive() -> dict[str, object]:
        outcomes: dict[str, object] = {}
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)

            # (a) 15-id census — each id resolves to exactly one widget.
            outcomes["id_counts"] = {
                wid: len(app.query(f"#{wid}")) for wid in _PATCH_PRESERVED_IDS
            }

            # (b) the AT-032a locked help token span survives.
            outcomes["help_text"] = str(
                app.query_one("#patch_checks_help", Label).render()
            )

            # (c) the run_checks wiring still routes (real handler produces the
            # status line — C-12).
            _set_entry_inputs(app, address="0x100", bytes_text="AA")
            panel.request_action("add_entry")
            await pilot.pause()
            app.query_one("#patch_checks_run_button", Button).press()
            await pilot.pause()
            outcomes["checks_line"] = any(
                line.startswith("Checks:") for line in app.log_lines
            )
        return outcomes

    outcomes = asyncio.run(_drive())
    missing = [
        wid for wid, count in outcomes["id_counts"].items() if count != 1
    ]
    assert not missing, f"patch ids missing after the reparent: {missing}"
    assert _CHECKS_HELP_TOKEN in outcomes["help_text"], (
        f"the AT-032a locked Checks-help token span must survive the reparent, "
        f"got {outcomes['help_text']!r}"
    )
    assert outcomes["checks_line"] is True, (
        "pressing Run checks must still route run_checks after the reparent "
        "(wiring unchanged)"
    )


# ===========================================================================
# US-064a (batch-37) — Patch-editor refresh (AT-064a + TC-328, LLR-064a.1/.2)
# ===========================================================================


def _entry_addresses(app: S19TuiApp) -> list[str]:
    """Read the address column of the rendered entries table.

    The address is column index 1 of ``#patch_doc_entries_table`` (kind,
    address, value, status, linkage — see ``refresh_entries``). This reads
    the CONSUMER surface the real handler produced, not the service model.
    """
    from textual.coordinate import Coordinate
    from textual.widgets import DataTable

    table = app.query_one("#patch_doc_entries_table", DataTable)
    return [
        str(table.get_cell_at(Coordinate(row, 1)))
        for row in range(table.row_count)
    ]


def test_at064a_refresh_rereads_edited_file_into_editor(
    tmp_path: Path,
) -> None:
    """Refresh re-reads the loaded change file from disk into the editor.

    Intent (AT-064a, US-064a / LLR-064a.1, C-12 output-then-consume): the
    operator loads a change file, the file is then edited EXTERNALLY (a new
    entry at a NEW address), the operator presses Refresh, and the entries
    table reflects the NEW on-disk content — asserting the SPECIFIC new
    address (content, C-10), not merely that the table re-rendered. The AT
    drives the REAL ``#patch_doc_refresh_button`` press through
    ``on_button_pressed`` and reads the table the real ``ChangeService.load``
    handler produced — never a value the test injected into the table.
    """
    from textual.widgets import Button, Input

    doc_path = _write_v2_document(
        tmp_path / "editable.json",
        [{"type": "bytes", "address": "0x100", "bytes": "AA BB"}],
    )

    async def _drive() -> dict[str, object]:
        outcomes: dict[str, object] = {}
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)

            _set_entry_inputs(app, path_text=str(doc_path))
            panel.request_action("load_doc")
            await pilot.pause()
            outcomes["before"] = _entry_addresses(app)

            # External edit: the SAME file now declares a NEW entry at a NEW
            # address that did not exist in the first on-disk version.
            _write_v2_document(
                doc_path,
                [
                    {"type": "bytes", "address": "0x100", "bytes": "AA BB"},
                    {"type": "string", "address": "0x555", "value": "NEW"},
                ],
            )
            # The path input is irrelevant to refresh (A-03) — blank it to
            # prove refresh does not read the widget value.
            app.query_one("#patch_doc_path_input", Input).value = ""

            app.query_one("#patch_doc_refresh_button", Button).press()
            await pilot.pause()
            outcomes["after"] = _entry_addresses(app)
        return outcomes

    outcomes = asyncio.run(_drive())
    assert "0x555" not in outcomes["before"], (
        "the new entry must not exist before the external edit + refresh"
    )
    assert "0x555" in outcomes["after"], (
        "after Refresh the entries table must show the NEW on-disk entry "
        f"(0x555); got {outcomes['after']!r}"
    )
    assert "0x100" in outcomes["after"], (
        "the pre-existing entry must survive the refresh re-read"
    )


def test_tc328_refresh_uses_source_path_not_widget_and_noops_when_unloaded(
    tmp_path: Path,
) -> None:
    """Refresh re-reads ``document.source_path``, never the widget value.

    Intent (TC-328, LLR-064a.1, A-03): (a) after a load, editing
    ``#patch_doc_path_input`` to point at a DIFFERENT file must NOT redirect
    refresh — refresh re-reads the file the document was loaded from
    (``ChangeService.document.source_path``), so the OTHER file's entry never
    appears; (b) with no document loaded (``source_path is None``), Refresh
    is a safe no-op that surfaces the existing load guard and does not crash.
    """
    from textual.widgets import Button, Input

    loaded_doc = _write_v2_document(
        tmp_path / "loaded.json",
        [{"type": "bytes", "address": "0x100", "bytes": "AA BB"}],
    )
    other_doc = _write_v2_document(
        tmp_path / "other.json",
        [{"type": "string", "address": "0xABC", "value": "OTHER"}],
    )

    async def _drive() -> dict[str, object]:
        outcomes: dict[str, object] = {}
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)

            # (b) No document loaded yet -> source_path is None -> refresh
            # is a no-op guard, not a crash.
            outcomes["source_before"] = (
                app._change_service.document.source_path
            )
            app.query_one("#patch_doc_refresh_button", Button).press()
            await pilot.pause()
            outcomes["guard_line"] = any(
                "enter a change-file path to load" in line
                for line in app.log_lines
            )
            outcomes["rows_after_noop"] = _entry_addresses(app)

            # (a) Load a file, then point the widget at a DIFFERENT file.
            _set_entry_inputs(app, path_text=str(loaded_doc))
            panel.request_action("load_doc")
            await pilot.pause()
            outcomes["source_after_load"] = (
                app._change_service.document.source_path is not None
            )
            app.query_one(
                "#patch_doc_path_input", Input
            ).value = str(other_doc)

            app.query_one("#patch_doc_refresh_button", Button).press()
            await pilot.pause()
            outcomes["addresses"] = _entry_addresses(app)
        return outcomes

    outcomes = asyncio.run(_drive())
    # (b) no-op guard when unloaded.
    assert outcomes["source_before"] is None
    assert outcomes["guard_line"] is True, (
        "Refresh with no document loaded must surface the load guard"
    )
    assert outcomes["rows_after_noop"] == [], (
        "Refresh with no document must not populate the table"
    )
    # (a) refresh re-read the source_path file, NOT the widget's other file.
    assert outcomes["source_after_load"] is True
    assert "0x100" in outcomes["addresses"], (
        "refresh must re-read the loaded document's source_path file"
    )
    assert "0xABC" not in outcomes["addresses"], (
        "refresh must NOT redirect to the widget path-input value (A-03); "
        f"got {outcomes['addresses']!r}"
    )


# ===========================================================================
# US-064b — JSON popup change-set editor + A-01 disable-guard
# (AT-064b, AT-064c, TC-329, TC-331 / LLR-064b.1/.2/.3/.4)
# ===========================================================================


def _changeset_text(entries: list[dict]) -> str:
    """Return a v2 ``s19app-changeset`` JSON document as raw text (paste seed)."""
    return json.dumps(
        {
            "format": "s19app-changeset",
            "version": "2.0",
            "kind": "change",
            "encoding": "utf-8",
            "value_mode": "text",
            "entries": entries,
        }
    )


def _seed_via_paste(app: S19TuiApp, text: str) -> None:
    """Seed the change document via the PASTE path (source_path stays None).

    Sets ``#patch_paste_text`` and presses the real Parse pasted button so
    ``ChangeService.load_text`` replaces the document — exactly the Q-07
    fixture path (paste-authored, so the LLR-064b.4 guard leaves Edit-JSON
    enabled).
    """
    from textual.widgets import Button, TextArea

    app.query_one("#patch_paste_text", TextArea).text = text
    app.query_one("#patch_paste_parse_button", Button).press()


def test_at064b_json_popup_edit_confirm_cancel_and_geometry(
    tmp_path: Path,
) -> None:
    """JSON popup: Confirm applies the edited change-set; Cancel is a no-op.

    Intent (AT-064b, US-064b / LLR-064b.1/.2/.3, C-12 output-then-consume,
    Q-07 paste-seed): for a PASTE-authored document (``source_path is None``)
    the operator opens the JSON popup, edits the JSON to add a NEW entry, and
    Confirms — the change document (the CONSUMER the real ``load_text``
    handler produced, read via the entries table) reflects the edited entry
    (specific NEW address, C-10), never merely the TextArea the test typed.
    A Cancel arm asserts the document is unchanged. A geometry arm measures
    the popup TextArea's visible editable lines at 80x24 AND 120x30
    (LLR-064b.3, C-23 pilot-measured) — the readable surface the height-
    starved in-panel box cannot give at 80x24.
    """
    from textual.widgets import Button, TextArea

    from s19_app.tui.screens import ChangeSetJsonScreen

    seed = _changeset_text(
        [{"type": "bytes", "address": "0x100", "bytes": "AA BB"}]
    )
    edited = _changeset_text(
        [
            {"type": "bytes", "address": "0x100", "bytes": "AA BB"},
            {"type": "string", "address": "0x777", "value": "VIAPOPUP"},
        ]
    )

    async def _confirm() -> dict[str, object]:
        outcomes: dict[str, object] = {}
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            _seed_via_paste(app, seed)
            await pilot.pause()
            outcomes["before"] = _entry_addresses(app)

            app.query_one("#patch_edit_json_button", Button).press()
            await pilot.pause()
            # The popup is a ModalScreen seeded from the paste buffer.
            outcomes["is_popup"] = isinstance(app.screen, ChangeSetJsonScreen)
            outcomes["seed_matches"] = (
                app.screen.query_one("#changeset_json_text", TextArea).text
                == seed
            )
            # Edit the JSON in the popup and Confirm.
            app.screen.query_one(
                "#changeset_json_text", TextArea
            ).text = edited
            app.screen.query_one("#changeset_json_confirm", Button).press()
            await pilot.pause()
            await pilot.pause()
            outcomes["after"] = _entry_addresses(app)
        return outcomes

    async def _cancel() -> dict[str, object]:
        outcomes: dict[str, object] = {}
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            _seed_via_paste(app, seed)
            await pilot.pause()

            app.query_one("#patch_edit_json_button", Button).press()
            await pilot.pause()
            app.screen.query_one(
                "#changeset_json_text", TextArea
            ).text = edited
            app.screen.query_one("#changeset_json_cancel", Button).press()
            await pilot.pause()
            await pilot.pause()
            outcomes["after"] = _entry_addresses(app)
        return outcomes

    async def _geometry(width: int, height: int) -> int:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(width, height)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            _seed_via_paste(app, seed)
            await pilot.pause()
            app.query_one("#patch_edit_json_button", Button).press()
            await pilot.pause()
            from textual.widgets import TextArea as _TA

            return app.screen.query_one("#changeset_json_text", _TA).size.height

    confirm = asyncio.run(_confirm())
    cancel = asyncio.run(_cancel())
    lines_80 = asyncio.run(_geometry(80, 24))
    lines_120 = asyncio.run(_geometry(120, 30))

    assert confirm["is_popup"] is True, "Edit JSON must push the popup modal"
    assert confirm["seed_matches"] is True, (
        "the popup TextArea must be seeded from the #patch_paste_text buffer"
    )
    assert "0x777" not in confirm["before"]
    assert "0x777" in confirm["after"], (
        "after Confirm the change document must reflect the edited JSON "
        f"(new entry 0x777); got {confirm['after']!r}"
    )
    assert "0x100" in confirm["after"], "the original entry must survive"

    # Cancel leaves the document unchanged (no 0x777).
    assert cancel["after"] == ["0x100"], (
        f"Cancel must not mutate the document; got {cancel['after']!r}"
    )

    # C-23 geometry (LLR-064b.3), PILOT-MEASURED N_w (not fr-estimated): the
    # full-screen modal gives a readable multi-line editor at BOTH widths —
    # N_80 = 7 and N_120 = 13 visible editable lines — each far above the ~0-1
    # in-viewport lines the height-starved in-panel box gives at 80x24 (F-01).
    assert lines_80 >= 7, (
        f"popup editor must show >= 7 lines at 80x24 (N_80); measured {lines_80}"
    )
    assert lines_120 >= 13, (
        f"popup editor must show >= 13 lines at 120x30 (N_120); "
        f"measured {lines_120}"
    )


def test_at064c_edit_json_disabled_for_file_backed_document(
    tmp_path: Path,
) -> None:
    """Edit JSON is DISABLED for a file-backed doc → no popup, no clobber.

    Intent (AT-064c, US-064b / LLR-064b.4, A-01 data-loss guard): after a
    FILE load (``source_path is not None``) the Edit-JSON control is disabled
    and the popup cannot open — so the stale ``DUMMY_CHANGESET_TEXT`` buffer
    can never be Confirmed to ``load_text``-REPLACE the loaded document. The
    test also drives the mechanism directly (posting ``EditJsonRequested``) to
    prove the handler's guard refuses to push the modal and mutates nothing.
    For a paste-authored doc (``source_path is None``) the same control is
    ENABLED and the popup opens — the two states asserted in ONE node so the
    guard is a real discriminator (C-10), not a constant.
    """
    from textual.widgets import Button

    from s19_app.tui.screens import ChangeSetJsonScreen

    doc_path = _write_v2_document(
        tmp_path / "loaded.json",
        [{"type": "bytes", "address": "0x100", "bytes": "AA BB"}],
    )
    paste = _changeset_text(
        [{"type": "string", "address": "0x222", "value": "PASTED"}]
    )

    async def _drive() -> dict[str, object]:
        outcomes: dict[str, object] = {}
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)

            # (a) FILE-backed document → source_path not None → disabled.
            _set_entry_inputs(app, path_text=str(doc_path))
            panel.request_action("load_doc")
            await pilot.pause()
            outcomes["file_source"] = (
                app._change_service.document.source_path is not None
            )
            outcomes["disabled_when_file"] = app.query_one(
                "#patch_edit_json_button", Button
            ).disabled
            outcomes["entries_before"] = _entry_addresses(app)

            # Drive the mechanism directly — the guard must refuse to push.
            panel.post_message(
                PatchEditorPanel.EditJsonRequested(paste_text="{}")
            )
            await pilot.pause()
            outcomes["popup_after_guarded_open"] = isinstance(
                app.screen, ChangeSetJsonScreen
            )
            outcomes["entries_after_guarded_open"] = _entry_addresses(app)

            # (b) PASTE-authored document → source_path None → enabled + opens.
            _seed_via_paste(app, paste)
            await pilot.pause()
            outcomes["paste_source_none"] = (
                app._change_service.document.source_path is None
            )
            outcomes["enabled_when_paste"] = not app.query_one(
                "#patch_edit_json_button", Button
            ).disabled
            app.query_one("#patch_edit_json_button", Button).press()
            await pilot.pause()
            outcomes["popup_opens_for_paste"] = isinstance(
                app.screen, ChangeSetJsonScreen
            )
        return outcomes

    outcomes = asyncio.run(_drive())
    # (a) file-backed → disabled, guarded open is a no-op, 0 clobber.
    assert outcomes["file_source"] is True
    assert outcomes["disabled_when_file"] is True, (
        "Edit JSON must be DISABLED when a file-backed document is loaded"
    )
    assert outcomes["popup_after_guarded_open"] is False, (
        "the guard must refuse to push the popup over a file-backed document"
    )
    assert outcomes["entries_after_guarded_open"] == outcomes[
        "entries_before"
    ], "a guarded open must not mutate the loaded document (no clobber)"
    # (b) paste-authored → enabled, popup opens.
    assert outcomes["paste_source_none"] is True
    assert outcomes["enabled_when_paste"] is True, (
        "Edit JSON must be ENABLED for a paste-authored document"
    )
    assert outcomes["popup_opens_for_paste"] is True, (
        "the popup must open for a paste-authored document"
    )


def test_tc329_popup_seed_and_load_text_apply_seam(tmp_path: Path) -> None:
    """Popup seed == buffer; Confirm routes through ``load_text``; Cancel none.

    Intent (TC-329, LLR-064b.1/.2 white-box): the popup ``#changeset_json_text``
    initial text equals the ``#patch_paste_text`` buffer at open; Confirm
    writes the edited text back to the buffer and routes it through the
    EXISTING ``parse_paste`` → ``ChangeService.load_text`` seam (asserted by a
    spy on ``load_text`` counting exactly one call carrying the edited text);
    Cancel calls ``load_text`` zero times and leaves the buffer unchanged.
    """
    from textual.widgets import Button, TextArea

    seed = _changeset_text(
        [{"type": "bytes", "address": "0x100", "bytes": "AA BB"}]
    )
    edited = _changeset_text(
        [{"type": "bytes", "address": "0x100", "bytes": "CC DD"}]
    )

    async def _drive(confirm: bool) -> dict[str, object]:
        outcomes: dict[str, object] = {}
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            _seed_via_paste(app, seed)
            await pilot.pause()

            calls: list[str] = []
            real_load_text = app._change_service.load_text

            def _spy(text: str):
                calls.append(text)
                return real_load_text(text)

            app._change_service.load_text = _spy  # type: ignore[assignment]

            app.query_one("#patch_edit_json_button", Button).press()
            await pilot.pause()
            outcomes["seed"] = app.screen.query_one(
                "#changeset_json_text", TextArea
            ).text
            app.screen.query_one(
                "#changeset_json_text", TextArea
            ).text = edited
            button_id = (
                "#changeset_json_confirm" if confirm else "#changeset_json_cancel"
            )
            app.screen.query_one(button_id, Button).press()
            await pilot.pause()
            await pilot.pause()
            outcomes["calls"] = list(calls)
            outcomes["buffer"] = app.query_one(
                "#patch_paste_text", TextArea
            ).text
        return outcomes

    confirmed = asyncio.run(_drive(confirm=True))
    cancelled = asyncio.run(_drive(confirm=False))

    assert confirmed["seed"] == seed, (
        "the popup must be seeded from the #patch_paste_text buffer"
    )
    assert confirmed["calls"] == [edited], (
        "Confirm must route the edited text through load_text exactly once; "
        f"got {confirmed['calls']!r}"
    )
    assert confirmed["buffer"] == edited, (
        "Confirm must write the edited text back to the paste buffer"
    )
    # Cancel: zero load_text calls, buffer unchanged.
    assert cancelled["calls"] == [], (
        f"Cancel must not call load_text; got {cancelled['calls']!r}"
    )
    assert cancelled["buffer"] == seed, (
        "Cancel must leave the paste buffer unchanged"
    )


def test_tc331_disable_guard_predicate_tracks_source_path(
    tmp_path: Path,
) -> None:
    """The disable-guard predicate tracks ``source_path`` live (TC-331).

    Intent (TC-331, LLR-064b.4): the Edit-JSON control's disabled state tracks
    ``ChangeService.document.source_path`` across the file→paste transition —
    fresh (None) → enabled; after a file load (not None) → disabled; after a
    subsequent paste (None) → enabled again.
    """
    from textual.widgets import Button

    doc_path = _write_v2_document(
        tmp_path / "f.json",
        [{"type": "bytes", "address": "0x100", "bytes": "AA BB"}],
    )
    paste = _changeset_text(
        [{"type": "string", "address": "0x9", "value": "P"}]
    )

    async def _drive() -> dict[str, bool]:
        outcomes: dict[str, bool] = {}
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            button = app.query_one("#patch_edit_json_button", Button)

            outcomes["fresh_enabled"] = not button.disabled

            _set_entry_inputs(app, path_text=str(doc_path))
            panel.request_action("load_doc")
            await pilot.pause()
            outcomes["file_disabled"] = button.disabled

            _seed_via_paste(app, paste)
            await pilot.pause()
            outcomes["paste_enabled"] = not button.disabled
        return outcomes

    outcomes = asyncio.run(_drive())
    assert outcomes["fresh_enabled"] is True, (
        "a fresh (paste-authored/empty) document → Edit JSON enabled"
    )
    assert outcomes["file_disabled"] is True, (
        "a file-backed document (source_path not None) → Edit JSON disabled"
    )
    assert outcomes["paste_enabled"] is True, (
        "a subsequent paste (source_path None) → Edit JSON re-enabled"
    )
