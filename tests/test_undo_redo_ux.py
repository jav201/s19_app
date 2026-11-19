"""batch-40 S1 + S2 — undo/redo UX polish (AC-1.1/1.2 + AC-2.1/2.2).

Covers two small patch-editor fixes shipped in batch-40 Increment 1:

- **S1 (AC-1.1 / AC-1.2)** — a change-set history move (Undo / Redo) must not
  leave a STALE Checks panel from the pre-move entries. ``ChangeService.undo`` /
  ``redo`` reset ``last_check_result`` and ``S19TuiApp._refresh_patch_history_
  view`` re-renders the (now cleared) Checks panel through the existing
  ``refresh_check_results`` seam.
- **S2 (AC-2.1 / AC-2.2)** — ``ctrl+z`` / ``ctrl+y`` reach the same guarded
  undo/redo path as the on-screen buttons (C-16 real key). D10-23 (R-TUI-057.8)
  dropped the old LLR-068a.4 A-01 file-backed guard: the keys now undo/redo a
  file-backed document too, and remain crash-free no-ops on any other screen
  (R-TUI-057.7) / with an empty history stack (R-TUI-057.6).

Helpers are reused from ``test_tui_patch_editor_v2`` so the surface idioms
(paste-authored seed, entries-table read, Add button) stay identical.

Batch-91 contract adoption (HLR-122):
# TC-632 — this module pins the undo/redo UX (LLR-122.5).
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens_directionb import PatchEditorPanel
from tests.test_tui_patch_editor_v2 import (
    _changeset_text,
    _entry_addresses,
    _load_image,
    _make_s19_image,
    _seed_via_paste,
    _set_entry_inputs,
    _write_v2_document,
)


def _check_paste_text(entries: list[dict]) -> str:
    """Return a paste-authored ``kind="check"`` changeset (source_path None).

    Distinct from ``_changeset_text`` (which hardcodes ``kind="change"``): a
    check document is what populates the Checks panel with per-entry rows when
    run against a loaded image, while ``source_path`` stays ``None`` through the
    paste seam so Undo/Redo remain enabled.
    """
    return json.dumps(
        {
            "format": "s19app-changeset",
            "version": "2.0",
            "kind": "check",
            "encoding": "utf-8",
            "value_mode": "text",
            "entries": entries,
        }
    )


def _check_row_count(app: S19TuiApp) -> int:
    """Count the rendered Checks-panel result rows (``#patch_checks_results``).

    Reads the CONSUMER surface (one ``Static`` per ``check_rows`` entry the
    handler produced) so a "stale vs cleared" assertion is over what the user
    actually sees, not the service model.
    """
    from textual.widgets import Static

    return len(list(app.query("#patch_checks_results > Static").results(Static)))


# ===========================================================================
# S1 — AC-1.1 / AC-1.2: Checks panel refreshes (clears) after undo / redo
# ===========================================================================


def test_ac1_checks_panel_clears_after_undo_and_redo(tmp_path: Path) -> None:
    """A history move clears the stale Checks panel (AC-1.1 undo, AC-1.2 redo).

    Intent (batch-40 S1, C-10 content, C-16 button surface): with a
    paste-authored ``kind="check"`` document run against a loaded image, the
    Checks panel is populated; after a history move it must NOT keep the
    pre-move result. The panel is populated for a 2-entry set, then Undo clears
    it (AC-1.1); it is re-populated for the restored 1-entry set, then Redo
    clears it (AC-1.2). RED counterfactual (pre-fix): ``last_check_result``
    survives the move so the stale rows persist (>0) after Undo and after Redo.
    """
    from textual.widgets import Button

    image_path = _make_s19_image(tmp_path)
    paste = _check_paste_text(
        [{"type": "bytes", "address": "0x100", "bytes": "00 00"}]
    )

    async def _drive() -> dict[str, int]:
        outcomes: dict[str, int] = {}
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            _load_image(app, image_path)
            app.action_show_screen("patch")
            await pilot.pause()
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)

            # Paste-author a 1-entry check doc (source_path None → enabled).
            _seed_via_paste(app, paste)
            await pilot.pause()

            # Add a 2nd checkable entry through the real Add button (history++).
            _set_entry_inputs(app, address="0x104", bytes_text="00")
            app.query_one("#patch_entry_add_button", Button).press()
            await pilot.pause()

            # Run checks on the 2-entry set → panel populated.
            panel.request_action("run_checks")
            await pilot.pause()
            outcomes["after_checks"] = _check_row_count(app)

            # UNDO → restores the 1-entry set; the 2-entry check result is now
            # stale and MUST be cleared (AC-1.1).
            app.query_one("#patch_undo_button", Button).press()
            await pilot.pause()
            outcomes["after_undo"] = _check_row_count(app)

            # Re-run checks on the restored 1-entry set → panel populated again.
            panel.request_action("run_checks")
            await pilot.pause()
            outcomes["after_recheck"] = _check_row_count(app)

            # REDO → restores the 2-entry set; the 1-entry check result is now
            # stale and MUST be cleared (AC-1.2).
            app.query_one("#patch_redo_button", Button).press()
            await pilot.pause()
            outcomes["after_redo"] = _check_row_count(app)
        return outcomes

    outcomes = asyncio.run(_drive())
    assert outcomes["after_checks"] > 0, "the 2-entry check run must render rows"
    assert outcomes["after_undo"] == 0, (
        "Undo must clear the stale Checks panel (AC-1.1); "
        f"got {outcomes['after_undo']} stale rows"
    )
    assert outcomes["after_recheck"] > 0, "the re-run check must render rows"
    assert outcomes["after_redo"] == 0, (
        "Redo must clear the stale Checks panel (AC-1.2); "
        f"got {outcomes['after_redo']} stale rows"
    )


# ===========================================================================
# S2 — AC-2.1: ctrl+z / ctrl+y drive the real undo/redo path (C-16 real key)
# ===========================================================================


def test_ac2_1_ctrl_z_y_undo_redo_via_real_key(tmp_path: Path) -> None:
    """``ctrl+z`` undoes and ``ctrl+y`` redoes a change-set edit (AC-2.1).

    Intent (batch-40 S2, C-16 real key): with a paste-authored change-set
    (``source_path`` None → controls enabled) the operator adds an entry, then a
    REAL ``ctrl+z`` press restores the prior change-set and a REAL ``ctrl+y``
    press re-applies it — the SAME path the Undo/Redo buttons drive, asserted
    over the entries table (C-10). RED counterfactual (pre-binding): ``ctrl+z``
    is unbound so the table is unchanged after the press.
    """
    from textual.widgets import Button

    from tests.b97_probes import settled

    paste = _changeset_text(
        [{"type": "string", "address": "0x200", "value": "REV_A"}]
    )

    async def _drive() -> dict[str, list[str]]:
        outcomes: dict[str, list[str]] = {}
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()
            app.action_show_screen("patch")
            await pilot.pause()

            _seed_via_paste(app, paste)
            await pilot.pause()

            _set_entry_inputs(app, address="0x300", bytes_text="DE AD")
            app.query_one("#patch_entry_add_button", Button).press()
            await settled(
                pilot,
                lambda: _entry_addresses(app) == ["0x200", "0x300"],
                "TC-632: the real Add appended 0x300",
            )
            outcomes["after_add"] = _entry_addresses(app)

            # Drop focus so the app-level binding (not a focused Input) handles
            # the key, then drive the REAL ctrl+z / ctrl+y.
            app.set_focus(None)
            await pilot.press("ctrl+z")
            await settled(
                pilot,
                lambda: _entry_addresses(app) == ["0x200"],
                "TC-632: ctrl+z restored 0x200 only",
            )
            outcomes["after_ctrl_z"] = _entry_addresses(app)

            await pilot.press("ctrl+y")
            await settled(
                pilot,
                lambda: _entry_addresses(app) == ["0x200", "0x300"],
                "TC-632: ctrl+y restored 0x300",
            )
            outcomes["after_ctrl_y"] = _entry_addresses(app)
        return outcomes

    outcomes = asyncio.run(_drive())
    assert outcomes["after_add"] == ["0x200", "0x300"], (
        f"the real Add must append 0x300, got {outcomes['after_add']!r}"
    )
    assert outcomes["after_ctrl_z"] == ["0x200"], (
        "ctrl+z must undo the add (restore 0x200 only), got "
        f"{outcomes['after_ctrl_z']!r}"
    )
    assert outcomes["after_ctrl_y"] == ["0x200", "0x300"], (
        "ctrl+y must redo the add (0x300 back), got "
        f"{outcomes['after_ctrl_y']!r}"
    )


# ===========================================================================
# S2 — AC-2.2: ctrl+z/ctrl+y undo every document; off-screen / empty are no-ops
# ===========================================================================


def test_ac2_2_ctrl_z_respects_a01_guard_and_is_crash_free(
    tmp_path: Path,
) -> None:
    """``ctrl+z`` undoes a file-backed doc; off-screen / empty-stack are no-ops.

    Intent (batch-40 S2, D10-23 R-TUI-057.6/.7/.8, C-10 discriminator): D10-23
    dropped the old LLR-068a.4 A-01 source-path guard, so the key binding now
    mirrors the always-enabled buttons — pressing ``ctrl+z`` against a
    FILE-backed document (``source_path`` not None) MUST undo the load (the
    loaded entry is replaced by the pre-load empty document); pressing it on a
    NON-patch screen (R-TUI-057.7) and with an EMPTY history stack
    (R-TUI-057.6) are crash-free no-ops. RED counterfactual (old guard kept):
    ``ctrl+z`` would be inert for the file-backed document and the loaded
    entry would survive.
    """
    doc_path = _write_v2_document(
        tmp_path / "loaded.json",
        [{"type": "bytes", "address": "0x100", "bytes": "AA BB"}],
    )

    async def _drive() -> dict[str, object]:
        outcomes: dict[str, object] = {}
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause()

            # (a) NON-patch screen + empty history → crash-free no-op (R-TUI-057.7).
            app.action_show_screen("workspace")
            app.set_focus(None)
            await pilot.press("ctrl+z")
            await pilot.pause()

            # (b) Patch screen, fresh (empty-stack) document → crash-free no-op
            # (R-TUI-057.6).
            app.action_show_screen("patch")
            app.set_focus(None)
            await pilot.press("ctrl+z")
            await pilot.pause()
            outcomes["fresh_entries"] = _entry_addresses(app)

            # (c) FILE-backed document (source_path not None) → ctrl+z UNDOES
            # the load (R-TUI-057.8): the pre-load empty document is restored.
            panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
            _set_entry_inputs(app, path_text=str(doc_path))
            panel.request_action("load_doc")
            await pilot.pause()
            outcomes["file_source_set"] = (
                app._change_service.document.source_path is not None
            )
            outcomes["file_entries_before"] = _entry_addresses(app)

            app.set_focus(None)
            await pilot.press("ctrl+z")
            await pilot.pause()
            outcomes["file_entries_after"] = _entry_addresses(app)
        return outcomes

    outcomes = asyncio.run(_drive())
    assert outcomes["fresh_entries"] == [], (
        "ctrl+z on a fresh empty-stack patch doc must be a crash-free no-op "
        "(R-TUI-057.6)"
    )
    assert outcomes["file_source_set"] is True, "the doc must be file-backed"
    assert outcomes["file_entries_before"] == ["0x100"], (
        "the file load must populate the entry (precondition)"
    )
    assert outcomes["file_entries_after"] == [], (
        "ctrl+z must UNDO a file-backed document's load (R-TUI-057.8); "
        f"got {outcomes['file_entries_after']!r}"
    )
