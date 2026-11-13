"""s19_app.tui.app.patch — S19TuiApp mixin: patch (moved verbatim from s19_app/tui/app.py at 4f721985)."""
from __future__ import annotations

from pathlib import Path
from typing import List, Mapping, Optional
from textual import work
from textual.widgets import DataTable, Select, Static, TextArea
from ...compare import DIFF_KIND_DOMAIN
from ..changes import STATUS_VERIFIED, VerifyResult
from ..changes.io import (
    SYMBOL_NO_A2L_CONTEXT_TEXT,
    parse_change_document,
    serialize_change_document,
)
from ..models import LoadedFile, ProjectVariantSet
from ..screens import ChangeSetJsonScreen, EntryJsonScreen
from ..screens_directionb import (
    CheckEditorPanel,
    LoadGuardScreen,
    PatchDocumentView,
    PatchEditorPanel,
)
from ..crc_designer_view import CrcDesignerPanel
from ...validation import ValidationIssue
from ..services.a2l_service import enrich_tags_and_render
from ..services.change_service import ChangeActionResult, save_back_status_suffix
from ..services.report_service import REPORT_SOURCE_DEFAULT, REPORT_SOURCE_MANIFEST
from ..segment_split_view import SplitJoinWindow
from ..services.variant_execution_service import (
    EXECUTION_SCOPES,
    SCOPE_ACTIVE,
    VariantExecutionResult,
    execute_project_variants,
)
from . import deps
from .shared import (_SAVEBACK_S0_MAX_BYTES)


#: The Patch Editor's routable action set (LLR-003.2) — the eight v2
#: actions of increment E3a extended by ``execute_scope`` at E6 (the stated
#: F-A-15 extension, LLR-006.6) and by ``parse_paste`` at batch-13
#: (LLR-014.2 — the paste-changeset surface; ten total).
#: A non-member action is reported as a status error, never a crash.
PATCH_ACTIONS_V2: frozenset[str] = frozenset(
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


def _synth_s0_header_from_filename(filename: str) -> bytes:
    """
    Summary:
        Synthesize a minimal populated S0 header from a save-back destination
        filename (US-015 / LLR-015.2) — used in 32-byte mode when the loaded
        image carried no source S0 to preserve. The result is plain ASCII,
        bounded to ``_SAVEBACK_S0_MAX_BYTES`` so the emitter's one-byte
        ``byte_count`` field cannot overflow.

    Args:
        filename (str): The (possibly edited) operator-confirmed target name.

    Returns:
        bytes: The ASCII bytes of ``filename`` with any non-ASCII character
        dropped, truncated to ``_SAVEBACK_S0_MAX_BYTES``. May be empty when
        ``filename`` holds no ASCII characters — an empty header is a valid,
        inert S0 the emitter accepts.

    Data Flow:
        - Encode the name as ASCII dropping un-encodable characters, then
          truncate to the 252-byte cap; the emitter writes it verbatim as the
          S0 data field, inert to the memory map.

    Dependencies:
        Used by:
            - S19TuiApp.on_patch_editor_panel_save_back_decision
    """
    ascii_bytes = filename.encode("ascii", errors="ignore")
    return ascii_bytes[:_SAVEBACK_S0_MAX_BYTES]


class PatchMixin:

    def on_patch_editor_panel_action_requested(
        self, event: PatchEditorPanel.ActionRequested
    ) -> None:
        """
        Summary:
            Route a Patch Editor control action to the change service and
            feed the shaped rows back to the screen — exactly the eleven
            ``PATCH_ACTIONS_V2`` actions (the LLR-003.2 eight plus the E6
            ``execute_scope`` extension, LLR-006.6, the batch-13
            ``parse_paste`` paste-changeset action, LLR-014.2, and the
            batch-37 ``refresh_doc`` re-read action, LLR-064a.1); a retired or
            unknown action is one status error, never a crash.

        Args:
            event (PatchEditorPanel.ActionRequested): The message a Patch
                Editor control posted — its ``action`` plus the current
                address / value / bytes / path input-field text.

        Returns:
            None

        Data Flow:
            - ``add_entry`` / ``edit_entry`` / ``remove_entry`` mutate the
              service's v2 document (both entry kinds).
            - ``load_doc`` / ``validate_doc`` / ``save_doc`` round-trip and
              re-validate the document; ``parse_paste`` replaces the owned
              document from the paste ``TextArea`` body via
              ``ChangeService.load_text`` (LLR-014.2), then the same apply
              path takes over; ``apply_doc`` runs the E2 engine
              and, with ≥1 applied entry, opens the save-back prompt (S19)
              or states HEX save-back is unsupported (LLR-002.7).
            - ``run_checks`` rides the E4 service seam and renders the
              LLR-004.5 display.
            - ``execute_scope`` hands the selector's scope to
              ``_trigger_execute_scope``, which guards on the UI thread and
              starts the E6 execution worker (LLR-006.6).
            - Every action's outcome and findings surface through
              ``_report_change_result`` / ``set_status``; an input error is
              caught and reported, never raised into the UI.
            - The entries table and the persistent declaration-fault area
              are re-rendered after every action (LLR-002.8).

        Dependencies:
            Uses:
                - ``ChangeService``
                - ``_compute_a2l_enriched_tags``
                - ``PatchEditorPanel.refresh_entries`` / ``refresh_issues``
                  / ``refresh_check_results`` / ``show_save_prompt``
            Used by:
                - Textual message dispatch for ``PatchEditorPanel``
        """
        if self._refuse_if_busy():
            return
        service = self._change_service
        loaded = self.current_file
        mem_map = loaded.mem_map if loaded is not None else None
        loaded_ranges = loaded.ranges if loaded is not None else None
        mac_records = loaded.mac_records if loaded is not None else None
        a2l_tags = self._compute_a2l_enriched_tags() or None
        panel = self.query_one("#patch_editor_panel", PatchEditorPanel)
        try:
            if event.action not in PATCH_ACTIONS_V2:
                self.set_status(
                    f"Patch Editor: unsupported action {event.action!r}"
                )
            elif event.action == "add_entry":
                service.add_entry(
                    event.address_text, event.value_text, event.bytes_text
                )
                self.set_status("Patch Editor: entry added.")
                self._refresh_patch_checks_tab(panel)
            elif event.action == "edit_entry":
                service.edit_entry(
                    event.address_text, event.value_text, event.bytes_text
                )
                self.set_status("Patch Editor: entry updated.")
                self._refresh_patch_checks_tab(panel)
            elif event.action == "remove_entry":
                service.remove_entry(event.address_text)
                self.set_status("Patch Editor: entry removed.")
                self._refresh_patch_checks_tab(panel)
            elif event.action == "load_doc":
                # US-061 / LLR-061.1 clear-on-context: a new load resets
                # ChangeService.last_summary to None, so the persistent
                # before/after control's report input is gone — re-hide it.
                panel.hide_before_after_prompt()
                if not event.path_text.strip():
                    self.set_status(
                        "Patch Editor: enter a change-file path to load."
                    )
                else:
                    self._patch_editor_load(panel, event.path_text)
            elif event.action == "parse_paste":
                # LLR-061.1 clear-on-context; Inc 6 hides the save-back
                # prompt too — a parsed paste replaces the document, so the
                # old apply's prompt and control must not survive it.
                self._hide_replaced_document_controls(panel)
                result = service.load_text(event.paste_text, a2l_context=self.current_a2l_data)
                self._report_change_result(result)
                # batch-97 Inc-4 gate (ux H1, LLR-144.6 amended): a parsed
                # paste is a draft no file holds — unsaved work, so the stamp
                # reads `unsaved changes` beside the ribbon's `draft` and a
                # Load asks first (was w4 `mark_loaded`, batch-94 LLR-005.1).
                if result.ok:
                    panel.mark_pasted()
                    self._parsed_paste_text = event.paste_text
                self._refresh_patch_checks_tab(panel)
            elif event.action == "refresh_doc":
                # batch-94 (annotation 6 / HLR-008 / LLR-008.2): Refresh
                # repopulates the file dropdown from the patches-folder
                # scan — "Refresh Files in Folder". The loaded document is
                # NOT re-read, remounted or reloaded: a refresh that mutates
                # the bound document is the negative control. (This
                # supersedes batch-37 US-064a's re-read semantics per the
                # operator's annotation 6 — recorded in the increment
                # packet's amendment note.)
                self._prefill_patch_change_files()
                self.set_status("Patch Editor: file list refreshed.")
            elif event.action == "validate_doc":
                self._report_change_result(service.validate(loaded_ranges))
            elif event.action == "apply_doc":
                variant_id = loaded.path.stem if loaded is not None else None
                summary = service.apply(
                    mem_map,
                    loaded_ranges,
                    mac_records,
                    a2l_tags,
                    variant_id=variant_id,
                )
                counts = summary.counts
                skipped = (
                    counts["skipped-partial"]
                    + counts["skipped-outside"]
                    + counts["skipped-no-image"]
                )
                self.set_status(
                    f"Apply: {counts['applied']} applied, "
                    f"{skipped} skipped, {counts['blocked']} blocked"
                )
                if counts["applied"] > 0 and loaded is not None:
                    if loaded.file_type in ("s19", "hex"):
                        suffix = ".hex" if loaded.file_type == "hex" else ".s19"
                        panel.show_save_prompt(f"{variant_id}-patched{suffix}")
                    else:
                        self.set_status(
                            f"{loaded.file_type} save-back not supported"
                        )
            elif event.action == "save_doc":
                # Change 1 (HLR-138): a NEW change-set defaults INTO the
                # project (``patches/``, or ``checks/`` for a check
                # document) when a project is active; without one the
                # COMMON patches library keeps the write.
                result = service.save(
                    self.base_dir, dest_dir=self._change_doc_save_home()
                )
                self._report_change_result(result)
                # w3 (LLR-005.1): a clean save clears the dirty flag — it
                # must not survive its own save.
                if result.ok:
                    panel.mark_saved()
                # R2 / LLR-030.3: a save while the patch screen is open must
                # appear in the dropdown without re-activation.
                self._prefill_patch_change_files()
            elif event.action == "run_checks":
                result = service.run_checks(
                    mem_map, loaded_ranges, mac_records, a2l_tags
                )
                self._report_change_result(result)
                panel.refresh_check_results(
                    service.check_rows(),
                    result.message,
                    service.check_aggregates(),
                )
                # batch-49 LLR-084.7 (site 1 of 2): the dedicated CHECKS screen
                # is a read-only mirror of the same ``last_check_result``, so it
                # rides this post-run refresh — the CHECKS screen and the Patch
                # panel read one state.
                self.update_checks_view()
            elif event.action == "execute_scope":
                self._trigger_execute_scope(event.scope_text or SCOPE_ACTIVE)
        except (ValueError, KeyError) as exc:
            self.set_status(f"Patch Editor: {exc}")

        # Inc 5 D-4: an apply wrote the loaded image's bytes in place (also
        # when it raises after the journal restore, and when 0 applied
        # restored an earlier apply), so tell the CRC Designer on both
        # outcomes — never gated on ``applied > 0`` (R-CRC-PREVIEW-002.5/8).
        if event.action == "apply_doc":
            self._note_image_bytes_written()

        # batch-48 (LLR-080.2) — site 1 of 5: push the image's memory map so
        # the before/after card can read its "before" bytes. `mem_map` is
        # already resolved above (`loaded.mem_map if loaded is not None else
        # None`), and an explicit `None` is MEANINGFUL ("no image loaded"),
        # which the panel's sentinel default keeps distinct from "not supplied".
        panel.refresh_entries(
            service.rows(loaded_ranges),
            # batch-99 HLR-157 (LLR-157.4): the strip reads the journal
            # overlay — source bytes at every address an apply wrote.
            mem_map=self._strip_source_map(loaded),
            document=self._patch_document_view(),
        )
        # batch-97 Inc-8 (PC-23): the key bar dims Undo / Redo by the
        # document's source, which this refresh may have changed.
        self.refresh_bindings()
        panel.refresh_issues(service.issue_lines())
        # US-064b / LLR-064b.4 A-01 guard: the JSON popup opens ONLY for a
        # paste-authored / empty document — disable Edit-JSON whenever the
        # document is file-backed (``source_path is not None``) so a stale
        # buffer can never Confirm-clobber a loaded document.
        panel.set_edit_json_enabled(service.document.source_path is None)
        # US-068a / LLR-068a.4 A-01 guard: undo/redo is available ONLY for a
        # paste-authored / empty document — disable both controls whenever the
        # document is file-backed so the history path cannot clobber it.
        # batch-48 LLR-081.3: the same call renders the history strip, so the
        # strip and the buttons read ONE state (writer census, site 1 of 3).
        panel.set_undo_redo_enabled(
            service.document.source_path is None, service.history_depths()
        )
        # US-068b / LLR-068b.4 A-01 guard: the per-entry JSON edit is available
        # ONLY for a paste-authored / empty document — disable it whenever the
        # document is file-backed so a per-entry edit cannot clobber it.
        panel.set_entry_edit_json_enabled(service.document.source_path is None)

    def on_patch_editor_panel_save_back_decision(
        self, event: PatchEditorPanel.SaveBackDecision
    ) -> None:
        """
        Summary:
            Handle the operator's answer to the post-apply save-back prompt
            (LLR-002.7 UI half): persist the patched image under the typed
            filename, or persist nothing on decline (``saved_path`` stays
            ``None``).

        Args:
            event (PatchEditorPanel.SaveBackDecision): The prompt outcome —
                the (possibly edited) filename, or ``None`` when declined.

        Returns:
            None

        Data Flow:
            - Hide the prompt either way.
            - Decline → one status line, no write.
            - Confirm → resolve the operator's selected record width and the
              matching S0 policy (US-015 / LLR-015.3): at 32 bytes/line
              PRESERVE the loaded image's ``source_s0_header`` when present,
              else SYNTHESIZE a minimal ASCII S0 from the destination filename
              (``_synth_s0_header_from_filename``). Note: an EMPTY source S0
              (zero-length ``bytes``) is falsy and so is treated as absent →
              synthesized, same as ``None`` (the ``source_s0_header or synth``
              semantics). At 16 bytes/line write the
              legacy empty S0 (``s0_header=None``). Then
              ``ChangeService.save_patched`` into the active project directory
              (work-area root when no project is active); the typed name
              passes the engine's F-S-01 sanitizer; the result and its
              findings surface on the status path. ``loaded.path`` rides the
              ``source_image_path`` kwarg — the LLR-038.2 B-2 provenance
              stamp the before/after composer checks for staleness. On a
              successful save, after the verify outcome surfaces and only
              when a project is open (R-BEFORE-AFTER-REPORT-001.36), an
              information notify offers the before/after report action
              (key ``b`` — LLR-038.3).
            - A save into the open project makes the written file the
              project's active variant (``_activate_project_file``) and
              rewrites ``project.json`` through
              ``_rewrite_project_manifest`` with every key the save-back
              does not own carried (LLR-168.2 / LLR-168.3) and the saved
              file's ``derived_from`` record (LLR-168.4: the loaded image
              is the base); a damaged ``project.json`` is left as it is;
              ``current_file.path`` stays on the loaded image.

        Dependencies:
            Uses:
                - ``ChangeService.save_patched``
                - ``_active_project_dir``
                - ``_synth_s0_header_from_filename``
                - ``_activate_project_file`` / ``_rewrite_project_manifest``
            Used by:
                - Textual message dispatch for ``PatchEditorPanel``
        """
        if self._refuse_if_busy():
            return
        panel = self.query_one("#patch_editor_panel", PatchEditorPanel)
        panel.hide_save_prompt()
        if event.filename is None:
            self.set_status("Patch Editor: save-back declined")
            return
        loaded = self.current_file
        if loaded is None:
            self.set_status("Patch Editor: no image loaded - nothing saved")
            return
        dest_dir = self._active_project_dir() or self.workarea
        bytes_per_line = event.bytes_per_line
        if bytes_per_line == 32:
            s0_header = loaded.source_s0_header or _synth_s0_header_from_filename(
                event.filename
            )
        else:
            s0_header = None
        result = self._change_service.save_patched(
            loaded.mem_map,
            loaded.ranges,
            dest_dir,
            event.filename,
            source_kind=loaded.file_type,
            bytes_per_line=bytes_per_line,
            s0_header=s0_header,
            source_image_path=loaded.path,
            # batch-99 HLR-157: the save re-derives the image from the whole
            # document; the linkage inputs keep a re-derived summary's
            # classification identical to the apply routing's.
            mac_records=loaded.mac_records,
            a2l_tags=self._compute_a2l_enriched_tags() or None,
            # SEC-4 (LED .56): the emit stages under THIS work area.
            workarea_root=self.workarea,
        )
        # Inc 5 D-4: a save-back wrote (or reverted) the loaded image's bytes
        # in place — ``save_patched`` adopts the re-derived bytes before it
        # possibly refuses a blocked save — so tell the CRC Designer whatever
        # ``result.ok`` (R-CRC-PREVIEW-002.5/7).
        self._note_image_bytes_written()
        self._report_change_result(result)
        if result.ok:
            # LLR-167.5: a successful save-back records the saved image.
            self._change_service.mark_saved(loaded.mem_map)
            # LLR-168.2: a save-back into the open project becomes its
            # active variant, in the session and in project.json; the
            # loaded image keeps its own path.
            project_dir = self._active_project_dir()
            summary = self._change_service.last_summary
            saved = summary.saved_path if summary is not None else None
            if project_dir is not None and saved is not None:
                if self._activate_project_file(project_dir, saved) is not None:
                    # LLR-168.4: the saved variant records its base.
                    self._rewrite_project_manifest(
                        project_dir,
                        saved,
                        self._derived_record(loaded.path, loaded.mem_map),
                    )
            self._surface_verify_result()
            # US-061 / LLR-061.1: reveal the PERSISTENT before/after-report
            # control (a durable widget, not a Toast) so the report stays
            # discoverable after the notify below would have timed out. It is
            # re-hidden on the next document load (clear-on-context).
            panel.show_before_after_prompt()
            # LLR-038.3 offer — AFTER _surface_verify_result so a
            # verify-mismatch error notice is never masked; a mismatch does
            # NOT suppress the offer (A-m2: the report is an honest
            # disk-to-disk comparison of what was actually written).
            # Inc 6 (R-BEFORE-AFTER-REPORT-001.1/.36): the offer needs a
            # project reports/ destination, so it is shown only when a
            # project is open — the same ``project_dir`` the manifest
            # rewrite above used. The persistent control stays unconditional
            # (R-TUI-049.1, D-2): pressing it without a project gives the
            # .11 refusal, which names the manual path.
            if project_dir is not None:
                self.notify(
                    "Before/after report ready - press b to write it to the "
                    "project reports directory.",
                    title="Before/after report",
                    severity="information",
                )

    def _refresh_patch_checks_tab(self, panel: PatchEditorPanel) -> None:
        """Render the Patch Editor Checks tab from the live run state (Inc 6).

        Summary:
            The one Checks-tab writer outside the run arm: paint the rows of
            a CURRENT check run (else none), the live status line and the
            live aggregates. A run that is no longer current — after a
            document load, an image install, a project reset or an
            in-place write — renders as ``no run yet`` with zero counts and
            no rows (R-CHK-PE-008 … -012). Pure render: reads the service,
            writes only the Checks tab.

        Args:
            panel (PatchEditorPanel): The mounted Patch Editor panel.

        Returns:
            None

        Data Flow:
            - ``check_run_is_current()`` gates the rows (I-1); the status
              line (I-2) and aggregates (I-3) ride the live accessors so a
              non-current run degrades to ``""`` / all-zero.

        Dependencies:
            Uses:
                - ``ChangeService.check_run_is_current`` / ``check_rows`` /
                  ``check_status_line`` / ``check_aggregates``
                - ``PatchEditorPanel.refresh_check_results``
            Used by:
                - the Patch Editor action arms, the load tail, the history
                  view, the project reset and the image install
        """
        service = self._change_service
        current = service.check_run_is_current()
        panel.refresh_check_results(
            service.check_rows() if current else [],
            service.check_status_line(),
            service.check_aggregates(),
        )

    def _hide_replaced_document_controls(self, panel: PatchEditorPanel) -> None:
        """Hide the before/after control and the save-back prompt (Inc 6).

        Summary:
            The single clear-on-replace helper: whenever the document is
            replaced (a load, a paste, undo/redo that moved a step, a
            project reset) or a new image is installed, the old apply's
            persistent before/after control and its save-back prompt must
            not survive under the new document or onto the new image
            (R-TUI-049.3.1/.3.2). Writes nothing to disk and moves no focus.

        Args:
            panel (PatchEditorPanel): The mounted Patch Editor panel.

        Returns:
            None

        Data Flow:
            - ``hide_before_after_prompt()`` then ``hide_save_prompt()``.

        Dependencies:
            Uses:
                - ``PatchEditorPanel.hide_before_after_prompt`` /
                  ``hide_save_prompt``
            Used by:
                - the parse-paste arm, undo/redo, ``_patch_editor_load``,
                  ``_reset_project_session``, ``_apply_prepared_load``
        """
        panel.hide_before_after_prompt()
        panel.hide_save_prompt()

    def _refresh_patch_history_view(self) -> None:
        """
        Summary:
            Re-render the Patch Editor after a change-set history restore
            (US-068a) — the shared tail of :meth:`on_patch_editor_panel_undo_
            requested` / :meth:`on_patch_editor_panel_redo_requested`. Mirrors
            the entries/issues/enable-sync tail of the action handler so the
            entries table, declaration-fault area, and both A-01 disable guards
            reflect the restored document.

        Data Flow:
            - Read the loaded image's ranges (``None`` when no image), then
              ``refresh_entries`` / ``refresh_issues``, clear the stale Checks
              panel from the restored (now check-less) document
              (``refresh_check_results`` — ``undo``/``redo`` reset
              ``last_check_result`` so ``check_rows`` returns the cleared state,
              batch-40 S1), and re-sync the Edit-JSON + Undo/Redo enable state
              from the restored document's ``source_path`` (LLR-068a.4).
            - batch-48 LLR-081.3: the same ``set_undo_redo_enabled`` call
              re-renders the history strip from ``history_depths()``. This is
              THE site that moves the history, so the depths it pushes are the
              strip's whole point.

        Dependencies:
            Uses:
                - ``ChangeService.rows`` / ``issue_lines`` / ``check_rows``
                  / ``check_aggregates`` / ``history_depths``
                - ``PatchEditorPanel.refresh_entries`` / ``refresh_issues``
                  / ``refresh_check_results`` / ``set_edit_json_enabled``
                  / ``set_undo_redo_enabled``
            Used by:
                - ``on_patch_editor_panel_undo_requested`` / ``..._redo_requested``
        """
        service = self._change_service
        loaded = self.current_file
        loaded_ranges = loaded.ranges if loaded is not None else None
        panel = self.query_one("#patch_editor_panel", PatchEditorPanel)
        # batch-48 (LLR-080.2) — site 2 of 5 (the history/refresh path).
        panel.refresh_entries(
            service.rows(loaded_ranges),
            # batch-99 HLR-157 (LLR-157.4): the strip reads the journal
            # overlay — source bytes at every address an apply wrote.
            mem_map=self._strip_source_map(loaded),
            document=self._patch_document_view(),
        )
        # batch-97 Inc-8 (PC-23): the key bar dims Undo / Redo by the
        # document's source, which this refresh may have changed.
        self.refresh_bindings()
        panel.refresh_issues(service.issue_lines())
        # batch-40 S1: a history move (undo/redo) restores a change-set whose
        # entries no longer match the pre-move check run, so the stale Checks
        # panel must not persist. ``undo``/``redo`` reset ``last_check_result``
        # → ``check_rows`` returns the cleared state; render it here.
        # batch-48 LLR-078.3: the pass/fail strip rides that SAME reset —
        # ``check_aggregates()`` reads all-zero once ``last_check_result`` is
        # None, so the strip clears in step with the rows. Omitting it here
        # (while the post-run site supplies it) would leave a stale count.
        # Inc 6: the one Checks-tab writer renders rows of a current run
        # (else none), the live status line and the live aggregates.
        self._refresh_patch_checks_tab(panel)
        # batch-49 LLR-084.7 (site 2 of 2): the CHECKS screen rides the SAME
        # undo/redo reset of ``last_check_result`` (``change_service.py:571/603``)
        # so its grouped list + aggregate strip clear in step with the Patch
        # panel — no stale rows (the batch-38 Inc-4 F1 stale-panel shape).
        self.update_checks_view()
        panel.set_edit_json_enabled(service.document.source_path is None)
        # batch-48 LLR-081.3 (writer census, site 2 of 3): THE site that moves
        # the history. `undo`/`redo` shift a snapshot between the two stacks, so
        # the depths this pushes are the whole point of the strip — an omission
        # here would freeze it at its pre-move numbers while the buttons updated
        # around it (the batch-38 Inc-4 F1 stale-panel shape).
        panel.set_undo_redo_enabled(
            service.document.source_path is None, service.history_depths()
        )
        panel.set_entry_edit_json_enabled(service.document.source_path is None)

    def on_patch_editor_panel_undo_requested(
        self, event: PatchEditorPanel.UndoRequested
    ) -> None:
        """
        Summary:
            Restore the immediately-prior change-set (US-068a / LLR-068a.2/.3):
            route the payload-free Undo button trigger through the shared
            :meth:`action_patch_undo` path (the same one the ``ctrl+z`` key
            binding drives). An empty undo history is a no-op inside the
            service, so this handler is crash-free even with no history. The
            Undo control is disabled for a file-backed document (LLR-068a.4),
            so this message is only posted for a paste-authored / empty
            document.

        Args:
            event (PatchEditorPanel.UndoRequested): The payload-free trigger.

        Returns:
            None

        Dependencies:
            Uses:
                - ``action_patch_undo`` (the shared guarded undo path)
            Used by:
                - Textual message dispatch for ``PatchEditorPanel``
        """
        if self._refuse_if_busy():
            return
        self.action_patch_undo()

    def on_patch_editor_panel_redo_requested(
        self, event: PatchEditorPanel.RedoRequested
    ) -> None:
        """
        Summary:
            Re-apply the most-recently-undone change-set (US-068a /
            LLR-068a.2/.3): route the payload-free Redo button trigger through
            the shared :meth:`action_patch_redo` path (the same one the
            ``ctrl+y`` key binding drives). An empty redo stack is a
            service-level no-op.

        Args:
            event (PatchEditorPanel.RedoRequested): The payload-free trigger.

        Returns:
            None

        Dependencies:
            Uses:
                - ``action_patch_redo`` (the shared guarded redo path)
            Used by:
                - Textual message dispatch for ``PatchEditorPanel``
        """
        if self._refuse_if_busy():
            return
        self.action_patch_redo()

    def _patch_history_action_allowed(self) -> bool:
        """
        Summary:
            The A-01 guard shared by the ``ctrl+z`` / ``ctrl+y`` history key
            bindings (batch-40 S2): change-set undo/redo is reachable ONLY
            while the Patch Editor screen is active AND the owned document is
            paste-authored (``source_path is None``) — the exact enable-state
            :meth:`PatchEditorPanel.set_undo_redo_enabled` gives the Undo/Redo
            buttons. A key press on any other screen, or against a file-backed
            document, is a safe no-op so the binding can never bypass the
            LLR-068a.4 data-loss guard.

        Returns:
            bool: ``True`` when a history action may run (patch screen active
            and paste-authored document); ``False`` otherwise.

        Data Flow:
            - Read the ``#screen_patch`` container's ``hidden`` class (active
              iff not hidden), then the owned document's ``source_path``.

        Dependencies:
            Uses:
                - ``ChangeService.document``
            Used by:
                - ``action_patch_undo`` / ``action_patch_redo``
        """
        if self.query_one("#screen_patch").has_class("hidden"):
            return False
        return self._change_service.document.source_path is None

    def action_patch_undo(self) -> None:
        """
        Summary:
            Restore the immediately-prior change-set (US-068a / LLR-068a.2/.3),
            the shared body behind both the ``ctrl+z`` key binding and the
            ``#patch_undo_button`` trigger. Guarded by
            :meth:`_patch_history_action_allowed`, so it is a no-op unless the
            Patch Editor is active and the document is paste-authored (the
            A-01 guard); an empty undo history is itself a service-level no-op.

        Returns:
            None

        Dependencies:
            Uses:
                - ``_patch_history_action_allowed``
                - ``ChangeService.undo`` / ``_refresh_patch_history_view``
            Used by:
                - The ``ctrl+z`` key binding
                - ``on_patch_editor_panel_undo_requested`` (the button path)
        """
        if self._refuse_if_busy():
            return
        if not self._patch_history_action_allowed():
            return
        service = self._change_service
        before = service.document
        service.undo()
        # Inc 6 (R-TUI-049.3.1/.3.2): a history move that changed the
        # document replaces it — hide the old apply's prompt and control.
        if service.document is not before:
            panel = self.query_one("#patch_editor_panel", PatchEditorPanel)
            self._hide_replaced_document_controls(panel)
        self._refresh_patch_history_view()

    def action_patch_redo(self) -> None:
        """
        Summary:
            Re-apply the most-recently-undone change-set (US-068a /
            LLR-068a.2/.3), the shared body behind both the ``ctrl+y`` key
            binding and the ``#patch_redo_button`` trigger. Guarded by
            :meth:`_patch_history_action_allowed` (patch screen active +
            paste-authored A-01 guard); an empty redo stack is a service-level
            no-op.

        Returns:
            None

        Dependencies:
            Uses:
                - ``_patch_history_action_allowed``
                - ``ChangeService.redo`` / ``_refresh_patch_history_view``
            Used by:
                - The ``ctrl+y`` key binding
                - ``on_patch_editor_panel_redo_requested`` (the button path)
        """
        if self._refuse_if_busy():
            return
        if not self._patch_history_action_allowed():
            return
        service = self._change_service
        before = service.document
        service.redo()
        # Inc 6 (R-TUI-049.3.1/.3.2): as the undo arm — a redo that moved a
        # step replaces the document.
        if service.document is not before:
            panel = self.query_one("#patch_editor_panel", PatchEditorPanel)
            self._hide_replaced_document_controls(panel)
        self._refresh_patch_history_view()

    def on_patch_editor_panel_edit_json_requested(
        self, event: PatchEditorPanel.EditJsonRequested
    ) -> None:
        """
        Summary:
            Open the full-size JSON popup (:class:`ChangeSetJsonScreen`) over
            the paste buffer (US-064b / LLR-064b.1), seeded from the message's
            ``paste_text``. Re-checks the LLR-064b.4 A-01 disable-guard
            defensively — even though ``#patch_edit_json_button`` is disabled
            for a file-backed document, this handler refuses to push the popup
            whenever ``ChangeService.document.source_path is not None`` so a
            stale-buffer Confirm can never ``load_text``-REPLACE (clobber) the
            loaded document. The popup's Confirm result is applied by
            :meth:`_apply_changeset_json_edit`.

        Args:
            event (PatchEditorPanel.EditJsonRequested): Carries the current
                ``#patch_paste_text`` buffer to seed the popup editor.

        Returns:
            None

        Data Flow:
            - ``source_path is not None`` → status-line refusal, no push
              (A-01 guard, LLR-064b.4).
            - else → ``push_screen(ChangeSetJsonScreen(seed),
              _apply_changeset_json_edit)``.

        Dependencies:
            Uses:
                - ``ChangeSetJsonScreen`` / ``_apply_changeset_json_edit``
            Used by:
                - Textual message dispatch for ``PatchEditorPanel``
        """
        if self._refuse_if_busy():
            return
        if self._change_service.document.source_path is not None:
            self.set_status(
                "Patch Editor: Edit JSON is available only for a pasted "
                "change-set, not a file-loaded document."
            )
            return
        self.push_screen(
            ChangeSetJsonScreen(event.paste_text),
            self._apply_changeset_json_edit,
        )

    def _apply_changeset_json_edit(self, edited: Optional[str]) -> None:
        """
        Summary:
            Apply the JSON popup's Confirm result (US-064b / LLR-064b.2,
            amended by batch-94 LLR-004.1/.2): write the edited text back to
            ``#patch_paste_text`` and route it through the EXISTING
            ``parse_paste`` → ``ChangeService.load_text`` seam by posting the
            panel's ``ActionRequested(parse_paste)`` — the SAME message the
            inline "Parse pasted" button posts — so no new parse/apply path
            is introduced and the collect-don't-abort re-render (entries
            table / issue lines / Edit-JSON enable-sync) happens through the
            one action handler. Batch-94 amendment (HLR-004 invalid arm):
            when the edited text does NOT parse clean, the confirm surfaces
            the collected issues and LEAVES the bound document and the
            entries table untouched — an invalid edit can never clobber the
            table (the parse_paste arm keeps its replace-on-confirm shape
            for the inline paste button; the popup's re-point to the guard
            is what LLR-004.2 pins). Cancel (``None``) is a no-op.

        Args:
            edited (Optional[str]): The edited JSON on Confirm, or ``None`` on
                Cancel / Escape.

        Returns:
            None

        Data Flow:
            - ``None`` → return (Cancel; document unchanged).
            - Invalid text → ``_report_change_result`` with the parse's
              collected issues; the document/table are NOT touched.
            - Valid text → set ``#patch_paste_text`` to ``edited`` and post
              ``PatchEditorPanel.ActionRequested(action="parse_paste",
              paste_text=edited)`` to re-use the existing paste apply arm.

        Dependencies:
            Uses:
                - ``parse_change_document`` (the batch-94 validity pre-check)
                - ``PatchEditorPanel.ActionRequested`` / ``load_text`` seam
            Used by:
                - ``on_patch_editor_panel_edit_json_requested`` (push callback)
        """
        if self._refuse_if_busy():
            return
        if edited is None:
            return
        # batch-94 (LLR-004.2): the validity pre-check decides whether the
        # confirm may touch the bound document at all.
        parsed = parse_change_document(edited, a2l_context=self.current_a2l_data)
        if parsed.has_errors:
            from ..services.change_service import ChangeActionResult

            self._report_change_result(
                ChangeActionResult(
                    message=(
                        f"Edit JSON refused: {parsed.kind} text carries "
                        f"{sum(1 for i in parsed.issues if i.severity.value == 'error')} "
                        "error(s) — the document is unchanged."
                    ),
                    issues=list(parsed.issues),
                    ok=False,
                )
            )
            return
        panel = self.query_one("#patch_editor_panel", PatchEditorPanel)
        self.query_one("#patch_paste_text", TextArea).text = edited
        panel.post_message(
            PatchEditorPanel.ActionRequested(
                action="parse_paste", paste_text=edited
            )
        )

    def on_patch_editor_panel_entry_edit_json_requested(
        self, event: PatchEditorPanel.EntryEditJsonRequested
    ) -> None:
        """
        Summary:
            Open the per-entry JSON popup (:class:`EntryJsonScreen`) for the
            selected entry (US-068b / LLR-068b.1/.2), seeded with ONLY that
            entry's JSON via ``ChangeService.entry_seed_json`` — a single
            entry, distinct from the whole-set :class:`ChangeSetJsonScreen`.
            Re-checks the LLR-068b.4 A-01 disable-guard defensively — even
            though ``#patch_entry_edit_json_button`` is disabled for a
            file-backed document, this handler refuses to push the popup
            whenever ``source_path is not None`` so a stale index can never
            mutate a loaded document. Bounds-checks the index (a stale message
            after a shrink is a no-op). The popup's Confirm result is applied
            by :meth:`_apply_entry_json_edit` for the same index.

        Args:
            event (PatchEditorPanel.EntryEditJsonRequested): Carries the
                selected entries-table row index.

        Returns:
            None

        Data Flow:
            - ``source_path is not None`` → status-line refusal, no push
              (A-01 guard, LLR-068b.4).
            - index out of range → no-op.
            - else → ``push_screen(EntryJsonScreen(seed), callback)`` where the
              callback binds the index for :meth:`_apply_entry_json_edit`.

        Dependencies:
            Uses:
                - ``ChangeService.entry_seed_json`` / ``EntryJsonScreen``
                - ``_apply_entry_json_edit``
            Used by:
                - Textual message dispatch for ``PatchEditorPanel``
        """
        if self._refuse_if_busy():
            return
        service = self._change_service
        if service.document.source_path is not None:
            self.set_status(
                "Patch Editor: per-entry Edit JSON is available only for a "
                "pasted change-set, not a file-loaded document."
            )
            return
        if event.index < 0 or event.index >= len(service.document.entries):
            return
        seed = service.entry_seed_json(event.index)
        self.push_screen(
            EntryJsonScreen(seed),
            lambda edited, index=event.index: self._apply_entry_json_edit(
                index, edited
            ),
        )

    def _apply_entry_json_edit(
        self, index: int, edited: Optional[str]
    ) -> None:
        """
        Summary:
            Apply the per-entry JSON popup's Confirm result (US-068b /
            LLR-068b.3): route the edited single-entry text through
            ``ChangeService.edit_entry_json`` — which validates it via the
            EXISTING ``parse_change_document`` seam and replaces ONLY the
            selected entry (malformed input is collected, not applied) — then
            surface the result and re-render the entries table / issue lines /
            enable guards through the shared :meth:`_refresh_patch_history_view`
            tail. Batch-101 Inc 4 (R-CHG-SYM.9/.10, R-TUI-058.9): the edit is
            validated against the session's loaded A2L, and when the read
            records the R-CHG-SYM.2 finding with no A2L loaded one
            plain-language status line follows the finding line (painted last).
            Cancel (``None``) is a no-op: the document is left unchanged.

        Args:
            index (int): The entry index the popup was opened for.
            edited (Optional[str]): The edited JSON on Confirm, or ``None`` on
                Cancel / Escape.

        Returns:
            None

        Data Flow:
            - ``None`` → return (Cancel; document unchanged).
            - else → ``edit_entry_json(index, edited,
              a2l_context=self.current_a2l_data)`` →
              ``_report_change_result`` → (R-TUI-058.9 plain-language line
              when the read records the R-CHG-SYM.2 finding with no A2L
              loaded) → ``_refresh_patch_history_view``.

        Dependencies:
            Uses:
                - ``ChangeService.edit_entry_json`` / ``_report_change_result``
                - ``_refresh_patch_history_view``
            Used by:
                - ``on_patch_editor_panel_entry_edit_json_requested`` (callback)
        """
        if self._refuse_if_busy():
            return
        if edited is None:
            return
        result = self._change_service.edit_entry_json(
            index, edited, a2l_context=self.current_a2l_data
        )
        self._report_change_result(result)
        if (
            not result.ok
            and self.current_a2l_data is None
            and any(
                issue.code == "CHG-SYMBOL-UNRESOLVED"
                and SYMBOL_NO_A2L_CONTEXT_TEXT in issue.message
                for issue in result.issues
            )
        ):
            self.set_status(
                "Patch Editor: the entry names an A2L symbol and no A2L is "
                "loaded - load the A2L, then edit the entry again."
            )
        self._refresh_patch_history_view()

    def _strip_source_map(
        self, loaded: Optional[LoadedFile]
    ) -> Optional[Mapping[int, int]]:
        """
        Summary:
            The memory map the Patch Editor's before/after strip reads
            (batch-99 HLR-157, LLR-157.4): the live image overlaid, at every
            address an apply journaled, with its SOURCE byte — so the strip's
            ``was`` line shows the byte the image held before any apply even
            on a repeated apply, when the live map already holds the entry's
            own bytes. With an empty journal (no apply yet) the live map is
            returned unchanged.

        Args:
            loaded (Optional[LoadedFile]): The loaded file whose map feeds
                the strip; ``None`` (no image) → ``None``, which the panel's
                refresh reads as "clear the map" (its sentinel keeps that
                distinct from "not supplied").

        Returns:
            Optional[Mapping[int, int]]: ``None`` when no image is loaded;
                else ``ChangeService.source_image_view(loaded.mem_map)`` —
                the live dict itself or a read-only journal overlay.

        Dependencies:
            Uses:
                - ``ChangeService.source_image_view``
            Used by:
                - the Patch Editor ``refresh_entries`` call sites (the
                  strip's map pushes)
        """
        if loaded is None:
            return None
        return self._change_service.source_image_view(loaded.mem_map)

    def _surface_verify_result(self) -> None:
        """
        Summary:
            Surface the verify-on-save outcome riding on
            ``ChangeService.last_summary.verify_result`` (HLR-004, hybrid
            D-B option 3): a quiet "saved + verified" status line on a clean
            verify (LLR-004.1), a prominent error notice naming the file and
            the per-kind run/byte mismatch summary on a ``mismatch``
            (LLR-004.2). The written file is left in place either way
            (collect-don't-abort) — surfacing only reads the already-computed
            ``VerifyResult``, it does not re-diff or re-verify.

            batch-99 PDR-UX-C6 (HLR-157): the verify status line — on BOTH
            arms, ``verified`` and ``mismatch`` — carries the save-back
            suffix naming the entries the saved image holds and each entry
            not applied before the save — outcome first, names in the SAME
            line — so the verify surfacing never overwrites the HLR-157
            naming text (the PDR-UX-C6 defect was exactly this line
            replacing the save result's naming).

        Args:
            None

        Returns:
            None

        Data Flow:
            - Read ``last_summary.verify_result`` (the §6.2 C-10 carrier
              stamped by ``ChangeService.emit_and_verify`` for the save-back and
              Save project); absent → no-op.
            - ``verified`` → one status line composed as ``Saved + verified:
              {name}`` + :func:`save_back_status_suffix` over
              ``ChangeService.last_save_applied`` /
              ``last_save_not_applied``, no notice.
            - ``mismatch`` → one status line composed as ``Verify MISMATCH:
              {name}`` + the SAME :func:`save_back_status_suffix` (UX-C6
              allows no exception — review round 1, finding F5) + a
              ``severity="error"`` notice built from ``stats.run_counts`` /
              ``byte_counts`` over ``DIFF_KIND_DOMAIN`` (counts/addresses
              only, never raw bytes — the F-S-05 no-byte-leak precedent).

        Dependencies:
            Uses:
                - set_status / notify
                - _verify_mismatch_summary
                - save_back_status_suffix (over the service's
                  ``last_save_applied`` / ``last_save_not_applied``)
            Used by:
                - on_patch_editor_panel_save_back_decision
                - _handle_save_dialog (Save project's emit, after commit)
        """
        summary = self._change_service.last_summary
        if summary is None or summary.verify_result is None:
            return
        verify = summary.verify_result
        name = (
            verify.written_path.name
            if verify.written_path is not None
            else "image"
        )
        if verify.status == STATUS_VERIFIED:
            # PDR-UX-C6: the suffix names what the saved image holds and any
            # entry not applied before the save, in the SAME status line as
            # the verify word — this line is the final painted status, so the
            # naming can no longer be overwritten by the verify surfacing.
            suffix = save_back_status_suffix(
                self._change_service.last_save_applied,
                self._change_service.last_save_not_applied,
            )
            self.set_status(f"Saved + verified: {name}{suffix}")
            return
        detail = self._verify_mismatch_summary(verify)
        # PDR-UX-C6 allows no exception (review round 1, finding F5): the
        # mismatch arm carries the SAME not-applied naming suffix, so the
        # names survive on both verify arms, outcome first.
        suffix = save_back_status_suffix(
            self._change_service.last_save_applied,
            self._change_service.last_save_not_applied,
        )
        self.set_status(f"Verify MISMATCH: {name}{suffix}")
        self.notify(
            f"{name}: {detail}",
            title="Verify mismatch - file may not match",
            severity="error",
            timeout=10.0,
            markup=False,
        )

    @staticmethod
    def _verify_mismatch_summary(verify: VerifyResult) -> str:
        """
        Summary:
            Render a one-line mismatch summary from an already-computed
            ``VerifyResult`` (LLR-004.2) — per-kind run and byte counts over
            the canonical ``DIFF_KIND_DOMAIN`` order. Pure rendering: it reads
            ``verify.stats`` only and never re-diffs (the diff was computed in
            the verify engine), and it emits counts/addresses only, never raw
            image bytes (F-S-05 no-byte-leak precedent).

        Args:
            verify (VerifyResult): The mismatch outcome to summarize.

        Returns:
            str: e.g. ``"changed 1 run / 1 byte, only_a 0 run / 0 byte, ..."``.

        Dependencies:
            Uses:
                - DIFF_KIND_DOMAIN
            Used by:
                - _surface_verify_result
        """
        stats = verify.stats
        parts = [
            f"{kind} {stats.run_counts.get(kind, 0)} run / "
            f"{stats.byte_counts.get(kind, 0)} byte"
            for kind in DIFF_KIND_DOMAIN
        ]
        return ", ".join(parts)

    def _report_change_result(self, result: ChangeActionResult) -> None:
        """
        Summary:
            Surface a change-service action result and its issues on the
            status path (the LLR-003.2 issue-surfacing arm — the evolved
            ``_report_cdfx_result`` pattern).

        Args:
            result (ChangeActionResult): The outcome of a ``ChangeService``
                load / validate / save / save-back / run-checks call.

        Returns:
            None

        Data Flow:
            - Emit the result's summary message, then one status line per
              ``ValidationIssue`` so the engineer sees every finding.

        Dependencies:
            Uses:
                - ``set_status``
            Used by:
                - ``on_patch_editor_panel_action_requested``
                - ``on_patch_editor_panel_save_back_decision``
        """
        self.set_status(result.message)
        for issue in result.issues:
            self.set_status(
                f"[{issue.code}] {issue.severity.value}: {issue.message}"
            )

    def _trigger_execute_scope(self, scope: str) -> None:
        """
        Summary:
            UI-thread gate for the E6 ``execute_scope`` action (LLR-006.6):
            validate the scope and the project/variant context, pick the
            manifest-absent fallback file, and start the execution worker.

        Args:
            scope (str): The selector's scope token — one of
                ``EXECUTION_SCOPES`` (``active`` / ``all`` /
                ``assignments``).

        Returns:
            None

        Data Flow:
            - Refuse an unknown scope, a missing project directory, or an
              empty variant set with one status line each.
            - The manifest-absent fallback batch (LLR-006.1 default) is the
              change service's loaded document ``source_path`` when it has
              one — the file the operator loaded in the Patch Editor.
            - Hand off to ``_start_execute_scope_worker`` (thread worker) so
              long runs never freeze the UI; all execution work happens in
              ``services.variant_execution_service``.

        Dependencies:
            Uses:
                - ``_active_project_dir`` / ``_start_execute_scope_worker``
            Used by:
                - ``on_patch_editor_panel_action_requested``
        """
        if scope not in EXECUTION_SCOPES:
            self.set_status(f"Execute: unknown scope {scope!r}")
            return
        project_dir = self._active_project_dir()
        variant_set = self._variant_set
        if project_dir is None or variant_set is None or not variant_set.variants:
            self.set_status("Execute: no project variants - load a project first.")
            return
        source_path = self._change_service.document.source_path
        fallback_batch = [source_path] if source_path is not None else []
        manifest_present = deps.read_project_manifest(project_dir) is not None
        if not fallback_batch and not manifest_present:
            self.set_status(
                "Execute: no manifest and no loaded change/check file - "
                "nothing to execute."
            )
            return
        assignment_source = (
            REPORT_SOURCE_MANIFEST if manifest_present else REPORT_SOURCE_DEFAULT
        )
        self.set_status(f"Execute: scope '{scope}' started...")
        self._start_execute_scope_worker(
            project_dir, variant_set, scope, fallback_batch, assignment_source
        )

    @work(thread=True, exclusive=True, group="execute_scope")
    def _start_execute_scope_worker(
        self,
        project_dir: Path,
        variant_set: ProjectVariantSet,
        scope: str,
        fallback_batch: list[Path],
        assignment_source: str,
    ) -> None:
        """
        Summary:
            Off-thread E6 execution worker: run
            ``execute_project_variants`` and surface per-variant status
            lines between variants via ``call_from_thread`` (F-Q-18), then
            dispatch the result report to the UI thread.

        Args:
            project_dir (Path): The active project directory.
            variant_set (ProjectVariantSet): The project's variant
                inventory at trigger time.
            scope (str): The validated execution scope.
            fallback_batch (list[Path]): The manifest-absent default file
                list.
            assignment_source (str): The report-vocabulary token
                (``manifest`` / ``default``) recorded at trigger time for
                the E8 retention snapshot.

        Returns:
            None

        Data Flow:
            - The service parses each variant's image itself (LLR-006.3);
              this worker never touches ``current_file``.
            - ``capture_mem_maps=True`` pins each variant's post-change
              memory map onto its result so a later "generate report from
              last execution" (E8 / LLR-008.5) can hexdump without
              re-running; ``_report_execution_results`` owns the bounded
              retention.
            - Status lines and the final report run on the UI thread via
              ``call_from_thread``; a service-level crash surfaces as one
              status line, never an unhandled worker exception.

        Dependencies:
            Uses:
                - ``execute_project_variants``
                - ``call_from_thread`` / ``_report_execution_results``
            Used by:
                - ``_trigger_execute_scope``
        """
        try:
            results, manifest_issues = execute_project_variants(
                project_dir,
                variant_set,
                scope=scope,
                fallback_batch=fallback_batch,
                capture_mem_maps=True,
                status_callback=lambda message: self.call_from_thread(
                    self.set_status, message
                ),
            )
        except Exception as exc:
            self.logger.exception("Execute scope worker failed: %s", exc)
            self.call_from_thread(
                self.set_status, f"Execute failed: {type(exc).__name__}: {exc}"
            )
            return
        self.call_from_thread(
            self._report_execution_results,
            project_dir,
            scope,
            assignment_source,
            results,
            manifest_issues,
        )

    def _report_execution_results(
        self,
        project_dir: Path,
        scope: str,
        assignment_source: str,
        results: List[VariantExecutionResult],
        manifest_issues: List[ValidationIssue],
    ) -> None:
        """
        Summary:
            UI-thread report of an E6 execution run: retain the run as the
            "last execution" snapshot for E8 report generation, then one
            status line per manifest finding and per variant result, plus
            the closing aggregate line.

        Args:
            project_dir (Path): The executed project directory — pinned in
                the retention snapshot so a later project switch
                invalidates it.
            scope (str): The executed scope token.
            assignment_source (str): ``manifest`` / ``default`` (report
                vocabulary, recorded at trigger time).
            results (List[VariantExecutionResult]): The per-variant
                outcomes in execution order.
            manifest_issues (List[ValidationIssue]): The manifest's
                collected findings (containment skips, parse faults).

        Returns:
            None

        Data Flow:
            - ``_last_execution`` is REPLACED first (LLR-008.5 retention:
              results + their captured mem_maps live until the next run,
              a project switch, or a successful report generation drops
              them).
            - Manifest findings first (the F-S-03 skip visibility), then
              one ``ok``/``error`` line per variant with its change/check
              counts and diagnostics, then the run summary.

        Dependencies:
            Uses:
                - ``set_status``
            Used by:
                - ``_start_execute_scope_worker`` (via ``call_from_thread``)
        """
        self._last_execution = (project_dir, scope, assignment_source, results)
        for issue in manifest_issues:
            self.set_status(
                f"[{issue.code}] {issue.severity.value}: {issue.message}"
            )
        for result in results:
            line = (
                f"Variant '{result.variant_id}': {result.status} - "
                f"{len(result.change_summaries)} change, "
                f"{len(result.check_results)} check"
            )
            self.set_status(line)
            for diagnostic in result.diagnostics:
                self.set_status(
                    f"Variant '{result.variant_id}': {diagnostic}"
                )
        error_count = sum(1 for result in results if result.status == "error")
        self.set_status(
            f"Execute: scope '{scope}' finished - {len(results)} variant(s), "
            f"{error_count} error(s)"
        )

    def on_patch_editor_panel_change_file_selected(
        self, event: PatchEditorPanel.ChangeFileSelected
    ) -> None:
        """Load a dropdown-chosen change file through the existing load path.

        Summary:
            Resolve the picked listed value against the change-list homes
            through the pick guard and, once it passes, route the file through
            the SAME ``ChangeService.load`` seam the typed-path Load action
            uses (LLR-030.3) — so the picked file becomes the active change
            document (its entries table reflects it). No new load/parse
            surface is introduced; only the source of the path differs.

        Args:
            event (PatchEditorPanel.ChangeFileSelected): Carries the listed
                value the operator selected (``checks/<n>``, ``patches/<n>``
                or ``library/<n>`` in a project; the bare name without one).

        Returns:
            None

        Data Flow:
            - ``candidate = _resolve_listed_file(event.filename,
              _change_homes())`` (R-PATCH-DOC-DROPDOWN-001.3/.4).
            - **Pick guard:** SKIP (the refusal status, no load) when the
              prefix names no home, the name is not a plain file name (empty,
              a separator, ``.`` or ``..``), a link or reparse point lies on
              the walk from the work area down to the file (also one that
              stays inside the project), or the resolved file is outside the
              work area. The unresolved ``folder / name`` is loaded (S-4).
            - **Dropdown guard (LLR-174.2t, S10-02):** when the panel holds
              unsaved entries, push the same ``LoadGuardScreen`` the Load
              button uses — accept runs the pick guard again (S-5) and loads
              ``str(candidate)`` only when it still passes, cancel keeps
              the document and resets ``#patch_doc_file_select`` to
              ``Select.NULL`` (A10-R2-3) so the same pick fires again.
              A clean panel loads at once.
            - Otherwise call ``ChangeService.load`` on the unresolved
              ``candidate`` and surface the result
              (``_report_change_result``); refresh the entries table from
              the new document.

        Dependencies:
            Uses:
                - ``_resolve_listed_file`` / ``_change_homes`` /
                  ``ChangeService.load``
                - ``_patch_editor_load`` / ``LoadGuardScreen``
                - ``_report_change_result`` / ``PatchEditorPanel.refresh_entries``
            Used by:
                - Textual message dispatch (the panel's ``ChangeFileSelected``)
        """
        if self._refuse_if_busy():
            return
        candidate = self._resolve_listed_file(
            event.filename, self._change_homes()
        )
        if candidate is None:
            self.set_status(
                f"Patch Editor: change file {event.filename!r} is outside "
                "the patches folder — not loaded."
            )
            return
        panel = self.query_one("#patch_editor_panel", PatchEditorPanel)
        if panel.is_dirty:

            def _answer(accepted: bool) -> None:
                if not accepted:
                    self.set_status("Patch Editor: load cancelled — changes kept.")
                    self.query_one(
                        "#patch_doc_file_select", Select
                    ).value = Select.NULL
                    return
                if self._refuse_if_busy():
                    return
                # Inc 6 (S-5): re-run the pick guard at accept — the folder
                # may have changed under the popup; a now-refused pick loads
                # nothing.
                rechecked = self._resolve_listed_file(
                    event.filename, self._change_homes()
                )
                if rechecked is None:
                    self.set_status(
                        f"Patch Editor: change file {event.filename!r} is outside "
                        "the patches folder — not loaded."
                    )
                    return
                self._patch_editor_load(panel, str(rechecked))

            self.push_screen(LoadGuardScreen(), _answer)
            return
        self._patch_editor_load(panel, str(candidate))

    def _patch_editor_load(self, panel: PatchEditorPanel, path_text: str) -> None:
        """The shared change-document load seam (LLR-008.1, batch-94).

        Summary:
            Route one concrete path through the validated
            ``ChangeService.load`` seam (size-cap + resolve_input_path +
            collect-don't-abort), surface the result, and — on success —
            clear the dirty flag (writer w4: a successful load rebinds BOTH
            editor regions to the loaded document, so its unsaved-state
            history is gone). The typed-path Load control, the change-file
            dropdown and the dirty-guard popup's accept branch are the three
            call sites; the post-load re-render tail lives in
            :meth:`_patch_editor_load_tail` so no site can drift.
        """
        # Inc 6 (R-TUI-049.3.1/.3.2, E3A-01): every load replaces the
        # document — also a failed read (``ChangeService.load`` always
        # assigns) — so the old apply's controls hide first.
        self._hide_replaced_document_controls(panel)
        service = self._change_service
        result = service.load(path_text, self.base_dir, a2l_context=self.current_a2l_data)
        self._report_change_result(result)
        if result.ok:
            panel.mark_loaded()
        self._patch_editor_load_tail(panel)

    def _patch_document_view(self) -> PatchDocumentView:
        """The Patch Editor document as plain data for the panel (batch-97 D1/D2).

        The ONE builder of the I-2/I-3 payload, passed at all four
        ``refresh_entries`` sites so the rows, the ribbon and the JSON view
        read one document. The serialiser emits ASCII JSON (``ensure_ascii``),
        so the ``bytes`` decode as ASCII (Code-Wire H-P4).
        """
        document = self._change_service.document
        source = document.source_path
        return PatchDocumentView(
            name=None if source is None else source.name,
            kind=document.kind,
            json_text=serialize_change_document(document).decode("ascii"),
            entry_count=len(document.entries),
        )

    def _patch_editor_load_tail(self, panel: PatchEditorPanel) -> None:
        """Re-render the panel after any document load (the shared tail).

        Refreshes the entries table (with the loaded image's memory map for
        the before/after card) and the declaration-fault listing, then
        re-applies the three A-01 file-backed guards (Edit-JSON, Undo/Redo
        with the history strip, per-entry Edit-JSON) — one tail, three call
        sites, no drift.
        """
        service = self._change_service
        loaded = self.current_file
        loaded_ranges = loaded.ranges if loaded is not None else None
        # batch-48 (LLR-080.2) — the load path's memory-map push.
        panel.refresh_entries(
            service.rows(loaded_ranges),
            # batch-99 HLR-157 (LLR-157.4): the strip reads the journal
            # overlay — source bytes at every address an apply wrote.
            mem_map=self._strip_source_map(loaded),
            document=self._patch_document_view(),
        )
        # batch-97 Inc-8 (PC-23): the key bar dims Undo / Redo by the
        # document's source, which this refresh may have changed.
        self.refresh_bindings()
        panel.refresh_issues(service.issue_lines())
        # US-064b / LLR-064b.4 A-01 guard: a file-backed document disables
        # Edit-JSON (no clobber path).
        panel.set_edit_json_enabled(service.document.source_path is None)
        # US-068a / LLR-068a.4 A-01 guard: same for Undo/Redo, with the
        # history-strip render (batch-48 LLR-081.3 writer census).
        panel.set_undo_redo_enabled(
            service.document.source_path is None, service.history_depths()
        )
        # US-068b / LLR-068b.4 A-01 guard: same for the per-entry JSON edit.
        panel.set_entry_edit_json_enabled(service.document.source_path is None)
        # Inc 6 (R-CHK-PE-009 … -012): a load replaces the document, so any
        # completed run is no longer current — render ``no run yet``.
        self._refresh_patch_checks_tab(panel)

    def on_patch_editor_panel_dirty_load_requested(
        self, event: PatchEditorPanel.DirtyLoadRequested
    ) -> None:
        """Raise the dirty-load guard popup (HLR-005 / LLR-005.2).

        Summary:
            The Load control fired while unsaved edits exist. Push
            :class:`LoadGuardScreen`; its boolean answer routes the two
            policy branches (C-10): ACCEPT continues the load of exactly the
            path the operator typed (through the shared
            :meth:`_patch_editor_load` seam — the dirty flag's clear rides
            that seam's success arm), CANCEL retains the document, its rows
            and the dirty flag, and loads nothing.
        """
        if self._refuse_if_busy():
            return
        panel = self.query_one("#patch_editor_panel", PatchEditorPanel)
        path_text = event.path_text

        def _answer(accepted: bool) -> None:
            if not accepted:
                self.set_status("Patch Editor: load cancelled — changes kept.")
                return
            if not path_text.strip():
                self.set_status(
                    "Patch Editor: enter a change-file path to load."
                )
                return
            if self._refuse_if_busy():
                return
            self._patch_editor_load(panel, path_text)

        self.push_screen(LoadGuardScreen(), _answer)

    def _prefill_patch_editor(self) -> None:
        """Populate the Patch Editor's A2L picker on screen entry
        (batch-102 Inc 5, R-B102-PE-001, R-B102-PE-005).

        Hands the loaded A2L's measurable parameters to the picker's
        highlight-mode ledger with the safe Inc-2 ``_a2l_enriched_key``
        signature: re-entering the screen with the same A2L and image is a
        no-op that preserves the filter, the page and the highlight
        (R-B102-PE-005). A not-yet-mounted panel (headless unit path) is
        tolerated as a no-op, matching ``_prefill_check_editor``.
        """
        try:
            panel = self.query_one("#patch_editor_panel", PatchEditorPanel)
        except Exception:
            return
        tags = self._compute_a2l_enriched_tags()
        measurable = [
            tag for tag in tags if isinstance(tag.get("address"), int)
        ]
        panel.set_a2l_parameters(measurable, self._a2l_enriched_key)

    def _note_image_bytes_written(self) -> None:
        """
        Summary:
            Tell the CRC Designer that the loaded image's bytes were written
            in place, so its coverage follows the written bytes (Inc 5 D-4).
            The ``current_file`` reactive does not fire for an in-place
            write (an apply, a save-back or a Save project commit), so this
            helper is the in-place twin of :meth:`watch_current_file`. It
            also clears the Check Editor's validation results, whose verdict
            rows judged the bytes before the write (R-CHKED-057), and it
            disarms a Split / Join export confirm, re-plans a displayed
            Split / Join preview and refreshes the three hex views and the
            A2L tag table's values, so every view over the image follows the
            written bytes (Inc 10b).

        Args:
            None

        Returns:
            None

        Data Flow:
            - First the Split / Join window (queried in its own ``try``;
              missing -> skipped): ``note_image_bytes_written`` disarms the
              confirm, so a fault later in this hook cannot leave a confirm
              given for other bytes armed (E5 R-2).
            - Inc 6 (E3A-03): end the current check run, repaint the Patch
              Editor ledger/Checks tab through the load tail (panel queried
              in a ``try``), repaint the Checks screen, then the CRC Designer
              and the Check Editor notices (each panel queried in its own
              ``try``; a missing panel skips only its own notice).
            - Inc 10b: refresh the three hex views, then the A2L tag table's
              values; each guards its panes the same way (a pane not mounted
              skips that notice).
            - A fault inside a panel or a notice is NOT swallowed: each
              delegation sits outside its ``try``.

        Dependencies:
            Uses:
                - ``CrcDesignerPanel``
                - ``CheckEditorPanel``
                - ``_refresh_hex_views_after_write``
                - ``_refresh_a2l_values_after_write``
                - ``SplitJoinWindow``
            Used by:
                - ``on_patch_editor_panel_action_requested``
                - ``on_patch_editor_panel_save_back_decision``
                - ``_on_project_saved``
        """
        try:
            split_window = self.query_one("#screen_split_join", SplitJoinWindow)
        except Exception:
            split_window = None
        if split_window is not None:
            split_window.note_image_bytes_written()
        # Inc 6 (E3A-03, I-7/I-8): an in-place write of the loaded image's
        # bytes ends the current run, then the Patch Editor ledger glyphs and
        # the Checks tab repaint with ``no run yet``, and a displayed Checks
        # screen follows (a guarded no-op when not mounted).
        self._change_service.end_check_run()
        try:
            panel = self.query_one("#patch_editor_panel", PatchEditorPanel)
        except Exception:
            panel = None
        if panel is not None:
            self._patch_editor_load_tail(panel)
        self.update_checks_view()
        try:
            designer = self.query_one(CrcDesignerPanel)
        except Exception:
            designer = None
        if designer is not None:
            designer.note_image_bytes_written()
        try:
            checks = self.query_one("#check_editor_panel", CheckEditorPanel)
        except Exception:
            checks = None
        if checks is not None:
            checks.clear_check_results()
        self._refresh_hex_views_after_write()
        self._refresh_a2l_values_after_write()

    def _refresh_hex_views_after_write(self) -> None:
        """
        Summary:
            Repaint the main, A2L and MAC hex views after an in-place write
            so each pane shows the written bytes while its window, scroll
            and ``> `` marker stay put (R-TUI-004.7, .8, .9).

        Args:
            None

        Returns:
            None

        Data Flow:
            - No file -> return (the views already read "No file loaded.").
            - A hex pane not mounted -> return (the hook's guard idiom, E5
              R-6).
            - ``update_hex_view()`` with no focus: 10a's single clamp keeps
              ``_hex_window_start``, the marker and the scroll (I-3).
            - Bisect the A2L view's first visible address in
              ``_hex_view_rows()`` and re-render with that ``start_row``
              (``None`` while the address is unset, as a load does); the same
              for the MAC view. No ``reset_scroll`` and no focus address, so
              no marker change.

        Dependencies:
            Uses:
                - ``update_hex_view`` / ``update_alt_hex_view`` /
                  ``update_mac_hex_view``
                - ``_hex_view_rows``
            Used by:
                - ``_note_image_bytes_written``
        """
        if not self.current_file:
            return
        try:
            self.query_one("#hex_view", Static)
            self.query_one("#alt_hex_view", Static)
            self.query_one("#mac_hex_view", Static)
        except Exception:
            return
        self.update_hex_view()
        rows = self._hex_view_rows()
        from bisect import bisect_left

        start = (
            bisect_left(rows, self._alt_first_visible_address)
            if self._alt_first_visible_address is not None
            else None
        )
        self.update_alt_hex_view(start_row=start)
        start = (
            bisect_left(rows, self._mac_first_visible_address)
            if self._mac_first_visible_address is not None
            else None
        )
        self.update_mac_hex_view(start_row=start)

    def _refresh_a2l_values_after_write(self) -> None:
        """
        Summary:
            Recompute the A2L tags whose bytes the write changed and repaint
            the shown tag-table page in place, so the Raw and Physical cells
            read the written bytes while the listed tags, the first shown
            row, the cursor and the scroll stay (R-A2L-048, -049, -105,
            -106). Only the changed tags are recomputed, so a write costs
            far less than a full enrichment on a large A2L (E5 R-1: 3.95 s
            for 220,040 tags on case_06).

        Args:
            None

        Returns:
            None

        Data Flow:
            - No image or no A2L -> return (nothing was written that a tag
              reads). The tag-table panes not mounted -> the cache and the
              filtered list still refresh; only the paints are skipped
              (E5 RR-3).
            - ``old = _a2l_enriched_tags``. When ``_compute_a2l_enriched_tags``
              returns ``old`` itself, the cache describes this image's
              layout, and a write keeps that layout (it writes only addresses
              already in ``mem_map``): a tag is recomputed when the bytes its
              row was computed from (``raw_bytes``) differ from the image's
              bytes at its range now. Those tags go through
              ``enrich_tags_and_render`` as a sub-list (a duplicated
              ``(section, name)`` group is flagged as a whole, since every
              row of the group carries the group's last tag's range, so the
              merge picks the same check row as a full run); every other
              dict is kept. No changed tag -> return. The summary lines read
              no byte value (D-10b-3), so they are kept.
            - Otherwise the cache did not describe this image: the full
              recompute runs and ``#a2l_view`` is repainted (S-8).
            - Re-point ``_a2l_filtered_tags`` to the new dict at each listed
              tag's position in ``old`` (same tags, same order, no
              ``_filter_a2l_tags`` call). A listed tag not in ``old`` (the
              listing was stale) re-runs the filter instead
              (``_refresh_a2l_filtered_tags``, anchor kept), never a
              ``KeyError`` (E5 R-2).
            - ``_repaint_a2l_tag_cells()`` writes the shown page's changed
              cells in place; not ``update_a2l_view()`` /
              ``_refresh_a2l_filtered_tags`` on the normal path (their
              ``clear()`` resets the cursor and scroll).

        Dependencies:
            Uses:
                - ``_compute_a2l_enriched_tags`` / ``enrich_tags_and_render``
                - ``_update_a2l_summary_buffer``
                - ``_refresh_a2l_filtered_tags``
                - ``_repaint_a2l_tag_cells``
            Used by:
                - ``_note_image_bytes_written``
        """
        if not self.current_file or not self.current_a2l_data:
            return
        try:
            self.query_one("#a2l_view", Static)
            self.query_one("#a2l_tags_list", DataTable)
            self.query_one("#a2l_tags_summary", deps.Label)
            mounted = True
        except Exception:
            mounted = False
        old = self._a2l_enriched_tags
        if self._compute_a2l_enriched_tags() is old:
            mem_map = self.current_file.mem_map
            changed = []
            for index, tag in enumerate(old):
                raw = tag.get("raw_bytes")
                if raw is None:
                    continue
                start = tag["address"]
                now = [mem_map.get(address) for address in range(start, start + len(raw) // 2)]
                if now != list(bytes.fromhex(raw)):
                    changed.append(index)
            if not changed:
                return
            source = self.current_a2l_data.get("tags", [])
            fresh, _lines = enrich_tags_and_render(
                {**self.current_a2l_data, "tags": [source[index] for index in changed]},
                mem_map,
            )
            new = list(old)
            for index, tag in zip(changed, fresh):
                new[index] = tag
            self._a2l_enriched_tags = new
        else:
            new = self._a2l_enriched_tags
            if mounted:
                self._update_a2l_summary_buffer()
        position_by_tag = {id(tag): i for i, tag in enumerate(old)}
        positions = [position_by_tag.get(id(tag)) for tag in self._a2l_filtered_tags]
        if None in positions:
            if mounted:
                self._refresh_a2l_filtered_tags(preserve_anchor=True)
            return
        self._a2l_filtered_tags = [new[i] for i in positions]
        if mounted:
            self._repaint_a2l_tag_cells()
