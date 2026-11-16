"""s19_app.tui.screens_directionb.patch_editor.actions - ActionsMixin (methods moved verbatim from patch_editor.py at 2dbd7d5a)."""
from __future__ import annotations

from typing import Mapping, Optional
from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Container, Horizontal
from textual.widgets import Button, DataTable, Input, Label, Static, TextArea
from ...insight_style import DGRAY, LABEL, VALUE
from ...os_clipboard_input import OsClipboardInput


class ActionsMixin:
    """Mixin: the panel's apply/save bar: actions, dirty state, prompts, history strip."""

    def request_action(self, action: str) -> None:
        """Post an :class:`ActionRequested` message for ``action``.

        Summary:
            Read the entry and path input fields and post an
            ``ActionRequested`` message so ``app.py`` can call
            ``ChangeService``. The widget itself performs no
            ``changes``-package work — it only forwards the request.
            Batch-94 (LLR-005.1): the entries-table edit actions also SET
            the dirty flag (writer w1) — an Add / Edit / Remove is unsaved
            work until the next successful save or load.

        Args:
            action (str): One of the eight LLR-003.2 v2 actions —
                ``"add_entry"`` / ``"edit_entry"`` / ``"remove_entry"`` /
                ``"load_doc"`` / ``"validate_doc"`` / ``"apply_doc"`` /
                ``"save_doc"`` / ``"run_checks"`` — or the E6 extension
                ``"execute_scope"`` (LLR-006.6).

        Dependencies:
            Uses:
                - ``ActionRequested``
            Used by:
                - the panel's entry and document controls
        """
        if action in ("add_entry", "edit_entry", "remove_entry"):
            # w1 (LLR-005.1 writer census): entries-table edit → dirty.
            self._dirty = True
            self._refresh_dirty_indicator()
        self.post_message(
            self.ActionRequested(
                action=action,
                address_text=self.query_one(
                    "#patch_entry_address_input", Input
                ).value,
                value_text=self.query_one(
                    "#patch_entry_value_input", Input
                ).value,
                bytes_text=self.query_one(
                    "#patch_entry_bytes_input", Input
                ).value,
                path_text=self.query_one(
                    "#patch_doc_path_input", Input
                ).value,
                scope_text=self._execute_scope,
            )
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Translate any Patch Editor button press into a message.

        Summary:
            Map the pressed button id to one of the v2 actions and forward
            it via :meth:`request_action`; the "Parse pasted" button posts
            its own :class:`ActionRequested` carrying the paste ``TextArea``
            body (``parse_paste``, LLR-014.2), and the save-back confirm /
            decline buttons post a :class:`SaveBackDecision` instead. Stops
            the event so it does not also reach the app-level
            ``on_button_pressed``.

        Args:
            event (Button.Pressed): The Textual button-press event.

        Dependencies:
            Uses:
                - ``request_action`` / ``SaveBackDecision``
            Used by:
                - Textual button-press dispatch
        """
        button_id = event.button.id or ""
        if any(button_id == tab[0] for tab in self._TABS):
            event.stop()
            self._show_tab(button_id)
            return
        if button_id == "patch_param_use_button":
            # batch-102 Inc 5 (R-B102-PE-003): transfer the highlighted A2L
            # row into the entry form — the document is not touched.
            event.stop()
            self._use_highlighted_parameter()
            return
        if button_id == "patch_saveback_width_button":
            # Selector state only — cycle the save-back record width and
            # relabel; no message is posted, so this adds no routed action
            # (the same idiom as #patch_execute_scope_button). The chosen
            # width rides the next SaveBackDecision (US-015 / LLR-015.3).
            event.stop()
            index = self.SAVEBACK_WIDTHS.index(self._saveback_width)
            self._saveback_width = self.SAVEBACK_WIDTHS[
                (index + 1) % len(self.SAVEBACK_WIDTHS)
            ]
            event.button.label = (
                f"Width: {self._saveback_width} bytes/line"
            )
            return
        if button_id == "patch_saveback_confirm_button":
            event.stop()
            self.post_message(
                self.SaveBackDecision(
                    self.query_one("#patch_saveback_name_input", Input).value,
                    bytes_per_line=self._saveback_width,
                )
            )
            return
        if button_id == "patch_saveback_decline_button":
            event.stop()
            self.post_message(self.SaveBackDecision(None))
            return
        if button_id == "patch_before_after_button":
            # US-061 / LLR-061.2: the persistent control is a second trigger
            # onto the ONE report writer — post a payload-free request; the app
            # routes it to action_before_after_report (no duplicated code).
            event.stop()
            self.post_message(self.BeforeAfterReportRequested())
            return
        if button_id == "patch_paste_parse_button":
            # The paste action carries the TextArea body (not an Input), so
            # it posts its own ActionRequested with ``paste_text`` rather
            # than going through request_action (LLR-014.2).
            event.stop()
            self.post_message(
                self.ActionRequested(
                    action="parse_paste",
                    paste_text=self.query_one(
                        "#patch_paste_text", TextArea
                    ).text,
                )
            )
            return
        if button_id == "patch_edit_json_button":
            # US-064b / LLR-064b.1: open the full-size JSON popup over the paste
            # buffer. Carries the current buffer as the seed; the app pushes
            # ``ChangeSetJsonScreen`` and applies the edit through the existing
            # ``parse_paste`` → ``load_text`` seam. Disabled for a file-backed
            # document (LLR-064b.4), so a press here is paste-authored only.
            event.stop()
            self.post_message(
                self.EditJsonRequested(
                    paste_text=self.query_one(
                        "#patch_paste_text", TextArea
                    ).text
                )
            )
            return
        if button_id == "patch_undo_button":
            # US-068a / LLR-068a.3: pure trigger — the app calls
            # ``ChangeService.undo()`` and re-renders. Disabled for a
            # file-backed document (LLR-068a.4), so a press is history-safe.
            event.stop()
            self.post_message(self.UndoRequested())
            return
        if button_id == "patch_redo_button":
            event.stop()
            self.post_message(self.RedoRequested())
            return
        if button_id == "patch_entry_edit_json_button":
            # US-068b / LLR-068b.1: open the per-entry JSON popup for the
            # SELECTED entries-table row. Carry the selected row index; the app
            # seeds ``EntryJsonScreen`` with that one entry's JSON and routes
            # Confirm through the validated per-entry apply. With no rows there
            # is no selection → no-op. Disabled for a file-backed document
            # (LLR-068b.4), so a press here is paste-authored only.
            event.stop()
            table = self.query_one("#patch_doc_entries_table", DataTable)
            if table.row_count == 0:
                return
            self.post_message(self.EntryEditJsonRequested(table.cursor_row))
            return
        if button_id == "patch_execute_scope_button":
            # Selector state only — cycle the scope and relabel; no message
            # is posted, so this adds no routed action.
            event.stop()
            index = self.EXECUTE_SCOPES.index(self._execute_scope)
            self._execute_scope = self.EXECUTE_SCOPES[
                (index + 1) % len(self.EXECUTE_SCOPES)
            ]
            event.button.label = (
                f"Scope: {self._SCOPE_LABELS[self._execute_scope]}"
            )
            # LLR-075.3: the line and the button label are two views of the
            # SAME `_execute_scope` — cycle them together or the line lies.
            self._refresh_scope_line()
            return
        if button_id == "patch_doc_load_button":
            # batch-94 (HLR-005 / LLR-005.2): the dirty guard. With unsaved
            # edits in either editor region, Load does NOT load — it asks.
            # Post :class:`DirtyLoadRequested`; ``app.py`` pushes the
            # :class:`LoadGuardScreen` modal and only proceeds with THIS path
            # when the operator accepts the loss. A clean document loads
            # directly (the popup-always shape is the negative control).
            event.stop()
            path_text = self.query_one("#patch_doc_path_input", Input).value
            if self._dirty:
                self.post_message(self.DirtyLoadRequested(path_text=path_text))
            else:
                self.request_action("load_doc")
            return
        actions = {
            "patch_entry_add_button": "add_entry",
            "patch_entry_edit_button": "edit_entry",
            "patch_entry_remove_button": "remove_entry",
            "patch_doc_refresh_button": "refresh_doc",
            "patch_doc_validate_button": "validate_doc",
            "patch_doc_apply_button": "apply_doc",
            "patch_doc_save_button": "save_doc",
            "patch_checks_run_button": "run_checks",
            "patch_execute_run_button": "execute_scope",
        }
        action = actions.get(button_id)
        if action is not None:
            event.stop()
            self.request_action(action)

    def mark_saved(self) -> None:
        """Clear the dirty flag after a successful save (LLR-005.1, writer w3).

        Called by ``app.py`` when the change service reports a clean
        ``save_doc`` — the flag must not survive its own save (the
        save-then-check arm of TC-B94-10 is the negative control).
        """
        self._dirty = False
        self._refresh_dirty_indicator()

    def mark_loaded(self) -> None:
        """Clear the dirty flag after a successful load (LLR-005.1, writer w4).

        Called by ``app.py`` when a document load / paste parse succeeds —
        the freshly-loaded document has no unsaved edits, in BOTH editor
        regions (the entries table re-renders from the loaded document and
        the buffer is reseeded, so one clear covers the two regions).
        """
        self._dirty = False
        self._refresh_dirty_indicator()

    @property
    def is_dirty(self) -> bool:
        """Whether either editor region holds unsaved edits (LLR-174.1c).

        The one reader of ``_dirty`` outside this module: the app's load
        guard, ``_handle_save_dialog`` and the change-file dropdown guard
        (LLR-174.2t) read it here, never the private attribute. No setter:
        only the five writers change the flag.
        """
        return self._dirty

    def _refresh_dirty_indicator(self) -> None:
        """Repaint the SCRIPT window's dirty marker (LLR-005.1 reader).

        The marker rides the SCRIPT window's border subtitle after the entry
        count: ``N entries ●`` when unsaved edits exist, ``N entries`` when
        clean. The count half is rewritten by :meth:`refresh_entries`; this
        method repaints only the marker half so the two readers (the Load
        guard and this chrome) can never disagree.
        """
        subtitle = self.query_one("#patch_win_script", Container).border_subtitle
        if subtitle is None:
            subtitle = ""
        base = subtitle.split(" ●", 1)[0]
        self.query_one("#patch_win_script", Container).border_subtitle = (
            f"{base} ●" if self._dirty else base
        )
        # batch-97 D4: the dirty trigger of the JSON stamp — the four dirty
        # writers all end here, so the stamp follows the flag at once.
        self._refresh_json_stamp()

    def show_save_prompt(self, suggestion: str) -> None:
        """Show the post-apply save-back prompt (LLR-002.7 UI half).

        Summary:
            Un-hide the save-back row and pre-fill the filename ``Input``
            with the editable ``<variant_id>-patched.s19`` suggestion.

        Args:
            suggestion (str): The pre-filled target filename suggestion.

        Dependencies:
            Used by:
                - ``S19TuiApp`` apply-action handling
        """
        self.query_one("#patch_saveback_name_input", Input).value = suggestion
        # Reset the width selector to its 32-byte default each time the prompt
        # appears, so a per-apply width choice never leaks into the next apply.
        self._saveback_width = self.SAVEBACK_WIDTHS[0]
        self.query_one("#patch_saveback_width_button", Button).label = (
            f"Width: {self._saveback_width} bytes/line"
        )
        self.query_one("#patch_saveback_row", Container).remove_class("hidden")

    def hide_save_prompt(self) -> None:
        """Hide the save-back prompt after a confirm / decline.

        Dependencies:
            Used by:
                - ``S19TuiApp.on_patch_editor_panel_save_back_decision``
        """
        self.query_one("#patch_saveback_row", Container).add_class("hidden")

    def show_before_after_prompt(self) -> None:
        """Reveal the persistent before/after-report control (US-061).

        Summary:
            Un-hide the ``#patch_before_after_row`` so the report control is
            discoverable and actionable after a successful save-back —
            persistent widget state, NOT a transient ``notify`` (LLR-061.1).
            Mirrors :meth:`show_save_prompt`'s ``.hidden``-reveal idiom.

        Dependencies:
            Used by:
                - ``S19TuiApp.on_patch_editor_panel_save_back_decision``
        """
        self.query_one("#patch_before_after_row", Container).remove_class(
            "hidden"
        )

    def hide_before_after_prompt(self) -> None:
        """Re-hide the persistent before/after-report control (US-061).

        Summary:
            Add the ``.hidden`` class back to ``#patch_before_after_row`` when
            the editing context clears (a new document load resets
            ``ChangeService.last_summary`` to ``None``, so a stale "report
            ready" offer must not persist — LLR-061.1 clear-on-context).

        Dependencies:
            Used by:
                - ``S19TuiApp.on_patch_editor_panel_action_requested``
                  (load_doc / parse_paste / refresh_doc arms)
        """
        self.query_one("#patch_before_after_row", Container).add_class("hidden")

    def _history_strip_text(
        self, enabled: bool, depths: Optional[Mapping[str, int]]
    ) -> Text:
        """Build the history strip's renderable (LLR-081.2).

        Summary:
            Compose the analyst's position in the undo/redo history — steps
            available backward and forward, the depth against the bound, and
            the keys that move it — as TWO deliberate lines:

                ``↶ 1 back  ↷ 1 fwd  2/20``
                ``ctrl+z / ctrl+y``

            When the controls are DISABLED the strip renders a single muted
            ``history off`` line and NO key hints, because the keys are inert:
            ``ctrl+z``/``ctrl+y`` route through the same ``_patch_history_
            action_allowed`` A-01 guard that disables the buttons. Printing a
            hint for a key that does nothing is a wrong answer, not chrome.

        Args:
            enabled (bool): The Undo/Redo controls' enabled state, so the strip
                and the buttons cannot disagree about whether a step exists
                (LLR-081.3). The panel is told the STATE, never the reason: it
                is a view, and "file-backed" is the caller's A-01 rationale.
            depths (Optional[Mapping[str, int]]): ``ChangeService.
                history_depths()`` — ``back`` / ``forward`` / ``bound``.
                Duck-typed so this view widget imports nothing from the service
                layer (C-7). ``None`` or a missing key reads 0, which renders
                the honest empty state.

        Returns:
            rich.text.Text: The strip's renderable. Never a ``str`` — and never
            any file-derived text: derived integers and an author-fixed
            vocabulary only (C-17).

        Data Flow:
            - Disabled → the muted ``history off`` line, nothing else.
            - Else → glyph + count per direction, ``back+forward`` against
              ``bound``, then the key-hint line.
            - Counts are rendered VALUE when non-zero and DGRAY at zero, so
              "no step that way" reads as absent rather than as a number. No
              new hue: the strip is chrome, not a verdict (GREEN/YELLOW/RED
              stay reserved for verdicts inside this panel — Inc-2b).

        Dependencies:
            Uses:
                - ``_HISTORY_HINT`` / ``_HISTORY_OFF`` ; ``insight_style``
                  ``LABEL`` / ``VALUE`` / ``DGRAY``
            Used by:
                - :meth:`set_undo_redo_enabled`

        Example:
            >>> panel = PatchEditorPanel.__new__(PatchEditorPanel)
            >>> panel._history_strip_text(
            ...     True, {"back": 1, "forward": 1, "bound": 20}
            ... ).plain
            '↶ 1 back  ↷ 1 fwd  2/20\\nctrl+z / ctrl+y'
        """
        if not enabled:
            return Text(self._HISTORY_OFF, style=DGRAY)

        counts = depths or {}
        back = int(counts.get("back", 0))
        forward = int(counts.get("forward", 0))
        bound = int(counts.get("bound", 0))

        text = Text()
        for index, (glyph, count, noun) in enumerate(
            (("↶", back, "back"), ("↷", forward, "fwd"))
        ):
            if index:
                text.append("  ", style=LABEL)
            text.append(f"{glyph} ", style=LABEL)
            text.append(str(count), style=VALUE if count else DGRAY)
            text.append(f" {noun}", style=LABEL)
        # Depth against the bound. `back + forward` is the number of snapshots
        # the history holds, which `_push_history`'s eviction caps at `bound`
        # and `undo`/`redo` conserve — so this total saturates rather than
        # growing (LLR-081.1's derivation; AT-081b's 21st-op arm).
        text.append("  ", style=LABEL)
        text.append(f"{back + forward}/{bound}", style=LABEL)
        text.append("\n", style=LABEL)
        text.append(self._HISTORY_HINT, style=DGRAY)
        return text

    def set_undo_redo_enabled(
        self, enabled: bool, depths: Optional[Mapping[str, int]] = None
    ) -> None:
        """Toggle the Undo/Redo controls + render the history strip (US-068a / LLR-081.2).

        Summary:
            Enable or disable ``#patch_undo_button`` and ``#patch_redo_button``
            together so change-set undo/redo is available ONLY for a
            paste-authored / empty document — the LLR-068a.4 data-loss guard.
            The app calls this after every action with
            ``enabled = document.source_path is None``: a file-backed document
            (``source_path is not None``) disables both controls so a
            file-backed change document can never be silently mutated or
            replaced through the history path (batch-37 ``set_edit_json_enabled``
            precedent).

            **batch-48 (LLR-081.2/.3): this is ALSO the history strip's seam**,
            deliberately — the strip answers "is a step back available?", which
            is the same question the enable state answers. Rendering both from
            ONE call means the strip and the buttons cannot disagree; a
            separate ``refresh_history`` would be a second seam that a future
            call site could forget, which is exactly the batch-38 Inc-4 F1
            stale-panel defect.

        Args:
            enabled (bool): ``True`` to enable both controls (paste-authored /
                empty document); ``False`` to disable them (file-backed).
            depths (Optional[Mapping[str, int]]): ``ChangeService.
                history_depths()`` — threaded in as a PARAMETER so the panel
                keeps importing nothing from the service layer and never
                reaches the running app (C-7 / the ``MemoryMapPanel.
                render_ranges(…, mem_map=…)`` precedent). Defaulted, so no
                existing caller breaks; ``None`` renders the empty state.

        Dependencies:
            Uses:
                - :meth:`_history_strip_text`
            Used by:
                - ``S19TuiApp`` Patch Editor action / change-file / history
                  handlers (all THREE push the depths — LLR-081.3)
        """
        self.query_one("#patch_undo_button", Button).disabled = not enabled
        self.query_one("#patch_redo_button", Button).disabled = not enabled
        self.query_one("#patch_history_strip", Static).update(
            self._history_strip_text(enabled, depths)
        )

    def _compose_action_bar(self) -> ComposeResult:
        """Compose helper: the history strip, undo/redo, execute scope, save-back and before/after rows."""
        # batch-48 (LLR-081.2): the history strip beside the
        # Undo/Redo row it describes; derived integers and
        # author-fixed key hints only (C-17).
        yield Static(
            "",
            id="patch_history_strip",
            markup=False,
            classes="patch-docked-row",
        )
        with Horizontal(
            id="patch_history_controls",
            classes="patch-docked-row patch-chip-entry",
        ):
            yield Button("Undo", id="patch_undo_button", classes="patch-chip")
            yield Button("Redo", id="patch_redo_button", classes="patch-chip")
        with Container(id="patch_execute_row", classes="patch-docked-group"):
            yield Label("Execute over variants", classes="patch-field-label")
            with Horizontal(
                id="patch_execute_buttons", classes="patch-chip-apply"
            ):
                yield Button(
                    f"Scope: {self._SCOPE_LABELS[self._execute_scope]}",
                    id="patch_execute_scope_button",
                    classes="patch-chip",
                )
                yield Button(
                    "Execute scope",
                    id="patch_execute_run_button",
                    classes="patch-chip",
                )
            # LLR-075.3: the execution scope as a readable line;
            # every update() passes a literal Text (C-17).
            yield Static(
                "",
                id="patch_scope_line",
                markup=False,
                classes="patch-stat-line",
            )
        # The save-back prompt (LLR-002.7), hidden until an
        # apply writes >= 1 entry; its label shares its input's
        # row (design §3).
        with Container(
            id="patch_saveback_row", classes="hidden patch-docked-group"
        ):
            with Horizontal(classes="pe-row"):
                yield Label("Save patched image as:", classes="pe-label")
                yield OsClipboardInput(
                    id="patch_saveback_name_input", compact=True
                )
            with Horizontal(
                id="patch_saveback_buttons", classes="patch-chip-apply"
            ):
                yield Button(
                    f"Width: {self._saveback_width} bytes/line",
                    id="patch_saveback_width_button",
                    classes="patch-chip",
                )
                yield Button(
                    "Write file",
                    id="patch_saveback_confirm_button",
                    classes="patch-chip",
                )
                yield Button(
                    "Don't save",
                    id="patch_saveback_decline_button",
                    classes="patch-chip",
                )
        # US-061: the persistent before/after-report control.
        with Container(
            id="patch_before_after_row", classes="hidden patch-docked-group"
        ):
            yield Label(
                "Before/after report available:",
                classes="patch-field-label",
            )
            with Horizontal(
                id="patch_before_after_buttons", classes="patch-chip-apply"
            ):
                yield Button(
                    "Write before/after report",
                    id="patch_before_after_button",
                    classes="patch-chip",
                )

    def _compose_doc_controls(self) -> ComposeResult:
        """Compose helper: the Validate / Apply / Save row."""
        with Horizontal(
            id="patch_doc_controls", classes="patch-docked-row patch-chip-apply"
        ):
            yield Button("Validate", id="patch_doc_validate_button", classes="patch-chip")
            yield Button(
                "Apply loaded changes", id="patch_doc_apply_button", classes="patch-chip"
            )
            # LLR-144.11: Save is the ONE filled element besides the ledger.
            yield Button(
                "Save", id="patch_doc_save_button", classes="patch-chip fill-accent"
            )
