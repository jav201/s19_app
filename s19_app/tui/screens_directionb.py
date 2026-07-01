"""Direction B screen widgets for the s19tui Textual app.

This module is the home for the Direction B "Rail + Command" view-layer
widgets and screen scaffolds introduced by batch-02-direction-b-restyle.

Increment 2 establishes the module with:
  - ``EmptyStatePanel`` — the LLR-002.3 neutral no-file-loaded panel;
  - ``ScreenScaffold`` — the neutral container scaffold for the rail screen
    slots that do not yet have rich content (Memory Map, Issues Report,
    Patch Editor, A2B Diff, Bookmarks).

Increment 9 adds the first two real scaffold contents:
  - ``MemoryMapPanel`` — a read-only coverage visualization of the loaded
    image, rendered from the existing ``LoadedFile.ranges`` and
    ``range_validity`` fields (LLR-012.1); it computes no coverage itself;
  - ``BookmarksPlaceholder`` — the neutral "coming soon" placeholder for
    the Bookmarks rail item (LLR-002.2); no persistence logic.

Increment 10 (batch-02) added the last two scaffold contents:
  - ``PatchEditorPanel`` — *(superseded by batch-03 increment 9 — see below)*;
  - ``AbDiffPanel`` — a static three-column placeholder (range list, hex A,
    hex B) filled with constant, clearly-labelled sample hex rows and a
    visible "PLACEHOLDER / diff deferred" marker (LLR-012.3).

batch-07 increment E3a consolidates the Patch Editor to the single v2 JSON
change flow (LLR-003.1), superseding the batch-03 parameter editor and the
batch-04 memory/unified halves:
  - ``PatchEditorPanel`` — one change-flow section: an entries ``DataTable``
    (kind / address / value-or-bytes / status / linkage), entry inputs for
    both v2 kinds, a Load / Validate / Apply / Save / Run-checks control
    row, the persistent declaration-fault area (LLR-002.8), the post-apply
    save-back prompt (LLR-002.7), and the check-results display
    (LLR-004.5). The widget stays presentational — it emits
    ``PatchEditorPanel.ActionRequested`` / ``SaveBackDecision`` messages
    and renders rows the app hands back; the ``changes``-package work is
    done by ``services.change_service``.

No engine code is imported here — these are presentational widgets that
receive their data via method calls and emit messages back to ``app.py``. The
Memory Map and A2B Diff panels are unchanged.
"""

from __future__ import annotations

from typing import List, Optional, Sequence, Tuple

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, ScrollableContainer
from textual.message import Message
from textual.widgets import (
    Button,
    DataTable,
    Input,
    Label,
    Select,
    Static,
    TextArea,
)

from .changes.io import DUMMY_CHANGESET_TEXT


class EmptyStatePanel(Static):
    """Neutral empty-state panel shown when a rail screen has no file loaded.

    Summary:
        Renders the LLR-002.3 no-file-loaded prompt ("no file loaded -
        Ctrl+L to load") as a single neutral static panel. It is mounted
        inside the rail screen scaffolds so activating Workspace, A2L
        Explorer, MAC View or Memory Map with no ``LoadedFile`` shows a
        prompt instead of a blank pane or an error.

    Args:
        None

    Returns:
        None

    Data Flow:
        - Static text only; reads no engine state and no ``LoadedFile``.

    Dependencies:
        Used by:
            - ``ScreenScaffold`` (the rail screen slots)

    Example:
        >>> panel = EmptyStatePanel()
        >>> panel.id
        'empty_state_panel'
    """

    PROMPT_TEXT = "No file loaded - press Ctrl+L (or 'l') to load a file."

    def __init__(self) -> None:
        super().__init__(self.PROMPT_TEXT, id="empty_state_panel", markup=False)


class ScreenScaffold(Container):
    """Neutral container scaffold for a Direction B rail screen slot.

    Summary:
        A titled, neutral container used as the real screen slot for the
        rail screens whose rich content lands in later increments (Memory
        Map, Issues Report, Patch Editor, A2B Diff, Bookmarks). It carries
        an ``EmptyStatePanel`` so an activated slot is never blank, plus a
        short title label. Increments 5-10 replace the body of these
        scaffolds with their real panes.

    Args:
        screen_id (str): The container id for this screen slot
            (e.g. ``"screen_map"``).
        title (str): Human-readable screen title shown at the top.
        hidden (bool): When True the slot carries the ``.hidden`` class so
            it is not visible until activated. Defaults to True — only the
            startup Workspace screen is composed visible.

    Returns:
        None

    Data Flow:
        - Composition only; reads no engine state.

    Dependencies:
        Uses:
            - ``EmptyStatePanel``
        Used by:
            - ``S19TuiApp.compose`` (the ``#workspace_body`` screen slots)

    Example:
        >>> scaffold = ScreenScaffold("screen_bookmarks", "Bookmarks")
        >>> scaffold.id
        'screen_bookmarks'
    """

    def __init__(self, screen_id: str, title: str, hidden: bool = True) -> None:
        classes = "db-screen hidden" if hidden else "db-screen"
        super().__init__(id=screen_id, classes=classes)
        self._title = title

    def compose(self) -> ComposeResult:
        yield Label(self._title, classes="db-screen-title")
        yield EmptyStatePanel()


class MemoryMapPanel(Static):
    """Read-only coverage visualization of the loaded image's memory ranges.

    Summary:
        Renders the firmware memory coverage of the loaded file as a textual
        map: one labelled line per contiguous range with a proportional
        coverage bar, plus the gap (uncovered) spans between consecutive
        ranges. It is a pure presentational widget — it reads the already-
        computed ``LoadedFile.ranges`` and ``LoadedFile.range_validity``
        fields handed to ``render_ranges`` and performs NO coverage,
        parsing or analysis of its own (LLR-012.1 / LLR-012.4).

    Args:
        None

    Returns:
        None

    Data Flow:
        - ``render_ranges`` receives the pre-computed ``ranges`` and
          ``range_validity`` lists from ``S19TuiApp.update_memory_map`` and
          formats them into static text; it derives gap spans by subtracting
          consecutive range bounds — arithmetic on already-parsed addresses,
          not a new coverage metric.
        - With no ranges the widget shows a neutral "no file loaded" note.

    Dependencies:
        Used by:
            - ``S19TuiApp._compose_screen_map`` (mounts the widget)
            - ``S19TuiApp.update_memory_map`` (drives ``render_ranges``)

    Example:
        >>> panel = MemoryMapPanel()
        >>> panel.render_ranges([(0x0, 0x100)], [True])
        >>> panel.id
        'memory_map_panel'
    """

    _BAR_WIDTH = 40
    _EMPTY_TEXT = "No file loaded - press Ctrl+L (or 'l') to load a file."

    def __init__(self) -> None:
        super().__init__(self._EMPTY_TEXT, id="memory_map_panel", markup=False)
        #: Last text passed to ``update`` — exposed so tests and callers can
        #: read the rendered coverage map without touching Textual internals.
        self.rendered_text: str = self._EMPTY_TEXT

    def render_ranges(
        self,
        ranges: Sequence[Tuple[int, int]],
        range_validity: Sequence[bool],
    ) -> None:
        """Render the coverage map from already-computed range data.

        Summary:
            Format the loaded file's contiguous memory ranges and the gaps
            between them into a static coverage map and display it. The
            input is consumed verbatim from the ``LoadedFile`` snapshot — no
            range is re-derived and no coverage value is computed here.

        Args:
            ranges (Sequence[Tuple[int, int]]): Contiguous ``(start, end)``
                memory ranges from ``LoadedFile.ranges`` (``end`` exclusive).
            range_validity (Sequence[bool]): Per-range validity flags from
                ``LoadedFile.range_validity``, positionally aligned with
                ``ranges``.

        Returns:
            None

        Data Flow:
            - When ``ranges`` is empty, show the neutral empty-state note.
            - Otherwise emit a summary line (range count, covered bytes),
              one line per range with a proportional fill bar and an
              OK/INVALID marker, and one line per inter-range gap.
            - The rendered text is also stored on ``rendered_text``.

        Dependencies:
            Used by:
                - ``S19TuiApp.update_memory_map``
        """
        if not ranges:
            self.rendered_text = self._EMPTY_TEXT
            self.update(self._EMPTY_TEXT)
            return

        ordered: List[Tuple[int, int, bool]] = []
        for index, (start, end) in enumerate(ranges):
            is_valid = bool(range_validity[index]) if index < len(range_validity) else True
            ordered.append((start, end, is_valid))
        ordered.sort(key=lambda item: item[0])

        span_start = ordered[0][0]
        span_end = max(end for _start, end, _valid in ordered)
        total_span = span_end - span_start
        covered = sum(end - start for start, end, _valid in ordered)

        lines: List[str] = [
            f"Memory coverage - {len(ordered)} range(s), "
            f"{covered} bytes across 0x{span_start:08X}-0x{span_end - 1:08X}",
            "",
        ]
        previous_end: Optional[int] = None
        for start, end, is_valid in ordered:
            if previous_end is not None and start > previous_end:
                gap = start - previous_end
                lines.append(
                    f"  gap                                       "
                    f" 0x{previous_end:08X}-0x{start - 1:08X} ({gap} bytes)"
                )
            size = end - start
            bar = self._coverage_bar(size, total_span)
            marker = "OK" if is_valid else "INVALID"
            lines.append(
                f"  {bar} 0x{start:08X}-0x{end - 1:08X} "
                f"({size} bytes) [{marker}]"
            )
            previous_end = end

        self.rendered_text = "\n".join(lines)
        self.update(self.rendered_text)

    def _coverage_bar(self, size: int, total_span: int) -> str:
        """Build a fixed-width fill bar proportional to a range's size.

        Summary:
            Produce a ``_BAR_WIDTH``-character bar whose filled portion is
            proportional to ``size`` over ``total_span``. This is display
            formatting only — it scales an already-known byte count, it does
            not measure or compute coverage.

        Args:
            size (int): Byte length of the range.
            total_span (int): Total span (last range end minus first range
                start) the bar is scaled against.

        Returns:
            str: A bracketed bar string, e.g. ``[####------------------]``.

        Dependencies:
            Used by:
                - ``render_ranges``
        """
        if total_span <= 0:
            filled = self._BAR_WIDTH
        else:
            filled = round(self._BAR_WIDTH * size / total_span)
            filled = max(1, min(self._BAR_WIDTH, filled))
        return "[" + "#" * filled + "-" * (self._BAR_WIDTH - filled) + "]"


class BookmarksPlaceholder(Static):
    """Neutral "coming soon" placeholder for the Bookmarks rail screen.

    Summary:
        Renders a static notice that the Bookmarks feature is not yet
        available (LLR-002.2). It holds no bookmark state and reads or
        writes no persistence — activating the Bookmarks rail item simply
        mounts this widget. Bookmark persistence is deferred to a follow-up
        batch (C-5).

    Args:
        None

    Returns:
        None

    Data Flow:
        - Static text only; reads no engine state and no ``LoadedFile``.

    Dependencies:
        Used by:
            - ``S19TuiApp._compose_screen_bookmarks``

    Example:
        >>> placeholder = BookmarksPlaceholder()
        >>> placeholder.id
        'bookmarks_placeholder'
    """

    PLACEHOLDER_TEXT = (
        "Bookmarks - coming soon.\n\n"
        "Saving and recalling memory bookmarks is not yet available. "
        "This feature is deferred to a future release."
    )

    def __init__(self) -> None:
        super().__init__(self.PLACEHOLDER_TEXT, id="bookmarks_placeholder", markup=False)


class PatchEditorPanel(ScrollableContainer):
    """Consolidated Patch Editor rail screen — the single v2 change flow.

    Summary:
        Lays out the Direction B Patch Editor as **one** change-flow section
        operating on v2 ``s19app-changeset`` JSON documents (LLR-003.1,
        batch-07 increment E3a): an entries ``DataTable`` (kind / address /
        value-or-bytes / status / linkage), address + string-value + bytes
        ``Input`` fields wired to add / edit / remove for **both** entry
        kinds, and one control row — Load / Validate / Apply / Save /
        Run checks — over a change-file path ``Input``. The batch-03
        parameter section, the ``.cdfx`` file row, and the batch-04
        selective-export control no longer exist (HLR-003 statement 2).

        Two further surfaces ride the panel:

        - **Declaration faults** (LLR-002.8) — a persistent fault listing
          plus a count line, re-rendered from the service's issue store
          after every action and cleared only by a clean re-validate or a
          clean re-load; never a transient status-line-only message.
        - **Save-back prompt** (LLR-002.7 UI half) — an inline row, hidden
          until an apply writes ≥1 entry on an S19 image, carrying an
          editable filename ``Input`` pre-filled with the
          ``<variant_id>-patched.s19`` suggestion and confirm / decline
          buttons that post a :class:`SaveBackDecision` message.
        - **Check results** (LLR-004.5) — one ``Static`` row per check
          entry coloured by its ``sev-*`` class, plus an aggregate-count
          status line.

        The panel stays **presentational**: a control press does not call
        the ``changes`` package directly — it posts an
        :class:`ActionRequested` (or :class:`SaveBackDecision`) message that
        ``app.py`` handles by calling ``services.change_service``; the
        screen then receives display rows back via the ``refresh_*``
        methods. No JSON / model logic lives in this widget (constraint
        C-7).

    Args:
        None

    Returns:
        None

    Data Flow:
        - Every control posts ``ActionRequested``; ``app.py`` routes it to
          ``ChangeService`` and calls :meth:`refresh_entries` /
          :meth:`refresh_issues` (and :meth:`refresh_check_results` after a
          check run) with the shaped results.
        - The save-back confirm / decline controls post
          ``SaveBackDecision`` — deliberately **not** an ``ActionRequested``
          action, so the routed action set stays exactly the LLR-003.2
          eight plus the single E6 extension (``execute_scope`` — nine
          total, F-A-15). The scope-cycling button is selector state only
          and posts no message.

    Dependencies:
        Used by:
            - ``S19TuiApp._compose_screen_patch`` / ``S19TuiApp`` action
              wiring

    Example:
        >>> panel = PatchEditorPanel()
        >>> panel.id
        'patch_editor_panel'
    """

    EMPTY_STATE_TEXT = (
        "No change entries yet - type an address (0x...) plus a string "
        "value or a run of hex bytes and press Add, or load a v2 "
        "change-set JSON file."
    )

    _ENTRIES_COLUMNS = ("Kind", "Address", "Value / bytes", "Status", "Linkage")

    #: The E6 execution scopes in selector cycle order (LLR-006.6) and their
    #: button labels. The scope tokens are the service vocabulary
    #: (``variant_execution_service.EXECUTION_SCOPES``) spelled locally so
    #: this view widget imports nothing from the service layer.
    EXECUTE_SCOPES = ("active", "all", "assignments")
    _SCOPE_LABELS = {
        "active": "active variant",
        "all": "all variants",
        "assignments": "per assignment",
    }

    #: The save-back S19 record widths in selector cycle order (US-015 /
    #: LLR-015.3). 32 is the default (the populated-S0 / 32-byte mode); 16 is
    #: the legacy empty-S0 / 16-byte mode. Spelled locally so this view widget
    #: imports nothing from the engine or service layer.
    SAVEBACK_WIDTHS = (32, 16)

    # Layout rules for the v2 widget ids live in styles.tcss (folded there
    # at E3b when the retired batch-03/04 ids' rules were removed).

    class ActionRequested(Message):
        """A Patch Editor control was triggered — ``app.py`` should act.

        Summary:
            Posted by the entry add / edit / remove controls and the
            document control row. The widget carries **no**
            ``changes``-package logic; this message hands the action and
            the current input-field values to ``app.py``, which calls
            ``ChangeService`` and feeds the shaped rows back via the
            panel's ``refresh_*`` methods. The routable action set is
            exactly the LLR-003.2 v2 eight at E3a (extended by
            ``execute_scope`` at E6).

        Args:
            action (str): One of ``"add_entry"`` / ``"edit_entry"`` /
                ``"remove_entry"`` / ``"load_doc"`` / ``"validate_doc"`` /
                ``"apply_doc"`` / ``"save_doc"`` / ``"run_checks"``.
            address_text (str): The entry-address input's current text.
            value_text (str): The string-value input's current text.
            bytes_text (str): The hex-bytes input's current text.
            path_text (str): The change-file path input's current text —
                used by the ``"load_doc"`` action.
            scope_text (str): The execution scope the selector currently
                shows (one of ``EXECUTE_SCOPES``) — used by the E6
                ``"execute_scope"`` action; empty default keeps the E3a
                constructions unchanged.
            paste_text (str): The paste ``TextArea``'s current text — used
                by the batch-13 ``"parse_paste"`` action (LLR-014.2); empty
                default keeps the prior constructions unchanged.

        Dependencies:
            Used by:
                - ``S19TuiApp.on_patch_editor_panel_action_requested``
        """

        def __init__(
            self,
            action: str,
            address_text: str = "",
            value_text: str = "",
            bytes_text: str = "",
            path_text: str = "",
            scope_text: str = "",
            paste_text: str = "",
        ) -> None:
            super().__init__()
            self.action = action
            self.address_text = address_text
            self.value_text = value_text
            self.bytes_text = bytes_text
            self.path_text = path_text
            self.scope_text = scope_text
            self.paste_text = paste_text

    class SaveBackDecision(Message):
        """The operator answered the post-apply save prompt (LLR-002.7).

        Summary:
            Posted by the save-back confirm / decline buttons. Deliberately
            a separate message class — not an ``ActionRequested`` action —
            so the LLR-003.2 routed action set stays exactly eight at E3a.

        Args:
            filename (Optional[str]): The (possibly edited) target filename
                when the operator confirmed; ``None`` when declined — the
                app persists nothing and ``ChangeSummary.saved_path`` stays
                ``None``.
            bytes_per_line (int): The data-bytes-per-S19-record width the
                operator selected (``{16, 32}``, default 32) — carried only on
                a confirm so ``app.py`` can thread it (and the matching S0
                policy) into ``ChangeService.save_patched`` (US-015 / LLR-015.3).

        Dependencies:
            Used by:
                - ``S19TuiApp.on_patch_editor_panel_save_back_decision``
        """

        def __init__(
            self, filename: Optional[str], bytes_per_line: int = 32
        ) -> None:
            super().__init__()
            self.filename = filename
            self.bytes_per_line = bytes_per_line

    class ChangeFileSelected(Message):
        """The operator picked a change file from the patches dropdown (US-026).

        Summary:
            Posted when ``#patch_doc_file_select`` fires ``Select.Changed`` with
            a concrete filename (not the blank sentinel). Carries the bare
            filename only — the panel owns no ``changes``-package logic and no
            path resolution; ``app.py`` re-resolves the name under the patches
            folder (with the LLR-030.3 containment guard) and routes it through
            the existing ``ChangeService.load`` path. Blank / cleared selections
            post nothing (a blank is not a load request).

        Args:
            filename (str): The chosen change-file's bare component
                (``match.name``), e.g. ``"changes.json"``.

        Dependencies:
            Used by:
                - ``S19TuiApp.on_patch_editor_panel_change_file_selected``
        """

        def __init__(self, filename: str) -> None:
            super().__init__()
            self.filename = filename

    def __init__(self) -> None:
        super().__init__(id="patch_editor_panel")
        #: The execution scope the selector currently shows (LLR-006.6) —
        #: cycled by ``#patch_execute_scope_button``; carried on the
        #: ``execute_scope`` ``ActionRequested``.
        self._execute_scope: str = self.EXECUTE_SCOPES[0]
        #: The save-back S19 record width the selector currently shows
        #: (US-015 / LLR-015.3) — cycled by ``#patch_saveback_width_button``;
        #: carried on the ``SaveBackDecision``. Defaults to 32.
        self._saveback_width: int = self.SAVEBACK_WIDTHS[0]

    def set_change_files(self, names: Sequence[str]) -> None:
        """Populate the change-file dropdown with the patches-folder files.

        Summary:
            Replace the ``#patch_doc_file_select`` options with one blank-prompt
            entry per change-file name (LLR-030.2), so the operator can pick a
            file instead of typing its path. Called by ``app.py`` on patch-screen
            activation and after each save (LLR-030.3 / R2). This is the ONLY
            populator of the dropdown; a panel never handed a scan keeps its
            empty (blank-prompt) option set — the bare-construction invariant
            (W2). An empty ``names`` clears every option, leaving the blank
            state (``allow_blank=True``), so an empty patches folder renders a
            valid placeholder dropdown without crashing (AT-030b / W1).

        Args:
            names (Sequence[str]): Bare change-file component names (``*.json``)
                discovered under ``workarea/patches/``, already sorted
                deterministically by the caller. The option value equals the
                name, so the ``Select.Changed`` handler forwards it verbatim.

        Returns:
            None

        Data Flow:
            - Map each name to a ``(name, name)`` option pair and hand them to
              the ``Select`` via ``set_options``; an empty list clears the
              options, and Textual falls back to the blank prompt.

        Dependencies:
            Uses:
                - ``textual.widgets.Select.set_options``
            Used by:
                - ``S19TuiApp._prefill_patch_change_files``

        Example:
            >>> panel.set_change_files(["changes.json", "changes-1.json"])
        """
        options = [(name, name) for name in names]
        self.query_one("#patch_doc_file_select", Select).set_options(options)

    def compose(self) -> ComposeResult:
        """Lay out the consolidated v2 Patch Editor widget tree.

        Summary:
            Yield the single change-flow section (LLR-003.1): the entries
            ``DataTable`` and its empty-state line, the address / value /
            bytes input row with add / edit / remove buttons, the
            change-file path ``Input`` with the Load / Validate / Apply /
            Save / Run-checks control row, the persistent declaration-fault
            area (count line + listing, LLR-002.8), the hidden save-back
            prompt row (LLR-002.7), and the check-results area
            (LLR-004.5). The panel is a :class:`ScrollableContainer`, so the
            stacked content scrolls vertically when it exceeds the terminal
            height.

        Args:
            None

        Returns:
            ComposeResult: The Patch Editor widget tree.

        Dependencies:
            Used by:
                - Textual ``ScrollableContainer`` compose lifecycle
        """
        yield Label(
            "Change document (v2 JSON)", classes="patch-section-title"
        )
        yield DataTable(
            id="patch_doc_entries_table",
            zebra_stripes=True,
            cursor_type="row",
        )
        yield Static(
            self.EMPTY_STATE_TEXT,
            id="patch_doc_empty_state",
            markup=False,
        )
        yield Container(
            Label("Address", classes="patch-field-label"),
            Input(placeholder="0x100", id="patch_entry_address_input"),
            Label("String value", classes="patch-field-label"),
            Input(
                placeholder="text (document encoding)",
                id="patch_entry_value_input",
            ),
            Label("Bytes", classes="patch-field-label"),
            Input(placeholder="DE AD BE EF", id="patch_entry_bytes_input"),
            Horizontal(
                Button("Add", id="patch_entry_add_button"),
                Button("Edit", id="patch_entry_edit_button"),
                Button("Remove", id="patch_entry_remove_button"),
                id="patch_doc_entry_buttons",
            ),
            id="patch_doc_entry_inputs",
        )
        yield Container(
            Label("Change file", classes="patch-field-label"),
            Select(
                [],
                id="patch_doc_file_select",
                prompt="Change files in patches/",
                allow_blank=True,
            ),
            Input(
                placeholder="path to v2 change-set .json",
                id="patch_doc_path_input",
            ),
            Horizontal(
                Button("Load", id="patch_doc_load_button"),
                Button("Validate", id="patch_doc_validate_button"),
                Button("Apply", id="patch_doc_apply_button"),
                Button("Save", id="patch_doc_save_button"),
                Button("Run checks", id="patch_checks_run_button"),
                id="patch_doc_controls",
            ),
            Label(
                "Checks: runs the loaded change document's checks against "
                "the loaded image.",
                id="patch_checks_help",
                classes="patch-field-label",
            ),
            id="patch_doc_file_row",
        )
        yield Container(
            Label(
                "Paste change-set (v2 JSON)", classes="patch-field-label"
            ),
            TextArea(DUMMY_CHANGESET_TEXT, id="patch_paste_text"),
            Horizontal(
                Button("Parse pasted", id="patch_paste_parse_button"),
                id="patch_paste_controls",
            ),
            id="patch_paste_row",
        )
        yield Label("", id="patch_doc_issue_count", classes="patch-field-label")
        yield Static("", id="patch_doc_issues", markup=False, classes="hidden")
        yield Container(
            Label("Save patched image as:", classes="patch-field-label"),
            Input(id="patch_saveback_name_input"),
            Horizontal(
                Button(
                    f"Width: {self._saveback_width} bytes/line",
                    id="patch_saveback_width_button",
                ),
                Button("Write file", id="patch_saveback_confirm_button"),
                Button("Don't save", id="patch_saveback_decline_button"),
                id="patch_saveback_buttons",
            ),
            id="patch_saveback_row",
            classes="hidden",
        )
        yield Container(
            Label("Execute over variants", classes="patch-field-label"),
            Horizontal(
                Button(
                    f"Scope: {self._SCOPE_LABELS[self._execute_scope]}",
                    id="patch_execute_scope_button",
                ),
                Button("Execute scope", id="patch_execute_run_button"),
                id="patch_execute_buttons",
            ),
            id="patch_execute_row",
        )
        yield Label("", id="patch_checks_status", classes="patch-field-label")
        yield Container(id="patch_checks_results")

    def on_mount(self) -> None:
        """Initialise the entries table columns and the empty state.

        Summary:
            Add the entries ``DataTable`` columns once the widget is
            mounted and show the empty-state line for the initially-empty
            document.

        Dependencies:
            Used by:
                - Textual mount lifecycle
        """
        table = self.query_one("#patch_doc_entries_table", DataTable)
        table.add_columns(*self._ENTRIES_COLUMNS)
        self.refresh_entries([])

    def request_action(self, action: str) -> None:
        """Post an :class:`ActionRequested` message for ``action``.

        Summary:
            Read the entry and path input fields and post an
            ``ActionRequested`` message so ``app.py`` can call
            ``ChangeService``. The widget itself performs no
            ``changes``-package work — it only forwards the request.

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
            return
        actions = {
            "patch_entry_add_button": "add_entry",
            "patch_entry_edit_button": "edit_entry",
            "patch_entry_remove_button": "remove_entry",
            "patch_doc_load_button": "load_doc",
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

    def on_select_changed(self, event: Select.Changed) -> None:
        """Forward a change-file dropdown pick to ``app.py`` (US-026).

        Summary:
            When ``#patch_doc_file_select`` changes to a concrete filename,
            post a :class:`ChangeFileSelected` carrying the bare name so the app
            re-resolves it under the patches folder (with the LLR-030.3
            containment guard) and loads it via the existing
            ``ChangeService.load`` path. A blank selection (``Select.BLANK`` —
            the placeholder state after ``set_change_files([])`` or a cleared
            option set) is NOT a load request, so nothing is posted. Only this
            panel's own ``#patch_doc_file_select`` is handled; other ``Select``
            widgets are left for their own handlers.

        Args:
            event (Select.Changed): The Textual select-change event; its
                ``select.id`` and ``value`` identify the widget and choice.

        Returns:
            None

        Data Flow:
            - Ignore events from other selects and the blank sentinel, else
              post ``ChangeFileSelected(str(value))``.

        Dependencies:
            Uses:
                - ``ChangeFileSelected``
            Used by:
                - Textual select-change dispatch
        """
        if event.select.id != "patch_doc_file_select":
            return
        if event.value is Select.BLANK:
            return
        event.stop()
        self.post_message(self.ChangeFileSelected(str(event.value)))

    def refresh_entries(self, rows: Sequence[object]) -> None:
        """Repopulate the entries table from shaped display rows.

        Summary:
            Replace every ``DataTable`` row with the supplied
            ``ChangeEntryRow`` list (kind, address, value-or-bytes, status,
            linkage). When the list is empty, show the neutral empty-state
            line and hide the table; otherwise hide the empty-state line
            and show the table (LLR-003.1).

        Args:
            rows (Sequence[object]): The ``ChangeEntryRow`` objects produced
                by ``ChangeService.rows`` — each exposes ``kind_text``,
                ``address_text``, ``value_text``, ``status_text`` and
                ``linkage_text``. Typed as ``object`` so this view widget
                imports nothing from the service layer.

        Data Flow:
            - Clear and refill the table from the row list.
            - Toggle the ``.hidden`` class on the table and the empty-state
              line by whether the list is empty.

        Dependencies:
            Used by:
                - ``S19TuiApp`` Patch Editor action handler
        """
        table = self.query_one("#patch_doc_entries_table", DataTable)
        empty_state = self.query_one("#patch_doc_empty_state", Static)
        table.clear()
        for row in rows:
            table.add_row(
                row.kind_text,
                row.address_text,
                row.value_text,
                row.status_text,
                row.linkage_text,
            )
        if rows:
            table.remove_class("hidden")
            empty_state.add_class("hidden")
        else:
            table.add_class("hidden")
            empty_state.remove_class("hidden")

    def refresh_issues(self, lines: Sequence[str]) -> None:
        """Render the persistent declaration-fault area (LLR-002.8).

        Summary:
            Show one line per declaration fault plus a count line. The
            rendering persists across unrelated UI actions because it is
            widget state, not a transient status message — it changes only
            when this method is called again with a different issue list
            (a clean re-validate or re-load clears it with an empty list).

        Args:
            lines (Sequence[str]): The ``ChangeService.issue_lines`` output
                — ``[CODE] severity: message`` per fault; empty when the
                document is clean.

        Data Flow:
            - Non-empty → count label ``Declaration faults: N`` and the
              joined listing, listing un-hidden.
            - Empty → blank count label, listing cleared and hidden.

        Dependencies:
            Used by:
                - ``S19TuiApp`` Patch Editor action handler
        """
        count_label = self.query_one("#patch_doc_issue_count", Label)
        listing = self.query_one("#patch_doc_issues", Static)
        if lines:
            count_label.update(f"Declaration faults: {len(lines)}")
            listing.update("\n".join(lines))
            listing.remove_class("hidden")
        else:
            count_label.update("")
            listing.update("")
            listing.add_class("hidden")

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

    def refresh_check_results(
        self, rows: Sequence[object], status_line: str
    ) -> None:
        """Render the check-run display (LLR-004.5).

        Summary:
            Replace the check-results area with one ``Static`` per result
            row, each carrying its ``sev-*`` class (the
            ``css_class_for_severity`` colour the service shaped), and set
            the aggregate-count status line.

        Args:
            rows (Sequence[object]): The ``ChangeService.check_rows``
                output — each exposes ``text`` and ``css_class``. Typed as
                ``object`` so this view widget imports nothing from the
                service layer.
            status_line (str): The three-aggregate-count line (``Checks: P
                passed, F failed, U uncheckable``) or the pending-seam
                message.

        Data Flow:
            - Update the status label, remove prior result children, mount
              one classed ``Static`` per row.

        Dependencies:
            Used by:
                - ``S19TuiApp`` run-checks action handling
        """
        self.query_one("#patch_checks_status", Label).update(status_line)
        container = self.query_one("#patch_checks_results", Container)
        container.remove_children()
        for row in rows:
            container.mount(Static(row.text, classes=row.css_class, markup=False))


class AbDiffPanel(Container):
    """Inline A↔B image-diff panel for the A2B Firmware Diff screen.

    Summary:
        Completes the Direction B A2B Diff surface (HLR-005): an INLINE
        image-pair selection row (G-6 — not a modal), a status line, and a
        three-column result area (run list + bounded hex windows of image A
        and image B). The panel is presentational only: it emits
        :class:`CompareRequested` / :class:`ReportRequested` messages and
        renders the :class:`ComparisonResult` the app hands back via
        :meth:`render_comparison`. It computes no run classification, no
        coverage count, and no report content itself — every comparison goes
        through ``compare_service`` and every report through
        ``diff_report_service`` (LLR-005.1). The static placeholder constants
        are gone (LLR-005.2).

        The selection row prefills two ``Select`` dropdowns from the active
        project's ``ProjectVariantSet`` (set via :meth:`set_variants`), plus
        two ``Input``s for external file paths, a Compare button, a no-project
        destination ``Input`` and a Report button.

    Args:
        None

    Returns:
        None

    Data Flow:
        - Operator picks sources -> Compare button -> :class:`CompareRequested`
          -> ``app.py`` calls ``compare_service.compare_images`` and feeds the
          result back via :meth:`render_comparison` (or :meth:`set_status` on
          refusal, LLR-005.3).
        - Operator picks a run in the range list -> the selected run's hex
          windows render in the A / B columns (LLR-005.2).
        - Report button -> :class:`ReportRequested` -> ``app.py`` calls the
          diff-report generators and surfaces the written path(s) or the
          refusal diagnostic via :meth:`set_status` (LLR-005.4).

    Dependencies:
        Uses:
            - ``hexview.render_hex_view`` (plain hex window renderer)
        Used by:
            - ``S19TuiApp._compose_screen_diff``
            - ``S19TuiApp.on_ab_diff_panel_compare_requested``
            - ``S19TuiApp.on_ab_diff_panel_report_requested``

    Example:
        >>> panel = AbDiffPanel()
        >>> panel.id
        'ab_diff_panel'
    """

    #: Relocated DISPLAY caps (G-9 / LLR-005.2). These bound only what the
    #: PANEL renders — never the persisted report files (which stay complete,
    #: I3). They mirror the batch-07 report caps
    #: (``report_service.REPORT_MAX_REGIONS_PER_VARIANT`` = 128,
    #: ``report_service.REPORT_MAX_TOTAL_BYTES`` = 2_097_152).
    DISPLAY_MAX_RUNS = 128
    DISPLAY_MAX_TOTAL_BYTES = 2_097_152

    #: Per-run hex-window context (± bytes) for the on-screen windows.
    DISPLAY_CONTEXT_BYTES = 16

    #: Rich colour per diff classification token (the panel's colour cue,
    #: LLR-005.2). ``changed`` / ``only_a`` / ``only_b`` are visually distinct.
    _KIND_MARKUP = {
        "changed": "#d9a35b",  # amber  — present in both, byte differs
        "only_a": "#e06c75",   # red    — mapped in A only
        "only_b": "#4ec9d4",   # cyan   — mapped in B only
    }

    _KIND_LABEL = {
        "changed": "changed",
        "only_a": "only A",
        "only_b": "only B",
    }

    #: ``Select`` sentinel for "use the external-path input instead".
    _EXTERNAL_OPTION = "__external__"

    class CompareRequested(Message):
        """The operator asked to compare two images (LLR-005.1).

        Summary:
            Posted by the Compare button. Carries the raw selection for each
            side — the chosen variant id (or the external sentinel) and the
            external-path input text — leaving all resolution, parsing and
            classification to ``app.py`` + ``compare_service`` (the panel
            performs none).

        Args:
            variant_a (Optional[str]): The variant id chosen for image A, or
                ``None`` when the external path is to be used.
            path_a (str): The external-path input text for image A.
            variant_b (Optional[str]): The variant id chosen for image B, or
                ``None`` when the external path is to be used.
            path_b (str): The external-path input text for image B.

        Dependencies:
            Used by:
                - ``S19TuiApp.on_ab_diff_panel_compare_requested``
        """

        def __init__(
            self,
            variant_a: Optional[str],
            path_a: str,
            variant_b: Optional[str],
            path_b: str,
        ) -> None:
            super().__init__()
            self.variant_a = variant_a
            self.path_a = path_a
            self.variant_b = variant_b
            self.path_b = path_b

    class ReportRequested(Message):
        """The operator asked to generate the diff report (LLR-005.4).

        Summary:
            Posted by the Report button. Carries the operator-typed
            destination directory (the no-project branch, G-8); ``app.py``
            ignores it when a project is active. The panel computes no report
            content — generation is routed through ``diff_report_service``.

        Args:
            dest_input (str): The operator-supplied destination directory text
                for the no-project case; empty when a project is active.

        Dependencies:
            Used by:
                - ``S19TuiApp.on_ab_diff_panel_report_requested``
        """

        def __init__(self, dest_input: str) -> None:
            super().__init__()
            self.dest_input = dest_input

    def __init__(self) -> None:
        super().__init__(id="ab_diff_panel")
        #: The most recent comparison runs (display-capped) the operator can
        #: select between; rendered into ``#diff_range_list``.
        self._runs: List[Tuple[int, int, str]] = []
        #: The two memory maps of the most recent comparison, for the per-run
        #: hex windows. Display-only — never the source of any classification.
        self._mem_map_a: dict = {}
        self._mem_map_b: dict = {}
        #: Whether a comparison result has been rendered (the report guard).
        self._has_result: bool = False

    def compose(self) -> ComposeResult:
        """Lay out the inline selection row, status line and result columns.

        Summary:
            Yield the inline image-pair selection row (two variant ``Select``
            dropdowns + two external-path ``Input``s + Compare/Report buttons
            + a no-project destination ``Input``), a status ``Static``, and the
            three result columns (``#diff_range_list`` / ``#diff_hex_a`` /
            ``#diff_hex_b``) reused from the placeholder. No placeholder
            constants are composed (LLR-005.2).

        Args:
            None

        Returns:
            ComposeResult: The A2B Diff panel widget tree.

        Dependencies:
            Used by:
                - Textual ``Container`` compose lifecycle
        """
        empty: List[Tuple[str, str]] = [("(external path below)", self._EXTERNAL_OPTION)]
        yield Horizontal(
            Label("A:", classes="diff-field-label"),
            Select(empty, id="diff_select_a", allow_blank=False),
            Input(placeholder="external path A", id="diff_path_a"),
            id="diff_select_row_a",
        )
        yield Horizontal(
            Label("B:", classes="diff-field-label"),
            Select(empty, id="diff_select_b", allow_blank=False),
            Input(placeholder="external path B", id="diff_path_b"),
            id="diff_select_row_b",
        )
        yield Horizontal(
            Button("Compare", id="diff_compare_button"),
            Button("Report", id="diff_report_button"),
            Input(
                placeholder="report destination dir (no-project only)",
                id="diff_report_dest",
            ),
            id="diff_action_row",
        )
        yield Static(
            "Select two images and press Compare.",
            id="diff_status",
            classes="sev-info",
            markup=False,
        )
        yield Horizontal(
            Static("Runs", id="diff_range_list", markup=True),
            Static("Image A", id="diff_hex_a", markup=False),
            Static("Image B", id="diff_hex_b", markup=False),
            id="diff_columns",
        )

    def set_variants(self, variants: Sequence[Tuple[str, str]]) -> None:
        """Prefill the A / B variant ``Select`` dropdowns (LLR-005.1).

        Summary:
            Replace both dropdowns' options with the active project's variants
            plus the trailing "external path" sentinel, so the operator can
            pick an in-project variant or fall through to the external-path
            input. Called by ``app.py`` when the diff screen activates.

        Args:
            variants (Sequence[Tuple[str, str]]): ``(label, variant_id)`` pairs
                from the active ``ProjectVariantSet``; empty when no project is
                active.

        Dependencies:
            Used by:
                - ``S19TuiApp.action_show_screen`` (diff activation)
        """
        options = list(variants) + [
            ("(external path below)", self._EXTERNAL_OPTION)
        ]
        for select_id in ("#diff_select_a", "#diff_select_b"):
            select = self.query_one(select_id, Select)
            select.set_options(options)
            select.value = options[0][1]

    def set_status(self, message: str, css_class: str = "sev-info") -> None:
        """Render a full (untruncated) status line in the panel (LLR-005.3/4).

        Summary:
            Update the panel's own ``#diff_status`` line with ``message`` and
            its severity class. This is the panel's status surface — distinct
            from the app's 50-char rolling log — so full report destination
            path(s) and refusal diagnostics are shown in full (LLR-005.4).

        Args:
            message (str): The status / diagnostic text.
            css_class (str): One of the ``sev-*`` colour classes.

        Dependencies:
            Used by:
                - ``S19TuiApp.on_ab_diff_panel_compare_requested``
                - ``S19TuiApp.on_ab_diff_panel_report_requested``
        """
        status = self.query_one("#diff_status", Static)
        status.set_classes(css_class)
        status.update(message)

    def _selected_variant(self, select_id: str) -> Optional[str]:
        """Return the chosen variant id, or ``None`` for the external option."""
        value = self.query_one(select_id, Select).value
        if value in (self._EXTERNAL_OPTION, Select.BLANK):
            return None
        return str(value)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Translate the Compare / Report button presses into messages.

        Summary:
            Compare -> :class:`CompareRequested` with the raw selection;
            Report -> :class:`ReportRequested` with the destination input. The
            panel performs no comparison or report work itself (LLR-005.1).
            Stops the event so it does not also reach the app-level handler.

        Args:
            event (Button.Pressed): The Textual button-press event.

        Dependencies:
            Uses:
                - ``CompareRequested`` / ``ReportRequested``
            Used by:
                - Textual button-press dispatch
        """
        button_id = event.button.id or ""
        if button_id == "diff_compare_button":
            event.stop()
            self.post_message(
                self.CompareRequested(
                    variant_a=self._selected_variant("#diff_select_a"),
                    path_a=self.query_one("#diff_path_a", Input).value,
                    variant_b=self._selected_variant("#diff_select_b"),
                    path_b=self.query_one("#diff_path_b", Input).value,
                )
            )
        elif button_id == "diff_report_button":
            event.stop()
            self.post_message(
                self.ReportRequested(
                    self.query_one("#diff_report_dest", Input).value
                )
            )

    def render_comparison(
        self,
        runs: Sequence[Tuple[int, int, str]],
        mem_map_a: dict,
        mem_map_b: dict,
        summary_a: str,
        summary_b: str,
    ) -> None:
        """Render a completed comparison into the three columns (LLR-005.2).

        Summary:
            Replace the result columns with the real comparison output: the
            classified run list (Rich-coloured per kind, with the per-image
            artifact-usage summaries), then the hex windows of the FIRST run
            for image A and image B. The on-screen run list is bounded by the
            relocated display caps (:attr:`DISPLAY_MAX_RUNS` /
            :attr:`DISPLAY_MAX_TOTAL_BYTES`, G-9) — the persisted report files
            stay complete. The static placeholder is never shown again.

        Args:
            runs (Sequence[Tuple[int, int, str]]): ``(start, end, kind)`` for
                every run of the comparison (already engine-ordered).
            mem_map_a (dict): Image A's memory map (hex-window source only).
            mem_map_b (dict): Image B's memory map.
            summary_a (str): Image A's ``both``/``one``/``none`` usage summary.
            summary_b (str): Image B's usage summary.

        Data Flow:
            - Apply the run-count + byte-budget display caps, store the capped
              runs + maps, render the range list, then the first run's windows.

        Dependencies:
            Uses:
                - ``_render_run_list`` / ``_render_run_windows``
            Used by:
                - ``S19TuiApp.on_ab_diff_panel_compare_requested``
        """
        capped = self._apply_display_caps(runs)
        self._runs = capped
        self._mem_map_a = mem_map_a
        self._mem_map_b = mem_map_b
        self._has_result = True
        self._render_run_list(len(runs), summary_a, summary_b)
        if capped:
            self._render_run_windows(0)
        else:
            self.query_one("#diff_hex_a", Static).update("Image A — no differing runs")
            self.query_one("#diff_hex_b", Static).update("Image B — no differing runs")

    def _apply_display_caps(
        self, runs: Sequence[Tuple[int, int, str]]
    ) -> List[Tuple[int, int, str]]:
        """Bound the on-screen run list by the relocated display caps (G-9).

        Summary:
            Keep at most :attr:`DISPLAY_MAX_RUNS` runs and stop once the
            accumulated run bytes would exceed :attr:`DISPLAY_MAX_TOTAL_BYTES`.
            This bounds only what the PANEL renders — the persisted report
            (I3) is complete and untouched.

        Args:
            runs (Sequence[Tuple[int, int, str]]): All runs of the comparison.

        Returns:
            List[Tuple[int, int, str]]: The display-capped prefix.

        Dependencies:
            Used by:
                - ``render_comparison``
        """
        capped: List[Tuple[int, int, str]] = []
        total = 0
        for start, end, kind in runs:
            if len(capped) >= self.DISPLAY_MAX_RUNS:
                break
            total += end - start
            if total > self.DISPLAY_MAX_TOTAL_BYTES and capped:
                break
            capped.append((start, end, kind))
        return capped

    def _render_run_list(
        self, total_runs: int, summary_a: str, summary_b: str
    ) -> None:
        """Render the Rich-coloured run list + artifact-usage notes.

        Summary:
            Build the range-list column: a header carrying the per-image
            ``both``/``one``/``none`` artifact-usage summaries, then one
            coloured line per displayed run, then a "showing N of M" line when
            the display caps elided runs (G-9).

        Args:
            total_runs (int): The complete run count before display capping.
            summary_a (str): Image A's usage summary.
            summary_b (str): Image B's usage summary.

        Dependencies:
            Uses:
                - ``_KIND_MARKUP`` / ``_KIND_LABEL``
            Used by:
                - ``render_comparison``
        """
        from rich.markup import escape

        lines = [
            f"Runs: {total_runs}",
            f"A artifacts: {escape(summary_a)}",
            f"B artifacts: {escape(summary_b)}",
            "",
        ]
        for index, (start, end, kind) in enumerate(self._runs):
            colour = self._KIND_MARKUP.get(kind, "#ffffff")
            label = self._KIND_LABEL.get(kind, kind)
            lines.append(
                f"[{colour}]{index:>3} 0x{start:08X}-0x{end:08X} "
                f"{label}[/]"
            )
        if len(self._runs) < total_runs:
            lines.append("")
            lines.append(
                f"[#6b7280](showing {len(self._runs)} of {total_runs} runs — "
                f"full report is complete)[/]"
            )
        self.query_one("#diff_range_list", Static).update("\n".join(lines))

    def _render_run_windows(self, run_index: int) -> None:
        """Render the selected run's bounded hex windows for A and B.

        Summary:
            Render image A's and image B's hex+ASCII windows around the
            selected run, each window respecting the ``hexview`` row caps
            (``MAX_HEX_ROWS``). The window spans the run ± a small context.

        Args:
            run_index (int): Index into :attr:`_runs` of the run to window.

        Dependencies:
            Uses:
                - ``hexview.render_hex_view``
            Used by:
                - ``render_comparison``
                - ``on_data_table_row_selected`` (run selection)
        """
        from .hexview import HEX_WIDTH, MAX_HEX_ROWS, render_hex_view

        if not (0 <= run_index < len(self._runs)):
            return
        start, end, _kind = self._runs[run_index]
        low = max(0, start - self.DISPLAY_CONTEXT_BYTES)
        low -= low % HEX_WIDTH
        high = end + self.DISPLAY_CONTEXT_BYTES
        row_bases = list(range(low, high, HEX_WIDTH))
        text_a = render_hex_view(self._mem_map_a, row_bases=row_bases, max_rows=MAX_HEX_ROWS)
        text_b = render_hex_view(self._mem_map_b, row_bases=row_bases, max_rows=MAX_HEX_ROWS)
        header = f"Run #{run_index} 0x{start:08X}-0x{end:08X}"
        self.query_one("#diff_hex_a", Static).update(f"Image A — {header}\n{text_a}")
        self.query_one("#diff_hex_b", Static).update(f"Image B — {header}\n{text_b}")

    def has_comparison(self) -> bool:
        """Return whether a comparison result is currently rendered (LLR-005.4).

        Summary:
            ``app.py`` guards the Report trigger on this so a report request
            with no completed comparison is one status message, not a crash.

        Returns:
            bool: ``True`` once :meth:`render_comparison` has stored runs/maps.

        Dependencies:
            Used by:
                - ``S19TuiApp.on_ab_diff_panel_report_requested``
        """
        return self._has_result

    @property
    def mem_map_a(self) -> dict:
        """Image A's memory map from the last comparison (report input)."""
        return self._mem_map_a

    @property
    def mem_map_b(self) -> dict:
        """Image B's memory map from the last comparison (report input)."""
        return self._mem_map_b
