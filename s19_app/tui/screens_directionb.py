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

batch-03 increment 9 makes the Patch Editor functional, replacing the inert
``PatchEditorPanel`` shell:
  - ``PatchEditorPanel`` — a functional Patch Editor: a change-list
    ``DataTable``, name / index / value ``Input``s wired to add / edit /
    remove, save / load action ``Button``s and a path ``Input``, and a
    neutral empty-state line (LLR-007.1..007.6). The widget stays
    presentational — it emits ``PatchEditorPanel.ActionRequested`` messages and
    renders rows the screen hands back; the ``cdfx``-package work (build /
    resolve / format / write / read) is done by ``services.cdfx_service``.

No engine code is imported here — these are presentational widgets that
receive their data via method calls and emit messages back to ``app.py``. The
Memory Map and A2B Diff panels are unchanged.
"""

from __future__ import annotations

from typing import List, Optional, Sequence, Tuple

from textual.app import ComposeResult
from textual.containers import Container, Horizontal
from textual.message import Message
from textual.widgets import Button, DataTable, Input, Label, Static


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


class PatchEditorPanel(Container):
    """Functional Patch Editor rail screen — parameter + memory change build.

    Summary:
        Lays out the Direction B Patch Editor as a working tool. Batch-03
        increment 9 made it functional for **parameter** changes — a
        change-list ``DataTable``, name / index / value inputs wired to
        add / edit / remove, and ``.cdfx`` save / load. Batch-04 increment 8
        extends it with the **memory-field** change kind: a second
        ``DataTable`` (one row per memory change — address, hex value, status),
        memory-address / new-bytes ``Input`` fields wired to add / edit /
        remove, and unified-file save / load plus a selective-export action —
        all alongside the batch-03 parameter controls without removing them
        (LLR-009.1..009.3).

        The panel stays **presentational**: a control press does not call the
        ``cdfx`` package directly — it posts a :class:`PatchEditorPanel.
        ActionRequested` message that ``app.py`` handles by calling
        ``services.cdfx_service``. The screen then hands resolved display rows
        back via :meth:`refresh_rows` / :meth:`refresh_memory_rows`. No XML /
        JSON / model logic lives in this widget (constraint C-7 / LLR-009.2).

    Args:
        None

    Returns:
        None

    Data Flow:
        - The parameter and memory add / edit / remove controls, the ``.cdfx``
          save / load controls and the unified save / load / export controls
          each post an ``ActionRequested`` message; ``app.py`` routes it to
          ``CdfxService`` and calls :meth:`refresh_rows` /
          :meth:`refresh_memory_rows` with the result.
        - :meth:`refresh_rows` fills the parameter ``DataTable`` from the
          ``PatchRow`` list; :meth:`refresh_memory_rows` fills the memory
          ``DataTable`` from the ``MemoryPatchRow`` list. Each shows its own
          empty-state line when its half is empty.

    Dependencies:
        Used by:
            - ``S19TuiApp._compose_screen_patch`` / ``S19TuiApp`` action wiring

    Example:
        >>> panel = PatchEditorPanel()
        >>> panel.id
        'patch_editor_panel'
    """

    EMPTY_STATE_TEXT = (
        "No change-list entries yet - type a parameter name, an optional "
        "array index and a value then press Add, or load a .cdfx file."
    )

    MEMORY_EMPTY_STATE_TEXT = (
        "No memory changes yet - type a memory address (0x...) and a run of "
        "new bytes then press Add Mem, or load a unified change-set file."
    )

    _TABLE_COLUMNS = ("Parameter", "Index", "Value", "Status")

    _MEMORY_TABLE_COLUMNS = ("Address", "New bytes (hex)", "Status")

    class ActionRequested(Message):
        """A Patch Editor control was triggered — ``app.py`` should act.

        Summary:
            Posted by a parameter or memory add / edit / remove control, a
            ``.cdfx`` save / load control, or a unified save / load / export
            control. The widget carries **no** ``cdfx``-package logic; this
            message hands the action and the current input-field values to
            ``app.py``, which calls ``CdfxService`` and feeds the result back
            via :meth:`PatchEditorPanel.refresh_rows` /
            :meth:`refresh_memory_rows`.

        Args:
            action (str): One of the parameter actions ``"add"`` / ``"edit"`` /
                ``"remove"`` / ``"save"`` / ``"load"``, the memory actions
                ``"add_memory"`` / ``"edit_memory"`` / ``"remove_memory"``, or
                the unified actions ``"save_unified"`` / ``"load_unified"`` /
                ``"export"``.
            parameter_name (str): The parameter-name input's current text.
            index_text (str): The array-index input's current text — blank
                for a scalar / string entry.
            value_text (str): The value input's current text.
            path_text (str): The ``.cdfx`` path input's current text — used by
                the ``"load"`` action.
            address_text (str): The memory-address input's current text — used
                by the memory actions.
            bytes_text (str): The new-bytes input's current text — used by the
                memory add / edit actions.
            unified_path_text (str): The unified-file path input's current
                text — used by the ``"load_unified"`` action.

        Dependencies:
            Used by:
                - ``S19TuiApp.on_patch_editor_panel_action_requested``
        """

        def __init__(
            self,
            action: str,
            parameter_name: str,
            index_text: str,
            value_text: str,
            path_text: str,
            address_text: str = "",
            bytes_text: str = "",
            unified_path_text: str = "",
        ) -> None:
            super().__init__()
            self.action = action
            self.parameter_name = parameter_name
            self.index_text = index_text
            self.value_text = value_text
            self.path_text = path_text
            self.address_text = address_text
            self.bytes_text = bytes_text
            self.unified_path_text = unified_path_text

    def __init__(self) -> None:
        super().__init__(id="patch_editor_panel")

    def compose(self) -> ComposeResult:
        """Lay out the functional Patch Editor widget tree.

        Summary:
            Yield the parameter-change ``DataTable`` and its empty-state line,
            the name / index / value input row with add / edit / remove
            buttons, the ``.cdfx`` save / load row; then the memory-change
            ``DataTable`` and its empty-state line, the address / new-bytes
            input row with memory add / edit / remove buttons, and the
            unified-file save / load / export row (LLR-009.1..009.3).

        Args:
            None

        Returns:
            ComposeResult: The Patch Editor widget tree.

        Dependencies:
            Used by:
                - Textual ``Container`` compose lifecycle
        """
        # --- Parameter-change half (batch-03) ---
        yield Label("Parameter changes", classes="patch-section-title")
        yield DataTable(
            id="patch_changelist_table",
            zebra_stripes=True,
            cursor_type="row",
        )
        yield Static(
            self.EMPTY_STATE_TEXT,
            id="patch_empty_state",
            markup=False,
        )
        yield Container(
            Label("Parameter", classes="patch-field-label"),
            Input(placeholder="A2L parameter name", id="patch_name_input"),
            Label("Index", classes="patch-field-label"),
            Input(placeholder="(blank = scalar)", id="patch_index_input"),
            Label("Value", classes="patch-field-label"),
            Input(placeholder="physical value", id="patch_value_input"),
            Horizontal(
                Button("Add", id="patch_add_button"),
                Button("Edit", id="patch_edit_button"),
                Button("Remove", id="patch_remove_button"),
                id="patch_entry_buttons",
            ),
            id="patch_inputs",
        )
        yield Container(
            Label("CDFX file", classes="patch-field-label"),
            Input(placeholder="path to .cdfx", id="patch_path_input"),
            Horizontal(
                Button("Save .cdfx", id="patch_save_button"),
                Button("Load .cdfx", id="patch_load_button"),
                id="patch_file_buttons",
            ),
            id="patch_file_row",
        )
        # --- Memory-field change half (batch-04, increment 8) ---
        yield Label("Memory changes", classes="patch-section-title")
        yield DataTable(
            id="patch_memory_table",
            zebra_stripes=True,
            cursor_type="row",
        )
        yield Static(
            self.MEMORY_EMPTY_STATE_TEXT,
            id="patch_memory_empty_state",
            markup=False,
        )
        yield Container(
            Label("Address", classes="patch-field-label"),
            Input(placeholder="0x100", id="patch_address_input"),
            Label("New bytes", classes="patch-field-label"),
            Input(placeholder="DE AD BE EF", id="patch_bytes_input"),
            Horizontal(
                Button("Add Mem", id="patch_mem_add_button"),
                Button("Edit Mem", id="patch_mem_edit_button"),
                Button("Remove Mem", id="patch_mem_remove_button"),
                id="patch_mem_entry_buttons",
            ),
            id="patch_mem_inputs",
        )
        yield Container(
            Label("Unified file", classes="patch-field-label"),
            Input(placeholder="path to unified .json", id="patch_unified_input"),
            Horizontal(
                Button("Save unified", id="patch_unified_save_button"),
                Button("Load unified", id="patch_unified_load_button"),
                Button("Export", id="patch_export_button"),
                id="patch_unified_buttons",
            ),
            id="patch_unified_row",
        )

    def on_mount(self) -> None:
        """Initialise both table columns and both empty states.

        Summary:
            Add the parameter ``DataTable`` columns and the memory ``DataTable``
            columns once the widget is mounted, and show both empty-state lines
            for the initially-empty change-set.

        Dependencies:
            Used by:
                - Textual mount lifecycle
        """
        table = self.query_one("#patch_changelist_table", DataTable)
        table.add_columns(*self._TABLE_COLUMNS)
        memory_table = self.query_one("#patch_memory_table", DataTable)
        memory_table.add_columns(*self._MEMORY_TABLE_COLUMNS)
        self.refresh_rows([])
        self.refresh_memory_rows([])

    def request_action(self, action: str) -> None:
        """Post an :class:`ActionRequested` message for ``action``.

        Summary:
            Read every input field — parameter, ``.cdfx`` path, memory and
            unified-file — and post an ``ActionRequested`` message so
            ``app.py`` can call ``CdfxService``. The widget itself performs no
            ``cdfx``-package work — it only forwards the request.

        Args:
            action (str): One of the parameter actions ``"add"`` / ``"edit"`` /
                ``"remove"`` / ``"save"`` / ``"load"``, the memory actions
                ``"add_memory"`` / ``"edit_memory"`` / ``"remove_memory"``, or
                the unified actions ``"save_unified"`` / ``"load_unified"`` /
                ``"export"``.

        Dependencies:
            Uses:
                - ``ActionRequested``
            Used by:
                - the panel's parameter, memory and unified-file controls
        """
        self.post_message(
            self.ActionRequested(
                action=action,
                parameter_name=self.query_one("#patch_name_input", Input).value,
                index_text=self.query_one("#patch_index_input", Input).value,
                value_text=self.query_one("#patch_value_input", Input).value,
                path_text=self.query_one("#patch_path_input", Input).value,
                address_text=self.query_one(
                    "#patch_address_input", Input
                ).value,
                bytes_text=self.query_one("#patch_bytes_input", Input).value,
                unified_path_text=self.query_one(
                    "#patch_unified_input", Input
                ).value,
            )
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Translate any Patch Editor button press into an action.

        Summary:
            Map the pressed button id to a parameter / memory / unified action
            and forward it via :meth:`request_action`. Stops the event so it
            does not also reach the app-level ``on_button_pressed``.

        Args:
            event (Button.Pressed): The Textual button-press event.

        Dependencies:
            Uses:
                - ``request_action``
            Used by:
                - Textual button-press dispatch
        """
        actions = {
            "patch_add_button": "add",
            "patch_edit_button": "edit",
            "patch_remove_button": "remove",
            "patch_save_button": "save",
            "patch_load_button": "load",
            "patch_mem_add_button": "add_memory",
            "patch_mem_edit_button": "edit_memory",
            "patch_mem_remove_button": "remove_memory",
            "patch_unified_save_button": "save_unified",
            "patch_unified_load_button": "load_unified",
            "patch_export_button": "export",
        }
        action = actions.get(event.button.id or "")
        if action is not None:
            event.stop()
            self.request_action(action)

    def refresh_rows(self, rows: Sequence[object]) -> None:
        """Repopulate the change-list table from resolved display rows.

        Summary:
            Replace every ``DataTable`` row with the supplied
            ``PatchRow`` list (parameter name, array index, displayed value,
            status). When the list is empty, show the neutral empty-state line
            and hide the table; otherwise hide the empty-state line and show
            the table (LLR-007.1 / LLR-007.6).

        Args:
            rows (Sequence[object]): The ``PatchRow`` objects produced by
                ``CdfxService.rows`` — each exposes ``parameter_name``,
                ``index_text``, ``value_text`` and ``status_text``. Typed as
                ``object`` so this view widget imports nothing from the
                service layer.

        Data Flow:
            - Clear and refill the table from the row list.
            - Toggle the ``.hidden`` class on the table and the empty-state
              line by whether the list is empty.

        Dependencies:
            Used by:
                - ``S19TuiApp`` Patch Editor action handler
        """
        table = self.query_one("#patch_changelist_table", DataTable)
        empty_state = self.query_one("#patch_empty_state", Static)
        table.clear()
        for row in rows:
            table.add_row(
                row.parameter_name,
                row.index_text,
                row.value_text,
                row.status_text,
            )
        if rows:
            table.remove_class("hidden")
            empty_state.add_class("hidden")
        else:
            table.add_class("hidden")
            empty_state.remove_class("hidden")

    def refresh_memory_rows(self, rows: Sequence[object]) -> None:
        """Repopulate the memory-change table from validated display rows.

        Summary:
            Replace every memory ``DataTable`` row with the supplied
            ``MemoryPatchRow`` list (memory address, hex rendering of the new
            bytes, validation status). When the list is empty, show the neutral
            memory empty-state line and hide the table; otherwise hide the
            line and show the table (LLR-009.1).

        Args:
            rows (Sequence[object]): The ``MemoryPatchRow`` objects produced by
                ``CdfxService.memory_rows`` — each exposes ``address_text``,
                ``value_text`` and ``status_text``. Typed as ``object`` so this
                view widget imports nothing from the service layer.

        Data Flow:
            - Clear and refill the memory table from the row list.
            - Toggle the ``.hidden`` class on the memory table and its
              empty-state line by whether the list is empty.

        Dependencies:
            Used by:
                - ``S19TuiApp`` Patch Editor action handler
        """
        table = self.query_one("#patch_memory_table", DataTable)
        empty_state = self.query_one("#patch_memory_empty_state", Static)
        table.clear()
        for row in rows:
            table.add_row(
                row.address_text,
                row.value_text,
                row.status_text,
            )
        if rows:
            table.remove_class("hidden")
            empty_state.add_class("hidden")
        else:
            table.add_class("hidden")
            empty_state.remove_class("hidden")


class AbDiffPanel(Container):
    """Static three-column placeholder for the A2B Firmware Diff screen.

    Summary:
        Lays out the Direction B A2B Diff as a static three-column shell —
        a range-list column, a hex-A column and a hex-B column — each filled
        with a small fixed set of constant, clearly-labelled sample hex rows
        and a visible "PLACEHOLDER" caption (LLR-012.3). There is no control
        to load a second ("B") firmware file and no diff computation: the
        rows are module-level constants, not data from any ``LoadedFile`` or
        any diff engine (LLR-012.3 / LLR-012.4). A visible notice states
        that diff computation and the second-file load path are deferred.

    Args:
        None

    Returns:
        None

    Data Flow:
        - Static composition only; reads no engine state and no
          ``LoadedFile``. All hex rows are constant placeholder text.

    Dependencies:
        Used by:
            - ``S19TuiApp._compose_screen_diff``

    Example:
        >>> panel = AbDiffPanel()
        >>> panel.id
        'ab_diff_panel'
    """

    DEFERRAL_TEXT = (
        "PLACEHOLDER - diff computation and the second-file (B) load path "
        "are deferred to a follow-up batch. The three columns below show "
        "static sample rows, not real diff output."
    )

    _RANGE_LIST_PLACEHOLDER = (
        "Ranges (PLACEHOLDER)\n"
        "0x00000000-0x0000000F\n"
        "0x00000010-0x0000001F\n"
        "0x00000020-0x0000002F"
    )
    _HEX_A_PLACEHOLDER = (
        "Hex A (PLACEHOLDER)\n"
        "00000000  DE AD BE EF 00 11 22 33\n"
        "00000010  44 55 66 77 88 99 AA BB\n"
        "00000020  CC DD EE FF 01 02 03 04"
    )
    _HEX_B_PLACEHOLDER = (
        "Hex B (PLACEHOLDER)\n"
        "00000000  DE AD BE EF 00 11 22 33\n"
        "00000010  44 55 66 77 88 99 A0 BB\n"
        "00000020  CC DD EE FF 01 02 03 04"
    )

    def __init__(self) -> None:
        super().__init__(id="ab_diff_panel")

    def compose(self) -> ComposeResult:
        """Lay out the static three-column A2B Diff placeholder.

        Summary:
            Yield the deferral notice and the three placeholder columns —
            range list, hex A and hex B — each carrying constant sample
            rows and a visible PLACEHOLDER caption.

        Args:
            None

        Returns:
            ComposeResult: The A2B Diff placeholder widget tree.

        Dependencies:
            Used by:
                - Textual ``Container`` compose lifecycle
        """
        yield Static(
            self.DEFERRAL_TEXT,
            id="diff_deferral_notice",
            classes="sev-warning",
            markup=False,
        )
        yield Horizontal(
            Static(self._RANGE_LIST_PLACEHOLDER, id="diff_range_list", markup=False),
            Static(self._HEX_A_PLACEHOLDER, id="diff_hex_a", markup=False),
            Static(self._HEX_B_PLACEHOLDER, id="diff_hex_b", markup=False),
            id="diff_columns",
        )
