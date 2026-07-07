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

from dataclasses import dataclass
from math import ceil
from typing import List, Optional, Sequence, Tuple

from rich.text import Text
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
from .color_policy import css_class_for_severity
from ..validation import ValidationIssue, ValidationSeverity


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


#: Default grid geometry (columns, rows) used when the panel's live content
#: region has not been measured yet (headless unit tests, pre-mount renders).
#: Kept small and fixed so the cell count is a pure function of
#: ``(span, geometry)`` and never drifts with runtime layout (LLR-041.2, R-4).
DEFAULT_GRID_COLS = 16
DEFAULT_GRID_ROWS = 8

#: The VISUAL column count of ``#map_grid``. Must equal the ``grid-size`` of the
#: ``#map_grid`` rule in ``styles.tcss`` — the two are the single source of
#: truth for how the cells wrap on screen, so arrow-key Up/Down (``∓ cols``)
#: lands on the cell the operator sees one row away (US-036). Kept equal to
#: ``DEFAULT_GRID_COLS`` so headless and rendered geometries agree.
MAP_GRID_COLS = DEFAULT_GRID_COLS

#: A single kibibyte, used only for the "≈ N KiB/cell" header label arithmetic.
_KIB = 1024

#: Filled block glyph rendered inside each cell; its colour comes from the
#: cell's ``sev-*`` CSS class (single source of truth = color_policy), never a
#: hard-coded severity hex in this module (LLR-041.3).
_CELL_GLYPH = "█"


def derive_image_span(
    ranges: Sequence[Tuple[int, int]],
) -> Tuple[int, int]:
    """Compute the image span ``[span_start, span_end)`` over all ranges.

    Summary:
        Return the minimum start and maximum end across ``ranges`` — the same
        ``span_start``/``span_end`` arithmetic the legacy text list used
        (superseded ``render_ranges``). Pure arithmetic on already-parsed
        addresses; no parse/coverage/analysis (LLR-041.7).

    Args:
        ranges (Sequence[Tuple[int, int]]): Contiguous ``(start, end)``
            memory ranges (``end`` exclusive).

    Returns:
        Tuple[int, int]: ``(span_start, span_end)``. ``(0, 0)`` when
        ``ranges`` is empty (zero-span → empty-state path, no ratio computed).

    Data Flow:
        - Reads only the supplied ``ranges``; feeds ``cell_count_for_geometry``
          and ``bytes_per_cell``.

    Dependencies:
        Used by:
            - ``MemoryMapPanel.render_ranges``

    Example:
        >>> derive_image_span([(0x100, 0x200), (0x400, 0x440)])
        (256, 1088)
    """
    if not ranges:
        return (0, 0)
    span_start = min(start for start, _end in ranges)
    span_end = max(end for _start, end in ranges)
    return (span_start, span_end)


def cell_count_for_geometry(span: int, cols: int, rows: int) -> int:
    """Choose the number of grid cells for a span and measured geometry.

    Summary:
        Return ``cols * rows`` capped so the whole ``span`` fits, i.e. never
        more cells than there are bytes. The result is a pure function of
        ``(span, cols, rows)`` — no live layout is read here, so the grid is
        deterministic and snapshot-stable (LLR-041.2, R-4).

    Args:
        span (int): Image span in bytes (``span_end - span_start``).
        cols (int): Grid columns available in the content region.
        rows (int): Grid rows available in the content region.

    Returns:
        int: Number of cells to render; ``0`` when ``span <= 0`` (empty
        state, no ratio computed → no divide-by-zero).

    Data Flow:
        - Called by ``render_ranges`` with ``derive_image_span`` output and
          the measured (or default) geometry; feeds ``bytes_per_cell``.

    Dependencies:
        Used by:
            - ``MemoryMapPanel.render_ranges``

    Example:
        >>> cell_count_for_geometry(1000, 16, 8)
        128
        >>> cell_count_for_geometry(10, 16, 8)
        10
        >>> cell_count_for_geometry(0, 16, 8)
        0
    """
    if span <= 0:
        return 0
    capacity = max(1, cols) * max(1, rows)
    return min(capacity, span)


def bytes_per_cell(span: int, cell_count: int) -> int:
    """Compute the bytes-per-cell size for the grid.

    Summary:
        Return ``ceil(span / cell_count)`` — the address window each cell
        covers so the whole span fits the grid (LLR-041.2). Guards against a
        zero ``cell_count`` (empty state) so no division occurs.

    Args:
        span (int): Image span in bytes.
        cell_count (int): Number of cells from ``cell_count_for_geometry``.

    Returns:
        int: Bytes covered by one cell; ``0`` when ``cell_count <= 0``.

    Data Flow:
        - Called by ``render_ranges``; drives per-cell window boundaries and
          the "≈ N KiB/cell" header.

    Dependencies:
        Used by:
            - ``MemoryMapPanel.render_ranges``

    Example:
        >>> bytes_per_cell(1000, 128)
        8
        >>> bytes_per_cell(0, 0)
        0
    """
    if cell_count <= 0:
        return 0
    return ceil(span / cell_count)


def cell_status(
    cell_start: int,
    cell_end: int,
    ordered_ranges: Sequence[Tuple[int, int, bool]],
) -> str:
    """Derive a cell's status from the ranges overlapping its window.

    Summary:
        Classify the half-open window ``[cell_start, cell_end)`` as
        ``"invalid"`` if it overlaps any invalid range, else ``"valid"`` if
        it overlaps any (only valid) range, else ``"gap"`` (LLR-041.1). Pure
        overlap arithmetic — no ``range_index`` call needed for a single
        window, no parse/analysis (LLR-041.7).

    Args:
        cell_start (int): Inclusive window start.
        cell_end (int): Exclusive window end.
        ordered_ranges (Sequence[Tuple[int, int, bool]]): ``(start, end,
            is_valid)`` triples (``end`` exclusive), start-sorted.

    Returns:
        str: One of ``"valid"``, ``"invalid"``, ``"gap"``.

    Data Flow:
        - Called once per cell by ``render_ranges``; its result routes
          through ``status_to_css_class`` for colour.

    Dependencies:
        Used by:
            - ``MemoryMapPanel.render_ranges``

    Example:
        >>> cell_status(0, 16, [(0, 8, True), (8, 16, False)])
        'invalid'
        >>> cell_status(0, 8, [(0, 8, True)])
        'valid'
        >>> cell_status(16, 32, [(0, 8, True)])
        'gap'
    """
    overlaps_valid = False
    for start, end, is_valid in ordered_ranges:
        if start < cell_end and end > cell_start:
            if not is_valid:
                return "invalid"
            overlaps_valid = True
    return "valid" if overlaps_valid else "gap"


def status_to_css_class(status: str) -> str:
    """Map a cell status to its canonical ``sev-*`` CSS class.

    Summary:
        Route ``"invalid"``→``ERROR``, ``"valid"``→``OK``, ``"gap"``→
        ``NEUTRAL`` through the frozen ``css_class_for_severity`` — the
        single source of truth for severity colours. The panel hard-codes no
        severity hex or inline style (LLR-041.3).

    Args:
        status (str): ``"valid"``, ``"invalid"`` or ``"gap"``.

    Returns:
        str: The matching CSS class (``"sev-ok"`` / ``"sev-error"`` /
        ``"sev-neutral"``).

    Data Flow:
        - Applied by ``render_ranges`` as a cell widget class.

    Dependencies:
        Uses:
            - ``css_class_for_severity`` (frozen, consumed read-only)
        Used by:
            - ``MemoryMapPanel.render_ranges``

    Example:
        >>> status_to_css_class("invalid")
        'sev-error'
    """
    severity = {
        "invalid": ValidationSeverity.ERROR,
        "valid": ValidationSeverity.OK,
        "gap": ValidationSeverity.NEUTRAL,
    }.get(status, ValidationSeverity.NEUTRAL)
    return css_class_for_severity(severity)


def safe_text(value: str, style: str = "") -> Text:
    """Build a markup-safe ``rich.text.Text`` from a possibly hostile string.

    Summary:
        Wrap ``value`` as a ``Text`` with an explicit ``style`` so the string
        is treated as literal content, never as Rich markup (LLR-041.11).
        This neutralises file-derived tokens such as ``sensor[red]`` or
        ``x[link=file:///…]`` and raw ANSI bytes carried in the never-scrubbed
        ``ValidationIssue.symbol`` — no ``MarkupError``, no style/ANSI leak,
        no crash of the Memory Map screen on load (security B-1 / F2).

    Args:
        value (str): The (possibly untrusted, file-derived) text to render.
        style (str): An optional Rich style applied to the whole span
            (developer-supplied, never file-derived).

    Returns:
        Text: A ``Text`` instance whose content is exactly ``value``.

    Data Flow:
        - Used for every file-derived string reaching the grid or (in a later
          increment) the detail pane; ``Text.from_markup`` is deliberately
          NOT used.

    Dependencies:
        Used by:
            - ``MemoryMapPanel.render_ranges``

    Example:
        >>> safe_text("sensor[red]").plain
        'sensor[red]'
    """
    return Text(value, style=style)


def issues_in_window(
    issues: Sequence["ValidationIssue"],
    window_start: int,
    window_end: int,
) -> List["ValidationIssue"]:
    """Return the issues whose address falls in ``[window_start, window_end)``.

    Summary:
        Filter ``issues`` to those whose ``address`` is an ``int`` inside the
        half-open window (LLR-041.5). Issues with ``address is None`` cannot be
        spatially anchored and are excluded (locks the R-1 default). Pure
        arithmetic on the already-computed issue list — no new analysis
        (LLR-041.7). Used both for the cell-scoped issue list (window = the
        cell) and for the "N issues in region" count (window = the covering
        range).

    Args:
        issues (Sequence[ValidationIssue]): The pre-computed
            ``S19TuiApp._validation_issues`` handed to the panel.
        window_start (int): Inclusive window start.
        window_end (int): Exclusive window end.

    Returns:
        List[ValidationIssue]: Issues whose ``address`` is in the window, in
        input order; empty when none match.

    Data Flow:
        - Called by ``MemoryMapPanel._render_detail`` for both the cell window
          and the covering-region window.

    Dependencies:
        Used by:
            - ``MemoryMapPanel._render_detail``

    Example:
        >>> class _I:  # doctest-only stand-in
        ...     def __init__(self, address):
        ...         self.address = address
        >>> [i.address for i in issues_in_window([_I(4), _I(None), _I(16)], 0, 16)]
        [4]
    """
    hits: List["ValidationIssue"] = []
    for issue in issues:
        address = issue.address
        if isinstance(address, int) and window_start <= address < window_end:
            hits.append(issue)
    return hits


def covering_range(
    cell_start: int,
    cell_end: int,
    ordered_ranges: Sequence[Tuple[int, int, bool]],
) -> Optional[Tuple[int, int, bool]]:
    """Return the range overlapping the cell window, or ``None`` for a gap.

    Summary:
        Find the first ``(start, end, is_valid)`` triple overlapping the
        half-open cell window ``[cell_start, cell_end)`` — the covering region
        surfaced in the detail pane (LLR-041.4). An invalid overlapping range
        is preferred so the detail status matches the cell colour
        (``cell_status`` invalid-wins, LLR-041.1). Returns ``None`` when the
        cell overlaps no range (a gap → "gap — no region").

    Args:
        cell_start (int): Inclusive cell-window start.
        cell_end (int): Exclusive cell-window end.
        ordered_ranges (Sequence[Tuple[int, int, bool]]): ``(start, end,
            is_valid)`` triples (``end`` exclusive), start-sorted.

    Returns:
        Optional[Tuple[int, int, bool]]: The covering range triple, or
        ``None`` when the window is a gap.

    Data Flow:
        - Called by ``MemoryMapPanel._render_detail`` to name the region and
          to bound the region-issue count window.

    Dependencies:
        Used by:
            - ``MemoryMapPanel._render_detail``

    Example:
        >>> covering_range(0, 16, [(0, 8, True), (8, 16, False)])
        (8, 16, False)
        >>> covering_range(16, 24, [(0, 8, True)]) is None
        True
    """
    first_valid: Optional[Tuple[int, int, bool]] = None
    for start, end, is_valid in ordered_ranges:
        if start < cell_end and end > cell_start:
            if not is_valid:
                return (start, end, is_valid)
            if first_valid is None:
                first_valid = (start, end, is_valid)
    return first_valid


@dataclass(frozen=True)
class CoverageStats:
    """The seven coverage-strip statistics for one rendered image (US-037).

    Summary:
        A pure value object holding the numbers the ``#map_stats`` strip
        displays. Every field is derived by arithmetic on the already-parsed
        ``ranges``/``range_validity`` and the pre-computed issue list — the
        panel computes no new coverage/parse/analysis (LLR-041.7/.8).

    Args:
        image_span (int): ``span_end - span_start`` in bytes (``0`` when
            there are no ranges → empty state, no ratio computed).
        covered_bytes (int): ``Σ(end - start)`` over all ranges.
        coverage_pct (float): ``covered_bytes / image_span * 100`` when
            ``image_span > 0``, else ``0.0`` (the ``image_span > 0`` guard is
            the single divide-by-zero guard).
        valid_count (int): number of ranges flagged valid.
        invalid_count (int): number of ranges flagged invalid.
        gap_count (int): number of uncovered spans between consecutive ranges.
        largest_gap (int): the widest inter-range gap in bytes (``0`` when
            there are no gaps).
        total_issues (int): ``len(issues)`` — the pre-computed issue count.
    """

    image_span: int
    covered_bytes: int
    coverage_pct: float
    valid_count: int
    invalid_count: int
    gap_count: int
    largest_gap: int
    total_issues: int


def coverage_stats(
    ranges: Sequence[Tuple[int, int]],
    range_validity: Sequence[bool],
    issues: Sequence["ValidationIssue"],
) -> CoverageStats:
    """Compute the coverage-strip statistics from already-parsed inputs.

    Summary:
        Derive the seven US-037 statistics — coverage %, bytes covered,
        valid/invalid range counts, gap count, largest-gap bytes and total
        issues — by arithmetic on the ``ranges``/``range_validity`` handed in
        by ``update_memory_map`` and ``len(issues)`` (LLR-041.8). Coverage %
        divides only when ``image_span > 0`` (the sole divide-by-zero guard,
        LLR-041.2/.9); an empty ``ranges`` yields an all-zero
        :class:`CoverageStats` and the strip shows nothing (LLR-041.9). No
        parsing, coverage or validation is performed here (LLR-041.7); the
        gap arithmetic mirrors the legacy consecutive-range subtraction the
        superseded text list used.

    Args:
        ranges (Sequence[Tuple[int, int]]): Contiguous ``(start, end)``
            memory ranges (``end`` exclusive) from ``LoadedFile.ranges``.
        range_validity (Sequence[bool]): Per-range validity flags,
            positionally aligned with ``ranges``.
        issues (Sequence[ValidationIssue]): The single canonical
            ``_validation_issues`` list — only its length is read (LLR-041.8).

    Returns:
        CoverageStats: the seven metrics; all-zero when ``ranges`` is empty.

    Data Flow:
        - Called by ``MemoryMapPanel.render_ranges`` with the same inputs the
          grid is built from; feeds ``build_stats_text``.

    Dependencies:
        Used by:
            - ``MemoryMapPanel.render_ranges`` / ``build_stats_text``
            - (test) TC-041.8 / TC-041.9

    Example:
        >>> s = coverage_stats([(0, 8), (16, 24)], [True, False], [])
        >>> (s.covered_bytes, s.gap_count, s.largest_gap, s.image_span)
        (16, 1, 8, 24)
        >>> (s.valid_count, s.invalid_count, s.total_issues)
        (1, 1, 0)
        >>> coverage_stats([], [], []).image_span
        0
    """
    if not ranges:
        return CoverageStats(0, 0, 0.0, 0, 0, 0, 0, len(issues))

    span_start, span_end = derive_image_span(ranges)
    image_span = span_end - span_start
    covered_bytes = sum(end - start for start, end in ranges)

    valid_count = 0
    invalid_count = 0
    for index in range(len(ranges)):
        is_valid = bool(range_validity[index]) if index < len(range_validity) else True
        if is_valid:
            valid_count += 1
        else:
            invalid_count += 1

    ordered = sorted(ranges, key=lambda item: item[0])
    largest_gap = 0
    gap_count = 0
    for index in range(1, len(ordered)):
        gap = ordered[index][0] - ordered[index - 1][1]
        if gap > 0:
            gap_count += 1
            if gap > largest_gap:
                largest_gap = gap

    coverage_pct = covered_bytes / image_span * 100 if image_span > 0 else 0.0

    return CoverageStats(
        image_span=image_span,
        covered_bytes=covered_bytes,
        coverage_pct=coverage_pct,
        valid_count=valid_count,
        invalid_count=invalid_count,
        gap_count=gap_count,
        largest_gap=largest_gap,
        total_issues=len(issues),
    )


#: The four arrow keys and their (row, column) focus deltas on the minimap
#: grid — Left/Right step one cell, Up/Down step one visual row. Consumed by
#: ``adjacent_cell_index``; kept as data so the handler stays a table lookup.
_ARROW_DELTAS = {
    "left": (0, -1),
    "right": (0, 1),
    "up": (-1, 0),
    "down": (1, 0),
}


def adjacent_cell_index(
    current: int, key: str, count: int, cols: int
) -> Optional[int]:
    """Return the grid index one arrow-step from ``current``, clamped.

    Summary:
        Compute the focus target for an arrow key over a ``count``-cell grid
        laid out ``cols`` columns wide (US-036 keyboard nav). Left/Right move
        ``∓1`` in mount order; Up/Down move ``∓cols`` (one visual row). The
        result is clamped to ``[0, count)`` — stepping off the first/last cell
        or above the top / below the bottom row is a no-op (returns the same
        index), so focus never wraps. Returns ``None`` for a non-arrow key or
        an empty grid. Pure arithmetic — no widget access, no parsing.

    Args:
        current (int): The focused cell's index in mount order.
        key (str): The pressed key (one of ``_ARROW_DELTAS`` or anything else).
        count (int): Total number of cells in the grid.
        cols (int): Visual column count (``MAP_GRID_COLS``).

    Returns:
        Optional[int]: The target index (possibly ``== current`` at an edge),
        or ``None`` when ``key`` is not an arrow or the grid is empty.

    Data Flow:
        - Called by ``MemoryMapPanel.focus_adjacent_cell`` with the current
          focus index; its result selects which cell receives ``.focus()``.

    Dependencies:
        Used by:
            - ``MemoryMapPanel.focus_adjacent_cell``

    Example:
        >>> adjacent_cell_index(0, "right", 32, 16)
        1
        >>> adjacent_cell_index(0, "left", 32, 16)  # clamp at first cell
        0
        >>> adjacent_cell_index(3, "down", 32, 16)
        19
        >>> adjacent_cell_index(3, "up", 32, 16)  # clamp above top row
        3
        >>> adjacent_cell_index(0, "enter", 32, 16) is None
        True
    """
    delta = _ARROW_DELTAS.get(key)
    if delta is None or count <= 0 or cols <= 0:
        return None
    row_delta, col_delta = delta
    target = current + col_delta + row_delta * cols
    if target < 0 or target >= count:
        return current
    return target


class MapCell(Static):
    """A single focusable, clickable cell of the Memory Map minimap grid.

    Summary:
        Carries the address window ``[cell_start, cell_end)`` and status of one
        grid tile so both the pointer-click and the keyboard-focus/``Enter``
        paths can resolve which cell was selected (LLR-041.4).

        Navigation (US-036):
            - ``Tab`` / ``Shift+Tab`` — Textual's default focus traversal steps
              cell to cell (each cell is ``can_focus``).
            - Arrow keys — Left/Right move focus to the previous/next cell in
              mount order; Up/Down move one grid row (``∓ cols``); focus clamps
              at the grid edges (no wrap). Handled by delegating to
              ``MemoryMapPanel.focus_adjacent_cell`` (the panel owns the cell
              list + column count — a single source of truth). Arrows only MOVE
              focus; they do NOT select.
            - Click / ``Enter`` — posts :class:`Selected`, which the panel
              handles by rendering the detail pane (the select step).

        Purely presentational — it stores windows, never parses.

    Args:
        cell_start (int): Inclusive window start of this cell.
        cell_end (int): Exclusive window end of this cell.
        status (str): The cell status (``"valid"`` / ``"invalid"`` / ``"gap"``).
        classes (str): The space-joined CSS classes (``map-cell`` + the
            ``sev-*`` status class).

    Returns:
        None

    Data Flow:
        - Mounted by ``MemoryMapPanel.render_ranges``; on click/``Enter`` posts
          :class:`Selected` → ``MemoryMapPanel.on_map_cell_selected``.

    Dependencies:
        Used by:
            - ``MemoryMapPanel.render_ranges``

    Example:
        >>> cell = MapCell(0, 16, "valid", "map-cell sev-ok")
        >>> (cell.cell_start, cell.cell_end, cell.status)
        (0, 16, 'valid')
    """

    can_focus = True

    class Selected(Message):
        """A map cell was activated (click or ``Enter``).

        Args:
            cell (MapCell): The activated cell.
        """

        def __init__(self, cell: "MapCell") -> None:
            super().__init__()
            self.cell = cell

    def __init__(
        self, cell_start: int, cell_end: int, status: str, classes: str
    ) -> None:
        super().__init__(safe_text(_CELL_GLYPH), classes=classes)
        self.cell_start = cell_start
        self.cell_end = cell_end
        self.status = status

    def on_click(self) -> None:
        """Post :class:`Selected` when the cell is clicked."""
        self.focus()
        self.post_message(self.Selected(self))

    def on_key(self, event) -> None:  # type: ignore[no-untyped-def]
        """Handle ``Enter`` (select) and the arrow keys (move focus).

        Summary:
            ``Enter`` posts :class:`Selected` (the select step). An arrow key
            moves focus to the adjacent cell via the parent
            :class:`MemoryMapPanel` and is CONSUMED (``event.stop()``) so it
            does not also scroll the enclosing ``#map_content``
            ``ScrollableContainer`` — the consumption is scoped to a focused
            cell only, so arrows retain their normal scroll behaviour when
            focus is elsewhere. Arrows never select.

        Args:
            event: The Textual key event (``event.key`` is the key name).

        Dependencies:
            Uses:
                - ``MemoryMapPanel.focus_adjacent_cell``
            Used by:
                - Textual key-event dispatch (only while this cell is focused)
        """
        if event.key == "enter":
            event.stop()
            self.post_message(self.Selected(self))
            return
        if event.key in _ARROW_DELTAS:
            panel = self._map_panel()
            if panel is not None:
                event.stop()
                panel.focus_adjacent_cell(self, event.key)

    def _map_panel(self) -> Optional["MemoryMapPanel"]:
        """Return the enclosing ``MemoryMapPanel`` ancestor, or ``None``."""
        node = self.parent
        while node is not None:
            if isinstance(node, MemoryMapPanel):
                return node
            node = node.parent
        return None


class MemoryMapPanel(Container):
    """Colour-coded 2-D spatial minimap of the loaded image's memory ranges.

    Summary:
        Renders the firmware image span as a grid of address-window cells,
        each coloured ``valid``/``invalid``/``gap`` from the already-computed
        ``LoadedFile.ranges`` and ``LoadedFile.range_validity`` handed to
        ``render_ranges``. Cell size auto-scales so the whole span fits the
        visible grid, and a header shows the "≈ N KiB/cell" ratio. It is a
        pure presentational widget — it performs NO coverage, parsing,
        validation or file I/O of its own (LLR-041.7). Cell colours route
        exclusively through ``css_class_for_severity`` (LLR-041.3); no
        severity hex is hard-coded. With no ranges it preserves the neutral
        no-file note (LLR-041.9).

    Args:
        None

    Returns:
        None

    Data Flow:
        - ``render_ranges`` receives the pre-computed ``ranges`` and
          ``range_validity`` from ``S19TuiApp.update_memory_map``, derives the
          image span and per-cell status by arithmetic on those already-parsed
          values, and mounts one ``.map-cell`` widget per cell into
          ``#map_grid`` carrying its ``sev-*`` status class.
        - Selecting a cell populates ``#map_detail`` (status chip, window,
          covering region, cell-scoped issues, region count); the
          ``#map_stats`` strip shows the seven coverage statistics derived by
          ``coverage_stats`` (US-037 / LLR-041.8).
        - With no ranges the header shows the neutral empty note, no cells are
          mounted, and the stats strip is blanked (LLR-041.9).
        - ``#map_grid`` and ``#map_detail`` sit in a ``#map_body`` sub-container
          laid horizontally when wide and stacked under ``width-narrow`` — the
          reflow rules live in ``styles.tcss`` (LLR-041.10).

    Dependencies:
        Uses:
            - ``derive_image_span`` / ``cell_count_for_geometry`` /
              ``bytes_per_cell`` / ``cell_status`` / ``status_to_css_class`` /
              ``safe_text``
        Used by:
            - ``S19TuiApp._compose_screen_map`` (mounts the widget)
            - ``S19TuiApp.update_memory_map`` (drives ``render_ranges``)

    Example:
        >>> panel = MemoryMapPanel()
        >>> panel.id
        'memory_map_panel'
    """

    _EMPTY_TEXT = "No file loaded - press Ctrl+L (or 'l') to load a file."
    _DETAIL_HINT = (
        "Click a cell, or focus the grid and use arrows "
        "(<-/->/up/down) then Enter to inspect."
    )

    class OpenInHexRequested(Message):
        """The operator asked to jump to the hex view at a cell's start (US-036).

        Summary:
            Posted by the "Open in Hex View" affordance in the detail pane so
            ``app.py`` drives the existing ``update_hex_view(focus_address=…)``
            and switches to the Workspace/hex screen (LLR-041.6). The panel
            renders no hex itself — it only carries the focus address.

        Args:
            focus_address (int): The selected cell's ``cell_start`` — the
                address the hex view should focus.

        Dependencies:
            Used by:
                - ``S19TuiApp.on_memory_map_panel_open_in_hex_requested``
        """

        def __init__(self, focus_address: int) -> None:
            super().__init__()
            self.focus_address = focus_address

    def __init__(self) -> None:
        super().__init__(id="memory_map_panel")
        #: Last header/summary text rendered — exposed so tests and callers
        #: can read the map's textual summary without touching Textual
        #: internals. Mirrors the old ``rendered_text`` accessor.
        self.rendered_text: str = self._EMPTY_TEXT
        #: The start-sorted ``(start, end, is_valid)`` triples of the last
        #: render — the covering-region lookup and region-issue count read
        #: these already-parsed ranges (never re-derived, LLR-041.7).
        self._ordered_ranges: List[Tuple[int, int, bool]] = []
        #: The pre-computed issue list handed in by ``update_memory_map`` — the
        #: single canonical source for both the cell join and the region count
        #: (LLR-041.5 / LLR-041.8, arch MINOR-3). Never re-derived here.
        self._issues: List[ValidationIssue] = []
        #: The currently-selected cell's start address, or ``None`` before any
        #: selection — carried on the Open-in-Hex message (LLR-041.6).
        self._selected_cell_start: Optional[int] = None
        #: The visual column count the last grid was laid out with — used by
        #: arrow-key Up/Down (``∓ cols``). Equals ``MAP_GRID_COLS`` (the CSS
        #: ``grid-size``), the single source of truth for on-screen wrapping.
        self._grid_cols: int = MAP_GRID_COLS

    def compose(self) -> ComposeResult:
        """Compose the header, the cell grid and the (empty) placeholders.

        Summary:
            Yield the full-width "≈ N KiB/cell" header, then a ``#map_body``
            horizontal sub-container holding the ``#map_grid`` cell grid and
            the ``#map_detail`` pane side by side (the wide-regime layout;
            ``#map_body`` stacks them vertically under ``width-narrow`` — the
            reflow lives in ``styles.tcss``, LLR-041.10), and finally the
            full-width ``#map_stats`` coverage strip (US-037 / LLR-041.8).

        Returns:
            ComposeResult: the header, the grid+detail body, and the stats
            strip.

        Dependencies:
            Used by:
                - Textual mount pipeline
        """
        yield Label(self._EMPTY_TEXT, id="map_header", markup=False)
        yield Horizontal(
            Container(id="map_grid"),
            Container(
                Static(safe_text(self._DETAIL_HINT), id="map_detail_body"),
                Button(
                    "Open in Hex View",
                    id="map_open_hex_button",
                    classes="hidden",
                ),
                id="map_detail",
            ),
            id="map_body",
        )
        yield Container(Static("", id="map_stats_body"), id="map_stats")

    def _grid_geometry(self) -> Tuple[int, int]:
        """Return the (cols, rows) grid geometry to scale cells against.

        Summary:
            Read the live content-region size of ``#map_grid`` when the panel
            is mounted and measured, else fall back to the fixed
            ``DEFAULT_GRID_COLS``/``DEFAULT_GRID_ROWS``. Kept separate so tests
            can reason about the cell count as a pure function of geometry
            (LLR-041.2, R-4).

        Returns:
            Tuple[int, int]: ``(cols, rows)`` — always ``>= 1`` each.

        Dependencies:
            Used by:
                - ``render_ranges``
        """
        try:
            grid = self.query_one("#map_grid", Container)
            size = grid.content_size
            cols = size.width if size.width > 0 else DEFAULT_GRID_COLS
            rows = size.height if size.height > 0 else DEFAULT_GRID_ROWS
        except Exception:
            cols, rows = DEFAULT_GRID_COLS, DEFAULT_GRID_ROWS
        return (max(1, cols), max(1, rows))

    def render_ranges(
        self,
        ranges: Sequence[Tuple[int, int]],
        range_validity: Sequence[bool],
        issues: Sequence[ValidationIssue] = (),
    ) -> None:
        """Render the colour-coded minimap grid from already-computed ranges.

        Summary:
            Build the image span, auto-scale the cell size to the visible
            grid, and mount one ``MapCell`` widget per cell coloured by its
            overlap status. The input is consumed verbatim from the
            ``LoadedFile`` snapshot and the pre-computed ``issues`` list — no
            range is re-derived and no coverage/validation is computed here
            (LLR-041.7). Cell content is built as markup-safe ``Text``
            (LLR-041.11). The ordered ranges and the issue list are stored so
            cell selection can assemble the detail pane (LLR-041.4/.5).

        Args:
            ranges (Sequence[Tuple[int, int]]): Contiguous ``(start, end)``
                memory ranges from ``LoadedFile.ranges`` (``end`` exclusive).
            range_validity (Sequence[bool]): Per-range validity flags from
                ``LoadedFile.range_validity``, positionally aligned with
                ``ranges``.
            issues (Sequence[ValidationIssue]): The already-computed
                ``S19TuiApp._validation_issues`` — the single canonical source
                for the cell-scoped issue list and the region-issue count
                (LLR-041.5); defaults to empty for the no-issue / headless
                path.

        Returns:
            None

        Data Flow:
            - When ``ranges`` is empty, show the neutral empty note, mount no
              cells and reset the detail pane (LLR-041.9).
            - Otherwise derive the span, cell count and bytes-per-cell, then
              mount a ``MapCell`` widget per cell into ``#map_grid`` with its
              ``sev-*`` status class and its ``[cell_start, cell_end)`` window;
              the header shows the "≈ N KiB/cell" ratio. The summary text is
              stored on ``rendered_text``.

        Dependencies:
            Uses:
                - ``derive_image_span`` / ``cell_count_for_geometry`` /
                  ``bytes_per_cell`` / ``cell_status`` /
                  ``status_to_css_class`` / ``MapCell``
            Used by:
                - ``S19TuiApp.update_memory_map``
        """
        try:
            header = self.query_one("#map_header", Label)
            grid = self.query_one("#map_grid", Container)
        except Exception:
            # App not mounted yet (headless render before compose) — nothing
            # to draw into; the compose default already shows the empty note.
            return

        grid.remove_children()
        self._issues = list(issues)
        self._reset_detail()

        span_start, span_end = derive_image_span(ranges)
        span = span_end - span_start
        if not ranges or span <= 0:
            self._ordered_ranges = []
            self.rendered_text = self._EMPTY_TEXT
            header.update(self._EMPTY_TEXT)
            self._render_stats([], [], self._issues, empty=True)
            return

        ordered: List[Tuple[int, int, bool]] = []
        for index, (start, end) in enumerate(ranges):
            is_valid = (
                bool(range_validity[index]) if index < len(range_validity) else True
            )
            ordered.append((start, end, is_valid))
        ordered.sort(key=lambda item: item[0])
        self._ordered_ranges = ordered

        cols, rows = self._grid_geometry()
        count = cell_count_for_geometry(span, cols, rows)
        per_cell = bytes_per_cell(span, count)
        #: Record the VISUAL column count for arrow-key Up/Down; the on-screen
        #: wrapping is fixed by the ``#map_grid`` CSS ``grid-size`` (MAP_GRID_COLS),
        #: not the measured content geometry used only for the cell *count*.
        self._grid_cols = MAP_GRID_COLS

        cells: List[MapCell] = []
        for index in range(count):
            cell_start = span_start + index * per_cell
            cell_end = min(span_end, cell_start + per_cell)
            status = cell_status(cell_start, cell_end, ordered)
            sev_class = status_to_css_class(status)
            cell = MapCell(
                cell_start, cell_end, status, f"map-cell {sev_class}"
            )
            cells.append(cell)
        if cells:
            grid.mount(*cells)

        kib_per_cell = per_cell / _KIB
        summary = f"≈ {kib_per_cell:.2f} KiB/cell ({count} cells, {per_cell} B/cell)"
        self.rendered_text = summary
        header.update(safe_text(summary))

        self._render_stats(ranges, range_validity, self._issues, empty=False)

    def _render_stats(
        self,
        ranges: Sequence[Tuple[int, int]],
        range_validity: Sequence[bool],
        issues: Sequence[ValidationIssue],
        empty: bool,
    ) -> None:
        """Populate (or clear) the ``#map_stats`` coverage strip (US-037).

        Summary:
            Compute the seven coverage statistics from the already-parsed
            ``ranges``/``range_validity`` and the pre-computed ``issues`` list
            via ``coverage_stats`` and render them markup-safe into
            ``#map_stats_body`` (LLR-041.8). When ``empty`` (no ranges), the
            strip is blanked so the no-file state shows nothing / neutral, with
            no divide-by-zero (LLR-041.9). Pure arithmetic on already-parsed
            values — no new coverage/parse/analysis (LLR-041.7).

        Args:
            ranges (Sequence[Tuple[int, int]]): The image ranges (empty in the
                no-file path).
            range_validity (Sequence[bool]): Per-range validity flags.
            issues (Sequence[ValidationIssue]): The single canonical
                ``_validation_issues`` list (only its length is read).
            empty (bool): ``True`` on the no-file / zero-span path → clear the
                strip; ``False`` → render the seven metrics.

        Data Flow:
            - Reads the same inputs the grid is built from; writes the composed
              ``Text`` into ``#map_stats_body``.

        Dependencies:
            Uses:
                - ``coverage_stats`` / ``build_stats_text`` / ``safe_text``
            Used by:
                - ``render_ranges``
        """
        try:
            body = self.query_one("#map_stats_body", Static)
        except Exception:
            return
        if empty:
            body.update(safe_text(""))
            return
        stats = coverage_stats(ranges, range_validity, issues)
        body.update(self.build_stats_text(stats))

    def build_stats_text(self, stats: CoverageStats) -> Text:
        """Assemble the markup-safe coverage-strip text (US-037 / LLR-041.8).

        Summary:
            Compose the seven-statistic strip — coverage %, bytes covered,
            valid/invalid range counts, gap count, largest-gap bytes and total
            issues — as labelled ``Text`` segments so the strip is readable and
            markup-safe (LLR-041.11 uniformity; the numbers are developer
            formatting, not file-derived, but the panel stays uniformly
            ``Text``-composed). Pure formatting of a :class:`CoverageStats` —
            no analysis (LLR-041.7).

        Args:
            stats (CoverageStats): The metrics from ``coverage_stats``.

        Returns:
            Text: The composed, markup-safe coverage strip.

        Data Flow:
            - Reads ``stats``; produces the ``Text`` rendered into
              ``#map_stats_body``.

        Dependencies:
            Uses:
                - ``safe_text``
            Used by:
                - ``_render_stats`` / (test) TC-041.8
        """
        text = Text()
        text.append(f"Coverage: {stats.coverage_pct:.6f}%  ")
        text.append(f"Bytes covered: {stats.covered_bytes}\n")
        text.append(f"Valid ranges: {stats.valid_count}  ")
        text.append(f"Invalid ranges: {stats.invalid_count}\n")
        text.append(f"Gaps: {stats.gap_count}  ")
        text.append(f"Largest gap: {stats.largest_gap} bytes\n")
        text.append(f"Total issues: {stats.total_issues}")
        return text

    def _reset_detail(self) -> None:
        """Clear the detail pane back to its neutral hint and hide the jump.

        Summary:
            Return the detail body to the "select a cell" hint and hide the
            Open-in-Hex button — used on every fresh render so a stale
            selection from a prior file never lingers.

        Dependencies:
            Used by:
                - ``render_ranges``
        """
        try:
            body = self.query_one("#map_detail_body", Static)
            button = self.query_one("#map_open_hex_button", Button)
        except Exception:
            return
        self._selected_cell_start = None
        body.update(safe_text(self._DETAIL_HINT))
        button.add_class("hidden")

    def build_detail_text(
        self,
        cell_start: int,
        cell_end: int,
        status: str,
    ) -> Text:
        """Assemble the markup-safe detail text for a selected cell.

        Summary:
            Compose the detail pane's body for the cell ``[cell_start,
            cell_end)`` (LLR-041.4): a status chip line, the cell window
            ``0x{start:08X}-0x{end-1:08X}``, the covering region (bounds/size/
            status, or "gap — no region"), the cell-scoped issue list
            (LLR-041.5) and a "N issues in region" count. Every file-derived
            string — issue ``code``/``message``/``symbol`` — is appended as a
            ``Text`` segment (never markup-parsed), so hostile tokens like
            ``sensor[red]`` render literally (LLR-041.11). Pure assembly over
            the stored ``_ordered_ranges`` / ``_issues`` — no new analysis
            (LLR-041.7).

        Args:
            cell_start (int): Inclusive cell-window start.
            cell_end (int): Exclusive cell-window end.
            status (str): The cell status (``"valid"`` / ``"invalid"`` /
                ``"gap"``).

        Returns:
            Text: The composed, markup-safe detail body.

        Data Flow:
            - Reads ``self._ordered_ranges`` (covering region) and
              ``self._issues`` (cell + region joins via ``issues_in_window``);
              produces the ``Text`` rendered into ``#map_detail_body``.

        Dependencies:
            Uses:
                - ``covering_range`` / ``issues_in_window`` / ``safe_text``
            Used by:
                - ``on_map_cell_selected`` / (test) TC-041.4
        """
        text = Text()
        chip = {
            "valid": "VALID",
            "invalid": "INVALID",
            "gap": "GAP (uncovered)",
        }.get(status, "GAP (uncovered)")
        text.append("Status: ")
        text.append(f"{chip}\n")
        text.append(f"Cell: 0x{cell_start:08X}-0x{cell_end - 1:08X}\n")

        region = covering_range(cell_start, cell_end, self._ordered_ranges)
        if region is None:
            text.append("Region: gap - no region\n")
            region_issue_count = 0
        else:
            r_start, r_end, r_valid = region
            r_status = "valid" if r_valid else "invalid"
            r_size = r_end - r_start
            text.append(
                f"Region: 0x{r_start:08X}-0x{r_end - 1:08X} "
                f"({r_size} bytes, {r_status})\n"
            )
            region_issue_count = len(
                issues_in_window(self._issues, r_start, r_end)
            )

        cell_issues = issues_in_window(self._issues, cell_start, cell_end)
        text.append(f"{len(cell_issues)} issue(s) in this cell\n")
        for issue in cell_issues:
            text.append("  [")
            text.append(safe_text(issue.code))
            text.append("] ")
            if isinstance(issue.address, int):
                text.append(f"0x{issue.address:08X} ")
            if issue.symbol:
                text.append(safe_text(issue.symbol))
                text.append(" ")
            text.append(safe_text(issue.message))
            text.append("\n")
        text.append(f"{region_issue_count} issue(s) in region")
        return text

    def on_map_cell_selected(self, event: "MapCell.Selected") -> None:
        """Render the detail pane for the activated cell (LLR-041.4).

        Summary:
            Handle a :class:`MapCell.Selected` message by composing the
            markup-safe detail body for that cell and revealing the
            Open-in-Hex jump. Stores the cell start so the jump can carry it.

        Args:
            event (MapCell.Selected): The cell-activation message.

        Dependencies:
            Uses:
                - ``build_detail_text``
            Used by:
                - Textual message dispatch (from ``MapCell``)
        """
        event.stop()
        cell = event.cell
        self._selected_cell_start = cell.cell_start
        body = self.query_one("#map_detail_body", Static)
        body.update(
            self.build_detail_text(cell.cell_start, cell.cell_end, cell.status)
        )
        self.query_one("#map_open_hex_button", Button).remove_class("hidden")

    def focus_adjacent_cell(self, current: "MapCell", key: str) -> None:
        """Move focus to the cell one arrow-step from ``current`` (US-036).

        Summary:
            Resolve the target cell index from ``adjacent_cell_index`` over the
            current ``#map_grid`` children (mount order) and the stored visual
            column count, then ``.focus()`` it. Focus clamps at the grid edges
            (no wrap). This only MOVES focus — selection stays on click/Enter,
            matching AT-036a (press Right, then Enter). The panel owns the cell
            list + column count, so ``MapCell`` needs no sibling access.

        Args:
            current (MapCell): The currently-focused cell.
            key (str): The arrow key pressed (``left``/``right``/``up``/
                ``down``).

        Returns:
            None

        Data Flow:
            - Reads the ``#map_grid`` ``MapCell`` children; computes the target
              via ``adjacent_cell_index``; calls ``.focus()`` on it (or on the
              same cell at an edge — a harmless no-op move).

        Dependencies:
            Uses:
                - ``adjacent_cell_index``
            Used by:
                - ``MapCell.on_key`` (arrow keys)
        """
        try:
            grid = self.query_one("#map_grid", Container)
        except Exception:
            return
        cells = list(grid.query(MapCell))
        if not cells or current not in cells:
            return
        index = cells.index(current)
        target = adjacent_cell_index(index, key, len(cells), self._grid_cols)
        if target is None:
            return
        cells[target].focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Post :class:`OpenInHexRequested` for the Open-in-Hex button.

        Summary:
            Translate the detail pane's "Open in Hex View" press into an
            :class:`OpenInHexRequested` carrying the selected cell's start so
            ``app.py`` drives ``update_hex_view`` and switches screen — the
            panel renders no hex itself (LLR-041.6).

        Args:
            event (Button.Pressed): The Textual button-press event.

        Dependencies:
            Uses:
                - ``OpenInHexRequested``
            Used by:
                - Textual button-press dispatch
        """
        if event.button.id != "map_open_hex_button":
            return
        event.stop()
        if self._selected_cell_start is not None:
            self.post_message(
                self.OpenInHexRequested(self._selected_cell_start)
            )


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

    class VariantSelected(Message):
        """The operator picked a variant from the Variant-pane dropdown (US-028).

        Summary:
            Posted when ``#patch_variant_select`` fires ``Select.Changed``
            with a concrete variant id (not the blank sentinel). Carries the
            bare id only — the panel owns no variant-set access and no
            activation logic; ``app.py`` routes the id wholesale through the
            existing ``_handle_select_variant`` pipeline (LLR-035.4). Blank /
            cleared selections post nothing (a blank is not a switch
            request), mirroring :class:`ChangeFileSelected`.

        Args:
            variant_id (str): The chosen variant's id, e.g. ``"b"`` (the
                FULL FILENAME when stems collide — the E6 duplicate-id rule).

        Dependencies:
            Used by:
                - ``S19TuiApp.on_patch_editor_panel_variant_selected``
        """

        def __init__(self, variant_id: str) -> None:
            super().__init__()
            self.variant_id = variant_id

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

    def set_variants(
        self,
        options: Sequence[tuple[str, str]],
        active_id: Optional[str] = None,
    ) -> None:
        """Populate the variant dropdown and mirror the active variant.

        Summary:
            Replace the ``#patch_variant_select`` options with the project's
            variant ids and pre-select the active one (LLR-035.3), mirroring
            :meth:`set_change_files`: the panel owns no ``_variant_set``
            access — ``app.py`` is the ONLY populator (the US-026 ownership
            split). ``set_options`` runs strictly BEFORE the value assignment
            (F-4: assigning a value not in the options raises
            ``InvalidSelectValueError``); the reset-to-blank-sentinel
            (``Select.NULL``) ``Changed`` echo pair a repopulate emits is
            absorbed by the ``Select.NULL`` / same-as-active
            short-circuits in the handler chain (LLR-035.4). An empty
            ``options`` clears the dropdown back to its blank placeholder
            with NO preselection (F-2), and the control is disabled whenever
            fewer than 2 options exist (LLR-035.5 — no false affordance for
            the no-project / single-variant states, DoR Q1).

        Args:
            options (Sequence[tuple[str, str]]): ``(label, variant_id)``
                pairs in model order (``ProjectVariantSet.variants``); empty
                for the no-project / N<2 states.
            active_id (Optional[str]): The ``variant_set.active_id`` to
                display, or ``None`` to leave the blank prompt.

        Returns:
            None

        Data Flow:
            - ``Select.set_options`` (resets the selection to the blank
              sentinel ``Select.NULL``), then
              the value assignment when ``active_id`` is provided with N >= 2,
              then the ``disabled`` invariant (``len(options) < 2``).

        Dependencies:
            Uses:
                - ``textual.widgets.Select.set_options``
            Used by:
                - ``S19TuiApp._refresh_patch_variant_select``

        Example:
            >>> panel.set_variants([("a", "a"), ("b", "b")], "b")
        """
        select = self.query_one("#patch_variant_select", Select)
        select.set_options(options)
        if active_id is not None and len(options) >= 2:
            select.value = active_id
        select.disabled = len(options) < 2

    def compose(self) -> ComposeResult:
        """Lay out the consolidated v2 Patch Editor widget tree as a 2x2 grid.

        Summary:
            Reparent the single change-flow section (LLR-003.1) into four
            area-pane :class:`Container` s laid out 2x2 (HLR-033.1) —
            ``#patch_pane_entries`` (top-left: entries table, empty-state,
            entry inputs), ``#patch_pane_changefile`` (top-right: the
            change-file row + the paste row), ``#patch_pane_checks``
            (bottom-left: the declaration-fault count + listing, the checks
            status line + results), and ``#patch_pane_variant``
            (bottom-right: the variant-dropdown row composed ABOVE the
            execute-over-variants row, LLR-035.2 — the switch affordance
            stays visible at scroll 0 while the execute group scrolls below
            when the pane overflows at 80x24). Each inner
            sub-tree is moved wholesale — no inner id is renamed or
            reordered, so every ``patch_*`` id and its action wiring stay
            queryable (HLR-033.2). The hidden save-back prompt row is yielded
            as a direct grid child after the four panes with ``column-span:
            2`` (LLR-033.4), landing in the grid's ``auto`` third row so it
            spans full width when shown without squeezing a pane. The panel
            itself is styled ``layout: grid`` (styles.tcss), so each pane
            scrolls vertically and independently (HLR-033.3).

        Args:
            None

        Returns:
            ComposeResult: The Patch Editor widget tree — four ``#patch_pane_*``
            containers plus the spanning save-back row.

        Data Flow:
            - Each pane ``Container`` wraps its area's pre-existing widget
              sub-tree intact; the panel's ``layout: grid; grid-size: 2 3``
              CSS places the four panes in the top two ``1fr`` rows and the
              save-back span in the ``auto`` third row.

        Dependencies:
            Used by:
                - Textual ``ScrollableContainer`` compose lifecycle
        """
        yield Container(
            Label(
                "Change document (v2 JSON)", classes="patch-section-title"
            ),
            DataTable(
                id="patch_doc_entries_table",
                zebra_stripes=True,
                cursor_type="row",
            ),
            Static(
                self.EMPTY_STATE_TEXT,
                id="patch_doc_empty_state",
                markup=False,
            ),
            Container(
                Label("Address", classes="patch-field-label"),
                Input(placeholder="0x100", id="patch_entry_address_input"),
                Label("String value", classes="patch-field-label"),
                Input(
                    placeholder="text (document encoding)",
                    id="patch_entry_value_input",
                ),
                Label("Bytes", classes="patch-field-label"),
                Input(
                    placeholder="DE AD BE EF", id="patch_entry_bytes_input"
                ),
                Horizontal(
                    Button("Add", id="patch_entry_add_button"),
                    Button("Edit", id="patch_entry_edit_button"),
                    Button("Remove", id="patch_entry_remove_button"),
                    id="patch_doc_entry_buttons",
                ),
                id="patch_doc_entry_inputs",
            ),
            id="patch_pane_entries",
        )
        yield Container(
            Container(
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
                    "Checks: runs the loaded change document's checks "
                    "against the loaded image.",
                    id="patch_checks_help",
                    classes="patch-field-label",
                ),
                id="patch_doc_file_row",
            ),
            Container(
                Label(
                    "Paste change-set (v2 JSON)",
                    classes="patch-field-label",
                ),
                TextArea(DUMMY_CHANGESET_TEXT, id="patch_paste_text"),
                Horizontal(
                    Button("Parse pasted", id="patch_paste_parse_button"),
                    id="patch_paste_controls",
                ),
                id="patch_paste_row",
            ),
            id="patch_pane_changefile",
        )
        yield Container(
            Label(
                "", id="patch_doc_issue_count", classes="patch-field-label"
            ),
            Static(
                "", id="patch_doc_issues", markup=False, classes="hidden"
            ),
            Label("", id="patch_checks_status", classes="patch-field-label"),
            Container(id="patch_checks_results"),
            id="patch_pane_checks",
        )
        yield Container(
            Container(
                Label("Active variant", classes="patch-field-label"),
                Select(
                    [],
                    id="patch_variant_select",
                    prompt="Variants in project",
                    allow_blank=True,
                    disabled=True,
                ),
                id="patch_variant_row",
            ),
            Container(
                Label(
                    "Execute over variants", classes="patch-field-label"
                ),
                Horizontal(
                    Button(
                        f"Scope: {self._SCOPE_LABELS[self._execute_scope]}",
                        id="patch_execute_scope_button",
                    ),
                    Button("Execute scope", id="patch_execute_run_button"),
                    id="patch_execute_buttons",
                ),
                id="patch_execute_row",
            ),
            id="patch_pane_variant",
        )
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
        """Forward a dropdown pick to ``app.py`` (US-026 / US-028).

        Summary:
            When ``#patch_doc_file_select`` changes to a concrete filename,
            post a :class:`ChangeFileSelected` carrying the bare name so the app
            re-resolves it under the patches folder (with the LLR-030.3
            containment guard) and loads it via the existing
            ``ChangeService.load`` path. When ``#patch_variant_select``
            changes to a concrete variant id, post a :class:`VariantSelected`
            so the app routes it through the existing activation pipeline
            (LLR-035.4). A blank selection (``Select.NULL`` — the
            ``NoSelection`` placeholder emitted when ``set_change_files`` /
            ``set_variants`` repopulates or clears the option set) is NOT a
            request, so nothing is posted. Only this panel's own two selects
            are handled; other ``Select`` widgets are left for their own
            handlers.

        Args:
            event (Select.Changed): The Textual select-change event; its
                ``select.id`` and ``value`` identify the widget and choice.

        Returns:
            None

        Data Flow:
            - Ignore events from other selects and the blank sentinel, else
              post ``VariantSelected(str(value))`` for the variant dropdown
              or ``ChangeFileSelected(str(value))`` for the change-file one.

        Dependencies:
            Uses:
                - ``ChangeFileSelected`` / ``VariantSelected``
            Used by:
                - Textual select-change dispatch
        """
        if event.select.id == "patch_variant_select":
            # ``Select.NULL`` is the installed textual 8.2.5 blank sentinel
            # (a ``NoSelection`` instance) — ``Select.BLANK`` resolves to an
            # unrelated inherited ``Widget.BLANK`` bool in this version and
            # never matches a blank value.
            if event.value is Select.NULL:
                return
            event.stop()
            self.post_message(self.VariantSelected(str(event.value)))
            return
        if event.select.id != "patch_doc_file_select":
            return
        if event.value is Select.NULL:
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
        """Return the chosen variant id, or ``None`` for the external option
        or a blank select (``Select.NULL`` — the no-selection sentinel)."""
        value = self.query_one(select_id, Select).value
        if value in (self._EXTERNAL_OPTION, Select.NULL):
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
