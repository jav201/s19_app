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
  - ``FlowBuilderPanel`` — the rail-8 Flow Builder (R-TUI-059 tracer): a
    dropdown-add block list + Run that composes a typed-block pipeline and
    emits ``RunRequested`` for the app to execute via ``run_flow``.

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

import bisect
from dataclasses import dataclass
from math import ceil
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import (
    Container,
    Horizontal,
    ScrollableContainer,
    Vertical,
    VerticalScroll,
)
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

from .capped_text_area import CappedTextArea
from .changes.io import DUMMY_CHANGESET_TEXT
from .color_policy import css_class_for_severity
from .entropy_style import ENTROPY_BAND_LABELS, band_style
from .insight_style import (
    CYAN,
    DGRAY,
    GREEN,
    PURPLE,
    RED,
    VALUE,
    YELLOW,
    human_bytes,
    label_value,
    microbar,
)
from .os_clipboard_input import OsClipboardInput
from ..range_index import address_in_sorted_ranges, build_sorted_range_index
from .services.entropy_service import EntropyWindow
from .services.flow_model import (
    BLOCK_PATCH,
    BLOCK_SOURCE,
    BLOCK_WRITE_OUT,
    Flow,
    FlowBlock,
    FlowRunResult,
    PatchBlock,
    SourceBlock,
    WriteOutBlock,
)
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

    PROMPT_TEXT = (
        "No file loaded - press Ctrl+L (or 'l') to load a file, "
        "or 'p' to load a saved project."
    )

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


#: Total character width the entropy band bar is drawn across (batch-45,
#: R-TUI-060). Fixed so each run's segment width is a deterministic function of
#: ``round(_BAND_BAR_WIDTH * run_bytes / total_bytes)`` — independent of live
#: layout geometry, exactly as the cell count was kept geometry-pure (LLR-041.2).
_BAND_BAR_WIDTH = 60

#: 9-glyph entropy ramp (0.0 → 8.0 bits/byte) for the At-a-glance sparkline
#: (batch-45, R-TUI-061 / LLR-045B.2). Index 0 = a space (near-zero entropy),
#: index 8 = a full block (maximal entropy). Mirrors the prototype ``BARS``.
_ENTROPY_BAR_RAMP = " ▁▂▃▄▅▆▇█"

#: Fixed histogram bar width for the At-a-glance per-band rows (LLR-045B.1) —
#: geometry-pure like ``_BAND_BAR_WIDTH``.
_GLANCE_BAR_WIDTH = 6

#: Fixed number of sparkline columns the profile is sampled to (LLR-045B.2).
_SPARKLINE_WIDTH = 24

#: Cell width of the per-region size micro-bar on each ``RegionRow`` (batch-47,
#: R-TUI-073 / LLR-073.1). Kept short so the enriched row (glyph · addr · size ·
#: bar · N sym · band · ↵) fits the tightest measured region-row width — 52 cols
#: at 120x30 (C-29 pilot measurement, Inc-6).
_REGION_MICROBAR_WIDTH = 4

#: App-supplied hatch glyph marking an unmapped address gap in the band strip
#: (batch-47, R-TUI-072 / LLR-072.1). NOT an entropy band and NOT sourced from
#: ``entropy_style`` — the strip's band glyphs come from ``ENTROPY_BAND_GLYPH``.
_MAP_GAP_HATCH = "╱"

#: Open-in-hex affordance glyph on each ``RegionRow`` (batch-47, LLR-073.2). A
#: hint that a single click drives the reused ``RegionRow.Activated`` nav.
_OPEN_IN_HEX_GLYPH = "↵"  # ↵

#: Target row count for the Memory-Map region inspector hex peek (batch-47,
#: R-TUI-074 / LLR-074.2). The ``#map_detail`` pane is ``height: auto`` and
#: reachable under scroll (C-29 pilot: 2 visible rows @120x30 / 1 @80x24; the
#: detail Static already overflows-under-scroll by the batch-45 design), so a
#: 3-row peek is content that is reachable under scroll, never clipped.
_MAP_PEEK_ROWS = 3


def entropy_ramp_glyph(entropy: float) -> str:
    """Map a Shannon entropy value (0.0–8.0) to its :data:`_ENTROPY_BAR_RAMP` glyph.

    Summary:
        Round ``entropy`` to the nearest integer band index and clamp it into
        ``[0, 8]`` to pick one of the nine ramp glyphs (batch-45, R-TUI-061 /
        LLR-045B.2). A constant-fill window (``0.0``) maps to the leading space;
        a maximal-entropy window (``8.0``) to the full block.

    Args:
        entropy (float): Entropy in bits/byte, normally ``0.0 ≤ H ≤ 8.0``.

    Returns:
        str: The single ramp glyph for ``entropy``.

    Data Flow:
        - Called once per sampled window by :func:`sparkline_glyphs` /
          :func:`_sparkline_segments`.

    Dependencies:
        Uses:
            - _ENTROPY_BAR_RAMP
        Used by:
            - sparkline_glyphs / _sparkline_segments / tests

    Example:
        >>> entropy_ramp_glyph(0.0), entropy_ramp_glyph(8.0)
        (' ', '█')
    """
    index = int(round(entropy))
    index = max(0, min(len(_ENTROPY_BAR_RAMP) - 1, index))
    return _ENTROPY_BAR_RAMP[index]


def band_histogram(
    runs: Sequence[Tuple[str, int, int]],
) -> List[Tuple[str, int, float]]:
    """Tally merged region runs per band into ``(band, count, pct)`` rows.

    Summary:
        Count how many merged region runs fall in each band and compute each
        band's share of the total region count (batch-45, R-TUI-061 /
        LLR-045B.1). Rows are returned for OCCUPIED bands only (count > 0), in
        the canonical :data:`ENTROPY_BAND_LABELS` order. The count is a REGION
        (merged-run) count — consistent with the region list — not a raw
        window count. A pure tally over the already-merged runs; no re-parse.

    Args:
        runs (Sequence[Tuple[str, int, int]]): The merged
            ``(band, bytes, start)`` runs from :func:`_merge_band_runs`.

    Returns:
        List[Tuple[str, int, float]]: One ``(band_label, region_count,
        percentage)`` per occupied band, in band order; ``[]`` when ``runs`` is
        empty. Percentages are ``100 * count / total`` and sum to ~100.

    Data Flow:
        - Reads each run's band; produces the histogram rows the At-a-glance
          panel renders.

    Dependencies:
        Uses:
            - ENTROPY_BAND_LABELS
        Used by:
            - MemoryMapPanel._build_glance_widgets / tests

    Example:
        >>> band_histogram([("low", 256, 0), ("low", 256, 4096),
        ...                 ("high/random", 256, 8192)])
        [('low', 2, 66.66666666666667), ('high/random', 1, 33.33333333333333)]
    """
    total = len(runs)
    if total == 0:
        return []
    counts = {label: 0 for label in ENTROPY_BAND_LABELS}
    for band, _bytes, _start in runs:
        if band in counts:
            counts[band] += 1
    return [
        (label, counts[label], 100.0 * counts[label] / total)
        for label in ENTROPY_BAND_LABELS
        if counts[label] > 0
    ]


def sparkline_glyphs(windows: Sequence[EntropyWindow], width: int) -> str:
    """Sample the entropy profile to a fixed-width ramp-glyph string.

    Summary:
        Sub-sample ``windows`` with step ``max(1, N // width)`` and map each
        sampled window's entropy to its :func:`entropy_ramp_glyph` (batch-45,
        R-TUI-061 / LLR-045B.2). The plain (uncoloured) glyph string; the
        rendered sparkline colours it per band via :func:`_sparkline_segments`.

    Args:
        windows (Sequence[EntropyWindow]): The loader-computed entropy windows.
        width (int): Target column budget the profile is sampled down to.

    Returns:
        str: One ramp glyph per sampled window; ``""`` for empty input.

    Data Flow:
        - Reads each sampled window's ``entropy``; used by the pure unit test
          and any plain-text sparkline read.

    Dependencies:
        Uses:
            - entropy_ramp_glyph
        Used by:
            - tests (TC-061.2)

    Example:
        >>> from s19_app.tui.services.entropy_service import EntropyWindow
        >>> w = lambda e: EntropyWindow(0, 256, 256, e, "x", False)
        >>> sparkline_glyphs([w(0.0), w(8.0)], 24)
        ' █'
    """
    if not windows:
        return ""
    step = max(1, len(windows) // max(1, width))
    return "".join(entropy_ramp_glyph(w.entropy) for w in windows[::step])


def _sparkline_segments(
    windows: Sequence[EntropyWindow], width: int
) -> List[Tuple[str, str]]:
    """Sample the profile and group it into ``(band, glyphs)`` colour segments.

    Summary:
        Sub-sample ``windows`` (step ``max(1, N // width)``) and group
        consecutive sampled windows of the SAME band into runs, each carrying
        that band's concatenated ramp glyphs (batch-45, LLR-045B.2). One
        band-styled ``Static`` per segment lets the sparkline be band-coloured
        through the ``band-*`` CSS classes (single colour source) rather than
        per-glyph widgets or hard-coded Rich colours.

    Args:
        windows (Sequence[EntropyWindow]): The loader-computed entropy windows.
        width (int): Target column budget for sampling.

    Returns:
        List[Tuple[str, str]]: ``(band, glyphs)`` colour segments in profile
        order; ``[]`` for empty input.

    Data Flow:
        - Reads each sampled window's ``band`` + ``entropy``; produces the
          per-band sparkline segments the panel mounts.

    Dependencies:
        Uses:
            - entropy_ramp_glyph
        Used by:
            - MemoryMapPanel._build_glance_widgets
    """
    if not windows:
        return []
    step = max(1, len(windows) // max(1, width))
    segments: List[Tuple[str, str]] = []
    for window in windows[::step]:
        glyph = entropy_ramp_glyph(window.entropy)
        if segments and segments[-1][0] == window.band:
            band, glyphs = segments[-1]
            segments[-1] = (band, glyphs + glyph)
        else:
            segments.append((window.band, glyph))
    return segments


def _merge_band_runs(
    windows: Sequence[EntropyWindow],
) -> List[Tuple[str, int, int]]:
    """Merge contiguous same-band entropy windows into region runs.

    Summary:
        Collapse an ascending-address ``EntropyWindow`` sequence into one run
        per maximal stretch of ADDRESS-CONTIGUOUS same-band windows, summing
        their byte counts (batch-45, R-TUI-060 / LLR-045A.4). A run extends
        onto the next window only when the band matches AND the window is
        physically adjacent (``run_start + run_total == window.start``); a band
        change OR an address discontinuity starts a new run. The contiguity
        break matters because ``compute_entropy`` walks per-contiguous-range,
        so two physically separate same-band regions (e.g. two padding blocks
        across an address gap) sit back-to-back in the window list and must NOT
        collapse into one span (review F1). Pure arithmetic over already-
        computed windows — no re-parse, no entropy recomputation.

    Args:
        windows (Sequence[EntropyWindow]): The loader-computed
            ``LoadedFile.entropy_windows`` in ascending address order.

    Returns:
        List[Tuple[str, int, int]]: One ``(band_label, summed_bytes,
        start_addr)`` per run, in window order; ``[]`` for empty input.

    Data Flow:
        - Reads each window's ``band`` / ``sample_count`` / ``start``; produces
          the run list the band bar + region list render from.

    Dependencies:
        Used by:
            - ``MemoryMapPanel.render_ranges`` (band bar + region list)

    Example:
        >>> from s19_app.tui.services.entropy_service import EntropyWindow
        >>> w = lambda s, band: EntropyWindow(s, s + 256, 256, 0.0, band, False)
        >>> _merge_band_runs([w(0, "low"), w(256, "low"), w(512, "high/random")])
        [('low', 512, 0), ('high/random', 256, 512)]
        >>> _merge_band_runs([w(0, "low"), w(4096, "low")])  # gap → 2 runs
        [('low', 256, 0), ('low', 256, 4096)]
    """
    runs: List[Tuple[str, int, int]] = []
    for window in windows:
        if (
            runs
            and runs[-1][0] == window.band
            and runs[-1][2] + runs[-1][1] == window.start
        ):
            band, total, start = runs[-1]
            runs[-1] = (band, total + window.sample_count, start)
        else:
            runs.append((window.band, window.sample_count, window.start))
    return runs


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


def _tag_address(tag: Mapping[str, Any]) -> Optional[int]:
    """Return an A2L tag's integer address, or ``None`` for a hostile shape.

    Summary:
        Extract the ``address`` of an enriched A2L tag as a real ``int``,
        rejecting the same hostile shapes ``symbols_in_window`` rejects — a
        non-dict tag, a missing/``None``/``str`` address, or a ``bool`` (which
        is an ``int`` subclass but is never a valid address). The shared guard
        keeps the region-row symbol count (LLR-073.1) aligned with the
        detail-pane symbol join.

    Args:
        tag (Mapping[str, Any]): One enriched A2L tag dict.

    Returns:
        Optional[int]: The tag's address as an ``int``, or ``None`` when the
        shape is malformed.

    Data Flow:
        - Read-only over one already-parsed tag dict; no analysis.

    Dependencies:
        Used by:
            - ``MemoryMapPanel._build_band_widgets`` (per-region ``N sym`` count)

    Example:
        >>> _tag_address({"name": "CAL", "address": 0x10})
        16
        >>> _tag_address({"name": "CAL", "address": True}) is None
        True
    """
    if not isinstance(tag, dict):
        return None
    addr = tag.get("address")
    if isinstance(addr, bool) or not isinstance(addr, int):
        return None
    return addr


def symbols_in_window(
    tags: Sequence[Mapping[str, Any]],
    start: int,
    end: int,
) -> List[str]:
    """Names of A2L symbols whose extent overlaps ``[start, end)`` (R-TUI-041 R-3).

    Summary:
        Join the already-computed enriched A2L tags to a memory window: a tag
        overlaps ``[start, end)`` iff ``addr < end and addr + size > start``,
        where ``size`` is the tag's positive-int ``byte_size`` else ``1`` (a
        point) — the same extent convention ``resolve_report_filter`` uses. The
        result is the overlapping tags' ``name`` strings, address-then-name
        sorted, for markup-safe display in the detail pane and cell tooltips.
        Read-only over the load snapshot; computes no coverage/parse/validation
        (LLR-041.7). Hostile-shape-safe (S-F4): a non-dict tag, a non-int / None
        ``address``, a non-str / empty ``name`` is skipped, never raised.

    Args:
        tags (Sequence[Mapping[str, Any]]): The enriched A2L tags
            (``S19TuiApp._a2l_enriched_tags``) — dicts with ``name`` /
            ``address`` (int, or ``None`` when absent) and optional
            ``byte_size``.
        start (int): Inclusive window start.
        end (int): Exclusive window end.

    Returns:
        List[str]: Overlapping tags' names, address-then-name sorted.

    Data Flow:
        - Called by ``MemoryMapPanel.build_detail_text`` (region window) and
          ``MemoryMapPanel.render_ranges`` (per-cell tooltip window).

    Dependencies:
        Used by:
            - ``MemoryMapPanel.build_detail_text``
            - ``MemoryMapPanel.render_ranges``

    Example:
        >>> symbols_in_window(
        ...     [{"name": "CAL", "address": 0x10, "byte_size": 4}], 0x10, 0x20
        ... )
        ['CAL']
    """
    matched: List[Tuple[int, str]] = []
    for tag in tags:
        if not isinstance(tag, dict):
            continue
        addr = tag.get("address")
        if not isinstance(addr, int) or isinstance(addr, bool):
            continue
        size = tag.get("byte_size")
        extent = (
            size
            if isinstance(size, int) and not isinstance(size, bool) and size > 0
            else 1
        )
        if addr < end and addr + extent > start:
            name = tag.get("name")
            if isinstance(name, str) and name:
                matched.append((addr, name))
    matched.sort(key=lambda item: (item[0], item[1]))
    return [name for _addr, name in matched]


def symbol_list_text(names: Sequence[str], cap: int = 3) -> Text:
    """Markup-safe ``Text`` of up to ``cap`` symbol names + a ``"+N more"`` tail.

    Summary:
        Compose a comma-joined run of the first ``cap`` names as markup-safe
        ``Text`` segments (each via ``safe_text``, so a hostile name like
        ``evil[red]`` renders literally — LLR-041.11 / the batch-27 markup
        BLOCKER class), followed by ``" +N more"`` when more names overlap. The
        whole aggregate is ``Text``; no name is ever formatted into an f-string
        (the sink that would re-introduce Rich-markup parsing, incl. the tooltip
        path where Textual markup-parses a bare ``str``).

    Args:
        names (Sequence[str]): The overlapping symbol names (from
            ``symbols_in_window``), already ordered.
        cap (int): Maximum names shown before the ``"+N more"`` tail.

    Returns:
        Text: The composed markup-safe label (empty ``Text`` when ``names`` is
        empty).

    Dependencies:
        Uses:
            - ``safe_text``
        Used by:
            - ``MemoryMapPanel.build_detail_text``
            - ``MemoryMapPanel.render_ranges``
    """
    text = Text()
    shown = list(names[:cap])
    for index, name in enumerate(shown):
        if index:
            text.append(", ")
        text.append(safe_text(name))
    remaining = len(names) - len(shown)
    if remaining > 0:
        text.append(f" +{remaining} more")
    return text


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


class RegionRow(Static):
    """A single clickable entropy region-list row (batch-45, R-TUI-062).

    Summary:
        One row of the ``.map-region-list`` — an address · size · band summary
        of one merged entropy run. A SINGLE real click posts
        :class:`Activated` carrying the run's ``[region_start, region_end)``
        window; the enclosing :class:`MemoryMapPanel` handles it by populating
        the detail pane (``build_detail_text``, keeping the R-TUI-041 R-3 A2L
        naming + its C-17 markup-safety guard alive on a live path) and posting
        :class:`MemoryMapPanel.OpenInHexRequested` for direct region→hex nav
        (LLR-045C.1 — no reveal-button, no two-step). The row itself shows
        addr/size/band ONLY — no file-derived A2L text (security B3). A click on
        padding/legend/empty area hits no ``RegionRow`` and is an inert no-op
        (LLR-045C.3).

    Args:
        content (Text): The markup-safe ``{glyph} 0x.. · N B · band`` row text.
        region_start (int): Inclusive start address of the run.
        region_end (int): Exclusive end address of the run
            (``region_start + run_bytes``).
        classes (str): Space-joined CSS classes (``map-region-row`` + the
            run's ``band-*`` token).

    Data Flow:
        - Mounted by ``MemoryMapPanel._build_band_widgets``; on click posts
          :class:`Activated` → ``MemoryMapPanel.on_region_row_activated``.

    Dependencies:
        Used by:
            - ``MemoryMapPanel._build_band_widgets``
    """

    class Activated(Message):
        """A region row was clicked (single-click region→hex + detail).

        Args:
            region_start (int): The run's inclusive start address (the hex
                focus address).
            region_end (int): The run's exclusive end address.
        """

        def __init__(self, region_start: int, region_end: int) -> None:
            super().__init__()
            self.region_start = region_start
            self.region_end = region_end

    def __init__(
        self,
        content: Text,
        region_start: int,
        region_end: int,
        classes: str,
    ) -> None:
        super().__init__(content, classes=classes)
        self.region_start = region_start
        self.region_end = region_end

    def on_click(self) -> None:
        """Post :class:`Activated` for this region on a single click."""
        self.post_message(self.Activated(self.region_start, self.region_end))


class MapRuler(Horizontal):
    """Address ruler beneath the entropy band strip (batch-47, R-TUI-072).

    Summary:
        A single-row ruler of exactly five evenly-spaced tick labels at
        0 / 25 / 50 / 75 / 100 % of the image address span (LLR-072.3): tick 0 %
        is the span start and tick 100 % is the span end. Each tick is a
        markup-safe ``.map-ruler-tick`` ``Static`` distributed by ``width: 1fr``
        so the five labels spread across the strip without overlap at both the
        80x24 and 120x30 regimes (C-29 two-axis pilot: the ruler spans the full
        ``#map_grid`` content width — 66 cols @80x24, 52 cols @120x30). Labels
        are 8 hex digits WITHOUT the ``0x`` prefix (C-13.1 deficit-matched
        fallback: five ``0x``-prefixed labels overflow the 52-col grid @120x30;
        dropping ``0x`` recovers 2 cols/label = 10 cols, which fits). The widget
        is self-styled via ``DEFAULT_CSS`` (no ``styles.tcss`` edit) and carries
        NO member named ``_nodes`` / ``_context`` (Textual internal-shadowing
        guard — verified ``set(dir(Widget)) & {_span_start, _span_end} == ∅``).

    Args:
        span_start (int): Inclusive image span start (0 % tick address).
        span_end (int): Exclusive image span end (100 % tick address).

    Data Flow:
        - Built by ``MemoryMapPanel._build_band_widgets`` from the same
          ``derive_image_span`` bounds the band bar uses; mounted as a
          ``#map_grid`` child beneath the band row.

    Dependencies:
        Uses:
            - ``safe_text`` (markup-safe tick labels)
        Used by:
            - ``MemoryMapPanel._build_band_widgets``

    Example:
        >>> ruler = MapRuler(0x80000000, 0x80010000)
        >>> ruler._span_start, ruler._span_end
        (2147483648, 2147549184)
    """

    #: Number of ruler ticks (0/25/50/75/100 %). Fixed by LLR-072.3.
    _TICK_COUNT = 5

    DEFAULT_CSS = """
    MapRuler {
        width: 100%;
        height: 1;
        layout: horizontal;
    }
    MapRuler .map-ruler-tick {
        width: 1fr;
        height: 1;
    }
    """

    def __init__(self, span_start: int, span_end: int) -> None:
        super().__init__(classes="map-ruler")
        self._span_start = span_start
        self._span_end = span_end

    def compose(self) -> ComposeResult:
        """Yield the five markup-safe tick labels across the span.

        Summary:
            Emit one ``.map-ruler-tick`` ``Static`` per tick at
            ``i / (N-1)`` of the span for ``i in 0..N-1``; tick 0 is exactly the
            span start and the final tick is exactly the span end (no rounding
            drift at the endpoints, LLR-072.3). Labels are 8-hex-digit addresses.

        Returns:
            ComposeResult: five ``.map-ruler-tick`` ``Static`` widgets.

        Dependencies:
            Uses:
                - ``safe_text``
            Used by:
                - Textual mount pipeline
        """
        span = self._span_end - self._span_start
        last = self._TICK_COUNT - 1
        for index in range(self._TICK_COUNT):
            if index == last:
                addr = self._span_end
            else:
                addr = self._span_start + span * index // last
            yield Static(safe_text(f"{addr:08X}"), classes="map-ruler-tick")


class MemoryMapPanel(Container):
    """Entropy band view of the loaded image's mapped memory.

    Summary:
        Renders the image as an ENTROPY band view (batch-45, R-TUI-060): a
        proportional band bar + a per-region list (address · size · band) + a
        band legend, merged by ``_merge_band_runs`` from the loader-computed
        ``LoadedFile.entropy_windows`` handed to ``render_ranges``. This
        replaced the batch-27 ``sev-*`` validity cell grid (the ``MapCell`` +
        arrow-nav machinery was removed in batch-45 Inc-5; a single click on a
        region row drives detail + hex nav via ``on_region_row_activated``). It
        is a pure presentational widget — it performs NO entropy, coverage,
        parsing or validation of its own (LLR-045A.2 / LLR-041.7).
        Band colours route through the ``band-*`` CSS classes owned by
        ``entropy_style`` + ``styles.tcss`` (LLR-045A.3); no colour hex is
        hard-coded. The coverage stats strip is retained unchanged. With no
        image / no entropy it preserves the neutral no-data note (LLR-045A.5).

    Args:
        None

    Returns:
        None

    Data Flow:
        - ``render_ranges`` receives the pre-computed ``ranges`` +
          ``range_validity`` + ``entropy_windows`` from
          ``S19TuiApp.update_memory_map``, merges contiguous same-band windows
          via ``_merge_band_runs``, and mounts ``.map-band-seg`` segments (the
          band bar) plus the ``.map-region-row`` region list, the band legend,
          and the docked ``.at-a-glance`` histogram/sparkline into
          ``#map_grid`` — no per-cell ``.map-cell`` widgets are mounted.
        - Clicking a region row drives ``on_region_row_activated`` → populates
          ``#map_detail`` (via ``build_detail_text``: status chip, covering
          region, A2L symbols, issues) and posts ``OpenInHexRequested`` for
          single-click hex nav; the ``#map_stats`` strip shows the seven
          coverage statistics derived by ``coverage_stats`` (US-037 / LLR-041.8).
        - With no ranges / no entropy the header shows the neutral empty note,
          no segments/rows are mounted, and the stats strip is blanked (LLR-041.9).
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
    _DETAIL_HINT = "Click a region row to inspect it and jump to the hex view."

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
        #: The enriched A2L tags handed in by ``update_memory_map`` (R-TUI-041
        #: R-3) — the read-only source for naming a region by the A2L symbol(s)
        #: overlapping it (region-triggered detail pane). Never re-parsed;
        #: joined via ``symbols_in_window``.
        self._a2l_tags: List[Mapping[str, Any]] = []
        #: The currently-selected region's start address, or ``None`` before any
        #: selection — carried on the Open-in-Hex message (LLR-041.6 / R-TUI-062).
        self._selected_cell_start: Optional[int] = None
        #: ``{region_start: band_label}`` for the last render's merged runs
        #: (batch-47, R-TUI-074) — the inspector reads a region's dominant band
        #: from its own run rather than recomputing entropy (LLR-074.1).
        self._run_bands: Dict[int, str] = {}
        #: The loaded image's address→byte map handed in by ``update_memory_map``
        #: (batch-47, R-TUI-074) — the read-only source for the inspector hex
        #: peek (LLR-074.2). Empty on the no-file path; never re-parsed.
        self._mem_map: Mapping[int, int] = {}

    def compose(self) -> ComposeResult:
        """Compose the header, the band-view body and the (empty) placeholders.

        Summary:
            Yield the full-width header, then a ``#map_body`` horizontal
            sub-container holding the ``#map_grid`` band-view container and the
            ``#map_detail`` pane side by side (the wide-regime layout;
            ``#map_body`` stacks them vertically under ``width-narrow`` — the
            reflow lives in ``styles.tcss``), and finally the full-width
            ``#map_stats`` coverage strip (US-037 / LLR-041.8).

        Returns:
            ComposeResult: the header, the band-view + detail body, and the
            stats strip.

        Dependencies:
            Used by:
                - Textual mount pipeline
        """
        yield Label(self._EMPTY_TEXT, id="map_header", markup=False)
        yield Horizontal(
            Container(id="map_grid"),
            Container(
                Static(safe_text(self._DETAIL_HINT), id="map_detail_body"),
                id="map_detail",
            ),
            id="map_body",
        )
        yield Container(Static("", id="map_stats_body"), id="map_stats")

    def render_ranges(
        self,
        ranges: Sequence[Tuple[int, int]],
        range_validity: Sequence[bool],
        issues: Sequence[ValidationIssue] = (),
        a2l_tags: Sequence[Mapping[str, Any]] = (),
        entropy_windows: Sequence[EntropyWindow] = (),
        mem_map: Optional[Mapping[int, int]] = None,
    ) -> None:
        """Render the entropy band view from already-computed windows.

        Summary:
            Merge the loader-computed ``entropy_windows`` into contiguous
            same-band runs and render the Memory-Map body as a proportional
            band bar + a per-region list + a band legend (batch-45, R-TUI-060 /
            LLR-045A.2..045A.6). This REPLACES the batch-27 ``sev-*`` validity
            cell grid — no ``MapCell`` is mounted. All input is consumed
            verbatim from the ``LoadedFile`` snapshot; no range is re-derived
            and no entropy/coverage/validation is computed here (LLR-045A.2 M4,
            LLR-041.7). Every segment/row is a widget carrying its
            ``band-*`` CSS class (colour owned by ``styles.tcss``) with
            markup-safe ``Text`` content (LLR-041.11). The coverage stats strip
            is retained unchanged (validity signal). The ordered ranges + issue
            list are still stored so the retained ``build_detail_text`` (re-wired
            to region-row selection in a later increment) stays usable.

        Args:
            ranges (Sequence[Tuple[int, int]]): Contiguous ``(start, end)``
                memory ranges from ``LoadedFile.ranges`` (``end`` exclusive) —
                used only for the retained coverage stats strip.
            range_validity (Sequence[bool]): Per-range validity flags from
                ``LoadedFile.range_validity``, positionally aligned with
                ``ranges`` — used only for the coverage stats strip.
            issues (Sequence[ValidationIssue]): The already-computed
                ``S19TuiApp._validation_issues`` — the canonical source for the
                stats strip issue count and the retained detail-pane join
                (LLR-041.5); defaults to empty for the headless path.
            a2l_tags (Sequence[Mapping[str, Any]]): The enriched A2L tags for
                the retained detail-pane region naming (R-TUI-041 R-3);
                deliberately NOT used by the new region-list rows, which are
                addr/size/band-only (security B3).
            entropy_windows (Sequence[EntropyWindow]): The loader-computed
                per-window entropy over the image (``LoadedFile.entropy_windows``);
                empty on the no-file path. The trailing default keeps every
                pre-batch-45 caller working (C-26 safe, mirrors the batch-43
                ``a2l_tags`` 4th-arg pattern).
            mem_map (Optional[Mapping[int, int]]): The loaded image's
                address→byte map (``LoadedFile.mem_map``), read-only, for the
                region-inspector hex peek (batch-47, R-TUI-074 / LLR-074.2).
                ``None`` (the default) keeps every pre-batch-47 caller working
                and leaves the peek empty (C-26 safe, same trailing-default
                pattern as ``entropy_windows``).

        Returns:
            None

        Data Flow:
            - When there is no image or no entropy (``ranges`` empty, zero
              span, or ``entropy_windows`` empty), show the neutral no-data
              note, mount no segments/rows and blank the stats strip — never
              raise (LLR-045A.5 / LLR-041.9).
            - Otherwise merge windows via ``_merge_band_runs`` and mount the
              band bar (``.map-band-bar``), region list (``.map-region-list``)
              and legend (``.map-band-legend``) into ``#map_grid``; the header
              shows a band summary. The summary is stored on ``rendered_text``.
              These three are addressed by CLASS (not id) because they are
              re-mounted every render (an id would trip ``DuplicateIds``).

        Dependencies:
            Uses:
                - ``_merge_band_runs`` / ``band_style`` / ``ENTROPY_BAND_LABELS``
                  / ``safe_text`` / ``derive_image_span``
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
        self._a2l_tags = list(a2l_tags)
        self._mem_map = mem_map or {}
        self._run_bands = {}
        self._reset_detail()

        span_start, span_end = derive_image_span(ranges)
        span = span_end - span_start
        if not ranges or span <= 0 or not entropy_windows:
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

        runs = _merge_band_runs(entropy_windows)
        self._run_bands = {start: band for band, _run_bytes, start in runs}
        grid.mount(
            *self._build_band_widgets(runs, entropy_windows, span_start, span_end)
        )

        total_bytes = sum(run_bytes for _band, run_bytes, _start in runs)
        summary = f"Entropy bands - {len(runs)} region(s), {total_bytes} B mapped"
        self.rendered_text = summary
        header.update(safe_text(summary))

        self._render_stats(ranges, range_validity, self._issues, empty=False)

    def _region_symbol_counts(
        self, runs: Sequence[Tuple[str, int, int]]
    ) -> Dict[int, int]:
        """Count A2L enriched-tag addresses per region via ``range_index``.

        Summary:
            Return ``{region_start: N sym}`` — the number of ``_a2l_enriched_tags``
            addresses falling inside each merged run's ``[start, start+bytes)``
            span (batch-47, R-TUI-073 / LLR-073.1). Built with the frozen
            ``range_index`` membership primitives, NOT a linear
            O(tags × regions) scan: one ``build_sorted_range_index`` over ALL
            region ranges (O(R log R)), then a single pass over the tags where
            each address is tested with ``address_in_sorted_ranges`` (O(log R))
            and, when it hits, located to its owning region by the same
            ``bisect_right`` on the shared ``starts`` vector that the primitive
            uses internally — O(T log R) total, no per-region re-scan.

        Args:
            runs (Sequence[Tuple[str, int, int]]): The merged
                ``(band_label, summed_bytes, start_addr)`` runs (disjoint spans).

        Returns:
            Dict[int, int]: ``{region_start: symbol_count}`` for every run.

        Data Flow:
            - Reads ``self._a2l_tags`` (read-only) + ``runs``; produces the
              per-region counts the region rows render.

        Dependencies:
            Uses:
                - ``build_sorted_range_index`` / ``address_in_sorted_ranges``
                  (frozen ``range_index``, read-only) / ``bisect.bisect_right``
                  / ``_tag_address``
            Used by:
                - ``_build_band_widgets``
        """
        region_ranges = [
            (start, start + run_bytes) for _band, run_bytes, start in runs
        ]
        index = build_sorted_range_index(region_ranges)
        starts, _ends = index
        counts: Dict[int, int] = {start: 0 for start in starts}
        for tag in self._a2l_tags:
            addr = _tag_address(tag)
            if addr is None or not address_in_sorted_ranges(addr, index):
                continue
            slot = bisect.bisect_right(starts, addr) - 1
            counts[starts[slot]] += 1
        return counts

    def _build_band_widgets(
        self,
        runs: Sequence[Tuple[str, int, int]],
        windows: Sequence[EntropyWindow],
        span_start: int,
        span_end: int,
    ) -> List[Container]:
        """Build the band row (bar + glance), address ruler, region list, legend.

        Summary:
            Assemble the entropy band-view sub-containers (batch-45, R-TUI-060 /
            R-TUI-061; extended batch-47, R-TUI-072/073): a ``.map-band-row``
            docking the proportional ``.map-band-bar`` beside the
            ``.at-a-glance`` panel, a NEW :class:`MapRuler` address ruler beneath
            the band row (5 ticks, LLR-072.3), then the ``.map-region-list`` and
            the ``.map-band-legend``. The band bar now spans the whole image
            ADDRESS SPACE (width ∝ byte share of ``span_end - span_start``, not
            of the mapped-bytes total), so unmapped address gaps between runs
            render as ``╱`` hatch segments (``.map-band-gap``, LLR-072.1); a
            contiguous image (no gap) keeps its pre-batch-47 widths (span ==
            mapped bytes). Each region row is enriched to ``{glyph} 0x{addr}
            {human_bytes} {microbar} {N} sym {band} ↵`` — a humanized size
            (LLR-072.2), a size micro-bar vs the largest region (LLR-073.1), the
            ``range_index`` symbol count (LLR-073.1) and the ``↵`` open-in-hex
            affordance (LLR-073.2). Region rows still carry NO file-derived text
            (band labels + counts only — security B3). Each sub-widget is
            addressed by CLASS (re-mounted every render; an id would trip
            ``DuplicateIds``) with markup-safe ``safe_text`` content. At
            ``width-narrow`` the band row reflows to vertical (LLR-045B.3).

        Args:
            runs (Sequence[Tuple[str, int, int]]): The merged
                ``(band_label, summed_bytes, start_addr)`` runs from
                ``_merge_band_runs`` (non-empty), ascending by start.
            windows (Sequence[EntropyWindow]): The loader-computed entropy
                windows the sparkline profile is sampled from.
            span_start (int): Inclusive image span start (``derive_image_span``).
            span_end (int): Exclusive image span end (``derive_image_span``).

        Returns:
            List[Container]: ``[band_row, ruler, region_list, legend]`` ready to
            mount into ``#map_grid``.

        Data Flow:
            - Reads ``runs`` + ``windows`` + the span + ``self._a2l_tags``;
              produces the widgets ``render_ranges`` mounts.

        Dependencies:
            Uses:
                - ``band_style`` / ``ENTROPY_BAND_LABELS`` / ``safe_text`` /
                  ``human_bytes`` / ``microbar`` / ``MapRuler`` /
                  ``_region_symbol_counts`` / ``_build_glance_widgets``
            Used by:
                - ``render_ranges``
        """
        total_span = max(1, span_end - span_start)
        largest_region = max(
            (run_bytes for _band, run_bytes, _start in runs), default=1
        ) or 1
        sym_counts = self._region_symbol_counts(runs)

        segments: List[Static] = []
        region_rows: List[RegionRow] = []
        cursor = span_start
        for band, run_bytes, start in runs:
            token, glyph, _meaning = band_style(band)
            # Hatch the unmapped gap (if any) preceding this run — an
            # app-supplied ``╱`` marker, NOT an entropy band (LLR-072.1).
            if start > cursor:
                gap_width = max(
                    1, round(_BAND_BAR_WIDTH * (start - cursor) / total_span)
                )
                segments.append(
                    Static(
                        safe_text(_MAP_GAP_HATCH * gap_width),
                        classes="map-band-seg map-band-gap",
                    )
                )
            seg_width = max(1, round(_BAND_BAR_WIDTH * run_bytes / total_span))
            segments.append(
                Static(safe_text(glyph * seg_width), classes=f"map-band-seg {token}")
            )
            region_rows.append(
                self._build_region_row(
                    band, glyph, token, run_bytes, start, largest_region, sym_counts
                )
            )
            cursor = start + run_bytes

        legend_rows: List[Static] = []
        for band in ENTROPY_BAND_LABELS:
            token, glyph, meaning = band_style(band)
            legend_rows.append(
                Static(
                    safe_text(f"{glyph} {band} — {meaning}"),
                    classes=f"map-legend-row {token}",
                )
            )

        # Re-mounted every render after ``grid.remove_children()`` (whose removal
        # is deferred), so these carry CLASSES, not unique IDs — an ID would trip
        # ``DuplicateIds`` when the old container is still registered at re-render
        # (the same reason the retired cell grid used ``.map-cell``, not an id).
        band_bar = Horizontal(*segments, classes="map-band-bar")
        glance = self._build_glance_widgets(runs, windows)
        return [
            Horizontal(band_bar, glance, classes="map-band-row"),
            MapRuler(span_start, span_end),
            Vertical(*region_rows, classes="map-region-list"),
            Vertical(*legend_rows, classes="map-band-legend"),
        ]

    def _build_region_row(
        self,
        band: str,
        glyph: str,
        token: str,
        run_bytes: int,
        start: int,
        largest_region: int,
        sym_counts: Mapping[int, int],
    ) -> RegionRow:
        """Compose one enriched region-list row (batch-47, R-TUI-073).

        Summary:
            Build the ``{glyph} 0x{addr} {human_bytes} {microbar} {N} sym {band}
            ↵`` row as a Rich ``Text`` (single-space separators so the row fits
            the tightest measured region-row width — 52 cols @120x30, C-29): a
            humanized size (LLR-072.2), a ``_REGION_MICROBAR_WIDTH``-cell size
            micro-bar of ``run_bytes / largest_region`` (LLR-073.1), the region's
            ``range_index`` symbol count (LLR-073.1) and the ``↵`` open-in-hex
            affordance (LLR-073.2). Every field is developer-formatted or a
            constant band label — NO file-derived text reaches the row (B3).

        Args:
            band (str): The run's band label.
            glyph (str): The band's texture glyph (``entropy_style``).
            token (str): The band's ``band-*`` CSS class token.
            run_bytes (int): The run's byte size.
            start (int): The run's inclusive start address.
            largest_region (int): The largest run's byte size (micro-bar
                denominator; ``>= 1``).
            sym_counts (Mapping[int, int]): ``{region_start: N sym}`` from
                ``_region_symbol_counts``.

        Returns:
            RegionRow: The composed clickable region row.

        Data Flow:
            - Pure composition over the run + counts; produces one row widget.

        Dependencies:
            Uses:
                - ``human_bytes`` / ``microbar`` / ``safe_text`` / ``RegionRow``
            Used by:
                - ``_build_band_widgets``
        """
        n_sym = sym_counts.get(start, 0)
        frac = run_bytes / largest_region if largest_region else 0.0
        content = Text()
        content.append_text(safe_text(f"{glyph} 0x{start:08X} "))
        content.append_text(safe_text(f"{human_bytes(run_bytes)} "))
        content.append_text(microbar(frac, _REGION_MICROBAR_WIDTH))
        content.append_text(safe_text(f" {n_sym} sym {band} {_OPEN_IN_HEX_GLYPH}"))
        return RegionRow(
            content,
            region_start=start,
            region_end=start + run_bytes,
            classes=f"map-region-row {token}",
        )

    def _build_glance_widgets(
        self,
        runs: Sequence[Tuple[str, int, int]],
        windows: Sequence[EntropyWindow],
    ) -> Container:
        """Build the docked "At a glance" panel (histogram + sparkline).

        Summary:
            Assemble the ``.at-a-glance`` panel (batch-45, R-TUI-061): a title,
            one band-styled histogram row per OCCUPIED band (``{glyph} {label}
            {count} {bar} {pct}%`` — region counts via :func:`band_histogram`,
            LLR-045B.1), and a band-coloured profile ``.map-sparkline`` of the
            entropy windows (one band-styled segment per contiguous same-band
            run of sampled ramp glyphs, :func:`_sparkline_segments`,
            LLR-045B.2). Colour flows solely through the ``band-*`` CSS classes;
            every text sink is a markup-safe ``safe_text`` over CONSTANT band
            labels — no file-derived text (security B3).

        Args:
            runs (Sequence[Tuple[str, int, int]]): The merged region runs (the
                histogram's region tally).
            windows (Sequence[EntropyWindow]): The entropy windows the
                sparkline profile is sampled from.

        Returns:
            Container: The ``.at-a-glance`` panel to dock beside the band bar.

        Data Flow:
            - Reads ``runs`` (histogram) + ``windows`` (sparkline); produces the
              docked panel.

        Dependencies:
            Uses:
                - ``band_histogram`` / ``_sparkline_segments`` / ``band_style``
                  / ``safe_text``
            Used by:
                - ``_build_band_widgets``
        """
        children: List[Static] = [
            Static(safe_text("At a glance"), classes="glance-title")
        ]
        for band, count, pct in band_histogram(runs):
            token, glyph, _meaning = band_style(band)
            bar = "█" * max(1, round(_GLANCE_BAR_WIDTH * pct / 100.0))
            children.append(
                Static(
                    safe_text(f"{glyph} {band} {count} {bar} {pct:.0f}%"),
                    classes=f"map-glance-row {token}",
                )
            )

        spark_segments: List[Static] = [
            Static(safe_text(glyphs), classes=f"map-sparkline-seg {band_style(band)[0]}")
            for band, glyphs in _sparkline_segments(windows, _SPARKLINE_WIDTH)
        ]
        children.append(
            Horizontal(*spark_segments, classes="map-sparkline")
            if spark_segments
            else Static(safe_text(""), classes="map-sparkline")
        )
        return Vertical(*children, classes="at-a-glance")

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
        text.append(f"Coverage: {stats.coverage_pct:.2f}%  ")
        text.append(f"Bytes covered: {stats.covered_bytes}\n")
        text.append(f"Valid ranges: {stats.valid_count}  ")
        text.append(f"Invalid ranges: {stats.invalid_count}\n")
        text.append(f"Gaps: {stats.gap_count}  ")
        text.append(f"Largest gap: {stats.largest_gap} bytes\n")
        text.append(f"Total issues: {stats.total_issues}")
        return text

    def _reset_detail(self) -> None:
        """Clear the detail pane back to its neutral hint.

        Summary:
            Return the detail body to the "click a region row" hint — used on
            every fresh render so a stale selection from a prior file never
            lingers.

        Dependencies:
            Used by:
                - ``render_ranges``
        """
        try:
            body = self.query_one("#map_detail_body", Static)
        except Exception:
            return
        self._selected_cell_start = None
        body.update(safe_text(self._DETAIL_HINT))

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
                f"({r_size} bytes, {r_status})"
            )
            # R-TUI-041 R-3: name the region by the A2L symbol(s) overlapping
            # it. Untrusted A2L names go through ``symbol_list_text`` (markup-
            # safe ``Text``), never an f-string (LLR-041.11).
            region_names = symbols_in_window(self._a2l_tags, r_start, r_end)
            if region_names:
                text.append(" - ")
                text.append(symbol_list_text(region_names))
            text.append("\n")
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

    def on_region_row_activated(self, event: "RegionRow.Activated") -> None:
        """Handle a region-row click: populate the inspector + jump to hex.

        Summary:
            On a single :class:`RegionRow.Activated` (one click), populate the
            retained ``#map_detail`` inspector for the clicked run's
            ``[region_start, region_end)`` window (batch-45 LLR-045C + batch-47
            R-TUI-074): the ``build_detail_text`` body (status chip, span/size,
            R-TUI-041 R-3 A2L-symbol region naming with its C-17 markup-safety
            guard), then a humanized size + the region's dominant band + a ≤3-row
            hex peek at the region start (LLR-074.1/074.2). It then posts
            :class:`OpenInHexRequested` so the reused app handler switches to the
            Workspace/hex screen (LLR-045C.1). Detail is populated BEFORE the nav
            message so the pane reflects the selection when the operator returns.
            Every file-derived string in the inspector (A2L symbol names via
            ``build_detail_text``) renders through ``safe_text`` — the peek adds
            only developer-formatted hex, no untrusted text (C-17 / MN-4).

        Args:
            event (RegionRow.Activated): The clicked run's window.

        Dependencies:
            Uses:
                - ``cell_status`` / ``build_detail_text`` / ``band_style`` /
                  ``human_bytes`` / ``_region_hex_peek`` / ``OpenInHexRequested``
            Used by:
                - Textual message dispatch (from ``RegionRow``)
        """
        event.stop()
        start, end = event.region_start, event.region_end
        self._selected_cell_start = start
        status = cell_status(start, end, self._ordered_ranges)
        detail = self.build_detail_text(start, end, status)
        detail.append("\n")
        detail.append(f"Size: {human_bytes(end - start)}\n")
        band = self._run_bands.get(start)
        if band is not None:
            _token, glyph, _meaning = band_style(band)
            detail.append(f"Dominant band: {glyph} {band}\n")
        detail.append(f"Peek @ 0x{start:08X}:\n")
        detail.append(self._region_hex_peek(start, end))
        body = self.query_one("#map_detail_body", Static)
        body.update(detail)
        self.post_message(self.OpenInHexRequested(start))

    def _region_hex_peek(self, start: int, end: int) -> Text:
        """Render a ≤3-row hex peek at a region's start (batch-47, R-TUI-074).

        Summary:
            Return a markup-safe ``Text`` hex+ASCII peek of up to
            ``_MAP_PEEK_ROWS`` 16-byte rows beginning at ``start``, using the
            plain ``hexview.render_hex_view`` renderer over the stored
            ``self._mem_map`` (LLR-074.2). Row bases start at the
            ``HEX_WIDTH``-aligned base of ``start`` and stop at the region end,
            so the first rendered row is the ``HEX_WIDTH``-aligned row that
            CONTAINS ``start`` (standard hex-grid convention); when the region
            start is 16-aligned (the common case) that row address equals the
            region start, otherwise it is the aligned row containing it. A
            region shorter than three rows
            shows only the available rows. The peek carries only developer hex
            formatting — no file-derived text — but is still wrapped in
            ``safe_text`` for uniform markup-safety. An empty ``_mem_map`` (no
            file / headless) yields an empty ``Text`` rather than raising.

        Args:
            start (int): The region's inclusive start address.
            end (int): The region's exclusive end address.

        Returns:
            Text: The composed, markup-safe hex peek (possibly empty).

        Data Flow:
            - Reads ``self._mem_map`` (read-only) + the region bounds; produces
              the ``Text`` appended to ``#map_detail_body``.

        Dependencies:
            Uses:
                - ``hexview.render_hex_view`` / ``hexview.HEX_WIDTH`` /
                  ``safe_text``
            Used by:
                - ``on_region_row_activated``
        """
        if not self._mem_map:
            return safe_text("")
        from .hexview import HEX_WIDTH, render_hex_view

        base = start - (start % HEX_WIDTH)
        row_bases: List[int] = []
        addr = base
        while addr < end and len(row_bases) < _MAP_PEEK_ROWS:
            row_bases.append(addr)
            addr += HEX_WIDTH
        # Pass the stored map directly (no O(N) copy — large images are 40M+);
        # supplying ``row_bases`` skips ``build_row_bases`` so only the ≤3 peek
        # rows are materialised.
        rendered = render_hex_view(
            self._mem_map, row_bases=row_bases, max_rows=_MAP_PEEK_ROWS
        )
        return safe_text(rendered)


def _make_flow_block(kind: str, ref: str) -> Optional[FlowBlock]:
    """Build a typed :class:`FlowBlock` from the panel's (kind, ref) selection.

    Returns ``None`` for an unknown kind or an empty ref (the panel no-ops).
    """
    ref = ref.strip()
    if not ref:
        return None
    if kind == BLOCK_SOURCE:
        return SourceBlock(ref)
    if kind == BLOCK_PATCH:
        return PatchBlock(ref)
    if kind == BLOCK_WRITE_OUT:
        return WriteOutBlock(ref)
    return None


def _flow_block_label(block: FlowBlock) -> str:
    """One-line display label for a block (plain text — rendered markup-safe)."""
    if isinstance(block, SourceBlock):
        return f"SOURCE  {block.image_ref}  ({block.file_type})"
    if isinstance(block, PatchBlock):
        return f"PATCH   {block.change_doc_ref}"
    if isinstance(block, WriteOutBlock):
        return f"WRITE-OUT  {block.output_name}  ({block.fmt})"
    return "?"


class FlowBuilderPanel(ScrollableContainer):
    """Rail-8 Flow Builder — compose + run an ordered typed-block pipeline.

    Summary:
        The tracer surface (R-TUI-059, batch-44): a ``Select`` (block kind) +
        an ``Input`` (the block's project-relative ref) + **Add** appends a
        block; the ordered list shows the composed flow; **Run** posts
        :class:`RunRequested` with the built :class:`Flow`, and the app calls
        ``flow_execution_service.run_flow`` and hands the
        :class:`FlowRunResult` back to :meth:`render_result`. Presentational —
        it imports the ``flow_model`` data types only (no engine), and EVERY
        dynamic string (block refs, run diagnostics, written paths) is rendered
        markup-safe via ``safe_text`` (security F4 / the batch-27/43 class).

    Data Flow:
        - Add → ``_make_flow_block(kind, ref)`` → append to ``self._blocks`` →
          repaint ``#flow_blocks``.
        - Run → ``RunRequested(Flow(blocks=self._blocks))`` → app → ``run_flow``
          → :meth:`render_result` paints ``#flow_result``.

    Dependencies:
        Uses:
            - ``flow_model`` (SourceBlock / PatchBlock / WriteOutBlock / Flow)
            - ``safe_text`` (markup-safe render)
        Used by:
            - ``S19TuiApp._compose_screen_flow`` /
              ``S19TuiApp.on_flow_builder_panel_run_requested``
    """

    #: The dropdown block-kind options (label, ``kind`` value).
    _KIND_OPTIONS = [
        ("Source (image)", BLOCK_SOURCE),
        ("Patch (change doc)", BLOCK_PATCH),
        ("Write-out (file)", BLOCK_WRITE_OUT),
    ]

    class RunRequested(Message):
        """The operator pressed Run — carries the composed flow to the app.

        Args:
            flow (Flow): The ordered typed-block flow to execute.
        """

        def __init__(self, flow: Flow) -> None:
            super().__init__()
            self.flow = flow

    def __init__(self) -> None:
        super().__init__(id="flow_panel")
        self._blocks: List[FlowBlock] = []

    def compose(self) -> ComposeResult:
        yield Label(
            "Flow Builder (tracer): pick a block kind, enter its "
            "project-relative ref, Add; then Run.",
            id="flow_help",
            markup=False,
        )
        yield Horizontal(
            Select(
                self._KIND_OPTIONS,
                value=BLOCK_SOURCE,
                allow_blank=False,
                id="flow_kind",
            ),
            Input(
                placeholder="ref (image / change-doc / output name)",
                id="flow_ref",
            ),
            Button("Add", id="flow_add"),
            id="flow_add_row",
        )
        yield Static(self._blocks_text(), id="flow_blocks", markup=False)
        yield Horizontal(
            Button("Run", id="flow_run", variant="primary"),
            Button("Clear", id="flow_clear"),
            id="flow_run_row",
        )
        yield Static("", id="flow_result", markup=False)

    def _blocks_text(self) -> Text:
        if not self._blocks:
            return safe_text("(no blocks yet)")
        text = Text()
        for position, block in enumerate(self._blocks, start=1):
            text.append(f"{position}. ")
            text.append(safe_text(_flow_block_label(block)))
            text.append("\n")
        return text

    def _refresh_blocks(self) -> None:
        self.query_one("#flow_blocks", Static).update(self._blocks_text())

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "flow_add":
            kind = str(self.query_one("#flow_kind", Select).value)
            ref = self.query_one("#flow_ref", Input).value
            block = _make_flow_block(kind, ref)
            if block is None:
                return
            self._blocks.append(block)
            self.query_one("#flow_ref", Input).value = ""
            self._refresh_blocks()
        elif event.button.id == "flow_run":
            self.post_message(
                self.RunRequested(Flow(name="flow", blocks=list(self._blocks)))
            )
        elif event.button.id == "flow_clear":
            self._blocks.clear()
            self._refresh_blocks()
            self.query_one("#flow_result", Static).update(safe_text(""))

    def render_result(self, result: FlowRunResult) -> None:
        """Paint the ``#flow_result`` pane from a run outcome (markup-safe)."""
        text = Text()
        text.append(f"Run: {result.status}\n")
        for block_result in result.block_results:
            text.append(f"  [{block_result.status}] ")
            text.append(safe_text(f"{block_result.kind}: {block_result.summary}"))
            text.append("\n")
            for diagnostic in block_result.diagnostics:
                text.append("      ")
                text.append(safe_text(diagnostic))
                text.append("\n")
        for path in result.written_paths:
            text.append("wrote: ")
            text.append(safe_text(str(path)))
            text.append("\n")
        self.query_one("#flow_result", Static).update(text)


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

    #: Check-glyph → render style (batch-48 LLR-077.3). The glyph is FOLDED
    #: into the ``Kind`` cell as its own leading span, so this map lives at the
    #: render boundary while ``ChangeService`` owns the token → glyph half —
    #: the panel imports nothing from the service layer (C-7 purity).
    #:
    #: The two halves are keyed on the same 4 characters in two modules, so
    #: ``test_tui_patch_glyphs.py::test_tc077_3_glyph_map`` asserts they stay
    #: TOTAL over each other. Without that guard a glyph renamed on the service
    #: side would fall through to the ``·`` style and mis-colour silently.
    _GLYPH_STYLE = {
        "✓": GREEN,
        "✗": RED,
        "◐": YELLOW,
        "·": DGRAY,
    }

    #: Cell budget for the CHECKS pass/fail strip's bar (LLR-078.1).
    #: ⚠ CORRECTED (Inc-4 code review F1 — the original note here was wrong in
    #: both directions and is retracted). PILOT-MEASURED in the real app:
    #:
    #:   120x30  body interior w=18 → strip w=16 h=2  ← WRAPS to two lines
    #:    80x24  body interior w=66 → strip w=64 h=1  ← fits on one
    #:
    #: So the strip is NOT "one always-visible line", and the window is NOT the
    #: budget: 22-23 is the WINDOW width recorded at
    #: ``test_tui_patch_layout.py:56-58``; the strip's real container is 16
    #: after borders + padding. Sizing 8 cells against the 22-23 figure
    #: INHERITED a recorded number instead of pilot-measuring the real
    #: container — which is the C-29 error itself, not merely an open C-29 gap
    #: (C-29 exists to forbid exactly that inheritance).
    #:
    #: Nothing is lost today: both lines paint in full, no count is truncated,
    #: and the window already scrolls (body h=40 vs window h=11), so the extra
    #: row costs scroll, not visibility. Hence MEDIUM, deferred to Inc-5's
    #: geometry pass — where the counts alone measure 15 chars against a 16-col
    #: body, so the bar CANNOT share the line at 120x30 at any width worth
    #: drawing. That is a design decision (tighter separators / responsive
    #: width / an intentional two-line strip), not a width tweak.
    _CHECK_STRIP_BAR_CELLS = 8

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

    #: The three windows' border titles (LLR-075.1). CONSTANT author strings —
    #: never file-derived (C-17). The superscript ordinal names the window's
    #: read order in the three-column regime.
    _WINDOW_BORDER_TITLES = {
        "patch_win_script": "¹PATCH SCRIPT",
        "patch_win_checks": "²CHECKS",
        "patch_win_json": "³JSON EDIT",
    }

    #: The JSON window's border subtitle (LLR-075.1) — the change-set schema
    #: token, spelled locally so this view widget imports nothing from the
    #: service layer (the panel's own paste label already reads "v2 JSON").
    _JSON_SCHEMA_SUBTITLE = "v2 schema"

    #: The CHECKS window's border subtitle before any check run (LLR-075.1).
    _NO_RUN_SUBTITLE = "no run yet"

    #: The variant/scope line's placeholder when no variant is active
    #: (LLR-075.3 invalid boundary — a neutral placeholder, never a crash).
    _NO_VARIANT_PLACEHOLDER = "-"

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

    class BeforeAfterReportRequested(Message):
        """The operator activated the persistent before/after control (US-061).

        Summary:
            Posted by the ``#patch_before_after_button`` in the persistent
            report row revealed after a successful save-back (LLR-061.1).
            Carries no payload — it is a pure trigger: ``app.py`` routes it to
            the single existing ``action_before_after_report`` writer
            (LLR-061.2), so the control adds no new report-writing code and the
            ``b`` accelerator stays bound to the same handler.

        Dependencies:
            Used by:
                - ``S19TuiApp.on_patch_editor_panel_before_after_report_requested``
        """

    class EditJsonRequested(Message):
        """The operator activated the "Edit JSON" control (US-064b).

        Summary:
            Posted by ``#patch_edit_json_button`` to open the full-size JSON
            popup (``ChangeSetJsonScreen``) over the current paste buffer
            (LLR-064b.1). Carries the ``#patch_paste_text`` contents so the app
            can seed the popup without a second query. The button is DISABLED
            whenever a file-backed document is loaded (LLR-064b.4 A-01
            data-loss guard), so this message is only posted for a
            paste-authored / empty document; the app re-checks the guard
            predicate defensively before pushing the popup.

        Args:
            paste_text (str): The current ``#patch_paste_text`` buffer — the
                paste-authored change-set JSON to seed the popup editor with.

        Dependencies:
            Used by:
                - ``S19TuiApp.on_patch_editor_panel_edit_json_requested``
        """

        def __init__(self, paste_text: str = "") -> None:
            super().__init__()
            self.paste_text = paste_text

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

    class VariantHelpRequested(Message):
        """The operator activated the variant-selector info button (US-067).

        Summary:
            Posted by ``#patch_variant_info_button`` — the always-rendered
            info affordance beside ``#patch_variant_select`` (LLR-067.1) — to
            open the ``VariantHelpScreen`` discovery-help modal (LLR-067.3).
            Carries no payload: it is a pure trigger, so ``app.py`` routes it
            straight to ``push_screen(VariantHelpScreen())`` (LLR-067.2). The
            button is unconditionally enabled (help is always available), so
            this message may be posted in any project state.

        Dependencies:
            Used by:
                - ``S19TuiApp.on_patch_editor_panel_variant_help_requested``
        """

    class UndoRequested(Message):
        """The operator activated the change-set Undo control (US-068a).

        Summary:
            Posted by ``#patch_undo_button`` — routed to
            ``ChangeService.undo()`` (LLR-068a.2/.3). Carries no payload: it is
            a pure trigger, so ``app.py`` restores the prior change-set and
            re-renders the entries table. The button is DISABLED whenever a
            file-backed document is loaded (LLR-068a.4 A-01 data-loss guard),
            so this message is only posted for a paste-authored / empty
            document.

        Dependencies:
            Used by:
                - ``S19TuiApp.on_patch_editor_panel_undo_requested``
        """

    class RedoRequested(Message):
        """The operator activated the change-set Redo control (US-068a).

        Summary:
            Posted by ``#patch_redo_button`` — routed to
            ``ChangeService.redo()`` (LLR-068a.2/.3). Carries no payload: it is
            a pure trigger, so ``app.py`` re-applies the undone change-set and
            re-renders the entries table. DISABLED for a file-backed document
            (LLR-068a.4 A-01 guard), mirroring :class:`UndoRequested`.

        Dependencies:
            Used by:
                - ``S19TuiApp.on_patch_editor_panel_redo_requested``
        """

    class EntryEditJsonRequested(Message):
        """The operator activated the per-entry Edit-JSON control (US-068b).

        Summary:
            Posted by ``#patch_entry_edit_json_button`` — the per-entry JSON
            control (LLR-068b.1), DISTINCT from the whole-set
            ``#patch_edit_json_button`` and the field-populate
            ``#patch_entry_edit_button``. Carries the SELECTED row index of
            ``#patch_doc_entries_table`` so ``app.py`` seeds ``EntryJsonScreen``
            with that one entry's JSON and routes Confirm through the validated
            per-entry apply (``ChangeService.edit_entry_json``). The button is
            DISABLED whenever a file-backed document is loaded (LLR-068b.4 A-01
            data-loss guard), so this message is only posted for a
            paste-authored / empty document; with no rows the panel posts
            nothing (no selection is a no-op).

        Args:
            index (int): The zero-based index of the selected entry row.

        Dependencies:
            Used by:
                - ``S19TuiApp.on_patch_editor_panel_entry_edit_json_requested``
        """

        def __init__(self, index: int) -> None:
            super().__init__()
            self.index = index

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
        #: The active variant id the variant/scope line shows (LLR-075.3),
        #: mirrored from ``set_variants`` — ``app.py`` remains the ONLY
        #: populator (the US-026 ownership split). File-derived, so it reaches
        #: the line only through a literal ``Text`` append (LLR-075.4 / C-17).
        self._active_variant: Optional[str] = None

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
            - Map each name to a ``(safe_text(name), name)`` option pair and
              hand them to the ``Select`` via ``set_options``; an empty list
              clears the options, and Textual falls back to the blank prompt.
              The VALUE stays the bare ``str`` — the ``Select.Changed`` handler
              forwards it verbatim and never renders it.

        Dependencies:
            Uses:
                - ``safe_text``
                - ``textual.widgets.Select.set_options``
            Used by:
                - ``S19TuiApp._prefill_patch_change_files``

        Example:
            >>> panel.set_change_files(["changes.json", "changes-1.json"])
        """
        # C-17 (Inc-1b — the THIRD site of the class the Inc-1 security review
        # measured): the option LABEL is a FILENAME read off disk
        # (`app.py:3693` -> `_scan_patch_change_files()` over
        # `workarea/patches/`), so anyone who can drop a file into the work
        # area names it. `Select._watch_value` hands the label to
        # `SelectCurrent.update(prompt)` (`_select.py:615`) -> a markup-enabled
        # `Static` -> `Content.from_markup` (`visual.py:103`). Measured at
        # `textual==8.2.8`: `[red]PWNED[/red]` -> plain 'PWNED' +
        # Span(0,5,'red'); `[/nope]` and `[link=…]` -> `MarkupError` out of
        # `set_change_files`. `update` takes a `RenderableType`, so a literal
        # `Text` label is passed through unparsed — same fix shape as
        # `set_variants` below.
        options = [(safe_text(str(name)), name) for name in names]
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
        # C-17 (LLR-075.4, WIDENED — a SECOND live sink found in Phase 3):
        # the option LABEL is project-file-derived (`app.py:3740-3742` maps
        # each `variant.variant_id` to BOTH label and value), and Textual's
        # `SelectCurrent.update(prompt)` (`_select.py:615`) hands a bare `str`
        # label to a markup-enabled `Static` -> `Content.from_markup`
        # (`visual.py:103`). Measured at `textual==8.2.8`: a variant id of
        # `[/nope]` raised `MarkupError` out of `set_variants`; `[link=…]`
        # injected a link from project data. `update` takes a `RenderableType`,
        # so a literal `Text` label is passed through unparsed — the same fix
        # shape as LLR-075.6, applied at the panel's render boundary so
        # `app.py` stays unchanged.
        select.set_options(
            [(safe_text(str(label)), value) for label, value in options]
        )
        if active_id is not None and len(options) >= 2:
            select.value = active_id
        select.disabled = len(options) < 2
        # LLR-075.3: mirror the active variant onto the variant/scope line.
        # Driving it from HERE (the single populator) is what keeps the line
        # from going stale: a dropdown pick routes through
        # ``_handle_select_variant`` -> load -> ``_apply_prepared_load`` ->
        # ``_refresh_patch_variant_select`` -> back into this method.
        self._active_variant = active_id
        self._refresh_variant_scope_line()

    def compose(self) -> ComposeResult:
        """Lay out the Patch Editor as three responsive bordered windows.

        Summary:
            Render the change-flow editor as three bordered windows
            (HLR-063) — ``#patch_win_script`` (PATCH SCRIPT),
            ``#patch_win_checks`` (CHECKS) and ``#patch_win_json``
            (JSON EDIT). Each window is a constant **border title** + a
            scrollable ``VerticalScroll`` body + one or more **docked
            button-row siblings of the body** (not descendants of it), so an
            action button is never trapped below the body's inner scroll fold
            (HLR-064 / the field-audit B2 fix).

            **batch-48 (§6.5 Amendment D): the in-body title ``Label`` is
            GONE.** R-TUI-063 originally specified a constant-title ``Label``
            as each window's first child; Inc-1 added the dolphie-idiom
            ``border_title`` (LLR-075.1), which rendered the SAME constant a
            second time — so each window read its own name twice. The border
            title supersedes the Label: it is strictly stronger (it self-
            describes on the window's own chrome, it cannot be scrolled away
            from its window, and it spends 0 content rows against the measured
            ~5-row @80x24 budget). The protected property — *each window
            self-describes* — is preserved and re-pinned in that stronger form
            by ``test_tui_patch_layout.py::test_tc46_1_*``, which now asserts
            ``border_title`` instead of the Label's class.

            **batch-48 (HLR-076): the docked buttons are CHIPS.** Each
            button-bearing container carries a ``patch-chip-{entry,apply,
            checks}`` group class and each ``Button`` a ``patch-chip``; the
            colour rules live in ``styles.tcss`` scoped under
            ``#patch_editor_panel`` (LLR-076.1 — the C-30 containment). This
            is a CLASSES-ONLY restyle: no id is added-in-place-of, renamed,
            moved, or re-parented (LLR-076.3).

            The pre-existing grouping
            sub-containers ``#patch_pane_entries``, ``#patch_pane_changefile``,
            ``#patch_pane_variant`` and ``#patch_doc_file_row`` are preserved
            intact as **non-scrolling** groups (FOLD-1) so every leaf id and
            the two variant-order tests stay green unchanged; only their
            button rows move out to the docked region. The wide↔narrow switch
            is pure CSS reusing the existing ``width-narrow`` regime
            (styles.tcss): three columns when ≥120 cols, stacked with a
            panel-level scroll below it (FOLD-8 reachable-under-scroll, since
            the measured 5-row @80×24 viewport cannot show all buttons at
            once). Window titles are CONSTANT strings — never file-derived
            (C-17 / F3). No leaf id is renamed; the variant group stays ABOVE
            the execute group (R-PATCH-VARIANT-SELECT-001).

        Args:
            None

        Returns:
            ComposeResult: The Patch Editor widget tree — three
            ``#patch_win_*`` window containers, each a border-titled window
            holding a scrollable body and its docked button-row sibling(s).

        Data Flow:
            - Each window ``Container`` lays its children out vertically
              (body / docked rows); ``#patch_editor_panel`` lays the
              three windows out horizontally when wide and vertically (with a
              panel scroll) when ``width-narrow`` is set (styles.tcss).

        Dependencies:
            Used by:
                - Textual ``ScrollableContainer`` compose lifecycle
        """
        # ================= PATCH SCRIPT window =================
        script_window = Container(
            VerticalScroll(
                Container(
                    Label(
                        "Change document (JSON)",
                        classes="patch-section-title",
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
                        # batch-31 AC-2 (B-03): OsClipboardInput (a drop-in
                        # Input subclass) so Ctrl+V pastes from the OS
                        # clipboard through the single bounded batch-29 funnel.
                        OsClipboardInput(
                            placeholder="0x100",
                            id="patch_entry_address_input",
                        ),
                        Label("String value", classes="patch-field-label"),
                        OsClipboardInput(
                            placeholder="text (document encoding)",
                            id="patch_entry_value_input",
                        ),
                        Label("Bytes", classes="patch-field-label"),
                        OsClipboardInput(
                            placeholder="DE AD BE EF",
                            id="patch_entry_bytes_input",
                        ),
                        id="patch_doc_entry_inputs",
                    ),
                    id="patch_pane_entries",
                ),
                Container(
                    Container(
                        Label("Change file", classes="patch-field-label"),
                        Select(
                            [],
                            id="patch_doc_file_select",
                            prompt="Change files in patches/",
                            allow_blank=True,
                        ),
                        OsClipboardInput(
                            placeholder=(
                                "or type a path to the same change-set JSON "
                                "(alternative to the patches/ dropdown)"
                            ),
                            id="patch_doc_path_input",
                        ),
                        # batch-35 (US-057 / LLR-057.1): the patch-script
                        # section label. Its button row (#patch_doc_controls)
                        # is docked below (batch-46 HLR-064), out of this
                        # scrollable body.
                        Label(
                            "Patch script",
                            id="patch_script_section_label",
                            classes="patch-section-title",
                        ),
                        id="patch_doc_file_row",
                    ),
                    id="patch_pane_changefile",
                ),
                id="patch_win_script_body",
                classes="patch-window-body",
            ),
            # Docked button rows — siblings of the body (the B2 fix): never
            # trapped below the body's inner scroll fold.
            # HLR-076: `patch-chip-entry` (blue) = the ENTRY-ACTIONS group —
            # the buttons that edit the change document itself.
            Horizontal(
                Button("Add", id="patch_entry_add_button", classes="patch-chip"),
                Button("Edit", id="patch_entry_edit_button", classes="patch-chip"),
                Button(
                    "Remove",
                    id="patch_entry_remove_button",
                    classes="patch-chip",
                ),
                # US-068b: the per-entry JSON editor for the SELECTED
                # entries-table row — disabled for a file-backed document.
                Button(
                    "Edit JSON",
                    id="patch_entry_edit_json_button",
                    classes="patch-chip",
                ),
                id="patch_doc_entry_buttons",
                classes="patch-docked-row patch-chip-entry",
            ),
            # US-068a: change-set Undo / Redo in their own dedicated row —
            # disabled for a file-backed document (A-01 data-loss guard).
            # LLR-076.2 `assumed` arm resolved: undo/redo MOVE the entry
            # document, so they are entry-actions (blue), not apply-path.
            Horizontal(
                Button("Undo", id="patch_undo_button", classes="patch-chip"),
                Button("Redo", id="patch_redo_button", classes="patch-chip"),
                id="patch_history_controls",
                classes="patch-docked-row patch-chip-entry",
            ),
            # batch-37 (US-064a): Refresh re-reads the loaded change file from
            # its own source_path. The 5-button census is pinned by
            # test_tui_patch_editor_v2 / the layout TC.
            # HLR-076: `patch-chip-apply` (green) = the APPLY-PATH group.
            Horizontal(
                Button("Load", id="patch_doc_load_button", classes="patch-chip"),
                Button(
                    "Refresh",
                    id="patch_doc_refresh_button",
                    classes="patch-chip",
                ),
                Button(
                    "Validate",
                    id="patch_doc_validate_button",
                    classes="patch-chip",
                ),
                Button("Apply", id="patch_doc_apply_button", classes="patch-chip"),
                Button("Save", id="patch_doc_save_button", classes="patch-chip"),
                id="patch_doc_controls",
                classes="patch-docked-row patch-chip-apply",
            ),
            # US-028 (LLR-035.2): the variant group composes ABOVE the execute
            # group (R-PATCH-VARIANT-SELECT-001 / TC-035.2). Kept intact as a
            # docked, non-scrolling group so the Select + "?" + execute buttons
            # are reachable by scrolling the window into view (FOLD-8), never
            # trapped below the body fold.
            Container(
                Container(
                    Label("Active variant", classes="patch-field-label"),
                    # US-067: the "?" info button is ALWAYS rendered beside the
                    # selector so its click target always exists.
                    # LLR-076.2 `assumed` arm resolved: the variant group
                    # scopes WHAT A RUN TARGETS, so both of its button-bearing
                    # rows join the apply-path group (green).
                    Horizontal(
                        Select(
                            [],
                            id="patch_variant_select",
                            prompt="Variants in project",
                            allow_blank=True,
                            disabled=True,
                        ),
                        Button(
                            "?",
                            id="patch_variant_info_button",
                            classes="patch-chip",
                        ),
                        id="patch_variant_select_row",
                        classes="patch-chip-apply",
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
                            classes="patch-chip",
                        ),
                        Button(
                            "Execute scope",
                            id="patch_execute_run_button",
                            classes="patch-chip",
                        ),
                        id="patch_execute_buttons",
                        classes="patch-chip-apply",
                    ),
                    # LLR-075.3: the variant + execution scope as a readable
                    # LINE. Before this, the scope was legible only from
                    # #patch_execute_scope_button's own label. An ADDED id —
                    # no existing id moves, is renamed, or is re-parented
                    # (§2.4-6). Nested INSIDE #patch_execute_row (still a
                    # descendant of #patch_pane_variant per LLR-075.3, and
                    # adjacent to the button that cycles it) so
                    # #patch_pane_variant's pinned direct-child list stays
                    # exactly [patch_variant_row, patch_execute_row] —
                    # TC-035.2 / R-PATCH-VARIANT-SELECT-001 stay green
                    # unedited. markup=False is defence-in-depth: every
                    # update() passes a literal Text, so the file-derived
                    # variant id is never markup-parsed (LLR-075.4 / C-17).
                    # batch-48 (code-review F4): `.patch-stat-line`, not the
                    # borrowed `.patch-field-label` — this renders a
                    # label+VALUE pair (label_value sets both colours on the
                    # Text itself), so the field label's `color: $fg-base` was
                    # inert here and only its padding was ever wanted.
                    Static(
                        "",
                        id="patch_variant_scope_line",
                        markup=False,
                        classes="patch-stat-line",
                    ),
                    id="patch_execute_row",
                ),
                id="patch_pane_variant",
                classes="patch-docked-group",
            ),
            id="patch_win_script",
            classes="patch-window",
        )
        # ================= CHECKS window =================
        checks_window = Container(
            VerticalScroll(
                Label(
                    "",
                    id="patch_doc_issue_count",
                    classes="patch-field-label",
                ),
                Static(
                    "", id="patch_doc_issues", markup=False, classes="hidden"
                ),
                # batch-33 (LLR-051.6, C-17): the check status renders the
                # UNTRUNCATED run-block reason (embeds file-derived {kind!r}
                # text) — markup must never be interpreted here.
                Label(
                    "",
                    id="patch_checks_status",
                    classes="patch-field-label",
                    markup=False,
                ),
                # batch-48 (LLR-078.1): the pass/fail strip, ABOVE the
                # results area. Renders integer counts + closed-vocabulary
                # glyphs + a bar and NOTHING file-derived — the blocked-run
                # reason keeps its `patch_checks_status` sink above (C-17 /
                # LLR-078.5). `markup=False` is belt-and-braces: the strip is
                # fed a `Text`, which Static never markup-parses.
                Static(
                    "",
                    id="patch_checks_strip",
                    markup=False,
                    classes="patch-field-label",
                ),
                Container(id="patch_checks_results"),
                id="patch_win_checks_body",
                classes="patch-window-body",
            ),
            # batch-35 (US-057): the "Checks" section label (its parentage is
            # not pinned, but its presence + text are — test_at057a); it labels
            # the docked Run-checks control below.
            Label(
                "Checks",
                id="patch_checks_section_label",
                classes="patch-section-title",
            ),
            # batch-35 (US-052 / LLR-057.2): the Run-checks button + its
            # clarity help stay together in #patch_checks_controls (their
            # parentage is pinned by test_at057a); docked here so the button is
            # reachable by scrolling the CHECKS window into view.
            # HLR-076: `patch-chip-checks` (yellow) = the CHECKS group.
            Container(
                Button(
                    "Run checks",
                    id="patch_checks_run_button",
                    classes="patch-chip",
                ),
                Label(
                    "Checks: runs the loaded change document's checks "
                    "against the loaded image. Needs kind 'check' (a "
                    "change-set cannot be checked). Uncheckable rows "
                    "name their reason (declaration fault, "
                    "partial/outside range, or no image); healthy "
                    "entries are still checked.",
                    id="patch_checks_help",
                    classes="patch-field-label",
                ),
                id="patch_checks_controls",
                classes="patch-docked-group patch-chip-checks",
            ),
            id="patch_win_checks",
            classes="patch-window",
        )
        # ================= JSON EDIT window =================
        json_window = Container(
            VerticalScroll(
                # batch-36 (US-058): the change-set paste group in a scrollable
                # body so the editor's first line sits inside the visible
                # content-region at scroll 0 (FOLD-4). #patch_paste_row is kept
                # for the AT-057a id census; its button row is docked below.
                Container(
                    Label(
                        "Paste change-set (v2 JSON)",
                        classes="patch-field-label",
                    ),
                    CappedTextArea(
                        DUMMY_CHANGESET_TEXT, id="patch_paste_text"
                    ),
                    id="patch_paste_row",
                ),
                id="patch_win_json_body",
                classes="patch-window-body",
            ),
            Horizontal(
                Button(
                    "Parse pasted",
                    id="patch_paste_parse_button",
                    classes="patch-chip",
                ),
                # US-064b: opens the full-size JSON popup over the paste buffer;
                # disabled by the app for a file-backed document (A-01 guard).
                Button(
                    "Edit JSON",
                    id="patch_edit_json_button",
                    classes="patch-chip",
                ),
                id="patch_paste_controls",
                classes="patch-docked-row patch-chip-apply",
            ),
            # The hidden save-back prompt is a docked group revealed by the
            # app's save-back handler on a successful save; docked so its
            # buttons are reachable when shown (AT-064c).
            Container(
                Label("Save patched image as:", classes="patch-field-label"),
                OsClipboardInput(id="patch_saveback_name_input"),
                Horizontal(
                    Button(
                        f"Width: {self._saveback_width} bytes/line",
                        id="patch_saveback_width_button",
                        classes="patch-chip",
                    ),
                    Button(
                        "Write file",
                        id="patch_saveback_confirm_button",
                        classes="patch-chip",
                    ),
                    Button(
                        "Don't save",
                        id="patch_saveback_decline_button",
                        classes="patch-chip",
                    ),
                    id="patch_saveback_buttons",
                    classes="patch-chip-apply",
                ),
                id="patch_saveback_row",
                classes="hidden patch-docked-group",
            ),
            # US-061: a PERSISTENT before/after-report control, hidden by
            # default and revealed on a successful save. Mirrors the
            # #patch_saveback_row reveal idiom.
            Container(
                Label(
                    "Before/after report available:",
                    classes="patch-field-label",
                ),
                Horizontal(
                    Button(
                        "Write before/after report",
                        id="patch_before_after_button",
                        classes="patch-chip",
                    ),
                    id="patch_before_after_buttons",
                    classes="patch-chip-apply",
                ),
                id="patch_before_after_row",
                classes="hidden patch-docked-group",
            ),
            id="patch_win_json",
            classes="patch-window",
        )
        # LLR-075.1: the dolphie-idiom border title + subtitle on each window
        # (the batch-47 `app.py:1651-1656` Workspace-pane precedent). The
        # titles are CONSTANT author strings; the subtitles carry LIVE state
        # and are re-set by refresh_entries (SCRIPT: entry count) and
        # refresh_check_results (CHECKS: run state). The JSON subtitle is the
        # static schema token. `.patch-window` already draws `border: round
        # $rule` (styles.tcss:864), so the border chrome exists to host them.
        script_window.border_title = self._WINDOW_BORDER_TITLES["patch_win_script"]
        checks_window.border_title = self._WINDOW_BORDER_TITLES["patch_win_checks"]
        json_window.border_title = self._WINDOW_BORDER_TITLES["patch_win_json"]
        checks_window.border_subtitle = self._NO_RUN_SUBTITLE
        json_window.border_subtitle = self._JSON_SCHEMA_SUBTITLE
        yield script_window
        yield checks_window
        yield json_window

    def _set_window_subtitle(self, window_id: str, subtitle: str) -> None:
        """Set one patch window's live border subtitle (LLR-075.1).

        Summary:
            Write ``subtitle`` onto the ``#patch_win_*`` container's
            ``border_subtitle``. Tolerates a not-yet-mounted tree so the
            ``refresh_*`` renderers stay callable from ``on_mount`` and from
            ``app.py`` alike.

        Args:
            window_id (str): The window container id — one of
                ``_WINDOW_BORDER_TITLES``' keys.
            subtitle (str): The author-composed live state token. NEVER
                file-derived (C-17): every caller passes a count or a fixed
                token, never a document string.

        Returns:
            None

        Data Flow:
            - Query the window container; assign ``border_subtitle``.

        Dependencies:
            Used by:
                - ``PatchEditorPanel.refresh_entries`` (SCRIPT entry count)
                - ``PatchEditorPanel.refresh_check_results`` (CHECKS run state)

        Example:
            >>> panel._set_window_subtitle("patch_win_script", "3 entries")
        """
        windows = self.query(f"#{window_id}")
        if windows:
            windows.first(Container).border_subtitle = subtitle

    def _refresh_variant_scope_line(self) -> None:
        """Render the variant + execution-scope line (LLR-075.3 / LLR-075.4).

        Summary:
            Compose ``Variant <id> · Scope <label>`` as a Rich ``Text`` and
            write it to ``#patch_variant_scope_line``. The scope label comes
            from the panel's OWN local vocabulary (``_SCOPE_LABELS``), so this
            view widget still imports nothing from the service layer (C-7).
            The variant id is project-file-derived and is therefore appended
            LITERALLY — never f-strung into a markup string and never passed
            to ``Text.from_markup`` (LLR-075.4 / C-17).

        Returns:
            None

        Data Flow:
            - ``self._active_variant`` (mirrored from ``set_variants``) +
              ``self._execute_scope`` (cycled by the scope button) →
              ``label_value`` pairs → ``Static.update``.

        Dependencies:
            Uses:
                - ``insight_style.label_value``
            Used by:
                - ``PatchEditorPanel.set_variants``
                - ``PatchEditorPanel.on_button_pressed`` (the scope cycle)
                - ``PatchEditorPanel.on_mount``

        Example:
            >>> panel._refresh_variant_scope_line()
        """
        lines = self.query("#patch_variant_scope_line")
        if not lines:
            return
        variant = self._active_variant or self._NO_VARIANT_PLACEHOLDER
        # `label_value` appends both segments literally — the C-17-safe
        # constructor. A hostile variant id renders as its own characters.
        line = label_value("Variant", variant, CYAN)
        line.append(" · ")
        line.append_text(
            label_value("Scope", self._SCOPE_LABELS[self._execute_scope])
        )
        lines.first(Static).update(line)

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
        # LLR-075.3: render the line's no-variant/default-scope initial state
        # so it never mounts blank.
        self._refresh_variant_scope_line()

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
        if button_id == "patch_variant_info_button":
            # US-067 / LLR-067.1/.2: open the variant-selector help modal. A
            # pure trigger — post a payload-free request; the app pushes
            # ``VariantHelpScreen`` (no variant-set access, no routed action).
            event.stop()
            self.post_message(self.VariantHelpRequested())
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
            self._refresh_variant_scope_line()
            return
        actions = {
            "patch_entry_add_button": "add_entry",
            "patch_entry_edit_button": "edit_entry",
            "patch_entry_remove_button": "remove_entry",
            "patch_doc_load_button": "load_doc",
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

    def _kind_cell(self, row: object) -> Text:
        """Build the ``Kind`` cell — the check glyph FOLDED in as a leading span.

        Summary:
            Render column 0 as ``"<glyph> <kind>"`` in one ``Text``: the glyph
            leads in its own verdict-coloured span, the kind text follows in
            the cell's PURPLE role style (LLR-077.3/077.4).

            **No sixth column is added** — this is the house idiom, not an
            invention: the A2L table folds its in-image glyph into the name
            cell (``app.py:9548``) and the MAC table folds its status glyph
            into the Tag cell "as its own span" (``app.py:9223-9226``), both
            keeping the column count unchanged. A leading COLUMN would instead
            shift ``Coordinate(row, 1)`` / ``(row, 2)`` under every existing
            index-reader (``tests/test_tui_patch_editor_v2.py:2578``,
            ``:3208-3209``, whose docstring pins the order as contract) and
            force a width relaxation at 80x24 that the fold makes unnecessary.

            The glyph is also NOT redundant with the ``Status`` column:
            ``status_text`` is the CONTAINMENT verdict (``MemoryStatus``), the
            glyph is the CHECK-RUN verdict — different semantics, different
            lifetimes. Folding into ``Kind`` puts visual distance between them.

        Args:
            row (object): One ``ChangeEntryRow``; ``check_glyph`` is read
                duck-typed (defaulting to ``·``) so this view widget keeps
                importing nothing from the service layer (C-7).

        Returns:
            Text: The cell — ``.style`` is the PURPLE role style (so the role
            assertion still reads the cell), ``.plain`` starts with the glyph,
            and ``.spans`` carries exactly the glyph's own style span.

        Data Flow:
            - Look the glyph's style up in ``_GLYPH_STYLE``; an unknown glyph
              falls back to the muted ``DGRAY``.
            - ``append`` the glyph, then ``append`` the kind text.

        Dependencies:
            Uses:
                - ``_GLYPH_STYLE`` ; ``insight_style.PURPLE`` / ``DGRAY``
            Used by:
                - ``refresh_entries``

        Note (C-17):
            ``kind_text`` is file-derived. ``Text.append`` takes its argument
            LITERALLY — it never markup-parses — so appending it is the same
            guarantee ``safe_text`` gives the other four cells. The cell is
            still a ``Text``, so ``default_cell_formatter`` never sees a
            ``str`` to hand to ``Text.from_markup`` (LLR-075.6). The glyph
            itself is one of four author-owned constants (LLR-077.6).
        """
        glyph = str(getattr(row, "check_glyph", "·"))
        cell = Text(style=PURPLE)
        cell.append(f"{glyph} ", style=self._GLYPH_STYLE.get(glyph, DGRAY))
        cell.append(str(row.kind_text))
        return cell

    def refresh_entries(self, rows: Sequence[object]) -> None:
        """Repopulate the entries table from shaped display rows.

        Summary:
            Replace every ``DataTable`` row with the supplied
            ``ChangeEntryRow`` list (kind, address, value-or-bytes, status,
            linkage). When the list is empty, show the neutral empty-state
            line and hide the table; otherwise hide the empty-state line
            and show the table (LLR-003.1). Also refresh the SCRIPT window's
            live entry-count border subtitle (LLR-075.1).

            The ``Kind`` cell additionally carries the row's check-run verdict
            as a leading span (batch-48 LLR-077.4 — see ``_kind_cell``); the
            column set stays at the same five.

            **Every cell is a Rich ``Text`` — the ``Kind`` cell via
            ``_kind_cell``, the other four via ``safe_text`` — regardless of
            whether a role style is assigned to it, and NO bare ``str`` is
            passed to ``add_row`` (LLR-075.6 / C-17).** This
            CLOSES A LIVE, EXPLOITABLE SINK: ``ChangeService.rows`` sets
            ``value_text = entry.value``, the raw file-derived change-set
            string, and Textual's ``default_cell_formatter``
            (``_data_table.py:202-222``) sets ``possible_markup=True`` and
            calls ``Text.from_markup`` **on any bare ``str``**. Measured
            against the pre-fix code at ``textual==8.2.8``:
            ``[red]PWNED[/red]`` injected ``Span(0,5,'red')`` and mangled the
            content; ``[link=http://evil]click[/link]`` injected a LINK from
            file data; ``[/nope]`` raised ``MarkupError`` and CRASHED this
            method. A ``Text`` cell is passed through unparsed, so
            constructing every cell is the fix.

            The three role styles (LLR-075.2) are a SEPARATE, presentational
            concern. ``status_text`` and ``linkage_text`` carry no role style
            — **that is not a licence to pass them as bare ``str``**; a
            role-driven conversion covering only the three styled cells is
            the partial fix that leaves the sink live.

        Args:
            rows (Sequence[object]): The ``ChangeEntryRow`` objects produced
                by ``ChangeService.rows`` — each exposes ``kind_text``,
                ``address_text``, ``value_text``, ``status_text``,
                ``linkage_text`` and ``check_glyph``. Typed as ``object`` so
                this view widget imports nothing from the service layer.

        Data Flow:
            - Clear and refill the table from the row list: the ``Kind`` cell
              via ``_kind_cell`` (glyph span + kind text), the other four
              wrapped by ``safe_text`` (a literal ``Text``; never
              ``from_markup``).
            - Toggle the ``.hidden`` class on the table and the empty-state
              line by whether the list is empty.
            - Set the SCRIPT window's ``N entries`` border subtitle.

        Dependencies:
            Uses:
                - ``_kind_cell`` ; ``safe_text`` ; ``insight_style.CYAN`` /
                  ``VALUE``
            Used by:
                - ``S19TuiApp`` Patch Editor action handler
        """
        table = self.query_one("#patch_doc_entries_table", DataTable)
        empty_state = self.query_one("#patch_doc_empty_state", Static)
        table.clear()
        for row in rows:
            table.add_row(
                self._kind_cell(row),
                safe_text(str(row.address_text), CYAN),
                safe_text(str(row.value_text), VALUE),
                safe_text(str(row.status_text)),
                safe_text(str(row.linkage_text)),
            )
        count = len(rows)
        self._set_window_subtitle(
            "patch_win_script",
            f"{count} {'entry' if count == 1 else 'entries'}",
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

    def set_edit_json_enabled(self, enabled: bool) -> None:
        """Toggle the "Edit JSON" control's enabled state (US-064b, A-01 guard).

        Summary:
            Enable or disable ``#patch_edit_json_button`` so the JSON popup
            opens ONLY for a paste-authored / empty document — the LLR-064b.4
            data-loss guard. The app calls this after every action with
            ``enabled = document.source_path is None``: a file-backed document
            (``source_path is not None``) disables the control so its stale
            ``DUMMY_CHANGESET_TEXT`` buffer can never be Confirmed to
            ``load_text``-REPLACE the loaded document.

        Args:
            enabled (bool): ``True`` to enable the control (paste-authored /
                empty document); ``False`` to disable it (file-backed).

        Dependencies:
            Used by:
                - ``S19TuiApp`` Patch Editor action / change-file handlers
        """
        self.query_one("#patch_edit_json_button", Button).disabled = not enabled

    def set_undo_redo_enabled(self, enabled: bool) -> None:
        """Toggle the Undo/Redo controls' enabled state (US-068a, A-01 guard).

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

        Args:
            enabled (bool): ``True`` to enable both controls (paste-authored /
                empty document); ``False`` to disable them (file-backed).

        Dependencies:
            Used by:
                - ``S19TuiApp`` Patch Editor action / change-file / history
                  handlers
        """
        self.query_one("#patch_undo_button", Button).disabled = not enabled
        self.query_one("#patch_redo_button", Button).disabled = not enabled

    def set_entry_edit_json_enabled(self, enabled: bool) -> None:
        """Toggle the per-entry Edit-JSON control's enabled state (US-068b).

        Summary:
            Enable or disable ``#patch_entry_edit_json_button`` so the
            per-entry JSON popup opens ONLY for a paste-authored / empty
            document — the LLR-068b.4 A-01 data-loss guard. The app calls this
            after every action with ``enabled = document.source_path is None``:
            a file-backed document (``source_path is not None``) disables the
            control so a per-entry edit can never silently mutate the loaded
            document (batch-37 ``set_edit_json_enabled`` precedent).

        Args:
            enabled (bool): ``True`` to enable the control (paste-authored /
                empty document); ``False`` to disable it (file-backed).

        Dependencies:
            Used by:
                - ``S19TuiApp`` Patch Editor action / change-file / history
                  handlers
        """
        self.query_one(
            "#patch_entry_edit_json_button", Button
        ).disabled = not enabled

    def _check_strip_text(self, aggregates: Optional[Mapping[str, int]]) -> Text:
        """Build the CHECKS pass/fail strip's renderable (LLR-078.1).

        Summary:
            Compose ``✓ P  ✗ F  ◐ U`` from the three aggregate counts, each
            glyph carrying its ``_GLYPH_STYLE`` verdict colour, followed by a
            proportional bar of the PASS rate.

        Args:
            aggregates (Optional[Mapping[str, int]]): The three counts —
                duck-typed so this view widget imports nothing from the
                service layer (C-7). ``None`` or a missing key reads ``0``;
                A3 guarantees the real seam always carries all three.

        Returns:
            rich.text.Text: The strip line. Never a ``str`` — and never any
            file-derived text: integers and a closed glyph vocabulary only
            (C-17 / LLR-078.5).

        Data Flow:
            - Read the three counts; append a styled glyph + count per
              verdict; append ``microbar(passed / total)``.
            - ``total == 0`` short-circuits ``frac`` to ``0.0`` — there is no
              division, so a 0-entry run cannot raise (LLR-078.4).
            - The bar is UNFLOORED (the helper's default). ``floor=True`` is
              reserved for bars meaning "this row exists" (batch-47
              LLR-042.7); this bar means "this fraction passed", so it must
              not round a small pass rate UP. MEASURED: the floor is gated on
              ``clamped > 0.0`` (``insight_style.py:214``), so it does NOT
              affect a 0-pass run — both settings render an empty bar there.
              What it would corrupt is a small-but-nonzero rate: 1 passed of
              20 is ``round(0.05 * 8) == 0`` cells honestly, but a floored bar
              paints 1, overstating the pass rate. Overstating passes is the
              harm this bar must not do.

        Dependencies:
            Uses:
                - ``_GLYPH_STYLE`` / ``_CHECK_STRIP_BAR_CELLS`` ;
                  ``insight_style.microbar`` / ``GREEN`` / ``VALUE``
            Used by:
                - :meth:`refresh_check_results`

        Example:
            >>> panel = PatchEditorPanel()
            >>> panel._check_strip_text(
            ...     {"passed": 2, "failed": 1, "uncheckable": 1}
            ... ).plain
            '✓ 2  ✗ 1  ◐ 1  ████░░░░'
        """
        counts = aggregates or {}
        passed = int(counts.get("passed", 0))
        failed = int(counts.get("failed", 0))
        uncheckable = int(counts.get("uncheckable", 0))
        total = passed + failed + uncheckable

        text = Text()
        for glyph, count in (
            ("✓", passed),
            ("✗", failed),
            ("◐", uncheckable),
        ):
            text.append(glyph, style=self._GLYPH_STYLE[glyph])
            text.append(f" {count}  ", style=VALUE)
        frac = passed / total if total else 0.0
        text.append_text(
            microbar(frac, self._CHECK_STRIP_BAR_CELLS, style=GREEN)
        )
        return text

    def refresh_check_results(
        self,
        rows: Sequence[object],
        status_line: str,
        aggregates: Optional[Mapping[str, int]] = None,
    ) -> None:
        """Render the check-run display (LLR-004.5) + the pass/fail strip (LLR-078.1).

        Summary:
            Replace the check-results area with one ``Static`` per result
            row, each carrying its ``sev-*`` class (the
            ``css_class_for_severity`` colour the service shaped), set the
            aggregate-count status line, and render the pass/fail strip.

        Args:
            rows (Sequence[object]): The ``ChangeService.check_rows``
                output — each exposes ``text`` and ``css_class``. Typed as
                ``object`` so this view widget imports nothing from the
                service layer.
            status_line (str): The three-aggregate-count line (``Checks: P
                passed, F failed, U uncheckable``) or the pending-seam
                message.
            aggregates (Optional[Mapping[str, int]]): The three counts for
                the strip — ``ChangeService.check_aggregates()``, threaded in
                as a PARAMETER so the panel keeps importing nothing from the
                service layer and never reaches the running app (C-7 /
                LLR-078.2; the ``MemoryMapPanel.render_ranges(…, mem_map=…)``
                precedent). Defaulted, so no existing caller breaks; ``None``
                renders the all-zero cleared strip.

        Data Flow:
            - Update the status label, render the strip, remove prior result
              children, mount one classed ``Static`` per row.
            - Set the CHECKS window's run-state border subtitle (LLR-075.1):
              the row count when a run produced rows, else the no-run token.
            - The strip CLEARS by riding ``last_check_result``'s existing
              ``undo``/``redo`` reset (``change_service.py:538`` / ``:570``):
              the history call site passes the accessor's all-zero mapping,
              so the strip and ``check_rows()`` always read one state
              (LLR-078.3). An omitted history site would leave a stale count
              — the batch-38 Inc-4 F1 defect.

        Dependencies:
            Used by:
                - ``S19TuiApp`` run-checks action handling (post-run site)
                - ``S19TuiApp._refresh_patch_history_view`` (cleared state)
        """
        self.query_one("#patch_checks_status", Label).update(status_line)
        self.query_one("#patch_checks_strip", Static).update(
            self._check_strip_text(aggregates)
        )
        container = self.query_one("#patch_checks_results", Container)
        container.remove_children()
        for row in rows:
            container.mount(Static(row.text, classes=row.css_class, markup=False))
        # LLR-075.1: derived from the ROW COUNT, never from `status_line` —
        # the status line is service-shaped text and the subtitle must stay an
        # author-composed token (C-17).
        self._set_window_subtitle(
            "patch_win_checks",
            f"{len(rows)} checked" if rows else self._NO_RUN_SUBTITLE,
        )


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
            OsClipboardInput(placeholder="external path A", id="diff_path_a"),
            id="diff_select_row_a",
        )
        yield Horizontal(
            Label("B:", classes="diff-field-label"),
            Select(empty, id="diff_select_b", allow_blank=False),
            OsClipboardInput(placeholder="external path B", id="diff_path_b"),
            id="diff_select_row_b",
        )
        yield Horizontal(
            Button("Compare", id="diff_compare_button"),
            Button("Report", id="diff_report_button"),
            OsClipboardInput(
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
            Uses:
                - ``safe_text``
            Used by:
                - ``S19TuiApp.action_show_screen`` (diff activation)
        """
        # C-17 (Inc-1b): same live sink as `PatchEditorPanel.set_variants` —
        # `app.py:3511` hands this method the SAME project-file-derived
        # `variant_id`s, and each becomes a `Select` option LABEL ->
        # `SelectCurrent.update` -> markup-enabled `Static` ->
        # `Content.from_markup`. Measured at `textual==8.2.8` with the same
        # payloads: span injection on `[red]…[/red]`, `MarkupError` on
        # `[/nope]` / `[link=…]`. Literal `Text` labels; the VALUE stays the
        # bare `str` (`_selected_variant` compares it against
        # `_EXTERNAL_OPTION` and never renders it).
        options: List[Tuple[Any, str]] = [
            (safe_text(str(label)), value) for label, value in variants
        ]
        options.append((safe_text("(external path below)"), self._EXTERNAL_OPTION))
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
