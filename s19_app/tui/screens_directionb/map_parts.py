"""s19_app.tui.screens_directionb.map_parts — memory-map parts (moved verbatim from s19_app/tui/screens_directionb.py at 4f721985)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple
from rich.text import Text
from textual import events
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.message import Message
from textual.widgets import Static
from ..services.entropy_service import EntropyWindow
from ...utils import safe_text
from .shared import (_RULER_TICK_PITCH)


#: Columns an unmapped gap folds to, independent of its byte size and of the
#: container width (batch-77, LLR-111.2). A gap is a separator, not a quantity:
#: at the measured container widths a proportional gap consumed up to 60 of 66
#: columns and floored nine mapped runs to one column each. Sizing gaps by their
#: address span is what the fold retires.
_BAND_GAP_FOLD = 1

#: Cell width of the per-region size micro-bar on each ``RegionRow`` (batch-47,
#: R-TUI-073 / LLR-073.1; batch-93 HLR-127 keeps it inside the fixed-width row).
_REGION_MICROBAR_WIDTH = 4

#: Display-only short forms of the band domain labels that are wider than the
#: region row's 9-cell band column (batch-93, HLR-127 / LLR-127.2). The domain
#: strings in ``ENTROPY_BAND_LABELS`` are NEVER touched — only the row's band
#: column DISPLAY maps them. ``constant/padding`` (16) -> ``const`` (5);
#: ``high/random`` (11) -> ``high/rand`` (exactly 9 — the column edge).
_BAND_SHORT_LABELS: Dict[str, str] = {
    "constant/padding": "const",
    "high/random": "high/rand",
}

#: Width-adaptive stats threshold, in PANEL columns (batch-93, HLR-129 /
#: LLR-129.2). PILOT-MEASURED at P3 (C-29), not copied: the full one-line form
#: `` Mapped 5.2 KiB / 511.9 MiB span (0.0010%) · 5 ranges (5 valid) · 4 gaps ·
#: 0 issues `` measures 84 cells on the charter demo fixture (executed
#: formatter measurement); the compact form (same seven statistics, shortened
#: labels/separators only — no flanking padding, no ``span`` word, no pct
#: parens) measures 66 cells on the same fixture, clearing the 68-column stats
#: strip the 80x24 floor geometry admits. A strip whose measured width is below
#: the full form's own 84-cell width renders compact.
_STATS_FULL_MIN_WIDTH = 84

#: Width-aware microbar threshold, in the region row's AVAILABLE columns
#: (batch-93, HLR-127 / LLR-127.3). PILOT-MEASURED at P3 (C-29): the microbar
#: row measures 40 cells and the compact row 35 cells (executed formatter);
#: the charter captures bound the threshold from both limbs — at 120x36 the
#: left pane's content width measures 41 columns and the microbar is ABSENT,
#: at 160x48 it measures 81 columns and the microbar is PRESENT (grid
#: reconstructions of ``memmap2_map_C.120w.svg`` / ``memmap2_map_C_160x48.120w.
#: svg``). 43 is the smallest threshold consistent with both limbs
#: (41 < 43 <= 81) while keeping the 40-cell row ~3 columns inside the
#: available width.
_REGION_ROW_MICROBAR_MIN_WIDTH = 43

#: The panel-width inset from the region row's available width, measured in
#: the SIDE-BY-SIDE regime: at 120x36 the panel measures 90 columns wide
#: while the row widget's region measures 39 (90 - 39 = 51 — the fixed 44-col
#: inspector + 1-col gutter, the pane's border + padding, and the region
#: list's scrollbar; re-measured at batch-93 inc-002, C-29). The STACKED
#: regime hands the left pane the full width: there the row widget measures
#: panel - 8 (measured at 60x24, 80x24/30, 90x30, 94x40 — 2 columns of
#: host chrome + 4 of pane chrome + the list's 2-column scrollbar, exactly 8
#: at every stacked geometry), so the microbar gate picks its inset per
#: regime (batch-93 inc-002, HLR-131 / LLR-131.1 — the regime-aware
#: re-derivation the inc-001 constant note deferred here). A panel that has
#: not been laid out yet reports width 0 (a conforming first-frame input,
#: P-4); the fallback then renders the narrow form, matching the 120x36
#: capture's microbar-free rows.
_MAP_PANEL_TO_ROWS_INSET = 51
_MAP_PANEL_TO_ROWS_INSET_STACKED = 8
_MAP_PANEL_WIDE_FALLBACK = 92

#: The map's stack threshold, in PANEL columns (batch-93 inc-002, HLR-131 /
#: LLR-131.1 — RE-MEASURED here, C-29, superseding the contract's ~84
#: estimate). The regime decision reads the PANEL's measured width, never the
#: terminal's (the app still toggles the workspace-level `width-narrow` at
#: the 120-column TERMINAL breakpoint for the other screens; the map's own
#: class carries the panel-keyed law). Derivation, executed: side-by-side,
#: the row widget's width is ``panel - _MAP_PANEL_TO_ROWS_INSET`` (39 at
#: panel 90, measured); the compact row (the form the 43-column microbar
#: gate admits below panel 94) measures 35 cells (inc-001's executed
#: formatter pilot); the threshold is the smallest panel width at which the
#: compact row still fits its widget — 51 + 35 = 86. At panel 86 the
#: side-by-side row widget measures exactly 35 and the compact row fits
#: exactly (verified by the wrap audit's boundary arm); at 85 it would wrap
#: (35 cells in a 34-column widget), so 85 and below STACK (the stacked
#: regime hands the rows the full width: widget 77 at panel 85, measured).
#: Boundary limbs: exactly 86 -> side-by-side, 85 -> stacked.
_MAP_STACK_MIN_WIDTH = 86

#: The inspector body's fallback CONTENT width when the pane has not been
#: laid out yet (a conforming width-0 first frame, P-4): the side-by-side
#: interior (40 columns at a 44-col pane minus border/padding) — the
#: binding interior across both regimes, so file-derived symbol names
#: clipped against it never exceed any painted interior.
_INSPECTOR_BODY_FALLBACK_WIDTH = 40

#: Columns the inspector pane's vertical scrollbar consumes inside the
#: body's content box when the body overflows (``overflow-y: auto`` —
#: measured at 100x30/120x36: the 40-column interior paints a 38-column
#: text budget). The symbol-name clip subtracts it UNCONDITIONALLY: the
#: scrollbar appears exactly when a long name overflows the body, so a
#: budget without it clips against a width the painted line can never
#: claim (batch-93 inc-002, HLR-130 — the wrap audit's own finding).
_INSPECTOR_SCROLLBAR_GUTTER = 2

#: The inspector peek renders 8-byte rows of ``ADDR  hh×8`` (batch-93, HLR-128 /
#: LLR-128.1): an 8-hex address, two spaces, eight 2-hex bytes — 33 cells, no
#: ASCII gutter, no ``0x`` prefix. The shipped 16-byte row measured 79 cells
#: and the 8-byte row 33 cells by executing the formatters (P-1 method) — 33
#: is the widest row that cannot wrap in the ~40-col inspector pane.
_PEEK_BYTES_PER_ROW = 8
#: Cell an UNMAPPED byte renders as inside a peek row (2 cells — the row keeps
#: its 33-cell width with holes).
_PEEK_UNMAPPED_CELL = "··"
#: Rows the aligned inspector field block occupies above the peek: the five
#: fields (Status/Region/Size/Band/Symbols) + the ``Peek`` header.
_INSPECTOR_FIELD_ROWS = 6
#: Width of the inspector's aligned field labels: the longest label
#: (``Symbols``, 7 cells) plus the capture's two-space field gutter
#: (batch-93, HLR-126 / LLR-126.2).
_INSPECTOR_LABEL_WIDTH = 9

#: App-supplied hatch glyph marking an unmapped address gap in the band strip
#: (batch-47, R-TUI-072 / LLR-072.1). NOT an entropy band and NOT sourced from
#: ``entropy_style`` — the strip's band glyphs come from ``ENTROPY_BAND_GLYPH``.
_MAP_GAP_HATCH = "╱"

#: Open-in-hex affordance glyph on each ``RegionRow`` (batch-47, LLR-073.2). A
#: hint that a single click drives the reused ``RegionRow.Activated`` nav.
_OPEN_IN_HEX_GLYPH = "↵"  # ↵

#: Default peek row count when the inspector pane cannot drive the cut:
#: ``0`` before first layout (a conforming width-0 first frame, P-4). The
#: stacked regime (panel < ``_MAP_STACK_MIN_WIDTH``, batch-93 inc-002 HLR-131)
#: makes ``#map_detail`` height-auto so its measured height drives the cut
#: from its current content; the fallback covers only the pre-layout case.
#: The height-derived cut takes over wherever the pane is height-constrained
#: (the side-by-side regime — LLR-126.3's monotone limb).
_PEEK_ROWS_FALLBACK = 2


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


def _allocate_band_widths(
    run_bytes: Sequence[int],
    n_gaps: int,
    bar_width: int,
    fold: int = _BAND_GAP_FOLD,
) -> List[int]:
    """Apportion band-bar columns across runs, BOUNDED BY THE CONTAINER.

    Summary:
        Return one column count per run such that, in domain, the run widths
        plus the gap markers sum to at most ``bar_width`` and every run gets at
        least one column (batch-77, R-TUI-103 / LLR-111.7). See ``Returns`` for
        the two degenerate cases where the sum is strictly less. The bound lives HERE,
        in the producer, and not in a predicate over the emitted widgets: an
        output-shaped check can detect an overflow but cannot prevent one. The
        superseded expression sized each run independently against a fixed
        60-column constant and floored the result at 1, so nine tiny runs each
        claimed a column while one claimed 26 — measured, 60 columns of content
        emitted into a 50-column bar with 5 of 14 runs left invisible.

        The method is **floor-one-then-largest-remainder**: reserve one column
        per run, then apportion the SURPLUS ``avail - n_runs`` by each run's
        share of total mapped bytes, giving the leftover columns to the largest
        fractional remainders. Apportioning the WHOLE of ``avail`` and clamping
        up to 1 afterwards is a different allocator that happens to agree with
        plain ``round()`` — the arithmetic this function exists to retire.

        Ties in the fractional remainder are broken by descending mapped bytes,
        then by ascending run index — deterministic, and biased toward the run
        the operator is more likely to be looking for.

    Args:
        run_bytes (Sequence[int]): Mapped byte count per emitted run, in bar
            order. May contain zeros.
        n_gaps (int): Number of unmapped-gap markers emitted between runs.
        bar_width (int): The container's width MEASURED at render time. May be
            0 before first layout; that is an out-of-domain input, not an error.
        fold (int): Columns each gap marker occupies (``_BAND_GAP_FOLD``).

    Returns:
        List[int]: One width per run, positionally aligned with ``run_bytes``.
        Every entry is always ``>= 1``. In domain,
        ``sum(widths) + n_gaps * fold <= bar_width`` — with EQUALITY whenever
        there is surplus to apportion and a nonzero byte total to apportion it
        by. It is strictly less in the two degenerate cases, which are normal
        inputs and not errors: ``surplus == 0`` (the container holds exactly one
        column per run and per gap) and ``total_bytes == 0`` (no byte share
        exists, so every run falls to the floor). ``TC-B77-04`` asserts the
        all-zero case directly. ``<=`` is what ``HLR-111``/``LLR-111.7``
        contract; the equality is an observation about the non-degenerate path,
        never a promise. Out of domain, one entry per run, every entry ``1``.

    Data Flow:
        - Pure arithmetic over run byte counts and one measured width. No widget,
          no address, and no file-derived string is an input.

    Dependencies:
        Used by:
            - ``MemoryMapPanel._build_band_widgets`` (initial mount)
            - ``MemoryMapPanel._resize_band_segments`` (post-refresh + resize)

    Example:
        >>> _allocate_band_widths([768, 256], 0, 66)
        [49, 17]
        >>> _allocate_band_widths([768, 256], 0, 50)
        [37, 13]
        >>> _allocate_band_widths([10, 20, 30], 2, 4)  # out of domain
        [1, 1, 1]
    """
    n_runs = len(run_bytes)
    if n_runs == 0:
        return []

    available = bar_width - n_gaps * fold
    if available < n_runs:
        # Out of domain: the bound is arithmetically unsatisfiable. The
        # degradation rule is deliberately unspecified by R-TUI-103 — the only
        # contracted properties are that this returns a width for every run
        # without raising, and that every run stays reachable in the region
        # list. One column each is the narrowest honest answer.
        return [1] * n_runs

    surplus = available - n_runs
    total_bytes = sum(run_bytes)
    if surplus <= 0 or total_bytes <= 0:
        return [1] * n_runs

    quotas = [surplus * count / total_bytes for count in run_bytes]
    extra = [int(quota) for quota in quotas]
    leftover = surplus - sum(extra)
    ranked = sorted(
        range(n_runs),
        key=lambda i: (-(quotas[i] - extra[i]), -run_bytes[i], i),
    )
    for index in ranked[:leftover]:
        extra[index] += 1
    return [1 + count for count in extra]


def _retained_tick_addresses(
    addresses: Sequence[int],
    ruler_width: int,
    pitch: int = _RULER_TICK_PITCH,
) -> List[int]:
    """Drop interior ruler labels until the retained set fits legibly.

    Summary:
        Return the subset of ``addresses`` the ruler labels at the measured
        width (batch-77, R-TUI-072 as amended / LLR-112.2). The ceiling is
        ``(ruler_width + 1) // pitch`` — one label plus one separator column
        each, with no separator owed after the last label. Past the ceiling the
        ruler MUST drop labels, and the only question is whether it drops them
        legibly or silently: ``width: 1fr`` children partition the row and
        cannot overlap, so an un-elided ruler degrades to ZERO-WIDTH ticks
        rather than to a visible collision. Executed at Phase 1: 60 ticks in a
        50-column row gives 10 zero-width ticks and 0 overlaps.

        The first and last labels are retained in preference to any interior
        one — they are the image's bounds, the two an operator reads first.
        Interior survivors are sampled evenly so a heavily elided ruler still
        spans the image rather than labelling only its head.

    Args:
        addresses (Sequence[int]): Ordered, de-duplicated tick addresses.
        ruler_width (int): The ruler's width MEASURED at render time. May be 0
            before layout; that is an out-of-domain input, not an error.
        pitch (int): Columns one tick claims (``_RULER_TICK_PITCH``).

    Returns:
        List[int]: A strictly ascending subset of ``addresses``, first and last
        always present. At most ``max(2, (ruler_width + 1) // pitch)`` entries —
        the floor of 2 is deliberate: out of domain HLR-112 contracts the bounds
        labels and no raise, and a ruler that renders nothing tells the operator
        less than one that renders two illegibly-narrow labels.

    Data Flow:
        - Pure arithmetic over addresses and one measured width. No widget and
          no file-derived string is an input.

    Dependencies:
        Used by:
            - ``MapRuler._reflow_ticks`` (on every Resize)

    Example:
        >>> _retained_tick_addresses([1, 2, 3, 4, 5], 66)
        [1, 2, 3, 4, 5]
        >>> _retained_tick_addresses(list(range(15)), 50)
        [0, 4, 7, 10, 14]
        >>> _retained_tick_addresses([1, 2, 3], 4)
        [1, 3]
    """
    ceiling = max(2, (ruler_width + 1) // pitch)
    if len(addresses) <= ceiling:
        return list(addresses)
    interior_slots = ceiling - 2
    if interior_slots <= 0:
        return [addresses[0], addresses[-1]]
    step = (len(addresses) - 1) / (interior_slots + 1)
    interior = sorted(
        {round(step * i) for i in range(1, interior_slots + 1)}
        - {0, len(addresses) - 1}
    )
    return [addresses[0]] + [addresses[i] for i in interior] + [addresses[-1]]


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
        of one merged entropy run. A real click posts :class:`Activated`
        carrying the run's ``[region_start, region_end)`` window **and the
        click-chain length**; the enclosing :class:`MemoryMapPanel` handles it
        by populating the detail pane (``build_detail_text``, keeping the
        R-TUI-041 R-3 A2L naming + its C-17 markup-safety guard alive on a live
        path) and — **only on a double click (batch-67 N4a)** — posting
        :class:`MemoryMapPanel.OpenInHexRequested` for direct region→hex nav
        (LLR-045C.1 — no reveal-button, no two-step). Before batch-67 a single
        click did both. The row itself shows
        addr/size/band ONLY — no file-derived A2L text (security B3). A click on
        padding/empty area hits no ``RegionRow`` and is an inert no-op
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

    #: batch-77 LLR-116.1. The row is the map's keyboard subject: the panel
    #: focuses the auto-selected row after every render (LLR-116.5) and the
    #: arrow keys walk the list from there (HLR-115). ``row.focus()`` is a
    #: silent NO-OP while this is False — ``Screen.set_focus`` ignores a widget
    #: whose ``focusable`` is False — so this is a precondition of the focus
    #: clause, not a convenience. Checked against ``dir(Widget)``: ``can_focus``
    #: IS a Widget class attribute (default False), so this OVERRIDES a known
    #: name rather than shadowing an internal one (the ``_nodes``/``_context``
    #: hazard). Same declaration form as ``IssueRow``/``CheckRow``.
    can_focus = True

    class Activated(Message):
        """A region row was clicked, carrying the click-chain length.

        Args:
            region_start (int): The run's inclusive start address (the hex
                focus address).
            region_end (int): The run's exclusive end address.
            chain (int): Textual's click-chain length — ``1`` for a single
                click (inspect only), ``2`` or more for a double click
                (inspect + navigate). Defaults to ``1`` so a hand-constructed
                message means "inspect", the non-navigating case.

        Data Flow:
            - ``chain`` originates at ``events.Click.chain`` and is the ONLY
              input ``MemoryMapPanel.on_region_row_activated`` uses to decide
              whether to post ``OpenInHexRequested`` (batch-67 N4a).
        """

        def __init__(
            self, region_start: int, region_end: int, chain: int = 1
        ) -> None:
            super().__init__()
            self.region_start = region_start
            self.region_end = region_end
            self.chain = chain

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

    def on_click(self, event: events.Click) -> None:
        """Post :class:`Activated` for this region, forwarding the click chain.

        The row itself does not decide what a click means — it reports how many
        clicks arrived and lets :class:`MemoryMapPanel` apply the policy, so the
        single/double split lives in exactly one place (batch-67 N4a).
        """
        self.post_message(
            self.Activated(self.region_start, self.region_end, chain=event.chain)
        )

    def on_key(self, event: events.Key) -> None:
        """Walk the region list with the arrows; inspect with ``Enter``.

        batch-77 HLR-115. Textual performs NO spatial arrow-focus of its own —
        measured at Phase 3 with ``can_focus`` already True, ``up``/``down`` on
        a focused row moved focus NOWHERE at either regime (C-16) — so the
        movement is implemented here rather than inherited from the framework.

        It is deliberately NOT a ``BINDINGS`` entry (LLR-115.4). A widget-scoped
        binding SHADOWS the application binding of the same key for as long as
        the row holds focus, and after batch-77 a region row holds focus by
        default on every map render (LLR-116.5) — so a binding here would sit on
        the operator's normal path. Only the three keys below are consumed;
        every other key bubbles untouched to the application bindings, which is
        what keeps ``j`` / ``k`` / ``o`` reaching ``dump_a2l_json`` /
        ``show_legend`` / ``open_workarea``.

        ``Enter`` posts the SAME :class:`Activated` message a click posts, with
        ``chain = 1`` — the "inspect, do not navigate" value (LLR-115.3). The
        single/double policy therefore stays in ``on_region_row_activated``
        alone; the keyboard adds no second route to the inspector.

        Arrow movement moves FOCUS ONLY. It deliberately does not select: the
        operator scans the list with the arrows and commits with ``Enter``.
        """
        if event.key == "enter":
            event.stop()
            self.post_message(
                self.Activated(self.region_start, self.region_end, chain=1)
            )
            return
        if event.key not in ("up", "down"):
            return
        event.stop()
        # The rows of THIS list only, in mounted order — which is the ascending
        # address order ``_build_band_widgets`` emitted them in. A panel-wide
        # query would also return the stale rows of a superseded render.
        rows = [
            child
            for child in self.parent.children
            if isinstance(child, RegionRow)
        ]
        index = rows.index(self) + (1 if event.key == "down" else -1)
        # No wraparound: at the first row ``up`` and at the last row ``down``
        # leave focus exactly where it is. ``0 <= index`` is what stops ``-1``
        # from being read as "the last row".
        if 0 <= index < len(rows):
            rows[index].focus()


class BandSegment(Static):
    """A clickable entropy-band segment of the map's top strip (batch-67 N4b).

    Summary:
        One coloured run of the ``#map_grid`` band strip — the visual overview
        above the region list. Before batch-67 the strip was inert decoration:
        the same information was navigable in the region list below, but the
        band the operator was actually looking at was not. This makes each
        MAPPED run carry its ``[region_start, region_end)`` window and post the
        SAME :class:`RegionRow.Activated` message a region row does, so the two
        surfaces share one handler and one set of semantics — single click
        inspects, double click opens in hex.

        Deliberately a SIBLING of :class:`RegionRow`, not a subclass: Textual's
        ``query(RegionRow)`` matches subclasses, so subclassing would silently
        add ~N band widgets to every existing ``app.query(RegionRow)`` call
        site (the region-count and ``N sym`` assertions in
        ``tests/test_tui_map_big.py`` among them). A sibling reuses the message
        without widening that query.

        The unmapped ``╱`` gap hatch is NOT a ``BandSegment`` — it stays a plain
        ``Static`` because there is no region behind it to inspect or open.

    Args:
        content (Text): The markup-safe repeated band glyph for this run.
        region_start (int): Inclusive start address of the run.
        region_end (int): Exclusive end address of the run.
        classes (str): Space-joined CSS classes (``map-band-seg`` + the run's
            ``band-*`` token) — unchanged from the pre-batch-67 ``Static``, so
            the strip renders identically.
        band_glyph (str): This run's band glyph, retained so the segment can be
            RE-rendered at a new width when the container is measured or
            resized (batch-77, LLR-111.1) without re-deriving the band.

    Data Flow:
        - Mounted by ``MemoryMapPanel._build_band_widgets``; on click posts
          :class:`RegionRow.Activated` → ``MemoryMapPanel.on_region_row_activated``.

    Dependencies:
        Uses:
            - :class:`RegionRow.Activated` (the shared message)
        Used by:
            - ``MemoryMapPanel._build_band_widgets``
            - ``MemoryMapPanel._resize_band_segments`` (reads ``band_glyph``)
    """

    def __init__(
        self,
        content: Text,
        region_start: int,
        region_end: int,
        classes: str,
        band_glyph: str = "",
    ) -> None:
        super().__init__(content, classes=classes)
        self.region_start = region_start
        self.region_end = region_end
        self.band_glyph = band_glyph

    def on_click(self, event: events.Click) -> None:
        """Post :class:`RegionRow.Activated` for this band run's window."""
        self.post_message(
            RegionRow.Activated(
                self.region_start, self.region_end, chain=event.chain
            )
        )


class BandBar(Horizontal):
    """The band strip, which REPORTS ITS OWN RESIZE (batch-77, LLR-111.1).

    Summary:
        A plain ``Horizontal`` holding the ``BandSegment`` runs and the ``╱`` gap
        markers, with one addition: when it is laid out it posts
        :class:`Measured` so the panel can re-apportion against a width that is
        now knowable.

        **This closes the hole that shipped the degenerate bar.**
        ``_build_band_widgets`` runs before ``grid.mount()`` takes effect, so the
        first apportionment is made against ``#map_grid``, which measures 0 at
        that moment at both regimes — every run starts at
        ``_allocate_band_widths``' out-of-domain ``[1] * n_runs`` floor. Pre-fix
        the correction depended on three things, none of which is the bar
        learning its own width:

          1. ``render_ranges``' ``call_after_refresh`` — traced observing 0.
          2. Its ONE bounded retry — traced observing 0 whenever layout takes
             longer than one extra frame.
          3. ``MemoryMapPanel.on_resize`` — which fires only when the PANEL is
             resized. ``events.Resize`` is declared ``bubble=False``, so a
             DESCENDANT's resize cannot reach the panel at all. On the dev
             machine the panel happens to still be settling (72→70 wide, 10→42
             tall) and its handler incidentally repaired the bar; on CI it did
             not, and every run painted one column on an in-domain image.

        A ``Message`` is used rather than a direct call because ``Message``
        bubbles where ``Resize`` does not, so the panel hears about a descendant
        it does not otherwise observe, and the widget stays ignorant of who is
        listening.

        This CANNOT spin, and the reason is **CSS, not the idempotence guard.**
        The bar's width is **content-independent**: ``.map-band-bar`` is
        ``width: 100%`` (``styles.tcss:798``) and ``Horizontal`` does not
        scroll, so rewriting segment content can never change the bar's own
        size and therefore never re-delivers ``Resize``. **Measured:** 14
        segments forced to 40 columns each — 560 columns of content in a
        66-column bar — left ``bar.region.width`` at **66** and posted **0**
        ``Measured``. **The loop is structurally open, not merely guarded.**

        ⚠️ **Changing ``.map-band-bar`` to ``width: auto`` would CLOSE that
        loop**, and the settle path performs genuinely non-no-op passes (4–6
        writes per render, measured), so the cycle would be live rather than
        hypothetical.

        ``_resize_band_segments``' *"rewrite only when the rendered length
        differs"* guard is a **second line of defence**, not the reason. An
        earlier draft of this docstring named it as the reason — which is false
        for the case that actually occurs, since during settle the widths
        genuinely differ, writes genuinely happen, and no spin follows anyway.

        The widget carries NO member named ``_nodes`` / ``_context`` (Textual
        internal-shadowing guard — verified
        ``set(dir(Widget)) & {"Measured"} == ∅``).

    Data Flow:
        - Built by ``MemoryMapPanel._build_band_widgets``; posts
          :class:`Measured` → ``MemoryMapPanel.on_band_bar_measured`` →
          ``_resize_band_segments``.

    Dependencies:
        Used by:
            - ``MemoryMapPanel._build_band_widgets``
            - ``MemoryMapPanel.on_band_bar_measured``
    """

    class Measured(Message):
        """The band bar has been laid out and its width is now knowable."""

    def on_resize(self, event: events.Resize) -> None:
        """Tell the panel the bar's width changed, so it can re-apportion."""
        self.post_message(self.Measured())


class MapRuler(Horizontal):
    """Address ruler beneath the entropy band strip (batch-77, R-TUI-072).

    Summary:
        A single-row ruler labelling the addresses the bar above it actually
        draws: one markup-safe ``.map-ruler-tick`` ``Static`` per emitted RUN
        start, plus one for the LAST MAPPED BYTE (LLR-112.1). Ticks are
        distributed by ``width: 1fr`` and labels are 8 hex digits WITHOUT the
        ``0x`` prefix (C-13.1 deficit-matched fallback, already spent at
        batch-47).

        **This retires the batch-47 percentile derivation** — five ticks at
        0/25/50/75/100 % of the image address SPAN (the superseded LLR-072.3).
        A percentile of the span is an arithmetic position, not an address the
        image contains: measured on ``case_02`` and on ``prg.s19``, 4 of the 5
        labels named addresses that lie in no mapped range at all, and the
        100 % tick named the EXCLUSIVE ``span_end``, which is by construction
        the first byte past the image. The end label is therefore
        ``span_end - 1`` — executed on ``case_02``,
        ``address_in_sorted_ranges(0x8001013F, index)`` is True while
        ``0x80010140`` (its ``span_end``) is False.

        The retained set is elided against the ruler's own MEASURED width
        (``_reflow_ticks``), never a proxy: executed at Phase 3, ``#map_grid``
        reports width 0 at the moment ``_build_band_widgets`` runs, at both
        regimes, so no width is knowable where the widget is constructed.
        ``compose`` therefore emits the FULL set — which is already correct
        inside HLR-112's domain — and the first ``Resize`` narrows it if the
        width cannot carry it.

        The widget carries NO member named ``_nodes`` / ``_context`` (Textual
        internal-shadowing guard — verified
        ``set(dir(Widget)) & {_tick_addrs} == ∅``).

    Args:
        run_starts (Sequence[int]): Start address of every emitted run, in bar
            order. Ties with ``last_mapped_byte`` are de-duplicated.
        last_mapped_byte (int): Inclusive address of the image's final mapped
            byte — ``span_end - 1``, never the exclusive ``span_end``.

    Data Flow:
        - Built by ``MemoryMapPanel._build_band_widgets`` from the SAME merged
          runs the band bar apportions, so the ruler labels the segments the
          operator is looking at; mounted as a ``#map_grid`` child beneath the
          band row.

    Dependencies:
        Uses:
            - ``safe_text`` (markup-safe tick labels)
            - ``_retained_tick_addresses`` (elision)
        Used by:
            - ``MemoryMapPanel._build_band_widgets``

    Example:
        >>> ruler = MapRuler([0x80000000, 0x80008000], 0x8000FFFF)
        >>> [f"{addr:08X}" for addr in ruler._tick_addrs]
        ['80000000', '80008000', '8000FFFF']
    """

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

    def __init__(
        self, run_starts: Sequence[int], last_mapped_byte: int
    ) -> None:
        super().__init__(classes="map-ruler")
        # Sorted + de-duplicated here, once, so ascending-and-distinct is a
        # property of the data rather than a promise every consumer re-checks.
        # A single-byte run makes its start EQUAL the last mapped byte.
        self._tick_addrs = sorted({*run_starts, last_mapped_byte})

    def compose(self) -> ComposeResult:
        """Yield one markup-safe tick label per retained address.

        Summary:
            Emit the FULL tick set. Inside HLR-112's domain that is the final
            answer and no reflow follows; outside it, the first ``Resize``
            elides. Composing the full set rather than an elided guess is what
            makes in-domain correctness independent of whether a ``Resize`` ever
            arrives — the failure mode of the alternative is a silently empty
            ruler, which ``AT-B77-04``'s lower bound exists to forbid.

        Returns:
            ComposeResult: one ``.map-ruler-tick`` ``Static`` per tick address.

        Dependencies:
            Uses:
                - ``safe_text``
            Used by:
                - Textual mount pipeline
        """
        for addr in self._tick_addrs:
            yield Static(safe_text(f"{addr:08X}"), classes="map-ruler-tick")

    def on_resize(self, event: events.Resize) -> None:
        """Re-elide the ruler against its newly measured width."""
        self._reflow_ticks(event.size.width)

    def _reflow_ticks(self, ruler_width: int) -> None:
        """Mount exactly the labels ``ruler_width`` can carry legibly.

        Summary:
            Reconcile the mounted ticks with
            ``_retained_tick_addresses(self._tick_addrs, ruler_width)``
            (LLR-112.2). The comparison against what is already mounted is
            load-bearing, not an optimisation: a remount invalidates layout and
            would deliver another ``Resize``, so an unconditional rewrite would
            re-arm itself every frame. It also keeps the common path — an
            in-domain image, where ``compose`` already emitted the right set —
            free of any remove/mount churn at all, and ``remove_children()`` is
            DEFERRED, so a needless churn would leave stale ticks matching
            ``.map-ruler-tick`` for a window.

        Args:
            ruler_width (int): The width just measured for this widget.

        Returns:
            None

        Dependencies:
            Uses:
                - ``_retained_tick_addresses`` / ``safe_text``
            Used by:
                - ``on_resize``
        """
        labels = [
            f"{addr:08X}"
            for addr in _retained_tick_addresses(self._tick_addrs, ruler_width)
        ]
        mounted = list(self.query(".map-ruler-tick"))
        if [str(tick.render()) for tick in mounted] == labels:
            return
        self.remove_children()
        self.mount(
            *(
                Static(safe_text(label), classes="map-ruler-tick")
                for label in labels
            )
        )
