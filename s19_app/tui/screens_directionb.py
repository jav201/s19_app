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
  - ``FlowBuilderPanel`` — MOVED to ``s19_app/tui/flow_screens.py`` (batch-94
    Inc-002, the R8/B2 move): the fb_a reworked Flow Builder now lives in the
    flow family's own module; this file keeps the Direction-B shell.

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
import json
from dataclasses import dataclass
from datetime import datetime
from math import ceil
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    List,
    Mapping,
    NamedTuple,
    Optional,
    Sequence,
    Tuple,
    Union,
)

from rich.cells import cell_len, set_cell_size
from rich.text import Text
from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.content import Content
from textual.containers import (
    Container,
    Horizontal,
    ScrollableContainer,
    Vertical,
    VerticalScroll,
)
from textual.coordinate import Coordinate
from textual.message import Message
from textual.widget import Widget
from textual.widgets import (
    Button,
    ContentSwitcher,
    DataTable,
    Input,
    Label,
    ListItem,
    ListView,
    Select,
    Static,
    TextArea,
)

from .changes.io import DUMMY_CHANGESET_TEXT, is_check_spec_name
from .color_policy import css_class_for_severity
from .entropy_style import ENTROPY_BAND_LABELS, band_style
from .insight_style import (
    CYAN,
    DGRAY,
    GREEN,
    LABEL,
    PURPLE,
    RED,
    VALUE,
    YELLOW,
    cap_gauge_style,
    human_bytes,
    label_value,
    microbar,
)
from .json_highlight import JsonHighlightTextArea
from .os_clipboard_input import _CLIPBOARD_READ_CAP_CHARS
from .os_clipboard_input import OsClipboardInput
from ..range_index import address_in_sorted_ranges, build_sorted_range_index
from textual.screen import ModalScreen
from .services.entropy_service import EntropyWindow
from ..validation import ValidationIssue, ValidationSeverity

if TYPE_CHECKING:
    from .models import LoadedFile


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


#: Columns an unmapped gap folds to, independent of its byte size and of the
#: container width (batch-77, LLR-111.2). A gap is a separator, not a quantity:
#: at the measured container widths a proportional gap consumed up to 60 of 66
#: columns and floored nine mapped runs to one column each. Sizing gaps by their
#: address span is what the fold retires.
_BAND_GAP_FOLD = 1

#: Rendered width of one address-ruler tick label — 8 hex digits, the ``0x``
#: prefix already spent as a C-13.1 deficit-matched fallback (batch-47).
_RULER_LABEL_WIDTH = 8

#: Columns one ruler tick claims: its label plus at least one blank separator
#: column (batch-77, LLR-112.2). The separator is NORMATIVE, not cosmetic — two
#: adjacent 8-hex labels with no gap render as an unreadable 16-digit run, and
#: the pitch is what decides whether an image is inside HLR-112's domain. At
#: pitch 8 the ceiling reads 8/6 instead of 7/5 and ``case_07_stress_smoke``
#: (6 ticks) would appear in domain at 120x30 when it is not.
_RULER_TICK_PITCH = _RULER_LABEL_WIDTH + 1

#: 9-glyph entropy ramp (0.0 → 8.0 bits/byte) for the At-a-glance sparkline
#: (batch-45, R-TUI-061 / LLR-045B.2). Index 0 = a space (near-zero entropy),
#: index 8 = a full block (maximal entropy). Mirrors the prototype ``BARS``.
_ENTROPY_BAR_RAMP = " ▁▂▃▄▅▆▇█"

#: Fixed number of sparkline columns the profile is sampled to (LLR-045B.2).
#: Retired from the always-on surface at batch-93 (the docked glance block
#: folded to one chips line) but kept — ``sparkline_glyphs`` remains a tested
#: unit of the entropy-profile sampling. (The glance histogram's
#: ``_GLANCE_BAR_WIDTH`` constant retired with the docked block it sized.)
_SPARKLINE_WIDTH = 24

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


from ..utils import safe_text


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


def _clip_to_cells(text: str, cap: int) -> str:
    """Clip ``text`` to ``cap`` terminal COLUMNS, marking the loss with an ellipsis.

    Summary:
        The house clip seam (``S19TuiApp._clip_to``, app.py), reimplemented at
        module scope because ``app.py`` imports this module (a circular import
        would otherwise pull the whole app into the panel). Columns, not code
        points: ``cell_len`` / ``set_cell_size`` come from ``rich`` (already a
        hard dependency via Textual), and ``set_cell_size`` handles a cap
        falling in the MIDDLE of a double-width character — the correct result
        there is a pad space, not half a glyph. An over-long authored or
        file-derived line is shortened AT A CELL BOUNDARY here so the painted
        line never wraps mid-content (batch-93 inc-002, HLR-130 — the wrap
        audit asserts the no-wrap law over every authored surface).

    Args:
        text (str): The line to clip (authored or file-derived).
        cap (int): The maximum cell width the painted line may claim.

    Returns:
        str: ``text`` when it already fits; otherwise its first ``cap - 1``
        columns plus an ellipsis.

    Example:
        >>> _clip_to_cells("abcdef", 4)
        'abc…'
        >>> _clip_to_cells("ab", 4)
        'ab'
    """
    if cap <= 0:
        return ""
    if cell_len(text) <= cap:
        return text
    if cap == 1:
        return "…"
    return set_cell_size(text, cap - 1) + "…"


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


class LoadedArtifactsPanel(Container):
    """The Workspace "Loaded" panel — the persistent load-state readout.

    Summary:
        A compact, always-visible panel on the Workspace rail screen showing the
        three typed artifact slots (S19/HEX spine, MAC, A2L companion). Each slot
        renders either present (kind + escaped file name + a counts/sizes
        summary) with an active ``[u]`` unload affordance, or a dim ``(none)``
        when absent; a footer ``[U]`` unloads everything. The panel is purely
        presentational — it holds no load state, reads the ``LoadedFile``
        snapshot handed to ``render_slots``, and drives unloads by posting
        ``UnloadRequested`` for ``S19TuiApp`` to act on. Every file-derived name
        is wrapped by ``safe_text`` and every summary is counts/sizes only
        (bytes / ranges / records / tags) — no file-derived markup sink
        (security B3).

    Args:
        None

    Returns:
        None

    Data Flow:
        - ``render_slots`` receives the current ``LoadedFile`` (or ``None``) from
          ``S19TuiApp._refresh_loaded_panel`` after every load and unload, clears
          ``#loaded_slots`` and re-mounts the three slot rows plus the
          unload-all row. Re-mounted children carry only CLASSES (never ids), so
          repeated renders never trip ``DuplicateIds`` — the same pattern as
          ``MemoryMapPanel.render_ranges``.
        - A slot's ``[u]`` / the footer ``[U]`` post ``UnloadRequested`` with the
          artifact key; ``S19TuiApp.on_loaded_artifacts_panel_unload_requested``
          dispatches to ``_apply_unload``.

    Dependencies:
        Uses:
            - ``safe_text`` (markup-safe names) / ``Content`` (literal button
              labels) / ``human_bytes`` (byte summary).
            - The three presence predicates inlined here (spine
              ``file_type``+``ranges``; ``mac_path``/``mac_records``;
              ``a2l_path``/``a2l_data``) — a mirror of ``app._has_primary`` /
              ``_has_mac`` / ``_has_a2l``, inlined to avoid the ``app`` import
              cycle (``app`` imports this module).
        Used by:
            - ``S19TuiApp._compose_screen_workspace`` (mounts the widget).
            - ``S19TuiApp._refresh_loaded_panel`` (drives ``render_slots``).

    Example:
        >>> panel = LoadedArtifactsPanel()
        >>> panel.id
        'loaded_panel'
    """

    #: (artifact-key, column-label) for the three slots, in display order.
    _SLOTS: Tuple[Tuple[str, str], ...] = (
        ("primary", "S19"),
        ("mac", "MAC"),
        ("a2l", "A2L"),
    )
    _ABSENT_TEXT = "(none)"
    #: LLR-120.2's absent sentinel for the project row. Bound here, in the class
    #: body, so `render_slots`'s default argument resolves it at definition time
    #: and the panel's "nothing loaded shows a sentinel, never a blank" contract
    #: (TC-B78-09) holds even for a caller that omits the argument entirely --
    #: `on_mount` is exactly such a caller.
    _PROJECT_ABSENT = _ABSENT_TEXT
    #: The project row's kind-cell token. `.loaded-kind` is `width: 6`, so the
    #: obvious `"project"` CLIPS to `"projec"` and runs into the detail cell —
    #: found by the Inc-6/Inc-7 independent review, and only visible through the
    #: PAINTED strip; `render()` returned the full word throughout. Four
    #: uppercase characters also match the siblings (`S19` / `MAC` / `A2L`)
    #: rather than introducing a second style of label in one column. Named so
    #: the acceptances match the EMITTED token instead of re-typing it.
    _PROJECT_KIND = "PROJ"

    class UnloadRequested(Message):
        """A slot's ``[u]`` / the footer ``[U]`` asked to unload an artifact.

        Summary:
            Posted by ``LoadedArtifactsPanel`` when an unload affordance is
            pressed; ``app.py`` handles it and calls ``_apply_unload``. The panel
            performs no teardown itself — it only names the artifact.

        Args:
            artifact (str): One of ``"primary"`` / ``"mac"`` / ``"a2l"`` /
                ``"all"`` — the ``_apply_unload`` kind.

        Dependencies:
            Used by:
                - ``S19TuiApp.on_loaded_artifacts_panel_unload_requested``
        """

        def __init__(self, artifact: str) -> None:
            super().__init__()
            self.artifact = artifact

    def __init__(self) -> None:
        super().__init__(id="loaded_panel")

    def compose(self) -> ComposeResult:
        """Yield the panel title and the re-mount target container.

        Returns:
            ComposeResult: the ``Loaded`` title label and the empty
            ``#loaded_slots`` container that ``render_slots`` fills.

        Dependencies:
            Used by:
                - Textual mount pipeline
        """
        yield Label("Loaded", id="loaded_title", markup=False)
        yield Container(id="loaded_slots")

    def on_mount(self) -> None:
        """Render the initial all-absent slots once the tree is mounted.

        Returns:
            None

        Dependencies:
            Used by:
                - Textual mount pipeline
        """
        self.render_slots(None)

    def render_slots(
        self, loaded: Optional["LoadedFile"], project: str = _PROJECT_ABSENT
    ) -> None:
        """Rebuild the project row + three slot rows (+ unload-all) from a snapshot.

        Summary:
            Clear ``#loaded_slots`` and re-mount the project row, one row per
            artifact and the unload-all footer, reflecting ``loaded``'s
            present/absent state. Re-mounted children carry only CLASSES (never
            ids), so repeated renders never trip ``DuplicateIds`` (the
            ``MemoryMapPanel`` pattern).

        Args:
            loaded (Optional[LoadedFile]): The current snapshot, or ``None`` when
                nothing is loaded (all three slots render ``(none)``).
            project (str): The already-composed project string for the project
                row (``LLR-120.2``) — the plain name at one variant,
                ``project:variant (index/total)`` above that. The FORM is the
                caller's: this panel renders what it is handed and never
                re-derives it, which is what keeps the two context surfaces from
                drifting apart (``LLR-120.5``). Defaults to the absent sentinel
                so ``on_mount``, which passes nothing, renders ``(none)`` rather
                than a blank.

        Returns:
            None

        Raises:
            None

        Data Flow:
            - Read-only over ``loaded`` and ``project``; per slot compute
              (present, name, summary) via ``_slot_state`` and build a row via
              ``_build_slot_row``; the project row via ``_build_project_row``.
            - Tolerates a not-yet-mounted tree (headless render before compose).

        Dependencies:
            Uses:
                - ``_slot_state`` / ``_build_slot_row`` / ``_build_project_row``
                  / ``_build_unload_all_row``.
            Used by:
                - ``S19TuiApp._refresh_loaded_panel`` and ``on_mount``.
        """
        try:
            slots = self.query_one("#loaded_slots", Container)
        except Exception:
            # Tree not mounted yet (headless render before compose).
            return
        slots.remove_children()
        rows: List[Widget] = []
        # LLR-120.2 -- the project row. FIRST, above the artifact slots: the
        # project is the context the three artifacts sit inside, not a fourth
        # artifact. It is built through `safe_text` like every other
        # file-derived cell in this panel (LLR-120.4): a project name is a
        # DIRECTORY name on the operator's own disk, and `U+009B` / `U+009D`
        # are single-byte C1 introducers that carry no `\x1b` and are legal
        # Windows filename characters. A `markup=False`-only row would sit
        # scrub-inconsistent beside scrubbed siblings, and
        # `grep -rl "loaded_slots\|_build_slot_row" tests/` returns 0 files, so
        # nothing in the repo would have caught it.
        rows.append(self._build_project_row(project))
        for artifact, kind in self._SLOTS:
            present, name, summary = self._slot_state(loaded, artifact)
            rows.append(self._build_slot_row(artifact, kind, present, name, summary))
        rows.append(self._build_unload_all_row(loaded is not None))
        slots.mount(*rows)

    def _build_project_row(self, project: str) -> Horizontal:
        """Build the Loaded panel's project row (LLR-120.2).

        Summary:
            One row naming the active project, in whichever display form the
            caller computed -- the plain name at N <= 1 variants, the
            ``project:variant (index/total)`` form above that (LLR-120.5). The
            FORM is the caller's business: this panel renders the string it is
            handed and never re-derives it, which is what keeps the two context
            surfaces from drifting apart.

        Args:
            project (str): The already-composed project string, or the absent
                sentinel.

        Returns:
            Horizontal: the project row, shaped like a slot row so it inherits
            the panel's existing column rhythm.
        """
        absent = project == self._PROJECT_ABSENT
        kind_cell = Static(Content(self._PROJECT_KIND), classes="loaded-kind")
        # `loaded-project-detail`, NOT `loaded-detail`. The latter is the
        # marker the three ARTIFACT slots carry, and two shipped readers select
        # on it and index the result POSITIONALLY as [primary, mac, a2l]
        # (`tests/test_unload_feature.py::_detail_texts`,
        # `tests/test_help_toggle_and_a2l_panel.py`). Reusing it here made the
        # query return four cells with the project at index 0, shifting every
        # artifact index by one and reddening six shipped tests -- while
        # violating LLR-120.2's "shall not alter the existing three artifact
        # slots" verbatim. The row still carries `loaded-slot` for the column
        # rhythm; nothing selects that positionally.
        detail = Static(
            safe_text(project),
            classes=(
                "loaded-project-detail loaded-absent"
                if absent
                else "loaded-project-detail"
            ),
        )
        return Horizontal(
            kind_cell,
            detail,
            classes="loaded-slot loaded-slot-absent" if absent else "loaded-slot",
        )

    def _slot_state(
        self, loaded: Optional["LoadedFile"], artifact: str
    ) -> Tuple[bool, str, str]:
        """Resolve one slot's (present, name, summary) triple from a snapshot.

        Summary:
            Inline the three presence predicates (spine / MAC / A2L) and, when
            present, source the name from the artifact's OWN path field
            (``path`` for the image spine, ``mac_path`` for MAC, ``a2l_path`` for
            A2L — never the bare ``path`` for MAC/A2L, which a MAC-only state
            leaves pointing at the former image) and build a counts/sizes-only
            summary.

        Args:
            loaded (Optional[LoadedFile]): The current snapshot or ``None``.
            artifact (str): ``"primary"`` / ``"mac"`` / ``"a2l"``.

        Returns:
            Tuple[bool, str, str]: ``(present, name, summary)``; ``name`` is the
                raw file-derived name (the caller escapes it) and ``summary`` is
                counts/sizes only. Empty names when absent.

        Raises:
            None

        Data Flow:
            - Read-only over ``loaded`` fields; no mutation, no re-derivation.

        Dependencies:
            Uses:
                - ``human_bytes`` (byte-count formatting).
            Used by:
                - ``render_slots``.
        """
        if loaded is None:
            return False, "", ""
        if artifact == "primary":
            present = loaded.file_type in {"s19", "hex"} and bool(loaded.ranges)
            if not present:
                return False, "", ""
            summary = f"{human_bytes(len(loaded.mem_map))} · {len(loaded.ranges)} rng"
            return True, loaded.path.name, summary
        if artifact == "mac":
            present = loaded.mac_path is not None or bool(loaded.mac_records)
            if not present:
                return False, "", ""
            name = loaded.mac_path.name if loaded.mac_path else "mac"
            count = len(loaded.mac_records)
            summary = f"{count} record{'' if count == 1 else 's'}"
            return True, name, summary
        # artifact == "a2l"
        present = loaded.a2l_path is not None or loaded.a2l_data is not None
        if not present:
            return False, "", ""
        name = loaded.a2l_path.name if loaded.a2l_path else "a2l"
        count = len((loaded.a2l_data or {}).get("tags", []))
        summary = f"{count} tag{'' if count == 1 else 's'}"
        return True, name, summary

    def _build_slot_row(
        self, artifact: str, kind: str, present: bool, name: str, summary: str
    ) -> Horizontal:
        """Build one slot row: kind cell + detail cell + (present) ``[u]``.

        Summary:
            Compose a single slot row. A present slot shows the escaped name and
            summary with an active ``[u]`` ``Button`` carrying the artifact key
            on its ``name`` (no id — re-render safe). An absent slot shows a dim
            ``(none)`` and no affordance.

        Args:
            artifact (str): The artifact key set as the ``[u]`` button ``name``.
            kind (str): The fixed column label (``S19`` / ``MAC`` / ``A2L``).
            present (bool): Whether the artifact is loaded.
            name (str): File-derived name (escaped here via ``safe_text``).
            summary (str): Counts/sizes-only summary (empty when absent).

        Returns:
            Horizontal: the slot row.

        Raises:
            None

        Data Flow:
            - Pure widget construction; ``safe_text`` neutralises the file name;
              the button label is a literal ``Content`` (no markup parse).

        Dependencies:
            Uses:
                - ``safe_text`` / ``Content`` / ``Button`` / ``Static``.
            Used by:
                - ``render_slots``.
        """
        kind_cell = Static(safe_text(kind), classes="loaded-kind")
        if present:
            detail = Static(
                safe_text(f"{name}  {summary}"), classes="loaded-detail"
            )
            unload = Button(
                Content("[u]"),
                name=artifact,
                compact=True,
                classes="loaded-unload",
            )
            return Horizontal(kind_cell, detail, unload, classes="loaded-slot")
        detail = Static(
            safe_text(self._ABSENT_TEXT), classes="loaded-detail loaded-absent"
        )
        return Horizontal(
            kind_cell, detail, classes="loaded-slot loaded-slot-absent"
        )

    def _build_unload_all_row(self, any_loaded: bool) -> Horizontal:
        """Build the footer row: an ``unload all`` label + the ``[U]`` button.

        Summary:
            The ``[U]`` button is present (active) only when something is loaded;
            with nothing loaded the row shows a dim label and no affordance.

        Args:
            any_loaded (bool): Whether any artifact is loaded.

        Returns:
            Horizontal: the unload-all footer row.

        Raises:
            None

        Data Flow:
            - Pure widget construction; constant labels only (no file-derived
              text); the ``[U]`` button carries ``name="all"``.

        Dependencies:
            Uses:
                - ``safe_text`` / ``Content`` / ``Button`` / ``Static``.
            Used by:
                - ``render_slots``.
        """
        label_cls = (
            "loaded-alllabel" if any_loaded else "loaded-alllabel loaded-absent"
        )
        children: List[Widget] = [Static(safe_text("unload all"), classes=label_cls)]
        if any_loaded:
            children.append(
                Button(
                    Content("[U]"),
                    name="all",
                    compact=True,
                    classes="loaded-unload loaded-unload-all",
                )
            )
        return Horizontal(*children, classes="loaded-allrow")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Translate an unload button press into an ``UnloadRequested`` post.

        Summary:
            Every button in this panel is an unload affordance whose ``name`` is
            the artifact key; read it, stop the event so it does not reach the
            app's id-keyed ``on_button_pressed``, and post ``UnloadRequested``.

        Args:
            event (Button.Pressed): The button-press message.

        Returns:
            None

        Raises:
            None

        Data Flow:
            - ``event.button.name`` → ``UnloadRequested`` posted to the app.

        Dependencies:
            Uses:
                - ``UnloadRequested`` / ``Message.stop``.
            Used by:
                - Textual message dispatch (child ``Button`` presses).
        """
        artifact = event.button.name
        if not artifact:
            return
        event.stop()
        self.post_message(self.UnloadRequested(artifact))


class MemoryMapPanel(Container):
    """Entropy band view of the loaded image's mapped memory.

    Summary:
        Renders the image as an ENTROPY band view (batch-45, R-TUI-060): a
        proportional band bar + a per-region list (address · size · band),
        merged by ``_merge_band_runs`` from the loader-computed
        ``LoadedFile.entropy_windows`` handed to ``render_ranges``. This
        replaced the batch-27 ``sev-*`` validity cell grid (the ``MapCell`` +
        arrow-nav machinery was removed in batch-45 Inc-5; a single click on a
        region row drives detail + hex nav via ``on_region_row_activated``).
        batch-93 (HLR-125..129, the memmap2 charter's variant C) re-composes the
        same facts as the inspector cockpit: chromed ``.db-pane`` panes, the
        left pane stacking band bar → ruler → one-line glance chips → scrollable
        region list beside a full-height inspector (aligned fields + multi-row
        8-byte peek), fixed-width region rows, and a one-line width-adaptive
        stats strip that always paints without scrolling. It is a pure
        presentational widget — it performs NO entropy, coverage,
        parsing or validation of its own (LLR-045A.2 / LLR-041.7).
        Band colours route through the ``band-*`` CSS classes owned by
        ``entropy_style`` + ``styles.tcss`` (LLR-045A.3); no colour hex is
        hard-coded. With no image / no entropy it preserves the neutral no-data
        note (LLR-045A.5).

    Args:
        None

    Returns:
        None

    Data Flow:
        - ``render_ranges`` receives the pre-computed ``ranges`` +
          ``range_validity`` + ``entropy_windows`` from
          ``S19TuiApp.update_memory_map``, merges contiguous same-band windows
          via ``_merge_band_runs``, and mounts the ``.map-band-seg`` band bar,
          the ruler, the one-line ``.map-glance-chips`` and the scrollable
          ``.map-region-list`` into the ``#map_grid`` pane — no per-cell
          ``.map-cell`` widgets are mounted.
        - Clicking a region row drives ``on_region_row_activated`` →
          ``_select_region`` populates ``#map_detail`` (the aligned field block
          + 8-byte peek) and posts ``OpenInHexRequested`` on a double click
          (batch-67 N4a); the ``#map_stats`` strip shows the seven coverage
          statistics as ONE width-adaptive line derived by ``coverage_stats``
          (batch-93, HLR-129).
        - With no ranges / no entropy the header shows the neutral empty note,
          no segments/rows are mounted, and the stats strip is blanked (LLR-041.9).
        - ``#map_grid`` and ``#map_detail`` sit in a ``#map_body`` sub-container
          laid horizontally at or above the panel-measured stack threshold
          (``_MAP_STACK_MIN_WIDTH``) and stacked below it — the panel toggles
          its own ``width-narrow`` class (HLR-131, batch-93 inc-002) and the
          reflow rules live in ``styles.tcss`` (LLR-041.10's class, re-anchored
          to the panel).

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
    #: Shown when an image IS loaded but yields no entropy band detail (zero
    #: span or band-less image) — kept distinct from ``_EMPTY_TEXT`` so a loaded
    #: image is never mislabelled "No file loaded" (fix-memmap-entropy AC-3).
    _NO_ENTROPY_TEXT = "No entropy detail for this image."
    #: The pre-selection inspector note, AUTHORED as two lines (batch-93
    #: inc-002, HLR-130): at side-by-side the inspector interior measures 40
    #: columns (38 once its scrollbar appears), so the retired one-line form
    #: (59 cells) wrapped mid-content at every side-by-side geometry — the
    #: wrap audit's first defect. Both authored lines measure <= 29 cells,
    #: clearing the narrowest painted interior with margin. The newline is a
    #: LINE BREAK, never content: the hint renders through ``Text`` directly,
    #: NOT through ``safe_text`` (whose C0/C1 scrub would delete it — the
    #: house rule: newlines join ``Text`` lines directly, as in
    #: ``build_detail_text``).
    _DETAIL_HINT = "Click a region to inspect it.\nDouble-click to open in hex."
    #: The selection marker class (batch-77, LLR-117.1). Carried in ADDITION to
    #: the row's ``band-*`` token, never in place of it: ``styles.tcss`` sets a
    #: background only, so the band's foreground colour survives selection
    #: (LLR-117.2).
    _SELECTED_ROW_CLASS = "map-region-selected"

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
        #: The last non-empty stats inputs (``ranges``, ``range_validity``,
        #: ``issues``) — carried so a live panel resize can re-render the
        #: width-adaptive one-line strip when the width crosses the
        #: ``_STATS_FULL_MIN_WIDTH`` threshold (batch-93, LLR-129.2). ``None``
        #: on the empty paths (the strip stays blank until the next render).
        self._stats_state: Optional[
            Tuple[List[Tuple[int, int]], List[bool], List[ValidationIssue]]
        ] = None
        #: Render generation counter — incremented on EVERY ``render_ranges``
        #: call so a deferred selection hook from a SUPERSEDED render can tell
        #: it is stale and stand down (batch-93: the bounded auto-selection
        #: retry extends the hook's window by one frame; without the guard a
        #: late retry could re-apply the previous render's resolution).
        self._render_generation = 0
        #: The merged runs of the last POPULATED render — the populated-path
        #: sentinel for the resize-driven width re-apportionment (batch-93
        #: inc-002, HLR-131 / LLR-131.2). ``None`` on the empty paths.
        self._last_runs: Optional[List[Tuple[str, int, int]]] = None
        #: The original inputs of the last populated render — carried so the
        #: resize-driven width re-apportionment can re-run ``render_ranges``
        #: itself (the single selection authority: generation-guarded hook,
        #: bounded retry, selection carried across), instead of a second
        #: remove/mount path with its own selection hook that could bind the
        #: superseded rows (batch-93 inc-002, HLR-131 / LLR-131.2).
        self._last_render_inputs: Optional[
            Tuple[
                List[Tuple[int, int]],
                List[bool],
                List[ValidationIssue],
                List[Mapping[str, Any]],
                List[EntropyWindow],
            ]
        ] = None
        #: The microbar-gate decision the CURRENTLY mounted rows were built
        #: with — the rebuild's change detector. Recorded by
        #: ``_build_band_widgets`` (the single build path, render and rebuild
        #: alike); ``None`` before the first populated render.
        self._rows_show_microbar_last: Optional[bool] = None

    def compose(self) -> ComposeResult:
        """Compose the header, the inspector-cockpit body and the stats strip.

        Summary:
            Yield the full-width header (the band summary, or the neutral
            no-file note), then a ``#map_body`` sub-container holding the two
            chromed cockpit panes side by side (batch-93, HLR-125/126 —
            variant C): the ``#map_grid`` ``.db-pane`` (lit title
            ``Memory Map``, subtitle ``{N} regions · ░▒▓ k``) carries the 1-row
            band bar, the run-start ruler, the one-line glance chips and the
            scrollable region list; the ``#map_detail`` ``.db-pane`` (lit title
            ``Inspector — 0x{selected:08X}``, subtitle ``↑↓ · ↵ hex``) carries
            the full-height aligned field block + 8-byte hex peek. The panes
            render side by side at or above the panel-measured stack threshold
            and stacked below it — the panel toggles its own ``width-narrow``
            class at ``_MAP_STACK_MIN_WIDTH`` (batch-93 inc-002, HLR-131; the
            reflow rules live in ``styles.tcss``, reusing the existing class
            per LLR-041.10). Finally the
            full-width ``#map_stats`` coverage strip renders OUTSIDE any scroll
            region so the one-line stats always paint in the visible viewport
            (batch-93, HLR-129 — defect ④ of premise P-1).

        Returns:
            ComposeResult: the header, the two-pane cockpit body, and the
            stats strip.

        Dependencies:
            Used by:
                - Textual mount pipeline
        """
        yield Label(self._EMPTY_TEXT, id="map_header", markup=False)
        yield Horizontal(
            Container(id="map_grid", classes="db-pane"),
            Container(
                # The hint's newline is a line break, not content — ``Text``
                # joins it directly (``safe_text``'s C0 scrub would eat it).
                Static(Text(self._DETAIL_HINT), id="map_detail_body"),
                id="map_detail",
                classes="db-pane",
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
            band bar + a per-region list (batch-45, R-TUI-060 /
            LLR-045A.2..045A.6; the band legend that used to sit below the list
            moved to the ``k`` legend screen at batch-77, HLR-114). This
            REPLACES the batch-27 ``sev-*`` validity
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
              band bar (``.map-band-bar``) and region list
              (``.map-region-list``) into ``#map_grid``; the header shows a
              band summary. The summary is stored on ``rendered_text``.
              Both are addressed by CLASS (not id) because they are
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

        # A new render supersedes any deferred hook still in flight from the
        # previous one (the auto-selection retry carries its generation).
        self._render_generation += 1
        generation = self._render_generation

        grid.remove_children()
        self._issues = list(issues)
        self._a2l_tags = list(a2l_tags)
        self._mem_map = mem_map or {}
        self._run_bands = {}
        # Read BEFORE ``_reset_detail()``, which nulls it. This is the only
        # carrier of the prior selection across a re-render (LLR-116.4), and it
        # is an ADDRESS, never an index — a re-merge changes how many runs
        # precede the selected one.
        previous_start = self._selected_cell_start
        self._reset_detail()

        span_start, span_end = derive_image_span(ranges)
        span = span_end - span_start
        if not ranges or span <= 0 or not entropy_windows:
            self._ordered_ranges = []
            # The empty paths mount nothing — a resize has nothing to rebuild.
            self._last_runs = None
            self._last_render_inputs = None
            self._rows_show_microbar_last = None
            # The cockpit panes mount no content on the empty paths — clear any
            # chrome a previous render left on them (batch-93, HLR-125; the
            # no-file screen state itself is the EmptyStatePanel, LLR-002.3).
            grid.border_title = ""
            grid.border_subtitle = ""
            self.query_one("#map_detail").border_title = ""
            self.query_one("#map_detail").border_subtitle = ""
            if not ranges:
                # Genuinely no image loaded.
                empty_msg = self._EMPTY_TEXT
                self._render_stats([], [], self._issues, empty=True)
            else:
                # An image IS loaded but has no entropy band detail (zero span or
                # band-less) — never mislabel it "No file loaded"; still show the
                # coverage stats strip from the real ranges (fix-memmap-entropy AC-3).
                empty_msg = self._NO_ENTROPY_TEXT
                self._render_stats(ranges, range_validity, self._issues, empty=False)
            self.rendered_text = empty_msg
            header.update(empty_msg)
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
        # Carried for the resize-driven width re-apportionment (HLR-131 /
        # LLR-131.2): the runs are the populated-path sentinel; the original
        # inputs let it re-run THIS method — the single selection authority —
        # rather than a parallel mount path with a second selection hook.
        self._last_runs = list(runs)
        self._last_render_inputs = (
            list(ranges),
            list(range_validity),
            list(issues),
            list(a2l_tags),
            list(entropy_windows),
        )
        # The bar does not exist yet, so its width is measured from ``#map_grid``
        # (LLR-111.9): the CONTENT box (border + padding excluded — the batch-93
        # pane chrome), which is the width the bar takes in full. ``0`` before
        # first layout is a conforming out-of-domain input (the allocator
        # floor); the post-refresh hook then re-apportions against the bar
        # itself, required because ``grid.mount()`` is deferred.
        grid.mount(
            *self._build_band_widgets(
                runs, span_start, span_end, max(0, grid.content_region.width)
            )
        )
        # batch-93 (HLR-125): the cockpit chrome — every map surface sits in a
        # lit, titled ``.db-pane``; the affordance hints live in the border
        # subtitles, never in body rows. The inspector title is (re)set by
        # ``_select_region`` — the single owner of the selection — because it
        # carries the SELECTED region's start address.
        grid.border_title = "Memory Map"
        grid.border_subtitle = f"{len(runs)} regions · ░▒▓ k"
        self.query_one("#map_detail").border_subtitle = "↑↓ · ↵ hex"
        self.call_after_refresh(self._resize_band_segments)
        # ``grid.mount()`` is DEFERRED, so the rows are not queryable here and
        # "after the rows are mounted" is not a synchronous point inside this
        # method. Resolving inline is what produced the detached-focus defect:
        # the resolution ran against the OLD row set, which
        # ``grid.remove_children()`` had already scheduled for removal
        # (LLR-116.2).
        self.call_after_refresh(
            self._apply_auto_selection, previous_start, False, generation
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

    def on_resize(self, event: events.Resize) -> None:
        """Re-apportion EVERY width-driven surface on resize (HLR-131).

        The stack regime (the panel's own ``width-narrow`` class at
        ``_MAP_STACK_MIN_WIDTH``), the band bar, the region rows (when the
        width-aware microbar gate flips), the peek (when the inspector
        pane's height cut changes) and the width-adaptive stats all
        re-derive against the then-measured width — the stats strip
        re-renders from the stored inputs so a live resize across
        ``_STATS_FULL_MIN_WIDTH`` swaps the full/compact form
        (batch-93, LLR-129.2); a same-width resize re-renders the identical
        line, which ``Static.update`` repaints without a layout change.
        """
        self._reapportion_width_surfaces()

    def on_band_bar_measured(self, event: BandBar.Measured) -> None:
        """Re-apportion when the BAR itself learns its width (LLR-111.1).

        ``events.Resize`` does not bubble, so ``on_resize`` above sees only the
        PANEL's own resizes and is blind to the one event that actually carries
        the information. :class:`BandBar` re-emits it as a bubbling message so
        the re-apportionment happens exactly when the width becomes knowable,
        however many frames that takes. The whole surface set re-apportions
        here, not the bar alone (batch-93 inc-002, HLR-131 / LLR-131.2).
        """
        event.stop()
        self._reapportion_width_surfaces()

    def _reapportion_width_surfaces(self, retry: bool = False) -> None:
        """One re-apportionment pass over every width-driven surface (HLR-131).

        Summary:
            The single funnel behind ``on_resize`` and
            ``on_band_bar_measured`` (LLR-131.2): the stack-regime class,
            the band bar, the region rows and the peek re-derive against
            the panel's MEASURED width, and the stats strip re-renders from
            its stored inputs. Every step is idempotent in the steady state
            (writes happen only on an actual change), so a same-width event
            repaints nothing.

            **The width-0 first frame is a conforming input** (P-4): an
            unlaid panel reports width 0 and nothing may ship a
            width-0-derived layout. The pass then schedules exactly ONE
            re-attempt on the next frame — the shipped bar's bounded-retry
            discipline — and gives up; a callback that re-armed
            unconditionally would spin every frame (LLR-131.3).

        Args:
            retry (bool): True only on the single self-scheduled re-attempt
                made when the panel measured width 0. Bounds the reschedule
                to ONE extra frame.
        """
        width = self.size.width
        if width <= 0:
            if not retry:
                self.call_after_refresh(self._reapportion_width_surfaces, True)
            return
        self._apply_stack_regime(width)
        self._resize_band_segments()
        self._rebuild_rows_for_width()
        if self._selected_cell_start is None and self._rows_show_microbar_last is not None:
            # Rows are mounted but the deferred auto-selection never landed —
            # its single bounded retry can give up inside a multi-frame
            # relayout (the width re-apportionment transition re-mounts the
            # whole stack). The bar's Measured that scheduled THIS pass is
            # the authoritative re-kick: one idempotent check per event, no
            # self-rearming, and the stand-down once a selection (this pass's
            # or an intervening click's) exists is structural.
            self._apply_auto_selection(None, False, self._render_generation)
        self._recut_peek_for_height()
        if self._stats_state is not None:
            ranges, range_validity, issues = self._stats_state
            self._render_stats(ranges, range_validity, issues, empty=False)

    def _apply_stack_regime(self, width: int) -> None:
        """Toggle the panel's own ``width-narrow`` class (HLR-131 / LLR-131.1).

        Summary:
            The map's stack decision reads the PANEL's measured width —
            ``width < _MAP_STACK_MIN_WIDTH`` stacks the inspector under the
            map pane; at or above it the panes render side by side. The
            class is the EXISTING ``width-narrow`` token and the reflow
            rules are the shipped LLR-041.10 pair, re-anchored to the panel
            (styles.tcss) — not a new breakpoint. The workspace-level
            ``width-narrow`` toggle at the 120-column TERMINAL breakpoint
            keeps serving the other screens; a narrow rail can therefore
            hand the map a wide panel (terminal < 120, panel >= 86) and the
            map correctly stays side-by-side — the shipped terminal-keyed
            trap the contract's negative control names.
        """
        stacked = self._is_stacked_width(width)
        if self.has_class("width-narrow") != stacked:
            self.set_class(stacked, "width-narrow")

    def _rebuild_rows_for_width(self) -> None:
        """Re-render the map when the microbar gate flips (LLR-131.2).

        Summary:
            The rows' only width-driven field is the 4-cell size microbar
            (LLR-127.3) — present or absent per ``_rows_show_microbar()`` —
            but its presence changes every surviving field's offset, so a
            gate flip across a resize (or across the stack threshold, where
            the inset itself changes) must re-compose the rows. The flip
            re-runs :meth:`render_ranges` itself — the SINGLE selection
            authority: it re-arms the generation-guarded auto-selection hook
            with the selection address carried across, so the deferred hook
            can never bind the superseded rows (the prune-window trap a
            second, parallel mount path would race). When the gate is
            unchanged (the steady state) this re-renders nothing, so a
            resize cannot reset the list's scroll.
        """
        if self._last_runs is None or self._rows_show_microbar_last is None:
            # Empty render — nothing mounted to rebuild.
            return
        if self._rows_show_microbar() == self._rows_show_microbar_last:
            return
        if self._last_render_inputs is None:
            return
        ranges, range_validity, issues, a2l_tags, entropy_windows = (
            self._last_render_inputs
        )
        # ``render_ranges`` re-derives the gate at the CURRENT measured width
        # and records it as the mounted baseline; the fresh render generation
        # supersedes any selection hook still queued from the pre-flip rows.
        self.render_ranges(
            ranges, range_validity, issues, a2l_tags, entropy_windows,
            self._mem_map,
        )

    def _recut_peek_for_height(self) -> None:
        """Re-apply the selection when the peek's height cut changes (LLR-131.2).

        Summary:
            The peek's row count is cut from the inspector pane's measured
            height (LLR-126.3), so it changes whenever a resize (or a
            stack-regime flip) changes that height. The cut re-derives by
            re-running ``_select_region`` for the CURRENT selection — the
            single owner of the inspector body — but ONLY when the computed
            row count differs from what the body already carries: the
            steady-state resize repaints nothing and never resets the
            pane's scroll.
        """
        start = self._selected_cell_start
        if start is None:
            # The hint state owns the body — nothing to re-cut.
            return
        end = None
        for row in self._live_region_rows():
            if row.region_start == start:
                end = row.region_end
                break
        if end is None:
            # The selection's run is gone (a newer render owns the body).
            return
        reserved = len(symbols_in_window(self._a2l_tags, start, end))
        want = self._inspector_peek_rows(reserved)
        try:
            body = self.query_one("#map_detail_body", Static)
        except Exception:
            return
        lines = body.render().plain.splitlines()
        try:
            have = len(lines) - lines.index("Peek") - 1
        except ValueError:
            have = -1
        if have != want:
            self._select_region(start, end)

    def _wrap_audit_mount_overlong(self, line: str) -> None:
        """TEST-ONLY injection point for the wrap-audit counterfactual (LLR-130.2).

        Summary:
            Mount ONE deliberately over-long authored line into the map
            pane so the wrap-audit harness (tests/test_tui_map_wrap.py) can
            prove it goes RED exactly there — an audit that cannot fail
            proves nothing (C-43). No production path calls this; it exists
            solely as the harness's error-class injection seam.
        """
        try:
            grid = self.query_one("#map_grid", Container)
        except Exception:
            return
        grid.mount(Static(safe_text(line), classes="map-wrap-audit-probe"))

    def _resize_band_segments(self, retry: bool = False) -> None:
        """Re-apportion the mounted band segments against the MEASURED bar.

        Summary:
            Re-run ``_allocate_band_widths`` over the segments already on screen
            and rewrite their glyph runs (batch-77, LLR-111.1). This exists
            because the container width is not knowable where the widgets are
            built: ``_build_band_widgets`` runs before ``grid.mount()``, whose
            effect is deferred, so ``.map-band-bar`` has no region yet. The
            initial build apportions against ``#map_grid`` — the same width the
            bar takes in full — and this hook corrects it once the bar itself is
            measurable, and again on every resize.

            Gap markers are untouched: they fold to one column independent of the
            container width (LLR-111.2), so a resize cannot change them.

            **The bar is resolved with ``.last()``, not ``query_one``.**
            ``render_ranges`` calls ``grid.remove_children()`` and the removal is
            DEFERRED, so during the prune window the OLD bar and the newly
            mounted one BOTH match ``.map-band-bar``. ``query_one`` does not
            raise there — in Textual 8.2.8 it returns the FIRST match and
            documents only ``NoMatches``/``WrongType`` (``query_exactly_one`` is
            the strict variant) — so it silently binds the STALE, detached bar
            and re-apportions against a width that is not the one being painted.
            Measured over 20 observed prune windows: ``.last()`` was the
            surviving (newly mounted) bar 20/20, ``query_one`` 0/20. ``.last()``
            is deterministic here because ``remove_children()`` precedes
            ``mount()`` and ``mount()`` appends, so the new bar is always last in
            DOM order.

        Args:
            retry (bool): True only on the single self-scheduled re-attempt made
                when the bar measures 0. Bounds the reschedule to ONE extra
                frame — a callback that re-armed unconditionally would spin every
                frame for as long as the bar stayed unlaid-out.

        Returns:
            None

        Data Flow:
            - Reads each mounted segment's own mapped span and band glyph, so
              the re-apportionment consumes the same population it rewrites; no
              parallel plan is kept that could fall out of step with the widgets.

        Dependencies:
            Uses:
                - ``_allocate_band_widths`` / ``safe_text``
            Used by:
                - ``render_ranges`` (via ``call_after_refresh``), ``on_resize``,
                  and itself (one bounded retry)
        """
        try:
            bar = self.query(".map-band-bar").last()
        except Exception:
            # No image rendered — nothing mounted to re-apportion.
            return
        bar_width = bar.region.width
        if bar_width <= 0:
            # Not laid out yet. Nothing else schedules a re-measure, so without
            # this the widths apportioned against ``#map_grid`` at build time
            # would ship unchecked. One more frame, then give up and wait for a
            # resize.
            if not retry:
                self.call_after_refresh(self._resize_band_segments, True)
            return

        children = list(bar.children)
        segments = [child for child in children if isinstance(child, BandSegment)]
        if not segments:
            return
        widths = _allocate_band_widths(
            [seg.region_end - seg.region_start for seg in segments],
            len(children) - len(segments),
            bar_width,
        )
        for seg, width in zip(segments, widths):
            # Only rewrite a segment whose width actually changed. ``update()``
            # invalidates layout, and in the steady state the initial build
            # already apportioned against the same measurement (#map_grid, whose
            # width the bar takes in full), so an unconditional rewrite would
            # relayout — and reset the region list's scroll — on every render.
            if len(seg.render().plain) != width:
                seg.update(safe_text(seg.band_glyph * width))

    def _build_band_widgets(
        self,
        runs: Sequence[Tuple[str, int, int]],
        span_start: int,
        span_end: int,
        bar_width: int,
    ) -> List[Container]:
        """Build the band bar, the ruler, the glance chips, the scrollable list.

        Summary:
            Assemble the left-pane stack of the inspector cockpit (batch-93,
            HLR-126 / LLR-126.1, amending the batch-45/47 layout): the 1-row
            ``.map-band-bar`` (the batch-77 allocator, untouched), the
            :class:`MapRuler` run-start ruler beneath it (one tick per
            run start plus the last mapped byte, batch-77 LLR-112.1 — this
            supersedes batch-47's five span percentiles, of which four named
            unmapped addresses), the one-line ``.map-glance-chips`` glance
            (batch-93, HLR-129 — the retired 6-row ``.at-a-glance`` dock
            folds to chips), and finally the SCROLLABLE region list — a
            ``ScrollableContainer`` around the ``.map-region-list`` of
            :class:`RegionRow`s, so every region is reachable however many
            runs overflow the viewport (defect #3 of premise P-1). Unmapped
            address gaps between runs render as ``╱`` hatch segments
            (``.map-band-gap``, LLR-072.1). Each region row is composed from
            FIXED-WIDTH fields (batch-93, HLR-127 / LLR-127.1): glyph ·
            ``0x{addr}`` (10) · right-aligned size (>7) · size microbar (4,
            dropped below ``_REGION_ROW_MICROBAR_MIN_WIDTH`` available
            columns, LLR-127.3) · symbol count (>2) · band short label (<=9,
            display-only, LLR-127.2) · ``↵`` — so every field of every row
            starts at the same column. Rows still carry NO file-derived text
            (band labels + counts only — security B3). Each sub-widget is
            addressed by CLASS (re-mounted every render; an id would trip
            ``DuplicateIds``) with markup-safe ``safe_text`` content.

            batch-77 (R-TUI-103 / LLR-111.1, .2, .7) changes what the bar is
            drawn against, on both axes. The BASIS is the measured container
            width rather than a fixed constant, and the DENOMINATOR is the total
            MAPPED bytes of the emitted runs rather than the image address span.
            Both are load-bearing: swapping only the basis keeps the span
            denominator, which is what made unmapped address space consume the
            bar. Gaps no longer scale at all — each folds to one column — and the
            run widths are bounded in ``_allocate_band_widths`` so the strip
            cannot emit more columns than its container has.

            batch-77 (HLR-114 / LLR-114.1) REMOVED the ``.map-band-legend``
            block this method used to append. The four band rows were a static
            key — identical on every image — occupying four of the map body's
            scarce rows, and the same key is already rendered by the ``k``
            legend screen from the same ``ENTROPY_BANDS`` source
            (``screens.py::LegendScreen`` via ``build_band_key_rows``). The
            legend is therefore not deleted, only moved off the always-on
            surface; ``ENTROPY_BAND_LABELS`` stays imported because the glance
            chips order themselves by it. batch-93 (HLR-129) likewise folds
            the ``.at-a-glance`` histogram + sparkline dock into the one-line
            chips — the per-band detail the block carried is entropy-window
            trivia the operator never reads on the always-on surface. The
            sampling helpers (``band_histogram`` / ``sparkline_glyphs`` /
            ``_sparkline_segments``) stay as tested units.

        Args:
            runs (Sequence[Tuple[str, int, int]]): The merged
                ``(band_label, summed_bytes, start_addr)`` runs from
                ``_merge_band_runs`` (non-empty), ascending by start.
            span_start (int): Inclusive image span start (``derive_image_span``).
            span_end (int): Exclusive image span end (``derive_image_span``).
            bar_width (int): The container width to apportion, measured at render
                time. ``0`` before first layout — a conforming out-of-domain
                input which yields one column per run; ``_resize_band_segments``
                re-apportions once the bar itself is measurable.

        Returns:
            List[Container]: ``[band_bar, ruler, glance_chips, region_scroll]``
            ready to mount into ``#map_grid``.

        Data Flow:
            - Reads ``runs`` + the span + ``self._a2l_tags``; produces the
              widgets ``render_ranges`` mounts.

        Dependencies:
            Uses:
                - ``band_style`` / ``safe_text`` /
                  ``human_bytes`` / ``microbar`` / ``MapRuler`` /
                  ``_region_symbol_counts`` / ``_build_glance_chips`` /
                  ``_allocate_band_widths``
            Used by:
                - ``render_ranges`` / ``_rebuild_rows_for_width`` (batch-93
                  inc-002, HLR-131 — the single build path, render and
                  resize rebuild alike)
        """
        largest_region = max(
            (run_bytes for _band, run_bytes, _start in runs), default=1
        ) or 1
        sym_counts = self._region_symbol_counts(runs)
        # The microbar gate is width-driven (LLR-127.3) and identical for every
        # row — decide ONCE here, record the decision as the mounted baseline
        # (the resize rebuild's change detector, HLR-131 / LLR-131.2), and hand
        # it to each row.
        show_microbar = self._rows_show_microbar()
        self._rows_show_microbar_last = show_microbar

        # ONE traversal decides where gaps go, and both the allocation bound and
        # the emission below consume that same list. Counting the gaps in a
        # second traversal — or inferring ``n_runs - 1`` — lets the count the
        # bound spends diverge from the count the bar draws, and the bar then
        # overflows its container by the difference. A gap is emitted wherever a
        # run starts above the cursor, so a LEADING gap is possible (n_gaps ==
        # n_runs) and a trailing one never is (the loop ends at the last run).
        gap_before: List[bool] = []
        cursor = span_start
        for _band, run_bytes, start in runs:
            gap_before.append(start > cursor)
            cursor = start + run_bytes
        widths = _allocate_band_widths(
            [run_bytes for _band, run_bytes, _start in runs],
            sum(gap_before),
            bar_width,
        )

        segments: List[Static] = []
        region_rows: List[RegionRow] = []
        for index, (band, run_bytes, start) in enumerate(runs):
            token, glyph, _meaning = band_style(band)
            # Hatch the unmapped gap (if any) preceding this run — an
            # app-supplied ``╱`` marker, NOT an entropy band (LLR-072.1) — at
            # exactly one column whatever its byte size (LLR-111.2). It stays a
            # plain Static: there is no region behind it to inspect or open.
            if gap_before[index]:
                segments.append(
                    Static(
                        safe_text(_MAP_GAP_HATCH * _BAND_GAP_FOLD),
                        classes="map-band-seg map-band-gap",
                    )
                )
            # batch-67 N4b: a MAPPED run is clickable and carries its window.
            segments.append(
                BandSegment(
                    safe_text(glyph * widths[index]),
                    start,
                    start + run_bytes,
                    classes=f"map-band-seg {token}",
                    band_glyph=glyph,
                )
            )
            region_rows.append(
                self._build_region_row(
                    band,
                    glyph,
                    token,
                    run_bytes,
                    start,
                    largest_region,
                    sym_counts,
                    show_microbar,
                )
            )

        # Re-mounted every render after ``grid.remove_children()`` (whose removal
        # is deferred), so these carry CLASSES, not unique IDs — an ID would trip
        # ``DuplicateIds`` when the old container is still registered at re-render
        # (the same reason the retired cell grid used ``.map-cell``, not an id).
        # A ``BandBar``, not a bare ``Horizontal``: the initial apportionment
        # above is made against a ``bar_width`` of 0 (``#map_grid`` is not laid
        # out yet), so the bar MUST report its own resize or the out-of-domain
        # floor is what ships. See :class:`BandBar`.
        band_bar = BandBar(*segments, classes="map-band-bar")
        # The list is STAMPED with the render generation that built it
        # (batch-93 inc-002): ``_apply_auto_selection`` resolves the list
        # whose stamp matches its hook's generation, so the deferred selection
        # can never bind the superseded list — with removal AND mount both
        # deferred, exactly ONE registered list can still be the stale one
        # (the count alone cannot tell them apart).
        region_list = Vertical(*region_rows, classes="map-region-list")
        region_list._map_build_generation = self._render_generation
        return [
            band_bar,
            # The ruler labels what the BAR DRAWS — run starts, not percentiles
            # of the span, and the last MAPPED byte, not the exclusive
            # ``span_end`` (LLR-112.1). ``runs`` is the same list the bar was
            # apportioned from three statements above, so the two surfaces
            # cannot disagree about which regions exist.
            MapRuler([start for _band, _run_bytes, start in runs], span_end - 1),
            # The glance block's successor: ONE line of per-band chips between
            # the ruler and the list (batch-93, HLR-129 / LLR-129.3).
            self._build_glance_chips(runs),
            # The region list scrolls inside its own container (HLR-126) — the
            # outer #map_content no longer scrolls, so the stats strip below
            # the cockpit always paints without scrolling (HLR-129).
            ScrollableContainer(
                region_list,
                classes="map-region-scroll",
            ),
        ]

    def _rows_show_microbar(self) -> bool:
        """True when the rows' available width admits the 4-cell size microbar.

        Summary:
            Width-aware microbar gate (batch-93, HLR-127 / LLR-127.3): the
            full row measures 40 cells against the compact row's 35 (executed
            formatter, P3 pilot), and the microbar renders only when the row's
            available width — the row widget's own width, derived from the
            panel's measured width via a REGIME-AWARE inset (batch-93 inc-002,
            HLR-131) — is at least ``_REGION_ROW_MICROBAR_MIN_WIDTH`` (43,
            pilot-measured against the charter captures: microbar ABSENT at 41
            available columns, PRESENT at 81). The inset is
            ``_MAP_PANEL_TO_ROWS_INSET`` (51) in the side-by-side regime and
            ``_MAP_PANEL_TO_ROWS_INSET_STACKED`` (8) in the stacked regime —
            the stacked pane hands the rows the full panel width, so the
            side-by-side inset would over-subtract there and drop the microbar
            at the 80x24 floor (the inc-001 constant note's recorded
            limitation; the regime-aware re-derivation was always HLR-131's).
            A panel that has not been laid out yet reports width 0 (a
            conforming first-frame input, P-4); the wide fallback then renders
            the narrow form, matching the 120x36 capture's microbar-free rows.

        Returns:
            bool: ``True`` to compose the 4-cell size microbar into each row.
        """
        width = self.size.width
        if width <= 0:
            width = _MAP_PANEL_WIDE_FALLBACK
        inset = (
            _MAP_PANEL_TO_ROWS_INSET_STACKED
            if self._is_stacked_width(width)
            else _MAP_PANEL_TO_ROWS_INSET
        )
        return (width - inset) >= _REGION_ROW_MICROBAR_MIN_WIDTH

    @staticmethod
    def _is_stacked_width(width: int) -> bool:
        """The stack-regime predicate, shared by the gate and the class toggle.

        Summary:
            ``True`` below ``_MAP_STACK_MIN_WIDTH`` (batch-93 inc-002,
            HLR-131) — the SAME predicate drives the ``width-narrow`` class
            (``_apply_stack_regime``) and the microbar inset, so the rows'
            form can never disagree with the layout regime.
        """
        return width < _MAP_STACK_MIN_WIDTH

    def _build_region_row(
        self,
        band: str,
        glyph: str,
        token: str,
        run_bytes: int,
        start: int,
        largest_region: int,
        sym_counts: Mapping[int, int],
        show_microbar: bool,
    ) -> RegionRow:
        """Compose one FIXED-WIDTH enriched region-list row (batch-93, HLR-127).

        Summary:
            Build the column-aligned ``{glyph} 0x{addr} {size:>7} {microbar}
            {sym:>2} {band-short:<9} ↵`` row as a Rich ``Text`` of fixed-width
            fields with single-space separators only INSIDE a field, never
            across fields (LLR-127.1): the humanized size is right-aligned in
            its >7-cell field, the ``_REGION_MICROBAR_WIDTH``-cell size
            micro-bar of ``run_bytes / largest_region`` (LLR-073.1) renders
            only when ``show_microbar`` admits it (LLR-127.3 — below the
            threshold it drops WITHOUT disturbing the surviving fields'
            offsets), the region's ``range_index`` symbol count sits in a
            >2-cell field, the band renders through the DISPLAY-ONLY
            ``_BAND_SHORT_LABELS`` mapping (LLR-127.2 — ``constant/padding``
            and ``high/random`` cannot fit the <=9-cell column raw), and the
            ``↵`` open-in-hex affordance closes the row (LLR-073.2). Because
            every field is fixed-width, every field of every row starts at the
            same column — the variable-width ``256 B`` vs ``2.0 KiB`` shifts
            the shipped single-space row suffered (P-1) cannot occur. Every
            field is developer-formatted or a constant band label — NO
            file-derived text reaches the row (B3).

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
            show_microbar (bool): ``_rows_show_microbar()`` — whether the
                available row width admits the 4-cell microbar.

        Returns:
            RegionRow: The composed clickable region row.

        Data Flow:
            - Pure composition over the run + counts; produces one row widget.

        Dependencies:
            Uses:
                - ``human_bytes`` / ``microbar`` / ``safe_text`` / ``RegionRow``
                  / ``_BAND_SHORT_LABELS``
            Used by:
                - ``_build_band_widgets``
        """
        n_sym = sym_counts.get(start, 0)
        frac = run_bytes / largest_region if largest_region else 0.0
        content = Text()
        content.append_text(safe_text(f" {glyph} "))
        content.append_text(safe_text(f"0x{start:08X} "))
        content.append_text(safe_text(f"{human_bytes(run_bytes):>7} "))
        if show_microbar:
            content.append_text(microbar(frac, _REGION_MICROBAR_WIDTH))
            content.append_text(safe_text(" "))
        content.append_text(safe_text(f"{n_sym:>2} "))
        content.append_text(safe_text(f"{_BAND_SHORT_LABELS.get(band, band):<9}"))
        content.append_text(safe_text(_OPEN_IN_HEX_GLYPH))
        return RegionRow(
            content,
            region_start=start,
            region_end=start + run_bytes,
            classes=f"map-region-row {token}",
        )

    def _build_glance_chips(
        self,
        runs: Sequence[Tuple[str, int, int]],
    ) -> Horizontal:
        """Build the one-line glance chips (the folded "At a glance" block).

        Summary:
            The at-a-glance block's successor (batch-93, HLR-129 / LLR-129.3,
            amending R-TUI-061): ONE line of per-band chips in canonical
            ``ENTROPY_BAND_LABELS`` order — ``{glyph} {count} {share}%`` per
            OCCUPIED band, where ``count`` is the band's merged-run tally
            (consistent with the region list, not a raw window count) and
            ``share%`` is the band's MAPPED-BYTE share of the total mapped
            bytes — the only reading under which the capture's chips sum to
            100 (``· 1 19% ░ 1 5% ▒ 4 57% ▓ 3 19%``: counts 1+1+4+3 = 9 runs,
            shares 19+5+57+19 = 100). Zero-count bands render NO chip. Colour
            flows solely through the ``band-*`` CSS classes — one chip widget
            per band, never an inline hex — and every text sink is a
            markup-safe ``safe_text`` over CONSTANT band labels + developer
            counts (security B3). The entropy-window sampling helpers
            (``band_histogram`` / ``sparkline_glyphs``) retire from this
            surface with the docked block; the chips need only the runs.

        Args:
            runs (Sequence[Tuple[str, int, int]]): The merged region runs —
            the tally + mapped-byte population.

        Returns:
            Horizontal: The ``.map-glance-chips`` one-line chip row.

        Data Flow:
            - Reads ``runs``; produces the chip widgets.

        Dependencies:
            Uses:
                - ``band_style`` / ``safe_text`` / ``ENTROPY_BAND_LABELS``
            Used by:
                - ``_build_band_widgets``
        """
        totals: Dict[str, int] = {}
        counts: Dict[str, int] = {}
        for band, run_bytes, _start in runs:
            totals[band] = totals.get(band, 0) + run_bytes
            counts[band] = counts.get(band, 0) + 1
        mapped = sum(totals.values()) or 1
        chips: List[Static] = []
        for band in ENTROPY_BAND_LABELS:
            if band not in totals:
                continue
            token, glyph, _meaning = band_style(band)
            chips.append(
                Static(
                    safe_text(f"{glyph} {counts[band]} {100 * totals[band] / mapped:.0f}%"),
                    classes=f"map-glance-chip {token}",
                )
            )
        return Horizontal(*chips, classes="map-glance-chips")

    def _render_stats(
        self,
        ranges: Sequence[Tuple[int, int]],
        range_validity: Sequence[bool],
        issues: Sequence[ValidationIssue],
        empty: bool,
    ) -> None:
        """Populate (or clear) the ONE-LINE ``#map_stats`` coverage strip.

        Summary:
            Compute the seven coverage statistics from the already-parsed
            ``ranges``/``range_validity`` and the pre-computed ``issues`` list
            via ``coverage_stats`` and render them markup-safe into
            ``#map_stats_body`` as ONE always-visible line (batch-93, HLR-129 /
            LLR-129.1, amending HLR-113 — defect ④ of premise P-1 was the
            multi-line strip rendering below the fold of the old scrolling
            ``#map_content``). The strip lives outside any scroll region now,
            so it paints without scrolling at 120x36; the form is width-adaptive
            (LLR-129.2): the full form renders when the strip's measured width
            admits its 84 cells, the compact form (same seven statistics,
            shortened labels only) below ``_STATS_FULL_MIN_WIDTH``. The last
            non-empty inputs are stored so a live resize re-renders the strip
            when the width crosses the threshold. When ``empty`` (no ranges),
            the strip is blanked so the no-file state shows nothing / neutral,
            with no divide-by-zero (LLR-041.9). Pure arithmetic on
            already-parsed values — no new coverage/parse/analysis (LLR-041.7).

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
                - ``render_ranges`` / ``on_resize`` (width re-adaptation)
        """
        try:
            body = self.query_one("#map_stats_body", Static)
        except Exception:
            return
        if empty:
            self._stats_state = None
            body.update(safe_text(""))
            return
        self._stats_state = (list(ranges), list(range_validity), list(issues))
        stats = coverage_stats(ranges, range_validity, issues)
        body.update(self.build_stats_text(stats, self._stats_available_width()))

    def _stats_available_width(self) -> int:
        """The strip's measured width for the width-adaptive form (LLR-129.2).

        Summary:
            The honest width is ``#map_stats_body``'s own region once laid out;
            before first layout (a conforming width-0 first frame, P-4) the
            panel's own measured width stands in, and before THAT the full-form
            threshold itself (the wide default — an unlaid panel renders the
            full form, matching the wide-regime capture).
        """
        try:
            width = self.query_one("#map_stats_body", Static).region.width
        except Exception:
            width = 0
        if width <= 0:
            width = self.size.width
        if width <= 0:
            width = _STATS_FULL_MIN_WIDTH
        return width

    def build_stats_text(
        self, stats: CoverageStats, available_width: int = 0
    ) -> Text:
        """Assemble the ONE-LINE coverage-strip text (batch-93, HLR-129).

        Summary:
            Compose the seven coverage statistics as ONE line in the contract's
            fixed field order — ``Mapped {covered} / {span} span ({pct}) ·
            {ranges} ranges ({valid} valid) · {gaps} gaps · {issues} issues``
            (LLR-129.1) — width-adaptive (LLR-129.2): below
            ``_STATS_FULL_MIN_WIDTH`` available columns the compact form
            renders the SAME seven statistics with shortened labels
            (``rng``/``ok``/``iss``, the ``span`` word, the pct parens and the
            flanking padding dropped) — 66 cells against the full form's 84 on
            the demo fixture (executed formatter, P3 pilot), clearing the
            68-column strip the 80x24 floor geometry admits. NO statistic's
            arithmetic changes —
            the numbers all come from the passed :class:`CoverageStats` and the
            coverage keeps **exactly four** fractional digits (batch-77,
            LLR-113.1: four digits discriminate ``0.0008%`` from ``0.0000%``
            where ``.2f`` reads flat). Coverage is a dual readout — mapped
            bytes against the image span, both through ``human_bytes`` —
            because a bare ``1024`` answers "how much" without "out of what".
            Pure formatting — no analysis (LLR-041.7); the content is
            developer-formatted, never file-derived, and stays uniformly
            ``Text``-composed (LLR-041.11).

        Args:
            stats (CoverageStats): The metrics from ``coverage_stats``.
            available_width (int): The strip's available width in columns;
                ``0`` (the default) means "unmeasured" and renders the full
                form — the wide default.

        Returns:
            Text: The composed, markup-safe one-line coverage strip.

        Data Flow:
            - Reads ``stats``; produces the ``Text`` rendered into
              ``#map_stats_body``.

        Dependencies:
            Uses:
                - ``safe_text`` / ``human_bytes`` / ``_STATS_FULL_MIN_WIDTH``
            Used by:
                - ``_render_stats`` / (test) TC-041.8
        """
        n_ranges = stats.valid_count + stats.invalid_count
        compact = 0 < available_width < _STATS_FULL_MIN_WIDTH
        text = Text()
        if compact:
            # Shortened labels/separators ONLY — the same seven statistics in
            # the same field order. No flanking padding, no ``span`` word, no
            # pct parens: the compact form must clear the 68-column strip the
            # 80x24 floor admits (66 cells measured on the demo fixture).
            text.append("Mapped ")
            text.append(human_bytes(stats.covered_bytes))
            text.append(
                f" / {human_bytes(stats.image_span)} "
                f"{stats.coverage_pct:.4f}%"
            )
            text.append(" · ")
            text.append(f"{n_ranges} rng ({stats.valid_count} ok)")
            text.append(" · ")
            text.append(f"{stats.gap_count} gaps")
            text.append(" · ")
            text.append(f"{stats.total_issues} iss")
        else:
            text.append(" Mapped ")
            text.append(human_bytes(stats.covered_bytes))
            text.append(
                f" / {human_bytes(stats.image_span)} span "
                f"({stats.coverage_pct:.4f}%)"
            )
            text.append(" · ")
            text.append(f"{n_ranges} ranges ({stats.valid_count} valid)")
            text.append(" · ")
            text.append(f"{stats.gap_count} gaps")
            text.append(" · ")
            text.append(f"{stats.total_issues} issues")
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
        # ``Text`` joins the hint's newline as a line break; ``safe_text``'s
        # C0 scrub would delete it (the hint is a developer constant, never
        # file-derived — the scrub has nothing to do here).
        body.update(Text(self._DETAIL_HINT))

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
        """Handle a region-row click: inspect on single, navigate on double.

        Summary:
            **batch-67 N4a — the click semantics SPLIT.** Every activation, at
            any chain length, populates the retained ``#map_detail`` inspector;
            only a chain of 2 or more (a double click) additionally posts
            :class:`MemoryMapPanel.OpenInHexRequested`. Before batch-67 a single
            click did both, which made browsing regions a navigation trap — the
            operator could not look at a region without being moved off the map.
            Inspecting is the cheap, reversible action and gets the cheap
            gesture; navigating is the disruptive one and gets the deliberate
            gesture.

            On a :class:`RegionRow.Activated`, populate the
            retained ``#map_detail`` inspector for the clicked run's
            ``[region_start, region_end)`` window (batch-93, HLR-126/128): the
            aligned Status/Region/Size/Band/Symbols field block + the
            multi-row 8-byte hex peek, composed by ``_build_inspector_text``
            (the retired ``build_detail_text``/16-byte-peek soup no longer
            renders on this screen). It then posts
            :class:`OpenInHexRequested` so the reused app handler switches to the
            Workspace/hex screen (LLR-045C.1). Detail is populated BEFORE the nav
            message so the pane reflects the selection when the operator returns.
            Every file-derived string in the inspector (A2L symbol names) renders
            through ``safe_text`` — the peek adds only developer-formatted hex,
            no untrusted text (C-17 / MN-4).

        Args:
            event (RegionRow.Activated): The clicked run's window plus the
                click-chain length; ``event.chain >= 2`` gates the hex jump.

        Dependencies:
            Uses:
                - ``_select_region`` / ``OpenInHexRequested``
            Used by:
                - Textual message dispatch (from ``RegionRow``)
        """
        event.stop()
        start, end = event.region_start, event.region_end
        self._select_region(start, end)
        # N4a: inspect always, navigate only on a deliberate double click.
        if event.chain >= 2:
            self.post_message(self.OpenInHexRequested(start))

    def _live_region_rows(self) -> List[RegionRow]:
        """The region rows of the CURRENTLY mounted region list.

        Summary:
            ``render_ranges`` calls ``grid.remove_children()`` and the removal
            is DEFERRED, so during the prune window the old rows and the new
            ones are BOTH returned by ``self.query(RegionRow)`` — a panel-wide
            query cannot tell them apart, and selecting or focusing a stale one
            leaves the operator on a widget that is about to vanish
            (``is_attached`` False, ``parent`` None) while every identity
            predicate still reads True.

            Resolving the list container with ``.last()`` and reading ITS
            children is the same disambiguation ``_resize_band_segments`` uses
            for the bar, and for the same reason: ``remove_children()`` precedes
            ``mount()`` and ``mount()`` appends, so the surviving container is
            always last in DOM order.

        Returns:
            List[RegionRow]: The mounted rows in ascending address order (the
            order ``_build_band_widgets`` emitted them in), or ``[]`` when no
            image is rendered.

        Dependencies:
            Used by:
                - ``_apply_auto_selection`` / ``_select_region``
        """
        try:
            region_list = self.query(".map-region-list").last()
        except Exception:
            # No image rendered — nothing mounted to select.
            return []
        return [
            child for child in region_list.children if isinstance(child, RegionRow)
        ]

    def _select_region(self, start: int, end: int) -> None:
        """Populate the inspector for ``[start, end)`` and mark its row.

        Summary:
            The single owner of "a region is selected": it stores the selection
            address, writes ``#map_detail_body`` with the cockpit inspector
            (batch-93, HLR-126 / LLR-126.2 + HLR-128): the aligned field block
            ``Status`` / ``Region`` / ``Size`` / ``Band`` / ``Symbols`` at fixed
            columns (labels padded to ``_INSPECTOR_LABEL_WIDTH`` — the longest
            label plus the capture's two-space gutter), the region's overlapping
            A2L symbol NAMES one per line (markup-safe, so a hostile name like
            ``sensor[red]`` renders literally — C-17/MN-4), the ``Peek`` header
            and the multi-row 8-byte hex peek cut against the pane height
            (LLR-126.3). The pane's lit border title is set to
            ``Inspector — 0x{start:08X}`` here — the title carries the SELECTED
            address, so it belongs to the selection owner. The values come from
            the already-selected region only — the panel re-derives nothing
            (P-3): status via ``cell_status``, size via ``human_bytes``, band
            via the run's own merged band, symbols via ``symbols_in_window``.

            It deliberately posts NOTHING. ``OpenInHexRequested`` is the click
            handler's decision alone, which is what keeps auto-selection from
            navigating (LLR-116.3) — the absence is structural rather than a
            flag this method has to be trusted to read.

            The marker is ADDED to the row's class list; no ``band-*`` class is
            touched, so the entropy band channel survives selection
            (LLR-117.2).

        Args:
            start (int): The selected run's inclusive start address.
            end (int): The selected run's exclusive end address.

        Returns:
            None

        Dependencies:
            Uses:
                - ``cell_status`` / ``band_style`` / ``human_bytes`` /
                  ``symbols_in_window`` / ``_build_inspector_text`` /
                  ``_live_region_rows``
            Used by:
                - ``on_region_row_activated`` (click) / ``_apply_auto_selection``
        """
        self._selected_cell_start = start
        status = cell_status(start, end, self._ordered_ranges)
        body = self.query_one("#map_detail_body", Static)
        body.update(self._build_inspector_text(start, end, status))
        self.query_one("#map_detail").border_title = f"Inspector — 0x{start:08X}"
        for row in self._live_region_rows():
            row.set_class(row.region_start == start, self._SELECTED_ROW_CLASS)

    def _build_inspector_text(self, start: int, end: int, status: str) -> Text:
        """Compose the aligned inspector field block + the multi-row peek.

        Summary:
            The full-height inspector's body (batch-93, HLR-126 / LLR-126.2,
            HLR-128): five fixed-column fields — ``Status`` (the ``cell_status``
            chip: ``VALID`` / ``INVALID`` / ``GAP (uncovered)``), ``Region``
            (``0x{start:08X}-0x{end-1:08X}``), ``Size`` (``human_bytes``),
            ``Band`` (the run's own dominant band: glyph + FULL domain label —
            the short labels are display-only on the region rows, never here),
            ``Symbols`` (the count) — then one line per overlapping A2L symbol
            NAME (``safe_text``, so hostile file-derived names render literally,
            C-17), each CLIPPED to the pane's measured interior via the house
            cell-boundary seam ``_clip_to_cells`` (batch-93 inc-002, HLR-130 —
            a long file-derived name used to wrap mid-content and push the
            peek off the pane; the clip keeps every painted line inside its
            widget), the ``Peek`` header, and the 8-byte hex peek rows. Every
            value is developer-formatted or carried through the shipped
            markup-safe seams; no statistic or entropy fact is re-derived here
            (P-3 / LLR-041.7).

        Args:
            start (int): The selected run's inclusive start address.
            end (int): The selected run's exclusive end address.
            status (str): The region status (``"valid"`` / ``"invalid"`` /
                ``"gap"``) from ``cell_status``.

        Returns:
            Text: The composed, markup-safe inspector body.

        Dependencies:
            Uses:
                - ``band_style`` / ``human_bytes`` / ``symbols_in_window`` /
                  ``safe_text`` / ``_clip_to_cells`` / ``_inspector_body_width``
                  / ``_region_peek_text``
            Used by:
                - ``_select_region``
        """
        text = Text()

        def field(label: str, value: str) -> None:
            text.append(f"{label:<{_INSPECTOR_LABEL_WIDTH}}")
            text.append(f"{value}\n")

        chip = {
            "valid": "VALID",
            "invalid": "INVALID",
            "gap": "GAP (uncovered)",
        }.get(status, "GAP (uncovered)")
        field("Status", chip)
        field("Region", f"0x{start:08X}-0x{end - 1:08X}")
        field("Size", human_bytes(end - start))
        band = self._run_bands.get(start)
        if band is not None:
            _token, glyph, _meaning = band_style(band)
            field("Band", f"{glyph} {band}")
        else:
            field("Band", "-")
        region_names = symbols_in_window(self._a2l_tags, start, end)
        field("Symbols", str(len(region_names)))
        # The 2-space indent plus the clipped name must fit the pane's
        # measured interior — the audit's no-wrap law is enforced HERE, at
        # authorship, never by weakening the assertion (batch-93 inc-002,
        # HLR-130).
        name_cap = max(1, self._inspector_body_width() - 2)
        for name in region_names:
            # File-derived names go through ``safe_text`` — a hostile
            # ``sensor[red]`` renders literally, never as markup (C-17) —
            # AFTER the cell-boundary clip shortens the painted line.
            text.append("  ")
            text.append(safe_text(_clip_to_cells(name, name_cap)))
            text.append("\n")
        text.append("Peek\n")
        text.append_text(self._region_peek_text(start, len(region_names)))
        return text

    def _inspector_body_width(self) -> int:
        """The inspector body's measured interior, for the symbol-name clip.

        Summary:
            The honest budget for the file-derived symbol-name lines
            (batch-93 inc-002, HLR-130): ``#map_detail_body``'s own measured
            content width, MINUS the vertical scrollbar's gutter
            (:data:`_INSPECTOR_SCROLLBAR_GUTTER`) — the gutter is subtracted
            unconditionally because the scrollbar appears exactly when a long
            name overflows the body, so budgeting without it clips against a
            width the painted line can never claim (the wrap audit's finding:
            a 40-cell line in the 38-column budget the scrollbar leaves).
            Before first layout (a conforming width-0 first frame, P-4) — or
            on the headless unit path — the side-by-side interior
            (:data:`_INSPECTOR_BODY_FALLBACK_WIDTH`, 40 columns) stands in:
            it is the binding interior across both regimes, so a name clipped
            against it never exceeds any painted interior.

        Returns:
            int: ``>= 1`` columns for one clipped name.
        """
        try:
            width = self.query_one("#map_detail_body", Static).content_region.width
        except Exception:
            width = 0
        if width <= 0:
            width = _INSPECTOR_BODY_FALLBACK_WIDTH
        return max(1, width - _INSPECTOR_SCROLLBAR_GUTTER)

    def _inspector_peek_rows(self, reserved: int) -> int:
        """The 8-byte peek row count the inspector pane height admits.

        Summary:
            The peek fills the inspector below the field block (batch-93,
            LLR-126.3): as many 8-byte rows as the pane's measured content
            height admits after the ``_INSPECTOR_FIELD_ROWS`` field rows and
            ``reserved`` extra body rows (the selected region's symbol-name
            lines), floored at one row so a region is never left without a
            peek. A pane that has not been laid out yet reports height 0 (a
            conforming first-frame input, P-4); the fallback then renders
            ``_PEEK_ROWS_FALLBACK`` rows — the count the 120x36 capture frame
            shows. The cut re-derives on every selection, so it tracks the
            pane the selection lands in.

        Args:
            reserved (int): Body rows above the peek but below the field block
                (the symbol-name lines of the selected region).

        Returns:
            int: ``>= 1`` peek rows.
        """
        try:
            height = self.query_one("#map_detail").region.height
        except Exception:
            height = 0
        if height <= 0:
            return _PEEK_ROWS_FALLBACK
        content_height = height - 4  # border (2) + ``.db-pane`` padding (2)
        return max(1, content_height - _INSPECTOR_FIELD_ROWS - reserved)

    def _region_peek_text(self, start: int, reserved: int = 0) -> Text:
        """Render the non-wrapping 8-byte hex peek at a region (batch-93, HLR-128).

        Summary:
            Return a markup-safe ``Text`` of ``_inspector_peek_rows()`` rows of
            ``f"{addr:08X}  " + " ".join(f"{byte:02X}")`` over 8 bytes (LLR-128.1
            — exactly 33 cells per mapped row): an 8-hex address with NO ``0x``
            prefix and NO ASCII gutter, assembled with ``markup=False`` content.
            Unmapped bytes render ``_PEEK_UNMAPPED_CELL`` (``··``, 2 cells — the
            row keeps its 33-cell width with holes). The first row starts at the
            8-aligned base CONTAINING ``start`` (the shipped alignment
            convention preserved); rows below a short region render ``··`` for
            the addresses past its end. An empty ``_mem_map`` (no file /
            headless) yields an empty ``Text`` rather than raising. The shipped
            16-byte ``hexview.render_hex_view`` peek surface is RETIRED on this
            screen by this replacement — 79-cell rows wrapped in the ~40-col
            inspector pane (defect ② of premise P-1).

        Args:
            start (int): The region's inclusive start address.
            reserved (int): Body rows above the peek (the symbol-name lines) —
                forwarded to ``_inspector_peek_rows``.

        Returns:
            Text: The composed, markup-safe 8-byte peek (possibly empty).

        Dependencies:
            Uses:
                - ``safe_text`` / ``_PEEK_BYTES_PER_ROW`` /
                  ``_PEEK_UNMAPPED_CELL`` / ``_inspector_peek_rows``
            Used by:
                - ``_build_inspector_text``
        """
        if not self._mem_map:
            return safe_text("")
        rows = self._inspector_peek_rows(reserved)
        base = start - (start % _PEEK_BYTES_PER_ROW)
        out = Text()
        for row in range(rows):
            addr = base + row * _PEEK_BYTES_PER_ROW
            if row:
                out.append("\n")
            out.append(f"{addr:08X}  ")
            cells = [
                f"{self._mem_map[addr + i]:02X}"
                if (addr + i) in self._mem_map
                else _PEEK_UNMAPPED_CELL
                for i in range(_PEEK_BYTES_PER_ROW)
            ]
            out.append(" ".join(cells))
        return out

    def _apply_auto_selection(
        self,
        previous_start: Optional[int],
        retry: bool = False,
        generation: Optional[int] = None,
    ) -> None:
        """Resolve, apply and focus the selection after a render (HLR-116).

        Summary:
            Runs on the post-refresh hook ``render_ranges`` schedules, which is
            the first point at which the newly mounted rows are queryable.
            Resolution is ``LLR-116.4``: the previously selected region when a
            region with that START ADDRESS is present among the new rows, the
            first region otherwise. Address, not index — a re-merge changes how
            many runs precede the selection, so an index would silently follow
            a different region.

            The hook can observe the DEFERRED-mount prune window: the rows are
            mounted by message, and the ``InvokeLater`` this hook runs on may
            fire before the mount messages are processed — measured
            intermittent (the batch-93 cockpit's nested ``ScrollableContainer``
            changed the frame timing, ~1 in 4 renders at any geometry). The
            window is detected STRUCTURALLY, not by row identity (batch-93
            inc-002): every ``.map-region-list`` is stamped at build time with
            the render generation that built it, and the hook resolves the
            list whose stamp equals ITS generation — with
            ``remove_children()`` and ``mount()`` both deferred, exactly ONE
            registered list can still be the superseded one (its removal
            queued, the successor's mount not yet landed), so a count alone
            cannot tell the survivor from the stale list. Binding the stale
            list selects and focuses rows that are about to vanish
            (LLR-116.2) — Textual then re-homes the focus to ``None``. ONE
            bounded retry is scheduled for the next frame — the
            ``_resize_band_segments`` width-0 discipline — then the hook gives
            up; it never spins and fabricates no selection.

            Two guards keep the deferred window safe (batch-93):
            ``generation`` ties the hook to the render that scheduled it — a
            newer ``render_ranges`` supersedes the hook, which stands down
            instead of re-applying a stale resolution. And the retry applies
            only while the selection is still unowned: an intervening click or
            key that selected a region between the attempt and the retry owns
            the inspector, and the retry must not stomp it.

            Focus then follows the resolved selection (``LLR-116.5``) so the
            operator's arrow keys act on the map instead of resuming wherever
            they were.

        Args:
            previous_start (Optional[int]): The selection address captured
                before ``_reset_detail()`` cleared it, or ``None`` on a first
                render.
            retry (bool): ``True`` only on the single self-scheduled re-attempt
                made when the rows were not yet mounted. Bounds the reschedule
                to ONE extra frame.
            generation (Optional[int]): The ``self._render_generation`` value
                at render time; a mismatch means a newer render superseded
                this hook. ``None`` (a direct call) means "current".

        Returns:
            None

        Data Flow:
            - Reads the mounted rows via the ``.map-region-list`` census;
              writes the inspector, the marker class and the app focus.

        Dependencies:
            Uses:
                - ``_select_region``
            Used by:
                - ``render_ranges`` (via ``call_after_refresh``) and itself
                  (one bounded retry)
        """
        if generation is not None and generation != self._render_generation:
            # A newer render superseded this hook — the new render's own hook
            # owns the resolution now.
            return
        generation_now = self._render_generation if generation is None else generation
        # Resolve the render's OWN list structurally: every list is stamped at
        # build time with the generation that built it, and with removal AND
        # mount both deferred, exactly ONE registered list can still be the
        # superseded one — a count alone cannot tell the survivor from the
        # stale list (batch-93 inc-002, LLR-116.2). Anything else means this
        # render's rows are not the sole registered survivors: fabricate no
        # selection and hand the resolution ONE more frame (the first
        # attempt), then give up and wait for the next real render.
        region_lists = [
            region_list
            for region_list in self.query(".map-region-list")
            if getattr(region_list, "_map_build_generation", None) == generation_now
        ]
        if len(region_lists) != 1:
            if not retry:
                self.call_after_refresh(
                    self._apply_auto_selection, previous_start, True, generation
                )
            return
        rows = [
            child
            for child in region_lists[0].children
            if isinstance(child, RegionRow)
        ]
        if not rows:
            # The list has mounted but its rows have not (their own mount
            # messages are still in flight) — fabricate no selection. Hand
            # the resolution ONE more frame on the first attempt, then give
            # up and wait for the next real render.
            if not retry:
                self.call_after_refresh(
                    self._apply_auto_selection, previous_start, True, generation
                )
            return
        if retry and self._selected_cell_start is not None:
            # An intervening selection (a click, a key) owns the inspector
            # between the attempt and this retry — re-applying the render's
            # auto-resolution would stomp it.
            return
        starts = [row.region_start for row in rows]
        index = starts.index(previous_start) if previous_start in starts else 0
        row = rows[index]
        self._select_region(row.region_start, row.region_end)
        # ``focus()`` is checked against DISPLAY, not just ``focusable``.
        # ``Widget.focusable`` consults ``visible`` (the ``visibility`` rule)
        # and NOT ``display`` — measured against textual 8.2.8 — while the rail
        # hides an inactive screen with ``.hidden { display: none }``. Loading a
        # file drives ``update_memory_map()`` whatever screen the operator is
        # on, so an unguarded focus would move the keyboard to an invisible row
        # on every load, on all nine screens. Focus is taken only when the map
        # is the screen actually being painted.
        #
        # The focus is taken SYNCHRONOUSLY through ``Screen.set_focus`` — the
        # same public API ``Widget.focus()`` defers to — because the deferred
        # ``call_later`` Callback can be silently dropped when this hook runs
        # inside the width-re-apportionment transition (batch-93 inc-002,
        # HLR-131): measured at the 80x24 floor, the deferred focus never
        # landed and the keyboard stayed on the rail. The guard above is the
        # precondition; the synchronous call makes the outcome observable in
        # the same frame.
        if row.focusable and self._is_displayed():
            try:
                self.app.screen.set_focus(row)
            except Exception:
                # NoScreen and friends: the map is not the painted screen —
                # the selection still applied; focus follows the next render.
                pass

    def _is_displayed(self) -> bool:
        """True while no ancestor (or the panel itself) is ``display: none``."""
        return all(
            node.display
            for node in self.ancestors_with_self
            if isinstance(node, Widget)
        )



class _Unset:
    """Sentinel type for "argument not supplied" (batch-48 LLR-080.2).

    ``None`` cannot serve: it is a MEANINGFUL value for ``mem_map`` — "no
    image is loaded" (LLR-080.4) — and conflating it with "not supplied" is
    the bug. ``refresh_entries`` has FIVE call sites and one of them (the
    panel's own ``on_mount`` self-call) has no ``mem_map`` to give; an
    unconditional retain would let that call NULL a map a real load had
    already supplied. Sentinel ⇒ preserve; explicit ``None`` ⇒ clear.
    """


_UNSET = _Unset()

#: The before/after strip's neutral states (batch-48 LLR-080.4; batch-97
#: D5 (h), LLR-148.9). Author-fixed literals, each at most 38 cells (the
#: card's content width at 118 columns) — nothing file-derived reaches the
#: card (LLR-080.7).
CARD_NO_ENTRIES = "No entry yet: Add one or Load a file."
CARD_NO_SELECTION = "Select a ledger row to see its bytes."
CARD_NO_IMAGE = "No image loaded: ^l loads one."
#: Rendered for an address the loaded image does not map (A4: absence is
#: UNMAPPED, never zero). MUST stay distinguishable from a real ``0x00``, whose
#: rendering is ``"00"`` — asserted by TC-080.3, not left to inspection.
CARD_UNMAPPED_TOKEN = "--"
#: The PATCH family teal (batch-94 spike; operator, Inc-4 gate 2026-10-21,
#: D5 (e) amended): the strip's changed ``now`` bytes and its ``N changed``
#: count, both bold. Claimed in the hue census (``test_tc079_5c``).
PATCH_TEAL = "#56e0d6"
#: batch-97 (D5 (c), D12): the strip stacks at most this many byte rows; a
#: longer run paints its first rows and one note line naming how much is shown.
STRIP_ROW_CAP = 8
#: batch-97 (D5 (f), D12): the byte-row widths the strip can take; the panel
#: picks the largest one whose line (``3·k + 8`` cells) fits the card.
STRIP_ROW_BYTES = (4, 8, 16, 32)
#: The strip's label column: ``  was    `` / ``  now    `` — 9 cells, so a
#: row line is ``3·per_row + 8`` cells wide, like its offset header.
_STRIP_LABEL_CELLS = 9


def before_after_card_text(
    address: Optional[int],
    before: Optional[Sequence[Optional[int]]],
    after: Sequence[int],
    per_row: int = 8,
    *,
    lead: Sequence[Optional[int]] = (),
    trail: Sequence[Optional[int]] = (),
    row_cap: int = STRIP_ROW_CAP,
) -> Text:
    """Compose the inspector's before→after hex strip (LLR-080.3, LLR-144.8).

    Summary:
        The pe_A grid (batch-97 D5): the selected entry's span, aligned down to
        a multiple of ``per_row``, painted as stacked byte rows. Each row is
        three lines — the offset header (row address as 8 hex digits, then
        ``+X`` per column, ``X`` = the address's low nibble), ``was`` (the
        image bytes) and ``now`` (the bytes the entry writes; a context
        position repeats its image byte). At most ``row_cap`` rows are
        painted; a longer run adds one note line ``showing N of M bytes``.
        A summary line ``M B @ 0x…… · C changed`` closes the strip, ``C``
        counted over the whole span by the shipped rule (image byte unmapped
        or different = changed). Pure, and fed ints only (LLR-080.7).

        Colour + attribute (LLR-144.8, D5 (e)): a changed span byte paints
        ``VALUE`` on the ``was`` line and ``bold PATCH_TEAL`` on the ``now``
        line, and a non-zero ``C changed`` count is ``bold PATCH_TEAL``; an
        unchanged span byte and every context byte paint ``DGRAY`` and are
        never bold. An unmapped byte paints ``--``.

    Args:
        address (Optional[int]): The entry's start address; ``None`` → the
            no-selection state.
        before (Optional[Sequence[Optional[int]]]): The image byte per span
            position (``None`` per unmapped position); ``None`` for the whole
            sequence → the no-image state.
        after (Sequence[int]): The entry's ``encoded_bytes``.
        per_row (int): Bytes per row (one of :data:`STRIP_ROW_BYTES`).
        lead (Sequence[Optional[int]]): Image bytes from the aligned row start
            up to ``address`` (context).
        trail (Sequence[Optional[int]]): Image bytes from the span end to the
            end of its last row (context).
        row_cap (int): The most byte rows painted.

    Returns:
        Text: Built with ``append`` only — never markup-parsed (C-17).

    Example:
        >>> t = before_after_card_text(0x203, [0xAA, 0xBB], [0x01, 0xBB], 8,
        ...     lead=[0, 0, 0], trail=[0, 0, 0])
        >>> t.plain.splitlines()[0]
        '00000200 +0 +1 +2 +3 +4 +5 +6 +7'
    """
    text = Text()
    if address is None:
        text.append(CARD_NO_SELECTION, style=DGRAY)
        return text
    if before is None:
        text.append(CARD_NO_IMAGE, style=DGRAY)
        return text

    span = len(after)
    start = address - len(lead)
    # One cell per painted position: (image byte, written byte, in the span).
    cells: list = [(byte, byte, False) for byte in lead]
    cells += [
        (before[i] if i < len(before) else None, after[i], True) for i in range(span)
    ]
    cells += [(byte, byte, False) for byte in trail]
    rows = -(-len(cells) // per_row) if cells else 0
    shown = min(rows, row_cap)

    def token(value: Optional[int]) -> str:
        return CARD_UNMAPPED_TOKEN if value is None else f"{value:02X}"

    for row in range(shown):
        row_start = start + row * per_row
        chunk = cells[row * per_row:(row + 1) * per_row]
        if row:
            text.append("\n")
        text.append(f"{row_start & 0xFFFFFFFF:08X}", style=CYAN)
        for col in range(len(chunk)):
            text.append(f" +{(row_start + col) % 16:X}", style=DGRAY)
        for label, written in (("was", False), ("now", True)):
            text.append("\n")
            text.append(f"  {label}".ljust(_STRIP_LABEL_CELLS), style=LABEL)
            for col, (image_byte, write_byte, in_span) in enumerate(chunk):
                if col:
                    text.append(" ")
                changed = in_span and (image_byte is None or image_byte != write_byte)
                value = write_byte if written else image_byte
                if not changed:
                    style = DGRAY
                elif written:
                    style = f"bold {PATCH_TEAL}"
                else:
                    style = VALUE
                text.append(token(value), style=style)
    if shown < rows:
        span_shown = max(0, shown * per_row - len(lead))
        text.append("\n" if shown else "")
        text.append(f"showing {span_shown} of {span} bytes", style=DGRAY)
    changed_count = sum(
        1
        for i in range(span)
        if (before[i] if i < len(before) else None) is None or before[i] != after[i]
    )
    if rows:
        text.append("\n")
    text.append(f"{span} B @ ", style=LABEL)
    text.append(f"0x{address & 0xFFFFFFFF:08X}", style=CYAN)
    text.append(" · ", style=LABEL)
    text.append(
        f"{changed_count} changed", style=f"bold {PATCH_TEAL}" if changed_count else DGRAY
    )
    return text


class BeforeAfterCard(Static):
    """The inspector's before→after hex strip (batch-48 LLR-080.1; batch-97 D5).

    Summary:
        A read-only card at the top of the Patch Editor's Inspector pane
        (batch-97 moved it there from the JSON window, D5). Selecting a ledger
        row shows the image bytes at that entry's span beside the bytes the
        entry would write, as the stacked pe_A grid of
        :func:`before_after_card_text` — live, BEFORE any apply. It applies
        nothing (LLR-080.5). Its ``border-top`` row carries the title
        ``BEFORE → AFTER``, so the title costs no row. Height is the content's
        (no cap): the strip itself caps its rows (``STRIP_ROW_CAP``).

    Note (Textual internal-name shadowing):
        The only members added are the public ``show_entry`` / ``show_state``
        methods and ``on_mount`` — no Widget private name is introduced
        (TC-080.1).
    """

    DEFAULT_CSS = """
    BeforeAfterCard {
        height: auto;
        padding: 0 1;
        border-top: solid $panel;
    }
    """

    def on_mount(self) -> None:
        self.border_title = "BEFORE → AFTER"

    def show_entry(
        self,
        address: Optional[int],
        before: Optional[Sequence[Optional[int]]],
        after: Sequence[int],
        per_row: int = 8,
        lead: Sequence[Optional[int]] = (),
        trail: Sequence[Optional[int]] = (),
    ) -> None:
        """Update the card to preview one entry (LLR-080.3/.4, D5)."""
        self.update(
            before_after_card_text(address, before, after, per_row, lead=lead, trail=trail)
        )

    def show_state(self, line: str) -> None:
        """Paint one of the card's author-fixed state lines (LLR-148.9)."""
        self.update(Text(line, style=DGRAY))


class LoadGuardScreen(ModalScreen[bool]):
    """The dirty-load warning popup (batch-94, HLR-005 / LLR-005.2).

    Summary:
        Modal raised by ``app.py`` when the Patch Editor's Load control is
        activated while unsaved edits exist in either editor region. It
        states the loss and offers the two policy branches: **Accept loss
        and load** continues the load of the path the operator typed (the
        document is replaced; the unsaved edits are lost), **Cancel** aborts
        the load and retains both the document and the dirty flag. Escape
        dismisses with Cancel, mirroring the sibling modals' Escape bond
        (batch-41 fold). Composed in this module (the ``screens.py`` modal
        idiom) because the popup is private to the panel that posts
        :class:`PatchEditorPanel.DirtyLoadRequested` — no fifth SOURCE file.

    Args:
        None

    Returns:
        bool: ``True`` when the operator accepted the loss, ``False`` on
            Cancel / Escape (``ModalScreen[bool]``).

    Data Flow:
        - ``compose`` builds a ``.modal-dialog`` with the warning text and
          the Accept / Cancel buttons.
        - ``on_button_pressed`` dismisses with the branch's value.

    Dependencies:
        Used by:
            - ``S19TuiApp.on_patch_editor_panel_dirty_load_requested``
    """

    #: Route initial focus to Cancel — the SAFE branch. Accept sits one Tab
    #: away; a popup whose default action destroys work would be a trap.
    AUTO_FOCUS = "#load_guard_cancel"

    BINDINGS = [Binding("escape", "cancel", "Cancel", show=False)]

    def compose(self) -> ComposeResult:
        with Vertical(classes="modal-dialog"):
            yield Label(
                "Unsaved changes will be lost",
                id="load_guard_title",
                classes="modal-title",
            )
            yield Static(
                "The change editor and the text editor carry unsaved "
                "changes. Loading a new document replaces them.",
                id="load_guard_body",
                markup=False,
            )
            yield Horizontal(
                Button(
                    "Accept loss and load",
                    id="load_guard_accept",
                    classes="patch-chip",
                ),
                Button(
                    "Cancel",
                    id="load_guard_cancel",
                    classes="patch-chip",
                ),
                id="load_guard_buttons",
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Dismiss with the branch the operator chose (LLR-005.2)."""
        button_id = event.button.id or ""
        if button_id == "load_guard_accept":
            event.stop()
            self.dismiss(True)
        elif button_id == "load_guard_cancel":
            event.stop()
            self.dismiss(False)

    def action_cancel(self) -> None:
        """Escape bond — dismiss with the Cancel branch (batch-41 fold)."""
        self.dismiss(False)


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

    #: The ledger's empty-state line (LLR-148.9): one English line, short
    #: enough for the 118-column ledger (65 cells), so it never wraps.
    EMPTY_STATE_TEXT = "No entries yet: Add one, paste a change-set or Load a file."

    #: The JSON view's state before any document reaches it (D4 (4), LLR-148.9).
    JSON_VIEW_EMPTY_TEXT = "No document yet: Load, paste or Add."

    #: The Checks tab's state line before any run (LLR-148.9).
    CHECKS_NO_RUN_TEXT = "No check run yet: press Run checks."

    #: The inspector's three tabs: (chip id, label, pane id, border title).
    _TABS = (
        ("patch_tab_inspector", "Inspector", "patch_pane_inspector", "INSPECTOR"),
        ("patch_tab_json", "JSON", "patch_win_json", "JSON"),
        ("patch_tab_checks", "Checks", "patch_win_checks", "CHECKS"),
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
    #:
    #: ⚠ RESOLVED at Inc-5 (the Inc-4 F1 note is superseded; its history is in
    #: the increment record). The strip is an INTENTIONAL TWO-LINE widget:
    #: counts on line 1, bar on line 2. The C-29 measurement chain that forces
    #: it, RE-MEASURED at Inc-5 against the real container:
    #:
    #:   120x30  window w=22 → body interior w=18 → STRIP CONTENT w=14
    #:    80x24  window w=68 → body interior w=66 → STRIP CONTENT w=62
    #:
    #: **14 is the budget at 120x30 — the batch's primary regime.** Two figures
    #: above it were each one container too generous: 22-23 is the WINDOW width
    #: (``test_tui_patch_layout.py:56-58``, which Inc-4 sized 8 cells against),
    #: and 16 is the BODY's content width. Each level costs borders + padding.
    #:
    #: The one-line layout does not fit at ANY separator width: the counts
    #: alone are 15 chars at the old spacing, and even the tightest form
    #: (``✓123 ✗456 ◐789`` = 14 exactly) leaves 0 cells for a bar. Worse, the
    #: old one-line form did not merely overflow — it wrapped MID-TOKEN once a
    #: count reached 2 digits, orphaning ``◐`` from its number and making the
    #: number read as a label on the bar:
    #:
    #:   agg 12/34/56 → line0 '✓ 12  ✗ 34  ◐ '   line1 '56  █░░░░░░░  '
    #:
    #: That is a WRONG-ANSWER defect on a verdict surface, reachable by any
    #: change-set with >= 10 entries — not an overflow nuisance. Making the two
    #: lines intentional costs nothing at 120x30 (h=2 is what already painted)
    #: and one scrolled row at 80x24, and it removes the mid-token wrap.
    #:
    #: REJECTED: responsive width (needs geometry in the builder — a
    #: first-layout-0 hazard, and it breaks the ``__new__`` unit tests) ·
    #: dropping the bar (fits, but guts HLR-078's proportional bar — an
    #: acceptance relaxation, not an implementation choice).
    _CHECK_STRIP_BAR_CELLS = 8

    #: The history strip's key-hint line (LLR-081.2). The two bindings are the
    #: batch-40 S2 ``ctrl+z`` / ``ctrl+y`` pair; this batch adds NO App-level
    #: ``Binding(show=True)``, so the hint is panel-local text and C-28's
    #: shared-chrome census does not fire (LLR-081.4).
    _HISTORY_HINT = "ctrl+z / ctrl+y"
    #: The history strip's DISABLED line. Shown whenever the Undo/Redo buttons
    #: are disabled — today the batch-38 A-01 file-backed guard, but the panel
    #: is a view and is told the STATE, not the reason, so this text names
    #: neither. It carries no key hints: the same guard gates the bindings, so
    #: the keys are inert and a hint for them would be a wrong answer.
    _HISTORY_OFF = "history off"

    #: The history strip's TWO-LINE shape — position on line 1, key hints on
    #: line 2 — is intentional, and the C-29 budget it is measured against is
    #: the SCRIPT window's, NOT the CHECKS window's. MEASURED at Inc-6 with the
    #: strip mounted (`region` / `content_region` off the live tree):
    #:
    #:   120x30  #patch_history_controls content w=38 → STRIP CONTENT w=38
    #:    80x24  #patch_history_controls content w=64 → STRIP CONTENT w=64
    #:
    #: **38 is the budget — do NOT inherit ``_CHECK_STRIP_BAR_CELLS``'s 14.**
    #: That 14 is the CHECKS window's content width at 120x30, and at that
    #: regime the patch layout is a 3-column split in which the SCRIPT window is
    #: nearly three times wider (44 vs 22). Inheriting a figure measured on a
    #: sibling container is precisely the C-29 error, and the record was sitting
    #: right there in `_CHECK_STRIP_BAR_CELLS` inviting it.
    #:
    #: Line 1's worst case is bounded WITHOUT a width assumption: ``back`` and
    #: ``forward`` are snapshot counts that `_push_history` evicts at
    #: `_HISTORY_MAX` (20) and `undo`/`redo` conserve, so ``back + forward <=
    #: 20`` and every count is at most 2 digits. The widest reachable line 1 is
    #: ``↶ 20 back  ↷ 0 fwd  20/20`` = 25 cells; line 2 is 15. Both clear 38
    #: with room, so the two lines are a READING-ORDER choice (position, then
    #: how to move it), not a wrap workaround like the CHECKS strip's.
    _HISTORY_STRIP_BUDGET_COLS = 38

    #: The shared 64 KiB paste cap, in CHARS (LLR-079.4). Aliased from the
    #: single source (``os_clipboard_input.py:72``) rather than re-spelled, so
    #: the gauge's denominator and the truncation it predicts cannot drift.
    _PASTE_CAP_CHARS = _CLIPBOARD_READ_CAP_CHARS
    #: Percent-of-cap cutoffs for the gauge's escalation (:func:`cap_gauge_style`).
    #: ``100`` is lower-inclusive, so AT the cap — the first point at which the
    #: next pasted character is silently dropped — already reads bold.
    _PASTE_GAUGE_WARN_PCT = 75.0
    _PASTE_GAUGE_BAD_PCT = 100.0

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

    #: The ledger window's border title (LLR-075.1). CONSTANT author string —
    #: never file-derived (C-17). batch-97: the inspector's title follows the
    #: active tab (``_TABS``); the JSON and CHECKS panes have no border.
    _WINDOW_BORDER_TITLES = {
        "patch_win_script": "PATCH SCRIPT",
    }

    #: The JSON tab's subtitle on the inspector border (LLR-075.1) — the
    #: change-set schema token, spelled locally (C-7).
    _JSON_SCHEMA_SUBTITLE = "v2 schema"

    #: The CHECKS pane's subtitle before any check run (LLR-075.1).
    _NO_RUN_SUBTITLE = "no run yet"

    #: The save-back S19 record widths in selector cycle order (US-015 /
    #: LLR-015.3). 32 is the default (the populated-S0 / 32-byte mode); 16 is
    #: the legacy empty-S0 / 16-byte mode. Spelled locally so this view widget
    #: imports nothing from the engine or service layer.
    SAVEBACK_WIDTHS = (32, 16)

    #: The DOCUMENT tally's bar width (pe_A, design §3).
    _TALLY_BAR_CELLS = 12

    # Layout rules for the v2 widget ids live in styles.tcss, in the one
    # scoped section ``/* batch-97 patch_editor */`` (D23).


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
        #: The dirty flag (batch-94, LLR-005.1). Set while unsaved edits exist
        #: in EITHER editor region (the entries or the paste buffer); cleared
        #: by a successful save or load. Readers: the Load guard, the ledger's
        #: border subtitle and the JSON stamp (batch-97 D4). Writer census
        #: (C-15.1, exactly four sites): w1 ``request_action`` (entry edit) ·
        #: w2 ``on_text_area_changed`` (paste typing) · w3 ``mark_saved`` ·
        #: w4 ``mark_loaded``.
        self._dirty: bool = False
        #: The loaded image's sparse memory map, RETAINED from
        #: ``refresh_entries``' parameter for the before/after strip
        #: (batch-48 LLR-080.2). ``None`` is MEANINGFUL — "no image loaded" —
        #: which is why that parameter's default is a sentinel. The panel never
        #: fetches this itself (C-7): it arrives as data, or not at all.
        self._mem_map: Optional[Mapping[int, int]] = None
        #: The rows last rendered into the entries table, retained so the strip
        #: resolves the highlighted row POSITIONALLY (LLR-080.3).
        self._entry_rows: List[object] = []
        #: batch-97 D4 (1): (entry count, ``HH:MM:SS``, uncapped json text) of
        #: the document the JSON view last painted; ``None`` until the first
        #: document push (the fresh-start state).
        self._json_shown: Optional[Tuple[int, str, str]] = None
        #: batch-97 D21: the last derived widths; ``None`` until measured.
        self._layout: Optional[PatchLayout] = None
        #: batch-97 LLR-144.7: the document identity the ribbon paints.
        self._identity: Tuple[Optional[str], str] = (None, "change")

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
        # (`S19TuiApp._scan_patch_change_files()` reads the filenames over
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

    def compose(self) -> ComposeResult:
        """Lay out the Patch Editor as a ledger + inspector (HLR-144, pe_A).

        Summary:
            The batch-97 composition (design §3, Patch Editor tree): an
            identity ribbon; the full-height PATCH SCRIPT ledger (``3fr``)
            beside the inspector (``2fr``) whose Inspector / JSON / Checks tab
            chips switch one ``ContentSwitcher``; then the file row, the
            document controls and the glyph legend, one terminal row each.
            Every shipped id is kept (LLR-144.1) and each ``patch_win_*`` /
            ``patch_saveback_row`` / ``patch_before_after_row`` /
            ``patch_checks_results`` id keeps its ``Container`` type. Geometry
            lives in ``styles.tcss`` (one scoped section, D23); Python sizes
            only the ledger columns and the strip's bytes per row (D21).

        Returns:
            ComposeResult: The widget tree.
        """
        yield Static(
            "", id="patch_identity_ribbon", classes="nowrap-ribbon", markup=False
        )
        with Horizontal(id="patch_main"):
            with Container(id="patch_win_script") as script:
                script.border_title = self._WINDOW_BORDER_TITLES["patch_win_script"]
                with VerticalScroll(id="patch_win_script_body") as script_body:
                    script_body.can_focus = False
                    with Container(id="patch_pane_entries"):
                        yield DataTable(
                            id="patch_doc_entries_table",
                            zebra_stripes=True,
                            cursor_type="row",
                            classes="nowrap-ledger",
                        )
                        yield Static(
                            self.EMPTY_STATE_TEXT,
                            id="patch_doc_empty_state",
                            markup=False,
                        )
            with Vertical(id="patch_inspector") as inspector:
                inspector.border_title = self._TABS[0][3]
                with Horizontal(id="patch_tabs"):
                    for chip_id, label, _pane, _title in self._TABS:
                        yield TabChip(
                            label,
                            id=chip_id,
                            classes="tab-chip chip-selected"
                            if chip_id == "patch_tab_inspector"
                            else "tab-chip",
                        )
                with ContentSwitcher(
                    initial="patch_pane_inspector", id="patch_tab_switcher"
                ):
                    with VerticalScroll(id="patch_pane_inspector") as pane:
                        pane.can_focus = False
                        yield BeforeAfterCard(id="patch_before_after_card")
                        with Vertical(id="patch_doc_entry_inputs"):
                            for label, input_id, placeholder in (
                                ("Address", "patch_entry_address_input", "0x100"),
                                ("String", "patch_entry_value_input", "text (document encoding)"),
                                ("Bytes", "patch_entry_bytes_input", "hex bytes, e.g. DE AD BE EF"),
                            ):
                                with Horizontal(classes="pe-row"):
                                    yield Label(label, classes="pe-label")
                                    # batch-31 AC-2 (B-03): OsClipboardInput so
                                    # Ctrl+V pastes through the bounded funnel.
                                    yield OsClipboardInput(
                                        placeholder=placeholder,
                                        id=input_id,
                                        compact=True,
                                    )
                        with Horizontal(
                            id="patch_doc_entry_buttons",
                            classes="patch-docked-row patch-chip-entry",
                        ):
                            yield Button("Add", id="patch_entry_add_button", classes="patch-chip")
                            yield Button("Edit", id="patch_entry_edit_button", classes="patch-chip")
                            yield Button(
                                "Remove", id="patch_entry_remove_button", classes="patch-chip"
                            )
                            # US-068b: the per-entry JSON editor for the
                            # SELECTED row — disabled for a file-backed document.
                            yield Button(
                                "Edit JSON",
                                id="patch_entry_edit_json_button",
                                classes="patch-chip",
                            )
                        yield Static("", id="patch_doc_tally", markup=False)
                    with Container(id="patch_win_json"):
                        yield Static(
                            "LOADED DOCUMENT · read-only",
                            id="patch_json_heading",
                            classes="nowrap-heading",
                            markup=False,
                        )
                        yield Static(
                            "", id="patch_json_stamp", classes="nowrap-heading", markup=False
                        )
                        # D3: literal by construction (no markup parser, C-17),
                        # focusable and scrolled by the arrow keys (LLR-144.10).
                        yield TextArea(
                            self.JSON_VIEW_EMPTY_TEXT,
                            id="patch_json_view",
                            read_only=True,
                            soft_wrap=False,
                        )
                        with VerticalScroll(id="patch_win_json_body") as json_body:
                            json_body.can_focus = False
                            with Container(id="patch_paste_row"):
                                with Horizontal(id="patch_paste_head"):
                                    yield Static(
                                        "PASTE BUFFER · example",
                                        id="patch_paste_heading",
                                        classes="nowrap-heading",
                                        markup=False,
                                    )
                                    # batch-48 (LLR-079.4): the paste-cap gauge
                                    # — integers + author-fixed labels only.
                                    yield Static(
                                        "",
                                        id="patch_paste_gauge",
                                        markup=False,
                                        classes="patch-field-label",
                                    )
                                # batch-48 (LLR-079.1): capped, JSON-coloured,
                                # no markup path (C-17 / LLR-079.3).
                                yield JsonHighlightTextArea(
                                    DUMMY_CHANGESET_TEXT, id="patch_paste_text"
                                )
                        spacer = Container(id="patch_win_json_dock_spacer")
                        spacer.display = False
                        yield spacer
                        with Horizontal(
                            id="patch_paste_controls",
                            classes="patch-docked-row patch-chip-apply",
                        ):
                            yield Button(
                                "Parse pasted",
                                id="patch_paste_parse_button",
                                classes="patch-chip",
                            )
                            # US-064b: the full-size JSON popup over the paste
                            # buffer; disabled for a file-backed document.
                            yield Button(
                                "Edit JSON", id="patch_edit_json_button", classes="patch-chip"
                            )
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
                    with Container(id="patch_win_checks"):
                        with VerticalScroll(id="patch_win_checks_body"):
                            yield Label(
                                "", id="patch_doc_issue_count", classes="patch-field-label"
                            )
                            yield Static(
                                "", id="patch_doc_issues", markup=False, classes="hidden"
                            )
                            # batch-33 (LLR-051.6, C-17): the untruncated
                            # run-block reason — markup never interpreted.
                            yield Label(
                                self.CHECKS_NO_RUN_TEXT,
                                id="patch_checks_status",
                                classes="patch-field-label",
                                markup=False,
                            )
                            # batch-48 (LLR-078.1): the pass/fail strip —
                            # integer counts and closed glyphs only (C-17).
                            yield Static(
                                "",
                                id="patch_checks_strip",
                                markup=False,
                                classes="patch-field-label",
                            )
                            yield Container(id="patch_checks_results")
                        section = Label(
                            "Checks",
                            id="patch_checks_section_label",
                            classes="patch-section-title",
                        )
                        section.display = False
                        yield section
                        with Container(
                            id="patch_checks_controls",
                            classes="patch-docked-group patch-chip-checks",
                        ):
                            yield Button(
                                "Run checks",
                                id="patch_checks_run_button",
                                classes="patch-chip",
                            )
                            # batch-35 (US-052): the clarity help, kept verbatim
                            # (AT-032a / AT-052a pin it); it wraps under Run
                            # checks in the pane's spare rows.
                            yield Label(
                                "Checks: runs the loaded change document's checks "
                                "against the loaded image. Needs kind 'check' (a "
                                "change-set cannot be checked). Uncheckable rows "
                                "name their reason (declaration fault, "
                                "partial/outside range, or no image); healthy "
                                "entries are still checked.",
                                id="patch_checks_help",
                                classes="patch-field-label",
                            )
        with Horizontal(id="patch_doc_file_row", classes="patch-docked-row"):
            yield Label("File", classes="pe-label")
            with Horizontal(id="patch_doc_file_line1"):
                yield Select(
                    [],
                    id="patch_doc_file_select",
                    prompt="Change files in patches/",
                    allow_blank=True,
                    compact=True,
                )
                yield OsClipboardInput(
                    placeholder=(
                        "or type a path to the same change-set JSON "
                        "(alternative to the patches/ dropdown)"
                    ),
                    id="patch_doc_path_input",
                    compact=True,
                )
                yield Button("Load", id="patch_doc_load_button", classes="patch-chip")
            with Horizontal(id="patch_doc_file_line2"):
                yield Button(
                    "Refresh", id="patch_doc_refresh_button", classes="patch-chip"
                )
                # batch-35 (US-057): the section label stays mounted (census),
                # its words carried by the ledger's border title.
                label = Label(
                    "Patch script",
                    id="patch_script_section_label",
                    classes="patch-section-title",
                )
                label.display = False
                yield label
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
        yield Static(
            "   ".join(f"{glyph} {meaning}" for glyph, meaning in PATCH_GLYPHS.items()),
            id="patch_legend",
            classes="glyph-legend nowrap-legend",
            markup=False,
        )

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
        self._refresh_inspector_subtitle()

    def _refresh_inspector_subtitle(self) -> None:
        """The inspector's border subtitle follows the tab (LLR-075.1): the
        JSON tab shows the schema token, the Checks tab its run state."""
        switchers = self.query("#patch_tab_switcher")
        if not switchers:
            return
        current = switchers.first(ContentSwitcher).current
        subtitle = ""
        if current == "patch_win_json":
            subtitle = self._JSON_SCHEMA_SUBTITLE
        elif current == "patch_win_checks":
            subtitle = self.query_one("#patch_win_checks", Container).border_subtitle or ""
        self.query_one("#patch_inspector").border_subtitle = subtitle

    def _refresh_scope_line(self) -> None:
        """Render the execution-scope line (LLR-075.3, batch-94 form).

        Summary:
            Compose ``Scope <label>`` as a Rich ``Text`` and write it to
            ``#patch_scope_line``. The scope label comes from the panel's
            OWN local vocabulary (``_SCOPE_LABELS``), so this view widget
            still imports nothing from the service layer (C-7). Batch-94
            (HLR-006): the ``Variant <id> ·`` half of the former
            variant/scope line retired with the variant selector — the line
            names the scope only, and carries NO file-derived text.

        Returns:
            None

        Data Flow:
            - ``self._execute_scope`` (cycled by the scope button) →
              ``label_value`` pair → ``Static.update``.

        Dependencies:
            Uses:
                - ``insight_style.label_value``
            Used by:
                - ``PatchEditorPanel.on_button_pressed`` (the scope cycle)
                - ``PatchEditorPanel.on_mount``

        Example:
            >>> panel._refresh_scope_line()
        """
        lines = self.query("#patch_scope_line")
        if not lines:
            return
        lines.first(Static).update(
            label_value("Scope", self._SCOPE_LABELS[self._execute_scope])
        )

    # ------------------------------------------------------------------
    # Width derivation (D21: mount, resize, show)
    # ------------------------------------------------------------------

    def _widths(self) -> "PatchLayout":
        """The current layout, or the 118-column reading before the first measure."""
        return self._layout or patch_layout(65, 41, self._status_longest(), 110)

    def _status_longest(self) -> int:
        return max((cell_len(str(row.status_text)) for row in self._entry_rows), default=0)

    def _ledger_cells(self, row: object, layout: "PatchLayout") -> tuple:
        """The five cells of one ledger row, every one a literal ``Text`` (C-17)."""
        return (
            self._kind_cell(row),
            safe_text(str(row.address_text), CYAN),
            safe_text(_clip_to_cells(safe_text(str(row.value_text)).plain, layout.value), VALUE),
            safe_text(_clip_to_cells(safe_text(str(row.status_text)).plain, layout.status)),
            safe_text(_clip_to_cells(safe_text(str(row.linkage_text)).plain, layout.linkage)),
        )

    def _apply_layout(self) -> None:
        """Re-derive the widths and repaint every width-dependent text (D21).

        Reads the measured content widths of ``#patch_win_script`` (the
        ledger's frame, which the table fills), ``#patch_inspector`` and the
        ribbon — never the terminal width. An unchanged layout repaints
        nothing. Otherwise it sets each column's width and rewrites the
        Value / Status / Linkage cells with ``update_cell`` (the first call
        ``update_width=True``, the PC-8 path), re-renders the strip at its new
        bytes per row and repaints the ribbon. It never adds a column.
        """
        ledger = self.query_one("#patch_win_script")
        inspector = self.query_one("#patch_inspector")
        ribbon = self.query_one("#patch_identity_ribbon")
        if ledger.content_region.width == 0 or inspector.content_region.width == 0:
            return
        layout = patch_layout(
            ledger.content_region.width,
            inspector.content_region.width,
            self._status_longest(),
            ribbon.content_region.width,
        )
        if layout == self._layout:
            return
        self._layout = layout
        table = self.query_one("#patch_doc_entries_table", DataTable)
        columns = table.ordered_columns
        widths = (layout.kind, layout.address, layout.value, layout.status, layout.linkage)
        for column, width in zip(columns, widths):
            column.width = width
            column.auto_width = False
        keys = [column.key for column in columns]
        if not self._entry_rows:
            # D21 (5): with no rows the pass is ``clear()`` (rows only).
            table.clear()
        for index, row in enumerate(self._entry_rows):
            cells = self._ledger_cells(row, layout)
            for column in (2, 3, 4):
                table.update_cell(
                    str(index), keys[column], cells[column],
                    update_width=(index == 0 and column == 2),
                )
        self._render_before_after_card()
        self._refresh_ribbon()

    def on_resize(self, event: events.Resize) -> None:
        self.call_after_refresh(self._apply_layout)

    def on_show(self, event: events.Show) -> None:
        self.call_after_refresh(self._apply_layout)

    def on_mount(self) -> None:
        """Add the five ledger columns once and paint every initial state."""
        layout = self._widths()
        table = self.query_one("#patch_doc_entries_table", DataTable)
        for label, width in zip(
            self._ENTRIES_COLUMNS,
            (layout.kind, layout.address, layout.value, layout.status, layout.linkage),
        ):
            table.add_column(label, width=width)
        self.refresh_entries([])
        # LLR-075.3: the scope line never mounts blank.
        self._refresh_scope_line()
        # LLR-079.4: the buffer mounts NON-empty (`DUMMY_CHANGESET_TEXT`).
        self._refresh_paste_gauge()
        self._set_window_subtitle("patch_win_checks", self._NO_RUN_SUBTITLE)
        self._refresh_json_stamp()
        self.call_after_refresh(self._apply_layout)

    # ------------------------------------------------------------------
    # Tabs, ribbon, tally and the JSON view (batch-97 HLR-144)
    # ------------------------------------------------------------------

    def _show_tab(self, chip_id: str) -> None:
        """Switch the inspector to ``chip_id``'s pane; its title follows the tab."""
        for tab_id, _label, pane, title in self._TABS:
            selected = tab_id == chip_id
            self.query_one(f"#{tab_id}").set_class(selected, "chip-selected")
            if selected:
                self.query_one("#patch_tab_switcher", ContentSwitcher).current = pane
                self.query_one("#patch_inspector").border_title = title
        self._refresh_inspector_subtitle()

    def _refresh_ribbon(self) -> None:
        """Paint the identity ribbon: file name (tail kept) · kind (LLR-144.7).

        The name is file-derived, so it goes through ``safe_text`` and is
        appended literally; a name wider than the ribbon keeps its tail behind
        one ``…`` (LLR-149.4, file names). A document with no file reads
        ``draft``.
        """
        name, kind = self._identity
        ribbon = self.query_one("#patch_identity_ribbon", Static)
        width = self._widths().ribbon
        tail = Text(f" · {kind or 'no kind'}", style=DGRAY)
        if name is None:
            text = Text("draft", style=VALUE)
        else:
            room = max(8, width - cell_len(tail.plain))
            text = safe_text(clip_tail(safe_text(name).plain, room), VALUE)
        text.append_text(tail)
        ribbon.update(text)

    def _tally_text(self) -> Text:
        """The DOCUMENT tally at the Inspector pane's foot (design §3, PC-6).

        Counts only, from the rows' closed status vocabulary: ``DOCUMENT``, a
        12-cell bar (one ``▓`` per entry in its status colour while the
        entries fit, else proportional), ``N entries · I inside · P partial``
        and ``O outside · F faults`` (`` · U no image`` when non-zero) — four
        explicit lines, never a wrapped one. Empty: ``DOCUMENT`` + ``0 entries``.
        """
        rows = self._entry_rows
        text = Text("DOCUMENT", style=DGRAY)
        text.append("\n")
        if not rows:
            text.append("0 entries", style=f"bold {VALUE}")
            return text
        counts = {"inside": 0, "partial": 0, "outside": 0, "unvalidated-no-image": 0}
        faults = 0
        colours = []
        style_of = {"inside": GREEN, "partial": YELLOW, "outside": RED}
        for row in rows:
            status = str(row.status_text)
            base = status.split(" / ", 1)[0]
            if base in counts:
                counts[base] += 1
            if "fault" in status:
                faults += 1
            colours.append(RED if "fault" in status else style_of.get(base, DGRAY))
        cells = self._TALLY_BAR_CELLS
        if len(rows) <= cells:
            for colour in colours:
                text.append("▓", style=colour)
            text.append("░" * (cells - len(rows)), style=DGRAY)
        else:
            painted = 0
            for key in ("inside", "partial", "outside"):
                share = round(cells * counts[key] / len(rows))
                text.append("▓" * share, style=style_of[key])
                painted += share
            text.append("░" * max(0, cells - painted), style=DGRAY)
        text.append("\n")
        n = len(rows)
        text.append(f"{n} {'entry' if n == 1 else 'entries'}", style=f"bold {VALUE}")
        text.append(" · ", style=DGRAY)
        text.append(f"{counts['inside']} inside", style=GREEN if counts["inside"] else DGRAY)
        text.append(" · ", style=DGRAY)
        text.append(f"{counts['partial']} partial", style=YELLOW if counts["partial"] else DGRAY)
        text.append("\n")
        text.append(f"{counts['outside']} outside", style=RED if counts["outside"] else DGRAY)
        text.append(" · ", style=DGRAY)
        text.append(f"{faults} faults", style=RED if faults else DGRAY)
        if counts["unvalidated-no-image"]:
            text.append(" · ", style=DGRAY)
            text.append(f"{counts['unvalidated-no-image']} no image", style=DGRAY)
        return text

    def _refresh_json_stamp(self) -> None:
        """Recompose the stamp from the retained count and time + the dirty flag (D4)."""
        stamps = self.query("#patch_json_stamp")
        if not stamps:
            return
        shown = self._json_shown
        stamps.first(Static).update(
            Text(
                json_stamp_text(
                    None if shown is None else shown[0],
                    None if shown is None else shown[1],
                    self._dirty,
                ),
                style=DGRAY,
            )
        )

    def _show_document(self, document: "PatchDocumentView") -> None:
        """The D1 document path: identity always, the view only on a new payload.

        D4 (2), the equal-payload rule: a document whose serialised text equals
        the one shown leaves the view (text, cursor, scroll), the retained time
        and the stamp untouched; the ribbon is repainted either way (a Save can
        name a draft). A new payload reloads the view with the capped text,
        takes the time from :func:`_json_clock` and recomposes the stamp.
        """
        self._identity = (document.name, document.kind)
        self._refresh_ribbon()
        shown = self._json_shown
        if shown is not None and shown[2] == document.json_text:
            return
        self._json_shown = (document.entry_count, _json_clock(), document.json_text)
        self.query_one("#patch_json_view", TextArea).load_text(
            cap_json_lines(document.json_text.rstrip("\n"))
        )
        self._refresh_json_stamp()

    def on_text_area_changed(self, event: TextArea.Changed) -> None:
        """Keep the paste-cap gauge in step with the buffer (LLR-079.4).

        Summary:
            Re-render the gauge whenever the paste buffer's content changes —
            which is every ingress at once (bracketed paste, ``ctrl+v``,
            typing, and the app's programmatic ``load_text``), because
            ``TextArea.Changed`` is posted by the document edit itself rather
            than by any one caller. A per-call-site refresh would be the
            batch-38 Inc-4 F1 stale-panel shape: an omitted site leaves a
            wrong number on screen.

        Args:
            event (TextArea.Changed): The originating widget's change message.

        Returns:
            None.

        Raises:
            None.

        Data Flow:
            - Filter to ``#patch_paste_text`` → :meth:`_refresh_paste_gauge`.
            - The id filter matters: ``Changed`` bubbles, so an unfiltered
              handler would repaint the gauge from an unrelated ``TextArea``.

        Dependencies:
            Uses:
                - :meth:`_refresh_paste_gauge`
            Used by:
                - Textual message dispatch (the ``#patch_paste_text`` buffer)
        """
        if event.text_area.id == "patch_paste_text":
            # w2 (LLR-005.1 writer census): an edit in the JSON text region
            # sets the dirty flag — the Load guard treats the buffer as
            # unsaved work even when the entries table is clean.
            self._dirty = True
            self._refresh_dirty_indicator()
            self._refresh_paste_gauge()

    def _refresh_paste_gauge(self) -> None:
        """Render the gauge from the buffer's CURRENT length (LLR-079.4).

        Summary:
            Read ``#patch_paste_text``'s length and hand it to
            :meth:`_paste_gauge_text`. The length is read from the widget
            here — not passed in — so no caller can supply a count that
            disagrees with what is on screen.

        Args:
            None.

        Returns:
            None.

        Raises:
            None — both ids are composed by this panel.

        Data Flow:
            - ``len(TextArea.text)`` → :meth:`_paste_gauge_text` →
              ``#patch_paste_gauge``.

        Dependencies:
            Uses:
                - :meth:`_paste_gauge_text`
            Used by:
                - :meth:`on_mount`, :meth:`on_text_area_changed`,
                  :meth:`clear_paste_buffer`

        The same pass names the buffer in ``#patch_paste_heading``:
        ``example`` while it equals ``DUMMY_CHANGESET_TEXT``, else
        ``editable``.
        """
        buffer = self.query_one("#patch_paste_text", TextArea)
        self.query_one("#patch_paste_gauge", Static).update(
            self._paste_gauge_text(len(buffer.text))
        )
        # batch-97 Inc-4 gate (ux Obs 5): the heading says when the buffer
        # still holds the shipped example rather than the operator's text.
        self.query_one("#patch_paste_heading", Static).update(
            "PASTE BUFFER · example"
            if buffer.text == DUMMY_CHANGESET_TEXT
            else "PASTE BUFFER · editable"
        )

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

    def clear_paste_buffer(self) -> None:
        """Empty ``#patch_paste_text`` without marking the panel dirty.

        Called by ``app.py``'s project-session reset (batch-100 LED .55(b)):
        the outgoing document's buffer is discarded, not edited. The clear
        runs with ``TextArea.Changed`` prevented, so writer w2 never sees it
        and no dirty flag is set behind the caller's back — a deferred
        ``mark_loaded`` raced that message and lost (hotfix 3b). The gauge
        and heading are repainted here because the prevented message is
        what normally repaints them.
        """
        buffer = self.query_one("#patch_paste_text", TextArea)
        with buffer.prevent(TextArea.Changed):
            buffer.text = ""
        self._refresh_paste_gauge()

    def mark_pasted(self) -> None:
        """Set the dirty flag after a successful paste parse (batch-97 Inc-4 gate).

        Called by ``app.py`` when Parse pasted replaces the document. The
        parsed document is a draft no file holds, so it is unsaved work: the
        JSON stamp reads ``unsaved changes`` beside the ribbon's ``draft`` and
        a Load asks first (ux-reviewer H1, LLR-144.6 amended; was
        ``mark_loaded``, batch-94 w4).
        """
        self._dirty = True
        self._refresh_dirty_indicator()

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

    class DirtyLoadRequested(Message):
        """Load was activated while unsaved edits exist (HLR-005).

        Summary:
            Posted by ``#patch_doc_load_button`` in place of the plain
            ``load_doc`` action when the dirty flag is set. Carries the path
            input's current text so ``app.py`` can present the guard popup
            and, on accept, run EXACTLY the load the operator asked for —
            the path beside the Load control (annotation 6).

        Args:
            path_text (str): The change-file path input's current text.

        Dependencies:
            Used by:
                - ``S19TuiApp.on_patch_editor_panel_dirty_load_requested``
        """

        def __init__(self, path_text: str) -> None:
            super().__init__()
            self.path_text = path_text

    def on_select_changed(self, event: Select.Changed) -> None:
        """Forward a change-file dropdown pick to ``app.py`` (US-026).

        Summary:
            When ``#patch_doc_file_select`` changes to a concrete filename,
            post a :class:`ChangeFileSelected` carrying the bare name so the app
            re-resolves it under the patches folder (with the LLR-030.3
            containment guard) and loads it via the existing
            ``ChangeService.load`` path. A blank selection (``Select.NULL`` —
            the ``NoSelection`` placeholder emitted when ``set_change_files``
            repopulates or clears the option set) is NOT a request, so
            nothing is posted. Batch-94 (HLR-006): the variant dropdown
            retired with the variant group — this handler owns the one
            remaining select.

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
            cell (``S19TuiApp._build_a2l_table_cells``) and the MAC table folds
            its status glyph into the Tag cell "as its own span"
            (``S19TuiApp._populate_mac_datatable``), both
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

    def refresh_entries(
        self,
        rows: Sequence[object],
        mem_map: Union[Mapping[int, int], None, _Unset] = _UNSET,
        document: Union["PatchDocumentView", _Unset] = _UNSET,
    ) -> None:
        """Repopulate the ledger, the strip, the tally and the JSON view.

        Summary:
            Replace every ledger row with the supplied ``ChangeEntryRow`` list;
            with no rows show the one empty-state line instead (LLR-148.9).
            Every cell is a literal ``Text`` (``_kind_cell`` / ``safe_text``),
            never a bare ``str`` — Textual's ``default_cell_formatter`` would
            markup-parse one (LLR-075.6 / C-17). Value, Status and Linkage are
            clipped to their derived widths with one ``…`` (LLR-149.4). Also
            refresh the ledger's ``N entries`` subtitle (+ the dirty marker),
            the DOCUMENT tally and the before→after strip.

            batch-97 I-2/I-3 (D1): ``document`` carries the serialised
            document and its identity; the app builds it at all four sites,
            so the rows, the ribbon and the JSON view cannot disagree.

        Args:
            rows (Sequence[object]): ``ChangeService.rows`` output (duck-typed,
                C-7).
            mem_map (Union[Mapping[int, int], None, _Unset]): The image's map,
                RETAINED for the strip: omitted ⇒ preserve; ``None`` ⇒ clear
                ("no image loaded"); a mapping ⇒ replace (TC-080.2a). The
                sentinel is load-bearing: ``on_mount``'s self-call has no map.
            document (Union[PatchDocumentView, _Unset]): omitted ⇒ preserve
                the shown document (the self-call); a view ⇒ the D4 document
                path (:meth:`_show_document`).
        """
        if not isinstance(mem_map, _Unset):
            self._mem_map = mem_map
        self._entry_rows = list(rows)
        table = self.query_one("#patch_doc_entries_table", DataTable)
        empty_state = self.query_one("#patch_doc_empty_state", Static)
        layout = self._widths()
        table.clear()
        for index, row in enumerate(rows):
            table.add_row(*self._ledger_cells(row, layout), key=str(index))
        count = len(rows)
        # LLR-005.1 (batch-94): the entry-count subtitle doubles as the dirty
        # indicator — the marker is part of the SAME string.
        self._set_window_subtitle(
            "patch_win_script",
            f"{count} {'entry' if count == 1 else 'entries'}"
            + (" ●" if self._dirty else ""),
        )
        if rows:
            table.remove_class("hidden")
            empty_state.add_class("hidden")
        else:
            table.add_class("hidden")
            empty_state.remove_class("hidden")
            empty_state.update(self.EMPTY_STATE_TEXT)
        self.query_one("#patch_doc_tally", Static).update(self._tally_text())
        self._render_before_after_card()
        if not isinstance(document, _Unset):
            self._show_document(document)
        # The Status column is sized to the longest status (D21 input): only a
        # change of that width needs a layout pass (resize / show run their own).
        if self._layout is not None and self._layout.status != max(
            7, min(self._status_longest(), 20)
        ):
            self.call_after_refresh(self._apply_layout)

    def on_data_table_row_highlighted(
        self, event: DataTable.RowHighlighted
    ) -> None:
        """Drive the before/after card as the entries cursor moves (LLR-080.3).

        Summary:
            The entries table is ``cursor_type="row"``, so the highlighted row
            index IS the document-order entry index — the card previews THAT
            entry. Highlight (not ``RowSelected``) is the right event: it fires
            on cursor movement, giving the analyst a live read-out without
            requiring a commit keystroke — the ``A2LDetailCard`` precedent
            (batch-47 LLR-069.2).

        Args:
            event (DataTable.RowHighlighted): Event payload carrying
                ``data_table`` and ``cursor_row``.

        Returns:
            None

        Data Flow:
            - Ignore every table but ``#patch_doc_entries_table``.
            - Hand ``event.cursor_row`` to :meth:`_render_before_after_card`.
            - The event is NOT stopped: ``S19TuiApp.on_data_table_row_highlighted``
              also listens (for the A2L card) and filters by table id, so
              letting it bubble costs nothing and stopping it would couple this
              panel to that handler's business.

        Dependencies:
            Uses:
                - :meth:`_render_before_after_card`
            Used by:
                - Textual event dispatch for ``DataTable.RowHighlighted``
        """
        table = getattr(event, "data_table", None)
        if getattr(table, "id", None) != "patch_doc_entries_table":
            return
        self._render_before_after_card(event.cursor_row)

    def _render_before_after_card(self, index: Optional[int] = None) -> None:
        """Render the before→after strip for one entry index (LLR-080.3, D5).

        Summary:
            Resolve the selected entry POSITIONALLY, read the image bytes of its
            span and of the context around it (the aligned row start up to the
            address, and the span end to the end of its last row) out of the
            retained ``mem_map``, and hand them to the card at the layout's
            bytes per row. No entries → the no-entries state; no selection →
            the no-selection state; no image → the no-image state.

        Note (the join is POSITIONAL — never address-matched):
            ``ChangeEntry`` carries no id; the contract is document order and
            ``cursor_type="row"`` makes the cursor row that same index; two
            entries sharing a start address stay distinct (TC-080.3).

        Note (read-only — LLR-080.5; ints only — LLR-080.7):
            ``mem_map`` is read with ``.get``; only ``row.address`` and
            ``row.encoded_bytes`` are read off the row.
        """
        cards = self.query("#patch_before_after_card")
        if not cards:
            return
        card = cards.first(BeforeAfterCard)
        if not self._entry_rows:
            card.show_state(CARD_NO_ENTRIES)
            return
        if index is None:
            index = self.query_one(
                "#patch_doc_entries_table", DataTable
            ).cursor_row
        if not 0 <= index < len(self._entry_rows):
            card.show_entry(None, None, ())
            return
        # Direct attribute access: these fields are REQUIRED for the strip,
        # and a default would silently paint an empty preview.
        row = self._entry_rows[index]
        address = int(row.address)
        after = tuple(row.encoded_bytes)
        if self._mem_map is None:
            card.show_entry(address, None, after)
            return
        per_row = self._widths().strip_bytes
        row_start = address - address % per_row
        span_end = address + len(after)
        rows = -(-(span_end - row_start) // per_row)
        mem = self._mem_map
        card.show_entry(
            address,
            [mem.get(a) for a in range(address, span_end)],
            after,
            per_row,
            lead=[mem.get(a) for a in range(row_start, address)],
            trail=[mem.get(a) for a in range(span_end, row_start + rows * per_row)],
        )

    def refresh_issues(self, lines: Sequence[str]) -> None:
        """Render the persistent declaration-fault area (LLR-002.8).

        Non-empty → the count label ``Declaration faults: N`` and the listing
        (a literal ``Text`` through ``safe_text`` — the lines echo file-derived
        values, LLR-144.7); empty → both cleared. With no entries, the first
        finding is also the ledger's one state line (LLR-148.9: a refused load
        shows its finding where the entries would be).
        """
        count_label = self.query_one("#patch_doc_issue_count", Label)
        listing = self.query_one("#patch_doc_issues", Static)
        empty_state = self.query_one("#patch_doc_empty_state", Static)
        if lines:
            count_label.update(f"Declaration faults: {len(lines)}")
            listing.update(safe_text("\n".join(str(line) for line in lines)))
            listing.remove_class("hidden")
            if not self._entry_rows:
                empty_state.update(safe_text(f"Refused: {lines[0]}"))
        else:
            count_label.update("")
            listing.update("")
            listing.add_class("hidden")
            if not self._entry_rows:
                empty_state.update(self.EMPTY_STATE_TEXT)

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

    def _paste_gauge_text(self, used_chars: int) -> Text:
        """Build the paste-cap gauge's renderable (LLR-079.4).

        Summary:
            Render ``<used>K / 64.0K`` against the shared 64 KiB paste cap,
            styled by :func:`cap_gauge_style` so the read-out ESCALATES as the
            buffer fills.

            **Units are CHARS, not bytes, and that is deliberate.** The cap
            (``_CLIPBOARD_READ_CAP_CHARS``, ``os_clipboard_input.py:72``)
            truncates on ``text[:CAP]`` — a **character** slice — so a
            byte-denominated gauge would disagree with the truncation it
            exists to predict, by up to 4x on non-ASCII input. ``human_bytes``
            is therefore NOT used here despite being the house size helper: it
            is a *byte* humanizer, and rendering a char count through it would
            print a confident, wrong unit. ``K`` = 1024 chars.

            **Hue (operator ruling, 2026-07-16):** the gauge escalates as a
            WARNING (§6.5 Amendment F's semantics, app-wide, unnarrowed) but
            must NOT reuse GREEN/YELLOW/RED, because inside
            ``#patch_editor_panel`` those three are VERDICT hues
            (``_GLYPH_STYLE``, the pass/fail strip). ``threshold_style``
            returns exactly those three and is therefore NOT usable here;
            :func:`cap_gauge_style` escalates within the MAGENTA family
            instead (quiet grey → magenta → bold magenta), whose hue is the
            MEASURED optimum against the full app-wide claimant census
            (``test_tc079_5*``): no hue on the circle separates further from
            every claimed hue than MAGENTA does.
            ⚠ The earlier ">= 43 deg from every claimant" wording here was
            FALSE and is retracted (Inc-5b). It was not merely wrong — it was
            UNSATISFIABLE: against the complete census the best any hue
            achieves is 40.77 deg, so no colour could have satisfied it. It
            "passed" only because the census omitted the hues that would have
            failed it. The binding assertion is now optimality plus an
            ANCHORED floor (24 deg — beating the 23.5 deg pair the app already
            ships and reads fine), which is self-calibrating and cannot go
            unsatisfiable. See REQUIREMENTS.md §6.5 Amendment F-1.

        Args:
            used_chars (int): The buffer's current ``len(text)``. Read from
                the widget by :meth:`_refresh_paste_gauge`; never a
                caller-supplied count.

        Returns:
            rich.text.Text: The gauge line. Never a ``str`` — and never any
            file-derived text: an integer and author-fixed labels only
            (C-17 / LLR-079.3). The pasted buffer reaches this method as a
            ``len``, so no payload character can reach the render path even
            in principle.

        Raises:
            None. Integer arithmetic and a constant divisor.

        Data Flow:
            - ``used_chars`` → percent of ``_PASTE_CAP_CHARS`` →
              :func:`cap_gauge_style` → :func:`label_value`.
            - No clamp on the percentage: ``cap_gauge_style``'s top band is
              lower-inclusive, so at-cap and over-cap both read bold.

        Dependencies:
            Uses:
                - ``_PASTE_CAP_CHARS`` / ``_PASTE_GAUGE_WARN_PCT`` /
                  ``_PASTE_GAUGE_BAD_PCT`` ; ``insight_style.cap_gauge_style``
                  / ``LABEL``
            Used by:
                - :meth:`_refresh_paste_gauge`

        Example:
            >>> panel = PatchEditorPanel.__new__(PatchEditorPanel)
            >>> panel._paste_gauge_text(32768).plain
            '32.0K / 64.0K'
        """
        cap = self._PASTE_CAP_CHARS
        pct = (used_chars / cap) * 100.0
        text = Text()
        # The USED figure escalates; the denominator is a constant, so it stays
        # muted. `label_value` would have styled these the other way round.
        text.append(
            f"{used_chars / 1024:.1f}K",
            style=cap_gauge_style(
                pct, self._PASTE_GAUGE_WARN_PCT, self._PASTE_GAUGE_BAD_PCT
            ),
        )
        text.append(f" / {cap / 1024:.1f}K", style=LABEL)
        return text

    def _check_strip_text(self, aggregates: Optional[Mapping[str, int]]) -> Text:
        """Build the CHECKS pass/fail strip's renderable (LLR-078.1).

        Summary:
            Compose ``✓P ✗F ◐U`` from the three aggregate counts, each glyph
            carrying its ``_GLYPH_STYLE`` verdict colour, followed on a SECOND
            LINE by a proportional bar of the PASS rate.

            **The line break is intentional, not overflow** — see
            ``_CHECK_STRIP_BAR_CELLS`` for the C-29 measurement that forces it.
            In one sentence: the strip's real content budget at 120x30 is 14
            cells, the tightest one-line counts consume all 14 at 3 digits, and
            the previous one-line form wrapped MID-TOKEN at 2 digits — reading
            a count as a bar label. Two deliberate lines cost h=2, which is
            exactly what the wrapped form already painted.

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
              LLR-042.7); this bar means "this fraction passed". MEASURED: the
              floor is gated on ``clamped > 0.0`` (``insight_style.py:214``),
              so it does NOT affect a 0-pass run — both settings render an
              empty bar there. What it changes is a small-but-nonzero rate: 1
              passed of 20 is ``round(0.05 * 8) == 0`` cells unfloored and 1
              floored.
            - ⚠ **The reason is REDUNDANCY, not asymmetry** (Inc-5, correcting
              this docstring's own third-time-repeated claim). The tempting
              justification — "overstating passes is the harm, and the floor
              only overstates" — is FALSE, and falsifying it needs no new
              measurement: ``round()`` overstates passes at the TOP end too,
              floored or not. **19 of 20 → ``round(0.95 * 8) == 8`` — a FULL
              bar, pixel-identical to 20 of 20.** A bar that paints "all
              passed" over a real failure is the same harm, at the end where
              the floor is not even involved; there is no asymmetry to appeal
              to. The honest reason ``floor=False`` is right is that the
              AUTHORITATIVE counts sit on the line above, so +-1 cell of
              rounding either way costs nothing — the bar is a shape cue, not
              the datum. The default is therefore the correct default because
              it is the default, and nothing here needs an override.

        Dependencies:
            Uses:
                - ``_GLYPH_STYLE`` / ``_CHECK_STRIP_BAR_CELLS`` ;
                  ``insight_style.microbar`` / ``GREEN`` / ``VALUE``
            Used by:
                - :meth:`refresh_check_results`

        Example:
            >>> panel = PatchEditorPanel.__new__(PatchEditorPanel)
            >>> panel._check_strip_text(
            ...     {"passed": 2, "failed": 1, "uncheckable": 1}
            ... ).plain
            '✓2 ✗1 ◐1\\n████░░░░'
        """
        counts = aggregates or {}
        passed = int(counts.get("passed", 0))
        failed = int(counts.get("failed", 0))
        uncheckable = int(counts.get("uncheckable", 0))
        total = passed + failed + uncheckable

        text = Text()
        for index, (glyph, count) in enumerate(
            (("✓", passed), ("✗", failed), ("◐", uncheckable))
        ):
            if index:
                text.append(" ", style=VALUE)
            text.append(glyph, style=self._GLYPH_STYLE[glyph])
            text.append(str(count), style=VALUE)
        # Line 2 — see `_CHECK_STRIP_BAR_CELLS`: the bar cannot share line 1 at
        # the measured 14-cell budget, so it gets its own line rather than
        # wrapping into one mid-token.
        text.append("\n", style=VALUE)
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
        # batch-97 LLR-148.9: a cleared run (the undo/redo reset passes "")
        # shows the Checks tab's one no-run line, never a blank region.
        self.query_one("#patch_checks_status", Label).update(
            status_line or self.CHECKS_NO_RUN_TEXT
        )
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


#: batch-97 (LLR-145.6 / LLR-144.5): the JSON tab shows at most this many lines
#: of a serialised document, then one note line naming the full count.
JSON_TAB_LINE_CAP = 5000

#: batch-97 (LLR-148.7, D6 / D7): the Check Editor's closed glyph vocabulary —
#: glyph -> its one meaning. ``✓`` marks an included row in the ledger's mark
#: column; ``◆`` / ``▪`` head the REPORT FIELDS lines. ``#check_legend`` is
#: generated from this mapping, so the legend cannot name a glyph the panel
#: does not paint. ``◆`` replaced ``☑``, which Windows Terminal paints two
#: cells wide (LED-2026-10-19-batch-97.12).
CHECK_GLYPHS: Mapping[str, str] = {
    "✓": "included",
    "◆": "parameter field",
    "▪": "memory-row field",
}


def cap_json_lines(text: str, cap: int = JSON_TAB_LINE_CAP) -> str:
    """Cap a JSON tab's text at ``cap`` lines plus one note line (LLR-144.5).

    Example:
        >>> cap_json_lines("a\\nb\\nc", cap=2)
        'a\\nb\\nshowing 2 of 3 lines'
    """
    lines = text.split("\n")
    if len(lines) <= cap:
        return text
    return "\n".join(lines[:cap] + [f"showing {cap} of {len(lines)} lines"])


#: batch-97 (LLR-148.7, D7): the Patch Editor's closed glyph vocabulary —
#: glyph -> its one meaning. The four check-run verdicts lead each ledger
#: row's Kind cell (``_GLYPH_STYLE``); ``--`` is the strip's unmapped byte
#: (``CARD_UNMAPPED_TOKEN``). ``#patch_legend`` is generated from it.
PATCH_GLYPHS: Mapping[str, str] = {
    "✓": "check passed",
    "✗": "check failed",
    "◐": "uncheckable",
    "·": "not checked",
    CARD_UNMAPPED_TOKEN: "byte not in the image",
}


@dataclass(frozen=True)
class PatchDocumentView:
    """The Patch Editor document as plain data (batch-97 D2, I-2/I-3).

    Built by ``S19TuiApp._patch_document_view`` and pushed through
    ``PatchEditorPanel.refresh_entries(…, document=)``, so the panel keeps
    importing nothing from the service layer (C-7).

    Attributes:
        name: The document file's name, or ``None`` for a draft.
        kind: ``change`` or ``check``.
        json_text: The whole serialised document, uncapped (the panel caps it
            when it paints, ``cap_json_lines``).
        entry_count: The document's entry count.
    """

    name: Optional[str]
    kind: str
    json_text: str
    entry_count: int


def _json_clock() -> str:
    """The time a JSON view repaint is stamped with (D4; the tests' seam)."""
    return datetime.now().strftime("%H:%M:%S")


def json_stamp_text(n: Optional[int], hhmmss: Optional[str], dirty: bool) -> str:
    """The JSON view's stamp (LLR-144.6, D4).

    Example:
        >>> json_stamp_text(6, "10:20:30", False)
        '6 entries · 10:20:30 · saved'
        >>> json_stamp_text(None, None, True)
        'no document yet · unsaved changes'
    """
    if n is None:
        return "no document yet" + (" · unsaved changes" if dirty else "")
    noun = "entry" if n == 1 else "entries"
    return f"{n} {noun} · {hhmmss} · {'unsaved changes' if dirty else 'saved'}"


class PatchLayout(NamedTuple):
    """The Patch Editor widths Python derives (D21); CSS sizes everything else."""

    kind: int
    address: int
    value: int
    status: int
    linkage: int
    strip_bytes: int
    ribbon: int


def patch_layout(
    ledger_w: int, inspector_w: int, status_longest: int = 0, ribbon_w: int = 110
) -> PatchLayout:
    """Derive the Patch Editor's painted widths from its measured content widths.

    Summary:
        D21 / D5 (f). ``ledger_w`` is the PATCH SCRIPT frame's content width
        (the table fills it; its 1-cell vertical scrollbar gutter is always
        reserved and every column pays 2 cells of padding). Kind (glyph +
        ``string``) is 8, Address 10 (``0x`` + 8 digits, never clipped),
        Linkage 7 (its header) and Status the longest status text, between 7
        and 20; Value / bytes takes the rest (never below 12).
        ``inspector_w`` is ``#patch_inspector``'s content width: the strip's
        bytes per row is the largest of :data:`STRIP_ROW_BYTES` whose line
        (``3·k + 8``) fits the card (``inspector_w − 3``: the pane's scrollbar
        gutter and the card's padding). ``ribbon_w`` is the identity ribbon's
        content width (the file name keeps its tail inside it).

    Example:
        >>> tuple(patch_layout(65, 41, 6))
        (8, 10, 22, 7, 7, 8, 110)
        >>> patch_layout(115, 75, 6).strip_bytes
        16
    """
    status = max(7, min(status_longest, 20))
    usable = ledger_w - 1 - 2 * 5
    value = max(12, usable - 8 - 10 - 7 - status)
    fitting = [k for k in STRIP_ROW_BYTES if 3 * k + 8 <= inspector_w - 3]
    strip = max(fitting) if fitting else STRIP_ROW_BYTES[0]
    return PatchLayout(8, 10, value, status, 7, strip, max(8, ribbon_w))


def _tail_cells(text: str, cap: int) -> str:
    """The longest tail of ``text`` that fits in ``cap`` terminal cells."""
    used = 0
    for index in range(len(text) - 1, -1, -1):
        used += cell_len(text[index])
        if used > cap:
            return text[index + 1:]
    return text


def clip_param(name: str, width: int) -> str:
    """Clip an A2L parameter name to ``width`` cells, keeping what tells it apart.

    LLR-145.3: a name that fits is painted whole; a longer one keeps its first
    dot-separated segment, one ``…`` and the name's tail filling the column
    (A2L names share long prefixes and differ at the end, P-38). A name with
    no dot keeps a third of the width as its head. Widths are terminal cells
    (``cell_len``), so a double-width name never paints past the column; a
    wide character that would straddle the edge is dropped, leaving the clip
    one cell short.

    Example:
        >>> clip_param("ASAM.M.SCALAR.UBYTE.TAB_VERB_NO_DEFAULT_VALUE", 24)
        'ASAM…RB_NO_DEFAULT_VALUE'
        >>> clip_param("UNKNOWN_PARAMETER_NAME_TAIL", 12)
        'UNKN…ME_TAIL'
    """
    if cell_len(name) <= width:
        return name
    first = name.split(".")[0]
    if cell_len(first) + 2 > width:
        first = set_cell_size(first, max(1, width // 3)).rstrip()
    return first + "…" + _tail_cells(name, width - cell_len(first) - 1)


def clip_tail(text: str, width: int) -> str:
    """Keep the tail of ``text`` behind one ``…`` when it exceeds ``width`` cells."""
    if cell_len(text) <= width:
        return text
    return "…" + _tail_cells(text, width - 1)


def _clip_fmt_unit(fmt_unit: str, width: int) -> str:
    """Clip a ``u<bits> <unit>`` cell: the unit goes first, the width stays.

    When even the ``u<bits>`` token fills the column, the token is painted
    alone (no room for a ``…``); the full-name line shows the whole text.
    """
    text = fmt_unit.rstrip()
    if cell_len(text) <= width:
        return text
    token = text.split(" ")[0]
    if cell_len(token) >= width:
        return set_cell_size(token, width)
    return _clip_to_cells(text, width)


def _count(n: int, noun: str) -> str:
    """``1 field`` / ``2 fields`` — a count with its noun in number (ux-reviewer L3)."""
    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"


class CheckLayout(NamedTuple):
    """The Check Editor widths Python derives (D21); CSS sizes everything else."""

    param: int
    fmt: int
    fmt_label: str
    fields_name: int
    mem_label: int
    full_name: int


def check_layout(table_w: int, card_w: int, fmt_longest: int) -> CheckLayout:
    """Derive the Check Editor's painted widths from its measured content widths.

    Summary:
        D21 / PC-5. ``table_w`` is ``#check_param_table``'s content width, its
        1-cell vertical scrollbar gutter always reserved; the fixed cells are
        the mark (1 + 2 padding), Address (10 + 2) and the two remaining
        paddings (19 in all). ``Fmt · Unit`` is sized first — the longest unit
        text, capped at 16, never below ``u128``'s 4 cells and never eating the
        Parameter floor of 42 — and Parameter takes the rest. ``card_w`` is
        ``#check_right_column``'s content width: the REPORT FIELDS name field
        is ``card_w − 14`` (mark 2, address 11, the pane's scrollbar gutter 1)
        and the memory table's Label column ``card_w − 21``. The full-name line
        under the ledger is as wide as the table less its 1-cell paddings
        (``table_w − 2``). Below the range (LLR-149.6) the widths shrink to
        their floors and the table scrolls.

    Example:
        >>> tuple(check_layout(68, 38, 11))
        (42, 6, 'Fmt', 24, 17, 66)
        >>> tuple(check_layout(120, 70, 11))
        (89, 11, 'Fmt · Unit', 56, 49, 118)
    """
    usable = table_w - 1
    fmt = max(4, min(fmt_longest, 16, usable - 19 - 42))
    param = max(8, usable - 19 - fmt)
    label = "Fmt · Unit" if fmt >= 10 else "Fmt"
    return CheckLayout(
        param, fmt, label, max(8, card_w - 14), max(4, card_w - 21), max(8, table_w - 2)
    )


class TabChip(Button):
    """A one-row tab chip: ``enter`` (Button's own) and ``space`` press it (D16)."""

    BINDINGS = [Binding("space", "press", "Press", show=False)]


class IncludeTable(DataTable):
    """The Check Editor's parameter ledger: ``space`` or ``enter`` toggles the
    highlighted row's inclusion (LLR-145.8, D16; ``enter`` replaces DataTable's
    row-select, which the ledger never used). The description ``Include`` is
    the key bar's label (D27); ``show=False`` keeps the shipped Footer
    unchanged until Inc-8 replaces it."""

    BINDINGS = [
        Binding("space", "toggle_include", "Include", show=False),
        Binding("enter", "toggle_include", "Include", show=False),
    ]

    class IncludeToggled(Message):
        """``space`` asked to toggle the highlighted row's inclusion."""

    def action_toggle_include(self) -> None:
        self.post_message(self.IncludeToggled())


class CheckEditorPanel(ScrollableContainer):
    """The Check Editor rail screen — ledger + REPORT FIELDS card (batch-97 ce_A).

    Summary:
        The check twin of the Patch Editor: a collector for A2L parameters
        and memory locations the operator wants in the A2B diff report. The
        batch-97 composition (HLR-145, operator verdict ce_A): the A2L
        parameter ledger fills the left column at full height (mark ·
        Parameter · Address · Fmt · Unit, the Address never clipped, names
        clipped to their discriminating tail), with the highlighted row's full
        name under it; the right column is the REPORT FIELDS card — Fields /
        JSON / Addendum tab chips over one ``ContentSwitcher`` (Fields: the
        included fields one per line, the memory-row table and its labelled
        inputs, the validate verdicts; JSON: the spec document those fields
        produce; Addendum: what the A2B diff report gains). Under the two
        columns: the spec row, one docked action row and the glyph legend.
        The product is ONE artifact: a ``.chk.json`` check spec (v2 grammar,
        ``kind="check"``).

        The NO-APPLY doctrine is carried three ways: the docked row shows a
        struck APPLY ghost (a STATIC — never an actionable control), the JSON
        tab carries ``"apply": false``, and the hint reads ``apply: n/a —
        check spec``. The panel exposes write and validate actions only;
        Write is its one filled element (LLR-145.9).

        Widths: CSS splits the columns (left ``1fr``, card ``38%`` / min 42);
        :func:`check_layout` derives what CSS cannot — the DataTable column
        widths, the Fields name field, the memory Label column — and
        :meth:`_apply_layout` repaints the width-dependent cells through the
        public ``update_cell`` path (D21, PC-8) on mount, resize and show.

        The panel stays **presentational** (C-7): controls post
        :class:`ActionRequested` messages that ``app.py`` routes.

    Example:
        >>> panel = CheckEditorPanel()
        >>> panel.id
        'check_editor_panel'
    """

    _APPLY_GHOST_TEXT = "APPLY — not available"
    _APPLY_HINT = "apply: n/a — check spec"
    _PREVIEW_CAP = 6
    _STATUS_HINT = "Validate compares fields to the image"
    _EMPTY_LEDGER = "No A2L parameters — load an A2L (^L) to list them."
    _EMPTY_FIELDS = "No fields included yet."

    #: The memory-size -> fmt label vocabulary (closed author set).
    _FMT_LABELS = {1: "u8", 2: "u16", 4: "u32", 8: "u64"}

    #: (tab chip id, label, pane id) — the REPORT FIELDS card's three tabs.
    _CARD_TABS = (
        ("check_tab_fields", "Fields", "check_pane_fields"),
        ("check_tab_json", "JSON", "check_pane_json"),
        ("check_tab_addendum", "Addendum", "check_pane_addendum"),
    )

    class ActionRequested(Message):
        """A Check Editor write/validate control was triggered (LLR-009).

        Args:
            action (str): ``"write_doc"`` or ``"validate_doc"``.
            file_name_text (str): The ``.chk.json`` name input's text.
            items (tuple): The collected field dicts, in collector order.

        Dependencies:
            Used by:
                - ``S19TuiApp.on_check_editor_panel_action_requested``
        """

        def __init__(
            self,
            action: str,
            file_name_text: str = "",
            items: tuple = (),
        ) -> None:
            super().__init__()
            self.action = action
            self.file_name_text = file_name_text
            self.items = items

    class SpecFileSelected(Message):
        """The operator picked a spec/patch file from the dropdown (LLR-010.1).

        Args:
            filename (str): The chosen file's bare component.

        Dependencies:
            Used by:
                - ``S19TuiApp.on_check_editor_panel_spec_file_selected``
        """

        def __init__(self, filename: str) -> None:
            super().__init__()
            self.filename = filename

    def __init__(self) -> None:
        super().__init__(id="check_editor_panel")
        #: The picked A2L parameter rows: {name: (address, size, fmt_unit)}.
        self._param_rows: dict = {}
        #: The picker rows currently mounted (filter-aware), in table order.
        self._visible_params: list = []
        #: The picked parameter names in inclusion order (the ✓ set).
        self._picked_params: list = []
        #: The declared memory rows: list of (address, label, size).
        self._memory_rows: list = []
        #: The last derived widths; ``None`` until the panel is measured.
        self._layout: Optional[CheckLayout] = None

    # ------------------------------------------------------------------
    # Population seams (app.py is the only caller — the US-026 split)
    # ------------------------------------------------------------------

    def set_spec_files(self, names: Sequence[str]) -> None:
        """Populate the spec dropdown, suffix-distinguished (LLR-010.1).

        Every option label is a FILENAME read off disk, so it reaches the
        Select as a literal ``Text`` (C-17); the VALUE stays the bare ``str``.
        """
        options = []
        for name in names:
            label = Text(safe_text(str(name)).plain)
            if is_check_spec_name(name):
                label.append(" CHECK", style=GREEN)
            else:
                label.append(" PATCH", style=CYAN)
            options.append((label, name))
        self.query_one("#check_spec_file_select", Select).set_options(options)

    def set_a2l_parameters(self, rows: Sequence[dict]) -> None:
        """Populate the A2L parameter ledger (LLR-001.1, LLR-145.1).

        Replaces the ledger's rows with the loaded A2L's parameters carrying an
        integer address, clears the picks, and re-derives the widths (the
        longest ``Fmt · Unit`` text is an input of :func:`check_layout`).
        Every cell is a literal ``Text`` (C-17): A2L names are file-derived.
        """
        self._param_rows = {}
        self._picked_params = []
        for row in rows:
            name = str(row.get("name") or "?")
            address = row.get("address")
            address = int(address) if isinstance(address, int) else None
            size = int(row.get("byte_size") or 1)
            unit = str(row.get("compu_method_unit") or "")
            fmt_unit = f"u{size * 8}" + (f" {unit}" if unit else "")
            self._param_rows[name] = (address, size, fmt_unit)
        self._visible_params = list(self._param_rows)
        self._rebuild_ledger()
        self._layout = None
        self.call_after_refresh(self._apply_layout)
        self._refresh_preview()

    def load_spec(self, items: Sequence[dict], source_name: str) -> None:
        """Populate the collector from a loaded check spec (LLR-009.1 read arm).

        Every declared address becomes a memory row (the v2 wire grammar
        carries no names). ``app.py`` read the document; this only mirrors it.
        """
        self._picked_params = []
        self._memory_rows = []
        for item in items:
            address = item.get("address")
            if address is None:
                continue
            size = int(item.get("size") or 1)
            self._memory_rows.append((int(address), self._default_label(int(address)), size))
        self._rebuild_memory_table()
        self._rebuild_ledger()
        base = str(source_name)
        if is_check_spec_name(base):
            base = base[: -len(".chk.json")]
        elif base.lower().endswith(".json"):
            base = base[:-5]
        self.query_one("#check_file_name_input", Input).value = (
            f"{base}.chk.json"
        )
        self._refresh_preview()

    # ------------------------------------------------------------------
    # Collector internals
    # ------------------------------------------------------------------

    def _fmt_label(self, size: int) -> str:
        """Map a declared byte size to the closed fmt vocabulary."""
        return self._FMT_LABELS.get(size, f"{size}B")

    @staticmethod
    def _default_label(address: int) -> str:
        """The stored name of a memory row typed with no label (kept in the spec)."""
        return f"field @ 0x{address:08X}"

    def _widths(self) -> CheckLayout:
        """The current layout, or the 118-column reading before the first measure."""
        return self._layout or check_layout(68, 38, self._fmt_longest())

    def _fmt_longest(self) -> int:
        return max((cell_len(v[2].rstrip()) for v in self._param_rows.values()), default=0)

    def _ledger_cells(self, name: str, layout: CheckLayout) -> tuple:
        address, _size, fmt_unit = self._param_rows[name]
        picked = name in self._picked_params
        plain = safe_text(name).plain
        return (
            Text("✓", style=GREEN) if picked else Text(" "),
            safe_text(clip_param(plain, layout.param), VALUE),
            safe_text(f"0x{address:08X}" if address is not None else "-", CYAN),
            safe_text(_clip_fmt_unit(fmt_unit, layout.fmt)),
        )

    def _rebuild_ledger(self) -> None:
        """Re-add the visible ledger rows (rows only — never the columns)."""
        table = self.query_one("#check_param_table", DataTable)
        layout = self._widths()
        table.clear()
        for name in self._visible_params:
            table.add_row(*self._ledger_cells(name, layout), key=name)
        self._refresh_full_name()

    def _rebuild_memory_table(self) -> None:
        table = self.query_one("#check_mem_table", DataTable)
        layout = self._widths()
        table.clear()
        for address, label, size in self._memory_rows:
            # A row typed with no label shows ``—``: its stored name only
            # repeats the address of the cell beside it (ux-reviewer M1).
            shown = (
                Text("—", style=DGRAY)
                if label == self._default_label(address)
                else safe_text(_clip_to_cells(safe_text(label).plain, layout.mem_label), VALUE)
            )
            table.add_row(
                safe_text(f"0x{address:08X}", CYAN),
                shown,
                safe_text(self._fmt_label(size)),
            )

    def _collected_items(self) -> tuple:
        """Gather the collector state into the message items tuple.

        One ``{"source", "name", "address", "size"}`` dict per declared
        field, in collector order: the included parameters first (inclusion
        order), then the memory rows (table order).
        """
        items = []
        for name in self._picked_params:
            address, size, _fmt = self._param_rows.get(name, (None, 1, ""))
            items.append(
                {"source": "param", "name": name, "address": address, "size": size}
            )
        for address, label, size in self._memory_rows:
            items.append(
                {"source": "memory", "name": label, "address": address, "size": size}
            )
        return tuple(items)

    def _preview_text(self) -> Text:
        """The JSON tab: the spec document the collected fields produce.

        A JSON document (``json.dumps``, ASCII-escaped, so no control byte and
        no markup reaches the view) carrying the v2 envelope with
        ``"kind": "check"`` and the explicit ``"apply": false`` marker, one
        entry per field (address, size, name), capped at
        :data:`JSON_TAB_LINE_CAP` lines. Built as a plain ``Text`` (C-17).
        """
        document = {
            "format": "s19app-changeset",
            "version": "2.0",
            "kind": "check",
            "apply": False,
            "entries": [
                {
                    "address": (
                        f"0x{item['address']:08X}"
                        if item["address"] is not None
                        else None
                    ),
                    "size": item["size"],
                    "name": str(item["name"]),
                }
                for item in self._collected_items()
            ],
        }
        return Text(cap_json_lines(json.dumps(document, indent=2)), style=LABEL)

    def _addendum_preview_text(self) -> Text:
        """Build the addendum preview (read-only report-gain frame).

        Renders what the A2B diff report gains from this spec: the ``## Checks``
        heading, the declared-field count, and the no-apply statement. Field
        names are appended literally (C-17).
        """
        items = self._collected_items()
        text = Text("## Checks", style=GREEN)
        text.append("\n", style=LABEL)
        text.append(
            f"· {len(items)} fields → A2B diff report · ", style=LABEL
        )
        text.append(self._APPLY_HINT, style=DGRAY)
        for item in items[: self._PREVIEW_CAP]:
            address = item["address"]
            addr = f"0x{address:08X}" if address is not None else "unresolved"
            text.append("\n")
            text.append(f"· {addr} ", style=CYAN)
            text.append(safe_text(str(item["name"]), VALUE))
        if len(items) > self._PREVIEW_CAP:
            text.append(f"  … {len(items) - self._PREVIEW_CAP} more", style=DGRAY)
        return text

    def _fields_lines_text(self) -> Text:
        """The Fields tab: a head line, then one line per included field.

        ``◆ <address> <name>`` per included parameter and ``▪ <address> <fmt>
        <label>`` per memory row, in inclusion order (LLR-145.6). A parameter
        name wider than the name field keeps its tail behind one ``…``
        (LLR-145.3); a memory label keeps its head (labels, LLR-149.4), and a
        row typed with no label reads ``memory row`` instead of repeating its
        address (ux-reviewer M1). Built with ``Text.append`` — never a markup
        string (C-17).
        """
        items = self._collected_items()
        params = sum(1 for item in items if item["source"] == "param")
        memory = len(items) - params
        text = Text(
            f"{_count(len(items), 'field')}: {_count(params, 'param')} · "
            f"{_count(memory, 'memory row')}",
            style=f"bold {GREEN}",
        )
        if not items:
            text.append("\n")
            text.append(self._EMPTY_FIELDS, style=DGRAY)
            return text
        width = self._widths().fields_name
        for item in items:
            param = item["source"] == "param"
            address = item["address"]
            text.append("\n")
            text.append("◆ " if param else "▪ ", style=GREEN if param else CYAN)
            text.append(
                f"0x{address:08X} " if address is not None else "unresolved ",
                style=CYAN,
            )
            name = safe_text(str(item["name"])).plain
            if param:
                text.append(safe_text(clip_tail(name, width), VALUE))
                continue
            fmt = self._fmt_label(item["size"])
            text.append(f"{fmt} ", style=DGRAY)
            if item["name"] == self._default_label(address):
                text.append("memory row", style=DGRAY)
            else:
                label_w = max(4, width - cell_len(fmt) - 1)
                text.append(safe_text(_clip_to_cells(name, label_w), VALUE))
        return text

    def _refresh_preview(self) -> None:
        """Repaint the Fields lines, the JSON and Addendum tabs and the count."""
        if not self.is_mounted:
            return
        items = self._collected_items()
        self.query_one("#check_fields_lines", Static).update(self._fields_lines_text())
        self.query_one("#check_preview", Static).update(self._preview_text())
        self.query_one("#check_addendum_preview", Static).update(
            self._addendum_preview_text()
        )
        self.query_one("#check_fields_count", Static).update(
            Text(f"{_count(len(items), 'field')} → report", style=GREEN)
        )
        self.query_one("#check_left_column").border_subtitle = (
            f"{len(self._param_rows)} params · {len(self._picked_params)} picked"
        )

    def _refresh_full_name(self) -> None:
        """Paint the highlighted row's address, ``Fmt · Unit`` and name under
        the ledger (LLR-145.3; code-reviewer F1, ux-reviewer L2).

        The address and the full ``Fmt · Unit`` come first and are never
        clipped; the name takes the cells left of ``layout.full_name`` and,
        when wider, is clipped by the ledger's rule (first segment, one ``…``,
        the tail) — so the line ends with the part that tells twins apart. The
        text depends on the derived width, so ``_apply_layout`` repaints it
        (D21 (4), PC-19).
        """
        line = self.query_one("#check_full_name_line", Static)
        table = self.query_one("#check_param_table", DataTable)
        if not self._visible_params:
            empty = self._EMPTY_LEDGER if not self._param_rows else "No parameter matches the filter."
            line.update(Text(empty, style=DGRAY))
            return
        row = table.cursor_row
        if not 0 <= row < len(self._visible_params):
            row = 0
        name = self._visible_params[row]
        address, _size, fmt_unit = self._param_rows[name]
        head = f"0x{address:08X}" if address is not None else "-"
        fmt_unit = fmt_unit.rstrip()
        text = Text(head, style=CYAN)
        text.append(f"  {fmt_unit}  ", style=DGRAY)
        room = max(8, self._widths().full_name - cell_len(text.plain))
        text.append(safe_text(clip_param(safe_text(name).plain, room), VALUE))
        line.update(text)

    # ------------------------------------------------------------------
    # Width derivation (D21: mount, resize, show)
    # ------------------------------------------------------------------

    def _apply_layout(self) -> None:
        """Re-derive the widths and repaint every width-dependent text.

        Reads the measured content widths of ``#check_param_table`` and
        ``#check_right_column`` (never the terminal width). An unchanged
        layout repaints nothing. Otherwise it sets each column's width and
        rewrites the Parameter and ``Fmt · Unit`` cells with ``update_cell``,
        the first call with ``update_width=True`` (the public repaint path
        the PC-8 spike measured); it never adds a column. The Fields lines
        and the memory Label cells are rebuilt by their own painters.
        """
        table = self.query_one("#check_param_table", DataTable)
        card = self.query_one("#check_right_column")
        if table.content_region.width == 0 or card.content_region.width == 0:
            return
        layout = check_layout(
            table.content_region.width, card.content_region.width, self._fmt_longest()
        )
        if layout == self._layout:
            return
        self._layout = layout
        columns = table.ordered_columns
        for column, width in zip(columns, (1, layout.param, 10, layout.fmt)):
            column.width = width
            column.auto_width = False
        columns[3].label = Text(layout.fmt_label)
        keys = [column.key for column in columns]
        if not self._visible_params:
            # D21 (5): with no rows the pass is ``clear()`` (rows only) — it
            # drops the table's cached render so the new column widths repaint
            # the header; there is no cell for ``update_cell`` to go through.
            table.clear()
        for index, name in enumerate(self._visible_params):
            cells = self._ledger_cells(name, layout)
            table.update_cell(name, keys[1], cells[1], update_width=(index == 0))
            table.update_cell(name, keys[3], cells[3])
        mem = self.query_one("#check_mem_table", DataTable)
        for column, width in zip(mem.ordered_columns, (10, layout.mem_label, 3)):
            column.width = width
            column.auto_width = False
        self._rebuild_memory_table()
        self._refresh_full_name()
        self._refresh_preview()

    def on_resize(self, event: events.Resize) -> None:
        self.call_after_refresh(self._apply_layout)

    def on_show(self, event: events.Show) -> None:
        self.call_after_refresh(self._apply_layout)

    # ------------------------------------------------------------------
    # Composition
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        """Lay out the ledger + REPORT FIELDS card (HLR-145, the ce_A tree).

        Every row below the two columns is one terminal row; the ledger is
        the panel's growing region (design §3, Check Editor tree). The shipped
        ids are all kept (LLR-145.1); ``#check_preview_toggle_button`` stays
        mounted and hidden, its function carried by the Addendum tab chip.
        """
        with Horizontal(id="check_columns"):
            with Vertical(id="check_left_column") as left:
                left.border_title = "A2L PARAMETERS"
                with Horizontal(classes="ce-row"):
                    yield Label("Filter", classes="ce-label")
                    yield OsClipboardInput(
                        placeholder="filter parameters",
                        id="check_param_filter",
                        compact=True,
                    )
                yield IncludeTable(
                    id="check_param_table",
                    zebra_stripes=True,
                    cursor_type="row",
                    classes="nowrap-ledger",
                )
                yield Static("", id="check_full_name_line", classes="nowrap-heading")
                with Horizontal(
                    id="check_param_controls",
                    classes="patch-docked-row patch-chip-entry",
                ):
                    yield Button(
                        "Include parameter",
                        id="check_param_include_button",
                        classes="patch-chip",
                    )
                    yield Static(
                        "space also toggles ✓ on the highlighted row",
                        classes="ce-hint",
                    )
            with Vertical(id="check_right_column") as right:
                right.border_title = "REPORT FIELDS"
                with Horizontal(id="check_card_tabs"):
                    for chip_id, label, _pane in self._CARD_TABS:
                        yield TabChip(
                            label,
                            id=chip_id,
                            classes="tab-chip chip-selected"
                            if chip_id == "check_tab_fields"
                            else "tab-chip",
                        )
                with ContentSwitcher(initial="check_pane_fields", id="check_card_switcher"):
                    with VerticalScroll(id="check_pane_fields") as fields_pane:
                        fields_pane.can_focus = False
                        yield Static(
                            "", id="check_fields_lines", classes="nowrap-fields"
                        )
                        yield Static("MEMORY LOCATIONS", classes="ce-title")
                        yield DataTable(
                            id="check_mem_table",
                            zebra_stripes=True,
                            cursor_type="row",
                        )
                        # One row per field, labels in one fixed column
                        # (operator decision at the Inc-3 gate, LED-…97.14).
                        with Vertical(id="check_mem_inputs", classes="patch-docked-row"):
                            with Horizontal(classes="ce-row"):
                                yield Label("Address", classes="ce-label")
                                yield OsClipboardInput(
                                    placeholder="0x100",
                                    id="check_mem_address_input",
                                    compact=True,
                                )
                            with Horizontal(classes="ce-row"):
                                yield Label("Label", classes="ce-label")
                                yield OsClipboardInput(
                                    placeholder="label",
                                    id="check_mem_label_input",
                                    compact=True,
                                )
                            with Horizontal(classes="ce-row"):
                                yield Label("Size (bytes)", classes="ce-label")
                                yield OsClipboardInput(
                                    placeholder="1",
                                    id="check_mem_size_input",
                                    compact=True,
                                )
                        with Horizontal(
                            id="check_mem_controls",
                            classes="patch-docked-row patch-chip-entry",
                        ):
                            yield Button(
                                "Add row",
                                id="check_mem_add_button",
                                classes="patch-chip",
                            )
                            yield Button(
                                "Remove row",
                                id="check_mem_remove_button",
                                classes="patch-chip",
                            )
                        yield Label(
                            self._STATUS_HINT,
                            id="check_status",
                            classes="patch-field-label",
                            markup=False,
                        )
                        yield Container(id="check_results")
                    with ScrollableContainer(id="check_pane_json"):
                        yield Static("", id="check_preview", markup=False)
                    with ScrollableContainer(id="check_pane_addendum"):
                        yield Static("", id="check_addendum_preview", markup=False)
        with Horizontal(id="check_spec_file_row", classes="patch-docked-row"):
            yield Label("Spec", classes="ce-label")
            yield Select(
                [],
                id="check_spec_file_select",
                prompt="Check specs in patches/",
                allow_blank=True,
                compact=True,
            )
            yield Label("Write as", classes="ce-label")
            yield OsClipboardInput(
                placeholder="spec file name",
                id="check_file_name_input",
                compact=True,
            )
        with Horizontal(id="check_dock"):
            with Horizontal(
                id="check_actions_row",
                classes="patch-docked-row patch-chip-apply",
            ):
                yield Button(
                    "Validate", id="check_validate_button", classes="patch-chip"
                )
                yield Button(
                    "Write .chk.json",
                    id="check_write_button",
                    classes="patch-chip fill-accent",
                )
                # The struck-APPLY ghost — a STATIC, not a Button: the
                # no-apply doctrine made visible (C-ux-2).
                yield Static(
                    Text(self._APPLY_GHOST_TEXT, style="strike dim"),
                    id="check_apply_ghost",
                )
            with Horizontal(id="check_actions_row2", classes="patch-docked-row"):
                yield Static("", id="check_fields_count", markup=False)
                toggle = Button(
                    "Addendum preview",
                    id="check_preview_toggle_button",
                    classes="patch-chip",
                )
                toggle.display = False
                yield toggle
            yield Static(
                Text(self._APPLY_HINT, style=DGRAY),
                id="check_apply_hint",
                markup=False,
            )
        yield Static(
            "   ".join(f"{glyph} {meaning}" for glyph, meaning in CHECK_GLYPHS.items()),
            id="check_legend",
            classes="glyph-legend nowrap-legend",
            markup=False,
        )

    def on_mount(self) -> None:
        """Add the two tables' columns once, at the 118-column widths."""
        layout = self._widths()
        table = self.query_one("#check_param_table", DataTable)
        table.add_column("✓", width=1, key="mark")
        table.add_column("Parameter", width=layout.param, key="param")
        table.add_column("Address", width=10, key="address")
        table.add_column(layout.fmt_label, width=layout.fmt, key="fmt")
        mem = self.query_one("#check_mem_table", DataTable)
        mem.add_column("Address", width=10)
        mem.add_column("Label", width=layout.mem_label)
        mem.add_column("Fmt", width=3)
        self.query_one("#check_file_name_input", Input).value = "spec.chk.json"
        self._refresh_full_name()
        self._refresh_preview()
        self.call_after_refresh(self._apply_layout)

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def _show_tab(self, chip_id: str) -> None:
        """Switch the card to ``chip_id``'s pane and mark that chip selected."""
        for tab_id, _label, pane in self._CARD_TABS:
            selected = tab_id == chip_id
            self.query_one(f"#{tab_id}").set_class(selected, "chip-selected")
            if selected:
                self.query_one("#check_card_switcher", ContentSwitcher).current = pane

    def _toggle_highlighted(self) -> None:
        """Include or exclude the highlighted ledger row (button and ``space``)."""
        if not self._visible_params:
            return
        table = self.query_one("#check_param_table", DataTable)
        cursor = table.cursor_row
        if not 0 <= cursor < len(self._visible_params):
            return
        name = self._visible_params[cursor]
        if name in self._picked_params:
            self._picked_params.remove(name)
        else:
            self._picked_params.append(name)
        table.update_cell_at(
            Coordinate(cursor, 0), self._ledger_cells(name, self._widths())[0]
        )
        self._refresh_preview()

    def on_include_table_include_toggled(self, event: IncludeTable.IncludeToggled) -> None:
        event.stop()
        self._toggle_highlighted()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id == "check_param_table":
            self._refresh_full_name()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Translate the collector controls into messages (LLR-001.1/.2)."""
        button_id = event.button.id or ""
        if any(button_id == tab_id for tab_id, _l, _p in self._CARD_TABS):
            event.stop()
            self._show_tab(button_id)
            return
        if button_id == "check_param_include_button":
            event.stop()
            self._toggle_highlighted()
            return
        if button_id == "check_mem_add_button":
            event.stop()
            self._add_memory_row()
            return
        if button_id == "check_mem_remove_button":
            event.stop()
            table = self.query_one("#check_mem_table", DataTable)
            if table.row_count == 0:
                return
            cursor = table.cursor_row
            if not 0 <= cursor < len(self._memory_rows):
                return
            self._memory_rows.pop(cursor)
            self._rebuild_memory_table()
            self._refresh_preview()
            return
        if button_id == "check_preview_toggle_button":
            event.stop()
            self._show_tab("check_tab_addendum")
            return
        actions = {
            "check_write_button": "write_doc",
            "check_validate_button": "validate_doc",
        }
        action = actions.get(button_id)
        if action is not None:
            event.stop()
            self.post_message(
                self.ActionRequested(
                    action=action,
                    file_name_text=self.query_one(
                        "#check_file_name_input", Input
                    ).value,
                    items=self._collected_items(),
                )
            )

    def _add_memory_row(self) -> None:
        """Validate the memory inputs and append one declared memory row."""
        address_text = self.query_one(
            "#check_mem_address_input", Input
        ).value.strip()
        label = self.query_one("#check_mem_label_input", Input).value.strip()
        size_text = self.query_one("#check_mem_size_input", Input).value.strip()
        try:
            address = int(address_text, 16) if address_text.lower().startswith(
                "0x"
            ) else int(address_text, 10)
        except ValueError:
            self.query_one("#check_status", Label).update(
                f"Check Editor: bad memory address {address_text!r}."
            )
            return
        if address < 0:
            self.query_one("#check_status", Label).update(
                "Check Editor: memory address must be non-negative."
            )
            return
        try:
            size = int(size_text, 10)
        except ValueError:
            size = 1
        if size <= 0 or size > 8:
            self.query_one("#check_status", Label).update(
                f"Check Editor: size must be 1..8 bytes, got {size}."
            )
            return
        if not label:
            label = self._default_label(address)
        self._memory_rows.append((address, label, size))
        self._rebuild_memory_table()
        self._refresh_preview()

    def on_input_changed(self, event: Input.Changed) -> None:
        """Filter the parameter ledger as the operator types."""
        if event.input.id != "check_param_filter":
            return
        needle = event.value.strip().lower()
        self._visible_params = [
            name for name in self._param_rows if not needle or needle in name.lower()
        ]
        self._rebuild_ledger()

    def on_select_changed(self, event: Select.Changed) -> None:
        """Forward a spec-file dropdown pick to ``app.py`` (LLR-010.1)."""
        if event.select.id != "check_spec_file_select":
            return
        if event.value is Select.NULL:
            return
        event.stop()
        self.post_message(self.SpecFileSelected(str(event.value)))

    def show_status_line(self, line: str) -> None:
        """Paint one English state line in the REPORT FIELDS card (LLR-148.9).

        Used for a refused Write: the line replaces the verdict rows under the
        memory form, and the card shows its Fields tab.
        """
        self.refresh_check_results([], line)

    def refresh_check_results(
        self,
        rows: Sequence[tuple],
        status_line: str,
    ) -> None:
        """Render the validate verdicts (LLR-009.2) under the memory form, on
        the Fields tab.

        Args:
            rows (Sequence[tuple]): ``(text, css_class)`` per entry verdict.
            status_line (str): The status sentence (one line).
        """
        self._show_tab("check_tab_fields")
        self.query_one("#check_status", Label).update(status_line)
        container = self.query_one("#check_results", Container)
        container.remove_children()
        for text, css_class in rows:
            container.mount(Static(text, classes=css_class, markup=False))


#: HLR-124 / LLR-124.1 — the three width/height regime constants. All three are
#: TERMINAL dimensions, compared against `events.Resize.size`, exactly as the
#: `S19TuiApp._apply_width_regime` precedent does (`app.py:6281`). Only the run
#: LIST width is in content cells, and it is authored in `styles.tcss` as a
#: border-box (22 content = CSS `width: 26`). They are named rather than inline
#: so no acceptance can quote the value instead of the constant (C-39), and they
#: are deliberately NOT the existing `width-narrow` breakpoint, which is read by
#: 11 unrelated rules across workspace, map, patch and rail.
#:
#: `_DIFF_WIDE_MIN` — the first terminal width at which a 22-content-cell run
#: list still leaves an unwrapped 79-cell window beside it, under `L <= C - 89`
#: (measured 138 -> 78 wrap, 139 -> 79 fit).
_DIFF_WIDE_MIN = 139
#: `_DIFF_MIN_W` — the first terminal width at which a FULL-width window fits an
#: unwrapped emitted hex row (measured 93 -> 78 wrap, 94 -> 79 fit).
_DIFF_MIN_W = 94
#: `_DIFF_MIN_H` — the first terminal height at which a window paints at least
#: one **HEX ROW**. **RE-DERIVED at Phase 3 against the real implementation**
#: (spec Sec.8 `A-1`, which flagged the spec's 29 as a `styles.height = 1`
#: simulation).
#:
#: ⚠️ **The spec carries TWO metrics for this axis and they give different
#: answers; this is the normative one.** Sec.2.8 D-1's height axis says "the
#: window has at least one visible CONTENT row" -> 26. **`LLR-125.2`, normative,
#: says "`#diff_hex_a` shall render at least one HEX ROW of content" -> 28.**
#: They differ because `_render_run_windows` writes `"Image A - {header}\n{text}"`,
#: so screen line 0 of each window is the HEADER: a painted content height of 1
#: delivers ZERO bytes. Surfaced rather than averaged (engineering rule 7). At
#: 26-27 the panel would declare the terminal deliverable, hide the notice and
#: show a header and nothing else — strictly WORSE than 25, where the operator is
#: at least told why. That is the silently empty results area HLR-124 exists to
#: abolish, so `LLR-125.2` governs.
#:
#: Measured with the fallback layout forced (so the constant cannot decide its
#: own measurement), the command-bar row hidden (the state `A-1`'s quantity is
#: defined in — "post-US-78-8 + US-78-1") and a run longer than any pane, so the
#: window is never the binding limit. VISIBLE HEX ROWS: 26 -> 0, 27 -> 0,
#: **28 -> 1**, 30 -> 2. Width-independent, confirmed at W = 94, 120 and 138 —
#: the spec's width-independence claim reproduces exactly; only the value moved.
#: The 30 -> 2 row is R-1's accepted 120x30 viewport, to the row.
#:
#: ⚠️ This is the POST-Inc-10 floor, because that is the state the batch ships.
#: As the tree stands at Inc-5 the command-bar row still spends three rows, so
#: between Inc-5 and Inc-10 the heights 28..30 select the fallback regime while
#: painting no hex row. Recorded, not hidden; `TC-B78-54` pins both sides of the
#: floor in the end state the constant is defined for.
#:
#: batch-97 Inc-8 (HLR-150): the two-row key bar takes one more chrome row, so
#: the floor moves up one. Re-measured on the Inc-8 tree: 28 -> 0, **29 -> 1**,
#: 30 -> 1 visible hex rows.
_DIFF_MIN_H = 29


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

    #: HLR-124's regime classes. Exactly one is set at a time; ``runs-open`` is
    #: the fallback regime's overlay latch and rides alongside it.
    _REGIME_WIDE = "diff-wide"
    _REGIME_FALLBACK = "diff-fallback"
    _REGIME_NOTICE = "diff-notice"
    _REGIME_CLASSES = (_REGIME_WIDE, _REGIME_FALLBACK, _REGIME_NOTICE)
    _RUNS_OPEN = "runs-open"

    #: LLR-126.1's affordance text, named so the acceptance asserts the EMITTED
    #: string rather than a re-typed copy of the requirement's wording. It is
    #: deliberately pure ASCII: the note renders `markup=False` into a widget
    #: the snapshot goldens capture, and an arrow glyph would put the predicate
    #: at the mercy of the emitted encoding rather than the text.
    #:
    #: It names how to move the SELECTION, which is what HLR-126 asks for. The
    #: panel's own `f` / `escape` / `[` / `]` are not selection movement — `[`
    #: and `]` page the hex window and `f` toggles the overlay — so they belong
    #: to the help panel's listing, not to this row. `j`/`k`/`n`/`p` are ruled
    #: out by D-4 and are not bound.
    #:
    #: ⚠️ It said `, Enter opens` until the Inc-6/Inc-7 independent review, and
    #: that clause was FALSE THREE TIMES OVER. There is no `diff_range_list`
    #: branch in `S19TuiApp.on_list_view_selected` and no `Selected` handler on
    #: this panel, so `Enter` is a no-op — executed, nothing observable changes.
    #: The spec does not merely omit the capability, it EXCLUDES it: §1.2 Scope
    #: Out, P-43 (*"it would show the wrong bytes… a defect, not a feature"*),
    #: and HLR-126's own rationale (*"what this deliberately does not do: …post
    #: an open-in-hex message on Enter"*, carry C-78-d). And the exclusion
    #: reasoning directly above contradicted itself — it drops `f`/`[`/`]` for
    #: not being selection movement while keeping `Enter`, which is not either.
    #: An affordance that advertises a rejected capability is worse than no
    #: affordance: it sends the operator looking for behaviour the batch decided
    #: not to build.
    _RUN_LIST_AFFORDANCE = "Keys: Up/Down move the selection"

    #: LLR-124.3's overlay + pagination keys. Widget-scoped, never App-level
    #: (D-2 ruled out a new App binding; `AT-B78-32` pins `app.py`'s BINDINGS
    #: block at a zero-line diff). All `show=False`: LLR-126.1 requires the
    #: Footer's `show and enabled` set to be set-EQUAL to its pre-change set of
    #: 14, so a shown chip here would redden `AT-B78-28` at Inc-6.
    #:
    #: None of these four keys is bound at application level (`f`, `escape`,
    #: `[` and `]` are all absent from `S19TuiApp.BINDINGS`; cited by SYMBOL
    #: because the line range this comment used to give was invalidated by an
    #: import added at the top of `app.py` in the same batch), so a press that reaches the
    #: panel cannot shadow an App action. That is HLR-122's anti-shadow clause
    #: applied one container up: these bindings sit on an ANCESTOR of the run
    #: list, so they are in the focus chain whenever `AT-B78-19` runs.
    BINDINGS = [
        Binding("f", "toggle_run_overlay", "Run list", show=False),
        Binding("escape", "close_run_overlay", "Close the run list", show=False),
        Binding("right_square_bracket", "page_window_down", "Window page +", show=False),
        Binding("left_square_bracket", "page_window_up", "Window page -", show=False),
    ]

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

    class CheckFileSelected(Message):
        """The operator picked a check-spec/patch file for the report (LLR-010.1).

        Summary:
            Posted when ``#diff_check_select`` fires ``Select.Changed`` with a
            concrete filename (not the blank sentinel). Carries the bare name
            only — ``app.py`` re-resolves it under the patches folder, reads it
            through the shipped ``read_change_document`` seam and, when it is a
            valid ``kind="check"`` document, stashes it as the check spec the
            next Report generation appends (LLR-010.2). A blank selection
            (``Select.NULL``) posts nothing. A patch file (``.json`` without
            the check suffix) is listed — suffix-distinguished — but loads as
            an ordinary change document, so the app refuses it for the check
            addendum with a status line naming the kind gate.

        Args:
            filename (str): The chosen file's bare component.

        Dependencies:
            Used by:
                - ``S19TuiApp.on_ab_diff_panel_check_file_selected``
        """

        def __init__(self, filename: str) -> None:
            super().__init__()
            self.filename = filename

    def __init__(self, check_files: Sequence[str] = ()) -> None:
        super().__init__(id="ab_diff_panel")
        #: The compose-time patches-folder listing (LLR-010.1): non-empty →
        #: :meth:`compose` mounts ``#diff_check_row``. The listing the OPERATOR
        #: sees is still the live one ``set_check_files`` installs on every
        #: diff-screen activation — this copy only decides whether the row
        #: exists at all (the P4 RC-2 geometry fix: an unconditionally mounted
        #: row reserved its auto height in EVERY session, including the many
        #: sessions whose patches folder holds no check spec, and ate the hex
        #: panes' rows at the B78 sizes).
        self._compose_check_files: Tuple[str, ...] = tuple(check_files)
        #: The most recent comparison runs (display-capped) the operator can
        #: select between; rendered into ``#diff_range_list``.
        self._runs: List[Tuple[int, int, str]] = []
        #: The two memory maps of the most recent comparison, for the per-run
        #: hex windows. Display-only — never the source of any classification.
        self._mem_map_a: dict = {}
        self._mem_map_b: dict = {}
        #: Whether a comparison result has been rendered (the report guard).
        self._has_result: bool = False
        #: The run the hex windows are currently showing, so the pagination
        #: actions can re-render it without going back through the list.
        self._selected_run: int = 0
        #: HLR-124's paginable viewport (LLR-124.3): which page of the selected
        #: run's window is on screen. Reset to 0 by every selection change and
        #: by every comparison, so the un-paged render is always what a fresh
        #: selection shows.
        self._window_page: int = 0
        #: What held focus when the run-list overlay was opened, so dismissing
        #: it does not strand the operator with no focus at all.
        self._focus_before_overlay: Optional[Widget] = None

    def compose(self) -> ComposeResult:
        """Lay out the inline selection row, status line and result columns.

        Summary:
            Yield the inline image-pair selection row (two variant ``Select``
            dropdowns + two external-path ``Input``s + Compare/Report buttons
            + a no-project destination ``Input``), a status ``Static``, the
            result area and the regime notice.

            The result area is ``#diff_range_list`` (a selectable ``ListView``,
            HLR-122) beside ``#diff_window_column``, which STACKS the
            ``#diff_hex_a`` / ``#diff_hex_b`` window ``Static``s. The stack is
            HLR-124's: one emitted hex row is 79 cells and the widest supported
            terminal offers 132 content cells, so two windows side by side
            cannot both be unwrapped at any supported width — the horizontal
            budget only ever fits ONE window, and the two share it vertically.

            ``#diff_size_notice`` carries LLR-124.4's explicit notice and is
            displayed only in the notice regime. No placeholder constants are
            composed (LLR-005.2).

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
        # batch-94 (HLR-010 / LLR-010.1): the check-spec file dropdown — lists
        # the patches folder's check specs (`.chk.json`) AND patch files from
        # the same directory, every check spec's label carrying the green
        # CHECK distinction. Loading a check spec adds its declared fields to
        # the emitted diff report (the C-12 writer→reader→report chain).
        #
        # P4 fix (RC-2): mount the row ONLY when the compose-time listing is
        # non-empty. C-13 arithmetic at the tight regime (120x28 fallback,
        # the floor tc_b78_54 pins): screen content 26 rows; above-panel
        # chrome 4; compacted controls (rows A/B + action + status, each
        # `height: 1` + the 1-row separator, styles.tcss:1286) 8; the
        # `1fr` `#diff_columns` gets the rest. An unconditionally mounted row
        # reserves its AUTO height here — measured 8 (wide) / 10 (fallback),
        # the Textual Select's 12-line dropdown overlay inflating the row
        # (the `#patch_variant_select_row` precedent, styles.tcss:1259) —
        # which is exactly 0-5 hex rows at the B78 sizes ((132,44) content
        # height 5 < the pinned 7; (160,40) painted 0). With an empty listing
        # the row therefore costs the operator bytes it can never spend, so
        # it is not composed; when a listing exists (files written before
        # startup, or appearing mid-session — `set_check_files` mounts the
        # row then), the 3 control rows + status + the row's own height still
        # leave the `1fr` columns the majority of the 26-row budget.
        if self._compose_check_files:
            yield self._make_check_row()[0]
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
            ListView(id="diff_range_list"),
            Vertical(
                Static("Image A", id="diff_hex_a", markup=False),
                Static("Image B", id="diff_hex_b", markup=False),
                id="diff_window_column",
            ),
            id="diff_columns",
        )
        yield Static("", id="diff_size_notice", classes="sev-warning", markup=False)

    def apply_regime(self, width: int, height: int) -> str:
        """Select and apply HLR-124's width/height regime for a terminal size.

        Summary:
            Set exactly one of the three regime classes on the panel and refresh
            the notice text. The panel stays presentational: this reads two
            integers and toggles CSS classes; every column and row figure lives
            in ``styles.tcss`` (LLR-124.1's "its own class, not
            ``width-narrow``").

        Args:
            width (int): Terminal width in columns.
            height (int): Terminal height in rows.

        Returns:
            str: The regime class applied — one of :attr:`_REGIME_CLASSES`.

        Data Flow:
            - ``S19TuiApp.on_resize`` -> here -> CSS class -> layout.

        Dependencies:
            Used by:
                - ``S19TuiApp._apply_diff_regime``
        """
        previous = next(
            (name for name in self._REGIME_CLASSES if self.has_class(name)), None
        )
        regime = self._regime_for(width, height)
        for name in self._REGIME_CLASSES:
            self.set_class(name == regime, name)
        if regime != self._REGIME_FALLBACK:
            # The overlay exists only in the fallback regime; leaving the latch
            # set would make a later fallback resize open on a stale state.
            self.remove_class(self._RUNS_OPEN)
        self.query_one("#diff_size_notice", Static).update(
            self._notice_text(width, height)
        )
        if regime != previous and self._has_result:
            # A regime change moves the pane, and `_render_run_windows` derives
            # its row count from the pane AT RENDER TIME (LLR-123.2) — so without
            # this the window keeps a row list computed for the old geometry.
            # Measured: 139x40 -> 138x40 moves capacity 1 -> 5 while the rendered
            # window does not change. AFTER the refresh, because the class is
            # what moves the pane and the new size is not readable until it lands.
            self.call_after_refresh(self._render_run_windows, self._selected_run)
        if regime != previous:
            # batch-97 Inc-7: `check_action` gates `f ] [` on the regime class,
            # and the key bar repaints only on the bindings signal — a
            # height-only resize moves no focus, so without this the bar keeps
            # the old regime's lit / dimmed tokens.
            self.app.refresh_bindings()
        return regime

    @classmethod
    def _regime_for(cls, width: int, height: int) -> str:
        """Map a terminal size onto one of HLR-124's three regimes.

        Summary:
            The deliverability condition is TWO-AXIS and the axes are
            independent — ``80x30`` passes height and fails width, ``120x24``
            passes width and fails height — so both are tested before the wide
            breakpoint, which is a refinement WITHIN deliverability.

        Args:
            width (int): Terminal width in columns.
            height (int): Terminal height in rows.

        Returns:
            str: The regime class name.
        """
        if width < _DIFF_MIN_W or height < _DIFF_MIN_H:
            return cls._REGIME_NOTICE
        if width >= _DIFF_WIDE_MIN:
            return cls._REGIME_WIDE
        return cls._REGIME_FALLBACK

    @staticmethod
    def _notice_text(width: int, height: int) -> str:
        """Compose LLR-124.4's notice, naming EVERY unsatisfied axis.

        Summary:
            One line per failed axis, each naming the measured value and the
            value that axis requires. A single "terminal too small" string
            would be wrong in each single-axis case, and a SINGULAR "the
            unsatisfied axis" would be wrong at 80x24, which fails both.

        Args:
            width (int): Terminal width in columns.
            height (int): Terminal height in rows.

        Returns:
            str: The notice text.
        """
        # SEC-F2 (normative, LLR-124.4): author-constant text and integers taken
        # from the terminal geometry and the regime constants ONLY. No loaded
        # path, image label or artifact name is interpolated here — "make the
        # error message more helpful" is precisely how a file-derived string
        # reaches a new sink, and this one is bounded before it exists.
        lines = ["The A2B diff result windows need a larger terminal."]
        if width < _DIFF_MIN_W:
            lines.append(f"  width {width} - needs at least {_DIFF_MIN_W} columns")
        if height < _DIFF_MIN_H:
            lines.append(f"  height {height} - needs at least {_DIFF_MIN_H} rows")
        return "\n".join(lines)

    def check_action(self, action: str, parameters: Tuple[object, ...]) -> Optional[bool]:
        """Gate the overlay / pagination keys on the regime that owns them.

        Summary:
            Returning ``False`` makes the binding inactive AND lets the key fall
            through, which is what keeps ``escape`` from shadowing the command
            palette's own dismissal: outside the open overlay this panel does
            not claim the key at all (spec Sec.8 ``A-2``).

        Args:
            action (str): The action name Textual is about to run.
            parameters (Tuple[object, ...]): Its parameters (unused).

        Returns:
            Optional[bool]: ``False`` to disable and hide the binding, ``True``
            otherwise.
        """
        if action == "close_run_overlay":
            return self.has_class(self._RUNS_OPEN)
        if action in ("page_window_down", "page_window_up"):
            # Overflow is a property of the RUN against the PANE, never of the
            # regime. Gating these to the fallback was a capability INVERSION:
            # measured on a 0x400-byte run, the wide regime's capacity is 1 at
            # both 160x40 and 139x40 while 132x44's is 7, so the operator on the
            # WIDEST supported terminal saw 1 of 66 rows with no key to reach the
            # rest, and the one on a narrower terminal reached all of them.
            return not self.has_class(self._REGIME_NOTICE)
        if action == "toggle_run_overlay":
            return self.has_class(self._REGIME_FALLBACK)
        return True

    def action_toggle_run_overlay(self) -> None:
        """Show / hide the fallback regime's run-list overlay (LLR-124.3).

        Summary:
            Opening focuses the list, because an overlay the arrow keys cannot
            drive is a picture of a run list. Closing hands focus back to
            whatever held it, which is not a courtesy: these bindings live on
            the PANEL, so they fire only while focus is inside it — and
            dismissing the overlay blurs the list, which would leave focus at
            ``None`` and make the very key that opened the overlay unable to
            reopen it. Executed before the restore was added: open, ``escape``,
            then ``f`` left ``runs-open`` False.
        """
        if self.has_class(self._RUNS_OPEN):
            self.action_close_run_overlay()
            return
        self._focus_before_overlay = self.screen.focused
        self.add_class(self._RUNS_OPEN)
        self.query_one("#diff_range_list", ListView).focus()

    def action_close_run_overlay(self) -> None:
        """Dismiss the run-list overlay and restore focus (LLR-124.3)."""
        self.remove_class(self._RUNS_OPEN)
        restore, self._focus_before_overlay = self._focus_before_overlay, None
        if restore is not None:
            restore.focus()

    def action_page_window_down(self) -> None:
        """Page both hex windows forward over the selected run (LLR-124.3)."""
        self._page_windows(1)

    def action_page_window_up(self) -> None:
        """Page both hex windows back over the selected run (LLR-124.3)."""
        self._page_windows(-1)

    def _page_windows(self, direction: int) -> None:
        """Move the window viewport one page and re-render both windows.

        Summary:
            Page 0 is byte-identical to the un-paged render, so every
            acceptance that does not page observes exactly what Inc-4 shipped;
            the paged branch is reached only after the operator asks for it.
            ``_render_run_windows`` clamps the page against the run's own span,
            so paging past either end is a no-op rather than an empty window.

            Both windows move together — a diff is readable only while A and B
            show the same address on the same screen line — which they do by
            construction here, because one page index drives one row list for
            both.

        Args:
            direction (int): ``+1`` to page forward, ``-1`` to page back.

        Note:
            Scrolling the widget was measured first and does not work: a
            ``Static`` with no children reports ``is_scrollable == False``, so
            ``scroll_page_down`` is a silent no-op on these windows.

        Dependencies:
            Uses:
                - ``_render_run_windows``
        """
        self._window_page = max(0, self._window_page + direction)
        self._render_run_windows(self._selected_run)

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

    @staticmethod
    def _check_select_options(names: Sequence[str]) -> List[Tuple[Any, str]]:
        """The dropdown's option list for a patches-folder scan (LLR-010.1).

        Summary:
            One entry per file — check specs and patch files listed TOGETHER,
            check specs labeled with the green ``CHECK`` suffix distinction
            (patch files get the plain ``PATCH`` label). The leading
            ``(no check spec)`` blank-value option is always present: it is
            the dropdown's "no addendum" state. The option labels are
            FILENAMES read off disk, so they reach the Select as literal
            ``Text`` objects (C-17 — the batch-37 ``set_change_files`` fold).
            The single construction site, shared by the Select's constructor
            (a row mounted mid-session) and ``set_check_files`` (the live
            re-population).

        Args:
            names (Sequence[str]): Sorted bare names from the folder scan
                (both patch ``*.json`` and check-spec ``*.chk.json`` files).

        Returns:
            List[Tuple[Any, str]]: ``(label, value)`` pairs; the label is a
                literal ``Text``.
        """
        options: List[Tuple[Any, str]] = [
            (safe_text("(no check spec)"), "")
        ]
        for name in names:
            label = Text(safe_text(str(name)).plain)
            if is_check_spec_name(name):
                label.append(" CHECK", style=GREEN)
            else:
                label.append(" PATCH", style=CYAN)
            options.append((label, name))
        return options

    def _make_check_row(self, names: Sequence[str] = ()) -> Tuple[Horizontal, Select]:
        """Build the check-spec dropdown row (LLR-010.1).

        Summary:
            The SINGLE construction site for ``#diff_check_row``, shared by
            :meth:`compose` (mounts the row when the compose-time listing is
            non-empty) and :meth:`set_check_files` (mounts it when a listing
            becomes non-empty mid-session), so the two mount paths cannot
            drift apart. Returns the row's ``Select`` by reference because a
            query on a not-yet-mounted subtree sees nothing (constructor
            children materialize at mount time), and the options are BAKED
            INTO the constructor: ``Select.set_options`` needs the mounted
            ``SelectOverlay``, which does not exist before mount.

        Args:
            names (Sequence[str]): The initial listing; ``()`` keeps only the
                ``(no check spec)`` blank option (the :meth:`compose` arm —
                its live options ride the next ``set_check_files`` call).

        Returns:
            Tuple[Horizontal, Select]: The row carrying
                ``#diff_check_select``, and that Select itself.

        Dependencies:
            Used by:
                - AbDiffPanel.compose / AbDiffPanel.set_check_files
        """
        select = Select(
            self._check_select_options(names),
            id="diff_check_select",
            allow_blank=False,
        )
        return (
            Horizontal(
                Label("Check spec:", classes="diff-field-label"),
                select,
                id="diff_check_row",
            ),
            select,
        )

    def set_check_files(self, names: Sequence[str]) -> None:
        """Populate the check-spec dropdown, suffix-distinguished (LLR-010.1).

        Summary:
            Replace ``#diff_check_select``'s options with one entry per file
            from the patches-folder scan (the shared
            :meth:`_check_select_options` builder).

            P4 fix (RC-2): the row is composed only when a listing exists.
            When the scan is empty and the row was never composed, this
            method is a no-op — mounting an empty dropdown would reserve its
            auto-height rows against the hex panes for nothing. When the
            scan turns non-empty AFTER compose (the operator wrote a
            ``.chk.json`` and revisits the diff screen — the AT-B94-12
            chain), the row is mounted here, in its compose slot ahead of
            the action row, with this scan's options baked in.

        Args:
            names (Sequence[str]): Sorted bare names from the folder scan
                (both patch ``*.json`` and check-spec ``*.chk.json`` files).
        """
        try:
            select = self.query_one("#diff_check_select", Select)
        except Exception:
            if not names:
                return  # no row, nothing to list — keep the hex panes' rows
            # The Select rides the builder's return (a query on the
            # not-yet-mounted subtree sees nothing) with these names as its
            # initial options (set_options needs the mounted overlay).
            row, _select = self._make_check_row(names)
            action_row = self.query_one("#diff_action_row")  # name, not Call — the address census (AT-B83-08) pins {literal, name, fstring}
            self.mount(row, before=action_row)
            return
        select.set_options(self._check_select_options(names))
        select.value = ""

    def on_select_changed(self, event: Select.Changed) -> None:
        """Forward a check-spec dropdown pick to ``app.py`` (LLR-010.1)."""
        if event.select.id != "diff_check_select":
            return
        value = event.value
        if value in ("", Select.NULL):
            event.stop()
            self.post_message(self.CheckFileSelected(""))
            return
        event.stop()
        self.post_message(self.CheckFileSelected(str(value)))

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

    async def render_comparison(
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

        Note:
            **Coroutine as of batch-78 Inc-2.** The run list is now a
            ``ListView`` whose rows are widgets carrying DOM ids, and
            ``ListView.clear()`` only *posts* a prune — the old rows are still
            registered when the next ``extend()`` runs. A second Compare
            therefore raised ``DuplicateIds`` on ``diff_run_0``. The removal is
            awaited, so callers must await this method.

        Dependencies:
            Uses:
                - ``_render_run_list`` / ``_render_run_windows``
            Used by:
                - ``S19TuiApp.on_ab_diff_panel_compare_requested`` (awaits)
        """
        capped = self._apply_display_caps(runs)
        self._runs = capped
        self._mem_map_a = mem_map_a
        self._mem_map_b = mem_map_b
        self._has_result = True
        self._window_page = 0
        await self._render_run_list(len(runs), summary_a, summary_b)
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

    async def _render_run_list(
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
                - ``_KIND_MARKUP`` / ``_KIND_LABEL`` / ``_run_note_item``
            Used by:
                - ``render_comparison``
        """
        listing = self.query_one("#diff_range_list", ListView)
        # AWAITED, and both awaits are load-bearing (batch-78 Inc-2 review F1).
        # `ListView.clear()` routes to `App._prune`, which only POSTS a
        # `Prune()` message: without awaiting it the old rows are still
        # registered when the new ones mount, and the second Compare raises
        # `DuplicateIds` on `diff_run_0`. Awaiting the mount in turn means the
        # rows are in `_nodes` before `index` is assigned below — otherwise
        # `watch_index` highlights a row that is about to be pruned and, because
        # the value does not change, never fires again, leaving NO row
        # highlighted after a re-render.
        await listing.clear()

        items: List[ListItem] = [
            self._run_note_item(f"Runs: {total_runs}"),
            self._run_note_item(f"A artifacts: {summary_a}"),
            self._run_note_item(f"B artifacts: {summary_b}"),
            # LLR-126.1's visible affordance. It rides in the list BODY, not in
            # `border_title`, and that is a regime decision rather than a style
            # one: `styles.tcss` gives `#diff_range_list` `border: none` in the
            # fallback regime (cited by SELECTOR -- the line number this comment
            # carried pointed at `#diff_hex_b`, ~47 lines short of the rule it
            # named), so a border-hosted affordance would be present at
            # 132x44 and ABSENT at 120x30 — "shall carry a visible affordance"
            # unsatisfied in a supported regime, with an acceptance green at one
            # size and inert at the other. A body row is visible wherever the
            # list itself is.
            #
            # Placed LAST among the notes so it sits immediately above the runs
            # it describes, and built through `_run_note_item` so it inherits
            # `disabled=True` — `action_cursor_up` / `action_cursor_down` skip
            # it, which is what keeps LLR-122.1's keyboard-reachable set equal
            # to the run indices. `first_run_position` is `len(items)`, so the
            # run offset follows this addition with no second edit.
            self._run_note_item(self._RUN_LIST_AFFORDANCE),
        ]
        first_run_position = len(items)
        for index, (start, end, kind) in enumerate(self._runs):
            colour = self._KIND_MARKUP.get(kind, "#ffffff")
            label = self._KIND_LABEL.get(kind, kind)
            items.append(
                ListItem(
                    Label(
                        f"[{colour}]{index:>3} 0x{start:08X}-0x{end:08X} "
                        f"{label}[/]",
                        markup=True,
                    ),
                    id=f"diff_run_{index}",
                    classes="diff-run-entry",
                )
            )
        if len(self._runs) < total_runs:
            items.append(
                self._run_note_item(
                    f"(showing {len(self._runs)} of {total_runs} runs — "
                    f"full report is complete)"
                )
            )
        await listing.extend(items)
        listing.index = first_run_position if self._runs else None

    @staticmethod
    def _run_note_item(text: str) -> ListItem:
        """Build a non-selectable header / notice row for the run list.

        Summary:
            The run count, the two artifact-usage summaries and the display-cap
            notice are context, not runs. They ride in the same ``ListView`` so
            they stay beside the runs they describe, but carry ``disabled=True``
            so ``ListView.action_cursor_up`` / ``action_cursor_down`` skip them
            — which is what keeps the keyboard-reachable set equal to the run
            indices and nothing else (LLR-122.1).

        Args:
            text (str): The line to render. Rendered ``markup=False``.

        Returns:
            ListItem: The disabled note row.
        """
        # C-17: the artifact-usage summaries are the one file-derived string
        # that reaches this column, so the note rows are markup-INERT at
        # construction (C11) rather than escaped at the call site. The widget
        # swap is exactly where a `rich.markup.escape` call gets lost; a
        # `markup=False` sink cannot lose it.
        return ListItem(Label(text, markup=False), classes="diff-run-note", disabled=True)

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        """Re-render both hex windows for the newly highlighted run (LLR-123.1).

        Summary:
            The run list is the shipped selection surface (HLR-122), and this
            is the only thing that makes it mean anything: moving the highlight
            re-renders the A and B windows onto the run the operator is on.
            Before batch-78 Inc-4 ``_render_run_windows`` had a single call
            site, ``render_comparison``'s literal ``0``, so runs 1..N were
            unreachable however the list was driven.

        Args:
            event (ListView.Highlighted): The highlight-change event. Its
                ``item`` is ``None`` while the list is being rebuilt, and is a
                header / notice row for the three context lines — neither
                stands for a run, and neither re-renders anything.

        Dependencies:
            Uses:
                - ``_render_run_windows``
            Used by:
                - Textual message dispatch for ``ListView.Highlighted``
        """
        # The run index rides on the row's shipped DOM id (`_render_run_list`),
        # not on the row's position: the list also carries three disabled
        # context rows at the top and a display-cap notice at the bottom, so
        # position and run index are not the same number.
        item = event.item
        if item is None or item.id is None or not item.id.startswith("diff_run_"):
            return
        # A new selection always starts on page 0 (LLR-124.3): the operator asked
        # for a different run, not for a different page of the old one.
        self._window_page = 0
        self._render_run_windows(int(item.id[len("diff_run_") :]))

    def _window_row_capacity(self) -> int:
        """Hex rows the pane can actually paint, header row excluded (LLR-123.2).

        Summary:
            The row count is a function of the RENDERED pane, read at render
            time — never of :attr:`DISPLAY_CONTEXT_BYTES`, which is a compile-
            time constant and made the window identical at every terminal
            height (executed pre-change: 132x44 and 132x60 both emitted 4
            lines, into panes of 13 and 29 content rows).

        Returns:
            int: ``min(A, B) - 1`` content rows, floored at 0. The MINIMUM of
            the two windows is the binding one because a diff is only readable
            when both columns show the SAME addresses on the same screen line;
            the two are siblings under one ``1fr`` row and measure equal
            (executed at 132x44, 132x60, 160x40, 120x30 and 80x24), so this is
            each window's own height wherever they agree and the honest bound
            where a future layout makes them differ. The ``- 1`` is the header
            line, which shares the widget with the hex rows.

        Dependencies:
            Used by:
                - ``_render_run_windows``
        """
        heights = (
            self.query_one("#diff_hex_a", Static).size.height,
            self.query_one("#diff_hex_b", Static).size.height,
        )
        return max(0, min(heights) - 1)

    def _render_run_windows(self, run_index: int) -> None:
        """Render the selected run's pane-sized hex windows for A and B.

        Summary:
            Render image A's and image B's hex+ASCII windows around the
            selected run, each window respecting the ``hexview`` row caps
            (``MAX_HEX_ROWS``). The window ALWAYS spans the run ±
            :attr:`DISPLAY_CONTEXT_BYTES` (the floor, HLR-123), and is then
            grown to fill the rendered pane, keeping the run centred.

        Args:
            run_index (int): Index into :attr:`_runs` of the run to window.

        Data Flow:
            - Compute the mandatory run ± context span, then grow it to the
              pane's capacity by splitting the surplus rows evenly above and
              below, clamping the low edge at address 0.

        Note:
            The floor is a floor, not the value. When the pane is shorter than
            the floor the floor still wins and the surplus rows overflow — the
            paginable viewport that bounds them is HLR-124's, built at Inc-5.
            The growth is therefore one-directional and this method never
            renders FEWER rows than the pre-batch-78 window did.

        Dependencies:
            Uses:
                - ``hexview.render_hex_view`` / ``_window_row_capacity``
            Used by:
                - ``render_comparison`` / ``on_list_view_highlighted``
        """
        from ..render.hexview import HEX_WIDTH, MAX_HEX_ROWS, render_hex_view

        if not (0 <= run_index < len(self._runs)):
            return
        self._selected_run = run_index
        start, end, kind = self._runs[run_index]
        low = max(0, start - self.DISPLAY_CONTEXT_BYTES)
        low -= low % HEX_WIDTH
        high = end + self.DISPLAY_CONTEXT_BYTES
        rows = len(range(low, high, HEX_WIDTH))
        capacity = self._window_row_capacity()
        if capacity > rows:
            # Centre the run: half the surplus goes above it, and whatever the
            # address-0 clamp refuses up there is kept, not dropped — the row
            # count stays `capacity` and the remainder simply extends downward.
            low = max(0, low - ((capacity - rows) // 2) * HEX_WIDTH)
            rows = capacity
        # LLR-124.3's paginable viewport. Page 0 leaves `low` and `rows` exactly
        # as Inc-4 computed them, so an un-paged window is byte-identical to the
        # one HLR-123's acceptances were written against; only an operator who
        # presses `]` reaches the branch below. The page is clamped to the run's
        # own span and written back, so `]` at the last page is a no-op instead
        # of an empty window.
        if capacity > 0:
            self._window_page = min(self._window_page, max(0, (rows - 1) // capacity))
            if self._window_page:
                low += self._window_page * capacity * HEX_WIDTH
                rows = min(capacity, rows - self._window_page * capacity)
        row_bases = [low + index * HEX_WIDTH for index in range(rows)]
        text_a = render_hex_view(self._mem_map_a, row_bases=row_bases, max_rows=MAX_HEX_ROWS)
        text_b = render_hex_view(self._mem_map_b, row_bases=row_bases, max_rows=MAX_HEX_ROWS)
        header = (
            f"Run #{run_index} 0x{start:08X}-0x{end:08X} "
            f"{self._KIND_LABEL.get(kind, kind)}"
        )
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
