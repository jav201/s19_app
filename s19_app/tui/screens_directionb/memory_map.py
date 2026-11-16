"""s19_app.tui.screens_directionb.memory_map — MemoryMapPanel (moved verbatim from s19_app/tui/screens_directionb.py at 4f721985)."""
from __future__ import annotations

import bisect
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple
from rich.text import Text
from textual import events
from textual.app import ComposeResult
from textual.containers import Container, Horizontal, ScrollableContainer, Vertical
from textual.message import Message
from textual.widget import Widget
from textual.widgets import Label, Static
from ..entropy_style import ENTROPY_BAND_LABELS, band_style
from ..insight_style import human_bytes, microbar
from ...range_index import address_in_sorted_ranges, build_sorted_range_index
from ..services.entropy_service import EntropyWindow
from ...validation import ValidationIssue
from ...utils import safe_text
from .shared import (_clip_to_cells)
from .map_parts import (
    _BAND_GAP_FOLD,
    _REGION_MICROBAR_WIDTH,
    _BAND_SHORT_LABELS,
    _STATS_FULL_MIN_WIDTH,
    _REGION_ROW_MICROBAR_MIN_WIDTH,
    _MAP_PANEL_TO_ROWS_INSET,
    _MAP_PANEL_TO_ROWS_INSET_STACKED,
    _MAP_PANEL_WIDE_FALLBACK,
    _MAP_STACK_MIN_WIDTH,
    _INSPECTOR_BODY_FALLBACK_WIDTH,
    _INSPECTOR_SCROLLBAR_GUTTER,
    _PEEK_BYTES_PER_ROW,
    _PEEK_UNMAPPED_CELL,
    _INSPECTOR_FIELD_ROWS,
    _INSPECTOR_LABEL_WIDTH,
    _MAP_GAP_HATCH,
    _OPEN_IN_HEX_GLYPH,
    _PEEK_ROWS_FALLBACK,
    _merge_band_runs,
    _allocate_band_widths,
    derive_image_span,
    cell_status,
    issues_in_window,
    covering_range,
    _tag_address,
    symbols_in_window,
    symbol_list_text,
    CoverageStats,
    coverage_stats,
    RegionRow,
    BandSegment,
    BandBar,
    MapRuler,
)


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
