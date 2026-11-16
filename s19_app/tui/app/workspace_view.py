"""s19_app.tui.app.workspace_view — S19TuiApp mixin: workspace_view (moved verbatim from s19_app/tui/app.py at 4f721985)."""
from __future__ import annotations

from typing import Optional, Sequence
from textual.containers import Container
from textual.widgets import ListItem, ListView, Static
from rich.cells import cell_len, set_cell_size
from rich.text import Text
from ...utils import safe_text
from ..screens_directionb import (
    CoverageStats,
    MemoryMapPanel,
    bytes_per_cell,
    cell_count_for_geometry,
    cell_status,
    coverage_stats,
    derive_image_span,
    status_to_css_class,
)
from ..color_policy import css_class_for_severity
from ..entropy_style import band_style
from ..insight_style import CYAN, GREEN, RED, VALUE, YELLOW, human_bytes, microbar
from ..services.entropy_service import EntropyWindow
from ...validation import ValidationSeverity
from ..open_folder_chip import OpenFolderChip
from . import deps


MAX_SECTIONS_OUT_OF_RANGE = 50
"""Max MAC out-of-range rows the Sections panel renders before adding a truncation marker."""


MAX_SECTIONS_PRIMARY_RANGES = 200
"""Max primary memory-range rows the Sections panel mounts before adding a truncation marker.

Textual's ``ListView.append`` incurs per-item DOM + CSS cost, so uncapped range lists
with thousands of entries can stall the main thread for many seconds. Capping keeps the
install step bounded regardless of how fragmented the S19/HEX image is.
"""


#: Fixed cell budget for the Workspace per-range coverage micro-bar (LLR-042.7).
#: Small enough (<= the ~18 usable cols of the 22-wide ``#ws_left`` pane) that the
#: bar renders as an ADDED third line inside the range row without widening it.
SECTIONS_COVERAGE_BAR_WIDTH = 8

#: Fallback column count for the Workspace whole-image memory strip (LLR-042.8)
#: used only before the ``#ws_memstrip`` band has a measured content width (e.g.
#: a headless render before layout). It caps the mounted cell count so a hostile
#: huge image never mounts unbounded cells even pre-layout.
WORKSPACE_MEMSTRIP_DEFAULT_COLS = 76

#: Glyph painted in each memory-strip cell. A full block so the ``sev-*`` colour
#: fills the cell; composed via ``safe_text`` so the band stays markup-safe.
_STRIP_CELL_GLYPH = "█"

#: App-supplied gap glyph for an unmapped address window in the memory strip
#: (batch-47, LLR-067.2). NOT an entropy band glyph — ``entropy_style`` owns only
#: ``· ░ ▒ ▓``; this hatch marks the holes between mapped ranges.
_STRIP_GAP_GLYPH = "╱"


#: Filled / empty glyphs for the range-magnitude micro-bar. Neither is a Rich
#: markup metacharacter, but the bar is composed into a ``rich.text.Text`` (never
#: a markup-parsed string) so the render surface stays markup-safe by construction.
def dominant_band_label(
    entropy_windows: Sequence[EntropyWindow], start: int, end: int
) -> Optional[str]:
    """
    Summary:
        Return the entropy band label covering the most bytes of the half-open
        address window ``[start, end)``, or ``None`` when no computed entropy
        window overlaps it (batch-47, LLR-066.2 / LLR-067.1). Pure arithmetic
        over the already-computed ``LoadedFile.entropy_windows`` — it recomputes
        no entropy.

    Args:
        entropy_windows (Sequence[EntropyWindow]): Loader-computed windows in
            ascending address order (``LoadedFile.entropy_windows``).
        start (int): Inclusive window start address.
        end (int): Exclusive window end address.

    Returns:
        Optional[str]: The band label with the greatest total overlapping byte
        span in ``[start, end)``; ``None`` when no window overlaps (empty
        windows or an all-gap window).

    Data Flow:
        - Accumulates overlap byte counts per band label, then returns the
          arg-max; ties resolve to the first band reaching the max (dict
          insertion order over the ascending-address windows).
        - Called by ``update_sections`` (per range row) and
          ``update_memory_strip`` (per strip cell) to pick a cell's band glyph.

    Dependencies:
        Uses:
            - EntropyWindow (read-only)
        Used by:
            - ``S19TuiApp.update_sections``
            - ``S19TuiApp.update_memory_strip``

    Example:
        >>> from s19_app.tui.services.entropy_service import EntropyWindow
        >>> w = EntropyWindow(0x0, 0x100, 256, 0.0, "constant/padding", False)
        >>> dominant_band_label([w], 0x0, 0x80)
        'constant/padding'
        >>> dominant_band_label([w], 0x200, 0x280) is None
        True
    """
    totals: dict[str, int] = {}
    for window in entropy_windows:
        lo = max(start, window.start)
        hi = min(end, window.end)
        if hi > lo:
            totals[window.band] = totals.get(window.band, 0) + (hi - lo)
    if not totals:
        return None
    return max(totals, key=lambda label: totals[label])


def build_loader_facts_text(
    error_count: int, ooo_count: int, entry_point: Optional[int]
) -> Text:
    """
    Summary:
        Compose the Workspace loader-facts line
        ``Loader N err · ⚠K OOO · Entry <hex-or-—>`` as a markup-safe
        ``rich.text.Text`` (batch-47, LLR-066.4 / LLR-066.6). Carries only
        numeric counts and a formatted hex entry address — never any
        file-derived free text — so the line is C-17-inert by construction.

    Args:
        error_count (int): ``len(LoadedFile.errors)`` — loader-level error count.
        ooo_count (int): ``LoadedFile.out_of_order_count`` — non-monotonic S19
            data-record count.
        entry_point (Optional[int]): ``LoadedFile.entry_point`` — the S7/S8/S9
            terminator address. A present-but-zero entry (``0x0``) renders
            ``Entry 0x00000000`` (PRESENT); ``None`` renders ``Entry —``
            (ABSENT, e.g. every HEX load).

    Returns:
        Text: The single loader-facts line, styled (err red when non-zero, OOO
        yellow when non-zero, entry cyan). Never a ``str``; never markup-parsed.

    Data Flow:
        - Pure formatting of already-derived scalars; appended by
          ``update_workspace_stats`` under the coverage-stats block in
          ``#ws_stats``.

    Dependencies:
        Uses:
            - rich.text.Text ; CYAN ; RED ; VALUE ; YELLOW
        Used by:
            - ``S19TuiApp.update_workspace_stats``
            - (test) AT-066a/AT-066b/AT-066c/AT-066d over ``#ws_stats``

    Example:
        >>> build_loader_facts_text(0, 4, 0x0).plain
        'Loader 0 err · ⚠4 OOO · Entry 0x00000000'
        >>> build_loader_facts_text(0, 0, None).plain
        'Loader 0 err · ⚠0 OOO · Entry —'
    """
    entry = f"0x{entry_point:08X}" if entry_point is not None else "—"
    text = Text()
    text.append("Loader ")
    text.append(f"{error_count} err", style=RED if error_count else VALUE)
    text.append(" · ")
    text.append(f"⚠{ooo_count} OOO", style=YELLOW if ooo_count else VALUE)
    text.append(" · ")
    text.append("Entry ")
    text.append(entry, style=CYAN)
    return text


def build_workspace_stats_text(
    stats: CoverageStats, error_count: int, warning_count: int
) -> Text:
    """
    Summary:
        Assemble the markup-safe Workspace stat pane body (LLR-042.9): coverage
        percent + range count (from ``coverage_stats``) and error / warning
        counts (severity tallies over ``_validation_issues``). No entropy figure
        (D3 descoped). Pure formatting of already-computed values.

    Args:
        stats (CoverageStats): Metrics from ``coverage_stats`` over the parsed
            ranges / validity and the pre-computed issue list.
        error_count (int): Count of ``ERROR``-severity validation issues.
        warning_count (int): Count of ``WARNING``-severity validation issues.

    Returns:
        Text: Four labelled lines. When there are no ranges the coverage line
        shows a neutral ``—`` (em dash) instead of ``0.00%``.

    Data Flow:
        - Called by ``S19TuiApp.update_workspace_stats``; rendered into
          ``#ws_stats``.

    Dependencies:
        Used by:
            - ``S19TuiApp.update_workspace_stats``
            - (test) TC-042.9
    """
    range_count = stats.valid_count + stats.invalid_count
    text = Text()
    if range_count == 0:
        text.append("Coverage: —\n")
    else:
        text.append(f"Coverage: {stats.coverage_pct:.2f}%\n")
    text.append(f"Ranges: {range_count}\n")
    text.append(f"Errors: {error_count}\n")
    text.append(f"Warnings: {warning_count}")
    return text


class WorkspaceViewMixin:

    def _jump_to_section(self, item: ListItem) -> None:
        section_range = getattr(item, "data", None)
        if section_range:
            start, _ = section_range
            self.update_hex_view(start)

    def update_sections(self, precomputed_out_of_range: Optional[list[int]] = None) -> None:
        """
        Summary:
            Render the ranges/Sections panel and cap appended MAC out-of-range rows so
            very large MAC misalignments never mount thousands of widgets synchronously.

        Args:
            precomputed_out_of_range (Optional[list[int]]): Sorted MAC out-of-range
                addresses produced by the load worker; when ``None`` the app falls back
                to ``_collect_mac_out_of_range_addresses``.

        Returns:
            None

        Data Flow:
            - Clear widget, refresh the Workspace stat pane and the whole-image
              memory strip, and short-circuit when no file is loaded.
            - Append at most ``MAX_SECTIONS_PRIMARY_RANGES`` memory-range rows,
              each an in-range ``✓`` glyph + cyan address, a humanized size
              (``human_bytes``) with the range's dominant entropy-band glyph, and
              a size micro-bar (``microbar(size / biggest, floor=True)``) as the
              third line (LLR-042.7 / batch-47 LLR-066.2), then a truncation row
              when more exist. The bar is floored to >=1 filled cell because at
              ``SECTIONS_COVERAGE_BAR_WIDTH`` (8) any range under 6.25% of the
              largest would otherwise render invisible (a 64 B vector table
              beside a 512 KiB image). OK/ERROR ``sev-*`` colouring is retained
              on the row label.
            - Append at most ``MAX_SECTIONS_OUT_OF_RANGE`` MAC out-of-range rows; when
              truncated, add a single summary row pointing users at the Issues panel.

        Dependencies:
            Uses:
                - ``_collect_mac_out_of_range_addresses``
                - ``css_class_for_severity``
                - ``dominant_band_label`` / ``band_style`` / ``human_bytes`` /
                  ``microbar``
                - ``update_workspace_stats``
                - ``update_memory_strip``
            Used by:
                - ``_apply_prepared_load``
        """
        sections = self.query_one("#sections_list", ListView)
        sections.clear()
        self.update_workspace_stats()
        self.update_memory_strip()
        if not self.current_file:
            return
        ranges = self.current_file.ranges
        validity = self.current_file.range_validity
        total_ranges = len(ranges)
        range_cap = MAX_SECTIONS_PRIMARY_RANGES
        visible_ranges = list(zip(ranges[:range_cap], validity[:range_cap]))
        max_size = max((end - start for (start, end), _ in visible_ranges), default=0)
        entropy_windows = self.current_file.entropy_windows
        for (start, end), is_valid in visible_ranges:
            size = end - start
            band_glyph = ""
            if entropy_windows:
                band_label = dominant_band_label(entropy_windows, start, end)
                if band_label is not None:
                    band_glyph = band_style(band_label)[1]
            content = Text()
            content.append("✓ ", style=GREEN)
            content.append(f"0x{start:08X}\n", style=CYAN)
            content.append(f"– 0x{end - 1:08X}  ")
            content.append(human_bytes(size).rjust(9), style=VALUE)
            if band_glyph:
                content.append(f" {band_glyph}")
            content.append("\n")
            content.append_text(
                microbar(
                    size / max_size if max_size else 0.0,
                    SECTIONS_COVERAGE_BAR_WIDTH,
                    floor=True,
                )
            )
            label = deps.Label(content)
            severity = ValidationSeverity.OK if is_valid else ValidationSeverity.ERROR
            label.add_class(css_class_for_severity(severity))
            item = deps.ListItem(label)
            item.data = (start, end)
            sections.append(item)
        if total_ranges > range_cap:
            extra_ranges = total_ranges - range_cap
            truncation_label = deps.Label(
                f"... {extra_ranges} more ranges (see log) ..."
            )
            truncation_label.add_class(css_class_for_severity(ValidationSeverity.NEUTRAL))
            truncation_item = deps.ListItem(truncation_label)
            truncation_item.data = None
            sections.append(truncation_item)
        if precomputed_out_of_range is not None:
            out_of_range = precomputed_out_of_range
        else:
            out_of_range = sorted(self._collect_mac_out_of_range_addresses(self.current_file))
        total_oor = len(out_of_range)
        oor_cap = MAX_SECTIONS_OUT_OF_RANGE
        visible = out_of_range[:oor_cap]
        for address in visible:
            label = deps.Label(f"MAC out-of-range\n@ 0x{address:08X}")
            label.add_class("mac_out_of_range")
            item = deps.ListItem(label)
            item.data = (address, address + 1)
            sections.append(item)
        if total_oor > oor_cap:
            truncation_label = deps.Label(
                f"... {total_oor - oor_cap} more MAC out-of-range (see Issues panel) ..."
            )
            truncation_label.add_class("mac_out_of_range")
            sections.append(deps.ListItem(truncation_label))
        self.logger.info(
            "Sections updated. count=%d rendered_ranges=%d mac_out_of_range_total=%d rendered_oor=%d",
            total_ranges,
            min(total_ranges, range_cap),
            total_oor,
            min(total_oor, oor_cap),
        )

    def update_workspace_stats(self) -> None:
        """
        Summary:
            Refresh the Workspace stat pane (``#ws_right`` → ``#ws_stats``) with
            coverage percent + range count and error / warning tallies
            (LLR-042.9 / US-040c). Display arithmetic only — it reuses
            ``coverage_stats`` and counts ``_validation_issues`` by severity;
            it performs no new parse / coverage / validation. No entropy figure
            (D3 descoped).

        Args:
            None

        Returns:
            None

        Data Flow:
            - With no file loaded, render the neutral empty pane (0 ranges,
              coverage ``—``).
            - Otherwise compute ``coverage_stats`` over the already-parsed
              ``ranges`` / ``range_validity`` and the pre-computed
              ``_validation_issues``, tally ERROR / WARNING counts, and render
              the markup-safe stat text into ``#ws_stats``, followed by the
              loader-facts line (``Loader N err · ⚠K OOO · Entry <hex-or-—>``,
              batch-47 LLR-066.4) built from the derived ``LoadedFile`` fields.

        Dependencies:
            Uses:
                - ``coverage_stats``
                - ``build_workspace_stats_text``
                - ``build_loader_facts_text``
            Used by:
                - ``update_sections``
        """
        # Render-defensive: ``update_sections`` also runs in unit tests that drive
        # a non-mounted app with a fake ``query_one`` (returns None for widgets they
        # don't stub) and pre-mount, where ``#ws_stats`` is absent. Either case is a
        # no-op, not a crash (mirrors ``update_memory_strip``).
        try:
            body = self.query_one("#ws_stats", Static)
        except Exception:  # noqa: BLE001 — display-side, non-fatal
            return
        if body is None:
            return
        if not self.current_file:
            body.update(build_workspace_stats_text(coverage_stats([], [], []), 0, 0))
            return
        stats = coverage_stats(
            self.current_file.ranges,
            self.current_file.range_validity,
            self._validation_issues,
        )
        error_count = sum(
            1 for issue in self._validation_issues
            if issue.severity is ValidationSeverity.ERROR
        )
        warning_count = sum(
            1 for issue in self._validation_issues
            if issue.severity is ValidationSeverity.WARNING
        )
        text = build_workspace_stats_text(stats, error_count, warning_count)
        text.append("\n")
        text.append_text(
            build_loader_facts_text(
                len(self.current_file.errors),
                self.current_file.out_of_order_count,
                self.current_file.entry_point,
            )
        )
        body.update(text)

    def update_memory_strip(self) -> None:
        """
        Summary:
            Refresh the Workspace whole-image memory strip (``#ws_memstrip``): a
            single-row band whose mapped cells are coloured by their dominant
            entropy band (``entropy_style.band_style`` over the loader-computed
            ``current_file.entropy_windows``) and whose unmapped gaps get the
            ``╱`` hatch (batch-47, LLR-067.1/067.2). When no entropy windows are
            present it FALLS BACK to the batch-27 valid / invalid / gap colouring
            via ``cell_status`` / ``status_to_css_class`` (LLR-067.3). The
            mounted cell count is BOUNDED to the band's measured content width
            via ``cell_count_for_geometry`` (rows=1), so a hostile huge image
            never mounts unbounded cells. Display arithmetic only — no new parse
            / coverage / validation / entropy computation.

        Args:
            None

        Returns:
            None

        Data Flow:
            - Clear the band; with no file loaded or no positive image span,
              leave a neutral empty band (no cells, no crash).
            - Otherwise build the ``(start, end, is_valid)`` triples from the
              parsed model, derive the image span, cap the cell count to the
              measured band width (fallback ``WORKSPACE_MEMSTRIP_DEFAULT_COLS``),
              and mount one ``Static`` cell per window coloured by ``cell_status``
              → ``status_to_css_class``.

        Dependencies:
            Uses:
                - ``derive_image_span`` / ``cell_count_for_geometry`` /
                  ``bytes_per_cell`` / ``cell_status`` / ``status_to_css_class``
                  / ``dominant_band_label`` / ``band_style`` / ``safe_text``
            Used by:
                - ``update_sections``
        """
        try:
            band = self.query_one("#ws_memstrip", Container)
        except Exception:  # noqa: BLE001 — display-side, non-fatal
            # App not mounted yet (headless render before compose).
            return
        if band is None:
            # Unit tests drive ``update_sections`` with a fake ``query_one`` that
            # returns None for widgets they don't stub — no-op, not a crash.
            return
        band.remove_children()
        if not self.current_file:
            return
        ranges = self.current_file.ranges
        validity = self.current_file.range_validity
        span_start, span_end = derive_image_span(ranges)
        span = span_end - span_start
        if not ranges or span <= 0:
            return
        ordered: list[tuple[int, int, bool]] = []
        for index, (start, end) in enumerate(ranges):
            is_valid = bool(validity[index]) if index < len(validity) else True
            ordered.append((start, end, is_valid))
        ordered.sort(key=lambda item: item[0])
        size = band.content_size
        cols = size.width if size.width > 0 else WORKSPACE_MEMSTRIP_DEFAULT_COLS
        count = cell_count_for_geometry(span, cols, 1)
        per_cell = bytes_per_cell(span, count)
        entropy_windows = self.current_file.entropy_windows
        cells: list[Static] = []
        for index in range(count):
            cell_start = span_start + index * per_cell
            cell_end = min(span_end, cell_start + per_cell)
            status = cell_status(cell_start, cell_end, ordered)
            if entropy_windows:
                # Entropy-banded view (batch-47, LLR-067.1/067.2): gaps get the
                # app-supplied ``╱`` hatch; mapped cells take their dominant
                # band's glyph + ``band-*`` class from ``entropy_style``.
                if status == "gap":
                    cells.append(
                        Static(
                            safe_text(_STRIP_GAP_GLYPH),
                            classes=f"strip-cell {status_to_css_class('gap')}",
                        )
                    )
                    continue
                band_label = dominant_band_label(entropy_windows, cell_start, cell_end)
                if band_label is not None:
                    band_class, glyph, _meaning = band_style(band_label)
                    cells.append(
                        Static(
                            safe_text(glyph),
                            classes=f"strip-cell {band_class}",
                        )
                    )
                    continue
            # No entropy windows (LLR-067.3 fallback) or a mapped cell with no
            # overlapping window: keep the pre-existing valid/invalid/gap band.
            sev_class = status_to_css_class(status)
            cells.append(
                Static(
                    safe_text(_STRIP_CELL_GLYPH),
                    classes=f"strip-cell {sev_class}",
                )
            )
        if cells:
            band.mount(*cells)

    def update_memory_map(self) -> None:
        """
        Summary:
            Refresh the Memory Map screen's coverage visualization from the
            current ``LoadedFile`` (LLR-012.1).

        Args:
            None

        Returns:
            None

        Data Flow:
            - When no file is loaded, hand empty lists to ``MemoryMapPanel``
              so it shows its neutral no-file note.
            - Otherwise pass ``current_file.ranges``,
              ``current_file.range_validity``, the pre-computed
              ``_validation_issues``, the enriched ``_a2l_enriched_tags``
              (R-TUI-041 R-3 region/cell symbol naming) and the loader-computed
              ``current_file.entropy_windows`` (batch-45 R-TUI-060 band view)
              straight through to ``MemoryMapPanel.render_ranges``. The renderer
              reads these already-computed model fields verbatim — it adds no
              coverage computation, entropy computation, parsing or analysis
              (LLR-012.1 / LLR-012.4 / LLR-045A.2 M4).

        Dependencies:
            Uses:
                - ``MemoryMapPanel.render_ranges``
            Used by:
                - ``_apply_prepared_load`` (post-load refresh)
        """
        panel = self.query_one("#memory_map_panel", MemoryMapPanel)
        if not self.current_file:
            panel.render_ranges([], [], [], [], [])
            return
        panel.render_ranges(
            self.current_file.ranges,
            self.current_file.range_validity,
            self._validation_issues,
            self._a2l_enriched_tags,
            self.current_file.entropy_windows,
            self.current_file.mem_map,
        )
        self.logger.info(
            "Memory Map updated. ranges=%d", len(self.current_file.ranges)
        )

    def on_memory_map_panel_open_in_hex_requested(
        self, message: "MemoryMapPanel.OpenInHexRequested"
    ) -> None:
        """Jump to the hex view focused on the selected cell (LLR-041.6).

        Summary:
            Handle the Memory Map's Open-in-Hex request by switching to the
            Workspace/hex screen and driving the existing
            ``update_hex_view(focus_address=…)`` with the cell's start address.
            The panel renders no hex itself — this app-side handler is the
            single owner of the focus path.

        Args:
            message (MemoryMapPanel.OpenInHexRequested): Carries the selected
                cell's ``focus_address`` (its ``cell_start``).

        Returns:
            None

        Dependencies:
            Uses:
                - ``action_show_screen`` / ``update_hex_view``
            Used by:
                - Textual message dispatch (from ``MemoryMapPanel``)
        """
        message.stop()
        self.action_show_screen("workspace")
        self.update_hex_view(focus_address=message.focus_address)

    def update_project_labels(self) -> None:
        """
        Summary:
            Refresh the project-name / A2L-filename context on BOTH context
            surfaces — ``#workspace_status_bar``'s context cell and the Loaded
            panel's project row — so the context stays visible from every
            Direction B screen (LLR-011.3, batch-79 LLR-120.1).

        Args:
            None

        Returns:
            None

        Data Flow:
            - Composes the project string via ``_compose_project_label`` and the
              A2L filename (or a ``(none)`` sentinel), then writes BOTH to
              ``#status_context`` through ``safe_text`` and drives
              ``_refresh_loaded_panel`` with the same composed string. One
              composer feeds both sinks, so the two surfaces cannot disagree
              about the display form (LLR-120.5).
            - There are TWO sinks, not three. The command bar's
              ``set_context_labels`` was the third; ``HLR-118`` deleted the row
              at Inc-10 and ``HLR-121`` deleted the helper at Inc-11. It is
              named here only as the thing that used to be here, because Inc-8
              re-pointed the test observables off it while all three were still
              live and that ordering is why nothing went red.
            - Returns early when ``#status_context`` cannot be resolved, so a
              call before the tree is mounted is a no-op (TC-B78-13).
            - Multi-variant projects (LLR-005.5): when the variant set holds
              N > 1 variants, the project label reads
              ``«project»:«variant» (i/N)`` with ``i`` the 1-based index of
              the active variant; single-variant projects keep the plain
              project name (LLR-005.3 back-compat).
            - batch-94 (HLR-006): the ``_refresh_patch_variant_select`` chain
              retired with the Patch Editor variant selector — the project
              label refresh no longer touches the editor's dropdown.

        Dependencies:
            Uses:
                - ``_compose_project_label`` (the single display-form composer)
                - ``safe_text`` (LLR-120.4 — the status-bar sink is markup- AND
                  control-character-safe)
                - ``_refresh_loaded_panel`` (the second context surface)
                - ``_compose_context_line`` (bounds the two halves against each
                  other so neither can evict the other — see its own docstring)
            Used by:
                - Project / A2L load handlers
                - ``_apply_unload`` (post-unload refresh)
                - ``_sync_loaded_file_to_project`` (variant append)
        """
        project_name = self._compose_project_label()
        a2l_name = self.current_a2l_path.name if self.current_a2l_path else "(none)"
        # LLR-120.1 -- ONE entry point drives BOTH surfaces. This replaces the
        # single write to the command bar (which HLR-118 deletes at Inc-10).
        #
        # Both surfaces are fed the SAME string from the SAME composer, so
        # LLR-120.5's two display forms cannot drift apart between them: the
        # form is decided in `_compose_project_label` and neither sink
        # re-derives it.
        #
        # `safe_text` on the status-bar sink (LLR-120.4). `markup=False` is a
        # PARSE FLAG that performs no string transform -- executed, it leaves
        # `0x0 0x7 0x1b 0x7f 0x9b 0x9d` byte-identical to the payload, and
        # `U+009B` / `U+009D` are single-byte C1 introducers carrying no `\x1b`
        # that are legal Windows filename characters. So an SGR recolour or an
        # OSC-8 hyperlink is reachable through a hostile A2L filename or
        # project directory name on the operator's own platform.
        # TC-B78-13 -- a call before the tree is mounted is a NO-OP, matching
        # `_refresh_loaded_panel` / `_apply_empty_state`.
        #
        # This guard is NEW BEHAVIOUR, not a restatement of existing behaviour,
        # and the distinction is worth the line: executed against the batch base
        # `829adc6`, `update_project_labels()` on an unmounted app raises
        # `ScreenStackError: No screens on stack`. HLR-120's boundary catalog
        # asserts the opposite ("before mount -> no raise"), so the catalog
        # named a tolerance the code had never had. It is made true here rather
        # than descoped, because it is an acceptance criterion of the very
        # requirement this increment implements.
        #
        # It wraps EVERY sink, not just the new one: each write below is equally
        # unguarded, so guarding only `#status_context` would move the raise one
        # line down and leave the catalog still false. (It wrapped THREE sinks
        # when written; the command-bar write was the third and is gone.)
        try:
            self.query_one("#status_context", deps.Label).update(
                safe_text(self._compose_context_line(project_name, a2l_name))
            )
        except Exception:
            return
        self._refresh_loaded_panel(project_name)
        # The command-bar write is GONE, and how it went is worth keeping.
        #
        # `LLR-120.1` said the new writes replace "its single write to the
        # command bar". Section 7's Inc-8 row said the 14 `_project_label()`
        # call sites are re-pointed "WHILE BOTH SURFACES EXIST" — which is false
        # the moment Inc-7 removes one. Executed at Inc-7: deleting the write
        # there reddened 10 shipped tests across `test_tui_variants.py` and
        # `test_tui_patch_variant.py`, because `_project_label()` read
        # `#cmdbar_project`.
        #
        # So Inc-7 KEPT it, Inc-8 re-pointed the readers while both surfaces
        # were live, and Inc-10 deleted it with the row it wrote into.
        # "Replacing" was discharged across Inc-7 + Inc-10 rather than inside
        # either one, and no increment ever had to choose between a green gate
        # and an honest one.
        # batch-94 (HLR-006): the variant-select refresh chain is gone — the
        # Patch Editor no longer carries a variant dropdown to re-sync.
        # batch-95 change 2 (HLR-139): the open-folder chips dim/enabled state
        # keys off the same project context, so the one project-refresh seam
        # re-resolves every mounted chip (the modal Reports chip re-resolves on
        # its own mount). Chips not mounted yet refresh at their on_mount.
        for chip in self.query(OpenFolderChip):
            chip.refresh_target()

    @staticmethod
    def _clip_to(text: str, cap: int) -> str:
        """Clip ``text`` to ``cap`` terminal COLUMNS, marking the loss with an ellipsis.

        Columns, not code points, and the distinction is the whole point.
        The first version of this measured ``len(text)``. A CJK project name is
        one code point and TWO columns per character, so a string that passed
        the budget check painted up to 2x the cell width and CSS resumed
        clipping the tail — restoring the exact eviction this bound removes,
        on a legal Windows directory name. Measured: a 42-character CJK project
        composed to 55 code points and **101 columns** against an 81-column
        budget.

        ``cell_len`` / ``set_cell_size`` come from ``rich``, already a hard
        dependency via Textual, and ``set_cell_size`` handles the case a manual
        slice cannot: a cap that falls in the MIDDLE of a double-width
        character, where the correct result is a pad space rather than half a
        glyph.
        """
        if cap <= 0:
            return ""
        if cell_len(text) <= cap:
            return text
        if cap == 1:
            return "…"
        return set_cell_size(text, cap - 1) + "…"

    def _compose_context_line(self, project_name: str, a2l_name: str) -> str:
        """Compose `#status_context` with the two halves bounded against EACH OTHER.

        Summary:
            HLR-120 requires the bar to name the project AND the A2L on all 10
            screens. The cell is one `Label` holding one string, clipped by CSS
            at `max-width: 70%` -- so whichever half comes second is the half
            that disappears, and nothing in the stylesheet can bound them
            independently. This method is that bound.

        Why it exists (measured, not theorised):
            With project `ECU_calibration_release_2026_customerA_v161` and A2L
            `ASAP2_ECU_calibration_release_2026_v161.a2l`, the composed string
            is 91 columns while the cell is allocated **53** at 80x24 and **81**
            at 120x30. `render()` returned the full 91 either way -- the loss is
            in the PAINTED strip. Result: the A2L was absent on **0 of 10**
            screens at both sizes, against a threshold of 10 of 10. It was
            visible before this batch, on the command bar that HLR-118 deleted,
            so this was a REGRESSION and not merely an unmet new requirement.

        Allocation:
            Fair share with slack redistribution -- each half may take half the
            budget, and a half that needs less lends the remainder to the other.
            Neither can evict the other, and a short name is never truncated
            just because its partner is long.

        Args:
            project_name (str): The composed project string (already in its
                LLR-120.5 display form).
            a2l_name (str): The A2L filename, or the absent sentinel.

        Returns:
            str: The two halves joined by ``_CONTEXT_SEPARATOR``, each clipped
            with a trailing ellipsis only when the budget forces it.
        """
        sep = self._CONTEXT_SEPARATOR
        # From the TERMINAL width, never from the bar's cached size -- see
        # `_CONTEXT_BAR_INSET`. The bar is stale mid-resize; `App.size` is not.
        try:
            terminal_width = self.size.width
        except Exception:
            terminal_width = 0
        bar_width = max(0, terminal_width - self._CONTEXT_BAR_INSET)
        budget = (
            int(bar_width * self._CONTEXT_MAX_SHARE)
            if bar_width > 0
            else self._CONTEXT_FALLBACK_BUDGET
        )
        # Every measurement below is in terminal COLUMNS (`cell_len`), never in
        # code points. `len()` under-counts double-width characters by 2x and
        # was how the first version of this bound let a CJK name overflow.
        avail = max(0, budget - cell_len(sep))
        project_w = cell_len(project_name)
        a2l_w = cell_len(a2l_name)

        if project_w + a2l_w <= avail:
            return f"{project_name}{sep}{a2l_name}"

        half = avail // 2
        if project_w <= half:
            # The project fits in its share; the A2L takes the slack.
            project_cap = project_w
            a2l_cap = avail - project_cap
        elif a2l_w <= avail - half:
            # The A2L fits in its share; the project takes the slack.
            a2l_cap = a2l_w
            project_cap = avail - a2l_cap
        else:
            # Both overflow: split evenly, so neither can evict the other.
            project_cap = half
            a2l_cap = avail - half

        return (
            f"{self._clip_to(project_name, project_cap)}{sep}"
            f"{self._clip_to(a2l_name, a2l_cap)}"
        )

    def _compose_project_label(self) -> str:
        """Compose the active project string in whichever display form applies.

        Summary:
            LLR-120.5's two forms, decided in ONE place: the plain project name
            when the active project holds at most one variant, and
            ``project:variant (index/total)`` when it holds more than one. Both
            context surfaces are handed the result of this method, so neither
            can re-derive a form the other does not have.

        Returns:
            str: The composed project string, or ``"(none)"`` when no project is
            active.

        Data Flow:
            - Read-only over ``current_project`` and ``_variant_set``.

        Dependencies:
            Uses:
                - ``_variant_display_options``
            Used by:
                - ``update_project_labels`` and ``_refresh_loaded_panel``
        """
        project_name = self.current_project or "(none)"
        variant_set = self._variant_set
        if (
            self.current_project
            and variant_set is not None
            and len(variant_set.variants) > 1
            and variant_set.active_id is not None
        ):
            options = self._variant_display_options(variant_set)
            active_index = next(
                (
                    index
                    for index, variant in enumerate(variant_set.variants)
                    if variant.variant_id == variant_set.active_id
                ),
                0,
            )
            display = options[active_index][1]
            project_name = (
                f"{self.current_project}:{display} "
                f"({active_index + 1}/{len(variant_set.variants)})"
            )
        return project_name
