"""s19_app.tui.app.issues_checks — S19TuiApp mixin: issues_checks (moved verbatim from s19_app/tui/app.py at 4f721985)."""
from __future__ import annotations

import time
from typing import Any, Optional
from textual.widgets import Static
from rich.text import Text
from ..insight_style import CYAN, RED, YELLOW
from ..issues_view import (
    _GROUP_DISPLAY_MAX,
    GroupedIssuesPanel,
    SEVERITY_ORDER,
    build_issues_severity_strip,
)
from ..checks_view import CHECK_GROUP_ORDER, GroupedChecksPanel, build_checks_aggregate_strip
from ...validation import ValidationIssue, ValidationSeverity
from . import deps


#: Display rank for the Issues-list sort (R-TUI-042b.5): ERROR → WARNING →
#: INFO in the fixed ``issues_view.SEVERITY_ORDER`` display order, so the
#: filtered list, the grouped panel, the paging and the summary line all
#: share one order. A severity outside ``SEVERITY_ORDER`` (OK, NEUTRAL) has
#: no entry here and is given the default rank ``len(SEVERITY_ORDER)`` — after
#: INFO — by ``_filtered_validation_issues`` (E3 A-5 / S-5). Distinct from
#: ``_A2L_ISSUE_SEVERITY_RANK`` above, which ranks all five severities
#: ascending to pick the worst per symbol.
_ISSUE_DISPLAY_RANK: dict[ValidationSeverity, int] = {
    severity: rank for rank, severity in enumerate(SEVERITY_ORDER)
}


class IssuesChecksMixin:

    def _issues_page_size(self) -> int:
        """
        Summary:
            Return the Issues screen's paging stride, bounded by the grouped
            panel's mount cap. The grouped Issues panel mounts at most
            ``_GROUP_DISPLAY_MAX`` non-virtualized ``IssueRow`` widgets (a DoS
            cap), so the paging stride must never exceed it — otherwise rows past
            the cap are truncated AND skipped by PgUp/PgDn, i.e. unreachable
            (field-audit B1). A smaller configured ``validation_issues_page_size``
            is honoured; a larger one is capped at ``_GROUP_DISPLAY_MAX``.

        Args:
            None

        Returns:
            int: ``min(_GROUP_DISPLAY_MAX, clamped validation_issues_page_size)``.

        Data Flow:
            - Read the (clamped) configured issues page size and cap at the
              grouped-panel mount limit.

        Dependencies:
            Uses:
                - ``_clamp_viewer_page_size`` / ``issues_view._GROUP_DISPLAY_MAX``
            Used by:
                - ``update_validation_issues_view``
                - ``_render_validation_issues_groups``
                - ``action_validation_issues_page_next`` / ``_page_prev``
        """
        return min(_GROUP_DISPLAY_MAX, self._clamp_viewer_page_size(self.validation_issues_page_size))

    def _update_issues_hex_pane(self, address: Optional[int]) -> None:
        """Render the selected issue's address bytes in ``#issues_hex_pane`` (US-020a).

        Summary:
            On an Issues-table row selection, show a focused hex+ASCII window
            around the issue's ``address`` in the Issues screen's hex pane
            (``#issues_hex_pane``, LLR-020.2). When the issue carries no address
            (a cross-artifact issue) or no file is loaded, show a fixed
            placeholder and clear any bytes from a prior selection — never a
            stale render.

        Args:
            address (Optional[int]): The selected issue's address, or ``None``.

        Returns:
            None

        Data Flow:
            - No pane present (Issues screen not composed) → no-op.
            - ``address`` is ``None`` / no file → the placeholder string.
            - Else render a ±``context``-row window via ``render_hex_view_text``
              focused at ``address`` into the pane.

        Dependencies:
            Uses:
                - ``render_hex_view_text``
            Used by:
                - ``on_issue_row_selected``
        """
        # A call with no mounted screen has no DOM to query; skip the
        # best-effort pane update.
        if not self.screen_stack:
            return
        matches = self.query("#issues_hex_pane")
        if not matches:
            return
        pane = matches.first(Static)
        if not isinstance(address, int) or not self.current_file:
            pane.update("(issue has no address — nothing to show)")
            return
        base = address - (address % 16)
        context_rows = 6
        low = max(0, base - 16 * context_rows)
        row_bases = list(range(low, base + 16 * (context_rows + 1), 16))
        pane.update(
            deps.render_hex_view_text(self.current_file.mem_map, address, row_bases, None)
        )

    def _deduplicate_issues(self, issues: list[ValidationIssue]) -> list[ValidationIssue]:
        """Drop duplicate issues by stable identity tuple while preserving order."""
        deduped: list[ValidationIssue] = []
        seen: set[tuple[Any, ...]] = set()
        for issue in issues:
            key = (
                issue.code,
                issue.severity.value,
                issue.message,
                issue.artifact,
                issue.symbol,
                issue.address,
                issue.line_number,
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(issue)
        return deduped

    def _filtered_validation_issues(self) -> list[ValidationIssue]:
        """Return cached validation issues filtered by active severity mode."""
        if self.validation_issue_filter_mode == "error":
            filtered = [item for item in self._validation_issues if item.severity == ValidationSeverity.ERROR]
        elif self.validation_issue_filter_mode == "warning":
            filtered = [item for item in self._validation_issues if item.severity == ValidationSeverity.WARNING]
        else:
            filtered = list(self._validation_issues)
        return sorted(
            filtered,
            key=lambda issue: _ISSUE_DISPLAY_RANK.get(
                issue.severity, len(SEVERITY_ORDER)
            ),
        )

    def _update_issues_severity_strip(
        self, error: int, warning: int, info: int
    ) -> None:
        """
        Summary:
            Repaint the ``#issues_severity_strip`` from the whole-list severity
            counts via :func:`build_issues_severity_strip` (batch-49, LLR-082.2).
            A guarded no-op when the strip is not mounted (no active screen /
            widget absent), mirroring ``_update_mac_coverage_strip``'s guard.

        Args:
            error (int): Whole-list ERROR count.
            warning (int): Whole-list WARNING count.
            info (int): Whole-list INFO count.

        Returns:
            None

        Data Flow:
            - Query ``#issues_severity_strip``; on absence, return.
            - Hand the three counts to ``build_issues_severity_strip`` and push
              the resulting markup-safe ``Text`` into the strip.

        Dependencies:
            Uses:
                - ``build_issues_severity_strip``
            Used by:
                - ``update_validation_issues_view``
        """
        try:
            strip = self.query_one("#issues_severity_strip", Static)
        except Exception:
            return
        if strip is None:  # headless unit tests fake query_one -> None
            return
        strip.update(build_issues_severity_strip(error, warning, info))

    def update_checks_view(self) -> None:
        """
        Summary:
            Rebuild the read-only CHECKS screen (``#screen_checks``) from the
            last check run (batch-49, LLR-084.3): group the
            ``ChangeService.check_display_rows()`` fail → uncheckable → pass
            into ``#checks_grouped`` and repaint the pass/fail/uncheckable
            ``#checks_aggregate_strip`` from ``check_aggregates()``. When a
            file is loaded but no check run is current (``check_run_is_current``
            is ``False`` — no run yet, or the document / image it ran over
            changed), render the distinct "no check run yet" note instead of a
            zeroed list (LLR-084.6, R-6). A guarded no-op when the screen is
            not mounted (no active screen / widget absent), mirroring
            ``_render_validation_issues_groups`` plus the headless
            ``query_one -> None`` guard (Inc-1 F1).

        Args:
            None

        Returns:
            None

        Data Flow:
            - No mounted screen (headless / monkeypatched call) or no
              ``#checks_grouped`` panel present → no-op.
            - Read ``check_display_rows()`` + ``check_aggregates()``; when
              ``check_run_is_current()`` is ``False`` render the no-run note,
              else group
              the rows by ``result`` and render them; always repaint the
              aggregate strip (all-zero when no run — it rides the reset).

        Dependencies:
            Uses:
                - ``ChangeService.check_display_rows`` / ``check_aggregates``
                - ``GroupedChecksPanel.render_groups`` / ``render_no_run``
                - ``build_checks_aggregate_strip``
            Used by:
                - ``action_show_screen`` (the ``checks`` nav-refresh hook)
        """
        if not self.screen_stack:
            return
        try:
            panel = self.query_one("#checks_grouped", GroupedChecksPanel)
        except Exception:
            return
        if panel is None:  # headless unit tests fake query_one -> None
            return
        rows = self._change_service.check_display_rows()
        aggregates = self._change_service.check_aggregates()
        if not self._change_service.check_run_is_current():
            panel.render_no_run()
        else:
            group_counts = {
                token: sum(1 for row in rows if row.result == token)
                for token in CHECK_GROUP_ORDER
            }
            panel.render_groups(rows, group_counts)
        try:
            strip = self.query_one("#checks_aggregate_strip", Static)
        except Exception:
            return
        if strip is None:
            return
        strip.update(build_checks_aggregate_strip(aggregates))

    def update_validation_issues_view(self) -> None:
        """
        Summary:
            Compute the aggregate validation-issue counts + paging summary line,
            push them into the ``#validation_issues_summary`` ``Label``, and
            render the grouped Issues view via ``_render_validation_issues_groups``.

        Args:
            None

        Returns:
            None

        Data Flow:
            - Resolve the filtered list via ``_filtered_validation_issues``.
            - Short-circuit with a summary-only message when there are no issues
              (still re-rendering the grouped panel so it clears).
            - Compute aggregate counts (errors/warnings/info) and a page-number line.
            - Render the current paging window through
              ``_render_validation_issues_groups`` — the sole Issues surface
              since batch-29 retired the legacy Issues DataTable.

        Dependencies:
            Uses:
                - ``_filtered_validation_issues``
                - ``_clamp_viewer_page_size`` / ``_get_window_bounds``
                - ``_render_validation_issues_groups``
            Used by:
                - ``_apply_prepared_load`` (post-load refresh)
                - ``update_mac_view`` (when MAC/validation input changes)
                - issue filter buttons and paging actions
        """
        populate_started = time.perf_counter()
        summary_label = self.query_one("#validation_issues_summary", deps.Label)
        filtered = self._filtered_validation_issues()
        # Whole-list severity distribution (batch-49, LLR-082.2) — computed
        # before the empty-filter short-circuit so the strip reflects the full
        # distribution (a 0/0/0 boundary only when the list is truly empty).
        severity_counts = {
            ValidationSeverity.ERROR: sum(
                1
                for item in self._validation_issues
                if item.severity == ValidationSeverity.ERROR
            ),
            ValidationSeverity.WARNING: sum(
                1
                for item in self._validation_issues
                if item.severity == ValidationSeverity.WARNING
            ),
            ValidationSeverity.INFO: sum(
                1
                for item in self._validation_issues
                if item.severity == ValidationSeverity.INFO
            ),
        }
        error_count = severity_counts[ValidationSeverity.ERROR]
        warning_count = severity_counts[ValidationSeverity.WARNING]
        info_count = severity_counts[ValidationSeverity.INFO]
        self._update_issues_severity_strip(error_count, warning_count, info_count)
        if not filtered:
            summary_label.update("No validation issues.")
            self._render_validation_issues_groups()
            self.logger.info(
                "Load phase boundary: populate_issues_table_done rows=0 elapsed=%.3f",
                time.perf_counter() - populate_started,
            )
            self._flush_logger()
            return
        total = len(filtered)
        page_size = self._issues_page_size()
        max_start = max(0, ((total - 1) // page_size) * page_size) if total else 0
        self._validation_issues_window_start = max(0, min(self._validation_issues_window_start, max_start))
        start, end = self._get_window_bounds(total, self._validation_issues_window_start, page_size)
        self._validation_issues_window_start = start
        page_num = start // page_size + 1
        total_pages = max(1, (total + page_size - 1) // page_size)
        # Severity-coloured summary line (batch-49, LLR-082.5): the errors/
        # warnings/info tokens carry RED/YELLOW/CYAN spans, but the ``.plain``
        # content stays byte-identical to the former " | ".join(...) so existing
        # summary tests keep passing. Built via append (never Text.from_markup).
        summary = Text()
        summary.append(f"total={len(self._validation_issues)}")
        summary.append(" | ")
        summary.append(f"errors={error_count}", style=RED)
        summary.append(" | ")
        summary.append(f"warnings={warning_count}", style=YELLOW)
        summary.append(" | ")
        summary.append(f"info={info_count}", style=CYAN)
        summary.append(" | ")
        summary.append(f"filter={self.validation_issue_filter_mode}")
        summary.append(" | ")
        summary.append(f"page {page_num}/{total_pages} rows {start + 1}-{end}/{total}")
        summary_label.update(summary)
        self._render_validation_issues_groups()
        self.logger.info(
            "Load phase boundary: populate_issues_table_done rows=%d total=%d elapsed=%.3f",
            end - start,
            total,
            time.perf_counter() - populate_started,
        )
        self._flush_logger()

    def _render_validation_issues_groups(self) -> None:
        """
        Summary:
            Render the grouped-by-severity dense Issues view
            (``#validation_issues_groups``) — the sole Issues surface since
            batch-29 — from the current filtered list + paging window
            (US-039 / LLR-042.3/.4/.6). Groups render in error →
            warning → info order; each group-header count is the whole
            (filtered) list count for that severity, while only the current
            bounded paging window of rows is mounted — a hostile large-N issue
            list therefore cannot mount O(N) row widgets.

        Args:
            None

        Returns:
            None

        Data Flow:
            - No mounted screen (headless / monkeypatched unit call) or no
              grouped panel present → no-op.
            - Else resolve the filtered list, reuse ``_get_window_bounds`` /
              ``page_size`` for the window, tally per-severity whole-filtered
              counts, and hand them to ``GroupedIssuesPanel.render_groups``.

        Dependencies:
            Uses:
                - ``_filtered_validation_issues`` / ``_clamp_viewer_page_size``
                  / ``_get_window_bounds``
                - ``GroupedIssuesPanel.render_groups``
            Used by:
                - ``update_validation_issues_view``
        """
        if not self.screen_stack:
            return
        panels = self.query("#validation_issues_groups")
        if not panels:
            return
        panel = panels.first(GroupedIssuesPanel)
        filtered = self._filtered_validation_issues()
        if not filtered:
            panel.render_groups([], {}, truncated=False)
            return
        total = len(filtered)
        page_size = self._issues_page_size()
        start, end = self._get_window_bounds(
            total, self._validation_issues_window_start, page_size
        )
        window = filtered[start:end]
        group_counts = {
            ValidationSeverity.ERROR: sum(
                1 for item in filtered if item.severity == ValidationSeverity.ERROR
            ),
            ValidationSeverity.WARNING: sum(
                1 for item in filtered if item.severity == ValidationSeverity.WARNING
            ),
            ValidationSeverity.INFO: sum(
                1 for item in filtered if item.severity == ValidationSeverity.INFO
            ),
        }
        panel.render_groups(window, group_counts, truncated=(end - start) < total)

    def on_issue_row_selected(self, event: "IssueRow.Selected") -> None:
        """
        Summary:
            Repaint the retained ``#issues_hex_pane`` when an issue row in the
            grouped view is activated by a real click or ``Enter`` (LLR-042.5,
            C-16 real mechanism). An ``address is None`` issue yields the
            neutral peek placeholder, never a crash.

        Args:
            event (IssueRow.Selected): The row-activation message carrying the
                selected issue's integer address (or ``None``).

        Returns:
            None

        Dependencies:
            Uses:
                - ``_update_issues_hex_pane``
            Used by:
                - Textual message dispatch (from ``IssueRow``)
        """
        self._update_issues_hex_pane(event.address)

    def on_check_row_selected(self, event: "CheckRow.Selected") -> None:
        """
        Summary:
            Repaint the retained ``#checks_hex_pane`` when a CHECKS row is
            activated by a real click or ``Enter`` (batch-49, LLR-084.5, C-16
            real mechanism). Mirrors ``on_issue_row_selected``: an
            ``address is None`` entry (an uncheckable/unaddressed check) yields
            the neutral peek placeholder, never a crash.

        Args:
            event (CheckRow.Selected): The row-activation message carrying the
                selected check entry's integer address (or ``None``).

        Returns:
            None

        Dependencies:
            Uses:
                - ``_update_checks_hex_pane``
            Used by:
                - Textual message dispatch (from ``CheckRow``)
        """
        self._update_checks_hex_pane(event.address)

    def _update_checks_hex_pane(self, address: Optional[int]) -> None:
        """Render the selected check entry's address bytes in ``#checks_hex_pane`` (LLR-084.5).

        Summary:
            On a CHECKS-row selection, show a focused hex+ASCII window around the
            entry's ``address`` in the Checks screen's hex pane
            (``#checks_hex_pane``). When the entry carries no address (an
            uncheckable entry with ``actual_bytes=None`` and no resolvable
            location) or no file is loaded, show a fixed placeholder and clear
            any bytes from a prior selection — never a stale render. Mirrors
            ``_update_issues_hex_pane`` (``app.py`` Issues peek), including its
            headless/absent-pane guards (the Inc-1 F1 ``query_one -> None``
            shape) so a row-select on an unmounted tree is a safe no-op.

        Args:
            address (Optional[int]): The selected entry's address, or ``None``.

        Returns:
            None

        Data Flow:
            - No mounted screen (headless call) or no ``#checks_hex_pane`` present
              → no-op.
            - ``address`` is not an int / no file → the placeholder string.
            - Else render a ±``context``-row window via ``render_hex_view_text``
              focused at ``address`` into the pane.

        Dependencies:
            Uses:
                - ``render_hex_view_text``
            Used by:
                - ``on_check_row_selected``
        """
        # No mounted screen (e.g. a headless unit-test call) -> no DOM to query.
        if not self.screen_stack:
            return
        matches = self.query("#checks_hex_pane")
        if not matches:
            return
        pane = matches.first(Static)
        if pane is None:  # headless unit tests fake query -> None (Inc-1 F1)
            return
        if not isinstance(address, int) or not self.current_file:
            pane.update("(check entry has no address — nothing to show)")
            return
        base = address - (address % 16)
        context_rows = 6
        low = max(0, base - 16 * context_rows)
        row_bases = list(range(low, base + 16 * (context_rows + 1), 16))
        pane.update(
            deps.render_hex_view_text(self.current_file.mem_map, address, row_bases, None)
        )

    def action_validation_issues_page_next(self) -> None:
        """Advance the validation-issues viewer window by one configured page."""
        total = len(self._filtered_validation_issues())
        if total == 0:
            return
        page_size = self._issues_page_size()
        max_start = max(0, ((total - 1) // page_size) * page_size)
        self._validation_issues_window_start = min(
            max_start, self._validation_issues_window_start + page_size
        )
        self.update_validation_issues_view()

    def action_validation_issues_page_prev(self) -> None:
        """Rewind the validation-issues viewer window by one configured page."""
        if not self._validation_issues:
            return
        page_size = self._issues_page_size()
        self._validation_issues_window_start = max(
            0, self._validation_issues_window_start - page_size
        )
        self.update_validation_issues_view()
