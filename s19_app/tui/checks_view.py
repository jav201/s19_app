"""Grouped-by-outcome dense view widgets for the dedicated CHECKS screen.

Batch-49 · R-TUI-084 · US-083 (HLR-084). These presentational widgets render
the already-computed ``ChangeService.check_display_rows()`` — one
:class:`CheckDisplayRow` per ``CheckRunEntry`` of the last check run — grouped
by outcome (fail → uncheckable → pass) with a per-group count header, a
pass/fail/uncheckable aggregate strip, and a per-row hex-peek address. It is the
read-only rail mirror of the Patch Editor's compact check window; it neither
runs checks nor mutates any state.

Parallel to ``issues_view.py``: :class:`CheckGroupHeader` / :class:`CheckRow` /
:class:`GroupedChecksPanel` mirror ``IssueGroupHeader`` / ``IssueRow`` /
``GroupedIssuesPanel`` (same ``safe_text`` / ``_GROUP_DISPLAY_MAX`` idioms).

C-17 markup-safety (LLR-084.8): every file-derived string reaching this view — a
row's rendered ``text`` (which folds in the entry ``reason`` on uncheckable
rows) and the entry ``linkage_symbol`` — is composed through ``safe_text`` as a
literal ``rich.text.Text``, never interpolated into a Rich-markup-parsed string
and never handed to a markup-parsing widget over the raw value. A hostile token
such as ``x[link=file:///etc]`` or a raw ANSI byte therefore renders LITERAL: no
``MarkupError``, no style/ANSI leak, no OSC-8 hyperlink escape, no crash.

No engine code is imported here — the widgets receive their data via
``GroupedChecksPanel.render_groups`` and emit a :class:`CheckRow.Selected`
message back to ``app.py`` (which drives the hex pane); colour flows exclusively
through the frozen ``css_class_for_severity`` (no hard-coded hex), and the
aggregate strip / group glyphs carry only ints + author constants.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, List, Mapping, Optional, Sequence

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal, ScrollableContainer
from textual.message import Message
from textual.widgets import Static

from .insight_style import GREEN, microbar
from .screens_directionb import safe_text

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .services.change_service import CheckDisplayRow

#: Max :class:`CheckRow` widgets mounted across all groups on one render (perf /
#: UX cap), mirroring ``issues_view._GROUP_DISPLAY_MAX``. Each row is a
#: ``Horizontal`` composing one-or-two ``Static`` children, so an oversized run
#: would remount hundreds of non-virtualized widgets and stall Textual's message
#: pump. The CHECKS screen is a dense read-only mirror; we mount at most this
#: many rows and append a truncation note when the run holds more (LLR-084.1,
#: DoS bound TC-084.10).
_CHECK_DISPLAY_MAX: int = 40

#: Fixed render order for the outcome groups (LLR-084.1: fail → uncheckable →
#: pass), keyed by the ``CheckRunEntry.result`` token.
CHECK_GROUP_ORDER: tuple[str, ...] = ("fail", "uncheckable", "pass")

#: Human-readable group labels, keyed by result token.
_GROUP_LABEL: Dict[str, str] = {
    "fail": "FAILED",
    "uncheckable": "UNCHECKABLE",
    "pass": "PASSED",
}

#: Author-controlled leading glyph per outcome group header (LLR-084.1). A
#: closed map keyed by :data:`CHECK_GROUP_ORDER`; the glyphs are fixed author
#: constants (never file-derived — C-17), matching the Patch Editor's check
#: vocabulary (``change_service.GLYPH_FAIL`` / ``GLYPH_UNCHECKABLE`` /
#: ``GLYPH_PASS``).
_CHECK_GROUP_GLYPH: Dict[str, str] = {
    "fail": "✗",
    "uncheckable": "◐",
    "pass": "✓",
}

#: Micro-bar cell count for the CHECKS aggregate strip (LLR-084.4) — the fixed
#: small scale reused from the Patch Editor's ``_CHECK_STRIP_BAR_CELLS`` (8).
_CHECKS_STRIP_BAR_CELLS: int = 8


def build_checks_aggregate_strip(aggregates: Mapping[str, int]) -> Text:
    """
    Summary:
        Build the CHECKS pass/fail/uncheckable aggregate strip as a C-17-safe
        Rich ``Text``: ``Pass N / Fail M / Uncheck K`` followed by a
        proportional :func:`microbar` whose fill fraction is ``passed / total``
        (LLR-084.4), rendered in :data:`GREEN`. The line carries ONLY integer
        counts and author constants — no file-derived text reaches this sink.

    Args:
        aggregates (Mapping[str, int]): The check run's aggregate counts, keyed
            ``"passed"`` / ``"failed"`` / ``"uncheckable"`` (the
            ``ChangeService.check_aggregates()`` contract — all-zero when no
            run is current, so the strip clears by riding that reset). Missing
            keys default to ``0``.

    Returns:
        rich.text.Text: The composed strip, built via ``append`` /
        ``append_text`` (never markup parsing) so it is markup-safe by
        construction. ``total == 0`` renders an empty bar with no division.

    Data Flow:
        - Read the three counts, sum for the total, compute the pass fraction
          (guarded → ``0.0`` when total is 0), append the count line + bar.
        - Consumed by ``S19TuiApp.update_checks_view`` →
          ``#checks_aggregate_strip`` (batch-49 Inc-3).

    Dependencies:
        Uses:
            - ``insight_style.microbar`` / ``GREEN``
        Used by:
            - ``S19TuiApp.update_checks_view``
            - ``tests/test_tui_checks_view.py``

    Example:
        >>> build_checks_aggregate_strip(
        ...     {"passed": 2, "failed": 1, "uncheckable": 1}
        ... ).plain
        'Pass 2 / Fail 1 / Uncheck 1  ████░░░░'
        >>> build_checks_aggregate_strip(
        ...     {"passed": 0, "failed": 0, "uncheckable": 0}
        ... ).plain
        'Pass 0 / Fail 0 / Uncheck 0  ░░░░░░░░'
    """
    passed = int(aggregates.get("passed", 0))
    failed = int(aggregates.get("failed", 0))
    uncheckable = int(aggregates.get("uncheckable", 0))
    total = passed + failed + uncheckable
    text = Text()
    text.append(f"Pass {passed} / Fail {failed} / Uncheck {uncheckable}  ")
    frac = passed / total if total else 0.0
    text.append_text(microbar(frac, _CHECKS_STRIP_BAR_CELLS, style=GREEN))
    return text


class CheckGroupHeader(Static):
    """A per-outcome group header carrying its label, glyph and entry count.

    Summary:
        One header precedes each outcome group in the grouped CHECKS view
        (LLR-084.1). It renders ``"<glyph> <LABEL>  (<count>)"`` (the leading
        author-constant glyph from :data:`_CHECK_GROUP_GLYPH`) as markup-safe
        text and is coloured by the ``css_class`` handed down by
        ``render_groups`` — the SAME single-sourced class its rows carry (from
        the accessor's ``_CHECK_RESULT_SEVERITY``), so the header colour cannot
        drift from the row colour. The label and integer count are also stored
        as attributes so a white-box test can read the count without parsing the
        rendered string.

    Args:
        result (str): The group's result token — ``"fail"`` / ``"uncheckable"``
            / ``"pass"`` — used only for the label + glyph identity.
        count (int): The whole-run count for this outcome.
        css_class (str): The ``sev-*`` class for the group, passed down from a
            row of the group (single-sourced from the accessor's
            ``css_class_for_severity`` — no local severity map to drift).

    Returns:
        None

    Data Flow:
        - Mounted by ``GroupedChecksPanel.render_groups``; read-only display.

    Dependencies:
        Uses:
            - ``safe_text``
        Used by:
            - ``GroupedChecksPanel.render_groups``

    Example:
        >>> h = CheckGroupHeader("fail", 3, css_class="sev-error")
        >>> (h.result_label, h.check_count)
        ('FAILED', 3)
    """

    def __init__(self, result: str, count: int, css_class: str) -> None:
        label = _GROUP_LABEL.get(result, result.upper())
        glyph = _CHECK_GROUP_GLYPH.get(result, "")
        super().__init__(
            safe_text(f"{glyph} {label}  ({count})"),
            classes=f"check-group-header {css_class}",
        )
        #: The group's display label (e.g. ``"FAILED"``).
        self.result_label: str = label
        #: The whole-run count this header reports.
        self.check_count: int = count


class CheckRow(Horizontal):
    """A focusable, clickable single-check row: the check detail + linkage cell.

    Summary:
        Renders one :class:`CheckDisplayRow` as a horizontal row holding a
        ``.check-detail`` span (address range · expected/actual bytes · result ·
        reason) beside an optional ``.check-linkage`` cell (the entry's
        ``linkage_symbol`` when linked). Both cells are markup-safe
        ``rich.text.Text`` built via ``safe_text`` (LLR-084.8), so hostile
        file-derived tokens render literal. The row is ``can_focus`` and on a
        real click or ``Enter`` posts :class:`Selected` carrying the entry's
        integer ``address`` (or ``None``), which ``app.py`` consumes to repaint
        the ``#checks_hex_pane`` (LLR-084.5). Purely presentational — it never
        parses or validates.

    Args:
        row (CheckDisplayRow): The already-shaped display row to render.

    Returns:
        None

    Data Flow:
        - Mounted by ``GroupedChecksPanel.render_groups``; :meth:`compose`
          yields the detail span and (when present) the linkage cell (both
          ``safe_text``). On click / ``Enter`` posts :class:`Selected` →
          ``S19TuiApp.on_check_row_selected``.

    Dependencies:
        Uses:
            - ``css_class_for_severity`` (via the row's ``css_class``) /
              ``safe_text``
        Used by:
            - ``GroupedChecksPanel.render_groups``
    """

    can_focus = True

    class Selected(Message):
        """A check row was activated (real click or ``Enter``).

        Args:
            address (Optional[int]): The activated entry's integer address, or
                ``None`` when the entry carries no address.
        """

        def __init__(self, address: Optional[int]) -> None:
            super().__init__()
            self.address = address

    def __init__(self, row: "CheckDisplayRow") -> None:
        self.row = row
        self.address: Optional[int] = (
            row.address if isinstance(row.address, int) else None
        )
        self._sev_class = row.css_class
        super().__init__(classes=f"check-row {self._sev_class}")

    def compose(self) -> ComposeResult:
        """Yield the markup-safe detail span and the optional linkage cell."""
        yield Static(
            safe_text(self.row.text),
            classes=f"check-detail {self._sev_class}",
        )
        linkage = self.row.linkage_symbol
        if linkage:
            yield Static(safe_text(linkage), classes="check-linkage")

    def on_click(self) -> None:
        """Focus and post :class:`Selected` on a real pointer click."""
        self.focus()
        self.post_message(self.Selected(self.address))

    def on_key(self, event) -> None:  # type: ignore[no-untyped-def]
        """Post :class:`Selected` on ``Enter`` (consumed); other keys pass."""
        if event.key == "enter":
            event.stop()
            self.post_message(self.Selected(self.address))


class GroupedChecksPanel(ScrollableContainer):
    """Scrollable grouped-by-outcome dense view of the last check run.

    Summary:
        Renders the ``CheckDisplayRow`` list grouped by outcome in fail →
        uncheckable → pass order (:data:`CHECK_GROUP_ORDER`). Each present group
        is led by a :class:`CheckGroupHeader` reporting the whole-run count for
        that outcome, followed by up to :data:`_CHECK_DISPLAY_MAX`
        :class:`CheckRow` widgets (in group order). Because each row is a
        multi-``Static`` ``Horizontal``, an oversized run is display-capped —
        mounted rows stay ``<= _CHECK_DISPLAY_MAX`` — and a truncation note is
        appended when the cap hides rows. Distinct empty states: a neutral note
        when there is nothing to group, and :data:`NO_RUN_TEXT` when a file is
        loaded but no check has run yet. Purely presentational.

    Args:
        id (str): The widget id (``#checks_grouped``).

    Returns:
        None

    Data Flow:
        - ``S19TuiApp.update_checks_view`` computes the rows + per-outcome
          counts and calls ``render_groups``.
        - Row activation bubbles :class:`CheckRow.Selected` to the app.

    Dependencies:
        Uses:
            - ``CheckGroupHeader`` / ``CheckRow`` / ``safe_text``
        Used by:
            - ``S19TuiApp._compose_screen_checks`` / ``update_checks_view``

    Example:
        >>> panel = GroupedChecksPanel(id="checks_grouped")
        >>> panel.id
        'checks_grouped'
    """

    EMPTY_TEXT = "No check entries to group."
    #: The file-loaded-but-no-run empty state (LLR-084.6): distinct from a real
    #: 0/0/0 run so the two never conflate.
    NO_RUN_TEXT = "No check run yet — run checks from the Patch Editor."
    TRUNCATION_NOTE = "More check entries than shown — see the Patch Editor."

    def render_groups(
        self,
        rows: Sequence["CheckDisplayRow"],
        group_counts: Optional[Mapping[str, int]] = None,
    ) -> None:
        """Rebuild the grouped view from the display rows.

        Summary:
            Clear the mounted children and remount one :class:`CheckGroupHeader`
            per outcome present in ``rows`` (in the fixed fail → uncheckable →
            pass order) followed by that outcome's :class:`CheckRow` widgets,
            capping the total mounted row count across all groups to
            :data:`_CHECK_DISPLAY_MAX` (rows taken in group order until the
            budget is spent). Each header reports ``group_counts[token]`` when
            provided, else the count derived from ``rows``. A truncation note is
            appended when the display cap hid rows (LLR-084.1 DoS bound).

        Args:
            rows (Sequence[CheckDisplayRow]): The display rows to group + mount
                (from ``ChangeService.check_display_rows()``).
            group_counts (Optional[Mapping[str, int]]): Whole-run count per
                result token for the header counts; when ``None`` the counts
                are derived from ``rows``.

        Returns:
            None

        Data Flow:
            - ``remove_children`` then ``mount`` the header/row widgets; no data
              is derived here beyond grouping the passed rows by result.

        Dependencies:
            Uses:
                - ``CheckGroupHeader`` / ``CheckRow`` / ``safe_text``
            Used by:
                - ``S19TuiApp.update_checks_view``
        """
        self.remove_children()
        if not rows:
            self.mount(
                Static(
                    safe_text(self.EMPTY_TEXT),
                    classes="checks-empty-note sev-neutral",
                )
            )
            return
        widgets: List[Static] = []
        remaining = _CHECK_DISPLAY_MAX
        capped = False
        for token in CHECK_GROUP_ORDER:
            group_rows = [row for row in rows if row.result == token]
            if not group_rows:
                continue
            count = (
                group_counts.get(token, len(group_rows))
                if group_counts is not None
                else len(group_rows)
            )
            widgets.append(
                CheckGroupHeader(token, count, css_class=group_rows[0].css_class)
            )
            shown = group_rows[:remaining] if remaining > 0 else []
            widgets.extend(CheckRow(row) for row in shown)
            remaining -= len(shown)
            if len(shown) < len(group_rows):
                capped = True
        if capped:
            widgets.append(
                Static(
                    safe_text(self.TRUNCATION_NOTE),
                    classes="checks-truncation-note sev-neutral",
                )
            )
        if widgets:
            self.mount(*widgets)

    def render_no_run(self) -> None:
        """Render the file-loaded-but-no-run note (:data:`NO_RUN_TEXT`).

        Summary:
            Clear the mounted children and mount the single
            :data:`NO_RUN_TEXT` note — the LLR-084.6 state that is distinct
            from a real 0/0/0 run (which ``render_groups`` shows as
            :data:`EMPTY_TEXT`). ``S19TuiApp.update_checks_view`` calls this
            when a file is loaded but ``last_check_result is None``.

        Returns:
            None

        Dependencies:
            Used by:
                - ``S19TuiApp.update_checks_view``
        """
        self.remove_children()
        self.mount(
            Static(
                safe_text(self.NO_RUN_TEXT),
                classes="checks-no-run-note sev-neutral",
            )
        )
