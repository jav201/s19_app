"""Grouped-by-severity dense view widgets for the Issues Report screen.

Batch-28 · R-TUI-042 · US-039 (Direction B). These presentational widgets
render the already-computed ``S19TuiApp._validation_issues`` list grouped by
severity (errors → warnings → info) with a per-group count header and a
compact per-issue code "chip", replacing the old flat single-table read of the
Issues Report while the ``#validation_issues_list`` ``DataTable`` and the
``#issues_hex_pane`` peek are retained beside them (LLR-042.3/.4/.5/.6).

C-17 markup-safety (LLR-042.10): every file-derived string reaching this view
(an issue ``.code``, ``.symbol`` or ``.message``) is composed through the
batch-27 ``safe_text`` helper as a literal ``rich.text.Text`` — never
interpolated into a Rich-markup-parsed string and never handed to a
markup-parsing widget over the raw value. A loaded symbol such as ``sensor[red]`` or
``x[link=file:///etc]`` or a raw ANSI byte therefore renders LITERAL: no
``MarkupError``, no style/ANSI leak, no OSC-8 hyperlink escape, no crash.
``.symbol``/``.code`` are never scrubbed upstream (``validation/model.py`` is
engine-frozen), so this render layer is the sole defense.

No engine code is imported here — the widgets receive their data via
``GroupedIssuesPanel.render_groups`` and emit an ``IssueRow.Selected`` message
back to ``app.py`` (which drives ``_update_issues_hex_pane``); colour flows
exclusively through the frozen ``css_class_for_severity`` (no hard-coded hex).
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence

from textual.app import ComposeResult
from textual.containers import Horizontal, ScrollableContainer
from textual.message import Message
from textual.widgets import Static

from .color_policy import css_class_for_severity
from .screens_directionb import safe_text
from ..validation import ValidationIssue, ValidationSeverity

#: Max ``IssueRow`` widgets mounted across all groups on one page (perf/UX cap).
#:
#: Each :class:`IssueRow` is a ``Horizontal`` composing two ``Static`` children,
#: so mounting the full ``page_size`` (up to 200) paging window remounts ~600
#: non-virtualized widgets per :meth:`GroupedIssuesPanel.render_groups` call —
#: which floods Textual's message pump and makes a ~200-issue Issues screen take
#: tens of seconds to settle (batch-28 Inc-2 regression). The grouped view is a
#: dense *preview*; paging (PgUp/PgDn) already reaches the rest, so we mount at
#: most this many rows and append a truncation note when the current page holds
#: more. This tightens — never loosens — the LLR-042.6 DoS bound (mounted rows
#: stay ``<= _GROUP_DISPLAY_MAX <= page_size``).
_GROUP_DISPLAY_MAX: int = 40

#: Fixed render order for severity groups (LLR-042.3: error → warning → info).
SEVERITY_ORDER: tuple[ValidationSeverity, ...] = (
    ValidationSeverity.ERROR,
    ValidationSeverity.WARNING,
    ValidationSeverity.INFO,
)

#: Human-readable group labels, keyed by severity.
SEVERITY_LABELS: Dict[ValidationSeverity, str] = {
    ValidationSeverity.ERROR: "ERRORS",
    ValidationSeverity.WARNING: "WARNINGS",
    ValidationSeverity.INFO: "INFO",
}


class IssueGroupHeader(Static):
    """A per-severity group header carrying the group's label and issue count.

    Summary:
        One header precedes each severity group in the grouped Issues view
        (LLR-042.3). It renders ``"<LABEL>  (<count>)"`` as markup-safe text
        and is coloured by the group's severity through the frozen
        ``css_class_for_severity`` (LLR-042.4 palette source; no hard-coded
        hex). The label and integer count are also stored as attributes so a
        white-box test can read the count without parsing the rendered string.

    Args:
        severity (ValidationSeverity): The group's severity.
        count (int): The whole-(filtered)-list count for this severity — NOT
            the windowed subset (LLR-042.6).

    Returns:
        None

    Data Flow:
        - Mounted by ``GroupedIssuesPanel.render_groups``; read-only display.

    Dependencies:
        Uses:
            - ``css_class_for_severity`` / ``safe_text``
        Used by:
            - ``GroupedIssuesPanel.render_groups``

    Example:
        >>> h = IssueGroupHeader(ValidationSeverity.ERROR, 3)
        >>> (h.severity_label, h.issue_count)
        ('ERRORS', 3)
    """

    def __init__(self, severity: ValidationSeverity, count: int) -> None:
        label = SEVERITY_LABELS.get(severity, str(severity.value).upper())
        super().__init__(
            safe_text(f"{label}  ({count})"),
            classes=f"issue-group-header {css_class_for_severity(severity)}",
        )
        #: The group's display label (e.g. ``"ERRORS"``).
        self.severity_label: str = label
        #: The whole-filtered-list count this header reports.
        self.issue_count: int = count


class IssueRow(Horizontal):
    """A focusable, clickable single-issue row: a code chip + issue detail.

    Summary:
        Renders one ``ValidationIssue`` as a horizontal row holding a compact
        ``.issue-code-chip`` (the issue ``.code``) beside a ``.issue-detail``
        span (symbol · address · message). Both cells are markup-safe
        ``rich.text.Text`` built via ``safe_text`` (LLR-042.10), so hostile
        file-derived tokens render literal. The row is ``can_focus`` and on a
        real click or ``Enter`` posts :class:`Selected` carrying the issue's
        integer address (or ``None``), which ``app.py`` consumes to repaint the
        retained ``#issues_hex_pane`` (LLR-042.5). Purely presentational — it
        never parses or validates.

    Args:
        issue (ValidationIssue): The already-computed issue to display.

    Returns:
        None

    Data Flow:
        - Mounted by ``GroupedIssuesPanel.render_groups``; on click/``Enter``
          posts :class:`Selected` → ``S19TuiApp.on_issue_row_selected``.

    Dependencies:
        Uses:
            - ``css_class_for_severity`` / ``safe_text``
        Used by:
            - ``GroupedIssuesPanel.render_groups``

    Example:
        >>> row = IssueRow(
        ...     ValidationIssue(code="C", severity=ValidationSeverity.ERROR,
        ...                     artifact="s19", message="m", address=0x10)
        ... )
        >>> row.address
        16
    """

    can_focus = True

    class Selected(Message):
        """An issue row was activated (real click or ``Enter``).

        Args:
            address (Optional[int]): The activated issue's integer address, or
                ``None`` when the issue carries no address.
        """

        def __init__(self, address: Optional[int]) -> None:
            super().__init__()
            self.address = address

    def __init__(self, issue: ValidationIssue) -> None:
        self.issue = issue
        self.address: Optional[int] = (
            issue.address if isinstance(issue.address, int) else None
        )
        self._sev_class = css_class_for_severity(issue.severity)
        super().__init__(classes=f"issue-row {self._sev_class}")

    def compose(self) -> ComposeResult:
        """Yield the markup-safe code chip and the issue-detail span."""
        yield Static(
            safe_text(self.issue.code or "-"),
            classes=f"issue-code-chip {self._sev_class}",
        )
        yield Static(safe_text(self._detail_text()), classes="issue-detail")

    def _detail_text(self) -> str:
        """Build the ``symbol · address · message`` detail string (literal)."""
        symbol = self.issue.symbol or "-"
        addr = (
            f"0x{self.issue.address:08X}"
            if isinstance(self.issue.address, int)
            else "no-addr"
        )
        return f"{symbol}  {addr}  {self.issue.message or ''}"

    def on_click(self) -> None:
        """Focus and post :class:`Selected` on a real pointer click."""
        self.focus()
        self.post_message(self.Selected(self.address))

    def on_key(self, event) -> None:  # type: ignore[no-untyped-def]
        """Post :class:`Selected` on ``Enter`` (consumed); other keys pass."""
        if event.key == "enter":
            event.stop()
            self.post_message(self.Selected(self.address))


class GroupedIssuesPanel(ScrollableContainer):
    """Scrollable grouped-by-severity dense view of the validation issues.

    Summary:
        Renders a bounded paging window of ``ValidationIssue`` objects grouped
        by severity in error → warning → info order (LLR-042.3). Each present
        group is led by an :class:`IssueGroupHeader` reporting the whole
        (filtered) list count for that severity (LLR-042.6), followed by up to
        :data:`_GROUP_DISPLAY_MAX` :class:`IssueRow` widgets drawn from the
        window (in severity order). Headers always report the whole-filtered
        count; only the rows are display-capped. Because each row is a
        multi-``Static`` ``Horizontal``, mounting a full ``page_size`` window
        would remount hundreds of non-virtualized widgets and stall the message
        pump — so the row count is bounded to a small constant, tightening (not
        loosening) the LLR-042.6 DoS bound (mounted rows stay
        ``<= _GROUP_DISPLAY_MAX <= page_size``). A truncation note is shown when
        the filtered list exceeds the window OR the display cap hides rows on
        this page. Purely presentational — no parse/validate/coverage work.

    Args:
        id (str): The widget id (``#validation_issues_groups``).

    Returns:
        None

    Data Flow:
        - ``S19TuiApp.update_validation_issues_view`` computes the window +
          per-severity counts and calls ``render_groups``.
        - Row activation bubbles :class:`IssueRow.Selected` to the app.

    Dependencies:
        Uses:
            - ``IssueGroupHeader`` / ``IssueRow`` / ``safe_text``
        Used by:
            - ``S19TuiApp._compose_screen_issues`` /
              ``update_validation_issues_view``

    Example:
        >>> panel = GroupedIssuesPanel(id="validation_issues_groups")
        >>> panel.id
        'validation_issues_groups'
    """

    EMPTY_TEXT = "No validation issues to group."
    TRUNCATION_NOTE = "More issues on other pages — use PgUp/PgDn to page."

    def render_groups(
        self,
        window_issues: Sequence[ValidationIssue],
        group_counts: Dict[ValidationSeverity, int],
        truncated: bool = False,
    ) -> None:
        """Rebuild the grouped view from a windowed issue slice + group counts.

        Summary:
            Clear the mounted children and remount one group header per
            severity present in ``window_issues`` (in the fixed error →
            warning → info order) followed by that severity's windowed rows,
            capping the total mounted :class:`IssueRow` count across all groups
            to :data:`_GROUP_DISPLAY_MAX` (rows are taken in severity order
            until the budget is spent). Each header reports
            ``group_counts[severity]`` (the whole-filtered count), not the
            number of rows shown. A neutral empty note is shown when there is
            nothing to group; a truncation note is appended when ``truncated``
            OR the display cap hid rows on this page (LLR-042.6).

        Args:
            window_issues (Sequence[ValidationIssue]): The bounded paging
                window of issues to mount as rows (already filtered + sliced by
                the caller — this widget mounts exactly these, never more).
            group_counts (Dict[ValidationSeverity, int]): Whole-(filtered)-list
                issue count per severity, used verbatim for the header counts.
            truncated (bool): ``True`` when the filtered list is larger than the
                window, so a "more on other pages" note is appended.

        Returns:
            None

        Data Flow:
            - ``remove_children`` then ``mount`` the header/row widgets; no data
              is derived here beyond grouping the passed window by severity.

        Dependencies:
            Uses:
                - ``IssueGroupHeader`` / ``IssueRow`` / ``safe_text``
            Used by:
                - ``S19TuiApp.update_validation_issues_view``
        """
        self.remove_children()
        if not window_issues and not any(group_counts.values()):
            self.mount(Static(safe_text(self.EMPTY_TEXT), classes="issues-empty-note sev-neutral"))
            return
        widgets: List[Static] = []
        remaining = _GROUP_DISPLAY_MAX
        capped = False
        for severity in SEVERITY_ORDER:
            group_rows = [
                issue for issue in window_issues if issue.severity == severity
            ]
            if not group_rows:
                continue
            count = group_counts.get(severity, len(group_rows))
            widgets.append(IssueGroupHeader(severity, count))
            shown = group_rows[:remaining] if remaining > 0 else []
            widgets.extend(IssueRow(issue) for issue in shown)
            remaining -= len(shown)
            if len(shown) < len(group_rows):
                capped = True
        if truncated or capped:
            widgets.append(
                Static(
                    safe_text(self.TRUNCATION_NOTE),
                    classes="issues-truncation-note sev-neutral",
                )
            )
        if widgets:
            self.mount(*widgets)
