"""Grouped-by-severity dense view widgets for the Issues Report screen.

Batch-28 · R-TUI-042 · US-039 (Direction B). These presentational widgets
render the already-computed ``S19TuiApp._validation_issues`` list grouped by
severity (errors → warnings → info) with a per-group count header and a
compact per-issue code "chip", replacing the old flat single-table read of the
Issues Report. Since batch-29 (US-043) the legacy Issues ``DataTable`` is fully
retired and this grouped panel is the sole Issues surface beside the
``#issues_hex_pane`` peek (LLR-042.3/.4/.5/.6, LLR-043.R1).

C-17 markup-safety (LLR-042.10): every file-derived string reaching this view
(an issue ``.code``, ``.symbol`` or ``.message``) is composed through the
batch-27 ``safe_text`` helper as a literal ``rich.text.Text`` — never
interpolated into a Rich-markup-parsed string and never handed to a
markup-parsing widget over the raw value. A loaded symbol such as ``sensor[red]`` or
``x[link=file:///etc]`` or a raw ANSI byte therefore renders LITERAL: no
``MarkupError``, no style/ANSI leak, no OSC-8 hyperlink escape, no crash.
``.symbol``/``.code`` are never scrubbed upstream (``validation/model.py`` is
engine-frozen), so this render layer is the sole defense.

Batch-94 Inc-004 (US-004 / HLR-012 / LLR-012.1/.2) adds the
``A2L_UNRECOGNIZED_BLOCK`` warnings triage (Cambio4): findings whose block
name belongs to the curated ASAP2 standard-keyword set
(:data:`CURATED_STANDARD_A2L_BLOCKS`, seeded from the executed 2026-10-13
fixture tally) are reclassified WARNING → INFO at presentation time in
:meth:`GroupedIssuesPanel.render_groups` — reclassification, never suppression
(D-6) — with the author-constant justification
:data:`A2L_BLOCK_RECLASSIFICATION_JUSTIFICATION` rendered at the INFO group.
The remap is a presentation-level copy (``dataclasses.replace``); the caller's
issue list is never mutated. Count triage is CALLER-owned:
:func:`adjust_counts_for_a2l_triage` (built on the same
:func:`a2l_reclassified_severity` predicate) adjusts the severity-strip /
summary counters and the panel's ``group_counts`` in ``app.py``, so every
painted surface reports one consistent triaged census; the panel mounts the
caller-supplied counts verbatim and remaps rows only. The engine
(``validation/rules.py`` / ``tui/a2l.py``) stays frozen (D-1) and is
deliberately NOT imported here — the curated set is view-owned, and the
engine constant's byte-unchanged proof lives in
``tests/test_tui_issues_triage_b94.py`` (TC-B94-18).

No engine code is imported here — the widgets receive their data via
``GroupedIssuesPanel.render_groups`` and emit an ``IssueRow.Selected`` message
back to ``app.py`` (which drives ``_update_issues_hex_pane``); colour flows
exclusively through the frozen ``css_class_for_severity`` (no hard-coded hex).
"""

from __future__ import annotations

import re
from dataclasses import replace
from typing import Dict, Iterable, List, Optional, Sequence

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, ScrollableContainer
from textual.message import Message
from textual.widgets import Static

from .color_policy import css_class_for_severity
from .insight_style import CYAN, RED, YELLOW, microbar
from ..utils import safe_text
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

#: Author-controlled leading glyph per severity group header (batch-49,
#: LLR-082.3). A closed map keyed by :data:`SEVERITY_ORDER`; the glyphs are
#: fixed author constants (never file-derived — C-17).
_SEVERITY_GLYPH: Dict[ValidationSeverity, str] = {
    ValidationSeverity.ERROR: "✗",
    ValidationSeverity.WARNING: "⚠",
    ValidationSeverity.INFO: "•",
}

#: Short strip label per severity (batch-49, LLR-082.1).
_STRIP_SEVERITY_LABEL: Dict[ValidationSeverity, str] = {
    ValidationSeverity.ERROR: "Errors",
    ValidationSeverity.WARNING: "Warnings",
    ValidationSeverity.INFO: "Info",
}

#: Fixed per-severity accent for the strip label + micro-bar (batch-49,
#: LLR-082.1): ERROR→RED, WARNING→YELLOW, INFO→CYAN, from ``insight_style``.
_STRIP_SEVERITY_STYLE: Dict[ValidationSeverity, str] = {
    ValidationSeverity.ERROR: RED,
    ValidationSeverity.WARNING: YELLOW,
    ValidationSeverity.INFO: CYAN,
}

#: Micro-bar cell count for the severity strip — a coarse glance cue, matching
#: the MAC coverage strip's fixed small scale (batch-49, LLR-082.1).
_ISSUES_STRIP_BAR_WIDTH: int = 5

#: Curated ASAP2 standard-keyword set (batch-94 Inc-004, LLR-012.1): the
#: block names whose ``A2L_UNRECOGNIZED_BLOCK`` findings the Issues surface
#: presents as INFO instead of WARNING. Seeded from the executed 2026-10-13
#: tally over ``examples/case_00_public/software_a.a2l`` — the 21 families
#: pasted in ``.dev-flow/2026-10-12-batch-94/evidence/p1_probe_a2l_unrecognized.txt``
#: are this set's lineage (437 REF_CHARACTERISTIC + 221 REF_MEASUREMENT +
#: 180 AXIS_DESCR + 69 COMPU_VTAB_RANGE + 69 SUB_GROUP + 22 DEF_CHARACTERISTIC
#: + 6 PAGE + 3 SEGMENT + 3 SUB_FUNCTION + 2 PROTOCOL_LAYER + 1 each of
#: A2ML/CAN_FD/DAQ/EVENT/FORMULA/MOD_COMMON/MOD_PAR/PAG/STIM/
#: TIMESTAMP_SUPPORTED/XCP_ON_CAN = 1 023 findings). View-owned policy
#: constant: the engine's ``RECOGNIZED_A2L_BLOCKS`` (``validation/rules.py``)
#: stays frozen (D-1) and is deliberately NOT imported here — the two sets
#: are disjoint by construction (the emitter only fires for names the engine
#: does NOT recognize), and the engine constant's byte-unchanged check lives
#: in ``tests/test_tui_issues_triage_b94.py`` (TC-B94-18).
CURATED_STANDARD_A2L_BLOCKS: frozenset[str] = frozenset(
    {
        "A2ML",
        "AXIS_DESCR",
        "CAN_FD",
        "COMPU_VTAB_RANGE",
        "DAQ",
        "DEF_CHARACTERISTIC",
        "EVENT",
        "FORMULA",
        "MOD_COMMON",
        "MOD_PAR",
        "PAG",
        "PAGE",
        "PROTOCOL_LAYER",
        "REF_CHARACTERISTIC",
        "REF_MEASUREMENT",
        "SEGMENT",
        "STIM",
        "SUB_FUNCTION",
        "SUB_GROUP",
        "TIMESTAMP_SUPPORTED",
        "XCP_ON_CAN",
    }
)

#: Reclassification justification (LLR-012.2) rendered at the INFO group when
#: the mounted window carries reclassified rows. An author constant — no
#: file-derived text — so it is markup-safe by construction (C-17); composed
#: through ``safe_text`` like every other string in this module.
A2L_BLOCK_RECLASSIFICATION_JUSTIFICATION: str = (
    "Standard ASAP2 keyword (curated set) — reclassified WARNING → INFO per "
    "the Cambio4 triage: standard vocabulary the parser surfaces as "
    "unrecognized; it represents no defect."
)

#: Emitter-anchored shape of an ``A2L_UNRECOGNIZED_BLOCK`` message
#: (``validation/rules.py`` emits exactly ``f"Unrecognized A2L block
#: '{section_name}'."`` with the name already stripped + uppercased). A
#: message that does not match this strict shape — including any hostile
#: file-derived token with markup metacharacters — is NEVER reclassified:
#: the predicate fails closed and the row keeps its engine severity.
_UNRECOGNIZED_BLOCK_RE = re.compile(r"^Unrecognized A2L block '([A-Z0-9_]+)'\.$")


def a2l_reclassified_severity(issue: ValidationIssue) -> Optional[ValidationSeverity]:
    """The Inc-004 reclassification predicate (HLR-012 / LLR-012.1/.2).

    Summary:
        For a WARNING ``A2L_UNRECOGNIZED_BLOCK`` finding whose message matches
        the emitter's exact shape and whose block name is a member of
        :data:`CURATED_STANDARD_A2L_BLOCKS`, return ``ValidationSeverity.INFO``
        — the curated standard-keyword names are informational, not warnings.
        Every other finding returns ``None``: non-``A2L_UNRECOGNIZED_BLOCK``
        codes, non-WARNING severities, messages that fail the strict emitter
        shape, and names outside the curated set (the executed ``FROBNICATE``
        negative control) all keep their engine severity and stay warnings.

    Args:
        issue (ValidationIssue): The already-computed finding to classify.

    Returns:
        Optional[ValidationSeverity]: ``INFO`` when the finding is
        reclassified, else ``None``.

    Data Flow:
        - Read-only over ``issue``: the severity remap happens at the single
          row-mounting caller (:meth:`GroupedIssuesPanel.render_groups`) via
          ``dataclasses.replace`` — this predicate never mutates.
        - The block name is extracted for a MEMBERSHIP TEST only; it never
          reaches a rendered string (the justification is an author
          constant), so the C-17 safe path is untouched.

    Dependencies:
        Uses:
            - :data:`CURATED_STANDARD_A2L_BLOCKS` / :data:`_UNRECOGNIZED_BLOCK_RE`
        Used by:
            - :func:`adjust_counts_for_a2l_triage` /
              :meth:`GroupedIssuesPanel.render_groups`
            - ``s19_app/tui/app.py`` (the strip / summary / group-counts
              painters — the fold round, HLR-012 "every presentation")
            - ``tests/test_tui_issues_triage_b94.py`` (TC-B94-19)

    Example:
        >>> issue = ValidationIssue(
        ...     code="A2L_UNRECOGNIZED_BLOCK", severity=ValidationSeverity.WARNING,
        ...     message="Unrecognized A2L block 'REF_CHARACTERISTIC'.",
        ...     artifact="a2l",
        ... )
        >>> a2l_reclassified_severity(issue) is ValidationSeverity.INFO
        True
        >>> bad = ValidationIssue(
        ...     code="A2L_UNRECOGNIZED_BLOCK", severity=ValidationSeverity.WARNING,
        ...     message="Unrecognized A2L block 'FROBNICATE'.", artifact="a2l",
        ... )
        >>> a2l_reclassified_severity(bad) is None
        True
    """
    if (
        issue.code != "A2L_UNRECOGNIZED_BLOCK"
        or issue.severity is not ValidationSeverity.WARNING
    ):
        return None
    match = _UNRECOGNIZED_BLOCK_RE.match(issue.message or "")
    if match is None or match.group(1) not in CURATED_STANDARD_A2L_BLOCKS:
        return None
    return ValidationSeverity.INFO


def adjust_counts_for_a2l_triage(
    counts: Dict[ValidationSeverity, int],
    issues: Iterable[ValidationIssue],
) -> Dict[ValidationSeverity, int]:
    """Apply the Inc-004 triage delta to a severity-count map (HLR-012).

    Summary:
        Count the findings ``issues`` that :func:`a2l_reclassified_severity`
        remaps (WARNING → INFO) and move that delta from WARNING to INFO in
        ``counts``. This is the ONE arithmetic site for the triage, shared by
        every whole-list painter — ``S19TuiApp`` 's severity strip, summary
        line and the grouped panel's ``group_counts`` — so the surfaces can
        never disagree. The panel itself mounts caller-supplied counts
        verbatim (LLR-042.6); it only remaps ROWS.

    Args:
        counts (Dict[ValidationSeverity, int]): Raw per-severity counts.
        issues (Iterable[ValidationIssue]): The list the counts were derived
            from (whole filtered list, or the whole unfiltered list).

    Returns:
        Dict[ValidationSeverity, int]: ``counts`` UNCHANGED (the same object)
        when the delta is zero — the no-reclassification no-op, byte-identical
        to the pre-Inc-004 painters; otherwise a copy with
        ``WARNING -= reclassified`` and ``INFO += reclassified``.

    Data Flow:
        - Single pass over ``issues`` through the predicate; no mutation of
          either argument.

    Dependencies:
        Uses:
            - :func:`a2l_reclassified_severity`
        Used by:
            - ``S19TuiApp.update_validation_issues_view`` /
              ``_render_validation_issues_groups``
            - ``tests/test_tui_issues_triage_b94.py`` (AT-B94-14)

    Example:
        >>> issue = ValidationIssue(
        ...     code="A2L_UNRECOGNIZED_BLOCK", severity=ValidationSeverity.WARNING,
        ...     message="Unrecognized A2L block 'PAGE'.", artifact="a2l",
        ... )
        >>> adjust_counts_for_a2l_triage(
        ...     {ValidationSeverity.WARNING: 1, ValidationSeverity.INFO: 0}, [issue]
        ... ) == {ValidationSeverity.WARNING: 0, ValidationSeverity.INFO: 1}
        True
        >>> raw = {ValidationSeverity.WARNING: 2}
        >>> adjust_counts_for_a2l_triage(raw, []) is raw
        True
    """
    reclassified = sum(
        1 for issue in issues if a2l_reclassified_severity(issue) is not None
    )
    if not reclassified:
        return counts
    adjusted = dict(counts)
    adjusted[ValidationSeverity.WARNING] = (
        adjusted.get(ValidationSeverity.WARNING, 0) - reclassified
    )
    adjusted[ValidationSeverity.INFO] = (
        adjusted.get(ValidationSeverity.INFO, 0) + reclassified
    )
    return adjusted


def build_issues_severity_strip(error: int, warning: int, info: int) -> Text:
    """
    Summary:
        Build the Issues Report severity-distribution strip as a C-17-safe Rich
        ``Text``: ``Errors N <bar>  Warnings M <bar>  Info K <bar>`` where each
        count is rendered in its fixed severity accent (ERROR→:data:`RED`,
        WARNING→:data:`YELLOW`, INFO→:data:`CYAN`) beside a proportional
        :func:`microbar` whose fill fraction is ``count / total`` (LLR-082.1).
        The slot set is bounded by :data:`SEVERITY_ORDER`, so a future issue
        severity is not silently dropped. The line carries ONLY integer counts
        and author constants — no file-derived text reaches this sink.

    Args:
        error (int): Whole-list ERROR count.
        warning (int): Whole-list WARNING count.
        info (int): Whole-list INFO count.

    Returns:
        rich.text.Text: The composed strip, built via ``append`` /
        ``append_text`` (never markup parsing) so it is markup-safe by
        construction. ``total == 0`` renders empty bars with no division.

    Data Flow:
        - Map the three counts onto :data:`SEVERITY_ORDER`, compute each bar's
          fill fraction against the total (guarded → ``0.0`` when total is 0).
        - Consumed by ``S19TuiApp.update_validation_issues_view`` →
          ``#issues_severity_strip``.

    Dependencies:
        Uses:
            - ``insight_style.microbar`` / ``RED`` / ``YELLOW`` / ``CYAN``
            - :data:`SEVERITY_ORDER` / :data:`_STRIP_SEVERITY_LABEL`
        Used by:
            - ``S19TuiApp.update_validation_issues_view``
            - ``tests/test_tui_issues_view.py``

    Example:
        >>> build_issues_severity_strip(3, 1, 2).plain.startswith("Errors 3")
        True
        >>> build_issues_severity_strip(0, 0, 0).plain
        'Errors 0 ░░░░░  Warnings 0 ░░░░░  Info 0 ░░░░░'
    """
    counts: Dict[ValidationSeverity, int] = {
        ValidationSeverity.ERROR: error,
        ValidationSeverity.WARNING: warning,
        ValidationSeverity.INFO: info,
    }
    total = error + warning + info
    text = Text()
    for index, severity in enumerate(SEVERITY_ORDER):
        count = counts[severity]
        style = _STRIP_SEVERITY_STYLE[severity]
        if index:
            text.append("  ")
        text.append(f"{_STRIP_SEVERITY_LABEL[severity]} {count} ", style=style)
        frac = count / total if total else 0.0
        text.append_text(microbar(frac, _ISSUES_STRIP_BAR_WIDTH, style=style))
    return text


class IssueGroupHeader(Static):
    """A per-severity group header carrying the group's label and issue count.

    Summary:
        One header precedes each severity group in the grouped Issues view
        (LLR-042.3). It renders ``"<glyph> <LABEL>  (<count>)"`` (the leading
        author-constant severity glyph is batch-49 LLR-082.3) as markup-safe
        text and is coloured by the group's severity through the frozen
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
        glyph = _SEVERITY_GLYPH.get(severity, "")
        super().__init__(
            safe_text(f"{glyph} {label}  ({count})"),
            classes=f"issue-group-header {css_class_for_severity(severity)}",
        )
        #: The group's display label (e.g. ``"ERRORS"``).
        self.severity_label: str = label
        #: The whole-filtered-list count this header reports.
        self.issue_count: int = count


class IssueRow(Horizontal):
    """A focusable, clickable single-issue row: a code chip + issue detail + related.

    Summary:
        Renders one ``ValidationIssue`` as a horizontal row holding a compact
        ``.issue-code-chip`` (the issue ``.code``) beside a ``.issue-detail``
        span (symbol · address · message) and a trailing ``.issue-related``
        node listing the issue's ``related_artifacts`` (``", ".join(...)`` or
        ``"-"`` when none) — the info the retired Related column showed,
        restored to the grouped view (LLR-043.R8). All three cells are
        markup-safe ``rich.text.Text`` built via ``safe_text`` (LLR-042.10 /
        LLR-043.R8), so hostile file-derived tokens render literal. The row is
        ``can_focus`` and on a real click or ``Enter`` posts :class:`Selected`
        carrying the issue's integer address (or ``None``), which ``app.py``
        consumes to repaint the retained ``#issues_hex_pane`` (LLR-042.5).
        Purely presentational — it never parses or validates.

    Args:
        issue (ValidationIssue): The already-computed issue to display.

    Returns:
        None

    Data Flow:
        - Mounted by ``GroupedIssuesPanel.render_groups``; :meth:`compose`
          yields the code chip, the detail span and the ``.issue-related``
          node (all ``safe_text``). On click/``Enter`` posts :class:`Selected`
          → ``S19TuiApp.on_issue_row_selected``.

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
        """Yield the markup-safe code chip, detail span and related node."""
        yield Static(
            safe_text(self.issue.code or "-"),
            classes=f"issue-code-chip {self._sev_class}",
        )
        yield Static(safe_text(self._detail_text()), classes="issue-detail")
        yield Static(
            safe_text(", ".join(self.issue.related_artifacts) or "-"),
            classes="issue-related",
        )

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

    # batch-31 AC-3 (B-04): when this ScrollableContainer holds focus its
    # inherited pageup/pagedown bindings would scroll (a no-op — the mounted
    # window is display-capped) and consume the keys before the app-level
    # `page_up/down_context` bindings could fire. Rebind them to the app's
    # issues paging actions so PgUp/PgDn page the window from inside the
    # panel too, matching TRUNCATION_NOTE's promise.
    BINDINGS = [
        Binding("pageup", "app.validation_issues_page_prev", "Page-", show=False),
        Binding("pagedown", "app.validation_issues_page_next", "Page+", show=False),
    ]

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

            Batch-94 Inc-004 (HLR-012 / LLR-012.2): before grouping, WARNING
            ``A2L_UNRECOGNIZED_BLOCK`` rows whose block name is curated
            standard ASAP2 vocabulary are remapped to INFO via
            :func:`a2l_reclassified_severity` — a presentation-level
            ``dataclasses.replace`` copy, never a mutation of the caller's
            list. The header counts are the caller-supplied ``group_counts``
            VERBATIM (LLR-042.6) — the caller owns count triage through
            :func:`adjust_counts_for_a2l_triage`, so the strip, the summary
            line and this panel can never disagree; the panel remaps rows
            only. When the window carries no reclassifiable row the render
            is byte-identical to the pre-Inc-004 grouping. The justification
            :data:`A2L_BLOCK_RECLASSIFICATION_JUSTIFICATION` renders
            immediately after the INFO group header whenever the mounted
            window carries at least one reclassified row. Genuinely unknown
            blocks (the executed ``FROBNICATE`` negative control) and every
            other code/severity keep their engine classification.

        Args:
            window_issues (Sequence[ValidationIssue]): The bounded paging
                window of issues to mount as rows (already filtered + sliced by
                the caller — this widget mounts exactly these, never more).
            group_counts (Dict[ValidationSeverity, int]): Whole-(filtered)-list
                issue count per severity, used verbatim for the header counts
                (triaged by the caller when it carries reclassifiable rows).
            truncated (bool): ``True`` when the filtered list is larger than the
                window, so a "more on other pages" note is appended.

        Returns:
            None

        Data Flow:
            - Classify each windowed issue once (``a2l_reclassified_severity``);
              the remapped severity drives row placement and the justification
              note; ``group_counts`` is mounted verbatim.
            - ``remove_children`` then ``mount`` the header/justification/row
              widgets; the caller's ``ValidationIssue`` objects are read-only.

        Dependencies:
            Uses:
                - ``IssueGroupHeader`` / ``IssueRow`` / ``safe_text``
                - :func:`a2l_reclassified_severity` /
                  :data:`A2L_BLOCK_RECLASSIFICATION_JUSTIFICATION`
            Used by:
                - ``S19TuiApp.update_validation_issues_view``
                - ``tests/test_tui_issues_triage_b94.py`` (AT-B94-14 /
                  TC-B94-19)
        """
        self.remove_children()
        if not window_issues and not any(group_counts.values()):
            self.mount(Static(safe_text(self.EMPTY_TEXT), classes="issues-empty-note sev-neutral"))
            return
        classified = [
            (issue, a2l_reclassified_severity(issue)) for issue in window_issues
        ]
        reclassified = sum(1 for _, severity in classified if severity is not None)
        display_issues: List[ValidationIssue] = [
            issue if severity is None else replace(issue, severity=severity)
            for issue, severity in classified
        ]
        widgets: List[Static] = []
        remaining = _GROUP_DISPLAY_MAX
        capped = False
        for severity in SEVERITY_ORDER:
            group_rows = [
                issue for issue in display_issues if issue.severity == severity
            ]
            if not group_rows:
                continue
            count = group_counts.get(severity, len(group_rows))
            widgets.append(IssueGroupHeader(severity, count))
            if severity is ValidationSeverity.INFO and reclassified:
                widgets.append(
                    Static(
                        safe_text(A2L_BLOCK_RECLASSIFICATION_JUSTIFICATION),
                        classes="issue-reclassify-note sev-neutral",
                    )
                )
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
