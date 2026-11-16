"""s19_app.tui.screens_directionb.ab_diff — AbDiffPanel (moved verbatim from s19_app/tui/screens_directionb.py at 4f721985)."""
from __future__ import annotations

from typing import Any, List, Optional, Sequence, Tuple
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.message import Message
from textual.widget import Widget
from textual.widgets import Button, Input, Label, ListItem, ListView, Select, Static
from ..changes.io import is_check_spec_name
from ..insight_style import CYAN, GREEN
from ..os_clipboard_input import OsClipboardInput
from ...utils import safe_text


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
            concrete filename (not the blank sentinel). Carries the listed
            value only (``checks/<n>`` or ``library/<n>`` in a project; the
            bare name without one) — ``app.py`` resolves it against the spec
            homes through the pick guard (``_resolve_listed_file``), reads it
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
            names (Sequence[str]): The spec list's listed values (patch
                ``*.json`` and check-spec ``*.chk.json`` files):
                ``checks/<n>`` then ``library/<n>`` with a project open, the
                sorted bare names without one.

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
            names (Sequence[str]): The spec list's listed values (patch
                ``*.json`` and check-spec ``*.chk.json`` files):
                ``checks/<n>`` then ``library/<n>`` with a project open, the
                sorted bare names without one.
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
        from ...render.hexview import HEX_WIDTH, MAX_HEX_ROWS, render_hex_view

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
