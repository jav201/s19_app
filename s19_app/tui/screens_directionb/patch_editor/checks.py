"""s19_app.tui.screens_directionb.patch_editor.checks - ChecksMixin (methods moved verbatim from patch_editor.py at 2dbd7d5a)."""
from __future__ import annotations

from typing import Mapping, Optional, Sequence
from rich.cells import cell_len
from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Container, VerticalScroll
from textual.widgets import Button, Label, Static
from ...a2l_parameter_picker import clip_tail
from ...insight_style import DGRAY, GREEN, RED, VALUE, YELLOW, microbar
from ....utils import safe_text


class ChecksMixin:
    """Mixin: the panel's checks tab: ribbon, tally, issues and check results."""

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
              the row count when a run is shown (a non-empty status line),
              else the no-run token.
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
        # LLR-075.1: derived from whether a run is shown (the status line is
        # non-empty), never from the row count — an empty 0-entry run shows
        # "0 checked" while a non-current run shows "no run yet". The subtitle
        # stays an author-composed token (C-17).
        self._set_window_subtitle(
            "patch_win_checks",
            f"{len(rows)} checked" if status_line else self._NO_RUN_SUBTITLE,
        )

    def _compose_tally(self) -> ComposeResult:
        """Compose helper: the inspector's tally line."""
        yield Static("", id="patch_doc_tally", markup=False)

    def _compose_checks_pane(self) -> ComposeResult:
        """Compose helper: the Checks tab's body and controls."""
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
