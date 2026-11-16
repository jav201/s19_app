"""s19_app.tui.screens_directionb.patch_editor.document - DocumentMixin (methods moved verbatim from patch_editor.py at 2dbd7d5a)."""
from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
from textual.widgets import Button, Static, TextArea
from ...changes.io import DUMMY_CHANGESET_TEXT
from ...insight_style import DGRAY, LABEL, cap_gauge_style
from ...json_highlight import JsonHighlightTextArea
from .. import deps
from ..shared import cap_json_lines
from .shared import json_stamp_text


class DocumentMixin:
    """Mixin: the panel's change-set document: JSON view, paste buffer and gauge."""

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
        self._json_shown = (document.entry_count, deps._json_clock(), document.json_text)
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

    def _compose_json_view(self) -> ComposeResult:
        """Compose helper: the JSON tab's heading, stamp and read-only view."""
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

    def _compose_paste_buffer(self) -> ComposeResult:
        """Compose helper: the paste buffer, its dock spacer and its controls."""
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
