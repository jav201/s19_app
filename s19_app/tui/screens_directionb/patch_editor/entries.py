"""s19_app.tui.screens_directionb.patch_editor.entries - EntriesMixin (methods moved verbatim from patch_editor.py at 2dbd7d5a)."""
from __future__ import annotations

from typing import Mapping, Optional, Sequence, Union
from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Label, Select, Static
from ...insight_style import DGRAY, PURPLE
from ...os_clipboard_input import OsClipboardInput
from .shared import _Unset, _UNSET, CARD_NO_ENTRIES, BeforeAfterCard


class EntriesMixin:
    """Mixin: the panel's entries ledger and its before/after card."""

    def on_select_changed(self, event: Select.Changed) -> None:
        """Forward a change-file dropdown pick to ``app.py`` (US-026).

        Summary:
            When ``#patch_doc_file_select`` changes to a concrete filename,
            post a :class:`ChangeFileSelected` carrying the listed value so
            the app resolves it against its homes through the pick guard
            (``_resolve_listed_file``) and loads it via the existing
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

    def _compose_ledger(self) -> ComposeResult:
        """Compose helper: the ledger's table and its empty-state line."""
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

    def _compose_entry_form(self) -> ComposeResult:
        """Compose helper: the before/after card, the entry inputs and the entry buttons."""
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

    def _compose_file_row(self) -> ComposeResult:
        """Compose helper: the change-file row (dropdown, path, Load, Refresh)."""
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
