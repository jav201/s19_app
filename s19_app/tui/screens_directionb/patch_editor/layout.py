"""s19_app.tui.screens_directionb.patch_editor.layout - LayoutMixin (methods moved verbatim from patch_editor.py at 2dbd7d5a)."""
from __future__ import annotations

from rich.cells import cell_len
from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.widgets import ContentSwitcher, DataTable, Static
from ...insight_style import CYAN, VALUE
from ....utils import safe_text
from ..shared import _clip_to_cells, TabChip
from .shared import PATCH_GLYPHS, PatchLayout, patch_layout


class LayoutMixin:
    """Mixin: the panel's layout: compose and the width derivation."""

    def compose(self) -> ComposeResult:
        """Lay out the Patch Editor as a staging sheet over a landing pane.

        Summary:
            batch-103 Inc 8 (R-TUI-063.1, CTX-PE-DEF), top to bottom: the
            identity ribbon; the filter row (the shared picker in pick mode,
            its table hidden, R-PE-DEF.2); the STAGING SHEET window, which
            takes every row the other regions leave (R-PE-DEF.1.1, at least
            12, R-PE-DEF.74); the LANDS IN landing pane, whose Patch script /
            Inspector / JSON / Checks chips switch one ``ContentSwitcher``
            (Patch script first, R-TUI-063.3, .4); the file row; the
            document controls (Inc 10's dock rides inside them, I-8.3); the
            glyph legend. ``#patch_main`` and ``#patch_win_a2l`` left; every
            other shipped id is kept (LLR-144.1) and each ``patch_win_*`` /
            ``patch_saveback_row`` / ``patch_before_after_row`` /
            ``patch_checks_results`` id keeps its ``Container`` type.
            Geometry lives in ``styles.tcss`` (one scoped section, D23);
            Python sizes only the ledger columns and the strip's bytes per
            row (D21).

        Returns:
            ComposeResult: The widget tree.
        """
        yield Static(
            "", id="patch_identity_ribbon", classes="nowrap-ribbon", markup=False
        )
        with Horizontal(id="patch_filter_row"):
            yield from self._compose_filter_row()
        with Container(id="patch_sheet_win") as sheet_win:
            sheet_win.border_title = "STAGING SHEET"
            sheet_win.border_subtitle = "enter edit · ↑↓ row · arrays open the bench"
            yield self._sheet
        with Vertical(id="patch_inspector") as inspector:
            inspector.border_title = self._TABS[0][3]
            with Horizontal(id="patch_tabs"):
                for chip_id, label, _pane, _title in self._TABS:
                    yield TabChip(
                        label,
                        id=chip_id,
                        classes="tab-chip chip-selected"
                        if chip_id == "patch_tab_script"
                        else "tab-chip",
                    )
            with ContentSwitcher(
                initial="patch_win_script", id="patch_tab_switcher"
            ):
                with Container(id="patch_win_script") as script:
                    script.border_title = self._WINDOW_BORDER_TITLES["patch_win_script"]
                    with VerticalScroll(id="patch_win_script_body") as script_body:
                        script_body.can_focus = False
                        with Container(id="patch_pane_entries"):
                            yield from self._compose_ledger()
                with VerticalScroll(id="patch_pane_inspector") as pane:
                    pane.can_focus = False
                    yield from self._compose_entry_form()
                    yield from self._compose_use_row()
                    yield from self._compose_tally()
                with Container(id="patch_win_json"):
                    yield from self._compose_json_view()
                    yield from self._compose_paste_buffer()
                    yield from self._compose_action_bar()
                with Container(id="patch_win_checks"):
                    yield from self._compose_checks_pane()
        yield from self._compose_file_row()
        yield from self._compose_doc_controls()
        yield Static(
            "   ".join(f"{glyph} {meaning}" for glyph, meaning in PATCH_GLYPHS.items()),
            id="patch_legend",
            classes="glyph-legend nowrap-legend",
            markup=False,
        )

    # ------------------------------------------------------------------
    # Width derivation (D21: mount, resize, show)
    # ------------------------------------------------------------------

    def _widths(self) -> "PatchLayout":
        """The current layout, or the 118-column reading before the first measure."""
        return self._layout or patch_layout(65, 41, self._status_longest(), 110)

    def _status_longest(self) -> int:
        return max((cell_len(str(row.status_text)) for row in self._entry_rows), default=0)

    def _ledger_cells(self, row: object, layout: "PatchLayout") -> tuple:
        """The five cells of one ledger row, every one a literal ``Text`` (C-17)."""
        return (
            self._kind_cell(row),
            safe_text(str(row.address_text), CYAN),
            safe_text(_clip_to_cells(safe_text(str(row.value_text)).plain, layout.value), VALUE),
            safe_text(_clip_to_cells(safe_text(str(row.status_text)).plain, layout.status)),
            safe_text(_clip_to_cells(safe_text(str(row.linkage_text)).plain, layout.linkage)),
        )

    def _apply_layout(self) -> None:
        """Re-derive the widths and repaint every width-dependent text (D21).

        Reads the measured content widths of ``#patch_win_script`` (the
        ledger's frame, which the table fills), ``#patch_inspector`` and the
        ribbon — never the terminal width. An unchanged layout repaints
        nothing. Otherwise it sets each column's width and rewrites the
        Value / Status / Linkage cells with ``update_cell`` (the first call
        ``update_width=True``, the PC-8 path), re-renders the strip at its new
        bytes per row and repaints the ribbon. It never adds a column.
        batch-103 Inc 8: the borderless ledger fills the landing pane, so
        while another tab hides it the pane's content width stands for it.
        """
        ledger = self.query_one("#patch_win_script")
        inspector = self.query_one("#patch_inspector")
        ribbon = self.query_one("#patch_identity_ribbon")
        ledger_w = ledger.content_region.width or inspector.content_region.width
        if ledger_w == 0 or inspector.content_region.width == 0:
            return
        layout = patch_layout(
            ledger_w,
            inspector.content_region.width,
            self._status_longest(),
            ribbon.content_region.width,
        )
        if layout == self._layout:
            return
        self._layout = layout
        table = self.query_one("#patch_doc_entries_table", DataTable)
        columns = table.ordered_columns
        widths = (layout.kind, layout.address, layout.value, layout.status, layout.linkage)
        for column, width in zip(columns, widths):
            column.width = width
            column.auto_width = False
        keys = [column.key for column in columns]
        if not self._entry_rows:
            # D21 (5): with no rows the pass is ``clear()`` (rows only).
            table.clear()
        for index, row in enumerate(self._entry_rows):
            cells = self._ledger_cells(row, layout)
            for column in (2, 3, 4):
                table.update_cell(
                    str(index), keys[column], cells[column],
                    update_width=(index == 0 and column == 2),
                )
        self._render_before_after_card()
        self._refresh_ribbon()
        # batch-102 Inc 5: the A2L tab's ledger follows the same D21 pass.
        self._apply_a2l_layout()
