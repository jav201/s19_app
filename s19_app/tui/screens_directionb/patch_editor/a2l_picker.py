"""s19_app.tui.screens_directionb.patch_editor.a2l_picker - A2lPickerMixin (methods moved verbatim from patch_editor.py at 2dbd7d5a)."""
from __future__ import annotations

from typing import List, Optional, Sequence
from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.widgets import Button, DataTable, Input, Static
from ...a2l import MAX_A2L_DECODE_BYTES
from ...a2l_parameter_picker import A2LParameterPicker
from ...screens import BulkParameterAddScreen
from ....utils import safe_text
from ..shared import CheckLayout, check_layout


class A2lPickerMixin:
    """Mixin: the panel's A2L tab (the shared parameter picker in pick mode)."""

    # ------------------------------------------------------------------
    # A2L tab (batch-102 Inc 5, US-102-05 — the shared picker in pick mode)
    # ------------------------------------------------------------------

    def set_a2l_parameters(
        self, rows: Sequence[dict], signature: object = None
    ) -> None:
        """Populate the A2L picker (R-B102-PE-001, R-B102-PE-005).

        Delegates rows, the app's safe ``_a2l_enriched_key`` signature and its
        current parsed A2L data to the embedded picker: it mounts at most one
        200-row page and preserves the filter, page, highlight and picks while
        the signature is unchanged, in which case this shim returns without
        touching the layout. On a real (re)population the cached ``Fmt · Unit``
        width may change, so the derived widths are invalidated and re-derived
        on the next layout pass. A headless panel or an app without parsed A2L
        data supplies ``None``.
        """
        a2l_data = (
            getattr(self.app, "current_a2l_data", None) if self.is_mounted else None
        )
        if not self._a2l_picker.set_parameters(rows, signature, a2l_data=a2l_data):
            return
        self._a2l_layout = None
        self.call_after_refresh(self._apply_a2l_layout)

    def _a2l_widths(self) -> "CheckLayout":
        """The A2L tab's current layout, or the pre-measure reading of the
        118-column regime before the tab is first measured (E3 ruling 1:
        never the picker's built-in 118-column default — this derivation
        follows the Patch inspector's real width)."""
        if self._a2l_layout is not None:
            return self._a2l_layout
        return check_layout(39, 41, self._a2l_fmt_longest())

    def _a2l_fmt_longest(self) -> int:
        """The cached longest ``Fmt · Unit`` cell (recomputed per population)."""
        return self._a2l_picker.fmt_longest

    def _apply_a2l_layout(self) -> None:
        """Re-derive the A2L tab widths and repaint the picker's ledger.

        Reads the measured content width of ``#patch_param_table`` (the
        picker's ledger fills the A2L pane inside the inspector — never the
        terminal width). A hidden tab measures 0 and repaints nothing; the
        cache is kept, so showing the tab re-derives nothing it already
        knows. An unchanged layout repaints nothing. Otherwise it sets each
        column's width and rewrites the Parameter and ``Fmt · Unit`` cells
        with ``update_cell`` (the public repaint path, D21/PC-8); it never
        adds a column. At no more than 12 panel rows the ledger keeps its
        header and one data row, the picker sizes to its content, and the panel
        grows to 13 rows so the full Use status wraps on its own row. Taller
        panels keep the flexible table and panel height. The ledger rows belong
        to the picker.
        """
        table = self.query_one("#patch_param_table", DataTable)
        if table.content_region.width == 0:
            return
        compact = self.region.height <= 13
        table.styles.height = 2 if compact else "1fr"
        table.show_header = True
        self._a2l_picker.styles.height = "auto"
        self.styles.height = 13 if compact else "1fr"
        layout = check_layout(
            table.content_region.width,
            self.query_one("#patch_inspector").content_region.width,
            self._a2l_fmt_longest(),
        )
        if layout == self._a2l_layout:
            return
        self._a2l_layout = layout
        columns = table.ordered_columns
        for column, width in zip(columns, (1, layout.param, 10, layout.fmt)):
            column.width = width
            column.auto_width = False
        columns[3].label = Text(layout.fmt_label)
        keys = [column.key for column in columns]
        if not self._a2l_picker.visible_params:
            # D21 (5): with no rows the pass is ``clear()`` (rows only).
            table.clear()
        for index, name in enumerate(self._a2l_picker.visible_params):
            cells = self._a2l_picker.row_cells(name, layout)
            table.update_cell(name, keys[1], cells[1], update_width=(index == 0))
            table.update_cell(name, keys[3], cells[3])
        self._a2l_picker.refresh_full_name()

    def _on_a2l_parameter_picker_bulk_add_requested(
        self, event: A2LParameterPicker.BulkAddRequested
    ) -> None:
        """The picker's bulk-add control was activated: push the shared bulk
        modal for this panel's picker. The host owns the screen stack; bulk
        inclusion never creates a Patch document action."""
        event.stop()
        self._open_parameter_bulk_add()

    def _open_parameter_bulk_add(self) -> None:
        """Push :class:`BulkParameterAddScreen` bound to the Patch picker."""
        self.app.push_screen(
            BulkParameterAddScreen(self._a2l_picker), self._on_bulk_add_closed
        )

    def _on_bulk_add_closed(self, summary: Optional[dict]) -> None:
        """Bulk modal dismissed without rebuilding the ledger or changing the
        document, dirty flag, undo/redo history or current selection. The
        shared picker retains successful includes and the modal owns its
        summary; cancellation and escape are inert."""

    def _use_highlighted_parameter(self) -> None:
        """Transfer the highlighted A2L row into the entry form
        (R-B102-PE-003, R-B102-PE-004; E3 rulings 4/5/6/9).

        Reads the picker's ``highlighted_parameter``: with no usable row (or
        a non-integer address, E3 ruling 9) it paints ``No parameter
        highlighted.`` and touches nothing else. It writes a valid Address as
        ``0x%08X``. A missing declared size then clears Bytes and paints
        ``Parameter has no length — Bytes not prefilled.`` before any image
        lookup. Otherwise the Bytes input receives the panel-retained current
        image bytes for the parameter size — every byte of
        ``[address, address + size)`` must be mapped, and the size must not
        exceed ``MAX_A2L_DECODE_BYTES`` (E3 ruling 5: no giant range is
        iterated, no silent truncation); on either miss Bytes is left empty
        and ``Parameter address loaded; image bytes unavailable.`` paints.
        No document action is posted and the dirty/undo/redo state is unchanged
        — the document changes only through Add / Edit. Every painted line is
        an author-fixed string through ``safe_text`` (E3 ruling 7); no
        parameter name, image byte or path is logged (E3 ruling 10).
        """
        parameter = self._a2l_picker.highlighted_parameter
        address = parameter.get("address") if parameter else None
        if parameter is None or not isinstance(address, int) or address < 0:
            self._paint_a2l_use_status("No parameter highlighted.")
            return
        self.query_one("#patch_entry_address_input", Input).value = (
            f"0x{address:08X}"
        )
        size = parameter.get("size")
        if size is None:
            self.query_one("#patch_entry_bytes_input", Input).value = ""
            self._paint_a2l_use_status(
                "Parameter has no length — Bytes not prefilled."
            )
            return
        bytes_text = ""
        status = ""
        if size > MAX_A2L_DECODE_BYTES:
            status = (
                f"Parameter size {size} bytes over the "
                f"{MAX_A2L_DECODE_BYTES}-byte decode cap — Bytes not prefilled."
            )
        else:
            mem_map = self._mem_map
            data: Optional[List[int]] = []
            if mem_map is not None:
                for offset in range(size):
                    byte = mem_map.get(address + offset)
                    if byte is None:
                        # Partial map: any missing byte means unavailable —
                        # zero-fill is prohibited (E3 ruling 6).
                        data = None
                        break
                    data.append(int(byte))
            if mem_map is None or data is None:
                status = "Parameter address loaded; image bytes unavailable."
            else:
                bytes_text = " ".join(f"{byte:02X}" for byte in data)
        self.query_one("#patch_entry_bytes_input", Input).value = bytes_text
        if status:
            self._paint_a2l_use_status(status)
        else:
            self._clear_a2l_use_status()

    def _paint_a2l_use_status(self, line: str) -> None:
        """Paint one author-fixed outcome line on the A2L tab's single status
        surface ``#patch_param_use_status`` (E3 ruling 7), tolerating a
        not-yet-mounted tree."""
        self._a2l_use_status = line
        holders = self.query("#patch_param_use_status")
        if not holders:
            return
        holder = holders.first(Static)
        holder.update(safe_text(line))
        holder.display = True

    def _clear_a2l_use_status(self) -> None:
        """Hide the use-status surface (a fully successful use paints no line)."""
        self._a2l_use_status = ""
        holders = self.query("#patch_param_use_status")
        if holders:
            holders.first(Static).display = False

    def _on_a2l_parameter_picker_view_changed(
        self, event: A2LParameterPicker.ViewChanged
    ) -> None:
        """The A2L ledger re-rendered (populate, filter, page turn):
        re-assert the host's use-status surface and re-derive the tab widths
        (the measured table width exists only while the tab is shown). The
        document rows and the entry inputs are never touched here
        (R-B102-PE-005, R-B102-PE-006)."""
        self._apply_a2l_layout()
        if self._a2l_use_status:
            self._paint_a2l_use_status(self._a2l_use_status)

    def _compose_a2l_tab(self) -> ComposeResult:
        """Compose helper: the A2L tab's picker, Use-parameter row and status line."""
        yield self._a2l_picker
        with Horizontal(
            id="patch_param_use_row",
            classes="patch-docked-row patch-chip-entry",
        ):
            yield Button(
                "Use parameter",
                id="patch_param_use_button",
                classes="patch-chip",
            )
        use_status = Static(
            "",
            id="patch_param_use_status",
            classes="patch-field-label",
            markup=False,
        )
        use_status.styles.height = 3
        use_status.styles.text_wrap = "wrap"
        use_status.display = False
        yield use_status
