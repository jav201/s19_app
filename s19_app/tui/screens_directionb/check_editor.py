"""s19_app.tui.screens_directionb.check_editor — CheckEditorPanel (moved verbatim from s19_app/tui/screens_directionb.py at 4f721985)."""
from __future__ import annotations

import json
from typing import Mapping, Optional, Sequence
from rich.cells import cell_len
from rich.text import Text
from textual import events
from textual.app import ComposeResult
from textual.containers import Container, Horizontal, ScrollableContainer, Vertical, VerticalScroll
from textual.message import Message
from textual.widgets import Button, ContentSwitcher, DataTable, Input, Label, Select, Static
from ..a2l_parameter_picker import A2LParameterPicker, clip_tail
from ..screens import BulkParameterAddScreen
from ..changes.io import is_check_spec_name
from ..insight_style import CYAN, DGRAY, GREEN, LABEL, VALUE
from ..os_clipboard_input import OsClipboardInput
from ...utils import safe_text
from .shared import (_clip_to_cells, cap_json_lines, CheckLayout, check_layout, TabChip)


#: batch-97 (LLR-148.7, D6 / D7): the Check Editor's closed glyph vocabulary —
#: glyph -> its one meaning. ``✓`` marks an included row in the ledger's mark
#: column; ``◆`` / ``▪`` head the REPORT FIELDS lines. ``#check_legend`` is
#: generated from this mapping, so the legend cannot name a glyph the panel
#: does not paint. ``◆`` replaced ``☑``, which Windows Terminal paints two
#: cells wide (LED-2026-10-19-batch-97.12).
CHECK_GLYPHS: Mapping[str, str] = {
    "✓": "included",
    "◆": "parameter field",
    "▪": "memory-row field",
}


def _count(n: int, noun: str) -> str:
    """``1 field`` / ``2 fields`` — a count with its noun in number (ux-reviewer L3)."""
    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"


class CheckEditorPanel(ScrollableContainer):
    """The Check Editor rail screen — ledger + REPORT FIELDS card (batch-97 ce_A).

    Summary:
        The check twin of the Patch Editor: a collector for A2L parameters
        and memory locations the operator wants in the A2B diff report. The
        batch-97 composition (HLR-145, operator verdict ce_A): the A2L
        parameter ledger fills the left column at full height (mark ·
        Parameter · Address · Fmt · Unit, the Address never clipped, names
        clipped to their discriminating tail), with the highlighted row's full
        name under it; the right column is the REPORT FIELDS card — Fields /
        JSON / Addendum tab chips over one ``ContentSwitcher`` (Fields: the
        included fields one per line, the memory-row table and its labelled
        inputs, the validate verdicts; JSON: the spec document those fields
        produce; Addendum: what the A2B diff report gains). Under the two
        columns: the spec row, one docked action row and the glyph legend.
        The product is ONE artifact: a ``.chk.json`` check spec (v2 grammar,
        ``kind="check"``).

        The NO-APPLY doctrine is carried three ways: the docked row shows a
        struck APPLY ghost (a STATIC — never an actionable control), the JSON
        tab carries ``"apply": false``, and the hint reads ``apply: n/a —
        check spec``. The panel exposes write and validate actions only;
        Write is its one filled element (LLR-145.9).

        Widths: CSS splits the columns (left ``1fr``, card ``38%`` / min 42);
        :func:`check_layout` derives what CSS cannot — the DataTable column
        widths, the Fields name field, the memory Label column — and
        :meth:`_apply_layout` repaints the width-dependent cells through the
        public ``update_cell`` path (D21, PC-8) on mount, resize and show.

        Bulk add (batch-102 Inc 4): the picker's ``Add list`` control posts
        ``BulkAddRequested`` and this panel pushes the
        :class:`BulkParameterAddScreen` modal for its picker
        (R-B102-BULK-001); the modal applies through the picker's
        ``include_names`` seam and the dismiss tail only refreshes the
        previews — never the ledger (R-B102-BULK-007).

        The panel stays **presentational** (C-7): controls post
        :class:`ActionRequested` messages that ``app.py`` routes.

    Example:
        >>> panel = CheckEditorPanel()
        >>> panel.id
        'check_editor_panel'
    """

    _APPLY_GHOST_TEXT = "APPLY — not available"
    _APPLY_HINT = "apply: n/a — check spec"
    _PREVIEW_CAP = 6
    _STATUS_HINT = "Validate compares fields to the image"
    _EMPTY_LEDGER = "No A2L parameters — load an A2L (^L) to list them."
    _EMPTY_FIELDS = "No fields included yet."

    #: The memory-size -> fmt label vocabulary (closed author set).
    _FMT_LABELS = {1: "u8", 2: "u16", 4: "u32", 8: "u64"}

    #: (tab chip id, label, pane id) — the REPORT FIELDS card's three tabs.
    _CARD_TABS = (
        ("check_tab_fields", "Fields", "check_pane_fields"),
        ("check_tab_json", "JSON", "check_pane_json"),
        ("check_tab_addendum", "Addendum", "check_pane_addendum"),
    )

    class ActionRequested(Message):
        """A Check Editor write/validate control was triggered (LLR-009).

        Args:
            action (str): ``"write_doc"`` or ``"validate_doc"``.
            file_name_text (str): The ``.chk.json`` name input's text.
            items (tuple): The collected field dicts, in collector order.

        Dependencies:
            Used by:
                - ``S19TuiApp.on_check_editor_panel_action_requested``
        """

        def __init__(
            self,
            action: str,
            file_name_text: str = "",
            items: tuple = (),
        ) -> None:
            super().__init__()
            self.action = action
            self.file_name_text = file_name_text
            self.items = items

    class SpecFileSelected(Message):
        """The operator picked a spec/patch file from the dropdown (LLR-010.1).

        Args:
            filename (str): The chosen file's bare component.

        Dependencies:
            Used by:
                - ``S19TuiApp.on_check_editor_panel_spec_file_selected``
        """

        def __init__(self, filename: str) -> None:
            super().__init__()
            self.filename = filename

    def __init__(self) -> None:
        super().__init__(id="check_editor_panel")
        #: The shared A2L parameter picker (batch-102 Inc 3): it owns the
        #: ledger, the filter debounce, the paging and the picks. The panel
        #: stays the host: it injects its width derivation as the picker's
        #: ``layout_provider`` (a one-way call — the provider reads cached
        #: scalars, never picker entry points, so there is no cycle).
        self._picker = A2LParameterPicker(layout_provider=self._widths)
        #: The declared memory rows: list of (address, label, size, expected).
        self._memory_rows: list = []
        #: Spec bytes of a field loaded from a spec, keyed by the included
        #: parameter name: name -> (address, size, bytes) of its spec entry.
        self._spec_bytes: dict[
            str, tuple[int, int, Optional[tuple[int, ...]]]
        ] = {}
        #: The last derived widths; ``None`` until the panel is measured.
        self._layout: Optional[CheckLayout] = None

    # ------------------------------------------------------------------
    # Picker state (compatibility properties — existing callers and tests
    # read the panel's historic attribute names)
    # ------------------------------------------------------------------

    @property
    def _param_rows(self) -> dict:
        """The normalized parameter source: {name: (address, size, fmt_unit)}."""
        return self._picker.param_rows

    @property
    def _visible_params(self) -> list:
        """The picker rows currently mounted (the current page), in table order."""
        return self._picker.visible_params

    @property
    def _picked_params(self) -> list:
        """The picked parameter names in inclusion order (the ✓ set)."""
        return self._picker.picked_params

    # ------------------------------------------------------------------
    # Population seams (app.py is the only caller — the US-026 split)
    # ------------------------------------------------------------------

    def set_spec_files(self, names: Sequence[str]) -> None:
        """Populate the spec dropdown, suffix-distinguished (LLR-010.1).

        Every option label is a FILENAME read off disk, so it reaches the
        Select as a literal ``Text`` (C-17); the VALUE stays the bare ``str``.
        """
        options = []
        for name in names:
            label = Text(safe_text(str(name)).plain)
            if is_check_spec_name(name):
                label.append(" CHECK", style=GREEN)
            else:
                label.append(" PATCH", style=CYAN)
            options.append((label, name))
        self.query_one("#check_spec_file_select", Select).set_options(options)

    def set_a2l_parameters(
        self, rows: Sequence[dict], signature: object = None
    ) -> None:
        """Populate the A2L parameter ledger (LLR-001.1, LLR-145.1).

        Delegates rows, the signature and the app's current parsed A2L data to
        the embedded :class:`A2LParameterPicker` (the batch-102 Inc 3 seam):
        the picker mounts at most one page, preserves filter/page/picks while
        the signature is unchanged (R-B102-SEL-004) and no-ops on the
        unchanged-signature re-entry, in which case this shim returns without
        touching the layout or the previews. On a real (re)population it
        re-includes every earlier pick the new ledger lists, demotes a pick
        loaded from a spec that the new ledger no longer lists at its spec
        entry's range into a memory row (R-CHKED-056) and drops the rest
        (R-CHKED-055), then re-derives the widths (the cached longest
        ``Fmt · Unit`` text is an input of :func:`check_layout`). A headless
        panel or an app without parsed A2L data supplies ``None``.
        """
        kept = list(self._picker.picked_params)
        a2l_data = (
            getattr(self.app, "current_a2l_data", None) if self.is_mounted else None
        )
        if not self._picker.set_parameters(rows, signature, a2l_data=a2l_data):
            return
        rows_before = len(self._memory_rows)
        kept = self._demote_moved_spec_params(kept)
        if kept:
            self._picker.include_names(kept)
            self._prune_spec_bytes()
        if len(self._memory_rows) != rows_before:
            self._rebuild_memory_table()
        self._layout = None
        self.call_after_refresh(self._apply_layout)
        self._refresh_preview()

    def load_spec(self, items: Sequence[dict], source_name: str) -> None:
        """Populate the collector from a loaded check spec (LLR-009.1 read arm).

        Each entry's named parameter (its symbol when the loaded A2L lists
        it at the entry's range, else the one parameter at the entry's
        address and byte count) is included in entry order; an entry without
        one becomes an unlabelled memory row carrying the spec's bytes.
        ``app.py`` read the document; this only mirrors it.
        """
        self._picker.clear_picks()
        self._spec_bytes = {}
        self._memory_rows = []
        by_key: dict = {}
        for name, (address, size, _fmt) in self._param_rows.items():
            if isinstance(address, int):
                by_key.setdefault((address, size), []).append(name)
        taken: set = set()
        named: list = []
        for item in items:
            address = item.get("address")
            if address is None:
                continue
            address = int(address)
            size = int(item.get("size") or 1)
            expected = item.get("expected")
            name = self._named_parameter(
                address, size, item.get("symbol"), by_key, taken
            )
            if name is not None:
                named.append(name)
                taken.add(name)
                self._spec_bytes[name] = (address, size, expected)
            else:
                self._memory_rows.append(
                    (address, self._default_label(address), size, expected)
                )
        if named:
            self._picker.include_names(named)
        self._rebuild_memory_table()
        self._rebuild_ledger()
        base = str(source_name)
        if is_check_spec_name(base):
            base = base[: -len(".chk.json")]
        elif base.lower().endswith(".json"):
            base = base[:-5]
        self.query_one("#check_file_name_input", Input).value = (
            f"{base}.chk.json"
        )
        self._refresh_preview()

    # ------------------------------------------------------------------
    # Collector internals
    # ------------------------------------------------------------------

    def _fmt_label(self, size: int) -> str:
        """Map a declared byte size to the closed fmt vocabulary."""
        return self._FMT_LABELS.get(size, f"{size}B")

    @staticmethod
    def _default_label(address: int) -> str:
        """The stored name of a memory row typed with no label (kept in the spec)."""
        return f"field @ 0x{address:08X}"

    def _named_parameter(
        self,
        address: int,
        size: int,
        symbol: Optional[str],
        by_key: dict,
        taken: set,
    ) -> Optional[str]:
        """The named parameter of one spec entry (the named-parameter rule).

        A symbol the loaded A2L lists names the entry only when its ledger
        range is the entry's address and byte count and it was not taken by
        an earlier entry; otherwise the address rule is not tried (E3 A-6).
        Without a usable symbol, the single parameter at the entry's address
        and byte count names it, when exactly one exists and is not taken.

        Args:
            address (int): The entry's address.
            size (int): The entry's byte count.
            symbol (Optional[str]): The resolved tag spelling, or ``None``.
            by_key (dict): ``(address, size)`` → the ledger names, in order.
            taken (set): Names already taken by earlier entries.

        Returns:
            Optional[str]: The named parameter, or ``None`` when there is
                none, it is ambiguous or taken, or the symbol names a listed
                parameter at another range.
        """
        if isinstance(symbol, str) and symbol and symbol in self._param_rows:
            if self._param_rows[symbol][:2] == (address, size) and symbol not in taken:
                return symbol
            return None
        names = by_key.get((address, size), [])
        if len(names) == 1 and names[0] not in taken:
            return names[0]
        return None

    def _demote_moved_spec_params(self, kept: list) -> list:
        """Demote spec-loaded picks the new ledger no longer lists at their
        spec entry's range into unlabelled memory rows (R-CHKED-056).

        Runs after ``set_parameters`` replaced the ledger. A pick whose name
        now resolves to another address, another byte count, or not at all
        (while it carries a spec entry) becomes a memory row at the spec
        entry's own address with its byte count and bytes, and is left out of
        the re-include list. The spec entry's address, size and bytes are
        never changed and the image is never read.

        Args:
            kept (list): The picks before the repopulation, in order.

        Returns:
            list: The picks to re-include, in order (a session pick the new
                ledger no longer lists is returned too — ``include_names``
                ignores it).
        """
        result: list = []
        for name in kept:
            spec = self._spec_bytes.get(name)
            if spec is None or self._param_rows.get(name, (None, None, ""))[:2] == spec[:2]:
                result.append(name)
                continue
            self._memory_rows.append(
                (spec[0], self._default_label(spec[0]), spec[1], spec[2])
            )
            del self._spec_bytes[name]
        return result

    def _prune_spec_bytes(self) -> None:
        """Keep only the spec bytes of currently included names whose ledger
        range is still their spec entry's (backstop to the demotion)."""
        picked = set(self._picker.picked_params)
        self._spec_bytes = {
            name: spec
            for name, spec in self._spec_bytes.items()
            if name in picked
            and self._param_rows.get(name, (None, None, ""))[:2] == spec[:2]
        }

    def _widths(self) -> CheckLayout:
        """The current layout, or the 118-column reading before the first measure."""
        return self._layout or check_layout(68, 38, self._fmt_longest())

    def _fmt_longest(self) -> int:
        """The cached longest ``Fmt · Unit`` cell (recomputed per population)."""
        return self._picker.fmt_longest

    def _rebuild_ledger(self) -> None:
        """Re-add the visible ledger rows (rows only — never the columns)."""
        self._picker.rebuild_ledger()

    def _rebuild_memory_table(self) -> None:
        table = self.query_one("#check_mem_table", DataTable)
        layout = self._widths()
        table.clear()
        for address, label, size, _expected in self._memory_rows:
            # A row typed with no label shows ``—``: its stored name only
            # repeats the address of the cell beside it (ux-reviewer M1).
            shown = (
                Text("—", style=DGRAY)
                if label == self._default_label(address)
                else safe_text(_clip_to_cells(safe_text(label).plain, layout.mem_label), VALUE)
            )
            table.add_row(
                safe_text(f"0x{address:08X}", CYAN),
                shown,
                safe_text(self._fmt_label(size)),
            )

    def _collected_items(self) -> tuple:
        """Gather the collector state into the message items tuple.

        One ``{"source", "name", "address", "size", "expected"}`` dict per
        declared field, in collector order: the included parameters first
        (inclusion order), then the memory rows (table order). ``expected``
        carries the spec's bytes for a field loaded from a spec — for a
        parameter only while its current ledger range is its spec entry's —
        and ``None`` otherwise.
        """
        items = []
        for name in self._picked_params:
            address, size, _fmt = self._param_rows.get(name, (None, 1, ""))
            spec = self._spec_bytes.get(name)
            if spec is not None and spec[:2] == (address, size):
                expected = spec[2]
            else:
                expected = None
            items.append(
                {
                    "source": "param",
                    "name": name,
                    "address": address,
                    "size": size,
                    "expected": expected,
                }
            )
        for address, label, size, expected in self._memory_rows:
            items.append(
                {
                    "source": "memory",
                    "name": label,
                    "address": address,
                    "size": size,
                    "expected": expected,
                }
            )
        return tuple(items)

    def _preview_text(self) -> Text:
        """The JSON tab: the spec document the collected fields produce.

        A JSON document (``json.dumps``, ASCII-escaped, so no control byte and
        no markup reaches the view) carrying the v2 envelope with
        ``"kind": "check"`` and the explicit ``"apply": false`` marker, one
        entry per field (address, size, name), capped at
        :data:`JSON_TAB_LINE_CAP` lines. Built as a plain ``Text`` (C-17).
        """
        document = {
            "format": "s19app-changeset",
            "version": "2.0",
            "kind": "check",
            "apply": False,
            "entries": [
                {
                    "address": (
                        f"0x{item['address']:08X}"
                        if item["address"] is not None
                        else None
                    ),
                    "size": item["size"],
                    "name": str(item["name"]),
                }
                for item in self._collected_items()
            ],
        }
        return Text(cap_json_lines(json.dumps(document, indent=2)), style=LABEL)

    def _addendum_preview_text(self) -> Text:
        """Build the addendum preview (read-only report-gain frame).

        Renders what the A2B diff report gains from this spec: the ``## Checks``
        heading, the declared-field count, and the no-apply statement. Field
        names are appended literally (C-17).
        """
        items = self._collected_items()
        text = Text("## Checks", style=GREEN)
        text.append("\n", style=LABEL)
        text.append(
            f"· {len(items)} fields → A2B diff report · ", style=LABEL
        )
        text.append(self._APPLY_HINT, style=DGRAY)
        for item in items[: self._PREVIEW_CAP]:
            address = item["address"]
            addr = f"0x{address:08X}" if address is not None else "unresolved"
            text.append("\n")
            text.append(f"· {addr} ", style=CYAN)
            text.append(safe_text(str(item["name"]), VALUE))
        if len(items) > self._PREVIEW_CAP:
            text.append(f"  … {len(items) - self._PREVIEW_CAP} more", style=DGRAY)
        return text

    def _fields_lines_text(self) -> Text:
        """The Fields tab: a head line, then one line per included field.

        ``◆ <address> <name>`` per included parameter and ``▪ <address> <fmt>
        <label>`` per memory row, in inclusion order (LLR-145.6). A parameter
        name wider than the name field keeps its tail behind one ``…``
        (LLR-145.3); a memory label keeps its head (labels, LLR-149.4), and a
        row typed with no label reads ``memory row`` instead of repeating its
        address (ux-reviewer M1). Built with ``Text.append`` — never a markup
        string (C-17).
        """
        items = self._collected_items()
        params = sum(1 for item in items if item["source"] == "param")
        memory = len(items) - params
        text = Text(
            f"{_count(len(items), 'field')}: {_count(params, 'param')} · "
            f"{_count(memory, 'memory row')}",
            style=f"bold {GREEN}",
        )
        if not items:
            text.append("\n")
            text.append(self._EMPTY_FIELDS, style=DGRAY)
            return text
        width = self._widths().fields_name
        for item in items:
            param = item["source"] == "param"
            address = item["address"]
            text.append("\n")
            text.append("◆ " if param else "▪ ", style=GREEN if param else CYAN)
            text.append(
                f"0x{address:08X} " if address is not None else "unresolved ",
                style=CYAN,
            )
            name = safe_text(str(item["name"])).plain
            if param:
                text.append(safe_text(clip_tail(name, width), VALUE))
                continue
            fmt = self._fmt_label(item["size"])
            text.append(f"{fmt} ", style=DGRAY)
            if item["name"] == self._default_label(address):
                text.append("memory row", style=DGRAY)
            else:
                label_w = max(4, width - cell_len(fmt) - 1)
                text.append(safe_text(_clip_to_cells(name, label_w), VALUE))
        return text

    def _refresh_preview(self) -> None:
        """Repaint the Fields lines, the JSON and Addendum tabs and the count."""
        if not self.is_mounted:
            return
        items = self._collected_items()
        self.query_one("#check_fields_lines", Static).update(self._fields_lines_text())
        self.query_one("#check_preview", Static).update(self._preview_text())
        self.query_one("#check_addendum_preview", Static).update(
            self._addendum_preview_text()
        )
        self.query_one("#check_fields_count", Static).update(
            Text(f"{_count(len(items), 'field')} → report", style=GREEN)
        )
        self.query_one("#check_left_column").border_subtitle = (
            f"{len(self._param_rows)} params · {len(self._picked_params)} picked"
        )

    def _refresh_full_name(self) -> None:
        """Paint the highlighted row's address, ``Fmt · Unit`` and name under
        the ledger — delegated to the picker, which owns the ledger and its
        empty states (LLR-145.3; code-reviewer F1, ux-reviewer L2).
        """
        self._picker.refresh_full_name()

    # ------------------------------------------------------------------
    # Width derivation (D21: mount, resize, show)
    # ------------------------------------------------------------------

    def _apply_layout(self) -> None:
        """Re-derive the widths and repaint every width-dependent text.

        Reads the measured content widths of ``#check_param_table`` and
        ``#check_right_column`` (never the terminal width). An unchanged
        layout repaints nothing. Otherwise it sets each column's width and
        rewrites the Parameter and ``Fmt · Unit`` cells with ``update_cell``,
        the first call with ``update_width=True`` (the public repaint path
        the PC-8 spike measured); it never adds a column. The Fields lines
        and the memory Label cells are rebuilt by their own painters.
        """
        table = self.query_one("#check_param_table", DataTable)
        card = self.query_one("#check_right_column")
        if table.content_region.width == 0 or card.content_region.width == 0:
            return
        layout = check_layout(
            table.content_region.width, card.content_region.width, self._fmt_longest()
        )
        if layout == self._layout:
            return
        self._layout = layout
        columns = table.ordered_columns
        for column, width in zip(columns, (1, layout.param, 10, layout.fmt)):
            column.width = width
            column.auto_width = False
        columns[3].label = Text(layout.fmt_label)
        keys = [column.key for column in columns]
        if not self._visible_params:
            # D21 (5): with no rows the pass is ``clear()`` (rows only) — it
            # drops the table's cached render so the new column widths repaint
            # the header; there is no cell for ``update_cell`` to go through.
            table.clear()
        for index, name in enumerate(self._visible_params):
            cells = self._picker.row_cells(name, layout)
            table.update_cell(name, keys[1], cells[1], update_width=(index == 0))
            table.update_cell(name, keys[3], cells[3])
        mem = self.query_one("#check_mem_table", DataTable)
        for column, width in zip(mem.ordered_columns, (10, layout.mem_label, 3)):
            column.width = width
            column.auto_width = False
        self._rebuild_memory_table()
        self._refresh_full_name()
        self._refresh_preview()

    def on_resize(self, event: events.Resize) -> None:
        self.call_after_refresh(self._apply_layout)

    def on_show(self, event: events.Show) -> None:
        self.call_after_refresh(self._apply_layout)

    # ------------------------------------------------------------------
    # Composition
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        """Lay out the ledger + REPORT FIELDS card (HLR-145, the ce_A tree).

        Every row below the two columns is one terminal row; the ledger is
        the panel's growing region (design §3, Check Editor tree). The shipped
        ids are kept (LLR-145.1), except the hidden addendum toggle, which
        batch-101 Inc 12 removed (R-CHKED-058).
        """
        with Horizontal(id="check_columns"):
            with Vertical(id="check_left_column") as left:
                left.border_title = "A2L PARAMETERS"
                yield self._picker
            with Vertical(id="check_right_column") as right:
                right.border_title = "REPORT FIELDS"
                with Horizontal(id="check_card_tabs"):
                    for chip_id, label, _pane in self._CARD_TABS:
                        yield TabChip(
                            label,
                            id=chip_id,
                            classes="tab-chip chip-selected"
                            if chip_id == "check_tab_fields"
                            else "tab-chip",
                        )
                with ContentSwitcher(initial="check_pane_fields", id="check_card_switcher"):
                    with VerticalScroll(id="check_pane_fields") as fields_pane:
                        fields_pane.can_focus = False
                        yield Static(
                            "", id="check_fields_lines", classes="nowrap-fields"
                        )
                        yield Static("MEMORY LOCATIONS", classes="ce-title")
                        yield DataTable(
                            id="check_mem_table",
                            zebra_stripes=True,
                            cursor_type="row",
                        )
                        # One row per field, labels in one fixed column
                        # (operator decision at the Inc-3 gate, LED-…97.14).
                        with Vertical(id="check_mem_inputs", classes="patch-docked-row"):
                            with Horizontal(classes="ce-row"):
                                yield Label("Address", classes="ce-label")
                                yield OsClipboardInput(
                                    placeholder="0x100",
                                    id="check_mem_address_input",
                                    compact=True,
                                )
                            with Horizontal(classes="ce-row"):
                                yield Label("Label", classes="ce-label")
                                yield OsClipboardInput(
                                    placeholder="label",
                                    id="check_mem_label_input",
                                    compact=True,
                                )
                            with Horizontal(classes="ce-row"):
                                yield Label("Size (bytes)", classes="ce-label")
                                yield OsClipboardInput(
                                    placeholder="1",
                                    id="check_mem_size_input",
                                    compact=True,
                                )
                        with Horizontal(
                            id="check_mem_controls",
                            classes="patch-docked-row patch-chip-entry",
                        ):
                            yield Button(
                                "Add row",
                                id="check_mem_add_button",
                                classes="patch-chip",
                            )
                            yield Button(
                                "Remove row",
                                id="check_mem_remove_button",
                                classes="patch-chip",
                            )
                        yield Label(
                            self._STATUS_HINT,
                            id="check_status",
                            classes="patch-field-label",
                            markup=False,
                        )
                        yield Container(id="check_results")
                    with ScrollableContainer(id="check_pane_json"):
                        yield Static("", id="check_preview", markup=False)
                    with ScrollableContainer(id="check_pane_addendum"):
                        yield Static("", id="check_addendum_preview", markup=False)
        with Horizontal(id="check_spec_file_row", classes="patch-docked-row"):
            yield Label("Spec", classes="ce-label")
            yield Select(
                [],
                id="check_spec_file_select",
                prompt="Check specs in patches/",
                allow_blank=True,
                compact=True,
            )
            yield Label("Write as", classes="ce-label")
            yield OsClipboardInput(
                placeholder="spec file name",
                id="check_file_name_input",
                compact=True,
            )
        with Horizontal(id="check_dock"):
            with Horizontal(
                id="check_actions_row",
                classes="patch-docked-row patch-chip-apply",
            ):
                yield Button(
                    "Validate", id="check_validate_button", classes="patch-chip"
                )
                yield Button(
                    "Write .chk.json",
                    id="check_write_button",
                    classes="patch-chip fill-accent",
                )
                # The struck-APPLY ghost — a STATIC, not a Button: the
                # no-apply doctrine made visible (C-ux-2).
                yield Static(
                    Text(self._APPLY_GHOST_TEXT, style="strike dim"),
                    id="check_apply_ghost",
                )
            with Horizontal(id="check_actions_row2", classes="patch-docked-row"):
                yield Static("", id="check_fields_count", markup=False)
            yield Static(
                Text(self._APPLY_HINT, style=DGRAY),
                id="check_apply_hint",
                markup=False,
            )
        yield Static(
            "   ".join(f"{glyph} {meaning}" for glyph, meaning in CHECK_GLYPHS.items()),
            id="check_legend",
            classes="glyph-legend nowrap-legend",
            markup=False,
        )

    def on_mount(self) -> None:
        """Add the memory table's columns; the picker mounts its own ledger."""
        layout = self._widths()
        mem = self.query_one("#check_mem_table", DataTable)
        mem.add_column("Address", width=10)
        mem.add_column("Label", width=layout.mem_label)
        mem.add_column("Fmt", width=3)
        self.query_one("#check_file_name_input", Input).value = "spec.chk.json"
        self._refresh_preview()
        self.call_after_refresh(self._apply_layout)

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def _show_tab(self, chip_id: str) -> None:
        """Switch the card to ``chip_id``'s pane and mark that chip selected."""
        for tab_id, _label, pane in self._CARD_TABS:
            selected = tab_id == chip_id
            self.query_one(f"#{tab_id}").set_class(selected, "chip-selected")
            if selected:
                self.query_one("#check_card_switcher", ContentSwitcher).current = pane

    def _on_a2l_parameter_picker_selection_changed(
        self, event: A2LParameterPicker.SelectionChanged
    ) -> None:
        """One ledger row was included or excluded (R-B102-SEL-003): prune the
        spec bytes to the current picks, then refresh the
        Fields/JSON/Addendum previews and the left-column count. The
        document controls keep collecting ``items`` from the picker at
        write/validate time."""
        event.stop()
        self._prune_spec_bytes()
        self._refresh_preview()

    def _on_a2l_parameter_picker_bulk_add_requested(
        self, event: A2LParameterPicker.BulkAddRequested
    ) -> None:
        """The picker's bulk-add control was activated (R-B102-BULK-001):
        push the bulk modal for this panel's picker. The picker stays
        presentational (C-7, E3 ruling 5) — it only announces; the host
        owns the screen stack."""
        event.stop()
        self._open_parameter_bulk_add()

    def _open_parameter_bulk_add(self) -> None:
        """Push :class:`BulkParameterAddScreen` bound to this panel's picker."""
        self.app.push_screen(
            BulkParameterAddScreen(self._picker), self._on_bulk_add_closed
        )

    def _on_bulk_add_closed(self, summary: Optional[dict]) -> None:
        """Bulk modal dismissed (R-B102-BULK-007; E3 rulings 6/9).

        ``None`` — escape, cancel, or a close after a change-less session —
        repaints nothing beyond the dismiss. A change-flagged close
        repaints the Fields/JSON/Addendum previews and the picked count.
        The ledger is never rebuilt here and ``load_spec`` is never
        called: the picker's ``SelectionChanged`` already carried the
        include to the previews at apply time.
        """
        if summary is None:
            return
        self._refresh_preview()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Translate the collector controls into messages (LLR-001.1/.2).

        The ledger's own controls (the include button, the page chips, the
        filter) are the embedded picker's; its ``SelectionChanged`` listener
        above refreshes the previews.
        """
        button_id = event.button.id or ""
        if any(button_id == tab_id for tab_id, _l, _p in self._CARD_TABS):
            event.stop()
            self._show_tab(button_id)
            return
        if button_id == "check_mem_add_button":
            event.stop()
            self._add_memory_row()
            return
        if button_id == "check_mem_remove_button":
            event.stop()
            table = self.query_one("#check_mem_table", DataTable)
            if table.row_count == 0:
                return
            cursor = table.cursor_row
            if not 0 <= cursor < len(self._memory_rows):
                return
            self._memory_rows.pop(cursor)
            self._rebuild_memory_table()
            self._refresh_preview()
            return
        actions = {
            "check_write_button": "write_doc",
            "check_validate_button": "validate_doc",
        }
        action = actions.get(button_id)
        if action is not None:
            event.stop()
            items = self._collected_items()
            if any(
                item["source"] == "param" and item["size"] is None for item in items
            ):
                self.query_one("#check_status", Label).update(
                    "Check Editor: parameter has no length — validate/write refused."
                )
                return
            self.post_message(
                self.ActionRequested(
                    action=action,
                    file_name_text=self.query_one(
                        "#check_file_name_input", Input
                    ).value,
                    items=items,
                )
            )

    def _add_memory_row(self) -> None:
        """Validate the memory inputs and append one declared memory row."""
        address_text = self.query_one(
            "#check_mem_address_input", Input
        ).value.strip()
        label = self.query_one("#check_mem_label_input", Input).value.strip()
        size_text = self.query_one("#check_mem_size_input", Input).value.strip()
        try:
            address = int(address_text, 16) if address_text.lower().startswith(
                "0x"
            ) else int(address_text, 10)
        except ValueError:
            self.query_one("#check_status", Label).update(
                f"Check Editor: bad memory address {address_text!r}."
            )
            return
        if address < 0:
            self.query_one("#check_status", Label).update(
                "Check Editor: memory address must be non-negative."
            )
            return
        try:
            size = int(size_text, 10)
        except ValueError:
            size = 1
        if size <= 0 or size > 8:
            self.query_one("#check_status", Label).update(
                f"Check Editor: size must be 1..8 bytes, got {size}."
            )
            return
        if not label:
            label = self._default_label(address)
        self._memory_rows.append((address, label, size, None))
        self._rebuild_memory_table()
        self._refresh_preview()

    def on_select_changed(self, event: Select.Changed) -> None:
        """Forward a spec-file dropdown pick to ``app.py`` (LLR-010.1)."""
        if event.select.id != "check_spec_file_select":
            return
        if event.value is Select.NULL:
            return
        event.stop()
        self.post_message(self.SpecFileSelected(str(event.value)))

    def show_status_line(self, line: str) -> None:
        """Paint one English state line in the REPORT FIELDS card (LLR-148.9).

        Used for a refused Write: the line replaces the verdict rows under the
        memory form, and the card shows its Fields tab.
        """
        self.refresh_check_results([], line)

    def refresh_check_results(
        self,
        rows: Sequence[tuple],
        status_line: str,
    ) -> None:
        """Render the validate verdicts (LLR-009.2) under the memory form, on
        the Fields tab.

        Args:
            rows (Sequence[tuple]): ``(text, css_class)`` per entry verdict.
            status_line (str): The status sentence (one line).
        """
        self._show_tab("check_tab_fields")
        self.query_one("#check_status", Label).update(status_line)
        container = self.query_one("#check_results", Container)
        container.remove_children()
        for text, css_class in rows:
            container.mount(Static(text, classes=css_class, markup=False))

    def clear_check_results(self) -> None:
        """Return the validation results to their mount state (R-CHKED-057).

        Summary:
            The app calls this after it wrote bytes into the loaded image in
            place: the painted verdict rows judged the bytes before the
            write, so they are removed and the status line goes back to the
            text the card shows when it opens. Unlike
            :meth:`refresh_check_results` it neither switches the card's tab
            nor moves the focus.

        Returns:
            None

        Data Flow:
            - ``#check_status`` <- ``_STATUS_HINT``; every child of
              ``#check_results`` removed. Nothing is computed.

        Dependencies:
            Used by:
                - ``S19TuiApp._note_image_bytes_written``
        """
        self.query_one("#check_status", Label).update(self._STATUS_HINT)
        self.query_one("#check_results", Container).remove_children()
