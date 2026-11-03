"""Batch-102 Inc 3 — the shared A2L parameter picker (R-B102-SEL-001..007).

The reusable selector the Check Editor embeds today and the Patch Editor can
embed at Inc 5: a filter, a paged parameter ledger (at most one 200-row page
mounted per rebuild), the highlighted row's full-name line, a separate count /
status line, the include control and the Prev / Next page chips. State is keyed
by the caller-provided A2L signature so re-entering a screen does not repopulate
the ledger or lose the operator's picks (R-B102-SEL-004).

Every file-derived string reaches the screen as a literal ``Text`` built by
:func:`s19_app.utils.safe_text` — no markup path exists here (R-B102-SEL-007).

The Check Editor cell helpers (:func:`clip_param`, :func:`clip_tail`,
:func:`_clip_fmt_unit`, :func:`_tail_cells`) moved here with the ledger so
the picker stays import-cycle-free; :func:`_clip_to_cells` is duplicated
verbatim from ``screens_directionb`` for the same reason (the house precedent
of ``S19TuiApp._clip_to``), and ``screens_directionb`` re-imports
:func:`clip_tail` for its remaining non-ledger painters.
"""

from __future__ import annotations

from math import ceil
from typing import TYPE_CHECKING, Callable, NamedTuple, Optional, Protocol, Sequence, runtime_checkable

from rich.cells import cell_len, set_cell_size
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.coordinate import Coordinate
from textual.message import Message
from textual.widgets import Button, DataTable, Input, Label, Static

from ..utils import safe_text
from .insight_style import CYAN, DGRAY, GREEN, VALUE
from .os_clipboard_input import OsClipboardInput

if TYPE_CHECKING:
    from textual.timer import Timer

#: One ledger page: at most this many rows are mounted per rebuild
#: (R-B102-SEL-001). A derive-class DataTable pays the mounted rows, not the
#: filtered set, so a 10 000-parameter A2L renders like a 200-row one.
PAGE_SIZE = 200

#: The filter rebuild debounce (R-B102-SEL-002): one typed burst causes one
#: content-cold rebuild, 150 ms after the last keystroke.
FILTER_DEBOUNCE_S = 0.15

#: The two empty states (R-B102-SEL-006), painted on #check_full_name_line —
#: the shipped surface TC-B97-58 and AT-B97-04 read.
_EMPTY_LEDGER = "No A2L parameters — load an A2L (^L) to list them."
_EMPTY_FILTER = "No parameter matches the filter."


def _clip_to_cells(text: str, cap: int) -> str:
    """Clip ``text`` to ``cap`` terminal COLUMNS, marking the loss with an ellipsis.

    Summary:
        The house clip seam (``S19TuiApp._clip_to``, app.py), kept at module
        scope because both ``app.py`` (via ``screens_directionb``) and this
        module's cell builders need it — a cross-module import back into the
        panels would cycle. Columns, not code points: ``cell_len`` /
        ``set_cell_size`` come from ``rich`` (already a hard dependency via
        Textual), and ``set_cell_size`` handles a cap falling in the MIDDLE of
        a double-width character — the correct result there is a pad space,
        not half a glyph. An over-long authored or file-derived line is
        shortened AT A CELL BOUNDARY here so the painted line never wraps
        mid-content (batch-93 inc-002, HLR-130 — the wrap audit asserts the
        no-wrap law over every authored surface).

    Args:
        text (str): The line to clip (authored or file-derived).
        cap (int): The maximum cell width the painted line may claim.

    Returns:
        str: ``text`` when it already fits; otherwise its first ``cap - 1``
        columns plus an ellipsis.

    Example:
        >>> _clip_to_cells("abcdef", 4)
        'abc…'
        >>> _clip_to_cells("ab", 4)
        'ab'
    """
    if cap <= 0:
        return ""
    if cell_len(text) <= cap:
        return text
    if cap == 1:
        return "…"
    return set_cell_size(text, cap - 1) + "…"


def _tail_cells(text: str, cap: int) -> str:
    """The longest tail of ``text`` that fits in ``cap`` terminal cells."""
    used = 0
    for index in range(len(text) - 1, -1, -1):
        used += cell_len(text[index])
        if used > cap:
            return text[index + 1:]
    return text


def clip_param(name: str, width: int) -> str:
    """Clip an A2L parameter name to ``width`` cells, keeping what tells it apart.

    LLR-145.3: a name that fits is painted whole; a longer one keeps its first
    dot-separated segment, one ``…`` and the name's tail filling the column
    (A2L names share long prefixes and differ at the end, P-38). A name with
    no dot keeps a third of the width as its head. Widths are terminal cells
    (``cell_len``), so a double-width name never paints past the column; a
    wide character that would straddle the edge is dropped, leaving the clip
    one cell short.

    Example:
        >>> clip_param("ASAM.M.SCALAR.UBYTE.TAB_VERB_NO_DEFAULT_VALUE", 24)
        'ASAM…RB_NO_DEFAULT_VALUE'
        >>> clip_param("UNKNOWN_PARAMETER_NAME_TAIL", 12)
        'UNKN…ME_TAIL'
    """
    if cell_len(name) <= width:
        return name
    first = name.split(".")[0]
    if cell_len(first) + 2 > width:
        first = set_cell_size(first, max(1, width // 3)).rstrip()
    return first + "…" + _tail_cells(name, width - cell_len(first) - 1)


def clip_tail(text: str, width: int) -> str:
    """Keep the tail of ``text`` behind one ``…`` when it exceeds ``width`` cells."""
    if cell_len(text) <= width:
        return text
    return "…" + _tail_cells(text, width - 1)


def _clip_fmt_unit(fmt_unit: str, width: int) -> str:
    """Clip a ``u<bits> <unit>`` cell: the unit goes first, the width stays.

    When even the ``u<bits>`` token fills the column, the token is painted
    alone (no room for a ``…``); the full-name line shows the whole text.
    """
    text = fmt_unit.rstrip()
    if cell_len(text) <= width:
        return text
    token = text.split(" ")[0]
    if cell_len(token) >= width:
        return set_cell_size(token, width)
    return _clip_to_cells(text, width)


class IncludeTable(DataTable):
    """The parameter ledger's table: ``space`` or ``enter`` toggles the
    highlighted row's inclusion (LLR-145.8, D16; ``enter`` replaces DataTable's
    row-select, which the ledger never used). The description ``Include`` is
    the key bar's label (D27); ``show=False`` keeps the shipped Footer
    unchanged until Inc-8 replaces it.

    Moved here from ``screens_directionb`` (batch-102 Inc 3) so the shared
    picker owns its ledger; ``screens_directionb`` re-exports the name to keep
    the public imports working.
    """

    BINDINGS = [
        Binding("space", "toggle_include", "Include", show=False),
        Binding("enter", "toggle_include", "Include", show=False),
    ]

    class IncludeToggled(Message):
        """``space`` asked to toggle the highlighted row's inclusion."""

    def action_toggle_include(self) -> None:
        self.post_message(self.IncludeToggled())


@runtime_checkable
class PickerLayout(Protocol):
    """The width slice the picker paints from (the host's ``CheckLayout``).

    The host (the Check Editor) injects a ``layout_provider`` returning its
    derived layout, so the picker never imports the host — no import cycle,
    and no call cycle either: the provider reads cached scalars, never picker
    entry points.
    """

    param: int
    fmt: int
    full_name: int


class _DefaultLayout(NamedTuple):
    """The 118-column pre-measure reading, used until a host injects its own."""

    param: int = 42
    fmt: int = 6
    full_name: int = 66


_DEFAULT_LAYOUT = _DefaultLayout()


class A2LParameterPicker(Vertical):
    """The shared A2L parameter selector (US-102-03).

    Composes the filter input (``#check_param_filter``), the paged ledger
    (``#check_param_table``, an :class:`IncludeTable`), the highlighted row's
    full-name line (``#check_full_name_line``), the separate count / status
    line (``#check_param_status``) and the docked control row (``#check_param_page_prev_button``,
    ``#check_param_page_label``, ``#check_param_page_next_button``,
    ``#check_param_include_button``). The shipped ids are conserved so help,
    tests and the key bar keep working.

    Population is keyed by the caller-provided ``signature`` (the app's safe
    ``_a2l_enriched_key``): an unchanged signature is a no-op that preserves
    the filter text, the page and the picks (R-B102-SEL-004). A ``None``
    signature never short-circuits — the no-op arm only applies to a real,
    matching key — so a bare ``set_parameters(rows)`` always repopulates.

    Events:
        ``SelectionChanged``: the picked-name tuple changed (one row toggled);
            the host repaints its collected-fields previews on it.
        ``ViewChanged``: the rendered page changed (populate, filter applied,
            page turned); carries ``shown`` / ``total`` / ``page`` /
            ``page_count`` for observers.
    """

    class SelectionChanged(Message, namespace="a2l_parameter_picker"):
        """The picked parameter set changed (R-B102-SEL-003).

        Args:
            names (tuple): The picked parameter names in inclusion order.
        """

        def __init__(self, names: tuple = ()) -> None:
            super().__init__()
            self.names = names

    class ViewChanged(Message, namespace="a2l_parameter_picker"):
        """The ledger view changed: one page was (re)rendered.

        Args:
            shown (int): Rows mounted on the current page.
            total (int): Filtered parameter count across all pages.
            page (int): The current 1-based page.
            page_count (int): The total number of pages (at least 1).
        """

        def __init__(
            self,
            shown: int = 0,
            total: int = 0,
            page: int = 1,
            page_count: int = 1,
        ) -> None:
            super().__init__()
            self.shown = shown
            self.total = total
            self.page = page
            self.page_count = page_count

    def __init__(
        self,
        *,
        layout_provider: Optional[Callable[[], PickerLayout]] = None,
        page_size: int = PAGE_SIZE,
        id: Optional[str] = None,
    ) -> None:
        super().__init__(id=id)
        #: The host's width provider; ``None`` reads the 118-column default.
        self._layout_provider = layout_provider
        #: One ledger page — at most this many rows are mounted per rebuild.
        self._page_size = max(1, int(page_size))
        #: The normalized parameter source: {name: (address, size, fmt_unit)}.
        self._param_rows: dict = {}
        #: Every name matching the current filter (all pages).
        self._filtered_params: list = []
        #: The names mounted on the current page, in table order.
        self._visible_params: list = []
        #: The picked names in inclusion order, preserved while the signature
        #: is unchanged (R-B102-SEL-004).
        self._picked_params: list = []
        #: The caller-provided identity (the app A2L/image cache key).
        self._signature: object = None
        #: The normalized filter text (lowercased, stripped).
        self._filter_text = ""
        #: The current 1-based page.
        self._page = 1
        #: The cached longest ``Fmt · Unit`` cell (an input of the host's
        #: layout derivation), computed once per ``set_parameters``.
        self._fmt_longest = 0
        #: The pending filter debounce timer, if any.
        self._filter_timer: Optional[Timer] = None

    # ------------------------------------------------------------------
    # State read by the host (compatibility surface)
    # ------------------------------------------------------------------

    @property
    def param_rows(self) -> dict:
        """The normalized parameter source keyed by name."""
        return self._param_rows

    @property
    def filtered_params(self) -> list:
        """Every name matching the current filter (all pages)."""
        return self._filtered_params

    @property
    def visible_params(self) -> list:
        """The names mounted on the current page, in table order."""
        return self._visible_params

    @property
    def picked_params(self) -> list:
        """The picked parameter names in inclusion order."""
        return self._picked_params

    @property
    def fmt_longest(self) -> int:
        """The cached longest ``Fmt · Unit`` cell width."""
        return self._fmt_longest

    @property
    def page(self) -> int:
        """The current 1-based page."""
        return self._page

    # ------------------------------------------------------------------
    # Population
    # ------------------------------------------------------------------

    def set_parameters(self, rows: Sequence[dict], signature: object = None) -> bool:
        """Populate the ledger (R-B102-SEL-001, R-B102-SEL-004, R-B102-SEL-006).

        Normalizes integer-address rows into ``{name: (address, size, fmt_unit)}``.
        When ``signature`` is non-``None`` and equals the stored signature,
        returns ``False`` without touching filter, page, picks or table.
        Otherwise replaces the source rows, clears the picks, resets the
        filter/page state, caches ``fmt_longest`` and rebuilds one page.

        Args:
            rows (Sequence[dict]): The loaded A2L's measurable parameters.
            signature (object): The caller-provided identity; ``None`` always
                repopulates.

        Returns:
            bool: ``True`` when the ledger was repopulated, ``False`` on the
                unchanged-signature no-op.
        """
        if signature is not None and signature == self._signature:
            return False
        self._signature = signature
        self._param_rows = {}
        self._picked_params = []
        for row in rows:
            name = str(row.get("name") or "?")
            address = row.get("address")
            address = int(address) if isinstance(address, int) else None
            size = int(row.get("byte_size") or 1)
            unit = str(row.get("compu_method_unit") or "")
            fmt_unit = f"u{size * 8}" + (f" {unit}" if unit else "")
            self._param_rows[name] = (address, size, fmt_unit)
        self._fmt_longest = max(
            (cell_len(v[2].rstrip()) for v in self._param_rows.values()), default=0
        )
        self._filter_text = ""
        self._page = 1
        self._cancel_filter_timer()
        if self.is_mounted:
            filter_input = self.query_one("#check_param_filter", Input)
            if filter_input.value:
                # The queued Input.Changed sees the already-reset filter text
                # and schedules no rebuild.
                filter_input.value = ""
        self._rebuild_ledger()
        return True

    def clear_picks(self) -> None:
        """Empty the picked set (the spec-file read arm); the ledger repaints
        on the next :meth:`rebuild_ledger`."""
        self._picked_params = []

    # ------------------------------------------------------------------
    # Host seams (the Check Editor's historic method names, delegating)
    # ------------------------------------------------------------------

    def row_cells(self, name: str, layout: PickerLayout) -> tuple:
        """The four ledger cells for ``name`` (the host's repaint path)."""
        return self._row_cells(name, layout)

    def rebuild_ledger(self) -> None:
        """Re-add the visible ledger rows (rows only — never the columns)."""
        self._rebuild_ledger()

    def refresh_full_name(self) -> None:
        """Repaint the highlighted row's full-name line."""
        self._refresh_full_name()

    # ------------------------------------------------------------------
    # Composition
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        """The filter row, the ledger, the two status lines and the control row.

        Every shipped id is conserved (``#check_param_filter``,
        ``#check_param_table``, ``#check_full_name_line``,
        ``#check_param_include_button``); the count line and the page chips are
        the increment's additions.
        """
        with Horizontal(classes="ce-row"):
            yield Label("Filter", classes="ce-label")
            yield OsClipboardInput(
                placeholder="filter parameters",
                id="check_param_filter",
                compact=True,
            )
        yield IncludeTable(
            id="check_param_table",
            zebra_stripes=True,
            cursor_type="row",
            classes="nowrap-ledger",
        )
        yield Static("", id="check_full_name_line", classes="nowrap-heading")
        status = Static("", id="check_param_status")
        status.display = False
        yield status
        with Horizontal(
            id="check_param_controls",
            classes="patch-docked-row patch-chip-entry",
        ):
            yield Button("Prev", id="check_param_page_prev_button", classes="patch-chip")
            yield Static("Page 1/1", id="check_param_page_label")
            yield Button("Next", id="check_param_page_next_button", classes="patch-chip")
            yield Button(
                "Include parameter",
                id="check_param_include_button",
                classes="patch-chip",
            )
            yield Static(
                "space also toggles ✓ on the highlighted row",
                classes="ce-hint",
            )

    def on_mount(self) -> None:
        """Add the ledger's columns once, at the pre-measure widths."""
        layout = self._layout()
        table = self.query_one("#check_param_table", DataTable)
        table.add_column("✓", width=1, key="mark")
        table.add_column("Parameter", width=layout.param, key="param")
        table.add_column("Address", width=10, key="address")
        table.add_column(
            "Fmt · Unit" if layout.fmt >= 10 else "Fmt", width=layout.fmt, key="fmt"
        )
        self._refresh_full_name()
        self._refresh_status()
        self._update_page_controls()

    def on_unmount(self) -> None:
        """Cancel a pending filter debounce so it cannot fire unmounted."""
        self._cancel_filter_timer()

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        """Filter the ledger as the operator types (R-B102-SEL-002).

        A result that exceeds one page pays a content-cold mount, so its
        rebuild is debounced 150 ms — one typed burst, one rebuild. A result
        that fits one page mounts at most 200 rows, the same cost the
        debounced render would pay, so it rebuilds synchronously and the
        ledger stays consistent with the filter text at every instant (the
        pre-Inc-3 behavior small parameter sets always had).
        """
        if event.input.id != "check_param_filter":
            return
        event.stop()
        needle = event.value.strip().lower()
        if needle == self._filter_text:
            return
        self._filter_text = needle
        self._page = 1
        matches = sum(
            1 for name in self._param_rows if not needle or needle in name.lower()
        )
        if matches > self._page_size:
            self._schedule_filter_rebuild()
        else:
            self._rebuild_ledger()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Route the control row: page chips and the include button."""
        button_id = event.button.id or ""
        if button_id == "check_param_page_prev_button":
            event.stop()
            self._turn_page(-1)
            return
        if button_id == "check_param_page_next_button":
            event.stop()
            self._turn_page(1)
            return
        if button_id == "check_param_include_button":
            event.stop()
            self._toggle_highlighted()
            return

    def on_include_table_include_toggled(
        self, event: IncludeTable.IncludeToggled
    ) -> None:
        event.stop()
        self._toggle_highlighted()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id == "check_param_table":
            self._refresh_full_name()

    # ------------------------------------------------------------------
    # Filter debounce and pagination
    # ------------------------------------------------------------------

    def _layout(self) -> PickerLayout:
        provider = self._layout_provider
        if provider is not None:
            return provider()
        return _DEFAULT_LAYOUT

    def _page_count(self) -> int:
        return max(1, ceil(len(self._filtered_params) / self._page_size))

    def _cancel_filter_timer(self) -> None:
        timer = self._filter_timer
        if timer is not None:
            timer.stop()
            self._filter_timer = None

    def _schedule_filter_rebuild(self) -> None:
        """Debounce seam for ``Input.Changed`` (R-B102-SEL-002): cancels the
        previous pending timer and schedules one rebuild 150 ms later, so one
        typed burst causes one content-cold rebuild."""
        self._cancel_filter_timer()
        self._filter_timer = self.set_timer(
            FILTER_DEBOUNCE_S, self._rebuild_ledger
        )

    def _turn_page(self, delta: int) -> None:
        """Move the stored page by ``delta``, clamped to ``[1, page_count]``
        (R-B102-SEL-005); the boundary chips disable on the first/last page."""
        self._page = min(max(1, self._page + delta), self._page_count())
        self._rebuild_ledger()

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def _row_cells(self, name: str, layout: PickerLayout) -> tuple:
        """The four ledger cells: mark, Parameter, Address, ``Fmt · Unit``.

        Every cell is a literal ``Text`` (C-17): the file-derived name is
        scrubbed by ``safe_text`` before clipping — no markup path, no control
        byte reaches the table (R-B102-SEL-007).
        """
        address, _size, fmt_unit = self._param_rows[name]
        picked = name in self._picked_params
        plain = safe_text(name).plain
        return (
            Text("✓", style=GREEN) if picked else Text(" "),
            safe_text(clip_param(plain, layout.param), VALUE),
            safe_text(f"0x{address:08X}" if address is not None else "-", CYAN),
            safe_text(_clip_fmt_unit(fmt_unit, layout.fmt)),
        )

    def _rebuild_ledger(self) -> None:
        """The one-page renderer (R-B102-SEL-001/002/005/006).

        Filters source names case-insensitively, clamps the page to the
        result, clears the table and mounts at most one page of rows keyed by
        name, then repaints the full-name line, the count line and the page
        chips. A synchronous rebuild supersedes any pending debounce.
        """
        if not self.is_mounted:
            return
        self._cancel_filter_timer()
        table = self.query_one("#check_param_table", DataTable)
        layout = self._layout()
        needle = self._filter_text
        names = [
            name for name in self._param_rows if not needle or needle in name.lower()
        ]
        self._filtered_params = names
        page_count = self._page_count()
        self._page = min(max(1, self._page), page_count)
        start = (self._page - 1) * self._page_size
        page = names[start : start + self._page_size]
        self._visible_params = page
        table.clear()
        for name in page:
            table.add_row(*self._row_cells(name, layout), key=name)
        self._refresh_full_name()
        self._refresh_status()
        self._update_page_controls()
        self.post_message(
            self.ViewChanged(
                shown=len(page),
                total=len(names),
                page=self._page,
                page_count=page_count,
            )
        )

    def _refresh_full_name(self) -> None:
        """Paint the highlighted row's address, ``Fmt · Unit`` and name under
        the ledger (LLR-145.3); the two empty states paint their message here
        (R-B102-SEL-006), the shipped surface since batch-97.
        """
        if not self.is_mounted:
            return
        line = self.query_one("#check_full_name_line", Static)
        table = self.query_one("#check_param_table", DataTable)
        if not self._visible_params:
            empty = _EMPTY_LEDGER if not self._param_rows else _EMPTY_FILTER
            line.update(Text(empty, style=DGRAY))
            return
        row = table.cursor_row
        if not 0 <= row < len(self._visible_params):
            row = 0
        name = self._visible_params[row]
        address, _size, fmt_unit = self._param_rows[name]
        head = f"0x{address:08X}" if address is not None else "-"
        fmt_unit = fmt_unit.rstrip()
        text = Text(head, style=CYAN)
        text.append(f"  {fmt_unit}  ", style=DGRAY)
        room = max(8, self._layout().full_name - cell_len(text.plain))
        text.append(safe_text(clip_param(safe_text(name).plain, room), VALUE))
        line.update(text)

    def _refresh_status(self) -> None:
        """Paint the separate count line (R-B102-SEL-002): ``<shown> of
        <total> shown``, with `` — refine filter.`` when a FILTER is active
        and its result exceeds one page (the suffix is the filter instruction;
        an unfiltered ledger paints the bare count). Hidden in the two empty
        states — the full-name line carries those messages."""
        if not self.is_mounted:
            return
        status = self.query_one("#check_param_status", Static)
        total = len(self._filtered_params)
        if not self._param_rows or not total:
            status.display = False
            return
        status.display = True
        text = f"{len(self._visible_params)} of {total} shown"
        if self._filter_text and total > self._page_size:
            text += " — refine filter."
        status.update(Text(text, style=DGRAY))

    def _update_page_controls(self) -> None:
        """Disable Prev on the first page and Next on the last (R-B102-SEL-005)."""
        if not self.is_mounted:
            return
        page_count = self._page_count()
        self.query_one("#check_param_page_prev_button", Button).disabled = (
            self._page <= 1
        )
        self.query_one("#check_param_page_next_button", Button).disabled = (
            self._page >= page_count
        )
        self.query_one("#check_param_page_label", Static).update(
            Text(f"Page {self._page}/{page_count}", style=DGRAY)
        )

    def _toggle_highlighted(self) -> None:
        """Include or exclude the highlighted ledger row (R-B102-SEL-003).

        Toggles only that row's mark cell and posts ``SelectionChanged`` — the
        ledger is never rebuilt here.
        """
        if not self._visible_params or not self.is_mounted:
            return
        table = self.query_one("#check_param_table", DataTable)
        cursor = table.cursor_row
        if not 0 <= cursor < len(self._visible_params):
            return
        name = self._visible_params[cursor]
        if name in self._picked_params:
            self._picked_params.remove(name)
        else:
            self._picked_params.append(name)
        table.update_cell_at(
            Coordinate(cursor, 0), self._row_cells(name, self._layout())[0]
        )
        self.post_message(self.SelectionChanged(names=tuple(self._picked_params)))
