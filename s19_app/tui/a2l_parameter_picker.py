"""The shared Check/Patch A2L parameter picker.

The selector provides a filter, a paged parameter ledger (at most one 200-row
page mounted per rebuild), the highlighted row's full-name line, a separate
count/status line, include and bulk controls, and Prev/Next page chips. State
is keyed by the caller-provided A2L signature so re-entering a screen does not
repopulate the ledger or lose the operator's picks (R-B102-SEL-004).

:func:`parse_parameter_list` splits a pasted name list, ``Add list`` emits
:class:`A2LParameterPicker.BulkAddRequested` for the host to push the modal,
and :meth:`A2LParameterPicker.include_names` includes exact source matches in
one pass, emitting the same ``SelectionChanged`` contract (R-B102-BULK-001..007).

``id_prefix`` rebuilds every child id and internal event route, while a
``layout_provider`` carries the host's proportional widths. ``mode="highlight"``
turns the ledger into a read-only highlighter with no include/bulk controls or
selection events; either mode exposes the current row through
:meth:`A2LParameterPicker.highlighted_parameter` (R-B102-PE-002/003).

Batch-103 Inc 6 normalizes only declared ``length`` as optional size, obtains
element datatype/kind from one batched I-2 description per population, and
renders picker-owned A2L/I-2 names and format/unit strings literally with C0/C1
controls replaced by U+FFFD. Ledger and full-name surfaces clip to their own
cell budgets (R-PICKER-CORRECT.001-.004/.017-.019).

The cell helpers live here so the picker stays import-cycle-free;
:func:`_clip_to_cells` mirrors the host's cell clipping without importing the
panels, and ``screens_directionb`` re-imports :func:`clip_tail` for its
remaining non-ledger painters.
"""

from __future__ import annotations

from math import ceil
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, NamedTuple, Optional, Protocol, Sequence, runtime_checkable

from rich.cells import cell_len, set_cell_size
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.coordinate import Coordinate
from textual.message import Message
from textual.widgets import Button, DataTable, Input, Label, Static

from .a2l_definition import Definition, describe_definitions
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


def parse_parameter_list(text: str) -> list:
    """Split a bulk-pasted name list into trimmed tokens (R-B102-BULK-002).

    Summary:
        The bulk modal's pure parser. New lines, carriage returns, commas
        and semicolons are normalized to spaces, then the text splits on
        whitespace — so every contract separator (and any combination of
        them) delimits names. Input order is preserved, repeated tokens are
        kept (the duplicate control lives in
        :meth:`A2LParameterPicker.include_names`) and empty tokens never
        reach the list.

    Args:
        text (str): The operator's pasted buffer.

    Returns:
        list: The trimmed, non-empty tokens in input order.

    Example:
        >>> parse_parameter_list("Alpha\\nBeta, Gamma; Delta   Alpha")
        ['Alpha', 'Beta', 'Gamma', 'Delta', 'Alpha']
        >>> parse_parameter_list(" ,;\\n ")
        []
    """
    normalized = (
        str(text)
        .replace("\r", " ")
        .replace("\n", " ")
        .replace(",", " ")
        .replace(";", " ")
    )
    return [token for token in normalized.split() if token]


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


_DATATYPE_FORMATS = {
    "UBYTE": "u8",
    "BYTE": "u8",
    "SBYTE": "s8",
    "UWORD": "u16",
    "WORD": "u16",
    "SWORD": "s16",
    "ULONG": "u32",
    "LONG": "u32",
    "SLONG": "s32",
    "A_UINT64": "u64",
    "A_INT64": "s64",
    "FLOAT16_IEEE": "f16",
    "FLOAT32_IEEE": "f32",
    "FLOAT64_IEEE": "f64",
}


def _format_parameter(definition: Optional[Definition], row: dict) -> str:
    """Return the element datatype label followed by its optional unit.

    A definition is authoritative when supplied. Direct rows without one use
    only their tag ``datatype``/``char_type`` and ``compu_method_unit`` fields.
    """
    if definition is not None:
        datatype = definition.datatype
        kind = definition.kind
        unit = definition.unit
    else:
        datatype = row.get("datatype")
        kind = row.get("char_type")
        unit = row.get("compu_method_unit")
    datatype_key = str(datatype) if datatype is not None else ""
    fmt = (
        "text"
        if kind in ("text", "ASCII")
        else _DATATYPE_FORMATS.get(datatype_key, "?")
    )
    unit_text = str(unit or "")
    return fmt + (f" {unit_text}" if unit_text else "")


def _literal_parameter_text(value: str, style: str = "") -> Text:
    """Return literal text with every C0/C1 control replaced by U+FFFD."""
    transformed = "".join(
        "\ufffd" if ord(character) <= 31 or 127 <= ord(character) <= 159 else character
        for character in value
    )
    return Text(transformed, style=style)


def _clip_fmt_unit(fmt_unit: str, width: int) -> str:
    """Clip a ``u<bits> <unit>`` cell: the unit goes first, the width stays.

    When even the ``u<bits>`` token fills the column, the token is painted
    alone (no room for a ``…``); the full-name line clips to its own budget.
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


@dataclass(frozen=True)
class _PickerIds:
    """The picker's child ids, all derived from the caller's ``id_prefix``.

    Every internal query, event-route comparison and repaint helper reads
    this map — nothing is hardcoded to ``check_param_*`` outside the default
    public Check ids (batch-102 Inc 5, E3 ruling 3). The ONE carve-out is
    the full-name line: the Check Editor shipped ``#check_full_name_line``
    before Inc 3 (TC-B97-58 / AT-B97-04 read it), so the default prefix
    keeps that exact id; any other prefix derives
    ``{prefix}_full_name_line``.
    """

    filter: str
    table: str
    full_name: str
    status: str
    controls: str
    page_prev: str
    page_next: str
    page_label: str
    include: str
    bulk: str


#: The default public prefix — the Check Editor's shipped ids.
DEFAULT_ID_PREFIX = "check_param"

#: The one legacy id the default prefix keeps (see :class:`_PickerIds`).
_LEGACY_FULL_NAME_ID = "check_full_name_line"


def _build_ids(id_prefix: str) -> _PickerIds:
    """Derive every child id from ``id_prefix`` (E3 ruling 3)."""
    return _PickerIds(
        filter=f"{id_prefix}_filter",
        table=f"{id_prefix}_table",
        full_name=(
            _LEGACY_FULL_NAME_ID
            if id_prefix == DEFAULT_ID_PREFIX
            else f"{id_prefix}_full_name_line"
        ),
        status=f"{id_prefix}_status",
        controls=f"{id_prefix}_controls",
        page_prev=f"{id_prefix}_page_prev_button",
        page_next=f"{id_prefix}_page_next_button",
        page_label=f"{id_prefix}_page_label",
        include=f"{id_prefix}_include_button",
        bulk=f"{id_prefix}_bulk_button",
    )


@runtime_checkable
class PickerLayout(Protocol):
    """The width slice the picker paints from (the host's ``CheckLayout``).

    The host (the Check Editor, the Patch Editor at Inc 5) injects a
    ``layout_provider`` returning its derived layout, so the picker never
    imports the host — no import cycle, and no call cycle either: the
    provider reads cached scalars, never picker entry points.
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
    """The shared A2L parameter selector (US-102-03, US-102-05).

    Composes the filter input (``#check_param_filter``), the paged ledger
    (``#check_param_table``, an :class:`IncludeTable` in pick mode, a plain
    ``DataTable`` in highlight mode), the highlighted row's full-name line
    (``#check_full_name_line``), the separate count / status line
    (``#check_param_status``) and the docked control row
    (``#check_param_page_prev_button``, ``#check_param_page_label``,
    ``#check_param_page_next_button``, ``#check_param_include_button``,
    ``#check_param_bulk_button``). The shipped ids are conserved so help,
    tests and the key bar keep working; any other ``id_prefix`` derives its
    whole id family from the prefix (E3 ruling 3), so two pickers mount
    side by side without duplicates (R-B102-PE-002).

    Population is keyed by the caller-provided ``signature`` (the app's safe
    ``_a2l_enriched_key``): an unchanged signature is a no-op that preserves
    the filter text, the page and the picks (R-B102-SEL-004). A ``None``
    signature never short-circuits — the no-op arm only applies to a real,
    matching key — so a bare ``set_parameters(rows)`` always repopulates.

    Modes:

    - ``mode="pick"`` (the default, used by Check and Patch): ``space``/``enter``
      toggle the highlighted row's inclusion; ``SelectionChanged`` carries
      the picked-name tuple; the include and bulk controls paint.
    - ``mode="highlight"``: the ledger is a read-only highlighter — the
      include/bulk controls, the include bindings and every
      ``SelectionChanged`` are disabled (E3 ruling 2) — and the host reads
      the current row through :meth:`highlighted_parameter` (R-B102-PE-003).

    Events:
        ``SelectionChanged``: the picked-name tuple changed (one row toggled
            or a bulk include landed); the host repaints its
            collected-fields previews on it. It stays the single "picks
            changed" contract (E3 ruling 4). Pick mode only.
        ``ViewChanged``: the rendered page changed (populate, filter applied,
            page turned); carries ``shown`` / ``total`` / ``page`` /
            ``page_count`` for observers.
        ``BulkAddRequested``: the operator activated the bulk-add control;
            the host pushes the bulk modal for this picker (R-B102-BULK-001).
            Pick mode only.
    """

    class SelectionChanged(Message, namespace="a2l_parameter_picker"):
        """The picked parameter set changed (R-B102-SEL-003).

        Args:
            names (tuple): The picked parameter names in inclusion order.
        """

        def __init__(self, names: tuple = ()) -> None:
            super().__init__()
            self.names = names

    class BulkAddRequested(Message, namespace="a2l_parameter_picker"):
        """The bulk-add control was activated (R-B102-BULK-001).

        The picker stays presentational (C-7 / E3 ruling 5): it composes
        ``#check_param_bulk_button`` but never pushes the modal itself —
        the Check or Patch host listens and pushes
        :class:`s19_app.tui.screens.BulkParameterAddScreen` for this picker.
        """

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
        id_prefix: str = DEFAULT_ID_PREFIX,
        mode: str = "pick",
        show_include_button: bool = True,
        show_bulk_button: bool = True,
        layout_provider: Optional[Callable[[], PickerLayout]] = None,
        page_size: int = PAGE_SIZE,
        id: Optional[str] = None,
    ) -> None:
        super().__init__(id=id)
        if not id_prefix:
            raise ValueError("id_prefix must be a non-empty string")
        if mode not in ("pick", "highlight"):
            raise ValueError(f"unknown picker mode: {mode!r}")
        #: The mode: ``pick`` includes rows; ``highlight`` only exposes the
        #: highlighted row (batch-102 Inc 5, E3 ruling 2).
        self._mode = mode
        #: Every child id, derived from ``id_prefix`` (E3 ruling 3).
        self._ids = _build_ids(id_prefix)
        #: The include/bulk controls paint only in pick mode — highlight
        #: mode is a read-only highlighter regardless of the flags.
        self._show_include_button = show_include_button and mode == "pick"
        self._show_bulk_button = show_bulk_button and mode == "pick"
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

    @property
    def highlighted_parameter(self) -> Optional[dict]:
        """The highlighted ledger row's source record.

        Summary:
            The read model for the Patch Editor's ``Use parameter`` action
            (R-B102-PE-003): the record under the ledger cursor —
            ``{"name", "address", "size", "fmt_unit"}`` — or ``None`` when
            there is no visible row or the cursor is out of range. The
            ``address`` is the normalized integer the picker stored and
            ``size`` is the positive declared length, both ``None`` when
            missing. Hosts must treat a non-integer address as a non-usable
            row and must not format it as ``0x%08X`` (E3 ruling 9).

        Returns:
            Optional[dict]: The highlighted row's record, or ``None``.

        Example:
            >>> picker = A2LParameterPicker()
            >>> picker.set_parameters(
            ...     [{"name": "TorqueMax", "address": 0x1000, "length": 4}]
            ... )
            True
            >>> picker.highlighted_parameter is None  # not mounted
            True
        """
        if not self.is_mounted or not self._visible_params:
            return None
        table = self.query_one(f"#{self._ids.table}", DataTable)
        cursor = table.cursor_row
        if not 0 <= cursor < len(self._visible_params):
            return None
        name = self._visible_params[cursor]
        address, size, fmt_unit = self._param_rows[name]
        return {
            "name": name,
            "address": address,
            "size": size,
            "fmt_unit": fmt_unit,
        }

    # ------------------------------------------------------------------
    # Population
    # ------------------------------------------------------------------

    def set_parameters(
        self,
        rows: Sequence[dict],
        signature: object = None,
        *,
        a2l_data: Optional[dict] = None,
    ) -> bool:
        """Populate the ledger (R-B102-SEL-001, R-B102-SEL-004, R-B102-SEL-006).

        Normalizes rows into ``{name: (address, size, fmt_unit)}``. Only a
        positive, non-boolean integer ``length`` supplies ``size``; missing or
        refused lengths stay ``None``. With ``a2l_data``, one batched definition
        description supplies every row's element datatype/kind and unit. Direct
        rows without A2L data use their tag datatype/characteristic kind instead.

        When ``signature`` is non-``None`` and equals the stored signature,
        returns ``False`` before describing definitions or touching filter,
        page, picks or table. Otherwise replaces the source rows, clears the
        picks, resets the filter/page state, caches ``fmt_longest`` and rebuilds
        one page.

        Args:
            rows (Sequence[dict]): The loaded A2L's measurable parameters.
            signature (object): The caller-provided identity; ``None`` always
                repopulates.
            a2l_data (Optional[dict]): The loaded parse payload used for one
                batched definition description per real population.

        Returns:
            bool: ``True`` when the ledger was repopulated, ``False`` on the
                unchanged-signature no-op.
        """
        if signature is not None and signature == self._signature:
            return False
        self._signature = signature
        self._param_rows = {}
        self._picked_params = []
        names = [str(row.get("name") or "?") for row in rows]
        definitions = (
            describe_definitions(names, a2l_data) if a2l_data is not None else {}
        )
        for row, name in zip(rows, names):
            address = row.get("address")
            address = (
                int(address)
                if isinstance(address, int) and not isinstance(address, bool)
                else None
            )
            length = row.get("length")
            size = (
                length
                if isinstance(length, int) and not isinstance(length, bool) and length > 0
                else None
            )
            fmt_unit = _format_parameter(definitions.get(name), row)
            self._param_rows[name] = (address, size, fmt_unit)
        self._fmt_longest = max(
            (
                cell_len(_literal_parameter_text(value[2]).plain.rstrip())
                for value in self._param_rows.values()
            ),
            default=0,
        )
        self._filter_text = ""
        self._page = 1
        self._cancel_filter_timer()
        if self.is_mounted:
            filter_input = self.query_one(f"#{self._ids.filter}", Input)
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

        Every shipped id is conserved for the default ``check_param``
        prefix (``#check_param_filter``, ``#check_param_table``,
        ``#check_full_name_line``, ``#check_param_include_button``); the
        count line and the page chips are the increment's additions. In
        ``highlight`` mode the ledger is a plain ``DataTable`` (no include
        bindings) and the include/bulk controls plus the include hint are
        omitted (E3 ruling 2).
        """
        ids = self._ids
        with Horizontal(classes="ce-row"):
            yield Label("Filter", classes="ce-label")
            yield OsClipboardInput(
                placeholder="filter parameters",
                id=ids.filter,
                compact=True,
            )
        table_cls = DataTable if self._mode == "highlight" else IncludeTable
        yield table_cls(
            id=ids.table,
            zebra_stripes=True,
            cursor_type="row",
            classes="nowrap-ledger",
        )
        yield Static("", id=ids.full_name, classes="nowrap-heading")
        status = Static("", id=ids.status)
        status.display = False
        compact = ids.controls == "patch_param_controls"
        if compact:
            status.styles.width = "auto"

        def page_controls():
            yield Button(
                "<" if compact else "Prev",
                id=ids.page_prev,
                classes="patch-chip",
                compact=compact,
            )
            yield Static("Page 1/1", id=ids.page_label)
            yield Button(
                ">" if compact else "Next",
                id=ids.page_next,
                classes="patch-chip",
                compact=compact,
            )
            if self._show_include_button:
                yield Button(
                    "Pick" if compact else "Include parameter",
                    id=ids.include,
                    classes="patch-chip",
                    compact=compact,
                )
            if self._show_bulk_button:
                yield Button(
                    "Add list",
                    id=ids.bulk,
                    classes="patch-chip",
                    compact=compact,
                )
            if self._mode == "pick" and not compact:
                yield Static("space toggles ✓", classes="ce-hint")

        yield status
        with Horizontal(
            id=ids.controls,
            classes="patch-docked-row patch-chip-entry",
        ):
            yield from page_controls()

    def on_mount(self) -> None:
        """Add the ledger's columns once, at the pre-measure widths."""
        layout = self._layout()
        table = self.query_one(f"#{self._ids.table}", DataTable)
        table.add_column("✓", width=1, key="mark")
        table.add_column("Parameter", width=layout.param, key="param")
        table.add_column("Address", width=10, key="address")
        table.add_column(
            "Fmt · Unit" if layout.fmt >= 10 else "Fmt", width=layout.fmt, key="fmt"
        )
        # A population that ran pre-mount must become visible on the first
        # paint instead of waiting for the next filter/page action.
        self._rebuild_ledger()
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
        if event.input.id != self._ids.filter:
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
        ids = self._ids
        button_id = event.button.id or ""
        if button_id == ids.page_prev:
            event.stop()
            self._turn_page(-1)
            return
        if button_id == ids.page_next:
            event.stop()
            self._turn_page(1)
            return
        if button_id == ids.include:
            event.stop()
            self._toggle_highlighted()
            return
        if button_id == ids.bulk:
            event.stop()
            self.post_message(self.BulkAddRequested())
            return

    def on_include_table_include_toggled(
        self, event: IncludeTable.IncludeToggled
    ) -> None:
        event.stop()
        self._toggle_highlighted()

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id == self._ids.table:
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

        A2L/I-2 names and format/unit strings are literal ``Text``: C0/C1
        controls become U+FFFD before cell clipping, and no markup is parsed.
        """
        address, _size, fmt_unit = self._param_rows[name]
        picked = name in self._picked_params
        plain_name = _literal_parameter_text(name).plain
        plain_fmt_unit = _literal_parameter_text(fmt_unit).plain
        return (
            Text("✓", style=GREEN) if picked else Text(" "),
            _literal_parameter_text(clip_param(plain_name, layout.param), VALUE),
            Text(f"0x{address:08X}" if address is not None else "-", style=CYAN),
            _literal_parameter_text(_clip_fmt_unit(plain_fmt_unit, layout.fmt)),
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
        table = self.query_one(f"#{self._ids.table}", DataTable)
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
        (R-B102-SEL-006). Format/unit clips to the budget remaining after the
        address, separators and eight name cells, before the name is fitted.
        """
        if not self.is_mounted:
            return
        line = self.query_one(f"#{self._ids.full_name}", Static)
        table = self.query_one(f"#{self._ids.table}", DataTable)
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
        full_name_width = self._layout().full_name
        plain_fmt_unit = _literal_parameter_text(fmt_unit).plain
        fmt_room = max(1, full_name_width - cell_len(head) - 12)
        fmt_unit = _clip_fmt_unit(plain_fmt_unit, fmt_room)
        text = Text(head, style=CYAN)
        text.append(_literal_parameter_text(f"  {fmt_unit}  ", DGRAY))
        room = max(1, full_name_width - cell_len(text.plain))
        plain_name = _literal_parameter_text(name).plain
        text.append(_literal_parameter_text(clip_param(plain_name, room), VALUE))
        line.update(text)

    def _refresh_status(self) -> None:
        """Paint the separate count line (R-B102-SEL-002): ``<shown> of
        <total> shown``, with `` — refine filter.`` whenever the filtered
        result exceeds the mounted page. Hidden in the two empty states —
        the full-name line carries those messages."""
        if not self.is_mounted:
            return
        status = self.query_one(f"#{self._ids.status}", Static)
        total = len(self._filtered_params)
        if not self._param_rows or not total:
            status.display = False
            return
        status.display = True
        text = f"{len(self._visible_params)} of {total} shown"
        if total > len(self._visible_params):
            text += " — refine filter."
        status.update(Text(text, style=DGRAY))

    def _update_page_controls(self) -> None:
        """Disable Prev on the first page and Next on the last (R-B102-SEL-005)."""
        if not self.is_mounted:
            return
        page_count = self._page_count()
        self.query_one(f"#{self._ids.page_prev}", Button).disabled = (
            self._page <= 1
        )
        self.query_one(f"#{self._ids.page_next}", Button).disabled = (
            self._page >= page_count
        )
        self.query_one(f"#{self._ids.page_label}", Static).update(
            Text(f"Page {self._page}/{page_count}", style=DGRAY)
        )

    def _toggle_highlighted(self) -> None:
        """Include or exclude the highlighted ledger row (R-B102-SEL-003).

        Toggles only that row's mark cell and posts ``SelectionChanged`` — the
        ledger is never rebuilt here. Pick mode only: highlight mode composes
        no include control and binds no include key, so this is unreachable
        there (E3 ruling 2).
        """
        if self._mode != "pick":
            return
        if not self._visible_params or not self.is_mounted:
            return
        table = self.query_one(f"#{self._ids.table}", DataTable)
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

    # ------------------------------------------------------------------
    # Bulk include (batch-102 Inc 4, R-B102-BULK-003/005)
    # ------------------------------------------------------------------

    def include_names(self, names: Sequence[str]) -> dict:
        """Include every listed name that exactly matches a source parameter
        (R-B102-BULK-003, R-B102-BULK-005; E3 rulings 3/4/7).

        Summary:
            The bulk path behind the Inc-4 modal. Counts classify UNIQUE
            names: a repeated token (``Gamma\\nGamma``) counts once, so a
            missing duplicate never inflates ``not_found`` (E3 ruling 3).
            An exact, case-sensitive source match not already picked is
            appended to the picks — existing picks are never cleared or
            reordered; a source match already picked counts
            ``already_included``; anything else counts ``not_found``, with
            ``first_missing`` naming the first missed name in list order.
            Every membership test runs on dict/set, never ``list.index`` /
            ``in`` over the growing pick list, so a thousands-of-tokens
            paste stays linear (E3 ruling 7).

            When at least one name is included, only the affected VISIBLE
            mark cells repaint and ``SelectionChanged`` posts — the message
            stays the single "picks changed" contract (E3 ruling 4) and the
            ledger is never rebuilt here. When nothing is included the pick
            state, the table and the message stream are all untouched.

        Args:
            names (Sequence[str]): The parsed list (see
                :func:`parse_parameter_list`); order matters, repeats allowed.

        Returns:
            dict: ``included`` / ``already_included`` / ``not_found`` counts
                plus ``first_missing`` (``None`` when nothing was missed).

        Example:
            >>> picker = A2LParameterPicker()
            >>> picker.set_parameters(
            ...     [{"name": "Alpha", "address": 1}, {"name": "Beta", "address": 2}]
            ... )
            True
            >>> picker.include_names(["Alpha"])["included"]
            1
            >>> picker.include_names(["Beta", "Beta", "Alpha", "Gamma"])
            {'included': 1, 'already_included': 1, 'not_found': 1, 'first_missing': 'Gamma'}
            >>> picker.picked_params
            ['Alpha', 'Beta']
        """
        if self._mode != "pick":
            # Highlight mode exposes the cursor row instead of a picked set
            # (E3 ruling 2) — nothing may join it or post SelectionChanged.
            return {
                "parsed_unique": 0,
                "included": 0,
                "already_included": 0,
                "not_found": 0,
                "first_missing": None,
            }
        source = self._param_rows
        picked_now = set(self._picked_params)
        included: list = []
        already_included = 0
        not_found = 0
        first_missing: Optional[str] = None
        seen: set = set()
        for raw in names:
            name = raw if isinstance(raw, str) else str(raw)
            if not name or name in seen:
                continue
            seen.add(name)
            if name in source:
                if name in picked_now:
                    already_included += 1
                else:
                    picked_now.add(name)
                    included.append(name)
            else:
                not_found += 1
                if first_missing is None:
                    first_missing = name
        if included:
            self._picked_params.extend(included)
            self._repaint_included_marks(included)
            self.post_message(self.SelectionChanged(names=tuple(self._picked_params)))
        return {
            "parsed_unique": len(seen),
            "included": len(included),
            "already_included": already_included,
            "not_found": not_found,
            "first_missing": first_missing,
        }

    def _repaint_included_marks(self, included: Sequence[str]) -> None:
        """Repaint the ✓ mark cell of every newly included VISIBLE row.

        The bulk include never rebuilds the ledger (R-B102-BULK-007
        doctrine): rows not on the current page keep their state and repaint
        when a later rebuild mounts them.
        """
        if not self.is_mounted:
            return
        fresh = set(included)
        if not any(name in fresh for name in self._visible_params):
            return
        table = self.query_one(f"#{self._ids.table}", DataTable)
        layout = self._layout()
        for index, name in enumerate(self._visible_params):
            if name in fresh:
                table.update_cell_at(
                    Coordinate(index, 0), self._row_cells(name, layout)[0]
                )
