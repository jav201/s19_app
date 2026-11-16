"""s19_app.tui.app.shared — shared helpers (moved verbatim from s19_app/tui/app.py at 4f721985)."""
from __future__ import annotations

from dataclasses import dataclass, field
import logging
import re
from pathlib import Path
from typing import Literal, Mapping, Optional, Tuple
from textual import events
from textual.message import Message
from textual.widgets import DataTable, RichLog
from rich.text import Text
from ...core import S19_INTEGRITY_NOTICE_CODES
from ...hexfile import HEX_INTEGRITY_NOTICE_CODES
from ...utils import safe_text
from ..changes.io import (
    CHG_ENCODING_UNKNOWN,
    CHG_FORMAT,
    CHG_KIND_UNKNOWN,
    CHG_V1_FORMAT,
    CHG_VALUE_MODE_UNKNOWN,
    MF_BAD_STRUCTURE,
    MF_JSON_PARSE,
)
from ..changes.model import ChangeDocument, ChangeSummary
from ..models import LoadedFile
from ..insight_style import CYAN, DGRAY, GREEN, LABEL, VALUE
from ...validation import ValidationReport, ValidationSeverity
from ..services.project_gather_service import ProjectInventory, SavePlan
from ..services.variant_execution_service import DerivedFrom, ProjectManifest


#: Inc 9b (G2): the refusal reason word ``_typed_load_route`` returns mapped
#: to the ``(reason_token, step_token)`` pair the Load dialog paints in
#: ``#load_reason`` (LLR-173.5 … LLR-173.5e). Every ``("refuse", <literal>)``
#: the classifier can return is a key here (B57); a new reason with no key
#: raises ``KeyError`` at verdict time.
_TYPED_REFUSAL_TOKENS: dict[str, tuple[str, str]] = {
    "not found": ("not found", "check the path"),
    "not a supported file": ("not a supported file", "check the path"),
    "not a project": ("not a project", "pick a project in the list"),
    "outside": ("outside the work area", "copy the folder into the work area"),
    "link": ("link or junction", "pick a project in the list"),
    # CR9b-03: a typed data or A2L path in the work area that is, or passes
    # through, a link — a file, so the step is not the project list.
    "link file": ("is a link or junction", "open the file it points to"),
    "unreadable": (
        "could not be read",
        "check that the folder can be opened, then load again",
    ),
}

#: Inc 12a (G-A, S-b/S-c/S-f): the progress-indicator seam. ``BusyKey`` is the
#: closed set of long actions that drive the ``#status_text`` spinner line and
#: the ``#progress_bar``; ``_BUSY_ACTIONS`` is the one table of labels and step
#: names (LLR-176.2b), and ``_BusyRun`` / ``_BusyState`` hold the whole run
#: state in ONE app attribute (``self._busy``, main thread only).
BusyKey = Literal[
    "file_load",
    "a2l_load",
    "project_load",
    "save_project",
    "report",
    "diff_report",
    "before_after",
]


@dataclass(frozen=True)
class _BusyAction:
    """S-c: one row of the busy action table — a label template + step names."""

    label: str
    steps: tuple[str, ...]


@dataclass
class _BusyRun:
    """S-b: one running action (mutable, main thread only)."""

    gen: int
    label: str
    steps: tuple[str, ...]
    n: int
    fraction: float
    started: float


#: Upper bound on a synthesized S0 header payload (US-015 / LLR-015.2): the
#: S19 ``byte_count`` field is one byte, so the S0 data plus its 2-byte
#: address and 1-byte checksum cannot exceed 255 — leaving ≤252 data bytes.
#: ``emit_s19_from_mem_map`` enforces the same cap; this trims the synthesized
#: header before it ever reaches the emitter.
_SAVEBACK_S0_MAX_BYTES = 252


_A2L_ISSUE_SEVERITY_RANK: dict[ValidationSeverity, int] = {
    ValidationSeverity.NEUTRAL: 0,
    ValidationSeverity.OK: 1,
    ValidationSeverity.INFO: 2,
    ValidationSeverity.WARNING: 3,
    ValidationSeverity.ERROR: 4,
}
"""Severity ordering for ``_a2l_issue_severity_map`` — ``ERROR`` ranks above all (LLR-037.1)."""


#: Inc 12b (S-h): one A2L parse-cache entry — the stat key (resolved path,
#: mtime_ns, size) and the parsed payload. The key shape
#: ``_load_a2l_data_with_cache`` used before 12b retired it.
A2LCacheEntry = tuple[tuple[str, int, int], dict]

#: The process-global logger ``setup_logging`` returns (workspace.py), so the
#: module-level cache logs land in the same rotating file as ``self.logger``.
_LOG = logging.getLogger("s19tui")


@dataclass
class PreparedLoad:
    """
    Summary:
        Bundle of pre-computed artifacts produced by the load worker so the main UI
        thread only needs to install them onto widgets.

    Args:
        loaded (LoadedFile): Parsed file payload ready to become ``current_file``.
        precomputed (bool): True when the worker populated MAC cache/validation fields.
        mac_cache_key (Optional[tuple]): Cache key that matches the one ``update_mac_view``
            will recompute, so MAC rendering treats the worker output as a cache hit.
        mac_rows / mac_meta / mac_summary / mac_coverage_line: MAC table payload mirroring
            the fields normally populated by ``_build_mac_view_cache``.
        validation_report / validation_issues: Cross-artifact validation output.
        mac_highlights (frozenset[int]): Addresses flagged for orange hex overlay.
        mac_out_of_range (list[int]): Sorted MAC addresses outside the primary image.
        bases_set (Optional[frozenset[int]]): ``frozenset(row_bases)`` for fast hex render.
        a2l_enriched_tags / a2l_enriched_key / a2l_summary_lines: Precomputed A2L enrichment
            state ready to install into ``_a2l_enriched_*`` caches.
        a2l_view_generation / a2l_image_generation (Optional[int]): The
            generation snapshot the worker predicted when precomputing the
            A2L enrichment. The apply preflight accepts the whole bundle only
            when both match the expected post-install generations; a mismatch
            rejects it before any state write. ``None`` on the non-precomputed
            fallback bundle.

    Data Flow:
        - Built inside ``S19TuiApp._prepare_load_payload`` on the worker thread.
        - Consumed by ``S19TuiApp._apply_prepared_load`` on the Textual main thread.

    Dependencies:
        Used by:
            - ``S19TuiApp._start_load_worker``
            - ``S19TuiApp._apply_loaded_file`` (synchronous fallback)
    """

    loaded: LoadedFile
    precomputed: bool = False
    mac_cache_key: Optional[tuple] = None
    mac_rows: list = field(default_factory=list)
    mac_meta: list = field(default_factory=list)
    mac_summary: dict = field(default_factory=dict)
    mac_coverage_line: Optional[str] = None
    validation_report: Optional[ValidationReport] = None
    validation_issues: list = field(default_factory=list)
    mac_highlights: frozenset = field(default_factory=frozenset)
    mac_out_of_range: list = field(default_factory=list)
    bases_set: Optional[frozenset] = None
    a2l_enriched_tags: list = field(default_factory=list)
    a2l_enriched_key: Optional[tuple] = None
    a2l_summary_lines: list = field(default_factory=list)
    # Generation snapshot checked against the expected post-install pair before
    # ``_apply_prepared_load`` performs any cache or session write.
    a2l_view_generation: Optional[int] = None
    a2l_image_generation: Optional[int] = None
    # DataTable-oriented precompute (populated by the load worker):
    # - ``mac_widths``: 8-tuple of column widths matching the historical inline computation
    #   in ``update_mac_view`` so the main thread never rescans full row vectors.
    # - ``mac_cell_rows``: list of 8-string tuples ready to hand to ``DataTable.add_rows``.
    # - ``mac_cell_styles``: parallel list of severity style strings per row.
    mac_widths: Optional[tuple] = None
    mac_cell_rows: list = field(default_factory=list)
    mac_cell_styles: list = field(default_factory=list)
    # Inc 12b (Q-h1): the A2L cache entry the file-load worker used, handed
    # back to the main thread for ``_store_a2l_cache`` (never stored off
    # main). ``PreparedLoad(loaded=…)`` leaves it ``None``.
    a2l_cache: Optional[A2LCacheEntry] = None


_MAC_COLUMN_HEADERS: tuple[str, ...] = (
    "Tag",
    "Address",
    "InA2L",
    "InMem",
    "Status",
    "SourceLine",
    "ParseErr",
    "A2LMatch",
)


_SEVERITY_TO_RICH_STYLE: dict[ValidationSeverity, str] = {
    ValidationSeverity.OK: "green",
    ValidationSeverity.ERROR: "red",
    ValidationSeverity.WARNING: "orange3",
    ValidationSeverity.INFO: "white",
    ValidationSeverity.NEUTRAL: "grey70",
}


def _severity_style(severity: ValidationSeverity) -> str:
    """
    Summary:
        Map a ``ValidationSeverity`` to a Rich-compatible style string usable by
        ``rich.text.Text`` cells inside a Textual ``DataTable``.

    Args:
        severity (ValidationSeverity): Severity to convert.

    Returns:
        str: Style string (e.g. ``"red"``, ``"green"``). Empty string when unknown.

    Dependencies:
        Used by:
            - ``precompute_mac_datatable_payload``
    """
    return _SEVERITY_TO_RICH_STYLE.get(severity, "")


#: Leading MAC status glyph + Rich style (batch-47, LLR-070.1). Derived from the
#: record's precomputed ``Status`` + ``InMem`` cells so the render layer never
#: re-runs validation. Per LLR-070.1 and the sev-* convention (green = memory-
#: checked + present): ``✗`` red = parse-error; ``⚠`` orange = parse-ok +
#: out-of-image (the existing MAC-warning orange); ``✓`` green = parse-ok +
#: in-image; ``·`` grey = NOT image-checked (MAC-only load / no address → the
#: "not yet checked" state — must NOT read as a green "verified present").
_MAC_GLYPH_PARSE_ERROR: tuple[str, str] = ("✗", "red")
_MAC_GLYPH_OUT_OF_IMAGE: tuple[str, str] = ("⚠", "orange3")
_MAC_GLYPH_IN_IMAGE: tuple[str, str] = ("✓", "green")
_MAC_GLYPH_UNCHECKED: tuple[str, str] = ("·", "grey50")

#: Placeholder shown in the A2L detail card before any tag is highlighted
#: (batch-47, LLR-069.1).
_A2L_CARD_HINT = "Highlight a tag to inspect its fields."


def _card_value_text(value: object, style: str = VALUE) -> Text:
    """
    Summary:
        Render one file-derived A2L detail-card value as a markup-safe Rich
        ``Text`` in which each maximal run of break characters is one space and
        every other control character is removed (R-TUI-042a.7.1, .7.2).

    Args:
        value (object): The field value to render; coerced via ``str(value)``.
        style (str): Rich style applied to the whole value. Defaults to
            ``VALUE``.

    Returns:
        Text: A literal ``Text`` holding the scrubbed value; never markup-parsed.

    Data Flow:
        - Coerce ``value`` to ``str``.
        - Replace each maximal run of TAB (U+0009), LF (U+000A) and CR (U+000D)
          with one space, preserving every other character.
        - Hand the scrubbed string to ``safe_text`` (``utils.py:44``), which
          deletes every other C0, DEL and C1 control character and wraps the
          result as a literal ``Text``, never markup.

    Dependencies:
        Uses:
            - ``safe_text``
        Used by:
            - ``_card_field``
            - ``_a2l_detail_card_text``

    Example:
        ``_card_value_text("SYN  desc" + LF + TAB + "part two")`` paints
        ``SYN  desc part two``; ``_card_value_text("m" + TAB + TAB + "s")``
        paints ``m s``.
    """
    scrubbed = re.sub(r"[\t\n\r]+", " ", str(value))
    return safe_text(scrubbed, style=style)


def _card_field(text: Text, label: str, value: object) -> None:
    """
    Summary:
        Append a ``label value`` line to an A2L detail-card ``Text``, skipping
        blank/absent values (batch-47, LLR-069.2). The label is a fixed,
        developer-supplied token (muted); the value goes through
        :func:`_card_value_text` so a file-derived value keeps no control
        character and can never be interpreted as Rich markup (R-TUI-042a.7.1).

    Args:
        text (Text): The card ``Text`` being composed (mutated in place).
        label (str): Fixed field label (never file-derived).
        value (object): The field value; ``None``/empty-string lines are elided.

    Returns:
        None

    Data Flow:
        - Called by :func:`_a2l_detail_card_text` per optional field.
        - Skips ``None`` and ``""``; otherwise appends the line end, the muted
          label, then the value via :func:`_card_value_text`.
        - Also builds the Name line (``"name"``) when the card's header shows
          the display identifier (R-TUI-042a.8).

    Dependencies:
        Uses:
            - rich.text.Text ; LABEL ; _card_value_text
        Used by:
            - _a2l_detail_card_text
    """
    if value is None or value == "":
        return
    text.append("\n")
    text.append(f"{label} ", style=LABEL)
    text.append(_card_value_text(value, style=VALUE))


def _a2l_detail_card_text(tag: Optional[dict]) -> Text:
    """
    Summary:
        Compose the A2L detail card as a single markup-safe Rich ``Text`` from a
        highlighted enriched tag: a header line (in-image glyph + display
        identifier or name + cyan address), the Name line when the header shows
        a display identifier (R-TUI-042a.8), then the tag's description,
        unit·conversion, record layout, byte order, and limits (batch-47,
        LLR-069.2 / LLR-069.3). Every file-derived value is appended through
        :func:`_card_value_text`, so hostile bracket/link/ANSI/unbalanced input
        renders verbatim with no ``MarkupError`` and with no control character
        (C-17; R-TUI-042a.7.1, .7.2). The card reads the tag dict, so it always
        shows the tag's full name — the Tag cell may cut it, the card never
        does (R-TUI-042a.3).

    Args:
        tag (Optional[dict]): The highlighted enriched A2L tag, or ``None`` when
            no row is highlighted (renders the placeholder hint).

    Returns:
        Text: The composed card content. Never a ``str``; never markup-parsed.

    Data Flow:
        - ``None`` → a muted placeholder hint.
        - Otherwise the header (glyph / display identifier or name / address),
          then the Name line when the header shows the display identifier,
          then per-field lines via :func:`_card_field`.
        - The unit·conversion line and the limits line append each file-derived
          value via :func:`_card_value_text`; the absent limit is the empty
          string.

    Dependencies:
        Uses:
            - rich.text.Text ; _card_field ; _card_value_text
            - VALUE ; CYAN ; GREEN ; DGRAY ; LABEL
        Used by:
            - A2LDetailCard.show_tag
    """
    if not tag:
        return Text(_A2L_CARD_HINT, style=DGRAY)
    text = Text()
    in_mem = bool(tag.get("in_memory"))
    text.append("✓ " if in_mem else "· ", style=GREEN if in_mem else DGRAY)
    display_id = tag.get("display_identifier")
    name = tag.get("name")
    text.append(_card_value_text(display_id or name or "UNKNOWN", style=VALUE))
    addr = tag.get("address")
    if isinstance(addr, int):
        text.append("  ")
        text.append(f"0x{addr:08X}", style=CYAN)
    if display_id:
        _card_field(text, "name", name)
    _card_field(text, "desc", tag.get("description"))
    unit = tag.get("unit")
    conversion = tag.get("conversion")
    if unit or conversion:
        text.append("\n")
        text.append("unit ", style=LABEL)
        if unit:
            text.append(_card_value_text(unit, style=VALUE))
        else:
            text.append("—", style=VALUE)
        if conversion:
            text.append(" · conv ", style=LABEL)
            text.append(_card_value_text(conversion, style=VALUE))
    _card_field(text, "layout", tag.get("record_layout_name"))
    _card_field(text, "byteorder", tag.get("effective_byte_order"))
    lower = tag.get("lower_limit")
    upper = tag.get("upper_limit")
    if lower is not None or upper is not None:
        text.append("\n")
        text.append("limits ", style=LABEL)
        text.append(_card_value_text(lower if lower is not None else ""))
        text.append("..", style=VALUE)
        text.append(_card_value_text(upper if upper is not None else ""))
    return text


class _CopyRowTable(DataTable):
    """
    Summary:
        Shared row-copy table base (Inc 1b, R-COPY.21 / R-COPY.22): the one
        base for both copy-able tables — ``A2LTagTable`` and the MAC records
        table. It owns only the non-left click policy: a button-3 (or any
        non-left) click on a valid in-bounds row moves the cursor/highlight
        and suppresses the toolkit's ``RowSelected`` / hex-jump route, while
        left clicks keep the toolkit default and ``out_of_bounds=True``
        padding is prevented from default and returns without moving the
        cursor or emitting ``RowSelected``. Row-name resolution stays in
        ``S19TuiApp._right_click_text``; this class never reads a name.

    Data Flow:
        - ``#a2l_tags_list`` is an ``A2LTagTable`` (this base) and
          ``#mac_records_list`` is a direct instance of this class
          (``_compose_screen_mac``).
        - ``on_click`` runs before ``DataTable._on_click`` in the MRO; a
          ``prevent_default()`` there stops the toolkit default route.

    Dependencies:
        Uses:
            - textual.widgets.DataTable ; textual.events.Click
        Used by:
            - ``A2LTagTable`` (subclass)
            - ``S19TuiApp._compose_screen_mac``
    """

    def on_click(self, event: events.Click) -> None:
        """
        Summary:
            Non-left click on a valid in-bounds row moves the cursor and
            suppresses only the toolkit's selection route; left clicks keep
            the toolkit default, while ``out_of_bounds=True`` padding is
            prevented from default and returns without moving the cursor or
            emitting ``RowSelected`` (Inc 1b, R-COPY.21 / R-COPY.22).

        Args:
            event (events.Click): The click, carrying the cell's
                ``row`` / ``column`` / ``out_of_bounds`` metadata in
                ``event.style.meta``.

        Returns:
            None

        Data Flow:
            - ``out_of_bounds=True`` is empty row padding: prevent the
              default and return without moving the cursor or emitting
              ``RowSelected`` (no copy, no hex jump).
            - An in-bounds ``button == 1`` click returns untouched, so
              ``DataTable._on_click`` still runs (highlight +
              ``RowSelected`` + hex jump on an already-highlighted row).
            - Any other button on a valid in-bounds row calls public
              :meth:`DataTable.move_cursor` (so ``RowHighlighted`` and
              cursor scrolling fire) and then ``prevent_default()`` before
              MRO dispatch can reach ``DataTable._on_click``.

        Dependencies:
            Uses:
                - ``DataTable.move_cursor``
                - ``events.Click.prevent_default``
            Used by:
                - Textual ``Click`` dispatch for both copy tables
        """
        meta = event.style.meta
        if meta.get("out_of_bounds", False):
            event.prevent_default()
            return
        if event.button == 1:
            return
        row = meta.get("row")
        column = meta.get("column")
        if not (isinstance(row, int) and isinstance(column, int)):
            return
        if not (0 <= row < self.row_count and column >= 0):
            return
        self.move_cursor(row=row, column=column, animate=True)
        event.prevent_default()


class A2LTagTable(_CopyRowTable):
    """
    Summary:
        The A2L Explorer's tag table, which REPORTS ITS OWN RESIZE
        (R-TUI-042a.5, batch-103 Inc 12). ``events.Resize`` does not bubble, so
        this subclass re-emits its own resize as a bubbling :class:`Measured`
        message, letting ``S19TuiApp`` re-fit the Tag cells exactly when the
        table's visible width becomes knowable — after a terminal resize or
        after the table is shown (a hidden table's size is ``(0, 0)``).

    Data Flow:
        - Composed by ``S19TuiApp._compose_screen_a2l`` as ``#a2l_tags_list``
          with ``cell_padding=1`` and ``fixed_columns=2`` (I-12.2).
        - ``on_resize`` posts :class:`Measured` →
          ``S19TuiApp.on_a2l_tag_table_measured`` →
          ``S19TuiApp._fit_a2l_tag_cells``.

    Dependencies:
        Uses:
            - textual.widgets.DataTable ; textual.message.Message
        Used by:
            - ``S19TuiApp._compose_screen_a2l``
            - ``S19TuiApp.on_a2l_tag_table_measured``
    """

    class Measured(Message, namespace="a2l_tag_table"):
        """The tag table's size changed, so its visible width is now knowable."""

    suppress_row_highlight = False

    def _highlight_row(self, row_index: int) -> None:
        if self.suppress_row_highlight:
            self.refresh_row(row_index)
        else:
            super()._highlight_row(row_index)

    def on_resize(self, event: events.Resize) -> None:
        """
        Summary:
            Post the bubbling :class:`Measured` message on the table's own
            resize, since ``events.Resize`` does not bubble on its own
            (R-TUI-042a.5).

        Args:
            event (events.Resize): The table's resize event.

        Returns:
            None

        Data Flow:
            - Re-emit the non-bubbling resize as a bubbling message, the house
              idiom of ``BandBar.Measured`` (``screens_directionb.py``).

        Dependencies:
            Uses:
                - ``Widget.post_message``
            Used by:
                - Textual layout, when the table's size changes
        """
        self.post_message(self.Measured())


class A2LDetailCard(RichLog):
    """
    Summary:
        A one-widget A2L detail card mounted at the top of ``#a2l_hex_pane``
        (batch-47, LLR-069.1). It renders the highlighted tag's hidden fields
        above the (shrunken) hex view in the same pane — no new pane. The card
        keeps a bounded height so the hex view below stays reachable at the
        80×24 floor (C-29); its content is a single markup-safe Rich ``Text``.

    Data Flow:
        - ``show_tag(tag)`` replaces the rendered content via
          :func:`_a2l_detail_card_text` (a markup-safe ``Text``).
        - Constructed with the placeholder hint so it renders before any
          highlight.

    Dependencies:
        Uses:
            - _a2l_detail_card_text
        Used by:
            - _compose_screen_a2l (mount) ; on_data_table_row_highlighted (update)

    Note (Textual internal-name shadowing): the subclass adds only ``on_mount``,
    ``on_resize``, ``render``, ``show_tag``, ``_rewrite_card_text`` and its
    current ``_card_text`` — no ``_nodes`` or ``_context`` (or any other
    ``Widget`` private) name is introduced.
    """

    DEFAULT_CSS = """
    A2LDetailCard {
        height: auto;
        max-height: 5;
        overflow-y: auto;
        padding: 0 1;
        border-bottom: solid $panel;
    }
    """

    def on_mount(self) -> None:
        """Paint the placeholder and keep wrapped text clear of scrollbars."""
        self.show_vertical_scrollbar = False
        self.show_tag(None)

    def on_resize(self, event: events.Resize) -> None:
        """Rewrap the current card text at its measured content width."""
        super().on_resize(event)
        if hasattr(self, "_card_text"):
            self._rewrite_card_text()

    def _rewrite_card_text(self) -> None:
        """Write the current text with wrap and paint using one width."""
        self.clear()
        width = self.scrollable_content_region.width
        if width:
            self.write(self._card_text, width=width)
        else:
            self.write(self._card_text)

    def render(self) -> Text:
        """Return the card's current text for the existing Static-era callers."""
        return getattr(self, "_card_text", _a2l_detail_card_text(None))

    def show_tag(self, tag: Optional[dict]) -> None:
        """
        Summary:
            Update the card to show ``tag``'s fields, or the placeholder hint
            when ``tag`` is ``None`` (batch-47, LLR-069.2).

        Args:
            tag (Optional[dict]): The highlighted enriched A2L tag, or ``None``.

        Returns:
            None

        Data Flow:
            - Delegates composition to :func:`_a2l_detail_card_text`, clears the
              log and writes the resulting ``Text`` with markup disabled.

        Dependencies:
            Uses:
                - _a2l_detail_card_text
            Used by:
                - on_data_table_row_highlighted
        """
        self._card_text = _a2l_detail_card_text(tag)
        self._rewrite_card_text()


#: The five HLR-154 load-integrity notice codes (map row B99-I10).
_INTEGRITY_NOTICE_CODES = frozenset(
    S19_INTEGRITY_NOTICE_CODES + HEX_INTEGRITY_NOTICE_CODES
)


def precompute_mac_datatable_payload(
    mac_rows: list[tuple],
    mac_meta: list[dict],
) -> tuple[tuple[int, ...], list[tuple[str, ...]], list[str]]:
    """
    Summary:
        Compute the column widths, row tuples, and per-row severity styles the MAC
        DataTable needs, using the raw row vectors produced by
        ``_compute_mac_view_payload`` so the work happens off the UI thread.

    Args:
        mac_rows (list[tuple]): 8-tuples in display order (Tag, Address, InA2L,
            InMem, Status, SourceLine, ParseErr, A2LMatch).
        mac_meta (list[dict]): Parallel metadata with ``severity`` keys.

    Returns:
        tuple[tuple[int, ...], list[tuple[str, ...]], list[str]]:
            ``(widths, cell_rows, styles)`` where ``widths`` has length 8 and mirrors
            the historical inline width computation in ``update_mac_view``, and
            ``styles`` is a Rich style string per row.

    Data Flow:
        - Single pass over ``mac_rows`` to compute per-column ``max(len(cell))``.
        - Clamp Tag/ParseErr/A2LMatch to 48 chars matching the current renderer.
        - Copy rows verbatim into the returned cell-row list (strings as-is).
        - Pull severity from ``mac_meta`` and map via ``_severity_style``.

    Dependencies:
        Uses:
            - ``_severity_style``
        Used by:
            - ``S19TuiApp._prepare_load_payload``
    """
    if not mac_rows:
        widths = tuple([len(label) for label in _MAC_COLUMN_HEADERS])
        return widths, [], []
    cell_rows: list[tuple[str, ...]] = [tuple(str(cell) for cell in row) for row in mac_rows]
    col_count = len(_MAC_COLUMN_HEADERS)
    widths_list = [len(header) for header in _MAC_COLUMN_HEADERS]
    for row in cell_rows:
        for idx in range(col_count):
            if idx < len(row):
                cell_len = len(row[idx])
                if cell_len > widths_list[idx]:
                    widths_list[idx] = cell_len
    # Clamp the three wide textual columns to match the historical inline computation.
    widths_list[0] = min(widths_list[0], 48)  # Tag
    widths_list[6] = min(widths_list[6], 48)  # ParseErr
    widths_list[7] = min(widths_list[7], 48)  # A2LMatch
    styles: list[str] = []
    for meta in mac_meta or []:
        severity = meta.get("severity") if isinstance(meta, dict) else None
        if isinstance(severity, ValidationSeverity):
            styles.append(_severity_style(severity))
        else:
            styles.append("")
    # Pad styles list to row count if meta was shorter than rows.
    while len(styles) < len(cell_rows):
        styles.append("")
    return tuple(widths_list), cell_rows, styles


def _has_primary(loaded: LoadedFile) -> bool:
    """
    Summary:
        Report whether a snapshot carries a live S19/HEX image spine.

    Args:
        loaded (LoadedFile): Snapshot to inspect.

    Returns:
        bool: ``True`` when ``file_type`` is a primary kind and at least one
            memory range is present.

    Raises:
        None

    Data Flow:
        - Reads ``file_type`` and ``ranges`` only; no mutation.

    Dependencies:
        Uses:
            - ``LoadedFile`` fields ``file_type`` / ``ranges``.
        Used by:
            - ``_unload_mac`` (keep-vs-drop decision) and the Inc-2 panel.

    Example:
        >>> _has_primary(LoadedFile(path=Path("f.s19"), file_type="s19",
        ...     mem_map={0: 1}, row_bases=[0], ranges=[(0, 1)],
        ...     range_validity=[True], errors=[], a2l_path=None, a2l_data=None))
        True
    """
    return loaded.file_type in {"s19", "hex"} and bool(loaded.ranges)


def _has_mac(loaded: LoadedFile) -> bool:
    """
    Summary:
        Report whether a snapshot carries MAC metadata.

    Args:
        loaded (LoadedFile): Snapshot to inspect.

    Returns:
        bool: ``True`` when a ``mac_path`` is attached or MAC records exist.

    Raises:
        None

    Data Flow:
        - Reads ``mac_path`` and ``mac_records`` only; no mutation.

    Dependencies:
        Uses:
            - ``LoadedFile`` fields ``mac_path`` / ``mac_records``.
        Used by:
            - ``_unload_primary`` (MAC-only-vs-``None`` decision) and the
              Inc-2 panel.

    Example:
        >>> lf = LoadedFile(path=Path("t.mac"), file_type="mac", mem_map={},
        ...     row_bases=[], ranges=[], range_validity=[], errors=[],
        ...     a2l_path=None, a2l_data=None, mac_records=[{"name": "RPM"}])
        >>> _has_mac(lf)
        True
    """
    return loaded.mac_path is not None or bool(loaded.mac_records)


def _has_a2l(loaded: LoadedFile) -> bool:
    """
    Summary:
        Report whether a snapshot carries an attached A2L companion.

    Args:
        loaded (LoadedFile): Snapshot to inspect.

    Returns:
        bool: ``True`` when an ``a2l_path`` or parsed ``a2l_data`` is present.

    Raises:
        None

    Data Flow:
        - Reads ``a2l_path`` and ``a2l_data`` only; no mutation.

    Dependencies:
        Uses:
            - ``LoadedFile`` fields ``a2l_path`` / ``a2l_data``.
        Used by:
            - The Inc-2 "Loaded" panel A2L slot.

    Example:
        >>> lf = LoadedFile(path=Path("f.s19"), file_type="s19", mem_map={},
        ...     row_bases=[], ranges=[], range_validity=[], errors=[],
        ...     a2l_path=Path("m.a2l"), a2l_data={"x": 1})
        >>> _has_a2l(lf)
        True
    """
    return loaded.a2l_path is not None or loaded.a2l_data is not None


@dataclass(frozen=True)
class _ProjectImageStep:
    """
    Summary:
        Save project's image decision (LLR-167.1), made on data before
        anything is created: emit the re-derived image, copy the source, or
        refuse the whole save.

    Args:
        emit (bool): True when the re-derived data differs from the source.
        derived (Optional[dict[int, int]]): The re-derived copy (emit only).
        summary (Optional[ChangeSummary]): Its summary (emit only).
        payload (Optional[bytes]): The exact bytes the emit writes.
        name (str): The emitted image's requested name.
        carried (int): Document entries the emitted image carries.
        applied_by_save (int): Of those, the ones no apply wrote before.
        refusal (Optional[str]): The blocked-entries refusal.
    """

    emit: bool
    derived: Optional[dict[int, int]] = None
    summary: Optional[ChangeSummary] = None
    payload: Optional[bytes] = None
    name: str = ""
    carried: int = 0
    applied_by_save: int = 0
    refusal: Optional[str] = None


@dataclass(frozen=True)
class _SaveSession:
    """
    Summary:
        Save project's per-open session (S-d, LLR-175.5, ruling Q-1): the
        inputs that do not depend on the typed name, computed once at the
        dialog's first ``preview`` (or ``confirm``) call and dropped when
        the Save router returns.

    Args:
        image_step (_ProjectImageStep): The image decision.
        digests (dict[Path, Tuple[str, int]]): The image (copy case),
            MAC and A2L digests, once each (S-d); a plain ``dict``, because
            the planner writes the S11-11 memo key into it.
        refusal (Optional[str]): The session refusal (missing source,
            unreadable source, blocked entries).
        image_generation (int): The app's ``_image_generation`` when the
            session was built; a load that lands while the dialog is open
            makes the session stale (SE5-11-1).
        inventory (Optional[ProjectInventory]): The save-as inventory,
            filled lazily at the first new-target preparation (P-1,
            S11-06).
        emitted_record (Optional[DerivedFrom]): The emitted image's
            ``derived_from`` record, computed once per open (A11-01).
        payload_sha256 (Optional[str]): The emitted payload's sha256, once
            per image generation (S11-06).
    """

    image_step: _ProjectImageStep
    digests: dict[Path, Tuple[str, int]]
    refusal: Optional[str]
    image_generation: int
    inventory: Optional[ProjectInventory] = None
    emitted_record: Optional[DerivedFrom] = None
    payload_sha256: Optional[str] = None


@dataclass(frozen=True)
class _PreparedSave:
    """
    Summary:
        The guard-and-plan half's result (S-c): the 12 values that cross
        from the preparation into the commit, plus the refusal/toast the
        router or the preview reads.

    Args:
        typed_name (str): The raw typed name.
        cleaned (str): The sanitised, possibly rebind-to-on-disk-spelling
            name (LED .52(a)).
        project_dir (Path): The target folder (unresolved).
        save_as_source (Optional[Path]): The save-as source, or ``None``.
        source_gone (Optional[str]): The vanished open-project folder name.
        image_step (_ProjectImageStep): The image decision.
        existing (Optional[ProjectManifest]): The target's manifest.
        target_carry (Mapping[str, object]): The carried manifest keys.
        carried_derived (Mapping[str, DerivedFrom]): Carried
            ``derived_from`` records.
        carried_active_document (Optional[str]): The carried
            ``active_document`` text.
        carried_document_line (Optional[str]): The dropped/io-error line.
        emitted_record (Optional[DerivedFrom]): The emitted image's record.
        plan (Optional[SavePlan]): The frozen plan; ``None`` on a refusal
            that carries no plan (A11-02).
        refusal (Optional[str]): The status text the direct path paints;
            its token pair is what the dialog paints.
        toast (bool): The direct path also notifies.
        active_variant (Optional[str]): The merge's predicted active
            variant (P-4), compared in confirm (A11-08).
    """

    typed_name: str
    cleaned: str
    project_dir: Path
    save_as_source: Optional[Path]
    source_gone: Optional[str]
    image_step: _ProjectImageStep
    existing: Optional[ProjectManifest]
    target_carry: Mapping[str, object]
    carried_derived: Mapping[str, DerivedFrom]
    carried_active_document: Optional[str]
    carried_document_line: Optional[str]
    emitted_record: Optional[DerivedFrom]
    plan: Optional[SavePlan]
    refusal: Optional[str]
    toast: bool
    active_variant: Optional[str] = None


#: The reopen caps of a recorded ``active_document`` (E3 R4, LLR-170.3):
#: a file over 1 MiB or over 1 000 entries is never parsed — the parse of
#: a 20 000-entry document took 33 s (probe P1).
REOPEN_MAX_BYTES = 1_048_576
REOPEN_MAX_ENTRIES = 1_000

#: The outcomes of :func:`recorded_document_state` (E3 R10).
DOCUMENT_OK = "ok"
DOCUMENT_MISSING = "missing"
DOCUMENT_LINK = "link"
DOCUMENT_TOO_LARGE = "too_large"
DOCUMENT_UNREADABLE = "unreadable"
DOCUMENT_IO_ERROR = "io_error"

#: The ``classify_active_document`` classes (E3 R11) of a file-backed
#: document that gets a plan row: recorded as on disk, or copied.
_DOCUMENT_IN_HOME = "in_home"

#: The file-level codes that make a recorded document unreadable (E3 R17);
#: an entry-level finding (an unresolved symbol, a blocked entry) never does.
_DOCUMENT_FILE_FAULT_CODES = frozenset(
    {
        MF_JSON_PARSE,
        MF_BAD_STRUCTURE,
        CHG_V1_FORMAT,
        CHG_FORMAT,
        CHG_KIND_UNKNOWN,
        CHG_ENCODING_UNKNOWN,
        CHG_VALUE_MODE_UNKNOWN,
    }
)

#: The exceptions a decode or parse of a recorded document can raise
#: (E3 R10, R19: ``ValueError`` covers an over-long integer literal, and
#: ``json.JSONDecodeError`` and ``UnicodeDecodeError``, its subclasses).
_DOCUMENT_PARSE_ERRORS = (ValueError, RecursionError, TypeError)


@dataclass(frozen=True)
class RecordedDocumentState:
    """
    Summary:
        What one read of a recorded ``active_document`` found (E3 R10): the
        outcome, the parsed document for ``ok``, and a detail for the log.

    Args:
        outcome (str): One of the ``DOCUMENT_*`` outcomes.
        document (Optional[ChangeDocument]): The parsed document (``ok``
            only), else ``None``.
        detail (str): The exception class or reader code — log only, never
            painted (E3 R6).
    """

    outcome: str
    document: Optional[ChangeDocument] = None
    detail: str = ""
