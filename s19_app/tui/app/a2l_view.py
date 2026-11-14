"""s19_app.tui.app.a2l_view — S19TuiApp mixin: a2l_view (moved verbatim from s19_app/tui/app.py at 4f721985)."""
from __future__ import annotations

import json
from pathlib import Path
import time
from typing import Any, Mapping, Optional
from textual.widgets import Button, DataTable, Input, ListItem, ListView, Static
from rich.text import Text
from ...utils import safe_text
from ..insight_style import CYAN, DGRAY, GREEN, VALUE
from ...validation import ValidationIssue, ValidationSeverity
from ..services.a2l_service import enrich_tags_and_render
from ..a2l_describe import CurveDescriptionScreen
from ..a2l import describe_curve_tag
from ..segment_split_view import SplitJoinWindow
from ..workspace import WORKAREA_TEMP
from ..a2l_parameter_picker import parse_parameter_list
from s19_app.tui import a2l_label_list as label_list
from . import deps
from .shared import (
    _A2L_ISSUE_SEVERITY_RANK,
    A2LCacheEntry,
    _severity_style,
    A2LTagTable,
    A2LDetailCard,
)

#: The shipped 16 A2L tag-table columns (text mode), in ``_build_a2l_table_cells``
#: order. List mode swaps these for ``label_list.LIST_COLUMNS`` and back
#: (R-A2L-LIST.009, R-TUI-042a.4).
_A2L_TEXT_COLUMNS = (
    "Address",
    "Length",
    "Tag",
    "Source",
    "Raw",
    "Physical",
    "InMem",
    "Region",
    "Limits",
    "Unit",
    "Bits",
    "Endian",
    "Virt",
    "Func",
    "Access",
    "Dtype",
)


def _a2l_tag_in_memory_display(tag: dict) -> str:
    if not tag.get("memory_checked"):
        return "n/a"
    if tag.get("in_memory") is True:
        return "yes"
    return "no"


def _a2l_tag_unit_display(tag: dict) -> str:
    """
    Summary:
        Choose the best display unit for an A2L tag, preferring explicit ``UNIT`` then COMPU method unit.

    Args:
        tag (dict): Enriched A2L tag dictionary.

    Returns:
        str: Unit text for tables, find, and filter surfaces.

    Raises:
        None

    Data Flow:
        - Prefer ``tag["unit"]`` when present.
        - Fall back to ``tag["compu_method_unit"]`` from resolved ``COMPU_METHOD``.
        - Normalize absent values to an empty string.

    Dependencies:
        Uses:
        - none
        Used by:
        - ``S19TuiApp.update_a2l_tags_view``
        - ``S19TuiApp._a2l_tag_find_haystack``
        - ``S19TuiApp._tag_matches_filter``
    """
    explicit = tag.get("unit")
    if explicit not in (None, ""):
        return str(explicit)
    compu_unit = tag.get("compu_method_unit")
    return "" if compu_unit in (None, "") else str(compu_unit)


def _a2l_issue_severity_map(
    issues: list[ValidationIssue],
) -> dict[str, ValidationSeverity]:
    """
    Summary:
        Derive a casefolded symbol -> maximum-severity map from a validation
        issue list, restricted to issues with ``artifact == "a2l"`` and a
        non-empty symbol (LLR-037.1, US-033 issue-implies-red-row).

    Args:
        issues (list[ValidationIssue]): Current validation issue list
            (``S19TuiApp._validation_issues`` at render time).

    Returns:
        dict[str, ValidationSeverity]: Casefolded issue symbol -> highest
        severity observed for that symbol per ``_A2L_ISSUE_SEVERITY_RANK``
        (``ERROR`` above all).

    Raises:
        None

    Data Flow:
        - Skip issues whose ``artifact`` is not ``"a2l"`` or whose ``symbol``
          is empty/absent (symbol-less codes such as ``A2L_STRUCTURE_ERROR``
          never map).
        - Casefold each symbol so lookups match the engine's ``name.lower()``
          duplicate grouping (``validation/rules.py``).
        - Keep the maximum severity per symbol, order-independent.
        - Pure function: O(issues) build, no widget access; consulted O(1)
          per rendered row.

    Dependencies:
        Uses:
            - ``_A2L_ISSUE_SEVERITY_RANK``
        Used by:
            - ``S19TuiApp.update_a2l_tags_view`` (built once per render)

    Example:
        >>> dup = ValidationIssue(
        ...     code="A2L_DUPLICATE_SYMBOL",
        ...     severity=ValidationSeverity.ERROR,
        ...     message="dup",
        ...     artifact="a2l",
        ...     symbol="RPM",
        ... )
        >>> _a2l_issue_severity_map([dup])
        {'rpm': <ValidationSeverity.ERROR: 'error'>}
    """
    severity_map: dict[str, ValidationSeverity] = {}
    for issue in issues:
        if issue.artifact != "a2l" or not issue.symbol:
            continue
        key = issue.symbol.casefold()
        current = severity_map.get(key)
        if current is None or (
            _A2L_ISSUE_SEVERITY_RANK[issue.severity] > _A2L_ISSUE_SEVERITY_RANK[current]
        ):
            severity_map[key] = issue.severity
    return severity_map


def _a2l_tag_row_severity(
    tag: dict,
    issue_severity_map: Mapping[str, ValidationSeverity],
) -> ValidationSeverity:
    """
    Summary:
        Resolve the severity that colours one A2L table row: an ERROR-severity
        issue mapped to the tag's casefolded name wins; every other case keeps
        the pre-existing schema/memory ladder (LLR-037.2, US-033).

    Args:
        tag (dict): Enriched A2L tag dictionary.
        issue_severity_map (Mapping[str, ValidationSeverity]): Casefolded
            symbol -> max severity map from ``_a2l_issue_severity_map``; pass
            ``{}`` for the ladder-only behavior.

    Returns:
        ValidationSeverity: Row severity consumed by ``_severity_style``.

    Raises:
        None

    Data Flow:
        - Return ``ERROR`` when the tag's casefolded name maps to ``ERROR``.
          Only ERROR recolours — a WARNING-mapped symbol falls through
          unchanged, because the A2L palette is Red/Green/White/Grey only
          (orange is a MAC-view convention; design decision D-2).
        - Otherwise apply the unchanged ladder: ``schema_ok=False`` -> ERROR;
          memory-checked present -> OK; memory-checked absent -> INFO;
          virtual/formula -> INFO; else NEUTRAL.

    Dependencies:
        Uses:
            - none
        Used by:
            - ``S19TuiApp.update_a2l_tags_view``

    Example:
        >>> _a2l_tag_row_severity(
        ...     {"name": "RPM", "schema_ok": True},
        ...     {"rpm": ValidationSeverity.ERROR},
        ... )
        <ValidationSeverity.ERROR: 'error'>
    """
    name = str(tag.get("name") or "").strip()
    if name and issue_severity_map.get(name.casefold()) is ValidationSeverity.ERROR:
        return ValidationSeverity.ERROR
    if not tag.get("schema_ok", True):
        return ValidationSeverity.ERROR
    if tag.get("memory_checked") and tag.get("in_memory") is True:
        return ValidationSeverity.OK
    if tag.get("memory_checked") and tag.get("in_memory") is False:
        return ValidationSeverity.INFO
    if tag.get("virtual") or str(tag.get("source") or "").lower() == "formula":
        return ValidationSeverity.INFO
    return ValidationSeverity.NEUTRAL


def _shorten_tag_name(name: str, width: int) -> str:
    """
    Summary:
        Project a tag name into its *painted tag name*: every character
        outside U+0021 … U+007E is shown as U+FFFD, then the name is cut in the
        middle to at most ``width`` cells (R-TUI-042a.3, .5, .6).

    Args:
        name (str): The tag's full name (file-derived, untrusted).
        width (int): The target cell count of the painted name; values below 1
            are taken as 1 (``…`` alone).

    Returns:
        str: The painted tag name, at most ``width`` cells. When ``name`` is
        longer than ``width``, the result is ``head + "…" + tail`` with
        ``head = (width - 1) // 2`` and ``tail = width - 1 - head`` cells.

    Data Flow:
        - Coerce ``width`` to at least 1.
        - Project each character outside U+0021 … U+007E to U+FFFD so every
          shown character occupies exactly one cell.
        - When ``len(name) <= width``, project the whole name; otherwise
          project only the two retained slices (head and tail), so the cost is
          O(width) even when a hostile tail follows the cut (R-TUI-042a.6).

    Dependencies:
        Uses:
            - none (pure)
        Used by:
            - ``S19TuiApp._build_a2l_table_cells``

    Example:
        ``_shorten_tag_name("ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.COLUMN_DIR", 14)``
        returns ``ASAM.C…UMN_DIR``; the same name at width 1 returns ``…``.
    """
    if width < 1:
        width = 1

    def _project(slice_: str) -> str:
        return "".join(
            ch if "\u0021" <= ch <= "\u007E" else "\uFFFD" for ch in slice_
        )

    if len(name) <= width:
        return _project(name)
    head = (width - 1) // 2
    tail = width - 1 - head
    return _project(name[:head]) + "…" + _project(name[len(name) - tail:])


class A2lViewMixin:

    def _a2l_clamp_page_start(self, total_tags: int) -> int:
        """
        Summary:
            Clamp ``_a2l_window_start`` to a legal page-aligned index for the A2L tags table.

        Args:
            total_tags (int): Number of rows in ``_a2l_filtered_tags``.

        Returns:
            int: Page-aligned start index in ``[0, total_tags)`` (or ``0`` when empty).

        Data Flow:
            - Align the current start down to ``a2l_tags_page_size`` boundaries.
            - Clamp to the last valid page start when the list shrinks.

        Dependencies:
            Used by:
                - ``update_a2l_tags_view``
                - ``_refresh_a2l_filtered_tags``
        """
        ps = self._clamp_viewer_page_size(self.a2l_tags_page_size)
        if total_tags <= 0 or ps <= 0:
            return 0
        aligned = (max(0, self._a2l_window_start) // ps) * ps
        max_start = max(0, ((total_tags - 1) // ps) * ps)
        return max(0, min(aligned, max_start))

    def action_dump_a2l_json(self) -> None:
        """Dump parsed A2L data into JSON in temp."""
        if not self.current_a2l_data:
            self.set_status("No A2L data to export.")
            self.logger.warning("A2L export requested with no data.")
            return
        temp_dir = self.workarea / WORKAREA_TEMP
        temp_dir.mkdir(parents=True, exist_ok=True)
        base_name = (
            self.current_a2l_path.stem
            if self.current_a2l_path
            else (self.current_file.path.stem if self.current_file else "a2l")
        )
        output = temp_dir / f"{base_name}.a2l.json"
        output.write_text(json.dumps(self.current_a2l_data, indent=2), encoding="utf-8")
        self.set_status(f"A2L JSON saved: {output.name}")
        self.logger.info("A2L JSON exported: %s", output)

    def action_a2l_describe_tag(self) -> None:
        """Open the E9 parameter description for the selected A2L tag.

        Summary:
            The ``d`` action on the A2L Explorer: resolve the highlighted
            ``#a2l_tags_list`` row to its enriched tag, build the E9
            description (A2L metadata + decoded CURVE/MAP points from the
            loaded image) and push the read-only modal. Self-guarding like
            the dump/export actions: outside the A2L screen, with no A2L
            loaded, or with no row under the cursor it is a no-op (a
            scalar tag still opens — the modal shows its honest
            ``not_a_curve`` header).

        Args:
            None

        Returns:
            None

        Dependencies:
            Uses:
                - ``describe_curve_tag`` / ``CurveDescriptionScreen``
                - ``_a2l_row_key_to_tag`` (the row_key -> tag map the
                  table render maintains)
            Used by:
                - the ``d`` binding (E9, batch-96)
        """
        if self._active_screen_key != "a2l" or not self.current_a2l_data:
            return
        try:
            a2l_table = self.query_one("#a2l_tags_list", DataTable)
        except Exception:
            return
        row_index = a2l_table.cursor_row
        if row_index is None:
            self.set_status("A2L: no tag row under the cursor.")
            return
        try:
            row_key, _ = a2l_table.coordinate_to_cell_key((row_index, 0))
        except Exception:
            return
        key_value = getattr(row_key, "value", row_key)
        tag = (
            self._a2l_row_key_to_tag.get(str(key_value))
            if isinstance(key_value, str)
            else None
        )
        if not isinstance(tag, dict):
            self.set_status("A2L: no tag row under the cursor.")
            return
        mem_map = self.current_file.mem_map if self.current_file else None
        description = describe_curve_tag(tag, self.current_a2l_data, mem_map)
        self.push_screen(CurveDescriptionScreen(description))

    def action_a2l_tags_page_next(self) -> None:
        """
        Summary:
            Advance the A2L tags table by one page of ``a2l_tags_page_size`` rows.

        Args:
            None

        Returns:
            None

        Data Flow:
            - Bump ``_a2l_window_start`` by one page and clamp to the last legal page start.
            - Re-render the current filtered tag slice.

        Dependencies:
            Uses:
                - ``update_a2l_tags_view``
        """
        total = len(self._a2l_filtered_tags)
        if total <= 0:
            return
        page_size = self._clamp_viewer_page_size(self.a2l_tags_page_size)
        max_start = max(0, ((total - 1) // page_size) * page_size)
        self._a2l_window_start = min(max_start, self._a2l_window_start + page_size)
        self._alt_goto_focus_address = None
        self.update_a2l_tags_view(self._a2l_filtered_tags)

    def action_a2l_tags_page_prev(self) -> None:
        """
        Summary:
            Move the A2L tags table back by one page of ``a2l_tags_page_size`` rows.

        Args:
            None

        Returns:
            None

        Data Flow:
            - Decrement ``_a2l_window_start`` by one page and clamp at zero.
            - Re-render the current filtered tag slice.

        Dependencies:
            Uses:
                - ``update_a2l_tags_view``
        """
        if not self._a2l_filtered_tags:
            return
        page_size = self._clamp_viewer_page_size(self.a2l_tags_page_size)
        self._a2l_window_start = max(0, self._a2l_window_start - page_size)
        self._alt_goto_focus_address = None
        self.update_a2l_tags_view(self._a2l_filtered_tags)

    def _a2l_tag_byte_length_for_hex_highlight(self, tag: dict) -> int:
        """
        Summary:
            Choose a byte span for alt-hex highlighting from an A2L tag record.

        Args:
            tag (dict): Enriched tag row including optional integer ``length``.

        Returns:
            int: Positive byte length, capped by ``a2l_tag_hex_highlight_max_bytes``.

        Data Flow:
            - Prefer parsed ``length`` when it is a positive integer.
            - Fall back to a single-byte span when length is unknown.

        Dependencies:
            Used by:
                - ``_jump_to_tag``
                - ``_handle_a2l_tag_find_next``
        """
        raw = tag.get("length")
        if isinstance(raw, int) and raw > 0:
            return min(raw, self.a2l_tag_hex_highlight_max_bytes)
        return 1

    def _jump_to_tag(self, item: ListItem) -> None:
        """
        Summary:
            Legacy ListView adapter that unpacks ``item.data`` into the shared
            ``_jump_to_tag_by_data`` helper so both DataTable and ListView paths
            share one implementation.

        Args:
            item (ListItem): A2L tags table row with ``item.data`` holding ``tag``.

        Returns:
            None

        Dependencies:
            Uses:
                - ``_jump_to_tag_by_data``
        """
        tag_info = getattr(item, "data", None)
        if not isinstance(tag_info, dict):
            return
        tag = tag_info.get("tag")
        if isinstance(tag, dict):
            self._jump_to_tag_by_data(tag)

    def _jump_to_tag_by_data(self, tag: dict) -> None:
        """
        Summary:
            Focus the alt hex panel on an A2L tag's address with a byte-range highlight.

        Args:
            tag (dict): Enriched A2L tag dict carrying ``address`` and optionally ``length``.

        Returns:
            None

        Data Flow:
            - Return early when no integer address is present.
            - Store ``_a2l_tag_hex_highlight`` so ``update_alt_hex_view`` can paint a span.
            - Re-render alt hex centered on the tag address.

        Dependencies:
            Uses:
                - ``_a2l_tag_byte_length_for_hex_highlight``
                - ``update_alt_hex_view``
                - ``set_status``
            Used by:
                - ``on_data_table_row_selected`` for the A2L DataTable
                - ``_jump_to_tag`` (legacy ListView adapter)
        """
        addr = tag.get("address") if isinstance(tag, dict) else None
        if not isinstance(addr, int):
            return
        span = self._a2l_tag_byte_length_for_hex_highlight(tag if isinstance(tag, dict) else {})
        self._a2l_tag_hex_highlight = (addr, span)
        self.last_search_address = None
        self._alt_goto_focus_address = None
        self.update_alt_hex_view(addr, near_top=True, reset_scroll=True)
        self.set_status(f"Tag at 0x{addr:08X}")

    def _focus_a2l_tag_absolute_index(self, absolute_index: int) -> bool:
        """
        Summary:
            Snap the tags table to the page that contains a tag and move list focus to that row.

        Args:
            absolute_index (int): Index into ``_a2l_filtered_tags``.

        Returns:
            bool: True when focus was applied; False when the index is out of range or the list is empty.

        Data Flow:
            - Align ``_a2l_window_start`` to ``(absolute_index // page_size) * page_size``.
            - Rebuild the visible page via ``update_a2l_tags_view``.
            - Set ``ListView.index`` to the summary/header offset plus the in-page row.

        Dependencies:
            Uses:
                - ``update_a2l_tags_view``
            Used by:
                - ``_handle_a2l_tag_find_next``
        """
        tags = self._a2l_filtered_tags
        total = len(tags)
        if total == 0 or absolute_index < 0 or absolute_index >= total:
            return False
        page_size = self._clamp_viewer_page_size(self.a2l_tags_page_size)
        self._a2l_window_start = (absolute_index // page_size) * page_size
        self.update_a2l_tags_view(tags)
        try:
            a2l_table = self.query_one("#a2l_tags_list", DataTable)
            row_offset = absolute_index - self._a2l_window_start
            if 0 <= row_offset < a2l_table.row_count:
                a2l_table.move_cursor(row=row_offset)
        except Exception:
            # Widget may not be fully mounted in test harnesses; focus is best-effort.
            pass
        return True

    def _a2l_tag_find_haystack(self, tag: dict) -> str:
        def _safe(value: Any) -> str:
            return "" if value is None else str(value)

        return " ".join(
            [
                _safe(tag.get("name")),
                _safe(tag.get("address")),
                _safe(tag.get("length")),
                _safe(tag.get("source")),
                _safe(tag.get("raw_value")),
                _safe(tag.get("physical_value")),
                _a2l_tag_in_memory_display(tag),
                _safe(tag.get("lower_limit")),
                _safe(tag.get("upper_limit")),
                _a2l_tag_unit_display(tag),
                _safe(tag.get("bit_org")),
                _safe(tag.get("endian")),
                _safe(tag.get("virtual")),
                _safe(tag.get("function_group")),
                _safe(tag.get("access")),
                _safe(tag.get("datatype")),
                _safe(tag.get("description")),
                _safe(tag.get("memory_region")),
            ]
        ).lower()

    def _a2l_tag_matches_find_query(self, tag: dict, query: str) -> bool:
        if not query.strip():
            return False
        return query.lower() in self._a2l_tag_find_haystack(tag)

    def _handle_a2l_tag_find_next(self) -> None:
        """
        Summary:
            Find the next filtered A2L tag matching the tag-find query, then page and highlight it.

        Args:
            None (reads ``#a2l_tag_find_input`` and ``_a2l_filtered_tags``).

        Returns:
            None

        Data Flow:
            - Normalize query and reset cyclic cursor when the query string changes.
            - Scan forward from the prior match with wrap-around.
            - Snap the table, set alt hex span highlight, and refresh the alt panel.

        Dependencies:
            Uses:
                - ``_a2l_tag_matches_find_query``
                - ``_focus_a2l_tag_absolute_index``
                - ``_a2l_tag_byte_length_for_hex_highlight``
                - ``update_alt_hex_view``
                - ``set_status``
            Used by:
                - ``on_button_pressed`` for ``a2l_tag_find_next``
        """
        query = self.query_one("#a2l_tag_find_input", Input).value.strip()
        if not query:
            self.set_status("Tag find query is empty.")
            return
        tags = self._a2l_filtered_tags
        if not tags:
            self.set_status("No A2L tags to search.")
            return
        if query != self._a2l_tag_find_query:
            self._a2l_tag_find_query = query
            self._a2l_tag_find_last_index = -1
        n = len(tags)
        start = (self._a2l_tag_find_last_index + 1) % n
        for k in range(n):
            i = (start + k) % n
            if self._a2l_tag_matches_find_query(tags[i], query):
                self._a2l_tag_find_last_index = i
                self._focus_a2l_tag_absolute_index(i)
                addr = tags[i].get("address")
                self.last_search_address = None
                self._alt_goto_focus_address = None
                if isinstance(addr, int):
                    span = self._a2l_tag_byte_length_for_hex_highlight(tags[i])
                    self._a2l_tag_hex_highlight = (addr, span)
                    self.update_alt_hex_view(addr, near_top=True, reset_scroll=True)
                else:
                    self.update_alt_hex_view()
                name = str(tags[i].get("name") or "")
                self.set_status(f"Tag find: {name} (row {i + 1})")
                return
        self.set_status("Tag find: no match.")

    def _a2l_cache_entry(self) -> Optional[A2LCacheEntry]:
        """S-h: the current A2L cache entry, or ``None`` (LLR-177.1d).

        Summary:
            Read the two ``_a2l_cache_*`` attributes and return them as one
            entry; writes nothing. Main thread (also read once by the
            file-load worker inside ``_parse_loaded_file``, as that worker
            reads the session today).

        Returns:
            Optional[A2LCacheEntry]: ``(key, data)`` when both are set.

        Dependencies:
            Used by: _handle_load_project / _parse_loaded_file /
                load_a2l_from_path
        """
        key, data = self._a2l_cache_key, self._a2l_cache_data
        return (key, data) if key is not None and data is not None else None

    def _store_a2l_cache(self, entry: A2LCacheEntry) -> None:
        """S-h: the one main-thread writer of the A2L cache (LLR-177.1d)."""
        self._a2l_cache_key, self._a2l_cache_data = entry

    def _log_a2l_parse_summary(self, path: Path, a2l_data: Optional[dict[str, Any]], elapsed_seconds: float) -> None:
        """
        Summary:
            Log a normalized A2L parse result summary and emit warnings for slow or error-heavy loads.

        Args:
            path (Path): Parsed A2L path.
            a2l_data (Optional[dict[str, Any]]): Parse payload from ``parse_a2l_file``.
            elapsed_seconds (float): Total parse stage duration in seconds.

        Returns:
            None

        Data Flow:
            - Derive section, tag, and parse error counts from payload.
            - Emit INFO summary with elapsed time and payload dimensions.
            - Emit WARNING when elapsed time exceeds configured threshold.
            - Emit WARNING with sample parse errors when parser reports structural issues.

        Dependencies:
            Uses:
                - ``logger.info`` / ``logger.warning``
            Used by:
                - ``load_a2l_from_path``
        """
        payload = a2l_data or {}
        sections = payload.get("sections", [])
        tags = payload.get("tags", [])
        errors = payload.get("errors", [])
        self.logger.info(
            "A2L parse summary: path=%s elapsed_seconds=%.3f sections=%d tags=%d errors=%d",
            path,
            elapsed_seconds,
            len(sections),
            len(tags),
            len(errors),
        )
        if elapsed_seconds > self.slow_parse_warn_seconds:
            self.logger.warning(
                "A2L parse exceeded threshold: path=%s elapsed_seconds=%.3f threshold_seconds=%.3f",
                path,
                elapsed_seconds,
                self.slow_parse_warn_seconds,
            )
        if errors:
            sample = "; ".join(str(item) for item in errors[:3])
            self.logger.warning("A2L parse reported structural errors: path=%s sample=%s", path, sample)

    def _invalidate_a2l_view_cache(self) -> None:
        """
        Summary:
            Clear the A2L enrichment/filter caches and the tag row-key map
            (batch-102 Inc 2): the derived view state that must never
            outlive the payload it was computed from.

        Args:
            None

        Returns:
            None

        Data Flow:
            - Reset ``_a2l_enriched_tags`` / ``_a2l_enriched_key`` and
              ``_a2l_filtered_tags`` to empty, and empty
              ``_a2l_row_key_to_tag`` so no stale row maps to a tag of the
              previous payload (R-B102-A2L-005).

        Dependencies:
            Used by:
                - ``_replace_current_a2l`` (the single-writer seam)
        """
        self._a2l_enriched_tags = []
        self._a2l_enriched_key = None
        self._a2l_filtered_tags = []
        self._a2l_row_key_to_tag = {}

    def _replace_current_a2l(
        self, a2l_path: Optional[Path], a2l_data: Optional[dict]
    ) -> None:
        """
        Summary:
            Single-writer seam for every ``current_a2l_path`` /
            ``current_a2l_data`` replacement or clear (batch-102 Inc 2,
            R-B102-A2L-001/.004/.005): direct attach, project install,
            file-load install and clear/unload all funnel through here.

        Args:
            a2l_path (Optional[Path]): The A2L artifact now in effect, or
                ``None`` when none is.
            a2l_data (Optional[dict]): The parsed A2L payload, or ``None``
                on clear/unload. May be a distinct dict at a reused object
                address — that is exactly why the generation bump exists.

        Returns:
            None

        Data Flow:
            - Replace both members, bump ``_a2l_view_generation``, and
              clear the enrichment/filter caches plus the row-key map via
              ``_invalidate_a2l_view_cache``.
            - Leave rendering to the caller: every call site runs the
              existing ``update_a2l_view()`` (directly or through the
              load chain) when the UI must repaint.

        Dependencies:
            Used by:
                - ``_install_attached_a2l`` / ``_install_prepared_project``
                - ``_apply_prepared_load`` / ``_apply_unload`` /
                  ``_reset_project_session``
        """
        self.current_a2l_path = a2l_path
        self.current_a2l_data = a2l_data
        self._a2l_view_generation += 1
        self._invalidate_a2l_view_cache()

    def _compute_a2l_enriched_tags(self) -> list[dict[str, Any]]:
        """
        Summary:
            Build and cache validated A2L tag payload used by summary, filters, and buffered list rendering.

        Args:
            None

        Returns:
            list[dict[str, Any]]: Enriched A2L tags with schema/memory validation fields.

        Data Flow:
            - Derive the cache key from the A2L attach generation, the
              image generation and the memory map size — never from
              ``id()``: CPython can reuse a freed dict's address for the
              next payload, and an equal-size memory map would leave an
              identity key unchanged (F-B102-A2L-1). Including
              ``_image_generation`` makes an equal-size/different-content
              image reload recompute automatically (R-B102-A2L-002).
            - Reuse previous enriched list when key is unchanged.
            - Use ``enrich_tags_and_render`` to compute merged tags and summary lines on cache miss.

        Dependencies:
            Uses:
                - ``enrich_tags_and_render``
            Used by:
                - ``update_a2l_view``
                - A2L filter debounce render path
        """
        if not self.current_a2l_data:
            self._a2l_enriched_tags = []
            self._a2l_enriched_key = None
            return []
        mem_map = self.current_file.mem_map if self.current_file else None
        mem_size = len(mem_map) if mem_map is not None else -1
        key = (self._a2l_view_generation, self._image_generation, mem_size)
        if self._a2l_enriched_key == key:
            return self._a2l_enriched_tags
        enriched, summary_lines = enrich_tags_and_render(
            self.current_a2l_data,
            mem_map,
            max_tag_lines=500,
        )
        self._a2l_enriched_tags = enriched
        self._a2l_enriched_key = key
        self._a2l_summary_lines = summary_lines
        self._a2l_summary_start = 0
        return enriched

    def _update_a2l_summary_buffer(self) -> None:
        """
        Summary:
            Render a buffered slice of A2L summary lines into the summary panel.

        Args:
            None

        Returns:
            None

        Data Flow:
            - Clamp summary window start/end indices.
            - Build header describing visible slice.
            - Push visible lines only into ``#a2l_view`` widget.

        Dependencies:
            Uses:
                - ``_get_window_bounds``
            Used by:
                - ``update_a2l_view``
        """
        a2l_view = self.query_one("#a2l_view", Static)
        if not self._a2l_summary_lines:
            a2l_view.update("No A2L loaded.")
            return
        total = len(self._a2l_summary_lines)
        start, end = self._get_window_bounds(total, self._a2l_summary_start, self.a2l_summary_window_size)
        self._a2l_summary_start = start
        visible = self._a2l_summary_lines[start:end]
        header = f"A2L summary lines {start + 1}-{end} / {total}"
        a2l_view.update("\n".join([header, "-" * len(header), *visible]))

    def _refresh_a2l_filtered_tags(self, preserve_anchor: bool) -> None:
        """
        Summary:
            Rebuild the filtered A2L tag source list (list mode or text mode)
            and render the buffered window plus the filter chips.

        Args:
            preserve_anchor (bool): Keep the current buffered start when
                possible; otherwise reset to top.

        Returns:
            None

        Data Flow:
            - List mode with ``preserve_anchor=True`` (the in-place write
              route's fallback, ``patch.py:1847``): repaint the shown page in
              place and refresh the chips, no ``clear()`` (R-A2L-LIST.036).
            - Otherwise filter via ``_filter_a2l_tags``, reset or clamp the
              anchor, and render the window through ``update_a2l_tags_view``.
            - A non-empty text with no row passes the short-text summary, the
              mode-hint variant when the text matches under ``All``
              (R-A2L-LIST.025); then paint the filter chips.

        Dependencies:
            Uses:
                - ``_a2l_list_names`` / ``_filter_a2l_tags`` / ``_a2l_empty_message``
                - ``_repaint_a2l_tag_cells`` / ``_paint_a2l_filter_chips``
                - ``update_a2l_tags_view``
            Used by:
                - ``update_a2l_view``
                - filter and debounce handlers
        """
        if preserve_anchor and self._a2l_list_names() is not None:
            self._repaint_a2l_tag_cells()
            self._paint_a2l_filter_chips()
            return
        self._a2l_filtered_tags = self._filter_a2l_tags(self._a2l_enriched_tags)
        if not preserve_anchor:
            self._a2l_window_start = 0
        else:
            self._a2l_window_start = self._a2l_clamp_page_start(len(self._a2l_filtered_tags))
        filter_text = self.a2l_tags_filter_text
        if not self._a2l_filtered_tags and filter_text:
            self.update_a2l_tags_view(
                self._a2l_filtered_tags,
                empty_message=self._a2l_empty_message(filter_text),
            )
            self._paint_a2l_filter_chips()
            return
        self.update_a2l_tags_view(self._a2l_filtered_tags)
        self._paint_a2l_filter_chips()

    def _a2l_empty_message(self, text: str) -> str:
        """
        Summary:
            Build the no-match summary for an empty text-mode result, switching
            to the mode hint when the text would match under ``All``.

        Args:
            text (str): The stripped, non-empty filter text.

        Returns:
            str: ``No A2L tags match '<short>'.``, or ``No tag matches
                '<short>' with mode <label> — <n> match with mode All alt+a``
                when the text matches at least one tag under ``All`` and the
                active mode is not ``all``. ``<short>`` is the short text of
                ``text`` (``display_text(text, 64)``).

        Data Flow:
            - Shorten the text once (E3S-02).
            - With mode ``all``, or when the text matches nothing under
              ``all``, keep the R-B102-A2L-003 summary with the short text.
            - Otherwise count the tags the text matches under ``all`` and
              build the mode-hint summary (R-A2L-LIST.025).

        Dependencies:
            Uses:
                - ``_tag_matches_filter``
                - ``display_text`` / ``MODE_LABEL`` (a2l_label_list)
            Used by:
                - ``_refresh_a2l_filtered_tags``
        """
        short = label_list.display_text(text, 64)
        mode = self.a2l_tags_filter_mode
        if mode == "all":
            return f"No A2L tags match '{short}'."
        lower = text.lower()
        matches = sum(
            1 for tag in self._a2l_enriched_tags if self._tag_matches_filter(tag, lower)
        )
        if not matches:
            return f"No A2L tags match '{short}'."
        label = label_list.MODE_LABEL.get(mode, mode)
        return (
            f"No tag matches '{short}' with mode {label} "
            f"— {matches} match with mode All alt+a"
        )

    def _paint_a2l_filter_chips(self) -> None:
        """
        Summary:
            Paint the list-mode / text-mode filter chips, mode tag and missing
            line above the A2L tag table (R-A2L-LIST.007-.008, .017-.024).

        Args:
            None

        Returns:
            None

        Data Flow:
            - Decide list mode via ``_a2l_list_names`` and mark the active
              mode's button with the ``-on`` class.
            - Paint the mode tag (``LIST`` / ``FILTER``) and the chips line(s).
            - Show ``#a2l_list_missing`` with the missing line in list mode and
              hide it in text mode. Every widget is queried defensively so an
              uncomposed surface is a no-op.

        Dependencies:
            Uses:
                - ``_a2l_list_names`` / ``_mark_a2l_filter_mode``
                - ``_a2l_list_chips`` / ``_a2l_text_chips``
            Used by:
                - ``_refresh_a2l_filtered_tags``
        """
        names = self._a2l_list_names()
        self._mark_a2l_filter_mode()
        mode_tag = self.query("#a2l_filter_mode_tag")
        if mode_tag:
            mode_tag.first(deps.Label).update("LIST" if names is not None else "FILTER")
        if names is not None:
            chips, missing = self._a2l_list_chips()
        else:
            chips, missing = self._a2l_text_chips(), None
        chips_widget = self.query("#a2l_list_chips")
        if chips_widget:
            chips_widget.first(Static).update(chips)
        missing_widget = self.query("#a2l_list_missing")
        if not missing_widget:
            return
        missing_static = missing_widget.first(Static)
        if missing is None:
            missing_static.add_class("hidden")
        else:
            missing_static.remove_class("hidden")
            missing_static.update(missing)

    def _mark_a2l_filter_mode(self) -> None:
        """Mark the active filter mode's button with the ``-on`` class (R-A2L-007.9)."""
        active = {
            "all": "a2l_filter_all",
            "invalid": "a2l_filter_invalid",
            "inmem": "a2l_filter_inmem",
        }.get(self.a2l_tags_filter_mode)
        for button_id in ("a2l_filter_all", "a2l_filter_invalid", "a2l_filter_inmem"):
            buttons = self.query(f"#{button_id}")
            if not buttons:
                continue
            button = buttons.first(Button)
            if button_id == active:
                button.add_class("-on")
            else:
                button.remove_class("-on")

    def _a2l_list_names(self) -> Optional[list[str]]:
        """
        Summary:
            Return the pasted names when the viewer is in list mode, else ``None``.

        Args:
            None

        Returns:
            Optional[list[str]]: The pasted names in order when an A2L is
                loaded, the filter field is ``name`` or ``all`` and the filter
                text is a list text (two or more names); else ``None`` (text
                mode).

        Data Flow:
            - An unloaded A2L, a non-``name``/``all`` field, or fewer than two
              parsed names each fall through to ``None`` (R-A2L-LIST.008, E3A-08).

        Dependencies:
            Uses:
                - ``parse_parameter_list`` (I-5)
            Used by:
                - ``_filter_a2l_tags``
                - ``_refresh_a2l_filtered_tags``
                - ``_paint_a2l_filter_chips``
        """
        if not self.current_a2l_data:
            return None
        if self.a2l_tags_filter_field not in ("name", "all"):
            return None
        names = parse_parameter_list(self.a2l_tags_filter_text)
        if len(names) < 2:
            return None
        return names

    def _a2l_mode_keeps(self, tag: dict, mode: str) -> bool:
        """Return True when ``mode`` keeps ``tag`` with no filter text.

        Summary:
            The shipped mode test, factored so the list-mode hidden predicate
            and the mode line's ``<h>`` count read one definition
            (R-A2L-LIST.005, .021). ``all`` keeps every tag; ``invalid`` keeps
            a schema-invalid or checked-not-in-image tag; ``inmem`` keeps an
            in-image tag.

        Args:
            tag (dict): Enriched A2L tag.
            mode (str): The filter mode (``all`` / ``invalid`` / ``inmem``).

        Returns:
            bool: True when the tag would stay in the text-mode table under
                ``mode`` with an empty filter text.
        """
        if mode == "invalid":
            return (not tag.get("schema_ok", True)) or (
                tag.get("memory_checked") and tag.get("in_memory") is False
            )
        if mode == "inmem":
            return tag.get("in_memory") is True
        return True

    def _a2l_mode_line(self) -> Text:
        """Build the mode line (R-A2L-LIST.020, .021)."""
        mode = self.a2l_tags_filter_mode
        total = len(self._a2l_enriched_tags)
        label = label_list.MODE_LABEL.get(mode, mode)
        if mode == "all":
            return Text(f"mode {label} · no tag hidden by mode ({total} tags)")
        kept = sum(
            1 for tag in self._a2l_enriched_tags if self._a2l_mode_keeps(tag, mode)
        )
        return Text(f"mode {label} · hides {total - kept} of {total} tags  alt+a All")

    def _a2l_text_chips(self) -> Text:
        """Build the text-mode chips line (R-A2L-LIST.019)."""
        text = self.a2l_tags_filter_text
        if text:
            part = (
                f"'{label_list.display_text(text, 64)}' in {self.a2l_tags_filter_field}"
            )
        else:
            part = "no text filter"
        line = Text()
        line.append(" TEXT ")
        line.append("  ")
        line.append(part)
        line.append(
            f"  ·  showing {len(self._a2l_filtered_tags)} of {len(self._a2l_enriched_tags)}"
        )
        line.append("   paste several names, or alt+p, to filter by a LIST")
        line.append("\n")
        line.append(self._a2l_mode_line())
        return line

    def _a2l_list_chips(self) -> tuple[Text, Text]:
        """Build the list-mode chips and missing line (R-A2L-LIST.017-.018, .022)."""
        resolution = getattr(self, "_a2l_list_resolution", None)
        if resolution is None:
            return Text(), Text()
        counts, ribbon, missing = label_list.list_summary_texts(
            resolution, label_list.VIEWER_RIBBON
        )
        chips = Text()
        chips.append(" LIST ")
        chips.append("  ")
        chips.append(counts)
        chips.append("\n")
        chips.append("order ")
        chips.append(ribbon)
        chips.append(
            "   field ignored in LIST mode · esc back to text filter · alt+p edit the list"
        )
        chips.append("\n")
        chips.append(self._a2l_mode_line())
        return chips, missing

    def _refresh_a2l_dependent_views(self) -> None:
        """
        Summary:
            Publish one coherent A2L transition to every live dependent view
            while preserving unrelated operator and historical state.

        Args:
            None

        Returns:
            None

        Data Flow:
            - Reset only the filter mode, then render fresh A2L/MAC/Issues data.
            - Invalidate the old hex span, description and detail selection;
              register the final detail clear behind queued row highlights.
            - Refresh both pickers, Memory Map, Split / Join and Loaded through
              their existing UI-thread seams.

        Dependencies:
            Uses:
                - ``update_a2l_view`` / ``_prefill_check_editor`` /
                  ``_prefill_patch_editor`` / ``update_memory_map``
                - ``SplitJoinWindow.invalidate_a2l_selection`` /
                  ``watch_current_file`` / ``_refresh_loaded_panel``
            Used by:
                - A2L attach, prepared file/project install and unload routes
        """
        self.a2l_tags_filter_mode = "all"
        for button_id, variant in (
            ("a2l_filter_all", "primary"),
            ("a2l_filter_invalid", "default"),
            ("a2l_filter_inmem", "default"),
        ):
            try:
                button = self.query_one(f"#{button_id}", Button)
            except Exception:
                continue
            button.variant = variant
        self.update_a2l_view()
        self._a2l_tag_hex_highlight = None
        self.update_alt_hex_view()
        try:
            screen = self.screen
        except Exception:
            screen = None
        if isinstance(screen, CurveDescriptionScreen):
            screen.dismiss(None)
        try:
            card = self.query_one("#a2l_detail_card", A2LDetailCard)
        except Exception:
            card = None
        if card is not None:
            card.show_tag(None)
            self.call_after_refresh(card.show_tag, None)
        self._prefill_check_editor()
        self._prefill_patch_editor()
        self.update_memory_map()
        try:
            window = self.query_one("#screen_split_join", SplitJoinWindow)
        except Exception:
            window = None
        if window is not None:
            window.invalidate_a2l_selection()
        self.watch_current_file()
        self._refresh_loaded_panel()

    def update_a2l_view(self) -> None:
        """
        Summary:
            Render buffered A2L summary and tag views, refreshing MAC/validation
            state BEFORE the tag rows render so their severity map is fresh.

        Args:
            None

        Returns:
            None

        Raises:
            None

        Data Flow:
            - A2L absent: clear enrichment/filter/find state, render empty views,
              refresh the MAC view, and (with no primary file) clear the
              validation members.
            - A2L present: enrich tags first, then call ``update_mac_view()`` —
              AFTER enrichment because ``_build_mac_view_cache`` consumes
              ``self._a2l_enriched_tags``, and BEFORE ``_refresh_a2l_filtered_tags``
              so the issue list read by the row-severity map reflects the current
              file pair on the sync-fallback load path (LLR-037.3; the call is
              idempotent over ``_mac_view_cache_key``, so the reorder adds no
              recomputation).

        Dependencies:
            Uses:
                - ``_compute_a2l_enriched_tags`` / ``update_mac_view``
                - ``_refresh_a2l_filtered_tags`` / ``_update_a2l_summary_buffer``
                - ``update_a2l_tags_view`` / ``update_validation_issues_view``
            Used by:
                - ``_refresh_a2l_dependent_views``
                - A2L filter handlers
        """
        ranker = getattr(self, "_a2l_label_ranker", None)
        if ranker is None:
            ranker = label_list.LabelRanker(self)
            self._a2l_label_ranker = ranker
        if not self.current_a2l_data:
            self._a2l_enriched_tags = []
            self._a2l_filtered_tags = []
            self._a2l_summary_lines = []
            self._a2l_window_start = 0
            self._a2l_tag_hex_highlight = None
            self._a2l_tag_find_query = ""
            self._a2l_tag_find_last_index = -1
            ranker.prepare([], self._a2l_view_generation)
            self._a2l_list_resolution = None
            self._update_a2l_summary_buffer()
            self.update_a2l_tags_view([])
            self.update_mac_view()
            if not self.current_file:
                self._validation_report = None
                self._validation_issues = []
                self.update_validation_issues_view()
            return
        self._compute_a2l_enriched_tags()
        ranker.prepare(self._a2l_distinct_tag_names(), self._a2l_view_generation)
        # LLR-037.3: install the validation issue list after enrichment (the
        # MAC-view cache consumes _a2l_enriched_tags) and before the tag rows
        # render, so the first frame reads a fresh issue-severity map.
        self.update_mac_view()
        filter_input = self.query_one("#a2l_tags_filter_input", Input)
        self.a2l_tags_filter_text = filter_input.value.strip()
        self._refresh_a2l_filtered_tags(preserve_anchor=False)
        self._update_a2l_summary_buffer()

    def update_a2l_tags_view(
        self, tags: list[dict], empty_message: Optional[str] = None
    ) -> None:
        """
        Summary:
            Render one page of A2L tag rows into the A2L DataTable with row_keys
            that map back to the enriched tag dicts for jump handling.

        Args:
            tags (list[dict]): Filtered enriched tags to display (may be empty).
            empty_message (Optional[str]): Summary text painted when ``tags`` is
                empty, replacing the generic ``No A2L tags.`` — the
                filter-specific ``No A2L tags match '<filter>'.`` is the one
                current caller (batch-102 Inc 2, R-B102-A2L-003). Wrapped in
                ``safe_text`` here so hostile filter text (``[red]``, escapes)
                renders literally, never as markup.

        Returns:
            None

        Data Flow:
            - Clear the DataTable (keep columns) and reset the row_key -> tag map.
            - Short-circuit when ``tags`` is empty (update summary text only).
            - Slice one page using ``_a2l_clamp_page_start`` and window bounds.
            - Build the issue-severity map from ``self._validation_issues`` once
              per render (LLR-037.2 map-build ownership) and pass it to
              ``_a2l_tag_row_severity`` so ERROR-issue symbols red their rows.
            - Build 16-cell tuples with the same fields the prior renderer produced,
              wrap each cell in a severity-styled ``rich.text.Text``, and insert
              via per-row ``add_row`` with ``a2l:<absolute_index>`` keys.
            - Measure the name width once per page (``_a2l_tag_name_width``) and
              hand it to every row's build; after the summary, schedule
              ``_fit_a2l_tag_cells`` for the next refresh so a page whose
              Address/Length widths or vertical scrollbar differ from the
              previous page's is re-fitted on its own layout (R-TUI-042a.5).

        Dependencies:
            Uses:
                - ``_a2l_clamp_page_start`` / ``_get_window_bounds``
                - ``_a2l_issue_severity_map``
                - ``_a2l_tag_row_severity`` / ``_severity_style``
                - ``_a2l_tag_in_memory_display`` / ``_a2l_tag_unit_display``
                - ``_a2l_tag_name_width`` / ``_fit_a2l_tag_cells``
                - ``safe_text``
            Used by:
                - ``_refresh_a2l_filtered_tags``
                - ``update_a2l_view``
                - A2L tag paging and find actions
        """
        populate_started = time.perf_counter()
        a2l_table = self.query_one("#a2l_tags_list", DataTable)
        summary_label = self.query_one("#a2l_tags_summary", deps.Label)
        self._a2l_row_key_to_tag = {}
        a2l_table.suppress_row_highlight = True
        try:
            resolution = getattr(self, "_a2l_list_resolution", None)
            if resolution is not None:
                self._update_a2l_list_page(a2l_table, summary_label, resolution)
                return
            self._set_a2l_table_columns(a2l_table, _A2L_TEXT_COLUMNS)
            a2l_table.clear(columns=False)
            if not tags:
                self._a2l_window_start = 0
                if empty_message is not None:
                    summary_label.update(safe_text(empty_message))
                else:
                    summary_label.update("No A2L tags.")
                self.logger.info(
                    "Load phase boundary: populate_a2l_table_done rows=0 elapsed=%.3f",
                    time.perf_counter() - populate_started,
                )
                self._flush_logger()
                return
            total_tags = len(tags)
            self._a2l_window_start = self._a2l_clamp_page_start(total_tags)
            page_size = self._clamp_viewer_page_size(self.a2l_tags_page_size)
            start, end = self._get_window_bounds(total_tags, self._a2l_window_start, page_size)
            self._a2l_window_start = start
            visible_tags = tags[start:end]
            name_width = self._a2l_tag_name_width(a2l_table)
            issue_severity_map = _a2l_issue_severity_map(self._validation_issues)
            for i, tag in enumerate(visible_tags):
                absolute_index = start + i
                row_key = f"a2l:{absolute_index}"
                self._a2l_row_key_to_tag[row_key] = tag
                cells = self._build_a2l_table_cells(tag, name_width)
                severity = _a2l_tag_row_severity(tag, issue_severity_map)
                style = _severity_style(severity)
                # LLR-068.1: the builder returns markup-safe Rich ``Text`` cells with
                # per-cell accents (name/address/source). Row-level severity (US-033,
                # the A2L Red/Green/White/Grey contract) overrides those accents when
                # present, preserving the pre-batch uniform per-row colouring.
                if style:
                    for cell in cells:
                        cell.style = style
                try:
                    a2l_table.add_row(*cells, key=row_key)
                except Exception:
                    a2l_table.add_row(*cells)
            page_num = start // page_size + 1
            total_pages = max(1, (total_tags + page_size - 1) // page_size)
            in_image = sum(1 for tag in tags if tag.get("in_memory"))
            summary_text = Text(
                f"Page {page_num}/{total_pages} | tags {start + 1}-{end} / {total_tags} "
                f"(page size {page_size}; +/- to change page)"
            )
            summary_text.append("  ·  ")
            summary_text.append(f"{in_image} in image", style=GREEN)
            summary_label.update(summary_text)
            self.call_after_refresh(self._fit_a2l_tag_cells)
            self.logger.info(
                "Load phase boundary: populate_a2l_table_done rows=%d total=%d elapsed=%.3f",
                len(visible_tags),
                total_tags,
                time.perf_counter() - populate_started,
            )
            self._flush_logger()
        finally:
            a2l_table.suppress_row_highlight = False

    def _a2l_tag_name_width(self, a2l_table: DataTable) -> Optional[int]:
        """
        Summary:
            Compute the name width *w* of the A2L tag table: the visible width
            minus the Address and Length column widths minus the Tag column's
            padding, glyph and trailing blank (R-TUI-042a.5).

        Args:
            a2l_table (DataTable): The ``#a2l_tags_list`` table, laid out.

        Returns:
            Optional[int]: The name width in cells, or ``None`` when the table
            has no visible width (a hidden table has a null region) or fewer
            than two columns.

        Data Flow:
            - Read the visible width from ``scrollable_content_region.width``
              (the content region minus a shown scrollbar).
            - Subtract ``Column.get_render_width`` of the Address and Length
              columns (each already includes its two padding cells).
            - Subtract ``2 * cell_padding + 2``: the Tag column's padding, the
              in-image glyph and the blank after it.

        Dependencies:
            Uses:
                - ``DataTable.scrollable_content_region`` / ``ordered_columns``
                - ``Column.get_render_width``
            Used by:
                - ``update_a2l_tags_view``
                - ``_repaint_a2l_tag_cells``
                - ``_fit_a2l_tag_cells``
        """
        visible = a2l_table.scrollable_content_region.width
        if visible == 0:
            return None
        ordered = a2l_table.ordered_columns
        if len(ordered) < 2:
            return None
        address_width = ordered[0].get_render_width(a2l_table)
        length_width = ordered[1].get_render_width(a2l_table)
        return (
            visible
            - address_width
            - length_width
            - 2 * a2l_table.cell_padding
            - 2
        )

    def _fit_a2l_tag_cells(self) -> None:
        """
        Summary:
            Rebuild the shown A2L tag-table page when the measured name width
            *w* no longer matches what is painted, restoring the cursor, scroll
            and detail card (R-TUI-042a.3, .5).

        Args:
            None

        Returns:
            None

        Data Flow:
            - Measure *w* via ``_a2l_tag_name_width``; return when it is
              ``None``, the page has no rows, or the row count differs from
              ``_a2l_row_key_to_tag``.
            - Compare each painted Tag cell (``get_row_at(i)[2].plain``)
              against ``_build_a2l_table_cells(tag, w)[2].plain`` for the
              row's tag.
            - Only when one differs, rebuild through ``update_a2l_tags_view``
              and restore the cursor and scroll. DataTable's cached composed
              line otherwise intermittently keeps the old narrow render.

        Dependencies:
            Uses:
                - ``_a2l_tag_name_width`` / ``_build_a2l_table_cells``
                - ``update_a2l_tags_view``
            Used by:
                - ``update_a2l_tags_view`` (after each non-empty page build)
                - ``on_a2l_tag_table_measured``
        """
        if getattr(self, "_a2l_list_resolution", None) is not None:
            return
        a2l_table = self.query_one("#a2l_tags_list", DataTable)
        name_width = self._a2l_tag_name_width(a2l_table)
        if name_width is None:
            return
        if not self._a2l_row_key_to_tag:
            return
        if a2l_table.row_count != len(self._a2l_row_key_to_tag):
            return
        for i, tag in enumerate(self._a2l_row_key_to_tag.values()):
            painted = a2l_table.get_row_at(i)[2].plain
            wanted = self._build_a2l_table_cells(tag, name_width)[2].plain
            if painted != wanted:
                cursor_row = a2l_table.cursor_row
                scroll_x, scroll_y = a2l_table.scroll_x, a2l_table.scroll_y
                self.update_a2l_tags_view(self._a2l_filtered_tags)
                if a2l_table.row_count:
                    a2l_table.move_cursor(
                        row=min(cursor_row, a2l_table.row_count - 1), scroll=False
                    )
                a2l_table.call_after_refresh(
                    a2l_table.scroll_to, x=scroll_x, y=scroll_y, animate=False
                )
                return

    def on_a2l_tag_table_measured(self, event: A2LTagTable.Measured) -> None:
        """
        Summary:
            Re-fit the A2L tag table's Tag cells when the table reports its own
            resize, at which point the screen is laid out and the region the fit
            reads is current (R-TUI-042a.5).

        Args:
            event (A2LTagTable.Measured): The table's re-emitted resize message.

        Returns:
            None

        Data Flow:
            - Stop the bubbling message so no other handler re-runs the fit.
            - Run ``_fit_a2l_tag_cells`` directly (no ``call_after_refresh``:
              the table's resize already follows layout).

        Dependencies:
            Uses:
                - ``_fit_a2l_tag_cells``
            Used by:
                - Textual dispatch of ``A2LTagTable.Measured``
        """
        event.stop()
        self._fit_a2l_tag_cells()

    def _repaint_a2l_tag_cells(self) -> None:
        """
        Summary:
            Write the shown A2L tag-table page's cells in place after a value
            recompute, so the Raw/Physical cells read the written bytes while
            the first shown row, the cursor, the scroll and the detail card
            stay (R-A2L-048, -049, -105, R2-7).

        Args:
            None

        Returns:
            None

        Data Flow:
            - Read ``_a2l_filtered_tags`` and ``_a2l_window_start``; compute
              the page bounds ``update_a2l_tags_view`` uses.
            - For each shown row, rebuild its 16 cells with the row's
              severity style — the Tag cell sized by the current name width
              (``_a2l_tag_name_width``) — and write only the cells whose
              plain text or style differs (``update_cell_at`` with
              ``update_width=True`` so values use their current render width).
            - Invalidate the table's cell and line caches with
              ``notify_style_update`` so the next paint uses the new text and
              width instead of a stale narrow render.
            - Re-point ``_a2l_row_key_to_tag`` for each shown row and
              recompute the summary label with ``update_a2l_tags_view``'s
              text. No ``clear()``, no ``move_cursor``, no ``scroll_to`` and
              no ``RowHighlighted`` is posted, so the detail card keeps its
              tag.

        Dependencies:
            Uses:
                - ``_build_a2l_table_cells``
                - ``_a2l_tag_row_severity`` / ``_severity_style``
                - ``_a2l_issue_severity_map``
                - ``_get_window_bounds`` / ``_clamp_viewer_page_size``
            Used by:
                - ``_refresh_a2l_values_after_write``
        """
        table = self.query_one("#a2l_tags_list", DataTable)
        summary_label = self.query_one("#a2l_tags_summary", deps.Label)
        names = self._a2l_list_names()
        if names is not None:
            self._repaint_a2l_list_cells(table, summary_label, names)
            return
        tags = self._a2l_filtered_tags
        total_tags = len(tags)
        if not total_tags:
            return
        page_size = self._clamp_viewer_page_size(self.a2l_tags_page_size)
        start, end = self._get_window_bounds(
            total_tags, self._a2l_window_start, page_size
        )
        from textual.coordinate import Coordinate

        issue_severity_map = _a2l_issue_severity_map(self._validation_issues)
        for i in range(end - start):
            absolute_index = start + i
            tag = tags[absolute_index]
            cells = self._build_a2l_table_cells(
                tag, self._a2l_tag_name_width(table)
            )
            severity = _a2l_tag_row_severity(tag, issue_severity_map)
            style = _severity_style(severity)
            if style:
                for cell in cells:
                    cell.style = style
            for column, cell in enumerate(cells):
                existing = table.get_cell_at(Coordinate(i, column))
                if isinstance(existing, Text):
                    text_changed = existing.plain != cell.plain
                    style_changed = existing.style != cell.style
                else:
                    text_changed = str(existing) != cell.plain
                    style_changed = True
                if text_changed or style_changed:
                    table.update_cell_at(
                        Coordinate(i, column), cell, update_width=True
                    )
            self._a2l_row_key_to_tag[f"a2l:{absolute_index}"] = tag
        page_num = start // page_size + 1
        total_pages = max(1, (total_tags + page_size - 1) // page_size)
        in_image = sum(1 for tag in tags if tag.get("in_memory"))
        summary_text = Text(
            f"Page {page_num}/{total_pages} | tags {start + 1}-{end} / {total_tags} "
            f"(page size {page_size}; +/- to change page)"
        )
        summary_text.append("  ·  ")
        summary_text.append(f"{in_image} in image", style=GREEN)
        summary_label.update(summary_text)
        table.notify_style_update()

    def _a2l_table_column_labels(self, a2l_table: DataTable) -> tuple[str, ...]:
        """Return ``a2l_table``'s current column labels in order."""
        return tuple(column.label.plain for column in a2l_table.columns)

    def _set_a2l_table_columns(
        self, a2l_table: DataTable, labels: tuple[str, ...]
    ) -> None:
        """Set ``a2l_table``'s columns to ``labels`` only when they differ."""
        if self._a2l_table_column_labels(a2l_table) == labels:
            return
        a2l_table.clear(columns=True)
        a2l_table.add_columns(*labels)

    def _a2l_list_text_cells(self, tag: dict) -> Mapping[str, Text]:
        """Map the shipped text-mode labels to ``tag``'s 16 built cells."""
        cells = self._build_a2l_table_cells(tag)
        return dict(zip(_A2L_TEXT_COLUMNS, cells))

    def _update_a2l_list_page(
        self,
        a2l_table: DataTable,
        summary_label: deps.Label,
        resolution: label_list.LabelListResolution,
    ) -> None:
        """Render one list-mode page of ``resolution`` into ``a2l_table``."""
        self._set_a2l_table_columns(a2l_table, label_list.LIST_COLUMNS)
        a2l_table.clear(columns=False)
        total = len(resolution.entries)
        self._a2l_window_start = self._a2l_clamp_page_start(total)
        page_size = self._clamp_viewer_page_size(self.a2l_tags_page_size)
        start, end = self._get_window_bounds(total, self._a2l_window_start, page_size)
        self._a2l_window_start = start
        mode = self.a2l_tags_filter_mode
        for index in range(start, end):
            entry = resolution.entries[index]
            text_cells = (
                self._a2l_list_text_cells(entry.tag)
                if entry.tag is not None
                else None
            )
            cells = label_list.list_row_cells(entry, text_cells, mode)
            row_key = f"a2l:{index}"
            self._a2l_row_key_to_tag[row_key] = resolution.rows[index]
            a2l_table.add_row(*cells, key=row_key)
        summary_label.update(Text(f"LIST  rows {start + 1}-{end} / {total} in pasted order"))

    def _repaint_a2l_list_cells(
        self,
        table: DataTable,
        summary_label: deps.Label,
        names: list[str],
    ) -> None:
        """Re-resolve and write the shown list-mode page in place (R-A2L-LIST.036)."""
        mode = self.a2l_tags_filter_mode
        resolution = label_list.resolve_label_list(
            names,
            self._a2l_enriched_tags,
            hidden=lambda tag: not self._a2l_mode_keeps(tag, mode),
        )
        self._a2l_list_resolution = resolution
        self._a2l_filtered_tags = list(resolution.rows)
        total = len(resolution.entries)
        if not total:
            return
        page_size = self._clamp_viewer_page_size(self.a2l_tags_page_size)
        start, end = self._get_window_bounds(total, self._a2l_window_start, page_size)
        from textual.coordinate import Coordinate

        for i in range(end - start):
            index = start + i
            entry = resolution.entries[index]
            text_cells = (
                self._a2l_list_text_cells(entry.tag)
                if entry.tag is not None
                else None
            )
            cells = label_list.list_row_cells(entry, text_cells, mode)
            for column, cell in enumerate(cells):
                existing = table.get_cell_at(Coordinate(i, column))
                if isinstance(existing, Text):
                    text_changed = existing.plain != cell.plain
                    style_changed = existing.style != cell.style
                else:
                    text_changed = str(existing) != cell.plain
                    style_changed = True
                if text_changed or style_changed:
                    table.update_cell_at(Coordinate(i, column), cell, update_width=True)
            self._a2l_row_key_to_tag[f"a2l:{index}"] = resolution.rows[index]
        summary_label.update(Text(f"LIST  rows {start + 1}-{end} / {total} in pasted order"))
        table.notify_style_update()

    def _a2l_distinct_tag_names(self) -> list[str]:
        """Return the distinct non-empty tag names of the current A2L in order."""
        seen: set[str] = set()
        names: list[str] = []
        for tag in self._a2l_enriched_tags:
            name = str(tag.get("name") or "")
            if not name or name in seen:
                continue
            seen.add(name)
            names.append(name)
        return names

    def _build_a2l_table_cells(
        self, tag: dict, name_width: Optional[int] = None
    ) -> tuple[Text, ...]:
        """
        Summary:
            Project one enriched A2L tag into the 16-cell tuple the DataTable
            row expects, in CTX-A2L-SCREEN order — Address, Length, Tag, then
            Source … Dtype unchanged (batch-47, LLR-068.1/068.3;
            R-TUI-042a.4). Every cell is a markup-safe Rich ``Text`` (built via
            ``safe_text``), so every file-derived value — name, source, unit,
            function group, memory region, raw/physical value — renders
            literally and can never be interpreted as Rich markup (C-17). The
            Tag cell carries a leading in-image glyph (``✓`` when
            ``tag["in_memory"]`` is truthy, else ``·``) and the name as its
            *painted tag name*, shortened in the middle by
            :func:`_shorten_tag_name` to at most ``min(34, name_width)`` cells
            (R-TUI-042a.3, .5, .6); the name is bright, the address cyan, the
            source muted. Row-level severity colouring is layered on top by
            ``update_a2l_tags_view`` (it overrides these accent styles when a
            severity applies), preserving the A2L Red/Green/White/Grey
            row-colour contract. The detail card keeps the full name.

        Args:
            tag (dict): Enriched A2L tag with value, memory, and schema fields.
            name_width (Optional[int]): The measured name width *w* in cells;
                ``None`` gives the 34-cell form (R-TUI-042a.3).

        Returns:
            tuple[Text, ...]: 16-cell tuple of Rich ``Text`` aligned with the
            DataTable columns — index 0 Address, 1 Length, 2 Tag, 3 Source …
            15 Dtype. The Tag cell (index 2) carries the leading in-image
            glyph.

        Data Flow:
            - Format address/length/limits defensively so missing fields stay blank.
            - Compute the Tag cell's cap as ``34 if name_width is None else
              min(34, name_width)`` and paint the glyph plus the shortened name.
            - Reuse ``_a2l_tag_in_memory_display`` / ``_a2l_tag_unit_display`` helpers
              so display conventions remain centralized.
            - Wrap each cell via ``safe_text`` (``Text`` constructor, never
              ``Text.from_markup``) so the tuple is markup-safe by construction.

        Dependencies:
            Uses:
                - ``_a2l_tag_in_memory_display``
                - ``_a2l_tag_unit_display``
                - ``_shorten_tag_name``
                - ``safe_text`` ; ``VALUE`` / ``CYAN`` / ``DGRAY``
            Used by:
                - ``update_a2l_tags_view``
                - ``_repaint_a2l_tag_cells``
                - ``_fit_a2l_tag_cells``
        """
        addr = tag.get("address")
        length = tag.get("length")
        addr_text = f"0x{addr:08X}" if isinstance(addr, int) else "n/a"
        len_text = str(length) if isinstance(length, int) else "n/a"
        name_text = str(tag.get("name") or "UNKNOWN")
        glyph = "✓" if tag.get("in_memory") else "·"
        cap = 34 if name_width is None else min(34, name_width)
        tag_text = f"{glyph} {_shorten_tag_name(name_text, cap)}"
        source_text = str(tag.get("source") or "assigned")
        raw_value_text = str(tag.get("raw_value") if tag.get("raw_value") is not None else "")
        if tag.get("physical_value") is not None:
            physical_value_text = str(tag.get("physical_value"))
        elif tag.get("raw_value") is not None:
            # the bytes are present but the COMPU_METHOD refused them (UX-C8):
            # "n/a", kept distinct from the blank cell of a tag with no bytes
            physical_value_text = "n/a"
        else:
            physical_value_text = ""
        in_mem_text = _a2l_tag_in_memory_display(tag)
        region_text = str(tag.get("memory_region") or "unknown")
        limits_text = ""
        if tag.get("lower_limit") is not None or tag.get("upper_limit") is not None:
            limits_text = f"{tag.get('lower_limit','')}..{tag.get('upper_limit','')}"
        unit_text = _a2l_tag_unit_display(tag)
        bit_text = str(tag.get("bit_org") or "")
        endian_text = str(tag.get("endian") or "")
        virt_text = "yes" if tag.get("virtual") else "no"
        func_text = str(tag.get("function_group") or "")
        access_text = str(tag.get("access") or "")
        dtype_text = str(tag.get("datatype") or "")
        return (
            safe_text(addr_text, style=CYAN),
            safe_text(len_text),
            safe_text(tag_text, style=VALUE),
            safe_text(source_text, style=DGRAY),
            safe_text(raw_value_text),
            safe_text(physical_value_text),
            safe_text(in_mem_text),
            safe_text(region_text),
            safe_text(limits_text),
            safe_text(unit_text),
            safe_text(bit_text),
            safe_text(endian_text),
            safe_text(virt_text),
            safe_text(func_text),
            safe_text(access_text),
            safe_text(dtype_text),
        )

    def _filter_a2l_tags(self, tags: list[dict]) -> list[dict]:
        """
        Summary:
            Resolve list mode into one row per pasted name, else run the
            shipped mode-then-substring text filter.

        Args:
            tags (list[dict]): Enriched A2L tags.

        Returns:
            list[dict]: In list mode, the resolution rows in pasted order
                (each row is the tag object itself for a found / duplicate /
                hidden name, or ``{"name": ..., "_list_pos": ...}`` for a
                missing name); in text mode, the tags the active mode and the
                filter text keep.

        Data Flow:
            - List mode: resolve the pasted names over ``tags`` with the
              active mode's hidden test, keep the resolution in
              ``_a2l_list_resolution`` and return its rows (R-A2L-LIST.006).
            - Text mode: clear the resolution and run the unchanged shipped
              mode-then-substring filter.

        Dependencies:
            Uses:
                - ``_a2l_list_names`` / ``_a2l_mode_keeps``
                - ``resolve_label_list`` (a2l_label_list)
                - ``_tag_matches_filter``
            Used by:
                - ``_refresh_a2l_filtered_tags``
        """
        names = self._a2l_list_names()
        if names is not None:
            mode = self.a2l_tags_filter_mode
            resolution = label_list.resolve_label_list(
                names,
                tags,
                hidden=lambda tag: not self._a2l_mode_keeps(tag, mode),
            )
            self._a2l_list_resolution = resolution
            return list(resolution.rows)
        self._a2l_list_resolution = None
        mode = self.a2l_tags_filter_mode
        text = (self.a2l_tags_filter_text or "").lower()
        filtered = []
        for tag in tags:
            if mode == "invalid":
                show = (not tag.get("schema_ok", True)) or (
                    tag.get("memory_checked") and tag.get("in_memory") is False
                )
                if not show:
                    continue
            if mode == "inmem" and tag.get("in_memory") is not True:
                continue
            if text:
                if not self._tag_matches_filter(tag, text):
                    continue
            filtered.append(tag)
        return filtered

    def _tag_matches_filter(self, tag: dict, text: str) -> bool:
        field = self.a2l_tags_filter_field
        if field == "all":
            haystack = " ".join(
                [
                    str(tag.get("name") or ""),
                    str(tag.get("address") or ""),
                    str(tag.get("length") or ""),
                    str(tag.get("source") or ""),
                    str(tag.get("raw_value") or ""),
                    str(tag.get("physical_value") or ""),
                    _a2l_tag_in_memory_display(tag),
                    str(tag.get("lower_limit") or ""),
                    str(tag.get("upper_limit") or ""),
                    _a2l_tag_unit_display(tag),
                    str(tag.get("bit_org") or ""),
                    str(tag.get("endian") or ""),
                    str(tag.get("virtual") or ""),
                    str(tag.get("function_group") or ""),
                    str(tag.get("access") or ""),
                    str(tag.get("datatype") or ""),
                    str(tag.get("description") or ""),
                    str(tag.get("memory_region") or ""),
                ]
            ).lower()
            return text in haystack

        value = ""
        if field == "name":
            value = str(tag.get("name") or "")
        elif field == "address":
            value = str(tag.get("address") or "")
        elif field == "length":
            value = str(tag.get("length") or "")
        elif field == "source":
            value = str(tag.get("source") or "")
        elif field == "raw_value":
            value = str(tag.get("raw_value") or "")
        elif field == "physical_value":
            value = str(tag.get("physical_value") or "")
        elif field == "in_memory":
            value = _a2l_tag_in_memory_display(tag)
        elif field == "limits":
            value = f"{tag.get('lower_limit','')}..{tag.get('upper_limit','')}"
        elif field == "unit":
            value = _a2l_tag_unit_display(tag)
        elif field == "bits":
            value = str(tag.get("bit_org") or "")
        elif field == "endian":
            value = str(tag.get("endian") or "")
        elif field == "virtual":
            value = "yes" if tag.get("virtual") else "no"
        elif field == "function_group":
            value = str(tag.get("function_group") or "")
        elif field == "access":
            value = str(tag.get("access") or "")
        elif field == "datatype":
            value = str(tag.get("datatype") or "")
        elif field == "description":
            value = str(tag.get("description") or "")
        elif field == "memory_region":
            value = str(tag.get("memory_region") or "")
        return text in value.lower()

    def _toggle_a2l_filter_menu(self) -> None:
        menu = self.query_one("#a2l_filter_menu")
        if "hidden" in menu.classes:
            self._update_a2l_filter_menu()
            menu.remove_class("hidden")
        else:
            menu.add_class("hidden")

    def _update_a2l_filter_menu(self) -> None:
        menu_list = self.query_one("#a2l_filter_menu_list", ListView)
        menu_list.clear()
        for field_name in self.a2l_tags_filter_fields:
            label = f"(*) {field_name}" if field_name == self.a2l_tags_filter_field else f"( ) {field_name}"
            item = deps.ListItem(deps.Label(label))
            item.data = field_name
            menu_list.append(item)

    def _set_a2l_filter_field(self, field: str) -> None:
        if field not in self.a2l_tags_filter_fields:
            return
        self.a2l_tags_filter_field = field
        button = self.query_one("#a2l_filter_field", Button)
        button.label = f"Field: {field}"
        menu = self.query_one("#a2l_filter_menu")
        menu.add_class("hidden")
        self._update_a2l_filter_menu()
        self._refresh_a2l_filtered_tags(preserve_anchor=False)

    def _schedule_a2l_filter_refresh(self) -> None:
        """
        Summary:
            Debounce rapid filter-input events and refresh only buffered A2L tags window.

        Args:
            None

        Returns:
            None

        Data Flow:
            - Increment debounce token for each new keystroke.
            - Schedule short delayed callback.
            - Refresh filtered buffered rows only if token matches latest request.
            - Drop the refresh when it comes due after the app stopped
              running: shutdown has already removed the A2L tag table
              (Inc 1b E5, R-COPY.26).

        Dependencies:
            Uses:
                - ``set_timer``
                - ``_refresh_a2l_filtered_tags``
            Used by:
                - ``on_input_changed`` for A2L filter input
        """
        self._a2l_filter_debounce_token += 1
        expected_token = self._a2l_filter_debounce_token

        def _apply_filter() -> None:
            if expected_token != self._a2l_filter_debounce_token:
                return
            if not self.is_running:
                return
            self._refresh_a2l_filtered_tags(preserve_anchor=False)

        self.set_timer(0.15, _apply_filter)
