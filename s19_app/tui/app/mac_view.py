"""s19_app.tui.app.mac_view — S19TuiApp mixin: mac_view (moved verbatim from s19_app/tui/app.py at 4f721985)."""
from __future__ import annotations

import time
from typing import Any, Optional
from textual.widgets import DataTable, Input, ListItem, Static
from rich.text import Text
from ...core import S19File, load_notice_code
from ...range_index import address_in_sorted_ranges, build_sorted_range_index
from ..models import LoadedFile
from ..insight_style import CYAN
from ...validation import ValidationIssue, ValidationReport, ValidationSeverity
from ..services.validation_service import build_mac_coverage_strip, build_validation_report
from . import deps
from .shared import (
    _MAC_GLYPH_PARSE_ERROR,
    _MAC_GLYPH_OUT_OF_IMAGE,
    _MAC_GLYPH_IN_IMAGE,
    _MAC_GLYPH_UNCHECKED,
    _INTEGRITY_NOTICE_CODES,
    precompute_mac_datatable_payload,
)


def _build_a2l_name_index(a2l_data: Optional[dict]) -> dict[str, list[dict]]:
    index: dict[str, list[dict]] = {}
    if not a2l_data:
        return index
    for tag in a2l_data.get("tags", []):
        name = str(tag.get("name") or "").strip()
        if not name:
            continue
        key = name.lower()
        index.setdefault(key, []).append(tag)
    return index


def _mac_record_ui_state(
    record: dict[str, Any],
    a2l_name_index: dict[str, list[dict]],
    has_a2l: bool,
    memory_checked: bool,
    in_memory: Optional[bool],
) -> tuple[str, str]:
    """
    Summary:
        Derive MAC table status text and CSS class for one parsed ``.mac`` record.

    Args:
        record (dict[str, Any]): Parser record with ``parse_ok``, ``name``, ``address``, etc.
        a2l_name_index (dict[str, list[dict]]): Map of lowercased A2L tag name to tag dicts.
        has_a2l (bool): Whether an A2L dataset is loaded for cross-check.
        memory_checked (bool): True when an S19/HEX image is available for address membership.
        in_memory (Optional[bool]): Image membership when ``memory_checked`` is True.

    Returns:
        tuple[str, str]: ``(status, css_class)`` where ``css_class`` is ``invalid``, ``valid``,
        or ``neutral`` (default terminal color; no green/red).

    Data Flow:
        - Fail parse rows to invalid.
        - When A2L is absent or the tag name is missing, mark neutral.
        - Keep out-of-image rows as non-hard findings (info).
        - When the name is absent from A2L, mark warning.
        - When the name exists, require a matching ECU address on some A2L tag for ``valid``.

    Dependencies:
        Used by:
            - ``S19TuiApp.update_mac_view``
    """
    if not record.get("parse_ok"):
        return "ERR_PARSE", ValidationSeverity.ERROR.value
    name = str(record.get("name") or "").strip()
    address = record.get("address")
    if memory_checked and in_memory is False:
        return "OUT_OF_IMAGE", ValidationSeverity.INFO.value
    if not has_a2l or not name:
        return "NO_A2L", ValidationSeverity.NEUTRAL.value
    matches = a2l_name_index.get(name.lower(), [])
    if not matches:
        return "NOT_IN_A2L", ValidationSeverity.WARNING.value
    if not isinstance(address, int):
        return "NO_ADDR", ValidationSeverity.ERROR.value
    for tag in matches:
        tag_addr = tag.get("address")
        if isinstance(tag_addr, int) and tag_addr == address:
            return "OK", ValidationSeverity.OK.value
    return "A2L_ADDR_MISMATCH", ValidationSeverity.ERROR.value


def _mac_status_glyph(status: str, in_mem: str) -> tuple[str, str]:
    """
    Summary:
        Return the ``(glyph, style)`` for a MAC row from its precomputed
        ``Status`` string and ``InMem`` cell (``"yes"``/``"no"``/``"n/a"``),
        per LLR-070.1. ``✓`` green is reserved for a memory-checked + present
        record; an un-image-checked record (MAC-only load, no primary) renders
        the grey ``·`` "not yet checked" cue, never a false green.

    Args:
        status (str): The row's ``Status`` column value (``"ERR_PARSE"`` etc.).
        in_mem (str): The row's ``InMem`` column value — ``"yes"`` (in image),
            ``"no"`` (out of image), or ``"n/a"`` (not image-checked).

    Returns:
        tuple[str, str]: ``(glyph, rich_style)`` — one of the four
        ``_MAC_GLYPH_*`` constants.
    """
    if status == "ERR_PARSE":
        return _MAC_GLYPH_PARSE_ERROR
    if in_mem == "no":
        return _MAC_GLYPH_OUT_OF_IMAGE
    if in_mem == "yes":
        return _MAC_GLYPH_IN_IMAGE
    return _MAC_GLYPH_UNCHECKED


class MacViewMixin:

    def _mac_clamp_page_start(self, total_records: int) -> int:
        """
        Summary:
            Clamp ``_mac_window_start`` to a legal page start for MAC record paging.

        Args:
            total_records (int): Number of parsed MAC records.

        Returns:
            int: Page-aligned start index in ``[0, total_records)`` (or ``0`` when empty).

        Data Flow:
            - Align the current MAC window start to ``mac_records_page_size`` boundaries.
            - Clamp to the last legal page when the list shrinks.

        Dependencies:
            Used by:
                - ``update_mac_view``
                - MAC page navigation actions
        """
        ps = self._clamp_viewer_page_size(self.mac_records_page_size)
        if total_records <= 0 or ps <= 0:
            return 0
        aligned = (max(0, self._mac_window_start) // ps) * ps
        max_start = max(0, ((total_records - 1) // ps) * ps)
        return max(0, min(aligned, max_start))

    def action_mac_records_page_next(self) -> None:
        """
        Summary:
            Advance the MAC records table by one page of ``mac_records_page_size`` rows.

        Args:
            None

        Returns:
            None

        Data Flow:
            - Bump ``_mac_window_start`` by one page and clamp to the last legal page start.
            - Re-render the MAC list.

        Dependencies:
            Uses:
                - ``update_mac_view``
        """
        if not self.current_file:
            return
        records = self.current_file.mac_records or []
        total = len(records)
        if total <= 0:
            return
        page_size = self._clamp_viewer_page_size(self.mac_records_page_size)
        max_start = max(0, ((total - 1) // page_size) * page_size)
        self._mac_window_start = min(max_start, self._mac_window_start + page_size)
        self._mac_goto_focus_address = None
        self.update_mac_view()

    def action_mac_records_page_prev(self) -> None:
        """
        Summary:
            Move the MAC records table back by one page of ``mac_records_page_size`` rows.

        Args:
            None

        Returns:
            None

        Data Flow:
            - Decrement ``_mac_window_start`` by one page and clamp at zero.
            - Re-render the MAC list.

        Dependencies:
            Uses:
                - ``update_mac_view``
        """
        if not self.current_file:
            return
        records = self.current_file.mac_records or []
        if not records:
            return
        page_size = self._clamp_viewer_page_size(self.mac_records_page_size)
        self._mac_window_start = max(0, self._mac_window_start - page_size)
        self._mac_goto_focus_address = None
        self.update_mac_view()

    def _jump_to_mac_record(self, item: ListItem) -> None:
        """Legacy ListView adapter that forwards to ``_jump_to_mac_address``."""
        info = getattr(item, "data", None)
        if not info:
            return
        addr = info.get("address")
        if isinstance(addr, int):
            self._jump_to_mac_address(addr)

    def _jump_to_mac_address(self, address: int) -> None:
        """
        Summary:
            Focus the MAC hex panel on a MAC row's address and surface a status note.

        Args:
            address (int): Absolute memory address for the selected MAC record.

        Returns:
            None

        Dependencies:
            Uses:
                - ``update_mac_hex_view``
                - ``set_status``
            Used by:
                - ``on_data_table_row_selected`` for the MAC DataTable
                - ``_jump_to_mac_record`` (legacy ListView adapter)
        """
        self.last_search_address = None
        self._mac_goto_focus_address = None
        self.update_mac_hex_view(address, near_top=True, reset_scroll=True)
        self.set_status(f"MAC tag at 0x{address:08X}")

    def _get_range_index(self, loaded: Optional[LoadedFile]) -> tuple[list[int], list[int]]:
        """
        Summary:
            Return a cached sorted (starts, ends) index for a ``LoadedFile``'s ranges, building
            it lazily on first access so repeated address-in-ranges checks scale at O(log R).

        Args:
            loaded (Optional[LoadedFile]): Payload whose ranges should be indexed; ``None``
                yields an empty index.

        Returns:
            tuple[list[int], list[int]]: Parallel ``(starts, ends)`` lists suitable for
            ``address_in_sorted_ranges``.

        Data Flow:
            - Return empty index when ``loaded`` is missing or carries no ranges.
            - Reuse cached ``loaded.range_index`` when present.
            - Build and cache via ``build_sorted_range_index`` otherwise.

        Dependencies:
            Uses:
                - ``build_sorted_range_index``
            Used by:
                - ``_mac_address_in_ranges``
                - ``_collect_mac_out_of_range_addresses``
                - ``_build_mac_view_cache``
        """
        if loaded is None or not loaded.ranges:
            return ([], [])
        cached = getattr(loaded, "range_index", None)
        if cached is not None:
            return cached
        index = build_sorted_range_index(loaded.ranges)
        try:
            loaded.range_index = index
        except Exception:
            # If LoadedFile was constructed by test code without the new field, fall back
            # to returning the fresh index without mutating the payload.
            pass
        return index

    def _mac_address_in_ranges(self, address: int, ranges: list[tuple[int, int]]) -> bool:
        """
        Summary:
            Test an address against a list of ranges using binary search over a sorted index.

        Args:
            address (int): Address to check.
            ranges (list[tuple[int, int]]): Half-open ``(start, end)`` ranges; these are
                indexed once per call, which keeps the signature stable but is slower than
                passing a pre-built index via ``_get_range_index``.

        Returns:
            bool: True when ``address`` falls inside any of the provided ranges.

        Data Flow:
            - Build a sorted ``(starts, ends)`` index on the fly.
            - Delegate the actual check to ``address_in_sorted_ranges``.

        Dependencies:
            Uses:
                - ``build_sorted_range_index``
                - ``address_in_sorted_ranges``
        """
        if not ranges:
            return False
        return address_in_sorted_ranges(address, build_sorted_range_index(ranges))

    def _collect_mac_out_of_range_addresses(self, loaded: Optional[LoadedFile]) -> set[int]:
        """
        Summary:
            Collect MAC addresses that fall outside the current primary image's ranges.

        Args:
            loaded (Optional[LoadedFile]): Active payload; must be an S19/HEX primary for
                the check to apply.

        Returns:
            set[int]: Out-of-range MAC addresses.

        Data Flow:
            - Short-circuit when no primary image is attached.
            - Resolve the cached sorted range index once via ``_get_range_index``.
            - Iterate MAC records and test each parsed address against the index.

        Dependencies:
            Uses:
                - ``_get_range_index``
                - ``address_in_sorted_ranges``
            Used by:
                - ``update_sections``
        """
        if not loaded or loaded.file_type not in {"s19", "hex"}:
            return set()
        range_index = self._get_range_index(loaded)
        if not range_index[0]:
            return {
                int(record["address"])
                for record in (loaded.mac_records or [])
                if record.get("parse_ok") and isinstance(record.get("address"), int)
            }
        out_of_range: set[int] = set()
        for record in loaded.mac_records or []:
            address = record.get("address")
            if not (record.get("parse_ok") and isinstance(address, int)):
                continue
            if not address_in_sorted_ranges(address, range_index):
                out_of_range.add(address)
        return out_of_range

    def _collect_mac_highlight_addresses(self, loaded: Optional[LoadedFile]) -> set[int]:
        """Return parsed MAC addresses for optional orange hex overlays."""
        if not loaded:
            return set()
        addresses: set[int] = set()
        for record in loaded.mac_records or []:
            address = record.get("address")
            if record.get("parse_ok") and isinstance(address, int):
                addresses.add(address)
        return addresses

    def _invalidate_mac_view_cache(self) -> None:
        """
        Summary:
            Clear cached MAC table/validation material so next render recomputes from current state.

        Args:
            None

        Returns:
            None

        Data Flow:
            - Reset cache key and cached row/meta payload.
            - Reset cached summaries and coverage line.

        Dependencies:
            Used by:
                - ``load_selected_file`` after artifact changes
                - settings handlers that alter MAC row semantics
        """
        self._mac_view_cache_key = None
        self._mac_view_cache_rows = []
        self._mac_view_cache_meta = []
        self._mac_view_cache_summary = {}
        self._mac_view_cache_coverage_line = None
        self._mac_view_cache_widths = None
        self._mac_view_cache_cell_rows = []
        self._mac_view_cache_cell_styles = []

    def _mac_view_cache_key_for(
        self,
        records: list[dict],
        loaded: LoadedFile,
        a2l_data: Optional[dict],
    ) -> tuple:
        """
        Summary:
            Build the MAC-view cache key shared by the load worker
            (``_prepare_load_payload``) and ``update_mac_view`` so both sides agree
            on cache hits, including no-MAC sessions (LLR-037.4).

        Args:
            records (list[dict]): Normalized MAC record list (may be empty).
            loaded (LoadedFile): File the key describes (``current_file`` at render time).
            a2l_data (Optional[dict]): A2L payload identity component.

        Returns:
            tuple: ``(records_identity, len(records), id(a2l_data), file_type,
            ranges_tuple, mem_map_len)``.

        Raises:
            None

        Data Flow:
            - With records present, the identity component stays ``id(records)``
              (pre-LLR-037.4 behavior, unchanged).
            - With records EMPTY, ``mac_records or []`` builds a fresh list per call,
              so ``id(records)`` would churn and force a full payload recompute
              (including an S19 re-parse for the overlap set) on every render. The
              stable substitute chosen at Phase 3 is ``id(loaded)``: the ``LoadedFile``
              identity is shared by the worker (``loaded``) and the renderer
              (``self.current_file``), so worker-precomputed no-MAC reports register
              as cache HITS and repeat renders never recompute.

        Dependencies:
            Uses:
                - none
            Used by:
                - ``_prepare_load_payload``
                - ``update_mac_view``
                - ``_refresh_no_mac_validation``
        """
        records_identity = id(records) if records else id(loaded)
        return (
            records_identity,
            len(records),
            id(a2l_data),
            loaded.file_type,
            tuple(loaded.ranges),
            len(loaded.mem_map),
        )

    def _refresh_no_mac_validation(self) -> None:
        """
        Summary:
            Keep (or compute) the primary+A2L validation report when
            ``update_mac_view`` takes a no-MAC branch, instead of wiping
            ``_validation_report`` / ``_validation_issues`` (LLR-037.4, the B-1a
            fix). Sessions with NO primary file keep the historical clear.

        Args:
            None (reads ``current_file`` / ``current_a2l_data``; writes the four
            validation members on the clear path.)

        Returns:
            None

        Raises:
            None

        Data Flow:
            - No primary file: clear ``_validation_report`` / ``_validation_issues``
              and the issue cell caches (unchanged pre-fix behavior).
            - Primary present: build the empty-records cache key via
              ``_mac_view_cache_key_for`` (stable ``id(current_file)`` substitute) and,
              only on a key change, run ``_build_mac_view_cache`` — which routes
              through ``_compute_mac_view_payload`` / ``build_validation_report`` for
              the primary+A2L pair. On a key match (worker precompute or a repeat
              render) every validation member is retained untouched — never
              wipe-then-recompute.

        Dependencies:
            Uses:
                - ``_mac_view_cache_key_for``
                - ``_build_mac_view_cache``
            Used by:
                - ``update_mac_view`` (both no-MAC branches)
        """
        if not self.current_file:
            self._validation_report = None
            self._validation_issues = []
            return
        cache_key = self._mac_view_cache_key_for(
            [], self.current_file, self.current_a2l_data
        )
        if self._mac_view_cache_key != cache_key:
            self._mac_view_cache_key = cache_key
            self._build_mac_view_cache()

    def _compute_mac_view_payload(
        self,
        loaded: Optional[LoadedFile],
        a2l_data: Optional[dict],
        a2l_enriched_tags: Optional[list[dict[str, Any]]] = None,
    ) -> dict[str, Any]:
        """
        Summary:
            Pure (thread-safe) builder for the MAC table rows, summary counters, and the
            cross-artifact validation report that feeds the Issues panel.

        Args:
            loaded (Optional[LoadedFile]): Parsed payload to validate; may be ``None``.
            a2l_data (Optional[dict]): Parsed A2L payload used for name-index lookup.
            a2l_enriched_tags (Optional[list[dict]]): Pre-enriched A2L tag list; falls back
                to raw ``a2l_data["tags"]`` when missing so the function stays self-contained.

        Returns:
            dict[str, Any]: ``{"rows", "meta", "summary", "coverage_line", "report",
                "issues"}``. ``report`` and ``issues`` are ``None``/``[]`` when ``loaded``
                is not an S19/HEX primary.

        Data Flow:
            - Classify the payload as primary-backed or MAC-only.
            - Walk MAC records once to build row tuples, severity metadata, and counters,
              using the sorted range index for O(log R) membership checks.
            - On primary payloads, run ``validate_artifact_consistency`` plus the A2L
              internal-issue pass and dedupe the resulting issue list.

        Dependencies:
            Uses:
                - ``_build_a2l_name_index``
                - ``_mac_record_ui_state``
                - ``build_sorted_range_index`` / ``address_in_sorted_ranges``
                - ``validate_artifact_consistency`` / ``validate_a2l_internal_issues``
                - ``_deduplicate_issues``
            Used by:
                - ``_prepare_load_payload`` (worker thread)
                - ``_build_mac_view_cache`` (synchronous fallback)
        """
        records = loaded.mac_records if loaded else []
        has_a2l = bool(a2l_data)
        a2l_name_index = _build_a2l_name_index(a2l_data)
        primary_file = (
            loaded
            if loaded is not None and loaded.file_type in {"s19", "hex"}
            else None
        )
        if primary_file is not None:
            cached_index = getattr(primary_file, "range_index", None)
            if cached_index is not None:
                range_index = cached_index
            else:
                range_index = build_sorted_range_index(primary_file.ranges)
        else:
            range_index = ([], [])
        rows: list[tuple[str, str, str, str, str, str, str, str]] = []
        row_meta: list[dict[str, Any]] = []
        total_verified = 0
        total_invalid = 0
        total_neutral = 0
        total_in_a2l = 0
        total_out_of_mem = 0
        total_parse_errors = 0
        for record in records or []:
            line_no = int(record.get("line_number") or 0)
            name = str(record.get("name") or "").strip()
            address = record.get("address")
            parse_ok = bool(record.get("parse_ok"))
            parse_error = str(record.get("parse_error") or "")
            if not parse_ok:
                total_parse_errors += 1
            in_a2l = False
            a2l_match_text = ""
            if name:
                matches = a2l_name_index.get(name.lower(), [])
                if matches:
                    in_a2l = True
                    total_in_a2l += 1
                    best = matches[0]
                    a2l_match_text = f"{best.get('section', '?')}:{best.get('name', name)}"
            memory_checked = False
            in_memory = None
            if primary_file is not None and isinstance(address, int):
                memory_checked = True
                in_memory = address_in_sorted_ranges(address, range_index)
            in_mem_text = "n/a"
            if memory_checked:
                in_mem_text = "yes" if in_memory else "no"
                if not in_memory:
                    total_out_of_mem += 1
            status, severity_text = _mac_record_ui_state(record, a2l_name_index, has_a2l, memory_checked, in_memory)
            severity = ValidationSeverity(severity_text)
            if severity == ValidationSeverity.OK:
                total_verified += 1
            elif severity == ValidationSeverity.ERROR:
                total_invalid += 1
            else:
                total_neutral += 1
            addr_text = f"0x{address:08X}" if isinstance(address, int) else "n/a"
            rows.append(
                (
                    name or "(invalid)",
                    addr_text,
                    "yes" if in_a2l else "no",
                    in_mem_text,
                    status,
                    str(line_no),
                    parse_error,
                    a2l_match_text,
                )
            )
            row_meta.append({"severity": severity, "address": address if isinstance(address, int) else None})
        summary = {
            "total": len(rows),
            "verified": total_verified,
            "invalid": total_invalid,
            "neutral": total_neutral,
            "in_a2l": total_in_a2l,
            "out_of_mem": total_out_of_mem,
            "parse_errors": total_parse_errors,
        }
        coverage_line: Optional[str] = None
        report: Optional[ValidationReport] = None
        issues: list[ValidationIssue] = []
        if loaded is not None:
            validate_started = time.perf_counter()
            overlap_set = set()
            if primary_file is not None and primary_file.file_type == "s19":
                try:
                    overlap_set = set(S19File(str(primary_file.path)).get_overlap_addresses())
                except Exception as exc:
                    self.logger.warning(
                        "Failed to compute overlap set for %s: %s",
                        primary_file.path,
                        exc,
                    )
                    overlap_set = set()
            report, issues, coverage_line = build_validation_report(
                records=records,
                primary_file=primary_file,
                a2l_data=a2l_data,
                a2l_enriched_tags=a2l_enriched_tags,
                dedupe_issues=self._deduplicate_issues,
                overlapped_addresses=overlap_set,
            )
            # HLR-154 / UX-C7: an integrity notice on the loaded image is an
            # ERROR issue naming the code, so the Issues panel reports a
            # truncated or inconsistent image — not only the loader-facts
            # counter.
            for err in getattr(loaded, "errors", None) or []:
                code = load_notice_code(err)
                if code in _INTEGRITY_NOTICE_CODES:
                    issues.append(
                        ValidationIssue(
                            code=code,
                            severity=ValidationSeverity.ERROR,
                            message=str(err.get("error", code)),
                            artifact=str(
                                getattr(loaded, "file_type", None) or "load"
                            ),
                            line_number=err.get("line_number"),
                        )
                    )
            self.logger.info(
                "MAC validation computed: records=%d issues=%d elapsed_seconds=%.3f",
                len(records or []),
                len(issues),
                time.perf_counter() - validate_started,
            )
        return {
            "rows": rows,
            "meta": row_meta,
            "summary": summary,
            "coverage_line": coverage_line,
            "report": report,
            "issues": issues,
        }

    def _build_mac_view_cache(self) -> None:
        """
        Summary:
            Populate the MAC view cache members from ``_compute_mac_view_payload`` for the
            synchronous fallback path (tests, project load, and non-worker invocations).

        Args:
            None

        Returns:
            None

        Data Flow:
            - Call ``_compute_mac_view_payload`` with the currently attached file and A2L data.
            - Mirror its result onto ``self._mac_view_cache_*`` and the validation members.

        Dependencies:
            Uses:
                - ``_compute_mac_view_payload``
            Used by:
                - ``update_mac_view`` when the cache key has not been pre-populated
        """
        started = time.perf_counter()
        payload = self._compute_mac_view_payload(
            self.current_file,
            self.current_a2l_data,
            a2l_enriched_tags=self._a2l_enriched_tags,
        )
        self._mac_view_cache_rows = payload["rows"]
        self._mac_view_cache_meta = payload["meta"]
        self._mac_view_cache_summary = payload["summary"]
        self._mac_view_cache_coverage_line = payload["coverage_line"]
        self._validation_report = payload["report"]
        self._validation_issues = list(payload["issues"])
        widths, cell_rows, cell_styles = precompute_mac_datatable_payload(
            payload["rows"], payload["meta"]
        )
        self._mac_view_cache_widths = widths
        self._mac_view_cache_cell_rows = cell_rows
        self._mac_view_cache_cell_styles = cell_styles
        self.logger.info(
            "MAC row cache built: records=%d elapsed_seconds=%.3f",
            len(self.current_file.mac_records) if self.current_file else 0,
            time.perf_counter() - started,
        )

    def update_mac_hex_view(
        self,
        focus_address: Optional[int] = None,
        near_top: bool = False,
        reset_scroll: bool = False,
        *,
        start_row: Optional[int] = None,
    ) -> None:
        """Render MAC hex view around a focus address if provided."""
        mac_hex_view = self.query_one("#mac_hex_view", Static)
        if not self.current_file:
            mac_hex_view.update("No file loaded.")
            self._mac_first_visible_address = None
            self._mac_goto_focus_address = None
            return
        highlight = None
        if self.last_search_address is not None and self.last_search_text:
            highlight = (self.last_search_address, len(self.last_search_text))
        mac_highlights = self._collect_mac_highlight_addresses(self.current_file)
        row_bases = self.current_file.row_bases or []
        rows = self._hex_view_rows()
        if isinstance(start_row, int):
            start_row_index = (
                max(0, min(start_row, len(rows) - 1)) if rows else None
            )
        elif near_top:
            start_row_index = self._row_start_for_near_top_focus(
                focus_address, row_bases, rows
            )
        else:
            start_row_index = None
        if focus_address is not None and focus_address != self._mac_goto_focus_address:
            self._mac_goto_focus_address = None
        if rows:
            effective_start = start_row_index if isinstance(start_row_index, int) else 0
            self._mac_first_visible_address = rows[effective_start]
        else:
            self._mac_first_visible_address = None
        mac_hex_view.update(
            deps.render_hex_view_text(
                self.current_file.mem_map,
                focus_address,
                row_bases,
                highlight,
                mac_highlights,
                max_rows=self._clamp_viewer_page_size(self.hex_rows_page_size),
                start_row_index=start_row_index,
                row_bases_set=getattr(self.current_file, "bases_set", None),
                focus_row_marker_address=self._mac_goto_focus_address,
            )
        )
        if reset_scroll:
            self._reset_scroll_to_top("#mac_hex_scroll")

    def update_mac_view(self) -> None:
        """
        Summary:
            Populate the MAC DataTable with a paged window of ``.mac`` rows plus an
            off-table summary label, consuming worker-precomputed cell rows so the UI
            thread only issues one ``clear`` + ``add_rows`` call.

        Args:
            None (reads ``current_file``, ``current_a2l_data``, ``#mac_records_list``,
            and ``#mac_records_summary``.)

        Returns:
            None

        Data Flow:
            - Short-circuit when no MAC records are loaded (empty table + summary);
              a session WITH a primary file still computes/retains the primary+A2L
              validation report via ``_refresh_no_mac_validation`` (LLR-037.4) —
              only no-primary sessions clear the validation members.
            - Ensure the DataTable's MAC cache matches the current loaded state.
            - Slice one page of precomputed cell rows using ``mac_records_page_size``.
            - Build ``rich.text.Text`` cells keyed by severity and insert them via
              ``DataTable.add_rows`` in a single O(page_size) dict update.
            - Render aggregate counts and coverage into ``#mac_records_summary`` so the
              DataTable never has to hold summary rows.

        Dependencies:
            Uses:
                - ``_populate_mac_datatable``
                - ``update_validation_issues_view``
                - ``_refresh_no_mac_validation`` / ``_mac_view_cache_key_for``
            Used by:
                - ``_apply_prepared_load`` post-load refresh
                - ``update_a2l_view`` when A2L data changes
                - MAC paging actions
        """
        populate_started = time.perf_counter()
        mac_table = self.query_one("#mac_records_list", DataTable)
        summary_label = self.query_one("#mac_records_summary", deps.Label)
        self._mac_row_key_to_address = {}
        mac_table.clear(columns=False)
        # Blank the coverage strip by default; the loaded-MAC path re-shows it
        # below (LLR-071.2 — gated on a MAC being loaded, not on file type).
        self._update_mac_coverage_strip(show=False)
        if not self.current_file or not self.current_file.mac_records:
            summary_label.update("No MAC loaded.")
            self._refresh_no_mac_validation()
            self.update_validation_issues_view()
            self.logger.info(
                "Load phase boundary: populate_mac_table_done rows=0 elapsed=%.3f",
                time.perf_counter() - populate_started,
            )
            self._flush_logger()
            return
        records = self.current_file.mac_records or []
        if not records:
            summary_label.update("No MAC records parsed.")
            self._refresh_no_mac_validation()
            self.update_validation_issues_view()
            self.logger.info(
                "Load phase boundary: populate_mac_table_done rows=0 elapsed=%.3f",
                time.perf_counter() - populate_started,
            )
            self._flush_logger()
            return
        cache_key = self._mac_view_cache_key_for(
            records, self.current_file, self.current_a2l_data
        )
        if self._mac_view_cache_key != cache_key:
            self._mac_view_cache_key = cache_key
            self._build_mac_view_cache()
        cell_rows = self._mac_view_cache_cell_rows or []
        cell_styles = self._mac_view_cache_cell_styles or []
        total = self._mac_view_cache_summary.get("total", len(cell_rows))
        self._mac_window_start = self._mac_clamp_page_start(total)
        page_size = self._clamp_viewer_page_size(self.mac_records_page_size)
        start, end = self._get_window_bounds(total, self._mac_window_start, page_size)
        self._mac_window_start = start
        visible_rows = cell_rows[start:end]
        visible_styles = cell_styles[start:end]
        visible_meta = self._mac_view_cache_meta[start:end]
        self._populate_mac_datatable(mac_table, visible_rows, visible_styles, visible_meta, start)
        self._update_mac_coverage_strip(show=True)
        page_num = start // page_size + 1
        total_pages = max(1, (total + page_size - 1) // page_size)
        summary_text = (
            f"Page {page_num}/{total_pages} | rows {start + 1}-{end} / {total} "
            f"(page size {page_size}; +/- for MAC page)  "
            f"Total={total}  Verified={self._mac_view_cache_summary.get('verified', 0)}  "
            f"Invalid={self._mac_view_cache_summary.get('invalid', 0)}  "
            f"Neutral={self._mac_view_cache_summary.get('neutral', 0)}  "
            f"NameInA2L={self._mac_view_cache_summary.get('in_a2l', 0)}  "
            f"OutOfMem={self._mac_view_cache_summary.get('out_of_mem', 0)}  "
            f"ParseErrs={self._mac_view_cache_summary.get('parse_errors', 0)}"
        )
        if self.current_file.file_type in {"s19", "hex"} and self._mac_view_cache_coverage_line:
            summary_text = f"{summary_text}\n{self._mac_view_cache_coverage_line}"
        summary_label.update(summary_text)
        self.update_validation_issues_view()
        self.logger.info(
            "Load phase boundary: populate_mac_table_done rows=%d total=%d elapsed=%.3f",
            len(visible_rows),
            total,
            time.perf_counter() - populate_started,
        )
        self._flush_logger()

    def _update_mac_coverage_strip(self, *, show: bool) -> None:
        """
        Summary:
            Render (or blank) the always-visible MAC coverage strip
            ``#mac_coverage_strip`` (batch-47, LLR-071.1/071.2). When a MAC is
            loaded the strip shows ``build_mac_coverage_strip`` from the session's
            ``CoverageMetrics`` — independent of the primary file type,
            superseding the old primary-only pct-line. When no MAC is loaded the
            strip is blanked.

        Args:
            show (bool): True → render the coverage strip; False → blank it.

        Returns:
            None

        Data Flow:
            - Read ``self._validation_report.coverage`` (or ``None`` when no
              report exists yet) and hand it to ``build_mac_coverage_strip``,
              which formats a numeric-only, C-17-safe Rich ``Text``.
            - Defensively no-op when the strip node is not mounted (headless unit
              tests that fake ``query_one``).

        Dependencies:
            Uses:
                - ``build_mac_coverage_strip``
            Used by:
                - ``update_mac_view``
        """
        try:
            strip = self.query_one("#mac_coverage_strip", Static)
        except Exception:
            return
        if strip is None:
            return
        if not show:
            strip.update("")
            return
        report = self._validation_report
        coverage = report.coverage if report is not None else None
        strip.update(build_mac_coverage_strip(coverage))

    def _populate_mac_datatable(
        self,
        mac_table: "DataTable",
        visible_rows: list[tuple[str, ...]],
        visible_styles: list[str],
        visible_meta: list[dict[str, Any]],
        start: int,
    ) -> None:
        """
        Summary:
            Insert one page of MAC rows into the MAC ``DataTable`` via a single
            ``add_rows`` call, recording a ``row_key -> address`` map so selection
            handlers can jump to the corresponding hex address.

        Args:
            mac_table (DataTable): Target table widget.
            visible_rows (list[tuple[str, ...]]): Precomputed cell strings for the page.
            visible_styles (list[str]): Rich style strings parallel to ``visible_rows``.
            visible_meta (list[dict]): Severity/address metadata parallel to rows.
            start (int): Absolute index of the first row in the page.

        Returns:
            None

        Data Flow:
            - Fold a leading status glyph (``✓``/``⚠``/``✗``, coloured per the
              precomputed ``Status`` column via ``_mac_status_glyph``) into the
              Tag cell as its own span, then append the file-derived name in the
              row severity style (batch-47, LLR-070.1/070.2 — the name is a
              ``Text`` segment, never markup-parsed).
            - Colour the Address cell cyan (LLR-070); style the rest by severity.
            - Build row-key strings of the form ``mac:<absolute_index>``.
            - Record the per-row address in ``_mac_row_key_to_address`` for jump logic.
            - Invoke ``DataTable.add_row`` once per row (per-row key).

        Dependencies:
            Uses:
                - ``_mac_status_glyph``
            Used by:
                - ``update_mac_view``
        """
        if not visible_rows:
            return
        rendered_rows: list[tuple] = []
        keys: list[str] = []
        for i, row in enumerate(visible_rows):
            style = visible_styles[i] if i < len(visible_styles) else ""
            status = str(row[4]) if len(row) > 4 else ""
            in_mem = str(row[3]) if len(row) > 3 else ""
            glyph, glyph_style = _mac_status_glyph(status, in_mem)
            rich_cells: list[Text] = []
            for col, cell in enumerate(row):
                cell_str = str(cell)
                if col == 0:
                    tag_cell = Text()
                    tag_cell.append(f"{glyph} ", style=glyph_style)
                    tag_cell.append(cell_str, style=style or None)
                    rich_cells.append(tag_cell)
                elif col == 1:
                    rich_cells.append(Text(cell_str, style=CYAN))
                else:
                    rich_cells.append(Text(cell_str, style=style) if style else Text(cell_str))
            rendered_rows.append(tuple(rich_cells))
            absolute_index = start + i
            row_key = f"mac:{absolute_index}"
            keys.append(row_key)
            meta = visible_meta[i] if i < len(visible_meta) else {}
            address = meta.get("address") if isinstance(meta, dict) else None
            if isinstance(address, int):
                self._mac_row_key_to_address[row_key] = address
        for key, row in zip(keys, rendered_rows):
            try:
                mac_table.add_row(*row, key=key)
            except Exception:
                mac_table.add_row(*row)

    def _handle_search_mac(self) -> None:
        if not self.current_file:
            self.set_status("No file loaded.")
            return
        query = self.query_one("#mac_search_input", Input).value.strip()
        if not query:
            self.set_status("Search text is empty.")
            return
        is_new_query = self.last_search_text != query
        if is_new_query:
            self.last_search_text = query
            self.last_search_address = None
            self._mac_goto_focus_address = None

        start_address = None
        if self.last_search_address is not None:
            start_address = self.last_search_address + 1
        elif not is_new_query:
            start_address = self._first_visible_hex_address("mac")

        addr = deps.find_string_in_mem(self.current_file.mem_map, query, start_address)
        if addr is None:
            self.set_status("Search text not found.")
            self.last_search_address = None
            return
        self.last_search_address = addr
        self.update_mac_hex_view(addr, near_top=True, reset_scroll=True)
        self.set_status(f"Found at 0x{addr:08X}")

    def _handle_goto_mac(self) -> None:
        if not self.current_file:
            self.set_status("No file loaded.")
            return
        raw = self.query_one("#mac_goto_input", Input).value.strip()
        if not raw:
            self.set_status("Goto address is empty.")
            self._clear_goto_marker_keeping_window("mac")
            return
        try:
            addr = int(raw, 0)
        except ValueError:
            self.set_status("Invalid address format.")
            self._clear_goto_marker_keeping_window("mac")
            return
        if not self._apply_goto("mac", addr):
            self._clear_goto_marker_keeping_window("mac")
            return
        self.update_mac_hex_view(addr, near_top=True, reset_scroll=True)
        self.set_status(f"Goto 0x{addr:08X}")
