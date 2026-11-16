"""s19_app.tui.app.hex_view — S19TuiApp mixin: hex_view (moved verbatim from s19_app/tui/app.py at 4f721985)."""
from __future__ import annotations

from typing import Optional
from textual.containers import ScrollableContainer
from textual.widgets import Input, Static
from ...range_index import address_in_sorted_ranges
from ...render.hexview import hex_row_bases
from . import deps


class HexViewMixin:

    def _get_window_bounds(self, total: int, start: int, window_size: int) -> tuple[int, int]:
        """
        Summary:
            Clamp a requested window start and return a safe half-open render range.

        Args:
            total (int): Total available rows/lines.
            start (int): Requested window start index.
            window_size (int): Number of rows/lines to render in one window.

        Returns:
            tuple[int, int]: ``(start, end)`` bounds clamped to ``[0, total]``.

        Data Flow:
            - Clamp ``start`` to a valid source index.
            - Compute ``end`` from clamped start plus window size.
            - Clamp ``end`` to source length.

        Dependencies:
            Uses:
                - built-in ``max`` / ``min`` arithmetic
            Used by:
                - A2L tags and summary buffered render helpers
        """
        if total <= 0:
            return 0, 0
        safe_start = max(0, min(start, total - 1))
        safe_end = min(total, safe_start + max(1, window_size))
        return safe_start, safe_end

    def _clamp_viewer_page_size(self, value: int) -> int:
        """
        Summary:
            Normalize viewer page-size settings into the allowed configured range.

        Args:
            value (int): Requested per-view page-size value.

        Returns:
            int: Clamped page-size in ``[1, viewer_page_size_max]``.

        Data Flow:
            - Coerce non-positive values to ``1``.
            - Clamp upper bound to ``viewer_page_size_max``.

        Dependencies:
            Used by:
                - Settings menu application handlers
        """
        return max(1, min(int(value), self.viewer_page_size_max))

    def _shift_window_for_index(self, total: int, index: int, start: int, window_size: int) -> int:
        """
        Summary:
            Shift a window start so a selected/highlighted absolute index stays within buffered margins.

        Args:
            total (int): Total source rows.
            index (int): Absolute row index that should remain in the buffered viewport.
            start (int): Current window start index.
            window_size (int): Number of rows rendered in one window.

        Returns:
            int: Updated window start index.

        Data Flow:
            - Compute current window bounds.
            - If index is near top/bottom overscan thresholds, move start forward/backward.
            - Clamp final start to source range.

        Dependencies:
            Uses:
                - ``_get_window_bounds``
            Used by:
                - A2L tags selection/highlight handlers
        """
        if total <= 0:
            return 0
        index = max(0, min(index, total - 1))
        current_start, current_end = self._get_window_bounds(total, start, window_size)
        top_threshold = current_start + self.a2l_window_overscan
        bottom_threshold = current_end - self.a2l_window_overscan
        if index < top_threshold:
            new_start = max(0, index - self.a2l_window_overscan)
            return new_start
        if index >= bottom_threshold:
            new_start = max(0, index - (window_size - self.a2l_window_overscan - 1))
            return min(new_start, max(0, total - window_size))
        return current_start

    def action_hex_page_next(self) -> None:
        """
        Summary:
            Advance the main hex viewer window by one configured page of rows.

        Args:
            None

        Returns:
            None

        Data Flow:
            - Guard on active layout and loaded row-base data.
            - Move ``_hex_window_start`` forward by ``hex_rows_page_size``.
            - Re-render main hex panel.

        Dependencies:
            Uses:
                - ``_active_view_name``
                - ``update_hex_view``
        """
        if self._active_view_name() != "main":
            return
        if not self.current_file or not self.current_file.row_bases:
            return
        page_size = self._clamp_viewer_page_size(self.hex_rows_page_size)
        total = len(self._hex_view_rows())
        start = self._hex_window_start
        self._hex_window_start = start + page_size if start + page_size < total else start
        self.last_search_address = None
        self._goto_focus_address = None
        self.update_hex_view()

    def action_hex_page_prev(self) -> None:
        """
        Summary:
            Move the main hex viewer window back by one configured page of rows.

        Args:
            None

        Returns:
            None

        Data Flow:
            - Guard on active layout and loaded row-base data.
            - Move ``_hex_window_start`` backward by ``hex_rows_page_size``.
            - Re-render main hex panel.

        Dependencies:
            Uses:
                - ``_active_view_name``
                - ``update_hex_view``
        """
        if self._active_view_name() != "main":
            return
        if not self.current_file or not self.current_file.row_bases:
            return
        page_size = self._clamp_viewer_page_size(self.hex_rows_page_size)
        self._hex_window_start = max(0, self._hex_window_start - page_size)
        self.last_search_address = None
        self._goto_focus_address = None
        self.update_hex_view()

    def _snapped_focus_row_index(
        self, focus_address: int, row_bases: list[int]
    ) -> Optional[int]:
        """
        Summary:
            Resolve a focus address to the index of the nearest present
            16-aligned row base — exact when present, else the first row
            at-or-after the focus, else the last row before it (batch-31
            AC-1 / B-01).

        Args:
            focus_address (int): The requested focus address (need not be
                present in the image — e.g. a coarse Memory-Map cell start).
            row_bases (list[int]): The image's ascending present row bases.

        Returns:
            Optional[int]: Index into ``row_bases``, or ``None`` when the
            list is empty.

        Data Flow:
            - Align the focus down to its 16-byte row, then bisect the
              sorted ``row_bases`` for the exact/at-or-after/before match.

        Dependencies:
            Uses:
                - ``bisect.bisect_left``
            Used by:
                - ``update_hex_view`` (window reposition on focus)
        """
        if not row_bases:
            return None
        from bisect import bisect_left

        focus_base = focus_address - (focus_address % 16)
        index = bisect_left(row_bases, focus_base)
        if index < len(row_bases):
            return index
        return len(row_bases) - 1

    def _hex_view_rows(self) -> list[int]:
        """
        Summary:
            The view rows of the three hex views (I-5): the present rows plus
            the rows R-TUI-004.3 adds for MAC records outside the image, in
            address order. Window starts, page bounds and first visible rows
            are indices into this list.

        Args:
            None

        Returns:
            list[int]: The view rows; ``[]`` without a file. With no MAC row
            outside the image it is ``current_file.row_bases`` itself (no
            copy).

        Data Flow:
            - Memoised in ``_hex_view_rows_cache`` under the key
              ``(_image_generation, frozenset(MAC record addresses))``.
            - Invalidation rule: every image install bumps
              ``_image_generation``; a writer of ``current_file`` that does
              not bump it (an unload, the project-load reset) must reset
              ``_hex_view_rows_cache`` to ``None`` itself, or the old image's
              rows are returned.
            - The renderer is not given this list: ``render_hex_view_text``
              rebuilds it from the same three inputs through
              ``hex_row_bases``, so both lists agree by construction.

        Dependencies:
            Uses:
                - ``hex_row_bases`` / ``_collect_mac_highlight_addresses``
            Used by:
                - ``update_hex_view`` / ``update_alt_hex_view`` /
                  ``update_mac_hex_view`` / ``action_hex_page_next`` /
                  ``_first_visible_hex_address`` /
                  ``_clear_goto_marker_keeping_window``
        """
        file = self.current_file
        if file is None:
            return []
        mac_set = self._collect_mac_highlight_addresses(file)
        key = (self._image_generation, frozenset(mac_set))
        cached = self._hex_view_rows_cache
        if cached is not None and cached[0] == key:
            return cached[1]
        rows = hex_row_bases(
            file.row_bases or [],
            getattr(file, "bases_set", None),
            mac_set,
        )
        self._hex_view_rows_cache = (key, rows)
        return rows

    def update_hex_view(self, focus_address: Optional[int] = None) -> None:
        """Render hex view around a focus address if provided."""
        hex_view = self.query_one("#hex_view", Static)
        if not self.current_file:
            hex_view.update("No file loaded.")
            self._goto_focus_address = None
            return
        row_bases = self.current_file.row_bases or []
        rows = self._hex_view_rows()
        page_size = self._clamp_viewer_page_size(self.hex_rows_page_size)
        if isinstance(focus_address, int):
            start = self._row_start_for_near_top_focus(focus_address, row_bases, rows)
            if start is not None:
                self._hex_window_start = start
        self._hex_window_start = max(0, min(self._hex_window_start, len(rows) - 1))
        if focus_address is not None and focus_address != self._goto_focus_address:
            self._goto_focus_address = None
        highlight = None
        if self.last_search_address is not None and self.last_search_text:
            highlight = (self.last_search_address, len(self.last_search_text))
        mac_highlights = self._collect_mac_highlight_addresses(self.current_file)
        hex_view.update(
            deps.render_hex_view_text(
                self.current_file.mem_map,
                focus_address,
                row_bases,
                highlight,
                mac_highlights,
                max_rows=page_size,
                start_row_index=self._hex_window_start,
                row_bases_set=getattr(self.current_file, "bases_set", None),
                focus_row_marker_address=self._goto_focus_address,
            )
        )
        if focus_address is not None:
            self._reset_scroll_to_top("#hex_scroll")
            self.logger.info("Hex view focused at 0x%08X", focus_address)

    def _row_start_for_near_top_focus(
        self,
        focus_address: Optional[int],
        row_bases: list[int],
        view_rows: list[int],
        context_rows: int = 1,
    ) -> Optional[int]:
        """Return a start-row index that keeps ``focus_address`` near the top."""
        if not isinstance(focus_address, int) or not view_rows:
            return None
        from bisect import bisect_left

        i = self._snapped_focus_row_index(focus_address, row_bases)
        if i is None:
            return None
        j = bisect_left(view_rows, row_bases[i])
        return max(0, j - max(0, context_rows))

    def _reset_scroll_to_top(self, container_id: str) -> None:
        """Best-effort scroll reset for a hex scroll container."""
        try:
            container = self.query_one(container_id, ScrollableContainer)
        except Exception:
            return
        try:
            container.scroll_home(animate=False)
            return
        except Exception:
            pass
        try:
            container.scroll_y = 0
        except Exception:
            pass

    def update_alt_hex_view(
        self,
        focus_address: Optional[int] = None,
        near_top: bool = False,
        reset_scroll: bool = False,
        *,
        start_row: Optional[int] = None,
    ) -> None:
        """
        Summary:
            Render the alternate hex panel with optional focus and a highlight span.

        Args:
            focus_address (Optional[int]): Focus the view on this address when set.
            near_top (bool): When True, anchor the focused address near the top rows.
            reset_scroll (bool): When True, reset alt hex scroll position to top.
            start_row (Optional[int]): Explicit start index into the view rows;
                wins over ``near_top`` when given (I-3).

        Returns:
            None

        Data Flow:
            - Prefer ``_a2l_tag_hex_highlight`` (address, length) when present.
            - Otherwise use ASCII alt-search hit span from ``last_search_*``.
            - Render via ``render_hex_view_text`` into ``#alt_hex_view``.

        Dependencies:
            Uses:
                - ``render_hex_view_text``
            Used by:
                - ``load_selected_file``
                - ``_jump_to_tag``
                - ``_handle_a2l_tag_find_next``
                - ``_handle_search_alt`` / ``_handle_goto_alt``
        """
        alt_hex_view = self.query_one("#alt_hex_view", Static)
        if not self.current_file:
            alt_hex_view.update("No file loaded.")
            self._alt_first_visible_address = None
            self._alt_goto_focus_address = None
            return
        highlight = None
        if self._a2l_tag_hex_highlight is not None:
            highlight = self._a2l_tag_hex_highlight
        elif self.last_search_address is not None and self.last_search_text:
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
        if focus_address is not None and focus_address != self._alt_goto_focus_address:
            self._alt_goto_focus_address = None
        if rows:
            effective_start = start_row_index if isinstance(start_row_index, int) else 0
            self._alt_first_visible_address = rows[effective_start]
        else:
            self._alt_first_visible_address = None
        alt_hex_view.update(
            deps.render_hex_view_text(
                self.current_file.mem_map,
                focus_address,
                row_bases,
                highlight,
                mac_highlights,
                max_rows=self._clamp_viewer_page_size(self.hex_rows_page_size),
                start_row_index=start_row_index,
                row_bases_set=getattr(self.current_file, "bases_set", None),
                focus_row_marker_address=self._alt_goto_focus_address,
            )
        )
        if reset_scroll:
            self._reset_scroll_to_top("#alt_hex_scroll")

    def _first_visible_hex_address(self, view: str) -> Optional[int]:
        """
        Summary:
            Return the base address of the first row currently visible in the named
            hex view, or ``None`` when the view has no rendered rows.

        Args:
            view (str): One of ``"main"``, ``"alt"``, or ``"mac"``.

        Returns:
            Optional[int]: First-visible row-base address; ``None`` when unavailable.
        """
        if view == "main":
            rows = self._hex_view_rows()
            index = self._hex_window_start
            if not isinstance(index, int) or index < 0 or index >= len(rows):
                return None
            return rows[index]
        if view == "alt":
            return self._alt_first_visible_address
        if view == "mac":
            return self._mac_first_visible_address
        return None

    def _handle_search(self) -> None:
        if not self.current_file:
            self.set_status("No file loaded.")
            return
        query = self.query_one("#search_input", Input).value.strip()
        if not query:
            self.set_status("Search text is empty.")
            return
        is_new_query = self.last_search_text != query
        if is_new_query:
            self.last_search_text = query
            self.last_search_address = None
            self._goto_focus_address = None

        start_address = None
        if self.last_search_address is not None:
            start_address = self.last_search_address + 1
        elif not is_new_query:
            start_address = self._first_visible_hex_address("main")

        addr = deps.find_string_in_mem(self.current_file.mem_map, query, start_address)
        if addr is None:
            self.set_status("Search text not found.")
            self.last_search_address = None
            return
        self.last_search_address = addr
        self.update_hex_view(addr)
        self.set_status(f"Found at 0x{addr:08X}")

    def _apply_goto(self, view: str, addr: int) -> bool:
        """
        Summary:
            Validate a parsed goto address against the current file's loaded ranges and,
            on a hit, record the per-view focus address that drives the hex-row marker.

        Args:
            view (str): One of ``"main"``, ``"alt"``, or ``"mac"`` — selects the
                ``_<view>_goto_focus_address`` field updated on a hit.
            addr (int): Parsed integer goto address.

        Returns:
            bool: True when ``addr`` lies inside a loaded range (focus address set);
            False when out of range (status emitted, focus field left unchanged).

        Data Flow:
            - Resolve the cached sorted range index via ``_get_range_index``.
            - On a membership miss, emit the ``Address 0x... not in loaded file.`` status
              and return False without mutating any focus field.
            - On a hit, set the matching ``_<view>_goto_focus_address`` and return True.

        Dependencies:
            Uses:
                - ``_get_range_index``
                - ``address_in_sorted_ranges``
                - ``set_status``
            Used by:
                - ``_handle_goto`` / ``_handle_goto_alt`` / ``_handle_goto_mac``
        """
        range_index = self._get_range_index(self.current_file)
        if not address_in_sorted_ranges(addr, range_index):
            self.set_status(f"Address 0x{addr:08X} not in loaded file.")
            return False
        if view == "main":
            self._goto_focus_address = addr
        elif view == "alt":
            self._alt_goto_focus_address = addr
        elif view == "mac":
            self._mac_goto_focus_address = addr
        return True

    def _handle_goto(self) -> None:
        if not self.current_file:
            self.set_status("No file loaded.")
            return
        raw = self.query_one("#goto_input", Input).value.strip()
        if not raw:
            self.set_status("Goto address is empty.")
            if self._goto_focus_address is not None:
                self._goto_focus_address = None
                self.update_hex_view()
            return
        try:
            addr = int(raw, 0)
        except ValueError:
            self.set_status("Invalid address format.")
            if self._goto_focus_address is not None:
                self._goto_focus_address = None
                self.update_hex_view()
            return
        if not self._apply_goto("main", addr):
            if self._goto_focus_address is not None:
                self._goto_focus_address = None
                self.update_hex_view()
            return
        self.update_hex_view(addr)
        self.set_status(f"Goto 0x{addr:08X}")

    def _handle_search_alt(self) -> None:
        if not self.current_file:
            self.set_status("No file loaded.")
            return
        self._a2l_tag_hex_highlight = None
        query = self.query_one("#alt_search_input", Input).value.strip()
        if not query:
            self.set_status("Search text is empty.")
            return
        is_new_query = self.last_search_text != query
        if is_new_query:
            self.last_search_text = query
            self.last_search_address = None
            self._alt_goto_focus_address = None

        start_address = None
        if self.last_search_address is not None:
            start_address = self.last_search_address + 1
        elif not is_new_query:
            start_address = self._first_visible_hex_address("alt")

        addr = deps.find_string_in_mem(self.current_file.mem_map, query, start_address)
        if addr is None:
            self.set_status("Search text not found.")
            self.last_search_address = None
            return
        self.last_search_address = addr
        self.update_alt_hex_view(addr, near_top=True, reset_scroll=True)
        self.set_status(f"Found at 0x{addr:08X}")

    def _handle_goto_alt(self) -> None:
        if not self.current_file:
            self.set_status("No file loaded.")
            return
        self._a2l_tag_hex_highlight = None
        raw = self.query_one("#alt_goto_input", Input).value.strip()
        if not raw:
            self.set_status("Goto address is empty.")
            self._clear_goto_marker_keeping_window("alt")
            return
        try:
            addr = int(raw, 0)
        except ValueError:
            self.set_status("Invalid address format.")
            self._clear_goto_marker_keeping_window("alt")
            return
        if not self._apply_goto("alt", addr):
            self._clear_goto_marker_keeping_window("alt")
            return
        self.update_alt_hex_view(addr, near_top=True, reset_scroll=True)
        self.set_status(f"Goto 0x{addr:08X}")

    def _clear_goto_marker_keeping_window(self, view: str) -> None:
        """
        Summary:
            After a failed go-to in the A2L or MAC hex view, remove the view's
            ``> `` marker and re-render it from the row it already shows
            (R-TUI-040.11, R-TUI-040.8). With no marker set nothing renders.

        Args:
            view (str): ``"alt"`` (the A2L view) or ``"mac"``.

        Returns:
            None

        Data Flow:
            - The start index is the painted first row's place in the view
              rows (``bisect_left``; an address no longer among them gives
              the next row, which the render's clamp bounds).

        Dependencies:
            Uses:
                - ``_hex_view_rows`` / ``update_alt_hex_view`` /
                  ``update_mac_hex_view``
            Used by:
                - ``_handle_goto_alt`` / ``_handle_goto_mac`` (their three
                  failure branches)
        """
        from bisect import bisect_left

        if view == "alt":
            if self._alt_goto_focus_address is None:
                return
            self._alt_goto_focus_address = None
            first, render = self._alt_first_visible_address, self.update_alt_hex_view
        else:
            if self._mac_goto_focus_address is None:
                return
            self._mac_goto_focus_address = None
            first, render = self._mac_first_visible_address, self.update_mac_hex_view
        start = bisect_left(self._hex_view_rows(), first) if first is not None else 0
        render(start_row=start)
