from __future__ import annotations

import bisect
from typing import Dict, List, Optional, Tuple

from rich.text import Text

from ..core import S19File
from ..hexfile import IntelHexFile
from ..range_index import (
    RangeIndex,
    address_in_sorted_ranges as _address_in_sorted_ranges,
    build_sorted_range_index as _build_sorted_range_index,
    range_in_sorted_ranges as _range_in_sorted_ranges,
)
from .color_policy import FOCUS_HIGHLIGHT_STYLE, MAC_ADDRESS_OVERLAY_STYLE


MAX_HEX_BYTES = 65536
HEX_WIDTH = 16
FOCUS_CONTEXT_ROWS = 64
MAX_HEX_ROWS = 512
SEARCH_ENCODING = "ascii"

def build_sorted_range_index(ranges: List[Tuple[int, int]]) -> RangeIndex:
    """
    Summary:
        Precompute a sorted (starts, ends) index so repeated address-in-ranges checks can
        use binary search instead of scanning all ranges.

    Args:
        ranges (List[Tuple[int, int]]): Half-open ``(start, end)`` address ranges, possibly
            unsorted and possibly overlapping.

    Returns:
        RangeIndex: Two parallel lists ``(starts, ends)``, both sorted by ``start``.

    Data Flow:
        - Sort a shallow copy of the input by ``start``.
        - Split into two parallel lists kept aligned by index.

    Dependencies:
        Used by:
            - ``address_in_sorted_ranges``
            - ``S19TuiApp`` MAC/A2L address membership checks
            - ``s19_app.validation.engine`` cross-artifact validation
    """
    return _build_sorted_range_index(ranges)


def address_in_sorted_ranges(addr: int, index: RangeIndex) -> bool:
    """
    Summary:
        Test whether ``addr`` falls inside any half-open range described by ``index``.

    Args:
        addr (int): Address to test.
        index (RangeIndex): Output of ``build_sorted_range_index``.

    Returns:
        bool: True when ``starts[i] <= addr < ends[i]`` for some ``i``.

    Data Flow:
        - Use ``bisect_right`` on ``starts`` to find the rightmost candidate range whose
          start is ``<= addr``.
        - Confirm the candidate is valid and that ``addr`` lies below its end.

    Dependencies:
        Uses:
            - ``bisect.bisect_right``
        Used by:
            - ``S19TuiApp._mac_address_in_ranges``
            - ``S19TuiApp._collect_mac_out_of_range_addresses``
            - ``S19TuiApp._build_mac_view_cache``
            - ``s19_app.validation.engine.validate_artifact_consistency``
    """
    return _address_in_sorted_ranges(addr, index)


def range_in_sorted_ranges(addr: int, length: int, index: RangeIndex) -> bool:
    """
    Summary:
        Test whether a contiguous span ``[addr, addr + length)`` fits entirely inside a single
        range of ``index`` (no spanning across gaps).

    Args:
        addr (int): Span start address.
        length (int): Positive length in bytes.
        index (RangeIndex): Output of ``build_sorted_range_index``.

    Returns:
        bool: True when one indexed range fully covers the span.

    Data Flow:
        - Reject zero/negative lengths (matches legacy semantics).
        - Binary search for the candidate range whose start is ``<= addr``.
        - Confirm ``addr + length`` does not exceed that range's end.

    Dependencies:
        Uses:
            - ``bisect.bisect_right``
        Used by:
            - ``s19_app.validation.engine.validate_artifact_consistency``
    """
    return _range_in_sorted_ranges(addr, length, index)


def build_mem_map_s19(s19: S19File) -> Dict[int, int]:
    """Build an address->byte map from S19 data records."""
    mem_map: Dict[int, int] = {}
    for record in s19.records:
        for offset, value in enumerate(record.data):
            mem_map[record.address + offset] = value
    return mem_map


def build_range_validity_s19(s19: S19File, ranges: List[Tuple[int, int]]) -> List[bool]:
    """Mark each address range as valid/invalid based on record validity."""
    address_valid: Dict[int, bool] = {}
    for record in s19.records:
        for offset in range(len(record.data)):
            addr = record.address + offset
            current = address_valid.get(addr, True)
            address_valid[addr] = current and record.valid

    validity = []
    for start, end in ranges:
        is_valid = True
        for addr in range(start, end):
            if addr in address_valid and not address_valid[addr]:
                is_valid = False
                break
        validity.append(is_valid)
    return validity


def build_range_validity_hex(hex_file: IntelHexFile, ranges: List[Tuple[int, int]]) -> List[bool]:
    """Mark all HEX ranges invalid if any HEX parsing errors exist."""
    has_errors = len(hex_file.get_errors()) > 0
    return [not has_errors for _ in ranges]


def build_row_bases(mem_map: Dict[int, int]) -> List[int]:
    """Precompute row base addresses for faster hex rendering."""
    if not mem_map:
        return []
    addresses = sorted(mem_map.keys())
    return sorted({addr - (addr % HEX_WIDTH) for addr in addresses})


def find_string_in_mem(
    mem_map: Dict[int, int],
    query: str,
    start_address: Optional[int] = None,
) -> Optional[int]:
    """Return the first address where the query string appears from a start."""
    if not query:
        return None
    try:
        needle = query.encode(SEARCH_ENCODING)
    except UnicodeEncodeError:
        return None
    needle = needle.lower()
    addresses = sorted(mem_map.keys())
    if not addresses:
        return None

    start = 0
    if start_address is not None:
        for i, addr in enumerate(addresses):
            if addr >= start_address:
                start = i
                break
        else:
            return None

    idx_base = start
    while idx_base < len(addresses):
        run_start = idx_base
        run_end = run_start + 1
        while run_end < len(addresses) and addresses[run_end] == addresses[run_end - 1] + 1:
            run_end += 1
        run_addrs = addresses[run_start:run_end]
        run_bytes = bytes(mem_map[addr] for addr in run_addrs)
        idx = run_bytes.lower().find(needle)
        if idx != -1:
            return run_addrs[0] + idx
        idx_base = run_end
    return None


def _collect_hex_rows(
    mem_map: Dict[int, int],
    focus_address: Optional[int] = None,
    row_bases: Optional[List[int]] = None,
    extra_addresses: Optional[set[int]] = None,
    max_rows: Optional[int] = None,
    start_row_index: Optional[int] = None,
    row_bases_set: Optional[set[int]] = None,
) -> tuple[List[str], List[Tuple[int, List[Optional[int]]]]]:
    """
    Summary:
        Materialize the hex-view row list for a window around ``focus_address`` while
        reusing precomputed row-base containers so very large images stay responsive.

    Args:
        mem_map (Dict[int, int]): Address-to-byte map backing the render.
        focus_address (Optional[int]): Preferred center address when no explicit start row.
        row_bases (Optional[List[int]]): Sorted 16-byte-aligned row anchors.
        extra_addresses (Optional[set[int]]): Additional addresses (e.g. MAC highlights)
            that must be visible, even when they fall outside ``row_bases``.
        max_rows (Optional[int]): Upper bound on rendered rows (defaults to ``MAX_HEX_ROWS``).
        start_row_index (Optional[int]): Explicit start index into the resolved bases list.
        row_bases_set (Optional[set[int]]): Precomputed ``set(row_bases)`` reused as the
            fast-path membership check so we never rebuild a multi-million-entry set per
            render.

    Returns:
        tuple[List[str], List[Tuple[int, List[Optional[int]]]]]: Header lines plus the
        rendered row data (base address + 16 byte slots).

    Data Flow:
        - Choose the active bases list (skip ``set(...)`` rebuild when ``row_bases_set``
          is supplied and the extra addresses form a subset).
        - Clamp a window around ``focus_address`` / ``start_row_index``.
        - Stream row tuples from ``mem_map`` up to the byte budget.

    Dependencies:
        Used by:
            - ``render_hex_view``
            - ``render_hex_view_text``
    """
    base_row_bases = row_bases if row_bases is not None else build_row_bases(mem_map)
    extra = extra_addresses or set()
    if not extra:
        # Hot path: no extra bases to splice in, so reuse the pre-sorted row_bases as-is.
        # This avoids rebuilding a set of millions of addresses on every hex-view refresh.
        bases: List[int] = base_row_bases if isinstance(base_row_bases, list) else list(base_row_bases)
    else:
        extra_bases = {addr - (addr % HEX_WIDTH) for addr in extra}
        # Prefer the caller-provided membership set so multi-million-row images skip the
        # O(n) set(base_row_bases) rebuild on every hex render.
        existing: set[int]
        if row_bases_set is not None:
            existing = row_bases_set
        else:
            existing = set(base_row_bases)
        if extra_bases.issubset(existing):
            bases = base_row_bases if isinstance(base_row_bases, list) else list(base_row_bases)
        else:
            bases = sorted(existing | extra_bases)
    if not bases:
        return ["No data available."], []

    lines: List[str] = []
    rows: List[Tuple[int, List[Optional[int]]]] = []

    row_limit = max(1, max_rows) if isinstance(max_rows, int) else MAX_HEX_ROWS
    start_index = 0
    if isinstance(start_row_index, int):
        start_index = max(0, min(start_row_index, max(0, len(bases) - 1)))
    elif focus_address is not None:
        focus_base = focus_address - (focus_address % HEX_WIDTH)
        focus_index = bisect.bisect_left(bases, focus_base)
        if focus_index < len(bases) and bases[focus_index] == focus_base:
            start_index = max(0, focus_index - FOCUS_CONTEXT_ROWS)
        else:
            lines.append(f"... address 0x{focus_address:08X} not present ...")

    if start_index > 0:
        lines.append(f"... showing from 0x{bases[start_index]:08X} (context preserved) ...")

    end_index = min(len(bases), start_index + row_limit)
    if end_index < len(bases):
        lines.append(f"... window limited to {row_limit} rows ...")

    bytes_rendered = 0
    for row_addr in bases[start_index:end_index]:
        row_bytes: List[Optional[int]] = []
        for offset in range(HEX_WIDTH):
            addr = row_addr + offset
            value = mem_map.get(addr)
            if value is not None:
                bytes_rendered += 1
            row_bytes.append(value)
        rows.append((row_addr, row_bytes))
        if bytes_rendered >= MAX_HEX_BYTES:
            lines.append(f"... output truncated at {MAX_HEX_BYTES} bytes ...")
            break

    return lines, rows


def render_hex_view(
    mem_map: Dict[int, int],
    focus_address: Optional[int] = None,
    row_bases: Optional[List[int]] = None,
    extra_addresses: Optional[set[int]] = None,
    max_rows: Optional[int] = None,
    start_row_index: Optional[int] = None,
    row_bases_set: Optional[set[int]] = None,
) -> str:
    """Render a windowed hex+ASCII view for responsive UI."""
    header_lines, rows = _collect_hex_rows(
        mem_map,
        focus_address,
        row_bases,
        extra_addresses,
        max_rows=max_rows,
        start_row_index=start_row_index,
        row_bases_set=row_bases_set,
    )
    if rows == [] and header_lines:
        return "\n".join(header_lines)

    lines = header_lines[:]
    for row_addr, row_bytes in rows:
        hex_part = " ".join(f"{b:02X}" if b is not None else "  " for b in row_bytes)
        ascii_part = "".join(chr(b) if b is not None and 32 <= b <= 126 else "." for b in row_bytes)
        lines.append(f"0x{row_addr:08X}  {hex_part}  |{ascii_part}|")
    return "\n".join(lines)


def render_hex_view_text(
    mem_map: Dict[int, int],
    focus_address: Optional[int],
    row_bases: Optional[List[int]],
    highlight: Optional[Tuple[int, int]],
    mac_highlight_addresses: Optional[set[int]] = None,
    max_rows: Optional[int] = None,
    start_row_index: Optional[int] = None,
    row_bases_set: Optional[set[int]] = None,
) -> Text:
    """Render hex view with optional highlighted match range."""
    header_lines, rows = _collect_hex_rows(
        mem_map,
        focus_address,
        row_bases,
        mac_highlight_addresses,
        max_rows=max_rows,
        start_row_index=start_row_index,
        row_bases_set=row_bases_set,
    )
    text = Text()
    for line in header_lines:
        text.append(line + "\n")
    if not rows:
        return text

    highlight_start = highlight[0] if highlight else None
    highlight_end = highlight_start + highlight[1] if highlight else None
    highlight_style = FOCUS_HIGHLIGHT_STYLE
    mac_highlight_style = MAC_ADDRESS_OVERLAY_STYLE
    mac_addresses = mac_highlight_addresses or set()

    for row_addr, row_bytes in rows:
        text.append(f"0x{row_addr:08X}  ")
        for offset, value in enumerate(row_bytes):
            addr = row_addr + offset
            style = (
                highlight_style
                if highlight_start is not None and highlight_start <= addr < highlight_end
                else mac_highlight_style if addr in mac_addresses else None
            )
            if value is None:
                text.append("   ")
            else:
                text.append(f"{value:02X} ", style=style)
        text.append(" |")
        for offset, value in enumerate(row_bytes):
            addr = row_addr + offset
            style = (
                highlight_style
                if highlight_start is not None and highlight_start <= addr < highlight_end
                else mac_highlight_style if addr in mac_addresses else None
            )
            if value is None:
                text.append(" ")
            else:
                char = chr(value) if 32 <= value <= 126 else "."
                text.append(char, style=style)
        text.append("|\n")
    return text
