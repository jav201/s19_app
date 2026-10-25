from __future__ import annotations

import bisect
from typing import Dict, List, Optional, Tuple

from rich.text import Text

from ..core import S19File, _is_data_record
from ..hexfile import IntelHexFile
from ..range_index import (
    RangeIndex,
    address_in_sorted_ranges as _address_in_sorted_ranges,
    build_sorted_range_index as _build_sorted_range_index,
    range_in_sorted_ranges as _range_in_sorted_ranges,
)
from .format import CYAN, DGRAY, VALUE, FOCUS_HIGHLIGHT_STYLE, MAC_ADDRESS_OVERLAY_STYLE


MAX_HEX_BYTES = 65536
HEX_WIDTH = 16
FOCUS_CONTEXT_ROWS = 64
MAX_HEX_ROWS = 512
SEARCH_ENCODING = "ascii"


def _hex_byte_style(value: int) -> str:
    """
    Summary:
        Classify a hex byte by kind and return the matching palette colour for its
        rendered two-hex-digit cell: ``00``/``FF`` (constant/padding) read as dim
        grey, printable ASCII (``0x20``-``0x7E``) as cyan, and every other byte as
        the bright value colour. This gives the analyst a glanceable read of a hex
        window's byte make-up without changing any character rendered.

    Args:
        value (int): A byte value in ``0..255``.

    Returns:
        str: One of :data:`insight_style.DGRAY` / :data:`insight_style.CYAN` /
        :data:`insight_style.VALUE` — a Rich style string applied to the byte cell.

    Data Flow:
        - Pure comparison over ``value``; no I/O, no markup parsing.
        - Called by ``render_hex_view_text`` for each present byte cell that carries
          no higher-priority search/MAC highlight style.

    Dependencies:
        Uses:
            - insight_style.DGRAY / insight_style.CYAN / insight_style.VALUE
        Used by:
            - render_hex_view_text
    """
    if value in (0x00, 0xFF):
        return DGRAY
    if 0x20 <= value <= 0x7E:
        return CYAN
    return VALUE


def build_mem_map_s19(s19: S19File) -> Dict[int, int]:
    """Build an address->byte map from S19 data records."""
    mem_map: Dict[int, int] = {}
    for record in s19.records:
        if not _is_data_record(record):
            continue
        for offset, value in enumerate(record.data):
            mem_map[record.address + offset] = value
    return mem_map


def build_range_validity_s19(s19: S19File, ranges: List[Tuple[int, int]]) -> List[bool]:
    """Mark each address range as valid/invalid based on record validity."""
    address_valid: Dict[int, bool] = {}
    for record in s19.records:
        if not _is_data_record(record):
            continue
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
    *,
    focus_row_marker_address: Optional[int] = None,
) -> Text:
    """
    Summary:
        Render a windowed hex+ASCII view as Rich ``Text``, optionally painting the
        search/MAC byte highlights and prepending a plain-text goto focus marker to
        the row that contains ``focus_row_marker_address``.

    Args:
        mem_map (Dict[int, int]): Address-to-byte map backing the render.
        focus_address (Optional[int]): Preferred center address when no explicit start row.
        row_bases (Optional[List[int]]): Sorted 16-byte-aligned row anchors.
        highlight (Optional[Tuple[int, int]]): ``(start, length)`` span painted with
            ``FOCUS_HIGHLIGHT_STYLE`` (yellow search highlight).
        mac_highlight_addresses (Optional[set[int]]): Addresses painted with
            ``MAC_ADDRESS_OVERLAY_STYLE`` (orange MAC overlay).
        max_rows (Optional[int]): Upper bound on rendered rows.
        start_row_index (Optional[int]): Explicit start index into the resolved bases list.
        row_bases_set (Optional[set[int]]): Precomputed ``set(row_bases)`` membership set.
        focus_row_marker_address (Optional[int]): When set, the row whose half-open
            ``[row_addr, row_addr + HEX_WIDTH)`` window contains this address is prefixed
            with ``"> "``; every other row is prefixed with ``"  "`` (two spaces) so the
            address column stays aligned. ``None`` (the default) prepends ``"  "`` to every
            row, preserving the pre-marker layout for all existing callers.

    Returns:
        Text: Rich ``Text`` with header lines plus one line per rendered hex row.

    Data Flow:
        - Materialize rows via ``_collect_hex_rows``.
        - For each row, append the 2-cell marker prefix (no ``style=``), then the address,
          the hex byte cells, and the ASCII gutter with their existing highlight styles.
        - Each present hex byte cell that carries no search/MAC highlight is classed by
          kind via ``_hex_byte_style`` (``00``/``FF`` dim, printable-ASCII cyan, else
          bright); the ASCII gutter is left unclassed. Classing only adds ``Text`` spans —
          the ``.plain`` string is unchanged, and the highlight styles keep priority.

    Dependencies:
        Uses:
            - ``_collect_hex_rows``
            - ``_hex_byte_style``
            - ``FOCUS_HIGHLIGHT_STYLE`` / ``MAC_ADDRESS_OVERLAY_STYLE``
        Used by:
            - ``S19TuiApp.update_hex_view`` / ``update_alt_hex_view`` / ``update_mac_hex_view``

    Example:
        >>> text = render_hex_view_text({0x1000: 0x41}, None, [0x1000], None,
        ...                             focus_row_marker_address=0x1000)
        >>> text.plain.splitlines()[0].startswith("> ")
        True
    """
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
        if (
            focus_row_marker_address is not None
            and row_addr <= focus_row_marker_address < row_addr + HEX_WIDTH
        ):
            text.append("> ")
        else:
            text.append("  ")
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
                byte_style = style if style is not None else _hex_byte_style(value)
                text.append(f"{value:02X} ", style=byte_style)
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
