from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from rich.text import Text

from ..core import S19File
from ..hexfile import IntelHexFile


MAX_HEX_BYTES = 65536
HEX_WIDTH = 16
FOCUS_CONTEXT_ROWS = 64
MAX_HEX_ROWS = 512
SEARCH_ENCODING = "ascii"


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
) -> tuple[List[str], List[Tuple[int, List[Optional[int]]]]]:
    bases = row_bases or build_row_bases(mem_map)
    if not bases:
        return ["No data available."], []

    lines: List[str] = []
    rows: List[Tuple[int, List[Optional[int]]]] = []

    start_index = 0
    if focus_address is not None:
        focus_base = focus_address - (focus_address % HEX_WIDTH)
        if focus_base in bases:
            focus_index = bases.index(focus_base)
            start_index = max(0, focus_index - FOCUS_CONTEXT_ROWS)
        else:
            lines.append(f"... address 0x{focus_address:08X} not present ...")

    if start_index > 0:
        lines.append(f"... showing from 0x{bases[start_index]:08X} (context preserved) ...")

    end_index = min(len(bases), start_index + MAX_HEX_ROWS)
    if end_index < len(bases):
        lines.append(f"... window limited to {MAX_HEX_ROWS} rows ...")

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
) -> str:
    """Render a windowed hex+ASCII view for responsive UI."""
    header_lines, rows = _collect_hex_rows(mem_map, focus_address, row_bases)
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
) -> Text:
    """Render hex view with optional highlighted match range."""
    header_lines, rows = _collect_hex_rows(mem_map, focus_address, row_bases)
    text = Text()
    for line in header_lines:
        text.append(line + "\n")
    if not rows:
        return text

    highlight_start = highlight[0] if highlight else None
    highlight_end = highlight_start + highlight[1] if highlight else None
    highlight_style = "bold yellow"

    for row_addr, row_bytes in rows:
        text.append(f"0x{row_addr:08X}  ")
        for offset, value in enumerate(row_bytes):
            addr = row_addr + offset
            style = (
                highlight_style
                if highlight_start is not None and highlight_start <= addr < highlight_end
                else None
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
                else None
            )
            if value is None:
                text.append(" ")
            else:
                char = chr(value) if 32 <= value <= 126 else "."
                text.append(char, style=style)
        text.append("|\n")
    return text
