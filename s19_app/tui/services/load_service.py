from __future__ import annotations

from pathlib import Path
from typing import Optional

from ...core import S19File
from ...hexfile import IntelHexFile
from ..hexview import (
    build_mem_map_s19,
    build_range_validity_hex,
    build_range_validity_s19,
    build_row_bases,
)
from ..models import LoadedFile


def build_loaded_s19(
    path: Path,
    s19: S19File,
    a2l_path: Optional[Path],
    a2l_data: Optional[dict],
) -> LoadedFile:
    """
    Summary:
        Build a ``LoadedFile`` snapshot for an S19 image, capturing the
        source S0 header for later re-emission (LLR-015.2).

    Args:
        path (Path): Source file path of the loaded image.
        s19 (S19File): Parsed S19 image (the frozen reader/oracle).
        a2l_path (Optional[Path]): Attached A2L file path, if any.
        a2l_data (Optional[dict]): Parsed A2L payload, if any.

    Returns:
        LoadedFile: The render snapshot, with ``source_s0_header`` set to the
        first ``S0`` record's data bytes when present, else ``None``.

    Data Flow:
        - Reads ``S19File.records`` (``core.py:226``) and each record's
          ``.type`` / ``.data`` (``core.py:98``/``core.py:145``), read-only —
          no write to the frozen reader.
        - Hands the snapshot to ``S19TuiApp._apply_loaded_file``.

    Dependencies:
        Uses:
            - build_mem_map_s19, build_row_bases, build_range_validity_s19
        Used by:
            - S19TuiApp._parse_loaded_file
    """
    mem_map = build_mem_map_s19(s19)
    ranges = s19.get_memory_ranges()
    source_s0_header = next(
        (bytes(record.data) for record in s19.records if record.type == "S0"),
        None,
    )
    return LoadedFile(
        path=path,
        file_type="s19",
        mem_map=mem_map,
        row_bases=build_row_bases(mem_map),
        ranges=ranges,
        range_validity=build_range_validity_s19(s19, ranges),
        errors=s19.get_errors(),
        a2l_path=a2l_path,
        a2l_data=a2l_data,
        mac_path=None,
        mac_records=[],
        mac_diagnostics=[],
        source_s0_header=source_s0_header,
    )


def build_loaded_hex(
    path: Path,
    hex_file: IntelHexFile,
    a2l_path: Optional[Path],
    a2l_data: Optional[dict],
) -> LoadedFile:
    """
    Build a ``LoadedFile`` snapshot for an Intel HEX image.
    """
    mem_map = dict(hex_file.memory)
    ranges = hex_file.get_ranges()
    return LoadedFile(
        path=path,
        file_type="hex",
        mem_map=mem_map,
        row_bases=build_row_bases(mem_map),
        ranges=ranges,
        range_validity=build_range_validity_hex(hex_file, ranges),
        errors=hex_file.get_errors(),
        a2l_path=a2l_path,
        a2l_data=a2l_data,
        mac_path=None,
        mac_records=[],
        mac_diagnostics=[],
    )
