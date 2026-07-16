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
from .entropy_service import compute_entropy


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
          ``.type`` / ``.data`` / ``.address`` (``core.py:98``/``core.py:145``/
          ``core.py:125``), read-only — no write to the frozen reader.
        - Derives ``out_of_order_count`` from
          ``S19File.get_out_of_order_records()`` (``core.py:542``) and
          ``entry_point`` from the first S7/S8/S9 terminator record's address
          (batch-47, LLR-066.5).
        - Computes per-window entropy over ``mem_map`` once here (worker
          thread) and caches it on ``LoadedFile.entropy_windows`` for the
          Memory-Map band view (batch-45, R-TUI-060 / LLR-045A.2).
        - Hands the snapshot to ``S19TuiApp._apply_loaded_file``.

    Dependencies:
        Uses:
            - build_mem_map_s19, build_row_bases, build_range_validity_s19,
              compute_entropy, S19File.get_out_of_order_records
        Used by:
            - S19TuiApp._parse_loaded_file
    """
    mem_map = build_mem_map_s19(s19)
    ranges = s19.get_memory_ranges()
    source_s0_header = next(
        (bytes(record.data) for record in s19.records if record.type == "S0"),
        None,
    )
    entry_point = next(
        (record.address for record in s19.records if record.type in {"S7", "S8", "S9"}),
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
        entropy_windows=compute_entropy(mem_map),
        out_of_order_count=len(s19.get_out_of_order_records()),
        entry_point=entry_point,
    )


def build_loaded_hex(
    path: Path,
    hex_file: IntelHexFile,
    a2l_path: Optional[Path],
    a2l_data: Optional[dict],
) -> LoadedFile:
    """
    Build a ``LoadedFile`` snapshot for an Intel HEX image.

    Mirrors ``build_loaded_s19``: caches per-window entropy over ``mem_map``
    on ``LoadedFile.entropy_windows`` for the Memory-Map band view (batch-45,
    R-TUI-060 / LLR-045A.2).

    Intel-HEX has no S-record ordering concept and discards type 03/05
    start-address records (``hexfile.py:135-137``), so ``out_of_order_count``
    is ``0`` and ``entry_point`` is ``None`` for every HEX load (batch-47,
    LLR-066.5).
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
        entropy_windows=compute_entropy(mem_map),
        out_of_order_count=0,  # Intel-HEX has no S-record ordering concept
        entry_point=None,  # HEX discards type 03/05 start-address records (hexfile.py:135-137)
    )
