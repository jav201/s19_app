from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from s19_app.core import S19File
from s19_app.hexfile import IntelHexFile
from s19_app.tui.a2l import parse_a2l_file
from s19_app.tui.hexview import (
    build_mem_map_s19,
    build_range_validity_hex,
    build_range_validity_s19,
    build_row_bases,
)
from s19_app.tui.mac import parse_mac_file
from s19_app.tui.models import LoadedFile
from s19_app.tui.workspace import HEX_EXTENSIONS, MAC_EXTENSIONS, S19_EXTENSIONS

from .a2l_utils import enrich_tags_with_validation


@dataclass
class WebLoadResult:
    """Outcome of attempting to load data + optional A2L for the web viewer."""

    loaded: Optional[LoadedFile]
    errors: list[str]
    a2l_summary_lines: list[str]
    enriched_tags: list[dict[str, Any]]


def _parse_a2l_optional(path: Optional[Path]) -> tuple[Optional[dict], list[str]]:
    if path is None:
        return None, []
    if not path.exists():
        return None, [f"A2L file not found: {path}"]
    data = parse_a2l_file(path)
    errs = list(data.get("errors") or [])
    return data, [str(e) for e in errs]


def load_data_and_a2l(
    data_path: Path,
    a2l_path: Optional[Path],
) -> WebLoadResult:
    """
    Summary:
        Load S19, Intel HEX, or MAC from disk and attach optional A2L for viewer APIs.

    Args:
        data_path (Path): Path to ``.s19`` / ``.srec`` / ``.hex`` / ``.mac``.
        a2l_path (Optional[Path]): Optional companion ``.a2l`` file.

    Returns:
        WebLoadResult: Loaded file model, parse errors, and A2L presentation lists.

    Raises:
        OSError: Propagated for unreadable paths (caller may catch).

    Data Flow:
        - Dispatch on suffix to S19, HEX, or MAC construction of ``LoadedFile``.
        - Parse optional A2L; merge into loaded model when present.
        - Build enriched tags and summary lines when A2L data exists.

    Dependencies:
        Uses:
            - ``S19File`` / ``IntelHexFile`` / ``parse_mac_file``
            - ``enrich_tags_with_validation``
    """
    errors: list[str] = []
    suffix = data_path.suffix.lower()
    a2l_data, a2l_errs = _parse_a2l_optional(a2l_path)
    errors.extend(a2l_errs)

    loaded: Optional[LoadedFile] = None
    if suffix in S19_EXTENSIONS:
        s19 = S19File(str(data_path))
        mem_map = build_mem_map_s19(s19)
        row_bases = build_row_bases(mem_map)
        ranges = s19._get_memory_ranges()
        range_validity = build_range_validity_s19(s19, ranges)
        file_errors = s19.get_errors()
        for e in file_errors:
            if isinstance(e, dict):
                errors.append(str(e.get("error", e)))
            else:
                errors.append(str(e))
        loaded = LoadedFile(
            path=data_path,
            file_type="s19",
            mem_map=mem_map,
            row_bases=row_bases,
            ranges=ranges,
            range_validity=range_validity,
            errors=file_errors,
            a2l_path=a2l_path,
            a2l_data=a2l_data,
        )
    elif suffix in HEX_EXTENSIONS:
        hex_file = IntelHexFile(str(data_path))
        mem_map = dict(hex_file.memory)
        row_bases = build_row_bases(mem_map)
        ranges = hex_file.get_ranges()
        range_validity = build_range_validity_hex(hex_file, ranges)
        file_errors = hex_file.get_errors()
        for e in file_errors:
            if isinstance(e, dict):
                errors.append(str(e.get("error", e)))
            else:
                errors.append(str(e))
        loaded = LoadedFile(
            path=data_path,
            file_type="hex",
            mem_map=mem_map,
            row_bases=row_bases,
            ranges=ranges,
            range_validity=range_validity,
            errors=file_errors,
            a2l_path=a2l_path,
            a2l_data=a2l_data,
        )
    elif suffix in MAC_EXTENSIONS:
        mac_data = parse_mac_file(data_path)
        records = mac_data.get("records", [])
        diagnostics = [str(item) for item in mac_data.get("diagnostics", [])]
        valid_addresses = sorted(
            {
                int(item["address"])
                for item in records
                if item.get("parse_ok") and isinstance(item.get("address"), int)
            }
        )
        mem_map = {addr: 0 for addr in valid_addresses}
        row_bases = build_row_bases(mem_map)
        errors.extend(diagnostics)
        loaded = LoadedFile(
            path=data_path,
            file_type="mac",
            mem_map=mem_map,
            row_bases=row_bases,
            ranges=[],
            range_validity=[],
            errors=[{"line": None, "message": entry} for entry in diagnostics],
            a2l_path=a2l_path,
            a2l_data=a2l_data,
            mac_records=records,
            mac_diagnostics=diagnostics,
        )
    else:
        errors.append(f"Unsupported file type: {suffix}")
        return WebLoadResult(None, errors, [], [])

    summary_lines: list[str] = []
    enriched: list[dict[str, Any]] = []
    if a2l_data and not (a2l_data.get("errors") or []):
        mem_for_val = loaded.mem_map if loaded.file_type in {"s19", "hex"} else None
        enriched, summary_lines = enrich_tags_with_validation(a2l_data, mem_for_val)
    elif a2l_data:
        summary_lines = [f"A2L error: {e}" for e in (a2l_data.get("errors") or [])]

    return WebLoadResult(loaded=loaded, errors=errors, a2l_summary_lines=summary_lines, enriched_tags=enriched)
