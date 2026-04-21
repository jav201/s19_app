from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class LoadedFile:
    """
    Summary:
        Snapshot of everything the TUI needs to render one loaded data file plus
        optional overlays (MAC records and A2L metadata).

    Args:
        path (Path): Source file path used to identify the load in UI and logs.
        file_type (str): ``"s19"``, ``"hex"``, or ``"mac"`` loader classification.
        mem_map (Dict[int, int]): Address-to-byte map backing hex views.
        row_bases (List[int]): Sorted 16-byte-aligned row anchors for hex rendering.
        ranges (List[Tuple[int, int]]): Contiguous memory ranges ``(start, end)``.
        range_validity (List[bool]): Per-range validity flags aligned with ``ranges``.
        errors (List[dict]): Loader-level error records for display.
        a2l_path (Optional[Path]): Attached A2L file when an A2L was merged in.
        a2l_data (Optional[dict]): Parsed A2L payload when available.
        mac_path (Optional[Path]): Attached ``.mac`` source path.
        mac_records (List[dict]): Parsed MAC records from ``parse_mac_file``.
        mac_diagnostics (List[str]): Human-readable MAC parse diagnostics.

    Data Flow:
        - Produced by ``S19TuiApp._parse_loaded_file``.
        - Consumed by ``_apply_loaded_file`` and by every ``update_*`` renderer that
          reads the snapshot on the main UI thread.
    """

    path: Path
    file_type: str
    mem_map: Dict[int, int]
    row_bases: List[int]
    ranges: List[Tuple[int, int]]
    range_validity: List[bool]
    errors: List[dict]
    a2l_path: Optional[Path]
    a2l_data: Optional[dict]
    mac_path: Optional[Path] = None
    mac_records: List[dict] = field(default_factory=list)
    mac_diagnostics: List[str] = field(default_factory=list)
    range_index: Optional[Any] = field(default=None, repr=False, compare=False)
