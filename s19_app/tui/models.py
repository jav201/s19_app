from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass
class LoadedFile:
    path: Path
    file_type: str
    mem_map: Dict[int, int]
    row_bases: List[int]
    ranges: List[Tuple[int, int]]
    range_validity: List[bool]
    errors: List[dict]
    a2l_path: Optional[Path]
    a2l_data: Optional[dict]
