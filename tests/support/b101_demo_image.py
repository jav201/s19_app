"""The shipped 10 MB demo image as a loaded image (batch-101 Inc 13, E1-D7).

``tools/synth/make_release_case.py`` with seed 20260001 and size 10 MB writes
``firmware.s19`` after two steps: ``compute_region_sizes(10)`` and
``build_objects(regions, random.Random(20260001))``. This module runs those
two steps (the bytes are those of the shipped file) and builds the address map
directly, without writing and parsing 10 MB of S19 text. Built once per
process.

Regions of the demo image (guide ch02.2): boot ``0x00000000``+``0x10000``,
app ``0x00040000``+``0x2C9FA0``, cal ``0x00800000``+``0x131FC0``, config
``0x00C00000``+``0x1000``.
"""
from __future__ import annotations

import random
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from s19_app.tui.models import LoadedFile

#: The seed and size of the shipped demo case (examples/case_08_release_demo).
DEMO_SEED = 20260001
DEMO_SIZE_MB = 10

_REPO_ROOT = Path(__file__).resolve().parents[2]

_CACHE: Dict[str, object] = {}


def _release_case_module():
    synth_dir = str(_REPO_ROOT / "tools" / "synth")
    if synth_dir not in sys.path:
        sys.path.insert(0, synth_dir)
    import make_release_case

    return make_release_case


def demo_regions() -> Dict[str, Tuple[int, bytearray]]:
    """``{name: (base, bytes)}`` for boot, app, cal and config (cached)."""
    if "regions" not in _CACHE:
        module = _release_case_module()
        regions = module.compute_region_sizes(DEMO_SIZE_MB)
        module.build_objects(regions, random.Random(DEMO_SEED))
        _CACHE["regions"] = regions
    return _CACHE["regions"]  # type: ignore[return-value]


def demo_mem_map() -> Dict[int, int]:
    """The address-to-byte map of the demo image (cached, never mutated)."""
    if "mem" not in _CACHE:
        mem: Dict[int, int] = {}
        for _name, (base, buf) in demo_regions().items():
            mem.update(enumerate(buf, base))
        _CACHE["mem"] = mem
    return _CACHE["mem"]  # type: ignore[return-value]


def demo_ranges() -> List[Tuple[int, int]]:
    """The four ``(start, end)`` ranges (end exclusive), ascending."""
    return sorted(
        (base, base + len(buf)) for base, buf in demo_regions().values()
    )


def demo_region_bytes(name: str) -> Tuple[int, bytes]:
    """``(base, bytes)`` of one named region."""
    base, buf = demo_regions()[name]
    return base, bytes(buf)


def demo_loaded_file(path: Optional[Path] = None) -> LoadedFile:
    """The demo image wrapped the way the load pipeline wraps an S19."""
    ranges = demo_ranges()
    return LoadedFile(
        path=path or Path("firmware.s19"),
        file_type="s19",
        mem_map=demo_mem_map(),
        row_bases=[],
        ranges=list(ranges),
        range_validity=[True] * len(ranges),
        errors=[],
        a2l_path=None,
        a2l_data=None,
    )
