"""Regression — Memory Map "No file loaded" when an S19/HEX coexists with a MAC.

Root cause (fix-memmap-entropy): the S19+MAC merge constructors dropped the
primary image's derived loader facts ``entropy_windows`` + ``source_s0_header``,
so the empty entropy list made ``MemoryMapPanel.render_ranges`` fall into its
"No file loaded" branch even though an image was loaded. These tests pin:
  AC-1  the two merges carry both fields forward,
  AC-2  a coexisting S19+MAC renders the band view (not "No file loaded"),
  AC-3  an image with ranges but no entropy shows a DISTINCT note, never
        "No file loaded".
Non-frozen test file (touches no engine-frozen module).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from s19_app.tui.app import S19TuiApp
from s19_app.tui.models import LoadedFile
from s19_app.tui.screens_directionb import MemoryMapPanel
from s19_app.tui.services.entropy_service import compute_entropy


def _s19_image(tmp_path: Path, n: int = 600, with_entropy: bool = True) -> LoadedFile:
    """A small non-empty S19 image; entropy windows optional (AC-3 needs none)."""
    mem = {0x1000 + i: (i * 7) & 0xFF for i in range(n)}
    return LoadedFile(
        path=tmp_path / "fw.s19",
        file_type="s19",
        mem_map=mem,
        row_bases=sorted({a - a % 16 for a in mem}),
        ranges=[(0x1000, 0x1000 + n)],
        range_validity=[True],
        errors=[],
        a2l_path=None,
        a2l_data=None,
        entropy_windows=compute_entropy(mem) if with_entropy else [],
        source_s0_header=b"S0HDR",
    )


def _mac_only(tmp_path: Path) -> LoadedFile:
    return LoadedFile(
        path=tmp_path / "tags.mac",
        file_type="mac",
        mem_map={},
        row_bases=[],
        ranges=[],
        range_validity=[],
        errors=[],
        a2l_path=None,
        a2l_data=None,
        mac_path=tmp_path / "tags.mac",
        mac_records=[{"parse_ok": True, "name": "RPM", "address": 0x1000}],
        mac_diagnostics=["ok"],
    )


def test_merge_primary_with_existing_mac_carries_entropy_and_s0(tmp_path: Path) -> None:
    """AC-1: a new primary merged over an existing MAC keeps its entropy_windows
    + source_s0_header (both were previously dropped -> the Memory Map bug)."""
    app = S19TuiApp(base_dir=tmp_path)
    app.current_file = _mac_only(tmp_path)
    primary = _s19_image(tmp_path)
    assert primary.entropy_windows, "sanity: a non-empty image has entropy windows"

    merged = app._merge_primary_with_existing_mac(primary)

    assert merged.mac_path == tmp_path / "tags.mac"           # MAC still overlaid
    assert merged.entropy_windows == primary.entropy_windows  # AC-1 (was [])
    assert merged.source_s0_header == b"S0HDR"                # AC-1 (was None)


def test_merge_mac_with_existing_primary_carries_entropy_and_s0(tmp_path: Path) -> None:
    """AC-1: overlaying a MAC on an existing primary keeps the primary's
    entropy_windows + source_s0_header."""
    app = S19TuiApp(base_dir=tmp_path)
    app.current_file = _s19_image(tmp_path)
    assert app.current_file.entropy_windows

    merged = app._merge_mac_with_existing_primary(_mac_only(tmp_path))

    assert merged.mac_records                                             # MAC attached
    assert merged.entropy_windows == app.current_file.entropy_windows     # AC-1
    assert merged.source_s0_header == b"S0HDR"                            # AC-1


def test_memory_map_renders_when_s19_and_mac_coexist(tmp_path: Path) -> None:
    """AC-2: the merged S19+MAC payload makes the Memory Map render its band
    view, not the "No file loaded" empty note."""

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.current_file = _mac_only(tmp_path)
            app.current_file = app._merge_primary_with_existing_mac(_s19_image(tmp_path))
            app.update_memory_map()
            await pilot.pause()
            return app.query_one("#memory_map_panel", MemoryMapPanel).rendered_text

    text = asyncio.run(_drive())
    assert text != MemoryMapPanel._EMPTY_TEXT       # AC-2: not "No file loaded"
    assert text != MemoryMapPanel._NO_ENTROPY_TEXT  # a real band summary rendered


def test_render_ranges_loaded_no_entropy_not_labelled_no_file(tmp_path: Path) -> None:
    """AC-3: an image with ranges but NO entropy windows shows the distinct
    "no entropy detail" note, never "No file loaded"."""

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.current_file = _s19_image(tmp_path, with_entropy=False)  # ranges, entropy=[]
            app.update_memory_map()
            await pilot.pause()
            return app.query_one("#memory_map_panel", MemoryMapPanel).rendered_text

    text = asyncio.run(_drive())
    assert text == MemoryMapPanel._NO_ENTROPY_TEXT  # AC-3: distinct message
    assert text != MemoryMapPanel._EMPTY_TEXT       # never "No file loaded"
