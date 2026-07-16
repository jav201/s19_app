"""Black-box acceptance tests for the Memory-Map BIG insight layer.

Batch-47 Inc-6 (US-MAP / HLR-072/073/074). Each AT drives the SHIPPED map
screen through ``App.run_test(size=…)`` at BOTH 80x24 and 120x30 and asserts
the observed deliverable in the rendered widget content — structural invariants
only (≥2 band styles, exactly 5 ruler ticks, first-hex-addr == region start,
``range_index`` symbol count), never a hard-coded rendered row/col count (C-29).

Non-frozen home (verified against the 9 frozen test files). Fixtures are the
public ``examples/`` triple + deterministic in-test builders (no client data).
"""
from __future__ import annotations

import asyncio
import random
import re
from pathlib import Path

import pytest

from s19_app.core import S19File
from s19_app.range_index import (
    address_in_sorted_ranges,
    build_sorted_range_index,
)
from s19_app.tui.app import S19TuiApp
from s19_app.tui.changes import emit_s19_from_mem_map
from s19_app.tui.screens_directionb import RegionRow
from s19_app.tui.services.entropy_service import compute_entropy
from s19_app.tui.services.load_service import build_loaded_s19

_SIZES = [(80, 24), (120, 30)]
_BAND_GLYPHS = {"·", "░", "▒", "▓"}
_HATCH = "╱"

_CASE_02 = "examples/case_02_gaps_and_patch_targets/firmware.s19"


def _load_case_02():
    """Load the public gapped fixture (4 ranges, ≥2 bands, aligned starts)."""
    return build_loaded_s19(
        _CASE_02, S19File(_CASE_02), a2l_path=None, a2l_data=None
    )


def _two_region_loaded(tmp_path: Path):
    """A deterministic 2-region image (const + high) with a 16-aligned gap.

    Region A (constant/padding): ``0x80000000..0x80000100`` (0xFF fill, H≈0).
    Region B (high/random): ``0x80010000..0x80010100`` (permutation, H≈8).
    Both 256 bytes; the gap makes two disjoint region rows. Region starts are
    16-aligned, so a hex peek's first row address equals the region start.
    """
    const_base = 0x80000000
    high_base = 0x80010000
    mem_map = {const_base + i: 0xFF for i in range(256)}
    values = list(range(256))
    random.Random(20260714).shuffle(values)
    for i, value in enumerate(values):
        mem_map[high_base + i] = value
    ranges = [(const_base, const_base + 256), (high_base, high_base + 256)]
    bands = {w.band for w in compute_entropy(mem_map)}
    assert {"constant/padding", "high/random"} <= bands, bands
    path = tmp_path / "two_region.s19"
    path.write_text(emit_s19_from_mem_map(mem_map, ranges), encoding="ascii")
    return build_loaded_s19(path, S19File(str(path)), a2l_path=None, a2l_data=None)


async def _prime_map(app: S19TuiApp, pilot, loaded, a2l_tags=None) -> None:
    """Install ``loaded`` (+ optional A2L tags) and render the map screen."""
    await pilot.pause()
    app.current_file = loaded
    if a2l_tags is not None:
        app._a2l_enriched_tags = a2l_tags
    app.action_show_screen("map")
    app.update_memory_map()
    await pilot.pause()


def _strip_text(app: S19TuiApp) -> str:
    return "".join(str(seg.render()) for seg in app.query(".map-band-seg"))


def _ruler_ticks(app: S19TuiApp) -> list:
    return [str(t.render()) for t in app.query(".map-ruler-tick")]


# ---------------------------------------------------------------------------
# AT-072a — bands + hatch gaps (HLR-072 / LLR-072.1)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("size", _SIZES)
def test_at072a_bands(tmp_path: Path, size) -> None:
    """The band strip shows ≥2 distinct band styles AND ≥1 ``╱`` hatch gap.

    Black-box over the shipped ``#map_grid`` band strip for a gapped, multi-band
    image (``case_02``, 4 ranges): the strip's concatenated glyphs contain ≥2 of
    ``{· ░ ▒ ▓}`` (distinct bands) and at least one ``╱`` (an unmapped gap). A
    C-29 structural invariant — asserts the glyph SET, never a cell count.
    """
    loaded = _load_case_02()

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await _prime_map(app, pilot, loaded)
            return _strip_text(app)

    strip = asyncio.run(_drive())
    present_bands = _BAND_GLYPHS & set(strip)
    assert len(present_bands) >= 2, (
        f"{size}: strip must show ≥2 distinct band glyphs; got {present_bands} "
        f"from {strip!r}"
    )
    assert _HATCH in strip, f"{size}: strip must hatch ≥1 gap with ╱; got {strip!r}"


# ---------------------------------------------------------------------------
# AT-072b — address ruler exactly 5 ticks, endpoints == span (LLR-072.3)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("size", _SIZES)
def test_at072b_ruler(tmp_path: Path, size) -> None:
    """The ruler has EXACTLY 5 tick labels; tick 0 % == span start, 100 % == end.

    Black-box over the shipped ``.map-ruler`` beneath the strip: exactly 5
    ``.map-ruler-tick`` labels; the first equals the image span start and the
    last equals the span end (``derive_image_span`` bounds, rendered as 8 hex
    digits). C-29 structural — 5 ticks regardless of panel width.
    """
    loaded = _load_case_02()
    span_start = min(start for start, _end in loaded.ranges)
    span_end = max(end for _start, end in loaded.ranges)

    async def _drive() -> list:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await _prime_map(app, pilot, loaded)
            return _ruler_ticks(app)

    ticks = asyncio.run(_drive())
    assert len(ticks) == 5, f"{size}: ruler must have exactly 5 ticks; got {ticks}"
    assert ticks[0] == f"{span_start:08X}", (
        f"{size}: tick 0% must be span start {span_start:#010x}; got {ticks[0]!r}"
    )
    assert ticks[-1] == f"{span_end:08X}", (
        f"{size}: tick 100% must be span end {span_end:#010x}; got {ticks[-1]!r}"
    )


# ---------------------------------------------------------------------------
# AT-073 — region rows: N sym == range_index count + ↵ affordance (LLR-073)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("size", _SIZES)
def test_at073_sym_count(tmp_path: Path, size) -> None:
    """Each region row's ``N sym`` equals an independent ``range_index`` count,
    and every row carries the ``↵`` open-in-hex affordance.

    Black-box over the shipped ``.map-region-row`` widgets for an S19 + A2L
    pair: two symbols placed in region B (high) and one in region A (constant).
    For each rendered row, the parsed ``N sym`` count must equal the INDEPENDENT
    membership count computed from ``build_sorted_range_index`` /
    ``address_in_sorted_ranges`` over that row's span.
    """
    loaded = _two_region_loaded(tmp_path)
    tags = [
        {"name": "CAL_A", "address": 0x80000010, "byte_size": 4},   # region A
        {"name": "CAL_B1", "address": 0x80010010, "byte_size": 4},  # region B
        {"name": "CAL_B2", "address": 0x80010040, "byte_size": 4},  # region B
        {"name": "OUT", "address": 0x88888888, "byte_size": 4},     # no region
    ]

    async def _drive() -> list:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await _prime_map(app, pilot, loaded, a2l_tags=tags)
            return [
                (row.region_start, row.region_end, str(row.render()))
                for row in app.query(RegionRow)
            ]

    rows = asyncio.run(_drive())
    assert rows, f"{size}: region rows must render"
    for start, end, text in rows:
        match = re.search(r"(\d+) sym", text)
        assert match, f"{size}: row missing 'N sym'; got {text!r}"
        shown = int(match.group(1))
        index = build_sorted_range_index([(start, end)])
        expected = sum(
            1 for t in tags if address_in_sorted_ranges(t["address"], index)
        )
        assert shown == expected, (
            f"{size}: region 0x{start:08X} N sym {shown} != range_index count "
            f"{expected}; row {text!r}"
        )
        assert "↵" in text, f"{size}: row missing ↵ affordance; got {text!r}"


# ---------------------------------------------------------------------------
# AT-074 — inspector hex peek @ NON-first region start + C-17 (MN-4)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("size", _SIZES)
def test_at074_inspector(tmp_path: Path, size) -> None:
    """Activating a NON-first region row renders a hex peek whose first address
    equals that region's start; a bracketed A2L symbol name renders verbatim.

    C-10(a): the operator activates a NON-default (non-first) region row and the
    inspector's hex peek moves to that region's start (content, not "non-empty").
    MN-4 (gate-blocking C-17): a ``sensor[red]`` symbol overlapping the region
    surfaces in ``#map_detail_body`` LITERALLY — no markup parse, no
    ``MarkupError``, no crash.
    """
    loaded = _two_region_loaded(tmp_path)
    hostile = "sensor[red]"
    non_first_start = 0x80010000
    tags = [{"name": hostile, "address": non_first_start + 0x10, "byte_size": 4}]

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app.current_file = loaded
            app._a2l_enriched_tags = tags
            app.action_show_screen("map")
            app.update_memory_map()
            await pilot.pause()
            row = next(
                r for r in app.query(RegionRow) if r.region_start == non_first_start
            )
            # Drive the shipped single-click path (RegionRow.on_click posts
            # RegionRow.Activated, which bubbles to the panel handler). Used in
            # place of pilot.click so the NON-first row is reachable at the
            # 80x24 floor where it renders below the scroll fold.
            row.on_click()
            await pilot.pause()
            await pilot.pause()
            return str(app.query_one("#map_detail_body").render())

    detail = asyncio.run(_drive())
    # Hex peek first row address == the activated region's start.
    assert f"0x{non_first_start:08X}" in detail, (
        f"{size}: inspector peek must start at region 0x{non_first_start:08X}; "
        f"got {detail!r}"
    )
    first_hex_row = next(
        (ln for ln in detail.splitlines() if ln.strip().startswith("0x8001")),
        None,
    )
    assert first_hex_row is not None, (
        f"{size}: a hex peek row for the region must render; got {detail!r}"
    )
    assert first_hex_row.strip().startswith(f"0x{non_first_start:08X}"), (
        f"{size}: first peek row addr must == region start; got {first_hex_row!r}"
    )
    # MN-4 C-17: the bracketed symbol name renders literally (no markup parse).
    assert hostile in detail, (
        f"{size}: hostile symbol name must render verbatim; got {detail!r}"
    )
