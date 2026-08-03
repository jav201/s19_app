"""Black-box acceptance tests for the Memory-Map BIG insight layer.

Batch-47 Inc-6 (US-MAP / HLR-072/073/074). Each AT drives the SHIPPED map
screen through ``App.run_test(size=…)`` at BOTH 80x24 and 120x30 and asserts
the observed deliverable in the rendered widget content — structural invariants
only (≥2 band styles, one ruler tick per run start plus the last mapped byte,
first-hex-addr == region start, ``range_index`` symbol count), never a
hard-coded rendered row/col count (C-29).

Non-frozen home (verified against the 9 frozen test files). Fixtures are the
public ``examples/`` triple + deterministic in-test builders (no client data).
"""
from __future__ import annotations

import asyncio
import random
import re
from pathlib import Path

import pytest
from textual.events import Key

from s19_app.core import S19File
from s19_app.range_index import (
    address_in_sorted_ranges,
    build_sorted_range_index,
)
from s19_app.tui.app import S19TuiApp
from s19_app.tui.changes import emit_s19_from_mem_map
from s19_app.tui.entropy_style import band_style
from s19_app.tui.screens_directionb import (
    BandSegment,
    MapRuler,
    MemoryMapPanel,
    RegionRow,
    _allocate_band_widths,
    _merge_band_runs,
    _retained_tick_addresses,
)
from s19_app.tui.services.entropy_service import compute_entropy
from s19_app.tui.services.load_service import build_loaded_s19

_SIZES = [(80, 24), (120, 30)]
_BAND_GLYPHS = {"·", "░", "▒", "▓"}
_HATCH = "╱"

_CASE_02 = "examples/case_02_gaps_and_patch_targets/firmware.s19"
_PRG = "examples/case_00_public/prg.s19"
_CASE_08 = (
    "examples/professional_validation/case_08_heavy_fragmentation/firmware.s19"
)


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


def _ruler_tick_widths(app: S19TuiApp) -> list:
    """Each tick's RENDERED width, in ruler order (LLR-112.2).

    Never an overlap predicate: ``width: 1fr`` children partition the row and
    CANNOT overlap — an over-full ruler degrades to zero-width ticks instead.
    Executed at Phase 1: 60 ticks in a 50-column row gives 10 zero-width ticks
    and 0 overlaps, and an overlap-based conjunction reads GREEN with 10
    invisible labels. Width-vs-label-length is the predicate that can fail.
    """
    return [t.region.width for t in app.query(".map-ruler-tick")]


def _admissible_tick_labels(loaded) -> set:
    """``{run starts} ∪ {last mapped byte}`` as 8-hex labels (HLR-112).

    The end label is ``span_end - 1``: ``span_end`` is EXCLUSIVE and is by
    construction the first byte past the image — executed on ``case_02``,
    ``address_in_sorted_ranges(span_end, index)`` is False while
    ``span_end - 1`` is True.

    ⚠️ NOT an independent oracle, and must not be called one (§2.9 note 2).
    This calls the SAME ``_merge_band_runs`` the producer calls, so it cannot
    detect a defect inside that function — a wrong merge yields a wrong
    ``expected`` and a wrong ``emitted`` that agree. What it DOES detect is a
    ruler whose labels disagree with the runs the bar was apportioned from,
    which is the defect this increment introduces the risk of.
    ``_merge_band_runs`` is unchanged by batch-77 (no increment lists it), so
    its correctness is inherited from batch-47 and is not what is being gated
    here.
    """
    span_end = max(end for _start, end in loaded.ranges)
    starts = {start for _band, _run_bytes, start in _merge_band_runs(
        loaded.entropy_windows
    )}
    return {f"{start:08X}" for start in starts} | {f"{span_end - 1:08X}"}


# ---------------------------------------------------------------------------
# batch-77 shared geometry oracles (LLR-111.6, §1.3 ``visible_cols``)
# ---------------------------------------------------------------------------
def _load_example(rel_path: str):
    """Load a shipped ``examples/`` image through the real load pipeline."""
    return build_loaded_s19(rel_path, S19File(rel_path), a2l_path=None, a2l_data=None)


async def _settled_bar_width(app: S19TuiApp, pilot, max_pauses: int = 40) -> int:
    """Return ``.map-band-bar``'s width once layout has SETTLED (LLR-111.6).

    Summary:
        Re-read the container width after successive ``pilot.pause()``
        boundaries until two successive POST-PAUSE reads agree. Textual's first
        read after a render is a transient in a measurable minority of runs
        (17 of 97 traces at Phase 1, e.g. 23 where the settled value is 21), and
        it is never transient twice in succession — so a post-pause fixed point
        is a sound settling criterion where a single pause is not.

    Args:
        app (S19TuiApp): The live application.
        pilot: The ``run_test`` pilot whose ``pause()`` bounds each frame.
        max_pauses (int): Safety bound; exceeding it is a hard failure rather
            than a silently unsettled read.

    Returns:
        int: The settled ``.map-band-bar`` region width.

    Data Flow:
        - Called by every batch-77 geometry acceptance before it reads a region.

    Dependencies:
        Used by:
            - ``AT-B77-01``, ``AT-B77-03``, ``AT-B77-18``
    """
    previous = None
    for _ in range(max_pauses):
        # One read per pause boundary. Repeated reads WITHIN a frame are not
        # evidence of settling (P-45) — that is the retracted trace.
        await pilot.pause()
        width = app.query_one(".map-band-bar").region.width
        if previous is not None and width == previous:
            return width
        previous = width
    raise AssertionError(
        f"band bar width never settled across {max_pauses} pause boundaries; "
        f"last read {previous}"
    )


def _visible_cols(seg, bar) -> int:
    """Painted, container-clipped width of ``seg`` (§1.3).

    Never ``len(str(seg.render()))`` — that is a pre-layout content proxy which
    reports full width for a segment painted entirely outside the bar (C-32).
    """
    return max(
        0,
        min(seg.region.right, bar.region.right) - max(seg.region.x, bar.region.x),
    )


def _run_pairs(app: S19TuiApp):
    """``[(mapped_bytes, visible_cols)]`` per emitted run segment, in bar order."""
    bar = app.query_one(".map-band-bar")
    return [
        (seg.region_end - seg.region_start, _visible_cols(seg, bar))
        for seg in app.query(BandSegment)
    ]


def _limb_verdicts(pairs):
    """The three HLR-111 limbs, reported INDIVIDUALLY (CC-1).

    ``monotone`` is ∀ over ordered pairs of run segments whose mapped sizes
    DIFFER (largest-remainder legitimately gives equal-byte runs unequal
    widths, so equal-byte pairs are not in the quantifier). ``strict`` is ∃ —
    at least one strictly greater pair — and is ``None``, i.e. explicitly
    skipped rather than silently passed, when no two runs differ in size.
    """
    visible = all(cols >= 1 for _bytes, cols in pairs)
    differing = any(bi < bj for bi, _ in pairs for bj, _ in pairs)
    monotone = all(
        vi <= vj for bi, vi in pairs for bj, vj in pairs if bi < bj
    )
    strict = any(vi < vj for bi, vi in pairs for bj, vj in pairs if bi < bj)
    return {
        "visible>=1": visible,
        "monotone": monotone,
        "strict": strict if differing else None,
    }


def _b77_fixtures():
    """(label, loader) pairs for the batch-77 geometry acceptances.

    ``two_region`` is byte-identical to ``test_tui_directionb._two_band_loaded``
    (same bases, same seed) — deliberately, because it is the fixture the
    retired ``test_ac6_clipped_segments_are_a_known_layout_limitation`` measured
    ``outside_count`` on. ``AT-B77-03`` measures the same predicate on the same
    fixture, INVERTED (Amendment C).
    """
    return [
        ("prg", lambda tmp: _load_example(_PRG)),
        ("case_02", lambda tmp: _load_case_02()),
        ("two_region", _two_region_loaded),
    ]


# ``two_region`` is excluded from AT-B77-01 because its two runs are BOTH
# exactly 256 bytes (executed: ``run_bytes == [256, 256]``, ``differing`` False).
# ``_limb_verdicts`` then reports ``strict`` as None, and AT-B77-01's conjunction
# admits None — so the fixture would pass the strict limb WITHOUT EVALUATING IT,
# diluting the one acceptance that exists to gate discrimination. It is kept in
# ``_b77_fixtures`` for AT-B77-03, whose containment predicate does not care
# about relative sizes and which needs this exact fixture for Amendment C.
_AT01_FIXTURES = [f for f in _b77_fixtures() if f[0] != "two_region"]


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
# AT-072b — every ruler label names a mapped address, legibly (HLR-112)
#
# FIXTURE PIN — NORMATIVE. This node MUST use ``case_02`` (4 runs -> 5 ticks)
# and MUST NOT use ``prg.s19``. The "no elided tick" clause below is IN-DOMAIN
# ONLY, and HLR-112's domain is ``n_ticks <= (ruler_width + 1) // 9`` = 7 ticks
# @80x24 and 5 @120x30 (executed: ruler width 66 / 50). ``prg.s19`` needs 15
# ticks and is out of domain at BOTH regimes, so pinning it here would redden
# this node ON CORRECT CODE. It is the obvious fixture to reach for — it is the
# batch's showcase everywhere else — and it is exactly wrong here.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("size", _SIZES)
def test_at072b_ruler(tmp_path: Path, size) -> None:
    """Ruler labels ⊆ run starts ∪ last mapped byte, ascending, distinct, legible.

    Black-box over the shipped ``.map-ruler``: every ``.map-ruler-tick`` label
    names an address that lies in some mapped range AND is either an emitted run
    start or the last mapped byte; the labels strictly ascend with no duplicate;
    and — the fixture being in domain at both regimes — nothing is elided and no
    tick renders narrower than the 8-digit label it carries.

    Pre-change this node asserted the retired 5-tick percentile contract, under
    which 4 of the 5 labels named addresses in NO mapped range at either regime
    (executed: ``20004050``/``400080A0``/``6000C0F0``/``80010140``), the last of
    them being the EXCLUSIVE ``span_end``.
    """
    loaded = _load_case_02()
    admissible = _admissible_tick_labels(loaded)
    index = build_sorted_range_index(loaded.ranges)

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await _prime_map(app, pilot, loaded)
            await _settled_bar_width(app, pilot)
            return _ruler_ticks(app), _ruler_tick_widths(app)

    ticks, widths = asyncio.run(_drive())
    addrs = [int(label, 16) for label in ticks]

    # Argument order is ``(addr, index)`` — a Phase-1 probe had it inverted and
    # was caught only by a TypeError (s19_app/range_index.py:39).
    outside = [t for t in ticks if not address_in_sorted_ranges(int(t, 16), index)]
    assert not outside, f"{size}: ruler labels naming no mapped address: {outside}"
    assert set(ticks) <= admissible, (
        f"{size}: labels outside the admissible set "
        f"{sorted(set(ticks) - admissible)}; ticks={ticks}"
    )
    assert addrs == sorted(set(addrs)), (
        f"{size}: labels must strictly ascend with no duplicate; got {ticks}"
    )
    # In domain (5 ticks vs a ceiling of 7 @80x24 and 5 @120x30): nothing elided.
    assert len(ticks) == len(admissible), (
        f"{size}: in-domain ruler elided a tick — expected {len(admissible)}, "
        f"got {len(ticks)}: {ticks}"
    )
    illegible = [
        (label, width)
        for label, width in zip(ticks, widths)
        if width < len(label)
    ]
    assert not illegible, (
        f"{size}: ticks rendered narrower than their label: {illegible}"
    )


# ---------------------------------------------------------------------------
# AT-B77-04 — the ⊇ lower bound (HLR-112)
#
# NOT OPTIONAL: executed, ``set() <= admissible`` is True, so AT-072b's
# subset-only predicate is GREEN on a ruler that rendered ZERO ticks. This node
# is the only thing standing between that and a green suite.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("size", _SIZES)
def test_b77_ruler_labels_every_run_start_and_the_last_byte(
    tmp_path: Path, size
) -> None:
    """In domain the ruler emits a label for EVERY run start and the last byte."""
    loaded = _load_case_02()
    admissible = _admissible_tick_labels(loaded)

    async def _drive() -> list:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await _prime_map(app, pilot, loaded)
            await _settled_bar_width(app, pilot)
            return _ruler_ticks(app)

    ticks = asyncio.run(_drive())
    assert admissible <= set(ticks), (
        f"{size}: ruler dropped in-domain labels "
        f"{sorted(admissible - set(ticks))}; ticks={ticks}"
    )


# ---------------------------------------------------------------------------
# TC-B77-06 — empty image: no ruler, no raise (HLR-112 boundary)
# ---------------------------------------------------------------------------
def test_tc_b77_06_b77_ruler_empty_image_emits_no_tick(tmp_path: Path) -> None:
    """With no file loaded the map renders and mounts no ruler tick."""

    async def _drive() -> list:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            app.action_show_screen("map")
            app.update_memory_map()
            await pilot.pause()
            return _ruler_ticks(app)

    assert asyncio.run(_drive()) == []


# ---------------------------------------------------------------------------
# TC-B77-07 — one run: start and last mapped byte, both labelled
# ---------------------------------------------------------------------------
def test_tc_b77_07_b77_ruler_single_run_labels_start_and_last_byte() -> None:
    """A single run yields two ticks; a single BYTE collapses them to one.

    Pure over the tick-address derivation: the start and the last mapped byte
    are the same address for a 1-byte image, and a duplicate label would break
    HLR-112's strictly-ascending, non-duplicate invariant.
    """
    assert MapRuler([0x8000], 0x80FF)._tick_addrs == [0x8000, 0x80FF]
    assert MapRuler([0x8000], 0x8000)._tick_addrs == [0x8000]


# ---------------------------------------------------------------------------
# TC-B77-08 — more run starts than ruler columns: elide, keep first and last
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("size", _SIZES)
def test_tc_b77_08_b77_ruler_out_of_domain_elides_legibly(
    tmp_path: Path, size
) -> None:
    """``prg.s19`` (15 ticks) renders without raising, first and last retained.

    OUT OF DOMAIN at both regimes — 15 ticks against a ceiling of 7 @80x24 and
    5 @120x30. HLR-112 contracts three things here and no more: the first and
    last labels survive, interior labels are DROPPED rather than emitted
    illegibly, and nothing raises. Which interior labels survive is NOT
    contracted, so this node does not assert them.
    """
    loaded = _load_example(_PRG)
    admissible = _admissible_tick_labels(loaded)
    index = build_sorted_range_index(loaded.ranges)
    first = min(admissible)
    last = max(admissible)

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await _prime_map(app, pilot, loaded)
            bar_width = await _settled_bar_width(app, pilot)
            ruler_width = app.query_one(".map-ruler").region.width
            return _ruler_ticks(app), _ruler_tick_widths(app), bar_width, ruler_width

    ticks, widths, bar_width, ruler_width = asyncio.run(_drive())
    ceiling = (ruler_width + 1) // 9
    assert len(admissible) > ceiling, (
        f"{size}: fixture is no longer out of domain — {len(admissible)} ticks "
        f"vs ceiling {ceiling} at ruler width {ruler_width}. This node asserts "
        f"ELISION and would pass vacuously."
    )
    assert ticks[0] == first, f"{size}: first label dropped; got {ticks}"
    assert ticks[-1] == last, f"{size}: last label dropped; got {ticks}"
    assert len(ticks) <= ceiling, (
        f"{size}: {len(ticks)} ticks emitted into a {ruler_width}-column ruler "
        f"(ceiling {ceiling}, bar {bar_width}); got {ticks}"
    )
    illegible = [
        (label, width)
        for label, width in zip(ticks, widths)
        if width < len(label)
    ]
    assert not illegible, (
        f"{size}: elision left ticks narrower than their label: {illegible}"
    )
    outside = [t for t in ticks if not address_in_sorted_ranges(int(t, 16), index)]
    assert not outside, f"{size}: retained labels naming no mapped address: {outside}"
    assert set(ticks) <= admissible, (
        f"{size}: elision invented a label: {sorted(set(ticks) - admissible)}"
    )


# ---------------------------------------------------------------------------
# TC-B77-09 — a ruler too narrow for even two labels still keeps both bounds
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("width", [0, 1, 8, 17])
def test_tc_b77_09_b77_ruler_floor_of_two_retains_both_bounds(width) -> None:
    """Below a ceiling of 2 the retained set is exactly the first and last.

    A ruler that renders nothing tells the operator less than one that renders
    two illegibly-narrow bounds, and HLR-112's out-of-domain clause contracts
    the bounds labels, not their legibility.
    """
    addrs = [0x100, 0x200, 0x300, 0x400]
    assert _retained_tick_addresses(addrs, width) == [0x100, 0x400]


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
            # Drive the shipped single-click path by posting the message
            # RegionRow.on_click would post (chain=1), which bubbles to the
            # panel handler. Used in place of pilot.click so the NON-first row
            # is reachable at the 80x24 floor where it renders below the scroll
            # fold. batch-67 N4a: chain=1 inspects WITHOUT navigating, which is
            # exactly what this test asserts — it reads #map_detail_body.
            row.post_message(
                RegionRow.Activated(row.region_start, row.region_end, chain=1)
            )
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


# ---------------------------------------------------------------------------
# AT-B77-01 — visible ∧ monotone∀ ∧ strict∃, IN DOMAIN (HLR-111 / LLR-111.1/.7)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("size", _SIZES)
@pytest.mark.parametrize("label,loader", _AT01_FIXTURES)
def test_b77_width_visible_monotone_strict(tmp_path: Path, label, loader, size) -> None:
    """Every emitted run paints ≥1 column, non-decreasing in mapped bytes.

    ONE three-way conjunction — ``visible ≥ 1`` ∧ ``monotone`` ∀ ∧ ``strict`` ∃
    — deliberately NOT split into three nodes. Pre-change the two regimes redden
    on DIFFERENT limbs, and at the wide regime the ``strict`` limb reads True
    only because clipped runs collapse to 0 columns and ``1 > 0``. Split apart,
    that spuriously-green arm would stand alone as a passing test.

    Geometry is read at SETTLED layout (LLR-111.6) and clipped against the
    container (§1.3 ``visible_cols``), so a segment painted outside the bar
    counts as 0 columns rather than as its content length.
    """
    loaded = loader(tmp_path)

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await _prime_map(app, pilot, loaded)
            bar_width = await _settled_bar_width(app, pilot)
            bar = app.query_one(".map-band-bar")
            pairs = _run_pairs(app)
            gaps = [_visible_cols(g, bar) for g in app.query(".map-band-gap")]
            emitted = {
                (s.region_start, s.region_end) for s in app.query(BandSegment)
            }
            return bar_width, pairs, gaps, emitted

    bar_width, pairs, gaps, emitted = asyncio.run(_drive())

    # Completeness guard (C-31, §2.9): an INDEPENDENT runs oracle — the pure
    # ``_merge_band_runs`` over the loader's windows — plus a coverage clause
    # over the RANGES, which are a different population from the runs.
    expected = _merge_band_runs(loaded.entropy_windows)
    assert emitted == {(start, start + n) for _band, n, start in expected}, (
        f"{label} @{size}: emitted run windows {sorted(emitted)} != oracle "
        f"{sorted((s, s + n) for _b, n, s in expected)}"
    )
    assert all(
        any(a <= rs < b for a, b in emitted) for rs, _ in loaded.ranges
    ), f"{label} @{size}: some range start is covered by no emitted run"

    verdicts = _limb_verdicts(pairs)
    context = (
        f"{label} @{size}: bar={bar_width} n_runs={len(pairs)} "
        f"n_gaps={len(gaps)} in_domain={len(pairs) + len(gaps) <= bar_width} "
        f"per-limb={verdicts} (bytes,visible)={pairs} gap_visible={gaps}"
    )

    # DOMAIN FIRST. The requirement is domain-scoped: out of domain the clauses
    # below are unsatisfiable rather than false, so a fixture that has drifted
    # out must say SO, not redden as a product defect. This has to precede the
    # conjunction — below it, the conjunction fails first and this message never
    # prints, which is the diagnosis the reader actually needs.
    assert len(pairs) + len(gaps) <= bar_width, (
        f"FIXTURE OUT OF DOMAIN — {context}"
    )

    assert verdicts["visible>=1"] and verdicts["monotone"] and (
        verdicts["strict"] is not False
    ), context


# ---------------------------------------------------------------------------
# AT-B77-03 — nothing paints outside the container, IN DOMAIN (LLR-111.3/.2)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("size", _SIZES)
@pytest.mark.parametrize("label,loader", _b77_fixtures())
def test_b77_contain_no_segment_outside_the_bar(
    tmp_path: Path, label, loader, size
) -> None:
    """Every ``.map-band-seg`` is contained in ``.map-band-bar``; gaps are 1 col.

    This is the INVERSE of the retired
    ``test_ac6_clipped_segments_are_a_known_layout_limitation``, which asserted
    ``outside_count > 0`` on the ``two_region`` fixture at 120x30. The same
    predicate on the same fixture is measured here, now expected to be 0
    (Amendment C).

    The gap co-assertion is HLR-111's ``gap markers all == 1`` threshold
    (LLR-111.2): a gap renders at exactly one column independent of its byte
    size and of the container width.
    """
    loaded = loader(tmp_path)

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await _prime_map(app, pilot, loaded)
            bar_width = await _settled_bar_width(app, pilot)
            bar = app.query_one(".map-band-bar")
            segs = list(app.query(".map-band-seg"))
            outside = [s for s in segs if not bar.region.contains_region(s.region)]
            gaps = [_visible_cols(g, bar) for g in app.query(".map-band-gap")]
            n_runs = len(list(app.query(BandSegment)))
            return bar_width, len(segs), len(outside), gaps, n_runs

    bar_width, n_segs, outside, gaps, n_runs = asyncio.run(_drive())

    assert n_segs > 0, f"{label} @{size}: the fixture must render band segments"

    # DOMAIN FIRST — same reason as AT-B77-01: LLR-111.3 is scoped to the
    # domain, so out of domain the containment assertion below is unsatisfiable
    # rather than false. Asserted after it, this message could never print: the
    # containment assertion would fail first and report an overflow where the
    # real finding is that the fixture left the domain.
    assert n_runs + len(gaps) <= bar_width, (
        f"FIXTURE OUT OF DOMAIN — {label} @{size}: n_runs={n_runs} "
        f"n_gaps={len(gaps)} bar={bar_width}"
    )

    assert outside == 0, (
        f"{label} @{size}: {outside} of {n_segs} .map-band-seg widgets paint "
        f"outside the {bar_width}-column bar"
    )
    assert all(g == 1 for g in gaps), (
        f"{label} @{size}: every gap marker must fold to exactly 1 column; "
        f"got {gaps} (bar={bar_width})"
    )


# ---------------------------------------------------------------------------
# AT-B77-18 — OUT OF DOMAIN: no raise, region list complete (HLR-111 domain)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("size", _SIZES)
def test_b77_domain_out_of_domain_renders_and_lists_every_run(
    tmp_path: Path, size
) -> None:
    """``case_08`` (801 runs) renders without raising and lists every run.

    The only shipped fixture past the bound's domain: 801 runs + 800 gaps far
    exceeds any container width, so the bound is arithmetically unsatisfiable
    (``avail`` is negative). HLR-111 contracts exactly two things out of domain —
    the panel does not raise, and every run stays reachable in the region list.

    It asserts NEITHER the widths NOR the invisible-run counts. The degradation
    rule is deliberately unspecified, so those figures are observations of one
    conforming implementation, not a contract; pinning them here would freeze an
    arbitrary choice that batch-78 owns.
    """
    loaded = _load_example(_CASE_08)
    expected_runs = len(_merge_band_runs(loaded.entropy_windows))

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await _prime_map(app, pilot, loaded)
            await _settled_bar_width(app, pilot)
            return len(list(app.query(RegionRow))), len(list(app.query(BandSegment)))

    n_rows, _n_segs = asyncio.run(_drive())

    assert expected_runs > 100, (
        f"fixture must be genuinely out of domain; oracle gave {expected_runs} runs"
    )
    assert n_rows == expected_runs, (
        f"@{size}: the region list must carry one row per oracle run; "
        f"got {n_rows} rows for {expected_runs} runs"
    )
    # DELIBERATELY NOT ASSERTED: ``n_segs == expected_runs``.
    #
    # That is a claim about the DEGRADATION RULE, and HLR-111 does not have one
    # out of domain. §3 says so in as many words: a ``first-N-only`` degradation
    # "would give different counts and still satisfy this requirement". Pinning
    # the segment count here would freeze one arbitrary conforming choice as if
    # it were the contract, and batch-78 — which is chartered to SPECIFY the
    # degradation rule (carry C-77-l) — would have to delete a green test to do
    # its job. The two assertions above ARE the contract: no raise, and every
    # run reachable in the region list.
    #
    # Do not re-pin this. If a future batch wants a segment-count guarantee out
    # of domain, it must first put one in the requirement.
    #
    # ``_n_segs`` is bound and left unasserted on purpose — a placeholder
    # assertion like ``>= 0`` cannot fail and would be the vacuous check this
    # batch keeps finding.


# ---------------------------------------------------------------------------
# TC-B77-01..05, TC-B77-30 — boundary catalog for the allocation (LLR-111.7)
# ---------------------------------------------------------------------------
def test_tc_b77_01_b77_bound_empty_image_emits_no_segment(tmp_path: Path) -> None:
    """TC-B77-01 (empty): no ranges -> zero segments, no raise."""
    assert _allocate_band_widths([], 0, 66) == []

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            app.action_show_screen("map")
            app.update_memory_map()
            await pilot.pause()
            return len(list(app.query(".map-band-seg")))

    assert asyncio.run(_drive()) == 0


def test_tc_b77_02_b77_bound_single_run_takes_the_whole_bar() -> None:
    """TC-B77-02 (one run): it gets every column, and ``strict`` is SKIPPED.

    With one run there is no ordered pair of differing sizes, so the exists-
    strictness limb has no subject. ``_limb_verdicts`` reports ``None`` for it
    rather than ``True`` — a limb that cannot be evaluated must not be counted
    as passed.
    """
    assert _allocate_band_widths([512], 0, 66) == [66]
    assert _allocate_band_widths([512], 1, 66) == [65]
    assert _limb_verdicts([(512, 66)])["strict"] is None


@pytest.mark.parametrize("bar_width", [50, 66])
def test_tc_b77_03_b77_bound_domain_edge_degrades_without_raising(
    bar_width,
) -> None:
    """TC-B77-03 (the domain edge): swept across ``n_runs + n_gaps > bar_width``.

    In domain the widths sum EXACTLY to the container. Past the edge the bound is
    unsatisfiable, and the only claims are that a width is returned for every run
    and nothing raises — the bar is NOT claimed correct there.

    ⚠️ **This sweep's fixture is ``[256] * n_runs`` — every run the SAME size.**
    ``_limb_verdicts`` reports ``strict`` as ``None`` (skipped) when no two runs
    differ, so across this entire sweep the strict limb has NO SUBJECT. That is
    why a test labelled "the domain edge" never evaluated the strictness clause,
    and why ``HLR-111`` shipped five revisions promising a discrimination that is
    unsatisfiable at some in-domain geometries. This is the batch's registered
    VACUOUS-FIXTURE defect class (batch-74): the sweep is over the right axis and
    the fixture is inert on the limb that mattered.

    ``test_tc_b77_03_..._differing_sizes`` below is the arm that fixes it.
    """
    onset = next(n for n in range(1, 400) if n + (n - 1) > bar_width)
    assert onset == (26 if bar_width == 50 else 34)

    for n_runs in range(1, onset + 6):
        n_gaps = n_runs - 1
        widths = _allocate_band_widths([256] * n_runs, n_gaps, bar_width)
        assert len(widths) == n_runs
        assert all(w >= 1 for w in widths)
        if n_runs + n_gaps <= bar_width:
            assert sum(widths) + n_gaps == bar_width, (
                f"in domain at n_runs={n_runs}, bar={bar_width}: widths must "
                f"fill the container exactly; got {sum(widths)} + {n_gaps}"
            )
        else:
            assert sum(widths) + n_gaps > bar_width, (
                "past the onset the emission necessarily exceeds the container "
                "— if it fit, the fixture was still in domain"
            )


@pytest.mark.parametrize("bar_width", [50, 66])
def test_tc_b77_03_b77_bound_domain_edge_differing_sizes_ties_widths(
    bar_width,
) -> None:
    """TC-B77-03 (differing arm): at the last in-domain point, strictness DIES.

    The sibling sweep above uses ``[256] * n_runs`` — all runs equal — so its
    ``differing`` flag is False and the strict limb is skipped at every point it
    visits. This arm supplies runs that DO differ in mapped size, which is the
    only configuration under which HLR-111's strictness clause has a subject.

    What it pins is the TRUTHFUL degenerate behaviour, not a repaired one: at the
    containment boundary the container holds exactly one column per run and per
    gap, ``surplus == 0``, and every run gets width 1 no matter how far apart
    their byte counts are. ``strict`` is therefore False on runs spanning 24
    doublings. **No allocator can do better** — a size difference smaller than
    one column's worth of bytes is not representable in integer columns — which
    is why Amendment D gives the strictness clause the precondition
    ``surplus * (max_bytes - min_bytes) > total_bytes`` rather than changing
    ``_allocate_band_widths``.

    ⚠️ **The boundary is reached with a LEADING gap (``n_gaps == n_runs``), not
    with ``n_gaps == n_runs - 1``.** With one gap between runs the sweep's own
    geometry gives ``n_runs + n_gaps == 2n - 1``, which for an even ``bar_width``
    is odd and so lands one column SHORT of the boundary: ``surplus == 1``, the
    largest run takes the spare column, and strictness HOLDS (executed: widths
    ``{1, 2}`` at both regimes). Only ``n_gaps == n_runs`` — which the producer
    explicitly supports, since a gap is emitted wherever a run starts above the
    cursor and a LEADING one is possible (``_build_band_widgets``) — reaches
    ``surplus == 0``. Stated because the first draft of this arm asserted
    ``surplus == 0`` on the ``n - 1`` geometry and would have failed.

    Registered VACUOUS-FIXTURE defect (batch-74 class): an all-equal fixture on a
    sweep whose label promises the domain edge hid an unsatisfiable requirement
    through five requirement revisions and an entire implementation increment.
    """
    n_runs = bar_width // 2
    n_gaps = n_runs  # leading gap -- the only way to sit exactly ON the boundary

    # Byte counts spanning 24 doublings: if ANY byte spread could discriminate,
    # this one would.
    run_bytes = [2**i for i in range(n_runs)]

    assert n_runs + n_gaps == bar_width, (
        f"arm must sit exactly ON the containment boundary; got "
        f"{n_runs} + {n_gaps} vs bar={bar_width}"
    )

    widths = _allocate_band_widths(run_bytes, n_gaps, bar_width)
    surplus = bar_width - n_gaps - n_runs
    assert surplus == 0, (
        f"the containment boundary must leave no surplus; got {surplus}"
    )

    verdicts = _limb_verdicts(list(zip(run_bytes, widths)))

    # The limb HAS a subject here -- that is the whole point of this arm.
    # ``strict`` is None exactly when no two runs differ, so this assertion is
    # what makes the arm non-vacuous, and it is the assertion the sibling sweep
    # would fail.
    assert verdicts["strict"] is not None, (
        "regression: this fixture must have runs of differing size, or the arm "
        "is as vacuous as the one it exists to complement"
    )
    # ...and it is False, truthfully.
    assert verdicts["strict"] is False, (
        f"at surplus=0 every run must tie at 1 column; got widths={widths}"
    )
    assert widths == [1] * n_runs, (
        f"bar={bar_width}: on the containment boundary every run takes exactly "
        f"one column; got {widths}"
    )
    assert verdicts["visible>=1"], "the floor still holds at the domain edge"
    assert verdicts["monotone"], "monotone-forall is not narrowed by Amendment D"
    assert sum(widths) + n_gaps == bar_width

    # Amendment D's precondition must REJECT this geometry -- if it admitted it,
    # the amended clause would be false right here.
    spread = max(run_bytes) - min(run_bytes)
    assert surplus * spread <= sum(run_bytes), (
        "Amendment D's precondition must not admit a geometry where strictness "
        "is provably unreachable"
    )


def test_tc_b77_04_b77_bound_zero_byte_run_still_paints_a_column() -> None:
    """TC-B77-04 (invalid): a zero-byte run gets a column, sum stays exact."""
    widths = _allocate_band_widths([0, 100, 200], 2, 66)
    assert widths[0] >= 1
    assert sum(widths) + 2 == 66
    assert widths[1] <= widths[2]

    # Every run zero: no byte share exists to apportion, so all fall to the floor.
    assert _allocate_band_widths([0, 0, 0], 0, 66) == [1, 1, 1]


def test_tc_b77_05_b77_bound_zero_span_image_renders_no_segments(
    tmp_path: Path,
) -> None:
    """TC-B77-05 (error): ``total_span <= 0`` short-circuits before allocation.

    ``render_ranges`` returns at its zero-span guard, so the allocator is never
    reached with a degenerate span. Asserted through the shipped surface: the
    panel shows its no-entropy note and mounts no segment, rather than raising.
    """

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            app.action_show_screen("map")
            panel = app.query_one(MemoryMapPanel)
            panel.render_ranges([(0x1000, 0x1000)], [True], entropy_windows=())
            await pilot.pause()
            return len(list(app.query(".map-band-seg"))), panel.rendered_text

    n_segs, text = asyncio.run(_drive())
    assert n_segs == 0
    assert text, "the panel must state WHY it drew nothing, not render blank"


def test_tc_b77_30_b77_width_one_range_yields_two_runs(tmp_path: Path) -> None:
    """TC-B77-30 (boundary): an entropy-heterogeneous SINGLE range -> 2 runs.

    The subject of every width clause is the RUN, not the range:
    ``_merge_band_runs`` starts a new run on band change OR address
    discontinuity, so one contiguous range spanning two entropy bands emits two
    ``BandSegment``s. This pins that the completeness guard's run-equality and
    its range-COVERAGE clause are genuinely different populations — the coverage
    clause holds here while a naive range-equality guard would be False.

    ONE ``random.Random`` is constructed and drawn from repeatedly. Constructing
    it per byte makes the "random" half constant, collapsing the fixture to a
    single run and appearing to refute the finding.
    """
    base = 0x10000
    half = 0x400
    rng = random.Random(20260801)
    mem_map = {base + i: 0xFF for i in range(half)}
    for i in range(half):
        mem_map[base + half + i] = rng.randrange(256)
    ranges = [(base, base + 2 * half)]
    path = tmp_path / "heterogeneous.s19"
    path.write_text(emit_s19_from_mem_map(mem_map, ranges), encoding="ascii")
    loaded = build_loaded_s19(path, S19File(str(path)), a2l_path=None, a2l_data=None)

    assert len(loaded.ranges) == 1, "the fixture must be ONE contiguous range"
    oracle = _merge_band_runs(loaded.entropy_windows)
    assert len(oracle) >= 2, (
        f"the fixture must split into >=2 runs; got {oracle} — if it is 1 run "
        "the 'random' half is constant (one rng per byte), not the finding "
        "refuted"
    )

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await _prime_map(app, pilot, loaded)
            await _settled_bar_width(app, pilot)
            return {(s.region_start, s.region_end) for s in app.query(BandSegment)}

    emitted = asyncio.run(_drive())
    assert emitted == {(start, start + n) for _band, n, start in oracle}
    assert len(emitted) > len(loaded.ranges), (
        f"one range must emit more than one run segment; {len(loaded.ranges)} "
        f"range(s) -> {len(emitted)} segment(s)"
    )
    assert all(
        any(a <= rs < b for a, b in emitted) for rs, _ in loaded.ranges
    ), "the range-coverage clause must hold where range-equality would not"


# ---------------------------------------------------------------------------
# AT-B77-02 — gapless no-op golden at a fixed container width (LLR-111.4)
# ---------------------------------------------------------------------------
#: Golden home, mirroring ``tests/goldens/batch35/`` / ``batch71/`` / ``batch74/``.
_B77_GOLDEN = (
    Path(__file__).parent / "goldens" / "batch77" / "at-b77-02-gapless-band-strip.txt"
)

#: Mapped byte counts of the two runs the gapless fixture emits. UNEQUAL by
#: requirement (LLR-111.4, R-2): through the shipped allocator an EQUAL 512/512
#: fixture gives [33,33] @bar=66 and [25,25] @bar=50 — equal widths at each
#: regime, invariant under any monotone re-weighting, so the golden would
#: certify nothing. ``_two_band_loaded`` / ``_two_region_loaded`` are equal-run
#: (256/256) fixtures and must not be borrowed for this.
_B77_GAPLESS_RUN_BYTES = [768, 256]


def _gapless_unequal_loaded(tmp_path: Path):
    """A deterministic GAPLESS image whose two runs are UNEQUAL (768 / 256).

    ONE contiguous range ``0x80000000..0x80000400``: 768 bytes of ``0xFF``
    (constant/padding, 3 entropy windows) followed by a 256-byte permutation of
    ``0..255`` (high/random, 1 window). One range means no address
    discontinuity, so ``_merge_band_runs`` splits on the band change alone and
    the producer emits two ``BandSegment``s with NO ``.map-band-gap`` between
    them — the gapless precondition of LLR-111.4.

    The shuffle seed does not reach the golden: a permutation of ``0..255`` has
    H == 8.0 in every order, so the second run classifies ``high/random``
    whatever the ordering, and the allocated widths are a function of the byte
    COUNTS only.
    """
    base = 0x80000000
    const_bytes, high_bytes = _B77_GAPLESS_RUN_BYTES
    mem_map = {base + i: 0xFF for i in range(const_bytes)}
    values = list(range(high_bytes))
    random.Random(20260801).shuffle(values)
    for i, value in enumerate(values):
        mem_map[base + const_bytes + i] = value
    ranges = [(base, base + const_bytes + high_bytes)]
    path = tmp_path / "gapless_unequal.s19"
    path.write_text(emit_s19_from_mem_map(mem_map, ranges), encoding="ascii")
    return build_loaded_s19(path, S19File(str(path)), a2l_path=None, a2l_data=None)


def _golden_record(size, bar_width: int, classes: str, content: str) -> str:
    """One golden line: ``COLSxROWS|BAR_WIDTH|CLASSES|CONTENT``.

    ``|`` is the field separator because no class token and no band glyph
    contains it. Classes are sorted so the record does not depend on Textual's
    ``frozenset`` iteration order.
    """
    return f"{size[0]}x{size[1]}|{bar_width}|{classes}|{content}"


def _golden_records_from_render(app: S19TuiApp, size, bar_width: int) -> list:
    """Compose the golden records from the RENDERED ``.map-band-seg`` widgets.

    Reads the widget's runtime ``render()`` text, never a snapshot export (whose
    bytes carry ``&#160;``) and never a console ``print`` (which dies on
    ``UnicodeEncodeError`` under cp1252) — C-42.
    """
    return [
        _golden_record(
            size, bar_width, " ".join(sorted(seg.classes)), str(seg.render())
        )
        for seg in app.query(".map-band-seg")
    ]


def _golden_records_from_allocator(loaded, size, bar_width: int) -> list:
    """Compose the SAME records without rendering — the independent derivation.

    Re-derives the payload a second way (batch-24 double-proof): the width
    vector comes from calling ``_allocate_band_widths`` directly, and the class
    string is rebuilt from ``band_style`` plus the producer's literal
    ``map-band-seg`` token. Nothing here queries a widget, so agreement with the
    captured golden proves the golden transcribes the producer's ARITHMETIC and
    not just one render.

    ``n_gaps`` is 0 by construction — the caller's fixture is a single
    contiguous range, so no gap marker can be emitted — and
    ``test_b77_gapless_fixture_is_unequal_and_gapless`` is what holds that true.
    """
    runs = _merge_band_runs(loaded.entropy_windows)
    widths = _allocate_band_widths([n for _band, n, _start in runs], 0, bar_width)
    records = []
    for (band, _run_bytes, _start), width in zip(runs, widths):
        token, glyph, _meaning = band_style(band)
        classes = " ".join(sorted({"map-band-seg", token}))
        records.append(_golden_record(size, bar_width, classes, glyph * width))
    return records


async def _drive_gapless(app: S19TuiApp, pilot, loaded, size):
    """Render the gapless fixture and return ``(bar_width, records, n_gap_widgets)``."""
    await _prime_map(app, pilot, loaded)
    bar_width = await _settled_bar_width(app, pilot)
    return (
        bar_width,
        _golden_records_from_render(app, size, bar_width),
        len(list(app.query(".map-band-gap"))),
    )


@pytest.mark.parametrize("size", _SIZES)
def test_b77_gapless_golden(tmp_path: Path, size) -> None:
    """AT-B77-02: the rendered strip equals the stored golden, byte for byte.

    LLR-111.4 — for a GAPLESS image at a fixed container width, the concatenated
    ``.map-band-seg`` classes and content equal a golden captured from the
    shipped producer. The mutation that discharges this node is substituting the
    allocator with plain ``round(bar * b / total)``: executed, ``[49,17]`` ->
    ``[50,16]`` @bar=66 and ``[37,13]`` -> ``[38,12]`` @bar=50, so the golden
    reddens at both regimes.

    The golden is captured AFTER the width basis settled (Inc-1). Captured
    before it, a golden pins the RETIRED arithmetic — which is exactly how the
    ``[45,15]`` payload (summing to the deleted ``_BAND_BAR_WIDTH`` of 60)
    entered revision 1 of the requirements document.

    ⚠️ **THIS NODE IS COUPLED TO THE CONTAINER CSS BY DESIGN — read a failure
    accordingly.** Each golden record is keyed by the SETTLED bar width
    (``80x24|66|…``, ``120x30|50|…``), because a byte-golden over a
    container-relative allocation is meaningless without the container it was
    allocated against. The consequence is direct: **any CSS change that moves
    ``.map-band-bar``'s width reddens this node**, and that is the contract
    working, not drift. ``LLR-111.1`` makes the measured container the basis, so
    a silent width change IS a silent change to every emitted segment width —
    the coupling is the only thing that surfaces it.

    So a future editor who widens or narrows the bar should expect this node RED
    and must **re-capture the golden deliberately**, recording the new settled
    widths — never ``-k``-skip it, and never treat the failure as flake. If it
    reddens with NO CSS change in the diff, that is the real alarm: the allocator
    or the settle path moved.
    """
    loaded = _gapless_unequal_loaded(tmp_path)

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            return await _drive_gapless(app, pilot, loaded, size)

    bar_width, records, n_gap_widgets = asyncio.run(_drive())
    prefix = f"{size[0]}x{size[1]}|"
    expected = [
        line
        for line in _B77_GOLDEN.read_text(encoding="utf-8").splitlines()
        if line.startswith(prefix)
    ]

    assert n_gap_widgets == 0, (
        f"{size}: the fixture must render GAPLESS; got {n_gap_widgets} "
        ".map-band-gap widget(s), which changes n_gaps and the allocation"
    )
    assert expected, f"{size}: the golden carries no record for this regime"
    assert records == expected, (
        f"{size} (settled bar {bar_width}): the rendered strip does not match "
        f"{_B77_GOLDEN.name}\n  rendered: {records}\n  golden:   {expected}"
    )


def test_b77_gapless_fixture_is_unequal_and_gapless(tmp_path: Path) -> None:
    """Guard the guard: the golden's fixture stays UNEQUAL and GAPLESS.

    Both properties are preconditions of AT-B77-02 being worth anything. Equal
    runs make the golden vacuous (R-2): the allocator gives them equal widths at
    every regime, so the payload is invariant under any monotone re-weighting
    and the ``round()`` mutation cannot redden it. A gap would make ``n_gaps``
    non-zero, changing the allocation the golden pins and silently voiding the
    "gapless no-op" the requirement names.
    """
    loaded = _gapless_unequal_loaded(tmp_path)

    assert len(loaded.ranges) == 1, (
        f"the fixture must be ONE contiguous range so no gap marker can be "
        f"emitted; got {loaded.ranges}"
    )
    runs = _merge_band_runs(loaded.entropy_windows)
    run_bytes = [n for _band, n, _start in runs]
    assert run_bytes == _B77_GAPLESS_RUN_BYTES, (
        f"the fixture must emit runs {_B77_GAPLESS_RUN_BYTES}; got {run_bytes}"
    )
    assert len(set(run_bytes)) == len(run_bytes), (
        f"the runs must DIFFER in mapped bytes or the golden is vacuous; got "
        f"{run_bytes}"
    )


def test_b77_gapless_golden_rederived_from_the_allocator(tmp_path: Path) -> None:
    """Double-proof: the whole golden re-derives WITHOUT rendering anything.

    A golden captured by its author alone proves transcription, not provenance
    (batch-24). This composes every record a second, independent way — the width
    vector straight out of ``_allocate_band_widths``, the class string rebuilt
    from ``band_style`` — and byte-compares the assembled file against the
    stored one.

    The bar widths are read FROM the golden rather than hard-coded, so this node
    checks the ARITHMETIC at a given container width; that those widths are the
    real settled ones is what ``test_b77_gapless_golden`` proves. Neither node
    is sufficient alone.
    """
    loaded = _gapless_unequal_loaded(tmp_path)
    stored = _B77_GOLDEN.read_text(encoding="utf-8")

    bar_widths = {}
    for line in stored.splitlines():
        regime, bar_width, _classes, _content = line.split("|", 3)
        bar_widths.setdefault(regime, bar_width)

    rederived = []
    for size in _SIZES:
        regime = f"{size[0]}x{size[1]}"
        assert regime in bar_widths, f"the golden carries no {regime} record"
        rederived.extend(
            _golden_records_from_allocator(loaded, size, int(bar_widths[regime]))
        )

    assert "\n".join(rederived) + "\n" == stored, (
        f"the allocator-composed payload does not reproduce {_B77_GOLDEN.name}"
        f"\n  re-derived: {rederived}\n  stored:     {stored.splitlines()}"
    )


def test_b77_golden_is_stored_lf_only_and_covers_both_regimes() -> None:
    """The STORED bytes — not the file handed to git — carry the golden.

    ``.gitattributes`` marks this path ``-text`` so git stores it verbatim: a
    byte-exact artifact must not be normalised in EITHER direction (``text
    eol=lf`` is the wrong fix for evidence bytes — it rewrites the blob). That
    only holds if the bytes on disk really are LF, which is what this asserts,
    together with the golden covering both regimes rather than degrading to one.
    """
    raw = _B77_GOLDEN.read_bytes()

    assert raw, "the golden must not be empty"
    assert b"\r\n" not in raw, "the golden must be LF-only"
    assert raw.endswith(b"\n"), "the golden must end with a newline"
    regimes = [
        line.split("|", 1)[0] for line in raw.decode("utf-8").splitlines()
    ]
    assert regimes.count("80x24") == 2 and regimes.count("120x30") == 2, (
        f"the golden must carry both runs at both regimes; got {regimes}"
    )


# ---------------------------------------------------------------------------
# batch-77 Inc-7 — HLR-116 auto-select + HLR-117 selection styling
#
# Shared drive helpers. Every arm below reaches the panel through the SHIPPED
# surface (``action_show_screen("map")`` → ``update_memory_map()``), never by
# calling the resolution hook directly: the whole point of LLR-116.2 is that
# the resolution is DEFERRED, and a test that called it inline would be green
# on an implementation that resolves against the stale, about-to-be-removed
# rows.
# ---------------------------------------------------------------------------
_SELECTED_CLASS = "map-region-selected"
_STYLES_TCSS = Path("s19_app/tui/styles.tcss")


def _blocks_image(tmp_path: Path, name: str, blocks):
    """Build a deterministic multi-run image from ``[(base, kind)]`` blocks.

    ``kind`` is ``"const"`` (0xFF fill → ``constant/padding``, H == 0) or
    ``"high"`` (a seeded permutation of 0..255 → ``high/random``, H == 8).
    Each block is 256 bytes; bases are far enough apart that the loader derives
    one range per block and ``_merge_band_runs`` emits one run each. The run
    population is ASSERTED by every caller that depends on it rather than
    assumed — a fixture that silently merged two blocks would make several of
    the clauses below vacuous.
    """
    mem_map = {}
    ranges = []
    for index, (base, kind) in enumerate(blocks):
        if kind == "const":
            for offset in range(256):
                mem_map[base + offset] = 0xFF
        else:
            values = list(range(256))
            random.Random(20260801 + index).shuffle(values)
            for offset, value in enumerate(values):
                mem_map[base + offset] = value
        ranges.append((base, base + 256))
    path = tmp_path / name
    path.write_text(emit_s19_from_mem_map(mem_map, ranges), encoding="ascii")
    return build_loaded_s19(path, S19File(str(path)), a2l_path=None, a2l_data=None)


def _panel(app: S19TuiApp) -> MemoryMapPanel:
    return app.query_one("#memory_map_panel", MemoryMapPanel)


def _live_rows(app: S19TuiApp):
    """The rows of the CURRENTLY mounted region list, in emission order.

    Deliberately NOT ``app.query(RegionRow)``: ``grid.remove_children()`` is
    deferred, so a panel-wide query returns the stale rows alongside the fresh
    ones during the prune window. That is the same trap the focus predicates
    below exist to catch, and an oracle that fell into it could not detect it.
    """
    return _panel(app)._live_region_rows()


def _markers(app: S19TuiApp):
    return [row for row in _live_rows(app) if _SELECTED_CLASS in row.classes]


def _style_triple(row):
    """The layer that HOLDS the selection fact (P-42, executed).

    ``render().spans`` is ``[]`` on these rows — the content is a plain ``Text``
    with no style — so C-37's span route is inapplicable and ``render_line``
    returns the base theme colour. The resolved style lives on the widget.
    """
    return (
        str(row.styles.background),
        str(row.styles.color),
        str(row.styles.text_style),
    )


def _band_tokens(row):
    return {cls for cls in row.classes if cls.startswith("band-")}


async def _settle_selection(pilot, panel, max_pauses: int = 10) -> bool:
    """Pause until the deferred resolution has applied, or give up.

    Returns True once ``_selected_cell_start`` is set, after ONE further pause
    for ``focus()``'s own ``call_later``. Callers asserting an ABSENCE use a
    fixed pause count instead — no condition can signal "nothing will happen".
    """
    for _ in range(max_pauses):
        await pilot.pause()
        if panel._selected_cell_start is not None:
            await pilot.pause()
            return True
    return False


class _PostRecorder:
    """Record every message the panel posts, then delegate to the real method.

    LLR-116.3 forbids AUTO-SELECTION from posting ``OpenInHexRequested``.
    ``post_message`` is the layer that claim is about — asserting on the app's
    hex screen instead would also pass if the message were posted and dropped.
    """

    def __init__(self, panel: MemoryMapPanel) -> None:
        self.posted = []
        self._real = panel.post_message
        panel.post_message = self._record  # type: ignore[method-assign]

    def _record(self, message):
        self.posted.append(message)
        return self._real(message)

    def open_in_hex(self):
        return [
            m for m in self.posted
            if isinstance(m, MemoryMapPanel.OpenInHexRequested)
        ]


# ---------------------------------------------------------------------------
# AT-B77-11 — fresh render selects run 1 and never navigates (LLR-116.2/.3/.5)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("size", _SIZES)
def test_b77_select_fresh_render_inspects_run_one_without_navigating(
    tmp_path: Path, size
) -> None:
    """Zero clicks, zero keys: run 1 is inspected, focused LIVE, no nav posted.

    Four claims in one node because three of them are only meaningful together:

    - the inspector NAMES run 1 (the presence co-assertion, C-40);
    - EXACTLY ZERO ``OpenInHexRequested`` are posted (LLR-116.3) — an absence
      clause which, without the presence clause above, would be green on a
      panel that did nothing at all;
    - the recorder can SEE a post, demonstrated in the same run by driving a
      chain-2 activation afterwards and observing 1. Without this control the
      zero is equally consistent with a recorder that was never wired up;
    - focus is on a row that is ATTACHED and PRESENT among the live rows, not
      merely one whose ``region_start`` matches (LLR-116.5). Identity alone
      reads True on a fully detached widget — measured at Phase 2:
      ``is_attached=False``, ``parent=None``, the focused row absent from the
      live set, and the identity threshold still True.
    """
    loaded = _load_case_02()

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app.current_file = loaded
            app.action_show_screen("map")
            panel = _panel(app)
            recorder = _PostRecorder(panel)
            app.update_memory_map()
            settled = await _settle_selection(pilot, panel)
            rows = _live_rows(app)
            focused = app.focused
            observed = {
                "settled": settled,
                "n_rows": len(rows),
                "first_start": rows[0].region_start if rows else None,
                "selected": panel._selected_cell_start,
                "detail": app.query_one("#map_detail_body").render().plain,
                "auto_nav": len(recorder.open_in_hex()),
                "focus_is_row": isinstance(focused, RegionRow),
                "focus_live": focused in set(rows),
                "focus_attached": bool(focused is not None and focused.is_attached),
                "focus_start": getattr(focused, "region_start", None),
                "markers": [r.region_start for r in _markers(app)],
            }
            # Positive control for the absence clause: the SAME recorder must
            # observe a real chain-2 activation. Driven only after every
            # assertion subject above has been captured.
            panel.on_region_row_activated(
                RegionRow.Activated(
                    rows[0].region_start, rows[0].region_end, chain=2
                )
            )
            await pilot.pause()
            observed["nav_after_double"] = len(recorder.open_in_hex())
            return observed

    got = asyncio.run(_drive())

    assert got["settled"], f"{size}: the deferred resolution never ran: {got}"
    assert got["n_rows"] >= 2, (
        f"{size}: the fixture must render ≥2 runs or 'run 1 was selected' is "
        f"indistinguishable from 'any run was selected'; got {got}"
    )
    assert got["selected"] == got["first_start"], (
        f"{size}: a fresh render must resolve to run 1; got {got}"
    )
    assert f"0x{got['first_start']:08X}" in got["detail"], (
        f"{size}: #map_detail_body must NAME run 1 — this is the presence "
        f"co-assertion the zero-navigation clause depends on; got {got}"
    )
    assert got["auto_nav"] == 0, (
        f"{size}: auto-selection must post ZERO OpenInHexRequested "
        f"(LLR-116.3); got {got}"
    )
    assert got["nav_after_double"] == 1, (
        f"{size}: CONTROL — the recorder must be able to observe a post at "
        f"all; a chain-2 activation produced {got['nav_after_double']}, so the "
        f"zero above would have been vacuous. {got}"
    )
    assert got["focus_is_row"] and got["focus_live"] and got["focus_attached"], (
        f"{size}: focus must be on a LIVE, ATTACHED region row, not merely on "
        f"a widget whose region_start matches (LLR-116.5); got {got}"
    )
    assert got["focus_start"] == got["selected"], (
        f"{size}: the focused row's start must equal the resolved selection; "
        f"got {got}"
    )
    assert got["markers"] == [got["selected"]], (
        f"{size}: exactly one row carries the selection marker, at the "
        f"resolved address; got {got}"
    )


# ---------------------------------------------------------------------------
# AT-B77-13 / AT-B77-14 — re-render resolution by ADDRESS (LLR-116.4, R-6)
# ---------------------------------------------------------------------------
async def _rerender(pilot, app, first, second, select_index):
    """Render ``first``, select one of its rows, then render ``second``."""
    await pilot.pause()
    app.current_file = first
    app.action_show_screen("map")
    panel = _panel(app)
    app.update_memory_map()
    assert await _settle_selection(pilot, panel), "first render never resolved"
    rows_a = _live_rows(app)
    target = rows_a[select_index]
    panel._select_region(target.region_start, target.region_end)
    await pilot.pause()
    starts_a = [r.region_start for r in rows_a]
    app.current_file = second
    app.update_memory_map()
    assert await _settle_selection(pilot, panel), "re-render never resolved"
    rows_b = _live_rows(app)
    focused = app.focused
    return {
        "starts_a": starts_a,
        "starts_b": [r.region_start for r in rows_b],
        "pre_selected": target.region_start,
        "selected": panel._selected_cell_start,
        "detail": app.query_one("#map_detail_body").render().plain,
        "focus_live": focused in set(rows_b),
        "focus_attached": bool(focused is not None and focused.is_attached),
        "focus_start": getattr(focused, "region_start", None),
        "markers": [r.region_start for r in _markers(app)],
    }


@pytest.mark.parametrize("size", _SIZES)
def test_b77_select_rerender_preserves_a_region_still_present(
    tmp_path: Path, size
) -> None:
    """AT-B77-13 — the selection survives a re-render that still holds it.

    The pre-selected run is asserted NOT to be run 1: a resolution that always
    reset to ``ordered[0]`` would be indistinguishable from a correct one on a
    first-row fixture.
    """
    loaded = _load_case_02()

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            return await _rerender(pilot, app, loaded, loaded, -1)

    got = asyncio.run(_drive())

    assert len(got["starts_b"]) >= 2, f"{size}: need ≥2 runs; got {got}"
    assert got["pre_selected"] != got["starts_b"][0], (
        f"{size}: the preserved run must NOT be run 1, or 'preserved' and "
        f"'reset to first' produce the same answer; got {got}"
    )
    assert got["pre_selected"] in got["starts_b"], (
        f"{size}: PRECONDITION — this arm requires the region to be PRESENT "
        f"after the re-render; got {got}"
    )
    assert got["selected"] == got["pre_selected"], (
        f"{size}: a present region must be PRESERVED across a re-render "
        f"(LLR-116.4); got {got}"
    )
    assert f"0x{got['pre_selected']:08X}" in got["detail"], (
        f"{size}: the inspector must name the preserved run; got {got}"
    )
    assert got["focus_live"] and got["focus_attached"], (
        f"{size}: the focused row must be LIVE and ATTACHED after the "
        f"re-render — the remount window is exactly where a detached row "
        f"satisfies the identity predicate; got {got}"
    )
    assert got["focus_start"] == got["pre_selected"], (
        f"{size}: focus must follow the preserved selection; got {got}"
    )
    assert got["markers"] == [got["pre_selected"]], (
        f"{size}: exactly one marker, on the preserved row; got {got}"
    )


@pytest.mark.parametrize("size", _SIZES)
def test_b77_select_rerender_falls_back_when_the_region_is_gone(
    tmp_path: Path, size
) -> None:
    """AT-B77-14 — an absent region falls back to the NEW first region.

    Two disjoint images, so the previously selected address cannot survive by
    accident. The disjointness is asserted, not assumed.
    """
    first = _blocks_image(
        tmp_path, "abs_a.s19", [(0x00100000, "const"), (0x00110000, "high")]
    )
    second = _blocks_image(
        tmp_path, "abs_b.s19", [(0x90000000, "const"), (0x90010000, "high")]
    )

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            return await _rerender(pilot, app, first, second, -1)

    got = asyncio.run(_drive())

    assert not (set(got["starts_a"]) & set(got["starts_b"])), (
        f"{size}: PRECONDITION — the two images must have DISJOINT run "
        f"addresses or 'absent' is not established; got {got}"
    )
    assert got["pre_selected"] not in got["starts_b"], (
        f"{size}: PRECONDITION — the selected region must be absent; got {got}"
    )
    assert got["selected"] == got["starts_b"][0], (
        f"{size}: an absent region must fall back to the NEW first region "
        f"(LLR-116.4); got {got}"
    )
    assert f"0x{got['starts_b'][0]:08X}" in got["detail"], (
        f"{size}: the inspector must name the new first run; got {got}"
    )
    assert got["focus_live"] and got["focus_attached"], (
        f"{size}: the focused row must be LIVE and ATTACHED; got {got}"
    )
    assert got["focus_start"] == got["starts_b"][0], (
        f"{size}: focus must follow the fallback selection; got {got}"
    )
    assert got["markers"] == [got["starts_b"][0]], (
        f"{size}: exactly one marker, on the new first row; got {got}"
    )


# ---------------------------------------------------------------------------
# AT-B77-12 — the selected row is visually distinguishable (HLR-117)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("size", _SIZES)
def test_b77_style_selected_row_differs_from_every_unselected_row(
    tmp_path: Path, size
) -> None:
    """AT-B77-12 — triple differs ∧ exactly one marker ∧ ≥2 runs (TC-B77-25).

    The BACKGROUND channel is asserted separately from the whole triple, and
    that separation is load-bearing: ``color`` ALREADY differs between rows of
    different bands (measured pre-change on this fixture — 4 rows, 2 distinct
    triples, zero selection styling), so "the selected row's triple differs
    from every other row's" is satisfiable with NO selection style at all
    whenever the selected row is the only one of its band. The background is
    transparent on every unselected row and is what this increment adds, so it
    is the channel that can discriminate.
    """
    loaded = _load_case_02()

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app.current_file = loaded
            app.action_show_screen("map")
            panel = _panel(app)
            app.update_memory_map()
            assert await _settle_selection(pilot, panel)
            rows = _live_rows(app)
            return {
                "n_rows": len(rows),
                "selected": panel._selected_cell_start,
                "markers": [r.region_start for r in _markers(app)],
                "triples": {r.region_start: _style_triple(r) for r in rows},
                "backgrounds": {
                    r.region_start: str(r.styles.background) for r in rows
                },
            }

    got = asyncio.run(_drive())

    assert got["n_rows"] >= 2, (
        f"{size}: TC-B77-25 — the fixture must render ≥2 runs; with one run "
        f"'differs from EVERY unselected row' is vacuously true; got {got}"
    )
    assert got["markers"] == [got["selected"]], (
        f"{size}: exactly one row carries the selection marker (LLR-117.1); "
        f"got {got}"
    )
    sel = got["selected"]
    others = [start for start in got["triples"] if start != sel]
    assert others, f"{size}: no unselected row to compare against; got {got}"
    for start in others:
        assert got["triples"][sel] != got["triples"][start], (
            f"{size}: the selected row's (background, color, text_style) must "
            f"differ from EVERY unselected row's; 0x{sel:08X} vs "
            f"0x{start:08X}; got {got}"
        )
        assert got["backgrounds"][sel] != got["backgrounds"][start], (
            f"{size}: the difference must be in the BACKGROUND channel — "
            f"`color` already differs per band, so a triple-only comparison "
            f"can pass with no selection style applied; got {got}"
        )


def test_tc_b77_32_b77_style_band_token_survives_selection(
    tmp_path: Path,
) -> None:
    """TC-B77-32 — selecting and MOVING the selection never touches ``band-*``.

    Asserted across a move, not a single application: a marker that replaced
    the band token would be invisible to a test that only ever looked at one
    selected row, because that row's band class would already be gone at the
    first read. (LLR-117.2, behavioural arm.)

    ⚠️ **Id allocation, recorded.** Inc-7 left this node and the inspection arm
    below unlabelled because §3's boundary list allocated `TC-B77-26/27/28`
    against HLR-117 as BARE IDS — no content was ever stated for them anywhere
    in the batch artifacts. Retro-fitting content into ids whose intent nobody
    recorded is minting, so those three are **WITHDRAWN — allocated without
    content, never specified**, their numbers are not reused, and these two
    nodes take the next free ids. Allocation stays monotonic, so a spent id can
    never mean two things (the same rule `AT-B77-17`'s withdrawal established).
    """

    async def _drive():
        loaded = _load_case_02()
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.current_file = loaded
            app.action_show_screen("map")
            panel = _panel(app)
            app.update_memory_map()
            assert await _settle_selection(pilot, panel)
            rows = _live_rows(app)
            bands_first = {r.region_start: _band_tokens(r) for r in rows}
            last = rows[-1]
            panel._select_region(last.region_start, last.region_end)
            await pilot.pause()
            rows = _live_rows(app)
            return {
                "bands_first": bands_first,
                "bands_second": {r.region_start: _band_tokens(r) for r in rows},
                "markers_second": [r.region_start for r in _markers(app)],
                "moved_to": last.region_start,
            }

    got = asyncio.run(_drive())

    assert all(got["bands_first"].values()), (
        f"PRECONDITION — every row must carry a band token to begin with, or "
        f"'unchanged' is vacuous; got {got}"
    )
    assert got["bands_first"] == got["bands_second"], (
        f"applying or moving the selection marker must not add, remove or "
        f"override any band-* class (LLR-117.2); got {got}"
    )
    assert got["markers_second"] == [got["moved_to"]], (
        f"the marker must MOVE, leaving exactly one; got {got}"
    )


def test_tc_b77_33_b77_style_selection_rule_sets_no_foreground_no_inversion() -> (
    None
):
    """TC-B77-33 — LLR-117.2's inspection arm, read from the stylesheet.

    Revision 1's wording — "sets no ``color:`` property" — is satisfied by
    ``text-style: reverse``, which swaps foreground and background and so
    repaints the band channel through the back door. Both are asserted.

    Labelled at Inc-8; see ``test_tc_b77_32_…`` for the withdrawal record that
    freed these two ids.
    """
    css = _STYLES_TCSS.read_text(encoding="utf-8")
    match = re.search(
        r"\.map-region-row\.map-region-selected\s*\{([^}]*)\}", css
    )
    assert match, (
        "the selection rule must exist in styles.tcss as "
        ".map-region-row.map-region-selected; the runtime style assertions "
        "would otherwise be passing on a rule from somewhere else"
    )
    body = match.group(1)
    props = {
        name.strip(): value.strip()
        for name, value in (
            line.split(":", 1) for line in body.split(";") if ":" in line
        )
    }

    assert "background" in props, (
        f"the selection must be carried by a background; got {props}"
    )
    assert "color" not in props, (
        f"the selection rule must NOT set a foreground colour — that is the "
        f"band channel (LLR-117.2); got {props}"
    )
    assert "reverse" not in props.get("text-style", ""), (
        f"the selection rule must NOT use a text style that inverts "
        f"foreground and background; `reverse` satisfies a naive no-`color:` "
        f"check while repainting the band colour; got {props}"
    )


# ---------------------------------------------------------------------------
# Boundary catalog — HLR-116
# ---------------------------------------------------------------------------
def test_tc_b77_21_b77_select_no_file_keeps_the_hint_and_fabricates_nothing(
    tmp_path: Path,
) -> None:
    """TC-B77-21 — no file: the hint stays, no selection, focus untouched."""

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.action_show_screen("map")
            app.update_memory_map()
            # A fixed pause count: no condition can signal "nothing happened".
            for _ in range(6):
                await pilot.pause()
            panel = _panel(app)
            return {
                "rows": len(_live_rows(app)),
                "selected": panel._selected_cell_start,
                "body": app.query_one("#map_detail_body").render().plain,
                "hint": panel._DETAIL_HINT,
                "focus_is_row": isinstance(app.focused, RegionRow),
            }

    got = asyncio.run(_drive())

    assert got["rows"] == 0, f"no file must render no region row; got {got}"
    assert got["selected"] is None, f"no selection may be fabricated; got {got}"
    assert got["body"] == got["hint"], f"the hint must be retained; got {got}"
    assert not got["focus_is_row"], f"focus must not move to a row; got {got}"


@pytest.mark.parametrize("size", _SIZES)
def test_tc_b77_22_b77_select_single_run_is_selected_and_marked(
    tmp_path: Path, size
) -> None:
    """TC-B77-22 — one run: it is the selection, and it carries the marker."""
    loaded = _blocks_image(tmp_path, "one.s19", [(0x80000000, "const")])

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app.current_file = loaded
            app.action_show_screen("map")
            panel = _panel(app)
            app.update_memory_map()
            settled = await _settle_selection(pilot, panel)
            rows = _live_rows(app)
            return {
                "settled": settled,
                "n_rows": len(rows),
                "selected": panel._selected_cell_start,
                "markers": [r.region_start for r in _markers(app)],
                "focus_start": getattr(app.focused, "region_start", None),
                "focus_live": app.focused in set(rows),
            }

    got = asyncio.run(_drive())

    assert got["n_rows"] == 1, (
        f"{size}: PRECONDITION — this boundary needs exactly one run; got {got}"
    )
    assert got["settled"] and got["selected"] == 0x80000000, got
    assert got["markers"] == [0x80000000], got
    assert got["focus_start"] == 0x80000000 and got["focus_live"], got


@pytest.mark.parametrize("size", _SIZES)
def test_tc_b77_23_b77_select_disjoint_file_switch_selects_the_new_first_run(
    tmp_path: Path, size
) -> None:
    """TC-B77-23 — switching to a wholly different image never carries over."""
    first = _blocks_image(
        tmp_path, "sw_a.s19", [(0x00200000, "const"), (0x00210000, "high")]
    )
    second = _blocks_image(
        tmp_path, "sw_b.s19", [(0xA0000000, "high"), (0xA0010000, "const")]
    )

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            return await _rerender(pilot, app, first, second, 0)

    got = asyncio.run(_drive())

    assert not (set(got["starts_a"]) & set(got["starts_b"])), (
        f"{size}: PRECONDITION — the images must be disjoint; got {got}"
    )
    assert got["selected"] == got["starts_b"][0], (
        f"{size}: the new image's first run must be selected; got {got}"
    )
    assert got["markers"] == [got["starts_b"][0]], got
    assert got["focus_live"] and got["focus_start"] == got["starts_b"][0], got


@pytest.mark.parametrize("size", _SIZES)
def test_tc_b77_24_b77_select_zero_byte_window_selects_without_raising(
    tmp_path: Path, size
) -> None:
    """TC-B77-24 — a zero-byte selection window inspects without raising.

    ⚠️ Stated plainly rather than dressed up: the SHIPPED producer cannot emit
    a zero-byte run — ``_merge_band_runs`` sums entropy-window sample counts,
    each ≥1 — so this boundary is not reachable through the load path and is
    exercised at the layer where it IS representable, the selection call. A
    test claiming to drive it through a loaded image would be asserting over an
    input the pipeline cannot produce.
    """
    loaded = _load_case_02()

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app.current_file = loaded
            app.action_show_screen("map")
            panel = _panel(app)
            app.update_memory_map()
            assert await _settle_selection(pilot, panel)
            rows = _live_rows(app)
            start = rows[-1].region_start
            panel._select_region(start, start)  # end == start: zero bytes
            await pilot.pause()
            return {
                "selected": panel._selected_cell_start,
                "markers": [r.region_start for r in _markers(app)],
                "detail": app.query_one("#map_detail_body").render().plain,
                "target": start,
            }

    got = asyncio.run(_drive())

    assert got["selected"] == got["target"], got
    assert got["markers"] == [got["target"]], (
        f"{size}: a zero-byte window must still mark its own row by address; "
        f"got {got}"
    )
    assert f"0x{got['target']:08X}" in got["detail"], got


@pytest.mark.parametrize("size", _SIZES)
def test_tc_b77_29_b77_select_preserves_by_address_when_the_index_shifts(
    tmp_path: Path, size
) -> None:
    """TC-B77-29 — the preserved run is no longer at its old index.

    THE discriminating case for "match by address, never by index". The second
    image prepends a run, so the preserved region moves from index 1 to index
    2. An index-based resolution would land on a DIFFERENT region, and the
    assertion below names which one it would have picked.
    """
    first = _blocks_image(
        tmp_path, "sh_a.s19", [(0x80010000, "const"), (0x80020000, "high")]
    )
    second = _blocks_image(
        tmp_path,
        "sh_b.s19",
        [(0x80000000, "high"), (0x80010000, "const"), (0x80020000, "high")],
    )

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            return await _rerender(pilot, app, first, second, -1)

    got = asyncio.run(_drive())
    pre = got["pre_selected"]

    assert pre in got["starts_b"], (
        f"{size}: PRECONDITION — the run must still be present; got {got}"
    )
    old_index = got["starts_a"].index(pre)
    new_index = got["starts_b"].index(pre)
    assert old_index != new_index, (
        f"{size}: PRECONDITION — the index must SHIFT, or address- and "
        f"index-matching give the same answer and this node proves nothing; "
        f"got {got}"
    )
    assert got["selected"] == pre, (
        f"{size}: resolution must match by ADDRESS. An index-based resolution "
        f"would have selected 0x{got['starts_b'][old_index]:08X} (index "
        f"{old_index} of the new render) instead of 0x{pre:08X}; got {got}"
    )
    assert got["focus_start"] == pre and got["focus_live"], got


@pytest.mark.parametrize("size", _SIZES)
def test_tc_b77_31_b77_select_resolution_runs_on_the_post_refresh_hook(
    tmp_path: Path, size
) -> None:
    """TC-B77-31 — the resolution is DEFERRED, not inline (LLR-116.2).

    ``grid.mount()`` is deferred, so "after the rows are mounted" is not a
    synchronous point inside ``render_ranges``. This asserts the observable
    consequence: the instant ``update_memory_map()`` returns, ZERO rows are
    queryable and no selection exists — so an inline resolution would have had
    nothing to resolve AGAINST. In the first-render case this node actually
    exercises there is no old row set at all: an inline resolution would find
    **zero** rows and could only fabricate a selection or none. On a RE-render
    the same deferral is what leaves the stale, about-to-be-removed rows as the
    only ones reachable inline, which is the mechanism that produced the
    detached-focus defect; that case is covered by ``TC-B77-29``. Either way
    the selection may appear only after the refresh boundary.

    *(Wording corrected at Inc-8: this docstring previously said an inline
    resolution "would have run against the OLD row set", which is the
    re-render mechanism, not the one measured here.)*
    """
    loaded = _load_case_02()

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app.current_file = loaded
            app.action_show_screen("map")
            panel = _panel(app)
            app.update_memory_map()  # NO pause: read the synchronous instant
            immediate = {
                "rows": len(_live_rows(app)),
                "any_region_row": len(app.query(RegionRow)),
                "selected": panel._selected_cell_start,
                "body_is_hint": (
                    app.query_one("#map_detail_body").render().plain
                    == panel._DETAIL_HINT
                ),
            }
            settled = await _settle_selection(pilot, panel)
            return immediate, settled, panel._selected_cell_start

    immediate, settled, after = asyncio.run(_drive())

    assert immediate["rows"] == 0 and immediate["any_region_row"] == 0, (
        f"{size}: PRECONDITION — the new rows must NOT be queryable at the "
        f"instant render_ranges returns, or 'a post-refresh hook is required' "
        f"is not established; got {immediate}"
    )
    assert immediate["selected"] is None and immediate["body_is_hint"], (
        f"{size}: the selection must NOT be applied inline — at this instant "
        f"the only rows an inline resolution could reach are the stale ones; "
        f"got {immediate}"
    )
    assert settled and after is not None, (
        f"{size}: the post-refresh hook must then apply the selection; got "
        f"settled={settled} after={after}"
    )


# ---------------------------------------------------------------------------
# OQ-4 — the focus-entry mechanism, and the guard it needs (LLR-116.1/.5)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("size", _SIZES)
def test_b77_select_focus_is_not_taken_while_the_map_screen_is_hidden(
    tmp_path: Path, size
) -> None:
    """Loading a file from another screen must not move focus to a hidden row.

    ``update_memory_map()`` runs on every load and unload, whatever screen the
    operator is on. ``Widget.focusable`` does NOT protect against this:
    measured against textual 8.2.8 it consults ``visible`` (the ``visibility``
    rule) and never ``display``, while the rail hides an inactive screen with
    ``.hidden { display: none }`` — so an unguarded ``focus()`` moves the
    keyboard to an invisible region row. Executed counterfactual, both regimes:
    with the guard removed, ``app.focused`` went ``RailItem -> RegionRow``
    while ``row.focusable`` was True and the map was not displayed.

    The selection itself IS still applied — only focus is withheld — so the
    operator finds the map already inspecting run 1 when they switch to it.
    """
    loaded = _load_case_02()

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app.action_show_screen("workspace")
            await pilot.pause()
            app.current_file = loaded
            panel = _panel(app)
            app.update_memory_map()
            settled = await _settle_selection(pilot, panel)
            rows = _live_rows(app)
            return {
                "settled": settled,
                "displayed": panel._is_displayed(),
                "row_focusable": rows[0].focusable if rows else None,
                "selected": panel._selected_cell_start,
                "focus_is_row": isinstance(app.focused, RegionRow),
            }

    got = asyncio.run(_drive())

    assert not got["displayed"], (
        f"{size}: PRECONDITION — the map must be hidden for this case; got {got}"
    )
    assert got["row_focusable"] is True, (
        f"{size}: PRECONDITION — the rows must be focusable, or the guard is "
        f"not what is keeping focus away and this node proves nothing; got {got}"
    )
    assert got["settled"] and got["selected"] is not None, (
        f"{size}: the selection must STILL be resolved while hidden — this is "
        f"the presence co-assertion for the absence below; got {got}"
    )
    assert not got["focus_is_row"], (
        f"{size}: focus must not move to a row on a screen that is not being "
        f"painted; got {got}"
    )


# ---------------------------------------------------------------------------
# batch-77 Inc-8 — HLR-115: arrows walk the region list, Enter inspects
#
# C-16 is the reason every node below presses REAL KEYS through the pilot and
# never calls ``row.focus()`` as a proxy. Textual performs NO spatial
# arrow-focus of its own: measured at Phase 3 on this tree with ``can_focus``
# already True and a row already focused, ``down``/``down``/``up`` left
# ``app.focused.region_start`` at ``0x0`` for all three presses, at BOTH
# regimes. A ``.focus()``-driven acceptance would have been green on that.
# ---------------------------------------------------------------------------
def _starts(rows):
    return [row.region_start for row in rows]


def _focus_start(app):
    return getattr(app.focused, "region_start", None)


class _ActionRecorder:
    """Replace an app action with a recorder, keeping the binding path intact.

    The claim ``AT-B77-09``/``AT-B77-16`` make is that the APPLICATION action
    still fires, so the action itself is the layer to read. Recording is also
    the only safe way to press ``o``: the shipped ``action_open_workarea``
    launches Explorer as a subprocess.
    """

    def __init__(self, app: S19TuiApp, *actions: str) -> None:
        self.invoked: list[str] = []
        for action in actions:
            setattr(app, f"action_{action}", self._make(action))

    def _make(self, action: str):
        def _record() -> None:
            self.invoked.append(action)

        return _record


# ---------------------------------------------------------------------------
# AT-B77-08 — GATE: real arrow keys move focus, Enter inspects (LLR-115.2/.3)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("size", _SIZES)
def test_b77_keys_arrows_move_focus_and_enter_inspects(
    tmp_path: Path, size
) -> None:
    """AT-B77-08 — ``down``/``down``/``up`` walk the list; ``Enter`` commits.

    Four claims that are only meaningful together:

    - the arrows move focus in ASCENDING ADDRESS ORDER — asserted against the
      mounted order, which is separately asserted to BE ascending, so the
      ordering is a checked precondition rather than an assumption about the
      producer;
    - the arrows move focus ONLY. The selection is still on run 1 after three
      presses, which is what makes the next clause discriminating: without it,
      an implementation that selected on every arrow would satisfy "Enter
      inspects run 2" without ``Enter`` doing anything at all;
    - ``Enter`` then moves the selection to the FOCUSED run — a run that is not
      the auto-selected one, so the observation cannot be satisfied by the
      auto-selection that ran before any key was pressed;
    - ``Enter`` posts ``chain = 1``: ZERO ``OpenInHexRequested``. The absence
      carries its presence co-assertion (the inspector moved) AND a positive
      control that the recorder can see a real post (C-40).
    """
    loaded = _load_case_02()

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app.current_file = loaded
            app.action_show_screen("map")
            panel = _panel(app)
            app.update_memory_map()
            settled = await _settle_selection(pilot, panel)
            rows = _live_rows(app)
            observed = {
                "settled": settled,
                "starts": _starts(rows),
                "auto_selected": panel._selected_cell_start,
                "focus_before": _focus_start(app),
                "focus_is_row": isinstance(app.focused, RegionRow),
            }
            recorder = _PostRecorder(panel)
            await pilot.press("down")
            await pilot.pause()
            observed["focus_after_down"] = _focus_start(app)
            await pilot.press("down")
            await pilot.pause()
            observed["focus_after_down2"] = _focus_start(app)
            await pilot.press("up")
            await pilot.pause()
            observed["focus_after_up"] = _focus_start(app)
            observed["selected_after_arrows"] = panel._selected_cell_start
            observed["focus_live_after_arrows"] = app.focused in set(
                _live_rows(app)
            )

            await pilot.press("enter")
            await pilot.pause()
            observed["selected_after_enter"] = panel._selected_cell_start
            observed["markers_after_enter"] = [
                r.region_start for r in _markers(app)
            ]
            observed["detail"] = app.query_one("#map_detail_body").render().plain
            observed["nav_posts"] = len(recorder.open_in_hex())
            # Positive control for the absence above, captured last: the SAME
            # recorder must observe a real chain-2 activation.
            panel.on_region_row_activated(
                RegionRow.Activated(
                    rows[0].region_start, rows[0].region_end, chain=2
                )
            )
            await pilot.pause()
            observed["nav_after_double"] = len(recorder.open_in_hex())
            return observed

    got = asyncio.run(_drive())

    starts = got["starts"]
    assert got["settled"] and len(starts) >= 3, (
        f"{size}: PRECONDITION — the fixture must render >=3 runs, or "
        f"'down, down, up' cannot distinguish movement from a no-op; got {got}"
    )
    assert starts == sorted(starts), (
        f"{size}: PRECONDITION — the mounted rows must be in ascending address "
        f"order, or 'the next row in ascending address order' and 'the next "
        f"mounted row' are different claims; got {got}"
    )
    assert got["focus_is_row"] and got["focus_before"] == starts[0], (
        f"{size}: PRECONDITION — a region row must hold focus before the first "
        f"key press (LLR-116.5); got {got}"
    )
    assert got["focus_after_down"] == starts[1], (
        f"{size}: `down` must move focus to the NEXT row by address; got {got}"
    )
    assert got["focus_after_down2"] == starts[2], (
        f"{size}: a second `down` must move on again; got {got}"
    )
    assert got["focus_after_up"] == starts[1], (
        f"{size}: `up` must move focus to the PREVIOUS row by address; got {got}"
    )
    assert got["focus_live_after_arrows"], (
        f"{size}: the arrows must land on a row that is LIVE and mounted, not "
        f"merely one whose region_start matches; got {got}"
    )
    assert got["selected_after_arrows"] == got["auto_selected"] == starts[0], (
        f"{size}: the arrows move FOCUS only — the selection must still be on "
        f"run 1, or `Enter`'s effect below cannot be attributed to `Enter`; "
        f"got {got}"
    )
    assert got["selected_after_enter"] == starts[1], (
        f"{size}: `Enter` must inspect the FOCUSED region; got {got}"
    )
    assert got["markers_after_enter"] == [starts[1]], (
        f"{size}: exactly one marker, on the row Enter committed; got {got}"
    )
    assert f"0x{starts[1]:08X}" in got["detail"], (
        f"{size}: the inspector body must NAME the region Enter committed; "
        f"got {got}"
    )
    assert got["nav_posts"] == 0, (
        f"{size}: `Enter` posts chain=1 — inspect, never navigate. "
        f"OpenInHexRequested must not be posted (LLR-115.3); got {got}"
    )
    assert got["nav_after_double"] == 1, (
        f"{size}: CONTROL — the recorder must be able to see a post at all, or "
        f"the zero above is equally consistent with a dead recorder; got {got}"
    )


# ---------------------------------------------------------------------------
# AT-B77-09 — PIN: focus ON a row, no application binding is shadowed
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("size", _SIZES)
def test_b77_keys_no_application_binding_is_shadowed_with_a_row_focused(
    tmp_path: Path, size
) -> None:
    """AT-B77-09 — PIN, not a gate: ``j``/``k``/``o`` still reach the app.

    This node is GREEN before and after Inc-8 and **will never be demonstrated
    RED by the change it guards**. ``RegionRow.BINDINGS`` is ``[]`` today and
    ``LLR-115.4`` keeps it ``[]``, so there is nothing here for the increment
    to break. Its entire falsifiability is its NAMED MUTATION — add
    ``Binding("k", ...)`` to ``RegionRow.BINDINGS`` and it reddens — which is
    executed and recorded at the gate rather than implied here.

    Focus ON a row is the only state in which widget-scoped shadowing can
    occur, and after batch-77 it is the DEFAULT state, which is why this arm
    exists separately from ``AT-B77-16``.

    ``j`` and ``o`` are read at the ACTION layer: the shipped
    ``action_open_workarea`` launches Explorer as a subprocess, so executing it
    for real is not an option. ``k``'s outcome is both safe and observable on
    the shipped surface, so it is asserted there — as a screen push — and is
    pressed LAST because it changes what holds focus.
    """
    loaded = _load_case_02()

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app.current_file = loaded
            app.action_show_screen("map")
            panel = _panel(app)
            app.update_memory_map()
            settled = await _settle_selection(pilot, panel)
            recorder = _ActionRecorder(app, "dump_a2l_json", "open_workarea")
            observed = {
                "settled": settled,
                "bindings_before": list(RegionRow.BINDINGS),
                "focus_is_row": isinstance(app.focused, RegionRow),
                "focus_before": _focus_start(app),
                "selected_before": panel._selected_cell_start,
                "stack_before": [type(s).__name__ for s in app.screen_stack],
            }
            await pilot.press("j")
            await pilot.pause()
            await pilot.press("o")
            await pilot.pause()
            observed["invoked"] = list(recorder.invoked)
            observed["selected_after_jo"] = panel._selected_cell_start
            observed["focus_after_jo"] = _focus_start(app)
            await pilot.press("k")
            await pilot.pause()
            observed["stack_after_k"] = [
                type(s).__name__ for s in app.screen_stack
            ]
            observed["selected_after_k"] = panel._selected_cell_start
            observed["bindings_after"] = list(RegionRow.BINDINGS)
            return observed

    got = asyncio.run(_drive())

    assert got["settled"] and got["focus_is_row"], (
        f"{size}: PRECONDITION — a region row must hold focus, or this node "
        f"tests the state AT-B77-16 already covers and proves nothing new; "
        f"got {got}"
    )
    assert got["bindings_before"] == [] and got["bindings_after"] == [], (
        f"{size}: LLR-115.4 — RegionRow.BINDINGS must be empty before and "
        f"after; a widget binding on j/k/o would shadow the application "
        f"binding for as long as a row holds focus; got {got}"
    )
    assert got["invoked"] == ["dump_a2l_json", "open_workarea"], (
        f"{size}: `j` and `o` must still reach their application actions with "
        f"a region row focused; got {got}"
    )
    assert got["stack_before"] == ["Screen"], (
        f"{size}: PRECONDITION — no modal may be on the stack before `k`; "
        f"got {got}"
    )
    assert got["stack_after_k"][-1] == "LegendScreen", (
        f"{size}: `k` must still push the legend screen; got {got}"
    )
    assert (
        got["selected_before"]
        == got["selected_after_jo"]
        == got["selected_after_k"]
        is not None
    ), f"{size}: none of the three keys may move the map selection; got {got}"
    assert got["focus_after_jo"] == got["focus_before"], (
        f"{size}: nor may they move focus off the row; got {got}"
    )


# ---------------------------------------------------------------------------
# AT-B77-16 — PIN: focus OFF the region list, same three keys
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("size", _SIZES)
def test_b77_keys_no_application_binding_is_shadowed_without_row_focus(
    tmp_path: Path, size
) -> None:
    """AT-B77-16 — PIN. Invariant under Inc-8 BY CONSTRUCTION.

    With no region row focused there is no widget in the resolution chain that
    could carry a binding at all, so this predicate cannot redden for the
    change it guards — it is a PIN for the same reason ``AT-B77-09`` is, one
    step more strongly. It is kept because the two arms answer different
    questions: this one says the pre-batch behaviour is untouched, the other
    says the NEW default focus state did not introduce a shadow.
    """
    loaded = _load_case_02()

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app.current_file = loaded
            app.action_show_screen("map")
            panel = _panel(app)
            app.update_memory_map()
            settled = await _settle_selection(pilot, panel)
            app.set_focus(None)
            await pilot.pause()
            recorder = _ActionRecorder(app, "dump_a2l_json", "open_workarea")
            observed = {
                "settled": settled,
                "focus_is_row": isinstance(app.focused, RegionRow),
                "selected_before": panel._selected_cell_start,
                "stack_before": [type(s).__name__ for s in app.screen_stack],
            }
            await pilot.press("j")
            await pilot.pause()
            await pilot.press("o")
            await pilot.pause()
            observed["invoked"] = list(recorder.invoked)
            await pilot.press("k")
            await pilot.pause()
            observed["stack_after_k"] = [
                type(s).__name__ for s in app.screen_stack
            ]
            observed["selected_after"] = panel._selected_cell_start
            return observed

    got = asyncio.run(_drive())

    assert got["settled"] and not got["focus_is_row"], (
        f"{size}: PRECONDITION — no region row may hold focus, or this node is "
        f"a duplicate of AT-B77-09; got {got}"
    )
    assert got["invoked"] == ["dump_a2l_json", "open_workarea"], (
        f"{size}: `j` and `o` must reach their application actions; got {got}"
    )
    assert got["stack_before"] == ["Screen"], (
        f"{size}: PRECONDITION — no modal on the stack before `k`; got {got}"
    )
    assert got["stack_after_k"][-1] == "LegendScreen", (
        f"{size}: `k` must push the legend screen; got {got}"
    )
    assert got["selected_after"] == got["selected_before"] is not None, (
        f"{size}: none of the three keys may move the map selection; got {got}"
    )


# ---------------------------------------------------------------------------
# TC-B77-16..20 — boundary catalog for HLR-115
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("size", _SIZES)
def test_tc_b77_16_b77_keys_first_and_last_row_edges_do_not_wrap(
    tmp_path: Path, size
) -> None:
    """TC-B77-16 (boundary) — at the first row ``up``, at the last ``down``.

    Both edges are exercised in one node because they are one clause with two
    ends, and because a wraparound implementation fails ONLY at the edges — the
    interior movement AT-B77-08 asserts is identical either way. ``-1`` is a
    legal Python index, so "the previous row" written without a lower-bound
    guard silently means "the last row"; that is the specific defect this node
    exists to catch, and it is asserted as ``focus unchanged``, never as
    ``focus is not the last row``.
    """
    loaded = _load_case_02()

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app.current_file = loaded
            app.action_show_screen("map")
            panel = _panel(app)
            app.update_memory_map()
            settled = await _settle_selection(pilot, panel)
            rows = _live_rows(app)
            observed = {"settled": settled, "starts": _starts(rows)}
            observed["focus_at_first"] = _focus_start(app)
            await pilot.press("up")
            await pilot.pause()
            observed["after_up_at_first"] = _focus_start(app)
            for _ in range(len(rows) - 1):
                await pilot.press("down")
                await pilot.pause()
            observed["focus_at_last"] = _focus_start(app)
            await pilot.press("down")
            await pilot.pause()
            observed["after_down_at_last"] = _focus_start(app)
            return observed

    got = asyncio.run(_drive())

    starts = got["starts"]
    assert got["settled"] and len(starts) >= 2, (
        f"{size}: PRECONDITION — >=2 runs, or first and last are the same row "
        f"and the two edges are indistinguishable; got {got}"
    )
    assert got["focus_at_first"] == starts[0], (
        f"{size}: PRECONDITION — focus must start on the FIRST row; got {got}"
    )
    assert got["after_up_at_first"] == starts[0], (
        f"{size}: `up` at the first row must leave focus unchanged — never "
        f"wrap to the last (index -1); got {got}"
    )
    assert got["focus_at_last"] == starts[-1], (
        f"{size}: PRECONDITION — the walk must reach the LAST row, or the "
        f"bottom edge is never exercised; got {got}"
    )
    assert got["after_down_at_last"] == starts[-1], (
        f"{size}: `down` at the last row must leave focus unchanged — never "
        f"wrap to the first; got {got}"
    )


@pytest.mark.parametrize("size", _SIZES)
def test_tc_b77_17_b77_keys_are_inert_with_no_file_loaded(
    tmp_path: Path, size
) -> None:
    """TC-B77-17 (empty) — no image: the keys raise nothing, select nothing.

    There is no row to focus, so the assertion is about the ABSENCE of a
    fabricated selection, paired with its presence co-assertion: the panel is
    still showing its hint, i.e. it rendered the empty state rather than
    nothing at all.
    """

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app.action_show_screen("map")
            panel = _panel(app)
            app.update_memory_map()
            for _ in range(3):
                await pilot.pause()
            for key in ("down", "up", "enter"):
                await pilot.press(key)
                await pilot.pause()
            return {
                "rows": len(_live_rows(app)),
                "any_region_row": len(app.query(RegionRow)),
                "selected": panel._selected_cell_start,
                "body_is_hint": (
                    app.query_one("#map_detail_body").render().plain
                    == panel._DETAIL_HINT
                ),
            }

    got = asyncio.run(_drive())

    assert got["rows"] == 0 and got["any_region_row"] == 0, (
        f"{size}: PRECONDITION — no file means no region rows; got {got}"
    )
    assert got["body_is_hint"], (
        f"{size}: the empty state must still be rendered — the presence "
        f"co-assertion for the absence below; got {got}"
    )
    assert got["selected"] is None, (
        f"{size}: the arrow and Enter keys must fabricate no selection with no "
        f"image loaded; got {got}"
    )


@pytest.mark.parametrize("size", _SIZES)
def test_tc_b77_18_b77_keys_single_region_has_nowhere_to_move(
    tmp_path: Path, size
) -> None:
    """TC-B77-18 (boundary) — one run: both edges land on the same row.

    With a single row the first and the last row are the same widget, so this
    is the case where an off-by-one in EITHER direction is visible as movement
    where none is possible. ``Enter`` must still inspect it — the row being the
    only one is not a reason for the key to be inert.
    """
    loaded = _blocks_image(tmp_path, "single.s19", [(0x20000, "const")])

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app.current_file = loaded
            app.action_show_screen("map")
            panel = _panel(app)
            app.update_memory_map()
            settled = await _settle_selection(pilot, panel)
            rows = _live_rows(app)
            observed = {"settled": settled, "starts": _starts(rows)}
            await pilot.press("down")
            await pilot.pause()
            observed["after_down"] = _focus_start(app)
            await pilot.press("up")
            await pilot.pause()
            observed["after_up"] = _focus_start(app)
            panel._selected_cell_start = None
            await pilot.press("enter")
            await pilot.pause()
            observed["selected_after_enter"] = panel._selected_cell_start
            return observed

    got = asyncio.run(_drive())

    assert got["settled"] and len(got["starts"]) == 1, (
        f"{size}: PRECONDITION — the fixture must render EXACTLY one run; "
        f"got {got}"
    )
    only = got["starts"][0]
    assert got["after_down"] == only and got["after_up"] == only, (
        f"{size}: with one row both arrows must leave focus on it; got {got}"
    )
    assert got["selected_after_enter"] == only, (
        f"{size}: `Enter` must still inspect the only region — the selection "
        f"was cleared first so this cannot pass on the auto-selection; "
        f"got {got}"
    )


def test_tc_b77_19_b77_keys_enter_on_an_invalidated_row_is_inert(
    tmp_path: Path,
) -> None:
    """TC-B77-19 (invalid) — ``Enter`` on a row a re-render has detached.

    This one boundary is driven by invoking the handler directly rather than
    through the pilot, and the reason is stated rather than hidden: after a
    re-render the panel moves focus to a LIVE row (LLR-116.5), so the shipped
    surface CANNOT deliver a key to a detached row. Driving it through the
    pilot would silently exercise the live row instead and the node would pass
    without ever reaching the state it is named for.

    The stale row's detachment is asserted first, so the node fails loudly if a
    future change makes ``_live_region_rows`` return it after all.
    """
    first = _load_case_02()
    second = _blocks_image(tmp_path, "disjoint.s19", [(0x900000, "high")])

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            app.current_file = first
            app.action_show_screen("map")
            panel = _panel(app)
            app.update_memory_map()
            assert await _settle_selection(pilot, panel)
            stale = _live_rows(app)[0]
            panel._selected_cell_start = None
            app.current_file = second
            app.update_memory_map()
            assert await _settle_selection(pilot, panel)
            observed = {
                "stale_start": stale.region_start,
                "stale_attached": stale.is_attached,
                "stale_in_live": stale in set(_live_rows(app)),
                "live_selection": panel._selected_cell_start,
                "live_starts": _starts(_live_rows(app)),
            }
            raised = None
            try:
                stale.on_key(Key("enter", None))
            except Exception as exc:  # pragma: no cover - the failure path
                raised = f"{type(exc).__name__}: {exc}"
            await pilot.pause()
            observed["raised"] = raised
            observed["selection_after"] = panel._selected_cell_start
            return observed

    got = asyncio.run(_drive())

    assert not got["stale_attached"] and not got["stale_in_live"], (
        f"PRECONDITION — the captured row must be DETACHED after the "
        f"re-render, or this node is exercising a live row; got {got}"
    )
    assert got["stale_start"] not in got["live_starts"], (
        f"PRECONDITION — the stale row's address must be absent from the new "
        f"render, or an inert Enter and a working one are indistinguishable; "
        f"got {got}"
    )
    assert got["raised"] is None, (
        f"`Enter` on an invalidated row must not raise; got {got}"
    )
    assert got["selection_after"] == got["live_selection"], (
        f"nor may it move the selection back to the vanished region; got {got}"
    )


@pytest.mark.parametrize("size", _SIZES)
def test_tc_b77_20_b77_keys_enter_with_no_focus_selects_nothing(
    tmp_path: Path, size
) -> None:
    """TC-B77-20 (boundary) — ``Enter`` with focus off the region list.

    The selection is cleared first so that "the selection did not change" is
    not satisfied by the auto-selection already sitting on run 1 — without
    that, this node would be green on an implementation where ``Enter``
    re-committed run 1 from nowhere.
    """
    loaded = _load_case_02()

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app.current_file = loaded
            app.action_show_screen("map")
            panel = _panel(app)
            app.update_memory_map()
            settled = await _settle_selection(pilot, panel)
            recorder = _PostRecorder(panel)
            app.set_focus(None)
            await pilot.pause()
            panel._selected_cell_start = None
            observed = {
                "settled": settled,
                "focus_is_row": isinstance(app.focused, RegionRow),
            }
            await pilot.press("enter")
            await pilot.pause()
            observed["selected_after"] = panel._selected_cell_start
            observed["markers"] = [r.region_start for r in _markers(app)]
            observed["nav_posts"] = len(recorder.open_in_hex())
            return observed

    got = asyncio.run(_drive())

    assert got["settled"] and not got["focus_is_row"], (
        f"{size}: PRECONDITION — no region row may hold focus; got {got}"
    )
    assert got["selected_after"] is None, (
        f"{size}: `Enter` with no focused row must select nothing; got {got}"
    )
    assert got["nav_posts"] == 0, (
        f"{size}: nor post OpenInHexRequested; got {got}"
    )
