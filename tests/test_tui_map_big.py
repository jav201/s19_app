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
from s19_app.tui.entropy_style import band_style
from s19_app.tui.screens_directionb import (
    BandSegment,
    MemoryMapPanel,
    RegionRow,
    _allocate_band_widths,
    _merge_band_runs,
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
