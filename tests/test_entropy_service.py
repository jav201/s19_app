"""
Unit tests for the headless entropy service — batch-26 US-035
(HLR-035, LLR-035.1..LLR-035.5).

Entropy is a pure arithmetic transform (deterministic, no RNG) so every H
assertion is EXACT: ``abs(H - expected) < 1e-9`` against a hand-computed
reference, never a "non-empty" vacuity. Fixtures are purpose-built in-memory
``mem_map`` dict literals (01b §5 decision) — ``large_s19`` is used ONLY for
the stress-guard window-COUNT check, never for exact H (its random fill gives a
non-uniform, non-exact histogram).

Each test names its AT-035* / TC-035.* id and maps to the LLR it exercises. The
pre-fix counterfactual for every AT-035* is the module-absent ``ImportError``,
satisfied by construction for this NEW module (01b §0, QR-8).
"""

from __future__ import annotations

from math import log2
from pathlib import Path

from s19_app.core import S19File
from s19_app.tui.services.entropy_service import (
    ENTROPY_BANDS,
    ENTROPY_MIN_SAMPLES,
    ENTROPY_WINDOW_BYTES,
    EntropyWindow,
    _derive_ranges,
    classify_band,
    compute_entropy,
)

_TOL = 1e-9


# ---------------------------------------------------------------------------
# AT-035a — constant-fill run → band constant/padding, exact H≈0.0 (LLR-035.3)
# ---------------------------------------------------------------------------
def test_at035a_constant_fill_band_and_zero_entropy() -> None:
    """AT-035a (LLR-035.3): 256×0xFF → 1 window, constant/padding, H==0.0."""
    mem_map = {0x1000 + i: 0xFF for i in range(256)}
    windows = compute_entropy(mem_map)
    assert len(windows) == 1
    (window,) = windows
    assert window.band == "constant/padding"
    assert abs(window.entropy) < _TOL
    assert window.start == 0x1000
    assert window.end == 0x1100
    assert window.sample_count == 256
    assert window.low_confidence is False


# ---------------------------------------------------------------------------
# AT-035b — max-entropy run → band high/random, exact H==8.0 (LLR-035.3)
# ---------------------------------------------------------------------------
def test_at035b_permutation_band_and_max_entropy() -> None:
    """AT-035b (LLR-035.3): 0..255 permutation → 1 window, high/random, H==8.0."""
    mem_map = {0x2000 + i: i for i in range(256)}
    windows = compute_entropy(mem_map)
    assert len(windows) == 1
    (window,) = windows
    assert window.band == "high/random"
    assert abs(window.entropy - 8.0) < _TOL
    assert window.sample_count == 256
    assert window.low_confidence is False


# ---------------------------------------------------------------------------
# AT-035c — mixed image: constant run + gap + high-entropy run (LLR-035.2/.3)
# ---------------------------------------------------------------------------
def test_at035c_mixed_two_ranges_gap_not_straddled() -> None:
    """AT-035c (LLR-035.2/.3): constant@0x3000 + gap + permutation@0x4000 →
    exactly 2 windows (gap NOT straddled), correct bands + H + start addrs."""
    mem_map = {0x3000 + i: 0x00 for i in range(256)}
    mem_map.update({0x4000 + i: i for i in range(256)})
    windows = compute_entropy(mem_map)
    assert len(windows) == 2  # one per range — gap 0x3100..0x3FFF not straddled

    first, second = windows
    assert first.start == 0x3000
    assert first.band == "constant/padding"
    assert abs(first.entropy) < _TOL

    assert second.start == 0x4000
    assert second.band == "high/random"
    assert abs(second.entropy - 8.0) < _TOL


# ---------------------------------------------------------------------------
# AT-035d — final partial window <64B → low-confidence tag (LLR-035.2/.3/.4)
# ---------------------------------------------------------------------------
def test_at035d_partial_final_window_low_confidence() -> None:
    """AT-035d (LLR-035.2/.3/.4): 296-byte range (256 + 40-byte tail =
    20×0xAA+20×0xBB) → 2 windows; window2 = 40B, H==1.0, low_confidence True;
    window1 low_confidence False."""
    mem_map = {0x5000 + i: 0x11 for i in range(256)}  # full window (constant)
    tail = [0xAA] * 20 + [0xBB] * 20  # 40 bytes, 2 symbols equiprobable → H==1.0
    for offset, value in enumerate(tail):
        mem_map[0x5100 + offset] = value

    windows = compute_entropy(mem_map)
    assert len(windows) == 2

    full, partial = windows
    assert full.sample_count == 256
    assert full.low_confidence is False

    assert partial.sample_count == 40
    assert partial.start == 0x5100
    assert partial.end == 0x5128
    assert abs(partial.entropy - 1.0) < _TOL  # computed on 40 present bytes
    assert partial.band == "low"
    assert partial.low_confidence is True


# ---------------------------------------------------------------------------
# AT-035e — empty map → [] (LLR-035.5)
# ---------------------------------------------------------------------------
def test_at035e_empty_map_returns_empty_list() -> None:
    """AT-035e (LLR-035.5): compute_entropy({}) → [], no exception."""
    assert compute_entropy({}) == []


# ---------------------------------------------------------------------------
# TC-035.1 — per-range walk / gap non-straddle: count = Σ ceil(len/256) (LLR-035.2)
# ---------------------------------------------------------------------------
def test_tc035_1_multi_range_window_count_and_containment() -> None:
    """TC-035.1 (LLR-035.2): 3 ranges (300B, 256B, 100B) with gaps → window
    count = ceil(300/256)+ceil(256/256)+ceil(100/256) = 2+1+1 = 4; every
    window's [start,end) lies within exactly one input range."""
    ranges = [(0x1000, 300), (0x8000, 256), (0xC000, 100)]
    mem_map: dict[int, int] = {}
    for base, length in ranges:
        for i in range(length):
            mem_map[base + i] = (base + i) & 0xFF

    windows = compute_entropy(mem_map)
    assert len(windows) == 4

    range_bounds = [(base, base + length) for base, length in ranges]
    for window in windows:
        assert any(
            lo <= window.start and window.end <= hi for lo, hi in range_bounds
        ), f"window [{window.start:#x},{window.end:#x}) straddled a gap"


# ---------------------------------------------------------------------------
# TC-035.2 — band cutoffs via DIRECT float injection, [lo,hi) sided (LLR-035.1)
# ---------------------------------------------------------------------------
def test_tc035_2_band_cutoff_sides_direct_injection() -> None:
    """TC-035.2 (LLR-035.1): classify_band with LITERAL floats pins the
    half-open [lo,hi) cutoff side at 1.0, 5.0, 7.2 — value AT a cutoff → higher
    band. Decoupled from histogram construction (QR-2)."""
    # 1.0 boundary
    assert classify_band(0.9999) == "constant/padding"
    assert classify_band(1.0) == "low"
    assert classify_band(1.0001) == "low"
    # 5.0 boundary
    assert classify_band(4.9999) == "low"
    assert classify_band(5.0) == "medium"
    assert classify_band(5.0001) == "medium"
    # 7.2 boundary
    assert classify_band(7.1999) == "medium"
    assert classify_band(7.2) == "high/random"
    assert classify_band(7.2001) == "high/random"
    # endpoints
    assert classify_band(0.0) == "constant/padding"
    assert classify_band(8.0) == "high/random"


# ---------------------------------------------------------------------------
# TC-035.3 — low-sample tag boundary: 63 vs 64 vs 65 bytes (LLR-035.4)
# ---------------------------------------------------------------------------
def test_tc035_3_low_sample_tag_boundary() -> None:
    """TC-035.3 (LLR-035.4): 63B → low_confidence True; 64B (==floor) → False;
    65B → False. The floor is ENTROPY_MIN_SAMPLES with '< floor' semantics."""
    for length, expected_tag in ((63, True), (64, False), (65, False)):
        mem_map = {0x6000 + i: 0x00 for i in range(length)}
        (window,) = compute_entropy(mem_map)
        assert window.sample_count == length
        assert window.low_confidence is expected_tag, (
            f"{length}B expected low_confidence={expected_tag}"
        )


# ---------------------------------------------------------------------------
# TC-035.4 — degenerate: {} → []; 1-byte range → 1 window H==0.0 low_conf (LLR-035.4/.5)
# ---------------------------------------------------------------------------
def test_tc035_4_degenerate_empty_and_single_byte() -> None:
    """TC-035.4 (LLR-035.4/.5): {} → []; a 1-byte range → 1 window, H==0.0,
    low_confidence True, no div-by-zero."""
    assert compute_entropy({}) == []

    (window,) = compute_entropy({0x7000: 0x42})
    assert window.sample_count == 1
    assert window.start == 0x7000
    assert window.end == 0x7001
    assert abs(window.entropy) < _TOL
    assert window.band == "constant/padding"
    assert window.low_confidence is True


# ---------------------------------------------------------------------------
# TC-035.5 — constants pinned against silent drift (LLR-035.1)
# ---------------------------------------------------------------------------
def test_tc035_5_constants_pinned() -> None:
    """TC-035.5 (LLR-035.1): the named constants match the spec exactly —
    window size, min-samples floor, and the ordered band tuple (incl. the
    8.000001 headroom sentinel)."""
    assert ENTROPY_WINDOW_BYTES == 256
    assert ENTROPY_MIN_SAMPLES == 64
    assert ENTROPY_BANDS == (
        ("constant/padding", 0.0, 1.0),
        ("low", 1.0, 5.0),
        ("medium", 5.0, 7.2),
        ("high/random", 7.2, 8.000001),
    )


# ---------------------------------------------------------------------------
# TC-035.6 — estimator reference: known histograms → exact H (LLR-035.3)
# ---------------------------------------------------------------------------
def test_tc035_6_estimator_reference_values() -> None:
    """TC-035.6 (LLR-035.3): H = -Σ p·log2(p) matches hand-computed refs —
    128×A+128×B → H==1.0; 4 symbols equiprobable (64 each) → H==2.0; 32
    symbols equiprobable (8 each) → H==5.0 == log2(32)."""
    # 128×A + 128×B → 2 equiprobable symbols → log2(2) == 1.0
    two_sym = {0x100 + i: (0x00 if i < 128 else 0x01) for i in range(256)}
    (w2,) = compute_entropy(two_sym)
    assert abs(w2.entropy - 1.0) < _TOL

    # 4 symbols × 64 each → log2(4) == 2.0
    four_sym = {0x200 + i: (i // 64) for i in range(256)}
    (w4,) = compute_entropy(four_sym)
    assert abs(w4.entropy - 2.0) < _TOL

    # 32 symbols × 8 each → log2(32) == 5.0
    thirty_two_sym = {0x300 + i: (i // 8) for i in range(256)}
    (w32,) = compute_entropy(thirty_two_sym)
    assert abs(w32.entropy - 5.0) < _TOL
    assert abs(w32.entropy - log2(32)) < _TOL


# ---------------------------------------------------------------------------
# TC-035.7 — purity probe: no textual import (LLR-035.5)
# ---------------------------------------------------------------------------
def test_tc035_7_service_purity_no_textual_import() -> None:
    """TC-035.7 (LLR-035.5): the service source contains no `import textual` /
    `from textual` — a headless pure-arithmetic module (before_after_service
    purity precedent)."""
    from s19_app.tui.services import entropy_service

    source = Path(entropy_service.__file__).read_text(encoding="utf-8")
    assert "import textual" not in source
    assert "from textual" not in source


# ---------------------------------------------------------------------------
# Result-shape guard — EntropyWindow is frozen with all six fields (LLR-035.5)
# ---------------------------------------------------------------------------
def test_llr035_5_entropy_window_frozen_shape() -> None:
    """LLR-035.5: compute_entropy returns EntropyWindow records (frozen) with
    all six fields set and ascending start order."""
    mem_map = {0x3000 + i: 0x00 for i in range(256)}
    mem_map.update({0x4000 + i: i for i in range(256)})
    windows = compute_entropy(mem_map)

    assert all(isinstance(w, EntropyWindow) for w in windows)
    assert [w.start for w in windows] == sorted(w.start for w in windows)

    window = windows[0]
    try:
        window.entropy = 1.0  # type: ignore[misc]
    except Exception as exc:  # frozen dataclass → FrozenInstanceError
        assert exc.__class__.__name__ == "FrozenInstanceError"
    else:  # pragma: no cover - must be frozen
        raise AssertionError("EntropyWindow is not frozen")


# ---------------------------------------------------------------------------
# Stress guard — large_s19 window COUNT (not exact H), completes fast (LLR-035.2)
# ---------------------------------------------------------------------------
def test_stress_guard_large_s19_window_count(large_s19: Path) -> None:
    """Stress guard (LLR-035.2): the large_s19 fixture parses to 201 contiguous
    ranges — 200 data ranges of 4096 B (each exactly 16 full 256-B windows →
    3200 windows) PLUS the 6-byte S0 header record mapped at address 0 (one
    short window). So the window count derives from the ACTUAL ranges via
    Σ ceil(len/256), asserted against the count computed from the same ranges —
    proving the walk is per-range and gap-safe on a real image, and that it
    completes fast. (Window COUNT, not exact H — large_s19 is random-fill.)"""
    mem_map = S19File(str(large_s19)).get_memory_map()
    windows = compute_entropy(mem_map)

    # Expected count = Σ ceil(len(range)/256) over the ranges the parser built.
    ranges = _derive_ranges(mem_map)
    expected = sum(-(-(end - start) // ENTROPY_WINDOW_BYTES) for start, end in ranges)
    assert len(windows) == expected

    # The fixture is 200 data ranges (16 windows each) + the 6-byte S0 header.
    assert len(ranges) == 201
    assert len(windows) == 200 * 16 + 1  # 3201
    # The 6-byte header window is < 64 B → low-confidence; the 4096-B data
    # windows are all full → not low-confidence.
    low_conf = [w for w in windows if w.low_confidence]
    assert len(low_conf) == 1
    assert low_conf[0].sample_count == 6
