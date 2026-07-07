"""
Headless entropy / band-classification service — s19_app batch-26,
increment 1 (US-035 / HLR-035, LLR-035.1..LLR-035.5).

Computes per-window Shannon entropy over a loaded image's mapped ranges and
classifies each window into one of four bands (``constant/padding`` · ``low`` ·
``medium`` · ``high/random``). A pure arithmetic transform — deterministic, no
RNG (eng-rule 5) — so its outputs are exact and unit-testable to
``abs(H - expected) < 1e-9`` precision.

The service derives contiguous half-open ranges from ``sorted(mem_map)`` the
same way ``core.py:503-514`` does (``(start, prev + 1)``); it imports no parser
and never touches the engine-frozen set. Windows are walked *per contiguous
range* and never span the unmapped gap between two ranges (``core.py:676-678``).

Purity (LLR-035.5, F-S mirror of ``before_after_service.py``): this module
imports no Textual symbol — it is a headless pure-arithmetic module consumed by
the report section (US-037) and the viewer modal (US-036) without pulling any
UI dependency into either consumer's test surface.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import log2
from typing import Dict, List, Tuple

#: Window size, in bytes, over which one entropy value is computed (LLR-035.1).
ENTROPY_WINDOW_BYTES = 256

#: Low-sample floor: a window with fewer than this many present bytes is tagged
#: ``low_confidence`` but never dropped (LLR-035.1 / LLR-035.4).
ENTROPY_MIN_SAMPLES = 64

#: Ordered ``(label, lo, hi)`` band cutoffs with half-open ``[lo, hi)`` lookup:
#: a value equal to a cutoff falls in the HIGHER band (LLR-035.1). The
#: ``8.000001`` upper bound is a headroom sentinel — not a reachable entropy
#: value — guaranteeing the maximum ``H == 8.0`` (a uniform 256-value window)
#: lands inside ``[7.2, 8.000001)`` = ``high/random``. This tuple is the single
#: source of the cutoffs referenced by HLR-035.
ENTROPY_BANDS: Tuple[Tuple[str, float, float], ...] = (
    ("constant/padding", 0.0, 1.0),
    ("low", 1.0, 5.0),
    ("medium", 5.0, 7.2),
    ("high/random", 7.2, 8.000001),
)


@dataclass(frozen=True)
class EntropyWindow:
    """
    Summary:
        One computed entropy window — the immutable record ``compute_entropy``
        returns per 256-byte (or final-partial) window (LLR-035.5).

    Args:
        start (int): Inclusive start address of the window.
        end (int): Exclusive end address of the window (``start + sample_count``).
        sample_count (int): Number of present bytes the window covers
            (``ENTROPY_WINDOW_BYTES`` for a full window; fewer for the final
            partial window of a range).
        entropy (float): Shannon entropy ``H = -Σ p·log2(p)`` in bits/byte on a
            0.0–8.0 scale (LLR-035.3); ``0.0`` for a constant-fill window.
        band (str): The band label from :data:`ENTROPY_BANDS` whose half-open
            ``[lo, hi)`` interval contains ``entropy``.
        low_confidence (bool): ``True`` when ``sample_count`` is below
            :data:`ENTROPY_MIN_SAMPLES` (LLR-035.4); the window is still
            returned with its computed band.

    Returns:
        None: Dataclass container.

    Data Flow:
        - Produced by :func:`compute_entropy`, one per window, in ascending
          address order.
        - Consumed by the report section (US-037) and the viewer modal
          (US-036) as their per-window data source.

    Dependencies:
        Used by:
            - compute_entropy
    """

    start: int
    end: int
    sample_count: int
    entropy: float
    band: str
    low_confidence: bool


def classify_band(entropy: float) -> str:
    """
    Summary:
        Map an entropy value to its band label using the half-open
        ``[lo, hi)`` semantics of :data:`ENTROPY_BANDS` (LLR-035.1): a value
        equal to a cutoff falls in the higher band.

    Args:
        entropy (float): A Shannon entropy value in bits/byte (0.0–8.0).

    Returns:
        str: The band label whose ``[lo, hi)`` interval contains ``entropy``.
        Values at or above the top cutoff (via the ``8.000001`` headroom
        sentinel) return ``high/random``; a value below ``0.0`` (never produced
        by the estimator) falls through to the first band.

    Data Flow:
        - Called once per window by :func:`compute_entropy` after the histogram
          estimate; also called directly by the band-cutoff unit tests
          (TC-035.2) with literal floats to pin the ``[lo, hi)`` cutoff side.

    Dependencies:
        Uses:
            - ENTROPY_BANDS
        Used by:
            - compute_entropy
            - tests/test_entropy_service.py

    Example:
        >>> classify_band(7.2)
        'high/random'
        >>> classify_band(1.0)
        'low'
    """
    for label, lo, hi in ENTROPY_BANDS:
        if lo <= entropy < hi:
            return label
    return ENTROPY_BANDS[-1][0]


def _derive_ranges(mem_map: Dict[int, int]) -> List[Tuple[int, int]]:
    """
    Summary:
        Derive contiguous half-open ``(start, end_exclusive)`` ranges from a
        sparse memory map, exactly as ``core.py:503-514`` builds them —
        ``(start, prev + 1)`` per run of consecutive addresses (LLR-035.2). The
        service derives ranges itself rather than importing a parser
        (``report_service`` imports no parser either).

    Args:
        mem_map (Dict[int, int]): Sparse address→byte map (may be empty).

    Returns:
        List[Tuple[int, int]]: Ascending contiguous ranges; ``[]`` for an empty
        map. Every address in ``range(start, end)`` is present in ``mem_map``.

    Data Flow:
        - Sorts ``mem_map`` keys once, then walks the sorted list splitting on
          each non-consecutive address.

    Dependencies:
        Used by:
            - compute_entropy
    """
    addresses = sorted(mem_map)
    if not addresses:
        return []
    ranges: List[Tuple[int, int]] = []
    start = addresses[0]
    prev = addresses[0]
    for addr in addresses[1:]:
        if addr == prev + 1:
            prev = addr
        else:
            ranges.append((start, prev + 1))
            start = addr
            prev = addr
    ranges.append((start, prev + 1))
    return ranges


def _window_entropy(mem_map: Dict[int, int], start: int, end: int) -> float:
    """
    Summary:
        Compute the Shannon entropy ``H = -Σ p·log2(p)`` (bits/byte) over the
        bytes present in ``mem_map`` for the half-open window ``[start, end)``
        via a 256-bin byte-value histogram over the occupied bins only
        (LLR-035.3). A constant-fill window yields ``0.0``.

    Args:
        mem_map (Dict[int, int]): The sparse address→byte map; every address in
            ``[start, end)`` is present (the window lies within one derived
            range).
        start (int): Inclusive window start address.
        end (int): Exclusive window end address.

    Returns:
        float: The entropy in bits/byte, bounded ``0.0 ≤ H ≤ 8.0``; only
        occupied histogram bins contribute.

    Data Flow:
        - Builds a 256-entry count histogram, then sums ``-p·log2(p)`` over the
          non-zero counts with ``p = count / sample_count``.

    Dependencies:
        Uses:
            - math.log2
        Used by:
            - compute_entropy
    """
    counts = [0] * 256
    for addr in range(start, end):
        counts[mem_map[addr]] += 1
    sample_count = end - start
    entropy = 0.0
    for count in counts:
        if count:
            probability = count / sample_count
            entropy -= probability * log2(probability)
    return entropy


def compute_entropy(mem_map: Dict[int, int]) -> List[EntropyWindow]:
    """
    Summary:
        Compute per-window Shannon entropy over a sparse memory map's mapped
        ranges and classify each window into an :data:`ENTROPY_BANDS` band
        (HLR-035, LLR-035.1..LLR-035.5). Ranges are derived from
        ``sorted(mem_map)`` and windows are walked *per contiguous range* in
        ``ENTROPY_WINDOW_BYTES`` strides, so no window ever spans the unmapped
        gap between two ranges; the final partial window of a range covers only
        its residual bytes.

    Args:
        mem_map (Dict[int, int]): Sparse address→byte map (a validated in-memory
            structure — ``LoadedFile.mem_map`` / ``VariantExecutionResult
            .mem_map``). May be empty.

    Returns:
        List[EntropyWindow]: One record per window in ascending address order,
        each carrying ``(start, end, sample_count, entropy, band,
        low_confidence)``. An empty ``mem_map`` returns ``[]``.

    Data Flow:
        - ``mem_map`` → :func:`_derive_ranges` → for each range, step
          ``start → end`` in ``ENTROPY_WINDOW_BYTES`` strides →
          :func:`_window_entropy` per window → :func:`classify_band` →
          low-sample tag (``sample_count < ENTROPY_MIN_SAMPLES``) →
          :class:`EntropyWindow`.

    Dependencies:
        Uses:
            - _derive_ranges / _window_entropy / classify_band
            - EntropyWindow / ENTROPY_WINDOW_BYTES / ENTROPY_MIN_SAMPLES
        Used by:
            - s19_app.tui.services.report_service (US-037, later increment)
            - s19_app.tui.screens.EntropyViewerScreen (US-036, later increment)
            - tests/test_entropy_service.py

    Example:
        >>> compute_entropy({0x1000 + i: 0xFF for i in range(256)})[0].band
        'constant/padding'
        >>> compute_entropy({})
        []
    """
    windows: List[EntropyWindow] = []
    for range_start, range_end in _derive_ranges(mem_map):
        window_start = range_start
        while window_start < range_end:
            window_end = min(window_start + ENTROPY_WINDOW_BYTES, range_end)
            sample_count = window_end - window_start
            entropy = _window_entropy(mem_map, window_start, window_end)
            windows.append(
                EntropyWindow(
                    start=window_start,
                    end=window_end,
                    sample_count=sample_count,
                    entropy=entropy,
                    band=classify_band(entropy),
                    low_confidence=sample_count < ENTROPY_MIN_SAMPLES,
                )
            )
            window_start = window_end
    return windows
