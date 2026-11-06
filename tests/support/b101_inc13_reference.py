"""The base `_sweep` and `_conflict_marks` of the Split/Join preview, kept as
the oracle of the band's invariance (batch-101 Inc 13, E1-D6).

The two function bodies below are copied VERBATIM from
``s19_app/tui/segment_split_view.py`` at commit ``b7b77c4`` (lines 288-351);
only the two names change (``_sweep`` -> ``reference_sweep``,
``_conflict_marks`` -> ``reference_conflict_marks``). Do not edit them: a
reference that follows the product cannot fail when the product is wrong.
``Block`` is the product's own data class (unchanged by Inc 13).
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from s19_app.tui.segment_split_view import Block


def reference_sweep(lo: int, hi: int, marks: List[Tuple[int, int, str]]) -> List[Block]:
    """Classify ``[lo, hi)`` by priority marks; merge adjacent equal classes.

    Priority: data > conflict > fill > ctx — a cell never mixes classes and
    adjacent equal classes coalesce BY CONSTRUCTION (one styled span per
    block, the run-economy law of LLR-135.2).
    """
    cuts = {lo, hi}
    for a, b, _ in marks:
        cuts.add(max(lo, min(a, hi)))
        cuts.add(max(lo, min(b, hi)))
    pts = sorted(cuts)
    prio = {"data": 4, "conflict": 3, "fill": 2, "ctx": 1}
    blocks: List[Block] = []
    for a, b in zip(pts, pts[1:]):
        if a >= b:
            continue
        best = "none"
        for s, e, cls in marks:
            if s < b and e > a and prio[cls] > prio.get(best, 0):
                best = cls
        if blocks and blocks[-1].cls == best:
            blocks[-1].size += b - a
        else:
            blocks.append(Block(best, b - a))
    return blocks


def reference_conflict_marks(
    mem_map: Dict[int, int],
    src: List[Tuple[int, int]],
    picked_spans: List[Tuple[int, int]],
    pad_byte: int,
) -> List[Tuple[int, int, str]]:
    """The ``▒`` marks: present source bytes inside a JOIN-fill padded gap
    that DIFFER from the pad byte — exactly the predicate of the shipped
    ``gap_conflict`` detector (the engine's abort law, ruling 8f), swept over
    the source∩gap intersections only (bounded by the SOURCE size, never the
    gap size — the guard case's 402 MiB gap must not be walked per byte).
    Equivalence with ``gap_conflict`` is pinned in tests/test_segment_ops.py's
    sibling (tests/test_segment_split_window.py, TC-710 battery).
    """
    spans = sorted(picked_spans)
    merged: List[Tuple[int, int]] = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    marks: List[Tuple[int, int, str]] = []
    prev_end: Optional[int] = None
    for start, end in merged:
        if prev_end is not None and start > prev_end:
            g_lo, g_hi = prev_end, start
            for s, e in src:
                lo, hi = max(g_lo, s), min(g_hi, e)
                for addr in range(lo, hi):
                    if addr in mem_map and mem_map[addr] != pad_byte:
                        if marks and marks[-1][1] == addr:
                            marks[-1] = (marks[-1][0], addr + 1, "conflict")
                        else:
                            marks.append((addr, addr + 1, "conflict"))
        prev_end = end
    return marks
