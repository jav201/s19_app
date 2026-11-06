"""Batch-101 increment 13 - the Split/Join preview band is unchanged by the
faster sweep (finding F-23, ``_sweep`` and ``_conflict_marks``).

Written by the independent tester (E4) from the approved design only
(``inc-13/01-requirements.md``, ``02-test-cases.md``, ``E1-slice.md``,
``E1-rulings.md`` E1-D6, ``codewire/graph-inc13.md`` and the E3 ruling SEC-6).
No line of the Inc 13 implementation was read.

Two oracles, as decision E1-D6 rules:

- for join fill (where the conflict class lives) the band is compared with a
  per-address classifier written here from the CTX-SJE-BAND classes (data >
  conflict > fill > context > absent), independent of the product code;
- for every mode, the plan is compared with the BASE reference: the base
  ``_sweep`` and ``_conflict_marks`` copied verbatim into
  ``tests/support/b101_inc13_reference.py`` and patched into ``build_plan``
  (the split-mode skip band, D17-24, differs from the canon on purpose until a
  UI round fixes it, so the invariance oracle is the base plan and not the
  canon classifier alone).

The nodes assert the plan a user sees (band blocks, per-file blocks, counters,
conflict marks), never the call sequence. They pass on the base tree (nothing
may change); they are RED against the mutants listed per node.
"""
from __future__ import annotations

import random
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import pytest

from s19_app.tui import segment_split_view as ssv
from s19_app.tui.operations.crc_designer_model import CrcTarget, gap_conflict
from s19_app.tui.segment_split_view import SegRow, build_plan
from tests.support.b101_demo_image import demo_mem_map
from tests.support.b101_inc13_reference import (
    reference_conflict_marks,
    reference_sweep,
)

Marks = List[Tuple[int, int, str]]
MODES = (("split", "skip"), ("split", "fill"), ("join", "concat"), ("join", "fill"))


# ---------------------------------------------------------------------------
# Seeded images
# ---------------------------------------------------------------------------
def _random_image(seed: int, touching: bool = False):
    """``(rows, src, mem_map, pad)`` for one seeded image: 1 to 6 source ranges
    of 1 to 96 bytes with gaps of 0 to 64 bytes (``touching``: every gap 0, so
    ``end == next start``), byte values drawn so runs equal to the pad occur,
    and rows that are the source ranges plus, sometimes, a manual row that
    reaches outside the source."""
    rng = random.Random(seed)
    pad = rng.choice((0x00, 0xFF))
    src: List[Tuple[int, int]] = []
    cursor = rng.randrange(0, 0x40)
    for _ in range(rng.randint(1, 6)):
        size = rng.randint(1, 96)
        src.append((cursor, cursor + size))
        cursor += size + (0 if touching else rng.randint(0, 64))
    mem: Dict[int, int] = {}
    for start, end in src:
        address = start
        while address < end:
            run = rng.randint(1, 12)
            value = pad if rng.random() < 0.45 else rng.randrange(256)
            for a in range(address, min(end, address + run)):
                mem[a] = value
            address += run
    rows = [SegRow(f"range_{i:02d}", "ranges", s, e - s) for i, (s, e) in enumerate(src)]
    if rng.random() < 0.4:
        base = rng.randrange(0, cursor + 32)
        rows.append(SegRow("manual_00", "manual", base, rng.randint(1, 80)))
    return rows, src, mem, pad


def _random_ticks(seed: int, count: int) -> Set[int]:
    rng = random.Random(seed * 7919 + 1)
    return set(rng.sample(range(count), rng.randint(1, count)))


def _blocks(blocks) -> List[Tuple[str, int]]:
    return [(b.cls, b.size) for b in blocks]


def _plan_view(plan) -> dict:
    """Everything the preview shows of a plan, as plain data."""
    return {
        "map_blocks": _blocks(plan.map_blocks),
        "files": [
            (f.label, _blocks(f.blocks), f.packed, f.pad, f.conflicts, f.empty)
            for f in plan.files
        ],
        "band": (plan.band_lo, plan.band_hi),
        "packed": plan.packed,
        "span": plan.span,
        "fill": plan.fill,
        "conflicts": plan.conflicts,
        "empty_files": plan.empty_files,
        "address_preserving": plan.address_preserving,
        "nothing_selected": plan.nothing_selected,
        "guard": plan.guard,
    }


def _build(rows, ticks, src, mem, mode, gap, pad):
    return build_plan(
        rows, ticks, src, mem, mode=mode, gap=gap, stem="t", ext="s19", pad_byte=pad
    )


# ---------------------------------------------------------------------------
# R-SEG-PREV.2/1 - join fill band == the per-address classifier
# ---------------------------------------------------------------------------
def _canon_classes(rows, ticks, src, mem, pad) -> Optional[Tuple[int, List[Tuple[str, int]]]]:
    """The band of a join-fill plan, written from CTX-SJE-BAND: for every address
    of the band span the class the planned export gives it. Priority data >
    conflict > fill > context > absent; run-length encoded."""
    picked = [rows[i] for i in sorted(ticks)]
    spans = sorted((r.base, r.base + r.size) for r in picked)
    span_lo = min(s for s, _ in spans)
    span_hi = max(e for _, e in spans)
    src_lo = min(s for s, _ in src)
    src_hi = max(e for _, e in src)
    lo, hi = min(span_lo, src_lo), max(span_hi, src_hi)

    def in_source(a: int) -> bool:
        return any(s <= a < e for s, e in src)

    def in_picked(a: int) -> bool:
        return any(s <= a < e for s, e in spans)

    runs: List[Tuple[str, int]] = []
    for a in range(lo, hi):
        if in_picked(a) and in_source(a):
            cls = "data"
        elif (
            span_lo <= a < span_hi and not in_picked(a) and a in mem and mem[a] != pad
        ):
            cls = "conflict"
        elif span_lo <= a < span_hi:
            cls = "fill"
        elif in_source(a):
            cls = "ctx"
        else:
            cls = "none"
        if runs and runs[-1][0] == cls:
            runs[-1] = (cls, runs[-1][1] + 1)
        else:
            runs.append((cls, 1))
    return lo, runs


@pytest.mark.parametrize("chunk", range(4))
def test_r_seg_prev_2_join_fill_band_matches_the_canon_classifier(chunk: int) -> None:
    """200 seeded images (4 chunks of 50), join fill, pad 0x00 or 0xFF drawn per
    image, random non-empty ticks: the band's blocks equal the run length of the
    per-address classes data > conflict > fill > context > absent over the band
    span, 200 of 200.

    Why: the band is what the operator reads before an export; a sweep that
    kept the wrong class where marks overlap would paint a clobbered byte as
    safe. Negative controls: a sweep that keeps the lowest priority -> RED; a
    run finder that counts pad-valued bytes as conflict -> RED."""
    for seed in range(chunk * 50, chunk * 50 + 50):
        rows, src, mem, pad = _random_image(seed)
        ticks = _random_ticks(seed, len(rows))
        plan = _build(rows, ticks, src, mem, "join", "fill", pad)
        lo, runs = _canon_classes(rows, ticks, src, mem, pad)
        assert plan.band_lo == lo, f"seed {seed}"
        assert _blocks(plan.map_blocks) == runs, f"seed {seed} pad {pad:#04x}"


# ---------------------------------------------------------------------------
# R-SEG-PREV.2/2 - every plan == the base reference's plan
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("mode,gap", MODES, ids=lambda v: str(v))
def test_r_seg_prev_2_plan_matches_the_base_reference_in_every_mode(
    monkeypatch: pytest.MonkeyPatch, mode: str, gap: str
) -> None:
    """The same 200 images plus 20 with touching source ranges (``end == next
    start``), every mode and gaps value, random ticks: the plan built by the
    product (band blocks, every file's blocks and counters, packed, span, fill,
    conflicts, guard) equals the plan built with the base ``_sweep`` and
    ``_conflict_marks`` patched in, 220 of 220 per mode.

    Why: the increment must change no render. Negative controls: a run finder
    that does not join a run across touching source ranges -> RED; a sweep that
    keeps the lowest priority -> RED."""
    cases = [(seed, False) for seed in range(200)] + [
        (1000 + seed, True) for seed in range(20)
    ]
    for seed, touching in cases:
        rows, src, mem, pad = _random_image(seed, touching)
        ticks = _random_ticks(seed, len(rows))
        got = _plan_view(_build(rows, ticks, src, mem, mode, gap, pad))
        with monkeypatch.context() as patch:
            patch.setattr(ssv, "_sweep", reference_sweep)
            patch.setattr(ssv, "_conflict_marks", reference_conflict_marks)
            want = _plan_view(_build(rows, ticks, src, mem, mode, gap, pad))
        assert got == want, f"seed {seed} touching={touching} {mode}/{gap}"
    # the ticks-free corner: nothing selected is a plan too
    rows, src, mem, pad = _random_image(3)
    with monkeypatch.context() as patch:
        patch.setattr(ssv, "_sweep", reference_sweep)
        want = _plan_view(_build(rows, set(), src, mem, mode, gap, pad))
    assert _plan_view(_build(rows, set(), src, mem, mode, gap, pad)) == want


# ---------------------------------------------------------------------------
# R-SEG-PREV.2/3 - the demo scene's conflict marks
# ---------------------------------------------------------------------------
def test_r_seg_prev_2_demo_scene_marks_match_the_per_byte_reference() -> None:
    """The F-23 Split/Join scene (boot and cal ticked, the app region in the join
    gap, pad 0x00): ``_conflict_marks`` equals the base per-byte reference
    exactly, as a list, and the marks' total size equals the engine detector's
    count ``len(gap_conflict(...))`` (1 of 1).

    Why: the app region's bytes break into many conflict runs wherever a byte
    equals the pad; the fast run finder must report the same runs. Negative
    control: a run finder that counts pad-valued bytes -> RED."""
    mem = demo_mem_map()
    src = [
        (0x00000000, 0x00010000),
        (0x00040000, 0x00040000 + 0x2C9FA0),
        (0x00800000, 0x00800000 + 0x131FC0),
        (0x00C00000, 0x00C01000),
    ]
    picked = [(0x0, 0x10000), (0x800000, 0x931FC0)]
    marks = ssv._conflict_marks(mem, src, picked, 0x00)
    assert marks == reference_conflict_marks(mem, src, picked, 0x00)
    engine = gap_conflict(
        mem,
        CrcTarget(tuple(picked), "skip", "fill", 0x00, 0, 1, "little"),
    )
    assert sum(e - s for s, e, _ in marks) == len(engine) > 0
    assert all(cls == "conflict" for _, _, cls in marks)


# ---------------------------------------------------------------------------
# R-SEG-PREV.2/4 - the sweep with many marks
# ---------------------------------------------------------------------------
def test_r_seg_prev_2_sweep_with_5000_marks_matches_the_reference() -> None:
    """5000 random marks of the four classes over ``[0, 1 000 000)`` (seed 7):
    ``_sweep(0, 1_000_000, marks)`` equals the base ``_sweep`` block for block
    (1 of 1).

    Why: the base sweep is quadratic in the marks and the design replaces it
    with a pass over sorted boundaries; with this many marks every overlap and
    every priority tie is exercised. Negative control: a sweep that keeps the
    lowest priority, or loses a block at a boundary -> RED."""
    rng = random.Random(7)
    marks: Marks = []
    for _ in range(5000):
        a = rng.randrange(0, 1_000_000)
        b = min(1_000_000, a + rng.randint(1, 4000))
        marks.append((a, b, rng.choice(("data", "conflict", "fill", "ctx"))))
    got = _blocks(ssv._sweep(0, 1_000_000, marks))
    want = _blocks(reference_sweep(0, 1_000_000, marks))
    assert got == want
    assert sum(size for _, size in got) == 1_000_000
    assert len({cls for cls, _ in got}) >= 4, "all four classes must occur"


# ---------------------------------------------------------------------------
# R-SEG-PREV.2/5 - the run pattern for every pad byte (E3 ruling SEC-6)
# ---------------------------------------------------------------------------
def test_r_seg_prev_2_conflict_marks_match_the_reference_for_every_pad() -> None:
    """One seeded image (``random.Random(256)``): three source ranges of 512
    bytes with 16-byte gaps, the middle range's bytes ``bytes(range(256)) * 2``
    shuffled by the seed (every value 0 ... 255 present); picked spans cover the
    first and the last range. For every pad byte ``0x00`` ... ``0xFF``,
    ``_conflict_marks`` equals the base reference as a list, 256 of 256.

    Why: the run pattern is built from the pad byte; a byte that is special in
    a regular expression (``0x5C``, ``0x5B``, ``0x5E``, ``0x2D``, ``0x0A`` ...)
    must be matched literally and a letter must not match its other case.
    Negative controls: the pad put unescaped into the pattern -> RED at pad
    ``0x5C`` (``re.error``); the pattern compiled with ``re.IGNORECASE`` -> RED
    at the ASCII letters."""
    rng = random.Random(256)
    first, middle, last = (0x1000, 0x1200), (0x1210, 0x1410), (0x1420, 0x1620)
    src = [first, middle, last]
    middle_bytes = list(bytes(range(256)) * 2)
    rng.shuffle(middle_bytes)
    mem: Dict[int, int] = {}
    for start, end in (first, last):
        for a in range(start, end):
            mem[a] = rng.randrange(256)
    for offset, value in enumerate(middle_bytes):
        mem[middle[0] + offset] = value
    picked = [(first[0], first[1] - 0x10), (last[0] + 0x10, last[1])]
    for pad in range(256):
        got = ssv._conflict_marks(mem, src, picked, pad)
        assert got == reference_conflict_marks(mem, src, picked, pad), f"pad {pad:#04x}"
    # the image is not degenerate: the middle range lies in the gap and conflicts
    assert ssv._conflict_marks(mem, src, picked, 0x41)
