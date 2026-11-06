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

import asyncio
import random
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import pytest

from s19_app.tui import segment_split_view as ssv
from s19_app.tui.app import S19TuiApp
from s19_app.tui.models import LoadedFile
from s19_app.tui.operations.crc_designer_model import CrcTarget, gap_conflict
from s19_app.tui.segment_split_view import (
    GUARD_SPAN_MIN,
    SegRow,
    SplitJoinWindow,
    build_plan,
    fmtB,
)
from tests.support.b101_demo_image import demo_loaded_file, demo_mem_map
from tests.support.b101_inc13_reference import (
    reference_conflict_marks,
    reference_sweep,
)
from tests.support.timing import wait_until

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


# ---------------------------------------------------------------------------
# E5 corrective (C-2, E5-CR-2) - the sweep's three hand examples of the graph
# ---------------------------------------------------------------------------
def test_r_seg_prev_2_sweep_hand_examples_skip_empty_inverted_and_outside_marks() -> None:
    """The three hand examples of graph node ``_sweep`` (R-SEG-PREV.2/4), as
    exact block lists, each also equal to the base ``_sweep``:

    - nested marks of the four classes keep the highest priority per interval;
    - one data mark inside ``[0, 4)`` leaves ``none`` around it;
    - a mark reaching outside the window is clamped, and an empty mark
      ``(2, 2)`` and an inverted mark ``(3, 1)`` cover nothing.

    Why: the faster sweep adds a class at a mark's start and removes it at its
    end; without the skip of empty and inverted marks, the inverted mark's end
    is processed before its start, so the per-class count goes wrong (a
    ``KeyError`` or a class left alive). Negative control: remove
    ``if cs >= ce: continue`` in ``_sweep`` -> the third list differs or raises."""
    cases = [
        (
            (0, 10, [(0, 10, "ctx"), (2, 8, "fill"), (4, 5, "conflict"), (3, 6, "data")]),
            [("ctx", 2), ("fill", 1), ("data", 3), ("fill", 2), ("ctx", 2)],
        ),
        ((0, 4, [(1, 2, "data")]), [("none", 1), ("data", 1), ("none", 2)]),
        (
            (0, 4, [(-5, 1, "fill"), (3, 9, "conflict"), (2, 2, "data"), (3, 1, "data")]),
            [("fill", 1), ("none", 2), ("conflict", 1)],
        ),
    ]
    for (lo, hi, marks), want in cases:
        assert _blocks(ssv._sweep(lo, hi, list(marks))) == want, marks
        assert _blocks(reference_sweep(lo, hi, list(marks))) == want, marks


# ---------------------------------------------------------------------------
# E5 corrective (C-1, E4-F1 / E5-CR-1, D17-27) - the state line puts a conflict
# before the span guard (canon R-SEG-PREV.7 / .8)
# ---------------------------------------------------------------------------
#: The F-23 Split/Join scene's picked spans (``range_00`` boot, ``range_02`` cal).
F23_PICKED = ((0x0, 0x10000), (0x800000, 0x931FC0))
#: The small guard scene: two 64-byte islands at the ends of a span just over
#: the guard's 1 MiB and, with a conflict, a 4-byte source range in the gap.
GUARD_SCENE_SPAN = GUARD_SPAN_MIN + 16
GUARD_SCENE_BASE = 0x1000


def _f23_conflict_bytes() -> int:
    return len(
        gap_conflict(
            demo_mem_map(), CrcTarget(F23_PICKED, "skip", "fill", 0x00, 0, 1, "little")
        )
    )


def _guard_scene(with_conflict: bool) -> LoadedFile:
    """A join-fill scene whose span guard fires (span ``GUARD_SPAN_MIN + 16``,
    fill above 99 %): ``range_00`` and the last range are the two islands;
    with ``with_conflict`` a middle source range of four ``0x55`` bytes lies in
    the join gap (4 conflict bytes against pad ``0x00``)."""
    lo = GUARD_SCENE_BASE
    hi_start = GUARD_SCENE_BASE + GUARD_SCENE_SPAN - 64
    ranges = [(lo, lo + 64)]
    mem = {lo + i: 0xA0 + (i % 16) for i in range(64)}
    if with_conflict:
        middle = GUARD_SCENE_BASE + GUARD_SCENE_SPAN // 2
        ranges.append((middle, middle + 4))
        mem.update({middle + i: 0x55 for i in range(4)})
    ranges.append((hi_start, hi_start + 64))
    mem.update({hi_start + i: 0xB0 + (i % 16) for i in range(64)})
    return LoadedFile(
        path=Path("guard.s19"),
        file_type="s19",
        mem_map=mem,
        row_bases=[],
        ranges=ranges,
        range_validity=[True] * len(ranges),
        errors=[],
        a2l_path=None,
        a2l_data=None,
    )


def _stats_lines(app: S19TuiApp) -> List[str]:
    return [line.rstrip() for line in str(app.query_one("#sje_stats").render()).split("\n")]


def _window(app: S19TuiApp) -> SplitJoinWindow:
    return app.query_one("#screen_split_join", SplitJoinWindow)


async def _join_fill(pilot, app: S19TuiApp) -> None:
    """``m`` (join, concat) then ``g`` (fill), each waited on its effect."""
    window = _window(app)
    await pilot.press("m")
    await wait_until(pilot, lambda: window._mode == "join", "m set join", pause_first=True)
    await pilot.press("g")
    await wait_until(
        pilot,
        lambda: window._gap == "fill" and len(_stats_lines(app)) >= 2,
        "g set fill and painted the stats",
        pause_first=True,
    )


async def _open_by_action_and_tick(pilot, app: S19TuiApp, ticks: Set[int]) -> SplitJoinWindow:
    """Open the window the palette's way (its action), tick ``ticks`` on the
    ranges tab, then ``m`` and ``g``."""
    app.action_open_split_join_export()
    await wait_until(
        pilot,
        lambda: bool(app.query("#screen_split_join")) and bool(_window(app)._range_rows()),
        "the Split / Join / Export window with its ranges rows",
        pause_first=True,
    )
    _window(app)._sel["ranges"] = set(ticks)
    await _join_fill(pilot, app)
    return _window(app)


def test_r_seg_prev_7_f23_scene_state_line_is_the_clobber_line(tmp_path: Path) -> None:
    """The F-23 Split/Join scene (demo image; ``range_00`` and ``range_02``
    ticked; ``m``, ``g``): the plan has conflict bytes AND a firing span guard,
    and the state line under the stats is ``⚠ <size> would clobber source —
    abort on export`` with ``<size>`` = ``fmtB`` of the engine detector's count
    (canon R-SEG-PREV.7), not the GUARD chip.

    Why: ``e`` refuses this export on its conflicts (LLR-136.4); a state line
    naming the guard told the operator the export would ask, when it will
    refuse. Negative control: the guard checked before the conflicts in
    ``_state_text`` (the shipped order before E5, finding E4-F1) -> the GUARD
    chip -> RED."""
    conflicts = _f23_conflict_bytes()
    assert conflicts > 0

    async def drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            app.current_file = demo_loaded_file()
            window = await _open_by_action_and_tick(pilot, app, {0, 2})
            plan = window._plan(window._rows())
            return plan.guard, plan.conflicts, _stats_lines(app)

    guard, plan_conflicts, lines = asyncio.run(drive())
    assert guard is True, "the scene's span guard must fire (the priority case)"
    assert plan_conflicts == conflicts
    assert lines[0].startswith("packed 1.26 MiB  ·  span 9.20 MiB  ·  fill "), lines
    assert lines[1] == f"⚠ {fmtB(conflicts)} would clobber source — abort on export", lines


def test_r_seg_prev_7_8_state_line_priority_conflict_over_guard(tmp_path: Path) -> None:
    """The small guard scene, join fill: (a) guard and 4 conflict bytes -> the
    state line is exactly ``⚠ 4 B would clobber source — abort on export``
    (R-SEG-PREV.7); (b) the same scene without the conflict range -> exactly
    ``⚠ GUARD  <fmtB(span)> span — e will ask`` (R-SEG-PREV.8: guard and no
    conflict byte).

    Why: the canon orders the two lines (a conflict hides the guard, never the
    reverse); (b) proves the reorder did not drop the guard chip. Negative
    control: the guard first -> (a) RED; the guard branch removed -> (b) RED."""

    async def drive(with_conflict: bool):
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            app.current_file = _guard_scene(with_conflict)
            last = 2 if with_conflict else 1
            window = await _open_by_action_and_tick(pilot, app, {0, last})
            plan = window._plan(window._rows())
            return plan.guard, plan.conflicts, plan.span, _stats_lines(app)

    guard, conflicts, span, lines = asyncio.run(drive(True))
    assert (guard, conflicts, span) == (True, 4, GUARD_SCENE_SPAN)
    assert lines[1] == "⚠ 4 B would clobber source — abort on export", lines
    guard, conflicts, span, lines = asyncio.run(drive(False))
    assert (guard, conflicts, span) == (True, 0, GUARD_SCENE_SPAN)
    assert lines[1] == f"⚠ GUARD  {fmtB(GUARD_SCENE_SPAN)} span — e will ask", lines


# ---------------------------------------------------------------------------
# E5 corrective (C-7) - black-box acceptance through the palette and the keys
# (coverage audit section 5, items 6 and 7)
# ---------------------------------------------------------------------------
async def _open_by_palette(pilot, app: S19TuiApp) -> SplitJoinWindow:
    """``ctrl+k``, the entry's name typed, ``enter`` (the window is palette-only,
    batch-95 ruling Q6/7a); wait for its table to hold the focus."""
    await pilot.press("ctrl+k")
    await wait_until(
        pilot,
        lambda: app.focused is not None and app.focused.id == "palette_input",
        "the palette filter input focused",
        pause_first=True,
    )
    await pilot.press(*"Split / Join / Export")
    await wait_until(
        pilot,
        lambda: "Split / Join / Export"
        in app.query_one("#command_bar").visible_palette_labels(),
        "the palette listing the Split / Join / Export entry",
    )
    await pilot.press("enter")
    await wait_until(
        pilot,
        lambda: app.focused is not None and app.focused.id == "sje_table",
        "the Split / Join / Export window open with its table focused",
    )
    return _window(app)


async def _tick_by_keys(pilot, app: S19TuiApp, rows: List[int]) -> None:
    """Tick ``rows`` (ascending) with ``down`` and ``space`` from row 0."""
    window = _window(app)
    at = 0
    for row in rows:
        await pilot.press(*(["down"] * (row - at)))
        await pilot.press("space")
        at = row
    await wait_until(
        pilot,
        lambda: window._sel["ranges"] == set(rows),
        lambda: f"ticks {window._sel['ranges']!r}, not {set(rows)!r}",
        pause_first=True,
    )


def _written(app: S19TuiApp) -> List[str]:
    dest = Path(app.workarea) / "splits"
    return sorted(p.name for p in dest.iterdir()) if dest.exists() else []


def test_r_seg_prev_at_f23_scene_by_palette_and_keys_refuses_export(tmp_path: Path) -> None:
    """Black-box (audit ATs 6 and 7a; R-SEG-PREV.20, .7, LLR-136.4): the demo
    image; Split / Join / Export opened from the palette (``ctrl+k``, the name,
    ``enter``); ``range_00`` and ``range_02`` ticked with ``space`` / ``down``;
    ``m`` and ``g`` -> the stats line ``packed 1.26 MiB  ·  span 9.20 MiB  ·
    fill <pct>%`` and the state line ``⚠ <size> would clobber source — abort
    on export``; then ``e`` -> nothing written, the window not armed, the state
    line unchanged. 1 of 1.

    Why: the timing arm opens the window by its action and writes the ticks;
    this is the operator's route, and the export key must do what the state
    line says (refuse). Negative control: the guard first in ``_state_text`` ->
    the GUARD chip -> RED; ``e`` arming on the guard -> ``_armed`` -> RED."""
    conflicts = _f23_conflict_bytes()
    packed = 0x10000 + (0x931FC0 - 0x800000)
    span = 0x931FC0
    stats = f"packed {fmtB(packed)}  ·  span {fmtB(span)}  ·  fill {100 * (span - packed - conflicts) / span:.2f}%"
    clobber = f"⚠ {fmtB(conflicts)} would clobber source — abort on export"

    async def drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            app.current_file = demo_loaded_file()
            await _open_by_palette(pilot, app)
            await _tick_by_keys(pilot, app, [0, 2])
            await _join_fill(pilot, app)
            before_e = _stats_lines(app)
            await pilot.press("e")
            await pilot.pause()
            await pilot.pause()
            return before_e, _stats_lines(app), _window(app)._armed, _written(app)

    before_e, after_e, armed, written = asyncio.run(drive())
    assert before_e[:2] == [stats, clobber], before_e
    assert after_e[:2] == [stats, clobber], after_e
    assert armed is False
    assert written == []


def test_r_seg_prev_at_guard_scene_e_asks_disarms_and_confirms_by_keys(tmp_path: Path) -> None:
    """Black-box (audit AT 7b; R-SEG-PREV.8, LLR-135.5): the small guard scene
    without a conflict, opened from the palette, ``range_00`` and ``range_01``
    ticked by keys, ``m``, ``g`` -> ``⚠ GUARD  <span> span — e will ask``;
    ``e`` -> ``... — e again to confirm`` and nothing written; ``f`` (a state
    change) cancels -> ``... — e will ask``; ``e``, ``e`` -> the export is
    written (files named ``guard_joined.*``). 1 of 1.

    Why: the guard's two-step is the operator's confirm and cancel; the reorder
    of C-1 must keep it for a plan with no conflict. Negative control: the guard
    branch moved below a check that always fires -> no "e again" -> RED."""
    chip = f"⚠ GUARD  {fmtB(GUARD_SCENE_SPAN)} span"

    async def drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            app.current_file = _guard_scene(False)
            await _open_by_palette(pilot, app)
            await _tick_by_keys(pilot, app, [0, 1])
            await _join_fill(pilot, app)
            seen = [(_stats_lines(app)[1], _written(app))]
            window = _window(app)
            await pilot.press("e")
            await wait_until(pilot, lambda: window._armed, "the first e arms", pause_first=True)
            seen.append((_stats_lines(app)[1], _written(app)))
            await pilot.press("f")
            await wait_until(pilot, lambda: not window._armed, "f disarms", pause_first=True)
            seen.append((_stats_lines(app)[1], _written(app)))
            await pilot.press("e")
            await wait_until(pilot, lambda: window._armed, "e re-arms", pause_first=True)
            await pilot.press("e")
            await wait_until(pilot, lambda: bool(_written(app)), "the confirmed export wrote", pause_first=True)
            seen.append((None, _written(app)))
            return seen

    seen = asyncio.run(drive())
    assert seen[0] == (f"{chip} — e will ask", []), seen[0]
    assert seen[1] == (f"{chip} — e again to confirm", []), seen[1]
    assert seen[2] == (f"{chip} — e will ask", []), seen[2]
    assert seen[3][1] and all(name.startswith("guard_joined") for name in seen[3][1]), seen[3]
