"""
Byte-run comparison engine tests — s19_app batch-09, increment I1 (HLR-001).

Test → TC → LLR map:
    test_classification_set_equality            TC-001  LLR-001.2
    test_classification_set_equality_random     TC-001  LLR-001.2
    test_adjacency_merge_same_kind_merges       TC-002  LLR-001.2
    test_adjacency_change_forces_boundary       TC-002  LLR-001.2
    test_boundary_cases                         TC-003  LLR-001.2
    test_identity_empty_and_equal               TC-004  LLR-001.3
    test_determinism_repeated_calls             TC-004  LLR-001.3
    test_stats_byte_count_equals_run_lengths    TC-005  LLR-001.4
    test_stats_run_counts_match                 TC-005  LLR-001.4
    test_symmetry_swap_only_a_only_b            TC-005  LLR-001.3/.4
    test_large_image_perf                       TC-006  LLR-001.5  (@slow)

LLR-001.1 (engine module purity) is verified by an rg inspection probe, not a
pytest node; see the increment packet.
"""

from __future__ import annotations

import random
import time
from pathlib import Path

import pytest

from s19_app.compare import (
    DIFF_KIND_DOMAIN,
    KIND_CHANGED,
    KIND_ONLY_A,
    KIND_ONLY_B,
    DiffRun,
    diff_mem_maps,
)
from s19_app.core import S19File
from tests.conftest import make_large_s19


# ---------------------------------------------------------------------------
# Brute-force oracle: the per-address classification, independent of the
# run-merging walk under test. TC-001/TC-002 assert the engine round-trips
# back to this oracle.
# ---------------------------------------------------------------------------


def _brute_force_classification(
    map_a: dict[int, int], map_b: dict[int, int]
) -> dict[int, str]:
    """Per-address classification computed without run merging (the oracle)."""
    result: dict[int, str] = {}
    for addr in map_a.keys() | map_b.keys():
        in_a = addr in map_a
        in_b = addr in map_b
        if in_a and in_b:
            if map_a[addr] != map_b[addr]:
                result[addr] = KIND_CHANGED
        elif in_a:
            result[addr] = KIND_ONLY_A
        else:
            result[addr] = KIND_ONLY_B
    return result


def _reconstruct_from_runs(runs: list[DiffRun]) -> dict[int, str]:
    """Expand emitted runs back to a per-address classification map."""
    reconstructed: dict[int, str] = {}
    for run in runs:
        for addr in range(run.start, run.end):
            assert addr not in reconstructed, "runs overlap at address"
            reconstructed[addr] = run.kind
    return reconstructed


# ---------------------------------------------------------------------------
# TC-001 — classification set-equality (LLR-001.2).
# ---------------------------------------------------------------------------


def test_classification_set_equality() -> None:
    # Planted: changed at 0x10-0x11, only_a at 0x20-0x21, only_b at 0x30,
    # plus an equal-byte address (0x40) that must produce NO run.
    map_a = {0x10: 0x01, 0x11: 0x02, 0x20: 0xAA, 0x21: 0xAB, 0x40: 0x77}
    map_b = {0x10: 0xF1, 0x11: 0xF2, 0x30: 0xCC, 0x40: 0x77}

    runs, _ = diff_mem_maps(map_a, map_b)

    assert _reconstruct_from_runs(runs) == _brute_force_classification(map_a, map_b)
    # The equal-byte address never appears in any run.
    assert all(0x40 < run.start or 0x40 >= run.end for run in runs)


def test_classification_set_equality_random() -> None:
    rng = random.Random(1234)
    map_a: dict[int, int] = {}
    map_b: dict[int, int] = {}
    for addr in range(0, 400):
        roll = rng.random()
        if roll < 0.25:
            map_a[addr] = rng.randrange(256)
        elif roll < 0.50:
            map_b[addr] = rng.randrange(256)
        elif roll < 0.80:
            value = rng.randrange(256)
            map_a[addr] = value
            map_b[addr] = value if rng.random() < 0.5 else (value ^ 0xFF)
        # else: address absent from both

    runs, _ = diff_mem_maps(map_a, map_b)

    assert _reconstruct_from_runs(runs) == _brute_force_classification(map_a, map_b)


# ---------------------------------------------------------------------------
# TC-002 — adjacency-merge (LLR-001.2): same-kind adjacency merges into one
# run; a classification change forces a boundary.
# ---------------------------------------------------------------------------


def test_adjacency_merge_same_kind_merges() -> None:
    # Four contiguous changed addresses must collapse to exactly one run.
    map_a = {0x100: 0x00, 0x101: 0x00, 0x102: 0x00, 0x103: 0x00}
    map_b = {0x100: 0x01, 0x101: 0x01, 0x102: 0x01, 0x103: 0x01}

    runs, _ = diff_mem_maps(map_a, map_b)

    assert runs == [DiffRun(0x100, 0x104, KIND_CHANGED)]


def test_adjacency_change_forces_boundary() -> None:
    # 0x10 changed, 0x11 only_a, 0x12 only_b — three touching addresses of
    # three different kinds must yield three separate single-byte runs.
    map_a = {0x10: 0x01, 0x11: 0x99, 0x12: 0x00}  # 0x12 only in B below
    map_b = {0x10: 0x02, 0x12: 0x55}
    del map_a[0x12]  # ensure 0x12 is only_b

    runs, _ = diff_mem_maps(map_a, map_b)

    assert runs == [
        DiffRun(0x10, 0x11, KIND_CHANGED),
        DiffRun(0x11, 0x12, KIND_ONLY_A),
        DiffRun(0x12, 0x13, KIND_ONLY_B),
    ]
    # Each is a single byte: no merge across a kind change.
    assert all(run.length == 1 for run in runs)


# ---------------------------------------------------------------------------
# TC-003 — boundary cases (LLR-001.2): addr 0, touching different kinds,
# single-byte runs, interleaved gaps.
# ---------------------------------------------------------------------------


def test_boundary_cases() -> None:
    # Run at address 0 (only_a), a gap, a single-byte changed run, then a
    # same-kind pair split by a gap (interleaved gaps must NOT merge).
    map_a = {0: 0xAA, 5: 0x10, 8: 0x20, 10: 0x20}
    map_b = {5: 0x11, 8: 0x20, 10: 0x20}
    # 0 -> only_a; 5 -> changed; 8,10 -> equal bytes (no run).
    runs, _ = diff_mem_maps(map_a, map_b)

    assert runs == [
        DiffRun(0, 1, KIND_ONLY_A),
        DiffRun(5, 6, KIND_CHANGED),
    ]
    # Interleaved gap: same-kind only_a at 0x100 and 0x102 must stay separate.
    map_c = {0x100: 0x01, 0x102: 0x02}
    runs_c, _ = diff_mem_maps(map_c, {})
    assert runs_c == [
        DiffRun(0x100, 0x101, KIND_ONLY_A),
        DiffRun(0x102, 0x103, KIND_ONLY_A),
    ]
    # Reconstruction still round-trips for the addr-0 fixture.
    assert _reconstruct_from_runs(runs) == _brute_force_classification(map_a, map_b)


# ---------------------------------------------------------------------------
# TC-004 — identity + determinism (LLR-001.3).
# ---------------------------------------------------------------------------


def test_identity_empty_and_equal() -> None:
    # Both empty -> zero runs.
    runs_empty, stats_empty = diff_mem_maps({}, {})
    assert runs_empty == []
    assert all(stats_empty.run_counts[kind] == 0 for kind in DIFF_KIND_DOMAIN)
    assert all(stats_empty.byte_counts[kind] == 0 for kind in DIFF_KIND_DOMAIN)

    # Identical non-empty maps -> zero runs.
    identical = {addr: addr & 0xFF for addr in range(0x200, 0x240)}
    runs_id, stats_id = diff_mem_maps(dict(identical), dict(identical))
    assert runs_id == []
    assert all(stats_id.byte_counts[kind] == 0 for kind in DIFF_KIND_DOMAIN)


def test_determinism_repeated_calls() -> None:
    map_a = {0x10: 0x01, 0x11: 0x02, 0x30: 0xCC}
    map_b = {0x10: 0xF1, 0x12: 0x05, 0x30: 0xCC}

    runs_1, stats_1 = diff_mem_maps(map_a, map_b)
    runs_2, stats_2 = diff_mem_maps(map_a, map_b)

    assert runs_1 == runs_2
    assert stats_1 == stats_2


# ---------------------------------------------------------------------------
# TC-005 — statistics consistency + symmetry (LLR-001.4 / LLR-001.3).
# ---------------------------------------------------------------------------


def test_stats_byte_count_equals_run_lengths() -> None:
    map_a = {0x00: 0, 0x01: 0, 0x10: 9, 0x20: 1, 0x21: 1}
    map_b = {0x00: 1, 0x01: 1, 0x20: 1, 0x21: 1, 0x30: 7}
    # 0x00-0x01 changed; 0x10 only_a; 0x20-0x21 equal (no run); 0x30 only_b.
    runs, stats = diff_mem_maps(map_a, map_b)

    for kind in DIFF_KIND_DOMAIN:
        expected = sum(run.length for run in runs if run.kind == kind)
        assert stats.byte_counts[kind] == expected


def test_stats_run_counts_match() -> None:
    map_a = {0x00: 0, 0x01: 0, 0x10: 9, 0x40: 3}
    map_b = {0x00: 1, 0x01: 1, 0x30: 7}
    # changed: one run (0x00-0x01); only_a: two runs (0x10, 0x40); only_b: one (0x30).
    runs, stats = diff_mem_maps(map_a, map_b)

    for kind in DIFF_KIND_DOMAIN:
        expected = sum(1 for run in runs if run.kind == kind)
        assert stats.run_counts[kind] == expected

    assert stats.run_counts[KIND_CHANGED] == 1
    assert stats.run_counts[KIND_ONLY_A] == 2
    assert stats.run_counts[KIND_ONLY_B] == 1


def test_symmetry_swap_only_a_only_b() -> None:
    map_a = {0x10: 0x01, 0x11: 0x02, 0x20: 0xAA, 0x40: 0x77}
    map_b = {0x10: 0xF1, 0x11: 0xF2, 0x30: 0xCC, 0x40: 0x77}

    runs_ab, _ = diff_mem_maps(map_a, map_b)
    runs_ba, _ = diff_mem_maps(map_b, map_a)

    def by_kind(runs: list[DiffRun], kind: str) -> set[tuple[int, int]]:
        return {(run.start, run.end) for run in runs if run.kind == kind}

    # changed set is invariant under swap; only_a and only_b mirror each other.
    assert by_kind(runs_ab, KIND_CHANGED) == by_kind(runs_ba, KIND_CHANGED)
    assert by_kind(runs_ab, KIND_ONLY_A) == by_kind(runs_ba, KIND_ONLY_B)
    assert by_kind(runs_ab, KIND_ONLY_B) == by_kind(runs_ba, KIND_ONLY_A)


# ---------------------------------------------------------------------------
# TC-006 — large-image performance (LLR-001.5, @slow).
# ---------------------------------------------------------------------------


@pytest.mark.slow
def test_large_image_perf(tmp_path: Path) -> None:
    path_a = make_large_s19(tmp_path / "a.s19")
    path_b = make_large_s19(tmp_path / "b.s19", seed=1)

    map_a = S19File(str(path_a)).get_memory_map()
    map_b = S19File(str(path_b)).get_memory_map()

    # Plant known mutations sampled from sorted(mem_map) so they land on
    # mapped addresses, not generator gaps (probe P-15 KeyError caveat).
    sorted_addrs = sorted(map_a.keys())
    planted_changed = sorted_addrs[1000:1005]
    for addr in planted_changed:
        map_b[addr] = (map_a[addr] ^ 0xFF) & 0xFF

    start = time.perf_counter()
    runs, stats = diff_mem_maps(map_a, map_b)
    elapsed = time.perf_counter() - start

    assert elapsed <= 2.0, f"diff compute took {elapsed:.3f}s, budget 2.0s"

    # Every planted change is reported.
    changed_addrs: set[int] = set()
    for run in runs:
        if run.kind == KIND_CHANGED:
            changed_addrs.update(range(run.start, run.end))
    assert set(planted_changed) <= changed_addrs

    # Stats consistency holds at scale.
    for kind in DIFF_KIND_DOMAIN:
        expected = sum(run.length for run in runs if run.kind == kind)
        assert stats.byte_counts[kind] == expected
