"""Batch a2l-load-performance INC 1 — E4 performance and scale tests for the
central occupancy index (R-A2L-DEF.158, .162, .163, .164, .165).

Design under test: ``.dev-flow/2026-11-18-a2l-load-performance/inc-1/``
(``01-requirements.md``, ``02-test-cases.md``, ``codewire/graph-inc1.md``).

Protocol: every timed case performs one untimed warm-up and then 3 measured
runs; the reported product time is the median.  Parsing, fixture generation,
independent-oracle construction and every actual-versus-expected comparison
stay outside the timed regions; each isolated run starts with a fresh index
over the same real entry tuples and each integrated run uses a freshly parsed
payload with the pinned case digest.  GC is disabled only inside a timed
region.  A run past its bound is a failure; an external temporal watchdog of
twice the product bound stops a runaway case.  The full-case source-text
oracle and its 220,040 expected outcomes are computed once per test invocation
before the warm-up under a 120 s watchdog (expiry is ``ORACLE INVALID``).

The full-case nodes start with a fast seam guard (``assert hasattr`` →
AttributeError) so they fail RED on the base without running the base's
quadratic route over 220,040 queries.

No test here touches the real clipboard, user secrets or user state; temporary
files stay under pytest's isolated temporary directory.
"""

from __future__ import annotations

import gc
import hashlib
import random
import statistics
import threading
import time
import tracemalloc
from bisect import bisect_right
from collections import defaultdict
from pathlib import Path

import pytest

import s19_app.tui.a2l_definition as a2ldef
from s19_app.tui.a2l_parse import parse_a2l_file
from tests.support.b103_a2l_arrays import characteristic, inline, valblk
from tests.support.timing import report_margin, timing_bound
from tests.test_alp_a2l_occupancy import (
    _install_counters,
    _reference_next_overlap,
    _require_seam,
)

# ---------------------------------------------------------------------------
# case_06 pinned inputs
# ---------------------------------------------------------------------------

_CASE06 = Path(__file__).resolve().parent.parent / "examples" / "case_06_large_nested_a2l" / "firmware.a2l"
_CASE06_SHA256 = "2b982461b90cf0089ccb23d181ed4528dabe78f54213c3adcef611550a423105"
_CASE06_POPULATION = 220040
_ORACLE_WATCHDOG_S = 120.0


# ---------------------------------------------------------------------------
# The independent full-case oracle (oracle rules 1 and 5)
# ---------------------------------------------------------------------------


def _lexical_scan(data: bytes):
    """Record each live MEASUREMENT / CHARACTERISTIC / BLOB / INSTANCE /
    AXIS_PTS ``/begin`` declaration by source line, byte offset and
    cross-kind declaration ordinal, skipping comments and quoted strings.
    Returns ``[(line, offset, ordinal, kind, name), ...]``."""
    decls = []
    i, n, line = 0, len(data), 1
    state = "N"  # N normal, Q quoted, L line comment, B block comment
    while i < n:
        ch = data[i:i + 1]
        if state == "N":
            if ch == b'"':
                state = "Q"
            elif ch == b"/" and i + 1 < n and data[i + 1:i + 2] == b"/":
                state = "L"
            elif ch == b"/" and i + 1 < n and data[i + 1:i + 2] == b"*":
                state = "B"
            elif data[i:i + 6] == b"/begin" and (
                i == 0 or data[i - 1:i] in (b" ", b"\t", b"\r", b"\n")
            ):
                j = i + 6
                while j < n and data[j:j + 1] in (b" ", b"\t"):
                    j += 1
                k = j
                while k < n and data[k:k + 1] not in (b" ", b"\t", b"\r", b"\n", b'"'):
                    k += 1
                kind = data[j:k].decode("ascii", "replace")
                j2 = k
                while j2 < n and data[j2:j2 + 1] in (b" ", b"\t"):
                    j2 += 1
                k2 = j2
                while k2 < n and data[k2:k2 + 1] not in (b" ", b"\t", b"\r", b"\n", b'"'):
                    k2 += 1
                name = data[j2:k2].decode("ascii", "replace")
                if kind in ("MEASUREMENT", "CHARACTERISTIC", "BLOB", "INSTANCE", "AXIS_PTS"):
                    decls.append((line, i, len(decls), kind, name))
                i = max(k2 - 1, i)
        elif state == "Q":
            if ch == b'"':
                state = "N"
        elif state == "L":
            if ch == b"\n":
                state = "N"
        elif state == "B":
            if ch == b"*" and i + 1 < n and data[i + 1:i + 2] == b"/":
                state = "N"
                i += 1
        if ch == b"\n":
            line += 1
        i += 1
    return decls


def _scanner_controls() -> None:
    """Hand-computed controls the lexical scanner must pass before case_06:
    comments and quoted fake declarations are skipped, and interleaved kinds
    are recorded in textual order."""
    text = (
        "ASAP2_VERSION 1 71\n"
        '/begin PROJECT P ""\n'
        '  /begin MODULE M ""\n'
        "    // /begin MEASUREMENT FAKE_COMMENT_ONE\n"
        "    /* /begin CHARACTERISTIC FAKE_COMMENT_TWO\n"
        "       /begin MEASUREMENT FAKE_COMMENT_THREE */\n"
        '    /begin CHARACTERISTIC BIG ""\n'
        "      ASCII 0x10 RL_U8 0 NO_COMPU_METHOD 0 255\n"
        "      NUMBER 64\n"
        "    /end CHARACTERISTIC\n"
        '    /begin MEASUREMENT LATE "x/begin MEASUREMENT FAKE_QUOTED"\n'
        "      UBYTE NO_COMPU_METHOD 0 0 0 255\n"
        "      ECU_ADDRESS 0x40\n"
        "    /end MEASUREMENT\n"
        '    /begin CHARACTERISTIC EARLY ""\n'
        "      VALUE 0x20 RL_U8 0 NO_COMPU_METHOD 0 255\n"
        "    /end CHARACTERISTIC\n"
        "  /end MODULE\n"
        "/end PROJECT\n"
    )
    got = [(decl[3], decl[4]) for decl in _lexical_scan(text.encode("utf-8"))]
    assert got == [
        ("CHARACTERISTIC", "BIG"),
        ("MEASUREMENT", "LATE"),
        ("CHARACTERISTIC", "EARLY"),
    ], got


def _reference_controls() -> None:
    """Hand-computed controls the ordered-interval reference must pass before
    case_06: cross-page spans (position order beats address order), homonyms,
    mask exemption and over-cap spans, over interleaved kinds.  The reference
    returns the first non-own overlap in declaration order — the same
    semantics as ``shared_with``, so it may precede the queried record."""
    # cross-page: BIG 0x10..0x4F; LATE at 0x40 (position 2) before EARLY at 0x20
    cross = [
        (1, "BIG", "CHARACTERISTIC", 0x10, 64, "big", None),
        (2, "LATE", "CHARACTERISTIC", 0x40, 1, "big", None),
        (3, "EARLY", "CHARACTERISTIC", 0x20, 1, "big", None),
    ]
    assert _reference_next_overlap(cross, 1) == "LATE"
    assert _reference_next_overlap(cross, 2) == "BIG"
    assert _reference_next_overlap(cross, 3) == "BIG"
    # homonym: same name, same span; the other record is the overlap
    homonym = [
        (10, "DUP", "CHARACTERISTIC", 0x10, 1, "big", None),
        (11, "DUP", "CHARACTERISTIC", 0x10, 1, "big", None),
    ]
    assert _reference_next_overlap(homonym, 10) == "DUP"
    # mask exemption: FREE's clean disjoint mask does not hide BLOCK
    masks = [
        (4, "Q", "CHARACTERISTIC", 0x10, 2, "big", 0x000F),
        (5, "FREE", "CHARACTERISTIC", 0x10, 2, "big", 0x00F0),
        (6, "BLOCK", "CHARACTERISTIC", 0x10, 2, "big", None),
    ]
    assert _reference_next_overlap(masks, 4) == "BLOCK"
    # over-cap: BIG at 0x0 with length 1,048,577 covers V at 0x100000
    over_cap = [
        (1, "BIG", "CHARACTERISTIC", 0x0, 1_048_577, "big", None),
        (2, "V", "CHARACTERISTIC", 0x100000, 1, "big", None),
    ]
    assert _reference_next_overlap(over_cap, 1) == "V"
    assert _reference_next_overlap(over_cap, 2) == "BIG"


def _case06_entries(a2l_data):
    """The real case_06 occupancy tuples ``(position, name, kind, address,
    length, byte_order)`` in declaration order, with the census pins asserted:
    220,040 records, all addressed and length-bearing, 4-aligned addresses of
    length at most 4, one byte order, no bit masks, no declared spans, no
    parse errors and unique names."""
    tags = a2l_data["tags"]
    assert len(tags) == _CASE06_POPULATION
    assert all(tag.get("address") is not None for tag in tags)
    assert all(tag.get("length") is not None and tag["length"] >= 1 for tag in tags)
    assert all(tag["address"] % 4 == 0 for tag in tags)
    assert max(tag["length"] for tag in tags) <= 4
    assert all(tag.get("effective_byte_order") == "big" for tag in tags)
    assert all(tag.get("bit_org") is None for tag in tags)
    assert len({tag["name"] for tag in tags}) == _CASE06_POPULATION
    assert len(a2l_data.get("declared_spans") or []) == 0
    assert len(a2l_data.get("errors") or []) == 0
    return tuple(
        (i, tag["name"], tag["section"], tag["address"], tag["length"], "big")
        for i, tag in enumerate(tags)
    )


def _bucket_expected(entries):
    """The independent ordered-interval reference for case_06.  Every address
    is 4-aligned and every length is at most 4 (asserted on the real inputs),
    so two spans overlap iff they share their 4-byte slot — i.e. the same
    address.  For each entry the expected answer is the first other entry, in
    position order, sharing its address; ``None`` when the entry is alone in
    its slot.  Returns ``[index | None, ...]``."""
    assert all(entry[3] % 4 == 0 for entry in entries)
    assert all(1 <= entry[4] <= 4 for entry in entries)
    by_addr = defaultdict(list)
    for i, entry in enumerate(entries):
        by_addr[entry[3]].append(i)
    expected = []
    for i, entry in enumerate(entries):
        bucket = by_addr[entry[3]]
        other = bucket[0] if bucket[0] != i else (bucket[1] if len(bucket) > 1 else None)
        expected.append(other)
    return expected


def _verify_reference_sample(entries, expected) -> None:
    """Runtime equivalence control: on a fixed-seed sample of 400 positions the
    bucket reference must agree with the deliberately exhaustive first-overlap
    scan (a hand-computed reference over the same real tuples)."""
    rng = random.Random(0xA25EED)
    sample = rng.sample(range(len(entries)), 400)
    for i in sample:
        entry = entries[i]
        first = entry[3]
        last = first + entry[4] - 1
        got = None
        for j, other in enumerate(entries):
            if j == i:
                continue
            other_first = other[3]
            other_last = other_first + other[4] - 1
            if first <= other_last and other_first <= last:
                got = j
                break
        assert got == expected[i], (i, got, expected[i])


def _case06_oracle(a2l_data):
    """Compute the full-case source-text oracle once: (oracle_seconds,
    oracle_by_name, expected_names aligned to declaration order).  The scanner
    and the ordered-interval reference must pass their hand-computed controls
    first; preparation past the 120 s watchdog reports ORACLE INVALID."""
    started = time.perf_counter()
    data = _CASE06.read_bytes()
    assert hashlib.sha256(data).hexdigest() == _CASE06_SHA256, (
        "case_06 digest does not match the pinned SHA-256"
    )
    _scanner_controls()
    _reference_controls()
    decls = _lexical_scan(data)
    assert len(decls) == _CASE06_POPULATION
    kinds = {decl[3] for decl in decls}
    assert kinds <= {"MEASUREMENT", "CHARACTERISTIC"}, kinds
    names = [decl[4] for decl in decls]
    assert len(set(names)) == _CASE06_POPULATION
    entries = _case06_entries(a2l_data)
    assert [entry[1] for entry in entries] == names, (
        "the source-text declaration order and the entry order must agree"
    )
    expected_idx = _bucket_expected(entries)
    _verify_reference_sample(entries, expected_idx)
    expected_names = [entries[j][1] if j is not None else None for j in expected_idx]
    oracle_by_name = {names[i]: expected_names[i] for i in range(_CASE06_POPULATION)}
    oracle_seconds = time.perf_counter() - started
    if oracle_seconds > _ORACLE_WATCHDOG_S:
        pytest.fail(
            f"ORACLE INVALID: oracle preparation took {oracle_seconds:.1f} s, "
            f"past the {_ORACLE_WATCHDOG_S:.0f} s watchdog"
        )
    return oracle_seconds, oracle_by_name, expected_names


# ---------------------------------------------------------------------------
# Timing protocol helpers
# ---------------------------------------------------------------------------


def _run_with_watchdog(work, seconds):
    """Run ``work()`` in a daemon thread; a run past ``seconds`` (2x the
    product bound) is a temporal-watchdog RED failure."""
    result = {}

    def runner():
        try:
            result["value"] = work()
        except BaseException as exc:  # pragma: no cover - propagated below
            result["error"] = exc

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    thread.join(seconds)
    if thread.is_alive():
        pytest.fail(f"temporal watchdog expired at {seconds} s (2x the product bound): RED")
    if "error" in result:
        raise result["error"]
    return result["value"]


def _timed_call(work, watchdog):
    """Wall-clock seconds of ``work()`` with GC disabled only inside the timed
    region, under the temporal watchdog."""
    gc.collect()
    gc.disable()
    try:
        started = time.perf_counter()
        _run_with_watchdog(work, watchdog)
        return time.perf_counter() - started
    finally:
        gc.enable()


def _assert_index_population(index, count):
    """``count`` records, ``count`` unique indexed positions and exactly one
    interval record per occupancy entry (0 page-expansion records)."""
    records = index.records
    assert len(records) == count, len(records)
    positions = [record[2][0] for record in records]
    assert len(set(positions)) == count
    assert len(positions) == count


def _semantic_pins(tmp_path, mod):
    """The known-answer pins of R-A2L-DEF.159 and R-A2L-DEF.160 asserted
    inside the full-case nodes (untimed)."""
    cross = inline(
        tmp_path,
        characteristic("BIG", "ASCII", "0x10", "RL_U8", "NO_COMPU_METHOD", "0", "255", "NUMBER 64"),
        characteristic("LATE", "VALUE", "0x40", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
        characteristic("EARLY", "VALUE", "0x20", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
    )
    assert mod.describe_definition("BIG", cross).shared_with == "LATE"
    pair = inline(
        tmp_path,
        characteristic("A", "VALUE", "0x10", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
        characteristic("B", "VALUE", "0x10", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
    )
    assert mod.describe_definition("A", pair).shared_with == "B"
    assert mod.describe_definition("B", pair).shared_with == "A"


def _run_integrated_case06(tmp_path, monkeypatch, mod):
    """The shared integrated full-case protocol (R-A2L-DEF.165/1 and
    AT-ALP-I1-1): oracle once before the warm-up, then one untimed warm-up and
    3 measured runs of the public batch describe of all 220,040 unique names;
    each run uses a freshly parsed payload, returns exactly the 220,040
    requested keys in request order with 0 oracle differences, and records
    exactly 1 index construction and 220,040 indexed positions; the median is
    at most 30.0 s.  Returns (median, runs, oracle_seconds, comparison_seconds)."""
    _require_seam(mod, "_build_occupancy_index")
    first_payload = parse_a2l_file(_CASE06)
    names = [tag["name"] for tag in first_payload["tags"]]
    assert len(names) == _CASE06_POPULATION and len(set(names)) == _CASE06_POPULATION
    oracle_seconds, _oracle_by_name, expected_names = _case06_oracle(first_payload)
    state = _install_counters(monkeypatch, mod)

    def one_run():
        payload = parse_a2l_file(_CASE06)  # freshly parsed payload per integrated run
        result = {}

        def describe():
            result["value"] = mod.describe_definitions(names, payload)

        seconds = _timed_call(describe, watchdog=60.0)
        value = result["value"]
        assert list(value) == names and len(value) == _CASE06_POPULATION
        started = time.perf_counter()
        for name, expected_name in zip(names, expected_names):
            assert value[name].shared_with == expected_name, (
                name, value[name].shared_with, expected_name
            )
        comparison = time.perf_counter() - started
        return seconds, comparison

    one_run()  # warm-up, untimed for the bound
    runs = []
    comparison_seconds = []
    for _ in range(3):
        seconds, comparison = one_run()
        runs.append(seconds)
        comparison_seconds.append(comparison)
    assert state["constructions"] == 4, state["constructions"]
    assert len(state["index_captures"]) == 4
    for index, _defs_by_pos, _entry_cache in state["index_captures"]:
        _assert_index_population(index, _CASE06_POPULATION)
    median = statistics.median(runs)
    return median, runs, oracle_seconds, comparison_seconds


# ---------------------------------------------------------------------------
# R-A2L-DEF.158 — pairwise-disjoint candidate checks stay bounded
# ---------------------------------------------------------------------------


def _run_disjoint(tmp_path, monkeypatch, variant, count, bound):
    """The shared .158 body: the fixed-arithmetic disjoint population run once
    as 1-byte scalars and once as valid 4-byte VAL_BLKs."""
    mod = a2ldef
    blocks = []
    names = []
    for i in range(count):
        name = f"D{(i * 7919) % 10007}_{i}"
        addr = 0x1000 + i * 0x40 + (i % 7) * 4
        if variant == "scalar":
            blocks.append(characteristic(name, "VALUE", f"0x{addr:X}", "RL_U8", "NO_COMPU_METHOD", "0", "255"))
        else:
            blocks.append(valblk(name, f"0x{addr:X}", "RL_U8", "NO_COMPU_METHOD", "0", "255",
                                 extras=("NUMBER 4",)))
        names.append(name)
    assert len(names) == count and len(set(names)) == count
    a2l = inline(tmp_path, *blocks)
    assert len(a2l["tags"]) == count and len(a2l.get("errors") or []) == 0
    state = _install_counters(monkeypatch, mod)
    result = mod.describe_definitions(names, a2l)
    assert list(result) == names and len(result) == count
    assert all(definition.shared_with is None for definition in result.values())
    assert state["overlap_checks"] <= bound, (
        f"{variant} variant: {state['overlap_checks']} candidate-overlap checks "
        f"exceed the bound {bound} (the base runs the global candidate scan)"
    )
    assert state["constructions"] == 1, (
        f"{variant} variant: expected exactly 1 total index construction and 0 "
        f"additional per-definition constructions, observed "
        f"{state['constructions']}"
    )
    assert len(state["index_captures"]) == 1
    if variant == "val_blk":
        for index, defs_by_pos, entry_cache in state["index_captures"]:
            open_known_final = [
                record for record in index.records
                if record[1] is None and (
                    record[2][0] in defs_by_pos or record[2][0] in entry_cache
                )
            ]
            assert open_known_final == [], (
                f"{len(open_known_final)} known-final VAL_BLK records kept open "
                "upper reachability"
            )
            assert state["builds_during_index"] == 0, state["builds_during_index"]
            assert state["materializations_during_index"] == 0, state["materializations_during_index"]
            assert all(record[1] == record[2][3] + 3 for record in index.records), (
                "a valid 4-byte VAL_BLK must have last == first + 3"
            )


@pytest.mark.parametrize("variant", ["scalar", "val_blk"])
def test_r_a2l_def_158_1_disjoint_1000_checks_bounded(tmp_path, monkeypatch, variant):
    """R-A2L-DEF.158/1 - 1,000 pairwise-disjoint definitions, scalar and valid
    4-byte VAL_BLK parametrizations: all shared_with None, at most 20,000
    checks, exactly 1 construction."""
    _run_disjoint(tmp_path, monkeypatch, variant, 1000, 20_000)


@pytest.mark.parametrize("variant", ["scalar", "val_blk"])
def test_r_a2l_def_158_2_disjoint_4000_checks_bounded(tmp_path, monkeypatch, variant):
    """R-A2L-DEF.158/2 - 4,000 pairwise-disjoint definitions, scalar and valid
    4-byte VAL_BLK parametrizations: all shared_with None, at most 100,000
    checks, exactly 1 construction."""
    _run_disjoint(tmp_path, monkeypatch, variant, 4000, 100_000)


# ---------------------------------------------------------------------------
# R-A2L-DEF.162 — isolated case_06 index build
# ---------------------------------------------------------------------------


@pytest.mark.serial_timing
@pytest.mark.slow
def test_r_a2l_def_162_1_case06_index_build_bound():
    """R-A2L-DEF.162/1 - the warm-up and each of 3 measured runs index exactly
    220,040 unique positions of case_06; the isolated build median is at most
    2.5 s under a 5.0 s watchdog."""
    mod = a2ldef
    _require_seam(mod, "_build_occupancy_index")
    a2l = parse_a2l_file(_CASE06)
    entries = _case06_entries(a2l)

    def build():
        return mod._build_occupancy_index(entries, lambda entry: False, {}, {})

    warm = build()  # warm-up, untimed for the bound
    _assert_index_population(warm, _CASE06_POPULATION)
    del warm
    runs = []
    for _ in range(3):
        holder = {}

        def run_build():
            holder["index"] = build()

        seconds = _timed_call(run_build, watchdog=5.0)
        runs.append(seconds)
        _assert_index_population(holder["index"], _CASE06_POPULATION)
        del holder["index"]
    median = statistics.median(runs)
    assert median <= report_margin(
        "R-A2L-DEF.162 case_06 isolated index build", median, timing_bound(2.5)
    ), runs


# ---------------------------------------------------------------------------
# R-A2L-DEF.163 — all 220,040 next-overlap resolutions
# ---------------------------------------------------------------------------


@pytest.mark.serial_timing
@pytest.mark.slow
def test_r_a2l_def_163_1_case06_all_queries_bound():
    """R-A2L-DEF.163/1 - resolve the next overlap for every one of the 220,040
    case_06 occupancy records after a fresh index per run: every run resolves
    exactly 220,040 positions with 0 shared_with differences from the
    independent full-case oracle; the median of 3 runs is at most 18.0 s under
    a 36.0 s watchdog."""
    mod = a2ldef
    _require_seam(mod, "_build_occupancy_index")
    _require_seam(mod, "_shared_with")
    a2l = parse_a2l_file(_CASE06)
    _oracle_seconds, _oracle_by_name, expected_names = _case06_oracle(a2l)
    entries = _case06_entries(a2l)
    names = [tag["name"] for tag in a2l["tags"]]
    defs = mod.describe_definitions(names, a2l)  # untimed definition build
    assert len(defs) == _CASE06_POPULATION

    def mask_of(name):
        return None  # case_06 carries no BIT_MASK (asserted in _case06_entries)

    def make_materialize():
        cache = {}

        def materialize(entry):
            if entry[0] not in cache:
                cache[entry[0]] = entry[:4] + (entry[4], entry[5])
            return cache[entry[0]]

        return materialize

    def resolve_all(index):
        materialize = make_materialize()
        differences = 0
        resolved = 0
        for position, entry in enumerate(entries):
            got = mod._shared_with(defs[entry[1]], index, position, mask_of, materialize)
            resolved += 1
            if got != expected_names[position]:
                differences += 1
        return resolved, differences

    def build():
        return mod._build_occupancy_index(entries, lambda entry: False, {}, {})

    warm = build()  # warm-up, untimed for the bound
    resolved, differences = resolve_all(warm)
    assert resolved == _CASE06_POPULATION and differences == 0
    del warm
    runs = []
    for _ in range(3):
        index = build()  # a fresh index over the same real entry tuples per run
        holder = {}

        def run_resolve():
            holder["resolved"], holder["differences"] = resolve_all(index)

        seconds = _timed_call(run_resolve, watchdog=36.0)
        runs.append(seconds)
        assert holder["resolved"] == _CASE06_POPULATION
        assert holder["differences"] == 0, holder["differences"]
        del index
    median = statistics.median(runs)
    assert median <= report_margin(
        "R-A2L-DEF.163 case_06 all 220040 resolutions", median, timing_bound(18.0)
    ), runs


# ---------------------------------------------------------------------------
# R-A2L-DEF.164 — case_06 index memory
# ---------------------------------------------------------------------------


@pytest.mark.slow
def test_r_a2l_def_164_1_case06_index_memory_bound():
    """R-A2L-DEF.164/1 - build and retain the case_06 index: each of 3 runs
    retains exactly 220,040 unique indexed positions with 0 page-expansion
    records, and the traced peak additional allocation stays at or below
    64 MiB (67,108,864 bytes)."""
    mod = a2ldef
    _require_seam(mod, "_build_occupancy_index")
    a2l = parse_a2l_file(_CASE06)
    entries = _case06_entries(a2l)
    bound = 67_108_864
    for run in range(1, 4):
        tracemalloc.start()
        gc.collect()
        current_before, _peak_before = tracemalloc.get_traced_memory()
        index = mod._build_occupancy_index(entries, lambda entry: False, {}, {})
        current_after, peak_after = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        _assert_index_population(index, _CASE06_POPULATION)
        retained = current_after - current_before
        peak_additional = peak_after - current_before
        assert retained <= bound, (run, "retained", retained)
        assert peak_additional <= bound, (run, "peak_additional", peak_additional)
        del index


# ---------------------------------------------------------------------------
# R-A2L-DEF.165 — integrated public describe of all case_06 names
# ---------------------------------------------------------------------------


@pytest.mark.serial_timing
@pytest.mark.slow
def test_r_a2l_def_165_1_case06_integrated_describe_bound(tmp_path, monkeypatch):
    """R-A2L-DEF.165/1 - public batch describe of every unique case_06 name:
    each of 3 measured runs returns exactly the 220,040 requested keys in
    request order with 0 oracle differences, median at most 30.0 s; the
    semantic pins of R-A2L-DEF.159 and R-A2L-DEF.160 also pass."""
    mod = a2ldef
    median, runs, oracle_seconds, comparison_seconds = _run_integrated_case06(
        tmp_path, monkeypatch, mod
    )
    assert median <= report_margin(
        "R-A2L-DEF.165 case_06 integrated describe", median, timing_bound(30.0)
    ), (runs, oracle_seconds, comparison_seconds)
    _semantic_pins(tmp_path, mod)
