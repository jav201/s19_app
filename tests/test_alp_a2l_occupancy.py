"""Batch a2l-load-performance INC 1 — E4 tests: the central occupancy index
(R-A2L-DEF.156, .157, .159, .160, .161; white-box counters and semantic arms).

Design under test: ``.dev-flow/2026-11-18-a2l-load-performance/inc-1/``
(``01-requirements.md``, ``02-test-cases.md``, ``codewire/graph-inc1.md``).

Oracle rules: the small-fixture semantic oracle in this file is an independent,
deliberately exhaustive iteration over explicitly constructed entry tuples in
declaration order; it never calls the product index, candidate iterator or
overlap predicate.  Private seams are reached lazily inside each test body
(``importlib`` + ``getattr``): no module-level import of a private name may
exist on the base, so the suite must collect there and each node must fail RED
individually — never with a collection error.  Small-fixture nodes run their
full body against the base; structural white-box nodes (which cannot run
without the E3 seam) guard first with ``assert hasattr`` (AttributeError RED).

No test here touches the real clipboard, user secrets or user state; temporary
files stay under pytest's isolated temporary directory.
"""

from __future__ import annotations

import gc
import importlib
import inspect
import math
import random
import sys
from collections import Counter
from dataclasses import replace

import pytest

import s19_app.tui.a2l_definition as a2ldef
from tests.support.b103_a2l_arrays import axis, axis_pts, characteristic, curve, img, inline, rl


# ---------------------------------------------------------------------------
# Lazy private-seam access and the shared instrumentation
# ---------------------------------------------------------------------------


def _mod():
    """The owner module via ``importlib`` (lazy private-seam access)."""
    return importlib.import_module("s19_app.tui.a2l_definition")


def _require_seam(mod, name: str) -> None:
    """Fail RED with AttributeError while the E3 private seam ``name`` does not
    exist on the base — without running the seam-dependent body."""
    assert hasattr(mod, name), (
        f"{name} is not implemented on the base: this white-box case is RED "
        "until the E3 private seam exists"
    )


class _CountingSeq:
    """A read-counting facade over an index summary sequence.

    Counts ``__getitem__`` reads — one internal-node ``min_first`` read is one
    index-node visit (the R-A2L-DEF.167 visit definition) — and delegates
    ``__len__`` and iteration to the wrapped sequence unchanged.
    """

    def __init__(self, seq, state):
        self._seq = seq
        self._state = state

    def __getitem__(self, index):
        self._state["visits"] += 1
        return self._seq[index]

    def __len__(self):
        return len(self._seq)

    def __iter__(self):
        return iter(self._seq)


def _install_counters(monkeypatch, mod) -> dict:
    """Install the six instrumentation seams and return their state.

    Counted: central-index constructions (plus the built index, its
    ``definitions_by_position`` and ``entry_cache`` inputs), index-node visits
    (one ``min_first`` ``__getitem__`` read per visited internal node),
    final candidate checks at ``_entry_overlaps``, definition builds at
    ``_describe_one``, actual entries into ``materialize`` through a call
    tracer at the ``_shared_with`` boundary (its last argument in both the old
    and the pinned private signature), and consumed candidate yields through a
    private generator wrapper around ``_occupancy_candidates`` (a yield is
    counted only when the downstream consumer pulls it).  On the base the two
    new seams do not exist: constructions stay 0 and the consumption
    instrument resolves 0 targets — both are asserted as RED by the cases that
    use them.
    """
    state: dict = {
        "constructions": 0,
        "index_captures": [],
        "visits": 0,
        "overlap_checks": 0,
        "builds": Counter(),
        "builds_during_index": 0,
        "materializations": 0,
        "materializations_during_index": 0,
        "consumed_positions": [],
    }

    real_build = getattr(mod, "_build_occupancy_index", None)

    def counting_build(span_entries, is_array_entry, definitions_by_position, entry_cache):
        state["constructions"] += 1
        mat_before = state["materializations"]
        build_before = sum(state["builds"].values())
        try:
            if real_build is None:  # pragma: no cover - seam absent on the base
                raise AssertionError("_build_occupancy_index seam missing")
            index = real_build(span_entries, is_array_entry, definitions_by_position, entry_cache)
        finally:
            pass
        state["materializations_during_index"] += state["materializations"] - mat_before
        state["builds_during_index"] += sum(state["builds"].values()) - build_before
        index = index._replace(min_first=_CountingSeq(index.min_first, state))
        # Capture build-time snapshots, not the live objects: describe
        # releases these containers before it returns (R-A2L-REFRESH.050), so
        # readers must check what the builder saw at build time (FA-TICK4).
        state["index_captures"].append(
            (
                index._replace(
                    records=list(index.records),
                    position_by_object=dict(index.position_by_object),
                ),
                dict(definitions_by_position),
                dict(entry_cache),
            )
        )
        return index

    monkeypatch.setattr(mod, "_build_occupancy_index", counting_build, raising=False)

    real_overlaps = getattr(mod, "_entry_overlaps")

    def counted_overlaps(definition, entry):
        state["overlap_checks"] += 1
        return real_overlaps(definition, entry)

    monkeypatch.setattr(mod, "_entry_overlaps", counted_overlaps)

    real_describe_one = getattr(mod, "_describe_one")

    def counted_describe_one(name, *args, **kwargs):
        state["builds"][name] += 1
        return real_describe_one(name, *args, **kwargs)

    monkeypatch.setattr(mod, "_describe_one", counted_describe_one)

    real_shared = getattr(mod, "_shared_with")

    def traced_shared(*args, **kwargs):
        materialize = args[-1] if args else None
        if callable(materialize):

            def counting_materialize(entry):
                state["materializations"] += 1
                return materialize(entry)

            args = args[:-1] + (counting_materialize,)
        return real_shared(*args, **kwargs)

    monkeypatch.setattr(mod, "_shared_with", traced_shared)

    real_candidates = getattr(mod, "_occupancy_candidates", None)
    state["real_candidates"] = real_candidates

    def wrapped_candidates(index, definition, own_position):
        if real_candidates is None:
            return iter(())
        inner = real_candidates(index, definition, own_position)

        def gen():
            for entry in inner:
                state["consumed_positions"].append(entry[0])
                yield entry

        return gen()

    monkeypatch.setattr(mod, "_occupancy_candidates", wrapped_candidates, raising=False)
    return state


def _reference_next_overlap(entries, own_position, final_lengths=None, own_final_length=None):
    """The independent small-fixture oracle (oracle rule 1).

    Iterates the explicitly constructed entry tuples in declaration order and
    returns the name of the first non-own entry whose span overlaps, unless the
    pair is mask-exempt (two clean same-span scalars whose masks select no
    common bit).  It never calls the product index, candidate iterator or
    overlap predicate.  ``entries`` items are
    ``(position, name, kind, address, length, byte_order, bit_mask)``.

    ``final_lengths`` maps position to the final byte length to use instead of
    the provisional ``entry[4]`` (the injected ``materialize`` result); when
    omitted the provisional length stands.  ``own_final_length`` overrides the
    own entry's length the same way.
    """
    own = next(entry for entry in entries if entry[0] == own_position)
    first = own[3]
    own_len = own_final_length if own_final_length is not None else own[4]
    last = first + (own_len - 1 if own_len and own_len >= 1 else 0)
    mask = own[6]
    for entry in entries:
        if entry[0] == own_position:
            continue
        if final_lengths is None:
            other_length = entry[4]
        else:
            other_length = final_lengths.get(entry[0], entry[4])
        other_length = other_length if other_length and other_length >= 1 else 0
        other_first = entry[3]
        other_last = other_first + (other_length - 1 if other_length else 0)
        if not (first <= other_last and other_first <= last):
            continue
        other_mask = entry[6]
        if mask is not None and other_mask is not None and (mask & other_mask) == 0:
            continue
        return entry[1]
    return None


def _assert_no_gather_sort(real) -> None:
    """The no-gather/no-sort source arm (oracle rule 4): parse the candidate
    selector's own source and reject collection as well as sorting of the
    query-wide alias population.  A consumption counter alone cannot see an
    internal gather, so gather-without-sort is a source-arm RED.  ``real`` is
    the unpatched function captured before instrumentation; inspecting the
    monkeypatched wrapper would make the arm vacuous.  On the base the seam
    does not exist: the arm is RED."""
    obj = real
    assert obj is not None, (
        "_occupancy_candidates is not implemented on the base: the no-gather/"
        "no-sort source arm is RED"
    )
    source = inspect.getsource(obj)
    for token in ("sorted(", ".sort(", "nsmallest(", "heapify(", "list("):
        assert token not in source, (
            f"the candidate selector must not use {token!r}: collecting or "
            "sorting the complete alias population is forbidden"
        )


# ---------------------------------------------------------------------------
# R-A2L-DEF.156 — one central index per batch-describe request
# ---------------------------------------------------------------------------


def test_r_a2l_def_156_1_single_name_uses_one_index(tmp_path, monkeypatch):
    """R-A2L-DEF.156/1 - one requested name in a three-object inline A2L:
    one result and exactly 1 central-index construction."""
    mod = _mod()
    a2l = inline(
        tmp_path,
        characteristic("A", "VALUE", "0x10", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
        characteristic("B", "VALUE", "0x10", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
        characteristic("C", "VALUE", "0x80", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
    )
    state = _install_counters(monkeypatch, mod)
    result = mod.describe_definitions(["A"], a2l)
    assert list(result) == ["A"]
    assert result["A"].shared_with == "B"
    assert state["constructions"] == 1, (
        f"expected exactly 1 central-index construction, observed "
        f"{state['constructions']} (the base assigns the same global list "
        "under span_index[None] once per addressed result)"
    )


def test_r_a2l_def_156_2_batch_uses_one_index(tmp_path, monkeypatch):
    """R-A2L-DEF.156/2 - A and B at 0x10, disjoint C at 0x80, requested as
    A, B, C: keys A, B, C; A.shared_with B; B.shared_with A; C.shared_with
    None; exactly 1 construction."""
    mod = _mod()
    a2l = inline(
        tmp_path,
        characteristic("A", "VALUE", "0x10", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
        characteristic("B", "VALUE", "0x10", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
        characteristic("C", "VALUE", "0x80", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
    )
    state = _install_counters(monkeypatch, mod)
    result = mod.describe_definitions(["A", "B", "C"], a2l)
    assert list(result) == ["A", "B", "C"]
    assert result["A"].shared_with == "B"
    assert result["B"].shared_with == "A"
    assert result["C"].shared_with is None
    assert state["constructions"] == 1, (
        f"expected exactly 1 central-index construction, observed "
        f"{state['constructions']}"
    )


def test_r_a2l_def_156_3_repeated_name_does_not_rebuild(tmp_path, monkeypatch):
    """R-A2L-DEF.156/3 - names A, A, B at disjoint 0x10 and 0x20: keys A, B
    in request order, both shared_with None, exactly 1 construction and no
    additional construction for the repeated name."""
    mod = _mod()
    a2l = inline(
        tmp_path,
        characteristic("A", "VALUE", "0x10", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
        characteristic("B", "VALUE", "0x20", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
    )
    state = _install_counters(monkeypatch, mod)
    result = mod.describe_definitions(["A", "A", "B"], a2l)
    assert list(result) == ["A", "B"]
    assert result["A"].shared_with is None
    assert result["B"].shared_with is None
    assert state["constructions"] == 1, (
        f"expected exactly 1 central-index construction, observed "
        f"{state['constructions']}"
    )


# ---------------------------------------------------------------------------
# R-A2L-DEF.157 — one compact interval record, zero page-expansion records
# ---------------------------------------------------------------------------


def _assert_single_interval(mod, entries, expected):
    """Build one index over ``entries`` and assert one record per entry with
    the hand-computed ``(first, last)`` pairs — the compact-interval shape
    with 0 page-expansion records (the index holds exactly one interval per
    occupancy entry and nothing else)."""
    index = mod._build_occupancy_index(tuple(entries), lambda entry: False, {}, {})
    records = index.records
    assert len(records) == len(entries), (
        f"expected exactly 1 interval record per occupancy entry and 0 "
        f"page-expansion records, observed {len(records)} records"
    )
    positions = [record[2][0] for record in records]
    assert len(set(positions)) == len(entries), positions
    for record, (first, last) in zip(records, expected):
        assert (record[0], record[1]) == (first, last), record
    return index


def test_r_a2l_def_157_1_point_like_span_is_compact():
    """R-A2L-DEF.157/1 - one byte at 0x10: exactly 1 interval record
    (first 0x10, last 0x10) and 0 page-expansion records."""
    mod = _mod()
    _require_seam(mod, "_build_occupancy_index")
    entry = (10, "P", "CHARACTERISTIC", 0x10, 1, "little")
    index = _assert_single_interval(mod, [entry], [(0x10, 0x10)])
    assert index.records[0][2] == entry


def test_r_a2l_def_157_2_cross_page_span_is_one_interval():
    """R-A2L-DEF.157/2 - sixty-four bytes at 0x10 crossing four 16-byte pages:
    exactly 1 interval record (first 0x10, last 0x4F) and 0 page records."""
    mod = _mod()
    _require_seam(mod, "_build_occupancy_index")
    entry = (11, "C", "CHARACTERISTIC", 0x10, 64, "little")
    index = _assert_single_interval(mod, [entry], [(0x10, 0x4F)])
    assert index.records[0][2] == entry


def test_r_a2l_def_157_3_over_cap_span_is_not_expanded(tmp_path, monkeypatch):
    """R-A2L-DEF.157/3 - over-cap span at 0x0 with length 1,048,577 covering a
    query at 0x100000: exactly 1 interval for BIG with last 0x100000, 0 page
    records, and the overlap stays visible through the public route."""
    mod = _mod()
    _require_seam(mod, "_build_occupancy_index")
    big = (10, "BIG", "CHARACTERISTIC", 0x0, 1_048_577, "little")
    point = (11, "V", "CHARACTERISTIC", 0x100000, 1, "little")
    index = _assert_single_interval(mod, [big, point], [(0x0, 0x100000), (0x100000, 0x100000)])
    assert index.records[0][2] == big and index.records[1][2] == point

    state = _install_counters(monkeypatch, mod)
    a2l = inline(
        tmp_path,
        characteristic("BIGC", "VALUE", "0x0", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
        characteristic("V", "VALUE", "0x100000", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
    )
    next(tag for tag in a2l["tags"] if tag.get("name") == "BIGC")["length"] = 1_048_577
    definition = mod.describe_definition("V", a2l)
    assert definition.shared_with == "BIGC"
    assert state["constructions"] == 1, state["constructions"]


# ---------------------------------------------------------------------------
# R-A2L-DEF.159 — position order, no gather/sort, exact selection
# ---------------------------------------------------------------------------


def test_r_a2l_def_159_1_position_not_address_selects_next(tmp_path, monkeypatch):
    """R-A2L-DEF.159/1 - BIG 0x10..0x4F; LATE at 0x40 has the smaller position
    than EARLY at 0x20: shared_with is exactly LATE, at most 1 consumed
    candidate yield and 2 final materializations, 0 gathers and sorts."""
    mod = _mod()
    a2l = inline(
        tmp_path,
        characteristic("BIG", "ASCII", "0x10", "RL_U8", "NO_COMPU_METHOD", "0", "255", "NUMBER 64"),
        characteristic("LATE", "VALUE", "0x40", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
        characteristic("EARLY", "VALUE", "0x20", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
    )
    entries = [
        (1, "BIG", "CHARACTERISTIC", 0x10, 64, "big", None),
        (2, "LATE", "CHARACTERISTIC", 0x40, 1, "big", None),
        (3, "EARLY", "CHARACTERISTIC", 0x20, 1, "big", None),
    ]
    state = _install_counters(monkeypatch, mod)
    definition = mod.describe_definition("BIG", a2l)
    assert definition.shared_with == "LATE"
    assert _reference_next_overlap(entries, 1) == "LATE" == definition.shared_with
    consumed = state["consumed_positions"]
    assert consumed, (
        "the consumed-yield instrument resolved 0 targets on a known-present "
        "case: hard failure (the base has no _occupancy_candidates seam)"
    )
    assert len(consumed) <= 1, consumed
    assert state["materializations"] <= 2, state["materializations"]
    assert state["constructions"] == 1, state["constructions"]
    _assert_no_gather_sort(state["real_candidates"])


def test_r_a2l_def_159_2_aliases_are_not_gathered_or_sorted(tmp_path, monkeypatch):
    """R-A2L-DEF.159/2 (E4R) - 4,000 records share one span with
    reverse-position names; the queried position is smallest and followed by
    NEXT: shared_with is exactly NEXT, at most 1 consumed candidate yield and
    2 materializations.  The no-gather arm is behavioural: one ``next()`` over
    a directly built 4,000-alias index visits at most ``2*log2(4000)+4`` index
    nodes (a gather before the first yield would visit the whole tree) and
    yields the minimum-position alias."""
    mod = _mod()
    count = 4000
    names = ["A3999", "NEXT"] + [f"A{3999 - i:04d}" for i in range(2, count)]
    assert len(names) == count and len(set(names)) == count
    blocks = [
        characteristic(name, "VALUE", "0x1000", "RL_U8", "NO_COMPU_METHOD", "0", "255")
        for name in names
    ]
    a2l = inline(tmp_path, *blocks)
    assert len(a2l["tags"]) == count and len(a2l.get("errors") or []) == 0
    entries = [(i, name, "CHARACTERISTIC", 0x1000, 1, "big", None) for i, name in enumerate(names)]

    real_build = mod._build_occupancy_index
    real_candidates = mod._occupancy_candidates
    state = _install_counters(monkeypatch, mod)

    # Behavioural no-gather probe: one next() over a directly built index must
    # visit at most 2*log2(4000)+4 index nodes before its first yield (a full
    # gather before the first yield would visit the whole tree) and must yield
    # the minimum-position alias NEXT (position 1, after self at position 0).
    # The probe uses the pre-instrumentation seams and its own visit state so
    # it does not disturb the public-route counters below.
    probe_index = real_build(tuple(entries), lambda entry: False, {}, {})
    probe_state = {"visits": 0}
    probe_index = probe_index._replace(min_first=_CountingSeq(probe_index.min_first, probe_state))
    probe_definition = replace(
        mod._empty_definition("A3999", "A3999"), address=0x1000, byte_length=1
    )
    first = next(real_candidates(probe_index, probe_definition, 0))
    assert (first[0], first[1]) == (1, "NEXT"), first
    assert probe_state["visits"] <= 2 * math.log2(count) + 4, probe_state["visits"]

    definition = mod.describe_definition("A3999", a2l)
    assert definition.shared_with == "NEXT"
    assert _reference_next_overlap(entries, 0) == "NEXT" == definition.shared_with
    consumed = state["consumed_positions"]
    assert consumed, (
        "the consumed-yield instrument resolved 0 targets on a known-present "
        "case: hard failure (the base has no _occupancy_candidates seam)"
    )
    assert len(consumed) <= 1, consumed
    assert state["materializations"] <= 2, state["materializations"]
    assert state["constructions"] == 1, state["constructions"]


def test_r_a2l_def_159_3_exempt_alias_does_not_hide_next(tmp_path, monkeypatch):
    """R-A2L-DEF.159/3 - the first overlapping scalar pair FREE has clean
    disjoint masks and the following BLOCK is unmasked: shared_with is exactly
    BLOCK, at most 2 consumed candidate yields (FREE, BLOCK) and 3
    materializations, 0 gathers and sorts."""
    mod = _mod()
    a2l = inline(
        tmp_path,
        characteristic("Q", "VALUE", "0x10", "RL_U16", "NO_COMPU_METHOD", "0", "65535", "BIT_MASK 0x000F"),
        characteristic("FREE", "VALUE", "0x10", "RL_U16", "NO_COMPU_METHOD", "0", "65535", "BIT_MASK 0x00F0"),
        characteristic("BLOCK", "VALUE", "0x10", "RL_U16", "NO_COMPU_METHOD", "0", "65535"),
    )
    assert len(a2l.get("errors") or []) == 0
    # the independent oracle's mask rule is exact here: same address, same
    # 2-byte span, masks 0x000F and 0x00F0 select no common bit.
    entries = [
        (3, "Q", "CHARACTERISTIC", 0x10, 2, "big", 0x000F),
        (4, "FREE", "CHARACTERISTIC", 0x10, 2, "big", 0x00F0),
        (5, "BLOCK", "CHARACTERISTIC", 0x10, 2, "big", None),
    ]
    state = _install_counters(monkeypatch, mod)
    definition = mod.describe_definition("Q", a2l)
    assert definition.shared_with == "BLOCK"
    assert _reference_next_overlap(entries, 3) == "BLOCK" == definition.shared_with
    consumed = state["consumed_positions"]
    assert consumed, (
        "the consumed-yield instrument resolved 0 targets on a known-present "
        "case: hard failure (the base has no _occupancy_candidates seam)"
    )
    assert 1 <= len(consumed) <= 2, consumed
    assert len(consumed) == len(set(consumed))
    assert consumed == sorted(consumed), "consumed candidates must be in position order"
    assert state["materializations"] <= 3, state["materializations"]
    assert state["constructions"] == 1, state["constructions"]
    _assert_no_gather_sort(state["real_candidates"])


# ---------------------------------------------------------------------------
# R-A2L-DEF.160 — self exclusion is by position, not name/address/span
# ---------------------------------------------------------------------------


def test_r_a2l_def_160_1_homonym_identity_is_position(tmp_path):
    """R-A2L-DEF.160/1 - two same-name, same-span records at positions 10 and
    11, own position 10: only position 10 is excluded; position 11 is the
    evaluated other record (private position witness)."""
    mod = _mod()
    _require_seam(mod, "_build_occupancy_index")
    _require_seam(mod, "_occupancy_candidates")
    a2l = inline(
        tmp_path,
        characteristic("DUP", "VALUE", "0x10", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
    )
    definition = mod.describe_definition("DUP", a2l)
    assert (definition.address, definition.byte_length) == (0x10, 1)
    entries = (
        (10, "DUP", "CHARACTERISTIC", 0x10, 1, "big"),
        (11, "DUP", "CHARACTERISTIC", 0x10, 1, "big"),
    )
    index = mod._build_occupancy_index(entries, lambda entry: False, {}, {})
    assert index.position_by_object[("DUP", "CHARACTERISTIC")] is None
    yielded = [entry[0] for entry in mod._occupancy_candidates(index, definition, 10)]
    assert yielded == [11], yielded
    all_yielded = [entry[0] for entry in mod._occupancy_candidates(index, definition, None)]
    assert all_yielded == [10, 11], all_yielded


def test_r_a2l_def_160_2_same_span_is_not_self(tmp_path, monkeypatch):
    """R-A2L-DEF.160/2 - different names, identical address, length and byte
    order: the other position is not mistaken for self.  Exactly one candidate
    is consumed per query, so neither name nor address/span equality excludes
    the other position."""
    mod = _mod()
    a2l = inline(
        tmp_path,
        characteristic("A", "VALUE", "0x10", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
        characteristic("B", "VALUE", "0x10", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
    )
    assert len(a2l.get("errors") or []) == 0
    entries = [
        (0, "A", "CHARACTERISTIC", 0x10, 1, "big", None),
        (1, "B", "CHARACTERISTIC", 0x10, 1, "big", None),
    ]
    state = _install_counters(monkeypatch, mod)
    a_def = mod.describe_definition("A", a2l)
    assert a_def.shared_with == "B"
    consumed_a = list(state["consumed_positions"])
    state["consumed_positions"].clear()
    assert consumed_a, (
        "the consumed-yield instrument resolved 0 targets on a known-present "
        "case: hard failure (the base has no _occupancy_candidates seam)"
    )
    assert len(consumed_a) == 1, consumed_a
    b_def = mod.describe_definition("B", a2l)
    assert b_def.shared_with == "A"
    consumed_b = list(state["consumed_positions"])
    assert len(consumed_b) == 1, consumed_b
    assert consumed_a != consumed_b
    assert _reference_next_overlap(entries, 0) == "B"
    assert _reference_next_overlap(entries, 1) == "A"
    assert state["constructions"] == 2, state["constructions"]


def test_r_a2l_def_160_3_same_name_elsewhere_is_not_self(tmp_path):
    """R-A2L-DEF.160/3 - same-name records at disjoint 0x10 and 0x80, own
    position 10: no candidate is yielded and the private selector answers
    exactly None — no false overlap and no name-based grouping."""
    mod = _mod()
    _require_seam(mod, "_build_occupancy_index")
    _require_seam(mod, "_occupancy_candidates")
    _require_seam(mod, "_shared_with")
    a2l = inline(
        tmp_path,
        characteristic("DUP", "VALUE", "0x10", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
    )
    definition = mod.describe_definition("DUP", a2l)
    entries = (
        (10, "DUP", "CHARACTERISTIC", 0x10, 1, "big"),
        (11, "DUP", "CHARACTERISTIC", 0x80, 1, "big"),
    )
    index = mod._build_occupancy_index(entries, lambda entry: False, {}, {})
    assert index.position_by_object[("DUP", "CHARACTERISTIC")] is None
    assert [entry[0] for entry in mod._occupancy_candidates(index, definition, 10)] == []
    assert [entry[0] for entry in mod._occupancy_candidates(index, definition, None)] == [10]
    materialized = []

    def materialize(entry):
        materialized.append(entry[0])
        return entry

    other = mod._shared_with(definition, index, 10, lambda name: None, materialize)
    assert other is None
    assert materialized == []


# ---------------------------------------------------------------------------
# R-A2L-DEF.161 — narrow queries stay lazy
# ---------------------------------------------------------------------------


def test_r_a2l_refresh_053_describe_leaves_no_cyclic_garbage(tmp_path):
    """R-A2L-REFRESH.053 (E4R) - describing 8,000 pairwise-disjoint objects
    leaves no cyclic garbage: with the ``walk`` closure self-cycle broken, an
    explicit ``gc.collect()`` after the call returns fewer than 1,000 objects
    (the base keeps every per-name list and walk entry alive until a cyclic
    collection)."""
    mod = _mod()
    count = 8000
    blocks = []
    all_names = []
    for i in range(count):
        addr = 0x1000 + i * 0x40 + (i % 7) * 4
        name = f"D{(i * 7919) % 10007}_{i}"
        blocks.append(characteristic(name, "VALUE", f"0x{addr:X}", "RL_U8", "NO_COMPU_METHOD", "0", "255"))
        all_names.append(name)
    assert len(all_names) == count and len(set(all_names)) == count
    a2l = inline(tmp_path, *blocks)
    assert len(a2l["tags"]) == count and len(a2l.get("errors") or []) == 0
    gc.collect()
    gc.disable()
    try:
        mod.describe_definitions(all_names, a2l)
        n = gc.collect()
    finally:
        gc.enable()
    assert n < 1000, (
        f"describe_definitions left {n} cyclic objects behind (the walk "
        "closure self-cycle keeps every per-name list and walk entry alive)"
    )


@pytest.mark.parametrize(
    "route",
    ["describe", "enrich"],
    ids=["R-A2L-REFRESH.050/1", "R-A2L-REFRESH.050/2"],
)
def test_r_a2l_refresh_050_producer_frees_private_containers_before_return(
    tmp_path, monkeypatch, route
):
    """R-A2L-REFRESH.050 (E4R) — the shared producer frees its private
    containers in slices just before return, so one C-level dealloc never
    holds the GIL.  At the target frame's ``return`` profile event every
    released local is empty, the result equals the no-op-release result, and
    the shared A2L tag dicts survive the release."""
    mod = _mod()
    service_mod = importlib.import_module("s19_app.tui.services.a2l_service")

    count = 8000
    blocks = []
    all_names = []
    for i in range(count):
        addr = 0x1000 + i * 0x40 + (i % 7) * 4
        name = f"D{(i * 7919) % 10007}_{i}"
        blocks.append(
            characteristic(
                name, "VALUE", f"0x{addr:X}", "RL_U8", "NO_COMPU_METHOD", "0", "255"
            )
        )
        all_names.append(name)
    a2l = inline(tmp_path, *blocks)
    assert len(a2l["tags"]) == count and len(a2l.get("errors") or []) == 0

    if route == "describe":
        target = mod.describe_definitions
        released = [
            "definitions",
            "definitions_by_position",
            "span_entries",
            "tags_by_name",
            "object_sections_by_name",
            "entry_cache",
            "requested",
            "requested_set",
            "mod_common_of",
            "tag_consumed",
        ]
        patch_module = mod

        def call():
            return target(all_names, a2l)

    else:
        target = service_mod.enrich_tags_and_render
        released = ["source_tags", "checked_tags", "check_map"]
        patch_module = service_mod

        def call():
            return target(a2l, {})

    before_tags = list(a2l["tags"])
    observed: dict[str, int] = {}

    def profiler(frame, event, arg):
        if event == "return" and frame.f_code is target.__code__:
            for name in released:
                observed[name] = len(frame.f_locals[name])

    sys.setprofile(profiler)
    try:
        result_active = call()
    finally:
        sys.setprofile(None)

    assert set(observed) == set(released), (
        f"R-A2L-REFRESH.050: the {route} return event was not observed "
        f"(observed {sorted(observed)}, expected {released})"
    )
    for name in released:
        assert observed[name] == 0, (
            f"R-A2L-REFRESH.050: producer {route} returned with local "
            f"{name!r} still holding {observed[name]} entries"
        )

    # (iii) the shared A2L tag dicts survive the release.
    assert len(a2l["tags"]) == count, len(a2l["tags"])
    assert a2l["tags"][0] == before_tags[0]
    assert a2l["tags"][-1] == before_tags[-1]

    # (ii) the result is unchanged when the release is a no-op.
    monkeypatch.setattr(patch_module, "release_in_slices", lambda *_: None)
    result_noop = call()
    if route == "describe":
        assert result_noop == result_active
    else:
        assert result_noop[0] == result_active[0]
        assert result_noop[1] == result_active[1]


def test_r_a2l_refresh_050_describe_frees_its_occupancy_index_before_return(
    tmp_path, monkeypatch
):
    """R-A2L-REFRESH.050 (E4R) — ``describe_definitions`` releases its own
    request-local occupancy index (``records`` and ``position_by_object``) in
    slices before it returns, so the ~220 k-record index never frees in one
    C-level dealloc with the GIL held (FA-TICK4).  At the target frame's
    ``return`` profile event both containers are empty; the result equals the
    no-op-release run (same keys, same order, equal values)."""
    mod = _mod()

    count = 8000
    blocks = []
    all_names = []
    for i in range(count):
        addr = 0x1000 + i * 0x40 + (i % 7) * 4
        name = f"D{(i * 7919) % 10007}_{i}"
        blocks.append(
            characteristic(
                name, "VALUE", f"0x{addr:X}", "RL_U8", "NO_COMPU_METHOD", "0", "255"
            )
        )
        all_names.append(name)
    a2l = inline(tmp_path, *blocks)
    assert len(a2l["tags"]) == count and len(a2l.get("errors") or []) == 0

    target = mod.describe_definitions
    observed: dict[str, int] = {"records": 0, "position_by_object": 0}
    seen = False

    def profiler(frame, event, arg):
        nonlocal seen
        if event == "return" and frame.f_code is target.__code__:
            seen = True
            index = frame.f_locals["index"]
            observed["records"] = len(index.records)
            observed["position_by_object"] = len(index.position_by_object)

    sys.setprofile(profiler)
    try:
        result_active = target(all_names, a2l)
    finally:
        sys.setprofile(None)

    assert seen, "R-A2L-REFRESH.050: the describe return event was never observed"
    assert observed["records"] == 0, (
        f"R-A2L-REFRESH.050: describe returned with index.records holding "
        f"{observed['records']} entries"
    )
    assert observed["position_by_object"] == 0, (
        f"R-A2L-REFRESH.050: describe returned with index.position_by_object "
        f"holding {observed['position_by_object']} entries"
    )

    # The result is unchanged when the release is a no-op (same keys, same
    # order, equal values).
    monkeypatch.setattr(mod, "release_in_slices", lambda *_: None)
    result_noop = target(all_names, a2l)
    assert list(result_noop) == list(result_active)
    assert result_noop == result_active


def _fa_tick3_cross_input(engine):
    """The FA-TICK3 cross-artifact input: > 2 × ``engine.SORT_SLICE`` distinct
    lowered names split across A2L-only, MAC-only, both-equal-address and
    both-different-address populations, as plain ``mac_records`` / ``a2l_tags``
    dicts (the ``validate_artifact_consistency`` field shapes)."""
    n = engine.SORT_SLICE * 2 + 100  # > 2 × SORT_SLICE distinct names
    mac_records = []
    a2l_tags = []
    for i in range(n // 4):
        mac_records.append(
            {"parse_ok": True, "line_number": i + 1,
             "name": f"mac_only_{i}", "address": 0x1000 + i}
        )
    for i in range(n // 4):
        a2l_tags.append({"name": f"a2l_only_{i}", "address": 0x2000 + i, "length": 1})
    for i in range(n // 4):
        addr = 0x3000 + i
        mac_records.append(
            {"parse_ok": True, "line_number": len(mac_records) + 1,
             "name": f"both_eq_{i}", "address": addr}
        )
        a2l_tags.append({"name": f"both_eq_{i}", "address": addr, "length": 1})
    for i in range(n // 4):
        mac_records.append(
            {"parse_ok": True, "line_number": len(mac_records) + 1,
             "name": f"both_diff_{i}", "address": 0x4000 + i}
        )
        a2l_tags.append({"name": f"both_diff_{i}", "address": 0x5000 + i, "length": 1})
    return mac_records, a2l_tags


def test_r_a2l_refresh_050_validation_sorts_names_in_slices(monkeypatch):
    """R-A2L-REFRESH.050 (E4R) — the cross-artifact validation sorts the union
    of A2L and MAC symbol names in bounded slices, so one C-level ``sorted()``
    over ~220 k names never holds the GIL and starves the UI tick (FA-TICK3).
    A spy on ``engine.sorted`` records the length of every input; each recorded
    length must be at most ``engine.SORT_SLICE``."""
    import builtins

    import s19_app.validation.engine as engine

    mac_records, a2l_tags = _fa_tick3_cross_input(engine)

    all_names = set()
    for record in mac_records:
        all_names.add(str(record["name"]).lower())
    for tag in a2l_tags:
        all_names.add(str(tag["name"]).lower())
    assert len(all_names) > 2 * engine.SORT_SLICE

    recorded = []
    real_sorted = builtins.sorted

    def spy(iterable, *args, **kwargs):
        items = list(iterable)
        recorded.append(len(items))
        return real_sorted(items, *args, **kwargs)

    monkeypatch.setattr(engine, "sorted", spy, raising=False)
    engine.validate_artifact_consistency(
        mac_records=mac_records,
        a2l_tags=a2l_tags,
        a2l_data=None,
        s19_ranges=[],
        overlapped_addresses=set(),
    )
    assert recorded, "engine.sorted was never called"
    assert max(recorded) <= engine.SORT_SLICE, (
        f"a slice passed to sorted() held {max(recorded)} names, above the "
        f"bound {engine.SORT_SLICE}"
    )


def test_r_a2l_refresh_050_validation_issue_order_unchanged(monkeypatch):
    """R-A2L-REFRESH.050 (E4R) — the slice-sort yields the exact issue order of
    one plain ``sorted()`` and identical coverage counters (FA-TICK3).  The
    cross-artifact issue ``symbol`` sequence equals the order produced by
    iterating ``sorted(all lowered names)``, and the coverage counters equal
    those of a run whose ``_sorted_in_slices`` is a plain sorted iterator."""
    import s19_app.validation.engine as engine

    mac_records, a2l_tags = _fa_tick3_cross_input(engine)

    a2l_by_name = {str(tag["name"]).lower(): tag for tag in a2l_tags}
    mac_by_name = {
        str(record["name"]).lower(): record
        for record in mac_records
        if record.get("parse_ok")
    }
    all_names = set(a2l_by_name) | set(mac_by_name)

    expected_symbols = []
    for name in sorted(all_names):
        in_a2l = name in a2l_by_name
        in_mac = name in mac_by_name
        if in_a2l and in_mac:
            if a2l_by_name[name]["address"] != mac_by_name[name]["address"]:
                expected_symbols.append(name)
        elif in_mac:
            expected_symbols.append(name)
        elif in_a2l:
            expected_symbols.append(name)

    report = engine.validate_artifact_consistency(
        mac_records=mac_records,
        a2l_tags=a2l_tags,
        a2l_data=None,
        s19_ranges=[],
        overlapped_addresses=set(),
    )
    codes = {"CROSS_A2L_ONLY_SYMBOL", "CROSS_MAC_ONLY_SYMBOL", "TRIPLE_NAME_ADDRESS_MISMATCH"}
    observed_symbols = [issue.symbol for issue in report.issues if issue.code in codes]
    assert observed_symbols == expected_symbols

    monkeypatch.setattr(engine, "_sorted_in_slices", lambda names: iter(sorted(names)))
    report_plain = engine.validate_artifact_consistency(
        mac_records=mac_records,
        a2l_tags=a2l_tags,
        a2l_data=None,
        s19_ranges=[],
        overlapped_addresses=set(),
    )
    assert report.coverage == report_plain.coverage


def test_r_a2l_refresh_050_dedupe_frees_its_key_set_before_return(monkeypatch):
    """R-A2L-REFRESH.050 (E4R) — ``IssuesChecksMixin._deduplicate_issues`` frees
    its private ``seen`` key set in slices just before returning, so one C-level
    dealloc of ~419 k tuples never holds the GIL (FA-TICK3).  At the ``return``
    profile event of the target frame ``seen`` is empty, and the deduped result
    equals (same objects, same order) a run whose release is a no-op.  ``self``
    is unused, so a bare ``IssuesChecksMixin()`` instance drives the call."""
    import s19_app.tui.app.issues_checks as issues_checks
    from s19_app.validation.model import ValidationIssue, ValidationSeverity

    issues = []
    for i in range(5000):
        issue = ValidationIssue(
            code="CROSS_MAC_ONLY_SYMBOL",
            severity=ValidationSeverity.WARNING,
            message=f"MAC symbol 'sym_{i}' missing from A2L.",
            artifact="cross",
            symbol=f"sym_{i}",
            address=0x1000 + i,
            line_number=None,
        )
        issues.append(issue)
        issues.append(issue)
    assert len(issues) >= 10000

    mixin = issues_checks.IssuesChecksMixin()
    target = issues_checks.IssuesChecksMixin._deduplicate_issues

    observed = {}

    def profiler(frame, event, arg):
        if event == "return" and frame.f_code is target.__code__:
            observed["seen_len"] = len(frame.f_locals["seen"])

    sys.setprofile(profiler)
    try:
        result_active = mixin._deduplicate_issues(issues)
    finally:
        sys.setprofile(None)

    assert "seen_len" in observed, "_deduplicate_issues return event was not observed"
    assert observed["seen_len"] == 0, (
        f"_deduplicate_issues returned with its seen set holding "
        f"{observed['seen_len']} entries"
    )

    monkeypatch.setattr(issues_checks, "release_in_slices", lambda *_: None)
    result_noop = mixin._deduplicate_issues(issues)
    assert result_noop == result_active
    assert all(a is b for a, b in zip(result_noop, result_active))
    assert len(result_active) == 5000


def test_r_a2l_def_161_1_narrow_query_is_not_eager(tmp_path, monkeypatch):
    """R-A2L-DEF.161/1 - one name requested from 4,000 pairwise-disjoint scalar
    objects: one result, 0 additional final-span materializations and exactly
    1 per-name definition build."""
    mod = _mod()
    count = 4000
    blocks = []
    names = []
    for i in range(count):
        addr = 0x1000 + i * 0x40 + (i % 7) * 4
        name = "V" if i == 1999 else f"D{(i * 7919) % 10007}_{i}"
        blocks.append(characteristic(name, "VALUE", f"0x{addr:X}", "RL_U8", "NO_COMPU_METHOD", "0", "255"))
        names.append(name)
    assert len(names) == count and len(set(names)) == count
    a2l = inline(tmp_path, *blocks)
    assert len(a2l["tags"]) == count and len(a2l.get("errors") or []) == 0
    state = _install_counters(monkeypatch, mod)
    result = mod.describe_definitions(["V"], a2l)
    assert list(result) == ["V"]
    assert result["V"].shared_with is None
    assert state["builds"]["V"] == 1 and len(state["builds"]) == 1, state["builds"]
    assert state["materializations"] == 0, (
        f"expected 0 additional final-span materializations, observed "
        f"{state['materializations']} (the base materializes every global "
        "candidate)"
    )
    assert state["constructions"] == 1, state["constructions"]


def _cx_v_fixture(tmp_path):
    """The inherited final-span fixture: an earlier-starting CURVE ``CX`` at
    0x20 whose final length is 64 (0x20..0x5F), a requested VALUE ``V`` at
    0x40 inside it, and 3,998 pairwise-disjoint scalars elsewhere."""
    blocks = [
        rl("RL_CX", "AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT", "ALIGNMENT_INT64 32",
           "FNC_VALUES 2 A_UINT64 ROW_DIR DIRECT"),
        curve("CX", "0x20", "RL_CX", axis("STD_AXIS", "CM_IDENT", "4", "0", "255")),
        characteristic("V", "VALUE", "0x40", "RL_U8", "NO_COMPU_METHOD", "0", "255"),
    ]
    for i in range(3998):
        addr = 0x1000 + i * 0x40 + (i % 7) * 4
        blocks.append(characteristic(f"X{i}", "VALUE", f"0x{addr:X}", "RL_U8", "NO_COMPU_METHOD", "0", "255"))
    a2l = inline(tmp_path, *blocks)
    assert len(a2l["tags"]) == 4000 and len(a2l.get("errors") or []) == 0
    return a2l


def test_r_a2l_def_161_2_only_selected_unresolved_candidate_materializes(tmp_path, monkeypatch):
    """R-A2L-DEF.161/2 - VALUE V at 0x40 inside the earlier-starting CURVE CX
    at 0x20 (final length 64, unresolved among 4,000 objects): shared_with is
    exactly CX, exactly 1 additional final-span materialization and exactly 2
    definition builds (V and CX)."""
    mod = _mod()
    a2l = _cx_v_fixture(tmp_path)
    assert mod.describe_definition("CX", a2l).byte_length == 64
    state = _install_counters(monkeypatch, mod)
    result = mod.describe_definitions(["V"], a2l)
    assert result["V"].shared_with == "CX"
    assert state["materializations"] == 1, (
        f"expected exactly 1 additional final-span materialization, observed "
        f"{state['materializations']}"
    )
    assert state["builds"] == {"V": 1, "CX": 1}, state["builds"]
    assert state["constructions"] == 1, state["constructions"]


def test_r_a2l_def_161_3_repeated_query_reuses_final_span(tmp_path, monkeypatch):
    """R-A2L-DEF.161/3 - request V, V with CX declared first: one result key V,
    V.shared_with exactly CX, exactly 1 additional final-span materialization
    of CX and exactly one build each of V and CX."""
    mod = _mod()
    a2l = _cx_v_fixture(tmp_path)
    assert mod.describe_definition("CX", a2l).byte_length == 64
    state = _install_counters(monkeypatch, mod)
    result = mod.describe_definitions(["V", "V"], a2l)
    assert list(result) == ["V"]
    assert result["V"].shared_with == "CX"
    assert state["materializations"] == 1, (
        f"expected exactly 1 additional final-span materialization of CX, "
        f"observed {state['materializations']}"
    )
    assert state["builds"] == {"V": 1, "CX": 1}, state["builds"]
    assert state["constructions"] == 1, state["constructions"]


# ---------------------------------------------------------------------------
# R-A2L-DEF.166 — unresolved array-like records are open-ended
# ---------------------------------------------------------------------------


def test_r_a2l_def_166_1_unresolved_array_is_open_ended():
    """R-A2L-DEF.166/1 (E4R; graph example R-A2L-DEF.140/11) - an unresolved
    array-like record is open-ended: a synthetic array-like CHARACTERISTIC with
    provisional length 4 gets ``last=None``; the same entry requested with final
    length 8 gets ``first + 7``; a scalar keeps ``first + len - 1``; an
    AXIS_PTS with no cache gets ``None``."""
    mod = _mod()
    _require_seam(mod, "_build_occupancy_index")
    entries = (
        (1, "ARR", "CHARACTERISTIC", 0x10, 4, "big"),
        (2, "REQ", "CHARACTERISTIC", 0x20, 4, "big"),
        (3, "SCL", "CHARACTERISTIC", 0x30, 4, "big"),
        (4, "AXP", "AXIS_PTS", 0x40, None, "little"),
    )
    is_array = lambda entry: entry[1] in ("ARR", "REQ")
    req = replace(mod._empty_definition("REQ", "REQ"), byte_length=8)
    index = mod._build_occupancy_index(entries, is_array, {2: req}, {})
    records = index.records
    assert len(records) == 4
    assert (records[0][0], records[0][1]) == (0x10, None)  # array-like, no cache
    assert (records[1][0], records[1][1]) == (0x20, 0x20 + 8 - 1)  # requested final 8
    assert (records[2][0], records[2][1]) == (0x30, 0x30 + 4 - 1)  # scalar
    assert (records[3][0], records[3][1]) == (0x40, None)  # AXIS_PTS, no cache


def test_r_a2l_def_166_2_equivalence_with_global_scan():
    """R-A2L-DEF.166/2 (E4R) - 4,000 seeded trials of up to 40 synthetic
    entries each: the product ``_shared_with`` over the product index agrees
    with the independent global-scan oracle using the injected final lengths
    (walk order, own position excluded, mask exemption)."""
    mod = _mod()
    _require_seam(mod, "_build_occupancy_index")
    _require_seam(mod, "_shared_with")
    rng = random.Random(0xA21)
    kinds = ("CHARACTERISTIC", "MEASUREMENT", "AXIS_PTS", "BLOB")
    provisional_pool = (None, 0, 1, 2, 4, 16, 64, 1_048_577)
    final_pool = (16, 64, 1_048_577)
    address_pool = (0, 0xFFFFFFFF, 0x10, 0x20, 0x40, 0x80, 0x100, 0x1000, 0x2000)
    queries = 0
    for trial in range(4000):
        n = rng.randint(1, 40)
        entries = []
        final_lengths = {}
        array_like = set()
        used_names = []
        for position in range(n):
            kind = rng.choice(kinds)
            address = rng.choice(address_pool)
            if kind == "AXIS_PTS":
                provisional = None
                final = None
            elif kind in ("CHARACTERISTIC", "MEASUREMENT"):
                if rng.random() < 0.4:
                    array_like.add(position)
                    provisional = rng.choice((None, 0, 1, 2, 4))
                    final = rng.choice(final_pool)
                else:
                    provisional = rng.choice(provisional_pool)
                    final = provisional
            else:  # BLOB
                provisional = rng.choice(provisional_pool)
                final = provisional
            if used_names and rng.random() < 0.1:
                name = rng.choice(used_names)
            else:
                name = f"N{trial}_{position}"
            used_names.append(name)
            final_lengths[position] = final
            entries.append((position, name, kind, address, provisional, "big", None))
        own_position = rng.randrange(n)
        own = entries[own_position]
        own_final = final_lengths[own_position]

        def is_array_entry(entry):
            return entry[0] in array_like

        def materialize(entry):
            return entry[:4] + (final_lengths[entry[0]], entry[5])

        definition = replace(
            mod._empty_definition(own[1], own[1]),
            address=own[3],
            byte_length=own_final,
        )
        index = mod._build_occupancy_index(
            tuple(entries), is_array_entry, {own_position: definition}, {}
        )
        got = mod._shared_with(
            definition, index, own_position, lambda name: None, materialize
        )
        expected = _reference_next_overlap(
            entries, own_position, final_lengths=final_lengths, own_final_length=own_final
        )
        assert got == expected, (trial, own_position, got, expected)
        queries += 1
    print(f"R-A2L-DEF.166/2 query count: {queries}")


def test_r_a2l_def_166_3_write_safety_curve_com_axis(tmp_path):
    """R-A2L-DEF.166/3 (E4R) - a COM_AXIS curve whose standing DATA_SIZE (4)
    is smaller than its final span (10): the VALUE V at 0x105 inside the final
    span but beyond the standing size shares with the curve and its encode is
    refused as A2L-DEF-OVERLAP."""
    mod = _mod()
    axo = axis_pts("AXO", "0x40", "RL_AXO", "5",
                   extras=rl("RL_AXO", "AXIS_PTS_X 1 UWORD INDEX_INCR DIRECT"))
    ax = axis("COM_AXIS", "CM_IDENT", "8", "0", "255", "AXIS_PTS_REF AXO")
    block = curve("CR", "0x100", "RL_U16", ax, extras=("DATA_SIZE 4",))
    v = characteristic("V", "VALUE", "0x105", "RL_U8", "NO_COMPU_METHOD", "0", "255")
    a2l_data = inline(tmp_path, axo, block, v)
    assert len(a2l_data.get("errors") or []) == 0
    cr = mod.describe_definition("CR", a2l_data)
    assert cr.refusal is None and cr.byte_length == 10
    tag_length = next(t["length"] for t in a2l_data["tags"] if t["name"] == "CR")
    assert tag_length == 4 and cr.byte_length > tag_length
    d = mod.describe_definition("V", a2l_data)
    assert d.shared_with == "CR"
    res = mod.encode_definition(d, a2l_data, "7", img(0x105, bytes(1)))
    assert isinstance(res, mod.Refusal)
    assert (res.code, res.message) == (
        "A2L-DEF-OVERLAP",
        "V: its bytes at 0x105 are shared with CR",
    )


# ---------------------------------------------------------------------------
# R-A2L-DEF.167 / .168 — D3 scale cases with a node-visit counter
# ---------------------------------------------------------------------------


_SCALE_COUNT = 8000
_SCALE_SLOT = 0x40
_SCALE_BASE = 0x1000


def _scale_address(k: int) -> int:
    """The pairwise-disjoint 4-byte slot address of object ``k``."""
    return _SCALE_BASE + k * _SCALE_SLOT + (k % 7) * 4


def _scale_population(tmp_path, layout):
    """The shared D3 scale population (R-A2L-DEF.167/.168).

    Builds 8,000 pairwise-disjoint 4-byte objects at
    ``0x1000 + k*0x40 + (k%7)*4`` in one of three declaration layouts:
    ``monotone`` (object k declared k-th, i.e. address order), ``shuffled``
    (declaration order a ``random.Random(0x5EED)`` permutation of k) and
    ``dense`` (1,000 AXIS_PTS declared first at the lowest 1,000 slots, each a
    one-byte ``AXIS_PTS_X`` layout with 4 points so the resolved span stays
    inside its 0x40 slot, then 7,000 4-byte CHARACTERISTIC VALUE scalars).
    Returns ``(a2l, all_names)`` with ``all_names`` the 8,000 names in
    declaration order and asserts 0 parse errors plus the layout's tag census
    (8,000 for monotone/shuffled, 7,000 for dense — AXIS_PTS carry no tag).
    """
    if layout == "dense":
        blocks = []
        all_names = []
        for k in range(1000):
            name = f"AXP{k}"
            blocks.append(
                axis_pts(
                    name,
                    f"0x{_scale_address(k):X}",
                    "RL_AXP",
                    "4",
                    extras=rl("RL_AXP", "AXIS_PTS_X 1 UBYTE INDEX_INCR DIRECT"),
                )
            )
            all_names.append(name)
        for k in range(1000, _SCALE_COUNT):
            name = f"D{k}"
            blocks.append(
                characteristic(
                    name,
                    "VALUE",
                    f"0x{_scale_address(k):X}",
                    "RL_U32",
                    "NO_COMPU_METHOD",
                    "0",
                    "4294967295",
                )
            )
            all_names.append(name)
        expected_tags = 7000
    else:
        order = list(range(_SCALE_COUNT))
        if layout == "shuffled":
            random.Random(0x5EED).shuffle(order)
        blocks = []
        all_names = []
        for k in order:
            name = f"D{k}"
            blocks.append(
                characteristic(
                    name,
                    "VALUE",
                    f"0x{_scale_address(k):X}",
                    "RL_U32",
                    "NO_COMPU_METHOD",
                    "0",
                    "4294967295",
                )
            )
            all_names.append(name)
        expected_tags = _SCALE_COUNT
    a2l = inline(tmp_path, *blocks)
    assert len(a2l.get("errors") or []) == 0, (layout, a2l.get("errors"))
    assert len(a2l["tags"]) == expected_tags, (layout, len(a2l["tags"]), expected_tags)
    assert len(all_names) == _SCALE_COUNT and len(set(all_names)) == _SCALE_COUNT
    return a2l, all_names


@pytest.mark.parametrize("layout", ["monotone", "shuffled", "dense"])
def test_r_a2l_def_167_visits_per_definition(tmp_path, monkeypatch, layout):
    """R-A2L-DEF.167 (E4R) - 8,000 pairwise-disjoint definitions in one of
    three declaration layouts, all names described in one request: the mean
    index-node visits per addressed definition is at most 4*log2(8000)+16
    (67.9).  The walk-order tree is GREEN for monotone and RED for shuffled
    (walk order not address order) and dense (open-ended AXIS_PTS first)."""
    mod = _mod()
    a2l, all_names = _scale_population(tmp_path, layout)
    state = _install_counters(monkeypatch, mod)
    result = mod.describe_definitions(all_names, a2l)
    assert list(result) == all_names and len(result) == _SCALE_COUNT
    addressed = sum(1 for definition in result.values() if definition.address is not None)
    assert addressed >= 1
    mean = state["visits"] / addressed
    print(
        f"R-A2L-DEF.167 {layout}: {state['visits']} visits / {addressed} "
        f"addressed definitions = {mean:.1f} mean visits"
    )
    bound = 4 * math.log2(_SCALE_COUNT) + 16
    assert mean <= bound, (
        f"{layout}: mean {mean:.1f} index-node visits per definition exceeds "
        f"the bound {bound:.1f}"
    )


def test_r_a2l_def_168_dense_overlap_checks(tmp_path, monkeypatch):
    """R-A2L-DEF.168 (E4R) - the dense layout (1,000 open-ended AXIS_PTS
    declared first): describing every name performs at most 25*n = 200,000
    candidate-overlap checks in total and every shared_with stays None
    (pairwise-disjoint)."""
    mod = _mod()
    a2l, all_names = _scale_population(tmp_path, "dense")
    state = _install_counters(monkeypatch, mod)
    result = mod.describe_definitions(all_names, a2l)
    assert list(result) == all_names and len(result) == _SCALE_COUNT
    assert all(definition.shared_with is None for definition in result.values())
    assert state["overlap_checks"] <= 25 * _SCALE_COUNT, (
        f"dense: {state['overlap_checks']} candidate-overlap checks exceed the "
        f"bound {25 * _SCALE_COUNT}"
    )
