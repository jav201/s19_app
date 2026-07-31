"""
Linkage-probe soundness over OVERLAPPING ranges — s19_app batch-73 (R-CHG-002).

``_first_intersecting_symbol`` resolves an address to a linkage **symbol name**
with a one-candidate bisect.  Over overlapping indexed ranges that probe can
miss an enclosing range that starts earlier, returning "no linkage" — or the
wrong symbol — for an address that plainly sits inside a named region.  The
linkage is **displayed to the operator**, so a wrong symbol is wrong data in an
evidentiary surface, not a cosmetic defect.

- **AT-220 / TC-521** — the overlap counterexample resolves to the enclosing
  range's symbol.
- **AT-221 / TC-522** — positive control: over **disjoint** ranges the answer is
  identical to the pre-fix implementation *and* to a linear-scan ground truth,
  across a deterministic generated sweep.  Guards the real risk — that the fix
  changes answers it had no business changing.
- **AT-222 / TC-523** — the same observations driven through ``check.py``'s
  public entry point.  The probe is **shared**; a fix proven only through
  ``apply`` is proven for half its consumers.
- **AT-223 / TC-524** — duplicate MAC point addresses (aliases) resolve to the
  **first-declared** symbol (operator decision D-2, 2026-07-31).  Two records at
  one address are an overlap, so ``AT-221``'s disjoint sweep cannot observe
  this.

Every fixture is synthetic (constraint C-9).
"""

from __future__ import annotations

import bisect
import random
from typing import List, Optional, Tuple

from s19_app.tui.changes import (
    FORMAT_ID,
    FORMAT_VERSION,
    ChangeDocument,
    ChangeEntry,
    apply_change_document,
)
from s19_app.tui.changes.apply import (
    _a2l_linkage_source,
    _first_intersecting_symbol,
    _linkage_index,
    _mac_linkage_source,
)
from s19_app.tui.changes.check import run_check_document

#: The backlog's counterexample: ``INNER`` is wholly nested inside
#: ``BIG_ARRAY``, and the probed address sits inside ``BIG_ARRAY`` only.
COUNTEREXAMPLE: List[Tuple[int, int, Optional[str]]] = [
    (0x1000, 0x9000, "BIG_ARRAY"),
    (0x2000, 0x2010, "INNER"),
]
PROBE_ADDRESS = 0x5000


def _ground_truth(
    start: int,
    end: int,
    source: List[Tuple[int, int, Optional[str]]],
) -> Tuple[bool, Optional[str]]:
    """
    Summary:
        Independent linear-scan oracle — the first-by-start indexed range
        intersecting the half-open span ``[start, end)``, which is the
        semantics ``_first_intersecting_symbol``'s own name and docstring
        declare (operator decision D-2, 2026-07-31).

    Args:
        start (int): Span start (inclusive).
        end (int): Span end (exclusive).
        source (List[Tuple[int, int, Optional[str]]]): ``(start, end, symbol)``
            triples in declaration order.

    Returns:
        Tuple[bool, Optional[str]]: ``(True, symbol)`` for the smallest-start
        intersecting range (ties resolving to declaration order), else
        ``(False, None)``.

    Data Flow:
        - Sort by start with the same stable key the index builder uses, then
          scan linearly and stop at the first intersection.

    Dependencies:
        Used by:
            - test_at220_tc521_overlap_counterexample_resolves_enclosing_symbol
            - test_at221_tc522_disjoint_ranges_match_pre_fix_and_ground_truth
    """
    for range_start, range_end, symbol in sorted(source, key=lambda t: t[0]):
        if range_start < end and range_end > start:
            return True, symbol
    return False, None


def _pre_fix_probe(
    start: int,
    end: int,
    source: List[Tuple[int, int, Optional[str]]],
) -> Tuple[bool, Optional[str]]:
    """
    Summary:
        Frozen verbatim copy of the ``@d81cb3d`` pre-fix implementation —
        ``_linkage_index`` + ``_first_intersecting_symbol`` as they stood
        before batch-73.  Used **only** as ``AT-221``'s differential oracle
        over the disjoint domain, which is the literal form of the plan's
        "identical to today's" clause.

    Args:
        start (int): Span start (inclusive).
        end (int): Span end (exclusive).
        source (List[Tuple[int, int, Optional[str]]]): ``(start, end, symbol)``
            triples in declaration order.

    Returns:
        Tuple[bool, Optional[str]]: What the pre-fix probe answered.

    Data Flow:
        - Sort by start, split into parallel vectors, then run the original
          one-candidate bisect (candidate at or before ``start``, else its
          immediate successor).

    Dependencies:
        Used by:
            - test_at221_tc522_disjoint_ranges_match_pre_fix_and_ground_truth

    Example:
        >>> _pre_fix_probe(0x5000, 0x5001, COUNTEREXAMPLE)
        (False, None)
    """
    ordered = sorted(source, key=lambda triple: triple[0])
    starts = [item[0] for item in ordered]
    ends = [item[1] for item in ordered]
    symbols = [item[2] for item in ordered]
    if not starts:
        return False, None
    candidate = bisect.bisect_right(starts, start) - 1
    if candidate >= 0 and ends[candidate] > start:
        return True, symbols[candidate]
    successor = candidate + 1
    if successor < len(starts) and starts[successor] < end:
        return True, symbols[successor]
    return False, None


def _probe(
    start: int,
    end: int,
    source: List[Tuple[int, int, Optional[str]]],
) -> Tuple[bool, Optional[str]]:
    """Drive the live index builder + probe over ``source``."""
    index, symbols = _linkage_index(source)
    return _first_intersecting_symbol(start, end, index, symbols)


def _disjoint_sources(seed: int, cases: int) -> List[List[Tuple[int, int, Optional[str]]]]:
    """
    Summary:
        Generate deterministic pairwise-**disjoint** ``(start, end, symbol)``
        sources for ``AT-221``'s positive control.

    Args:
        seed (int): Seed pinning the sweep so a failure is reproducible.
        cases (int): How many sources to generate.

    Returns:
        List[List[Tuple[int, int, Optional[str]]]]: One source per case,
        including empty and single-range degenerate cases.

    Data Flow:
        - Walk a monotonically increasing cursor, consuming a gap then a
          length, so range ``i`` always ends strictly before range ``i+1``
          starts — disjointness holds by construction, not by assertion.

    Dependencies:
        Used by:
            - test_at221_tc522_disjoint_ranges_match_pre_fix_and_ground_truth
    """
    rng = random.Random(seed)
    sources: List[List[Tuple[int, int, Optional[str]]]] = []
    for _ in range(cases):
        cursor = rng.randint(0, 64)
        source: List[Tuple[int, int, Optional[str]]] = []
        for slot in range(rng.randint(0, 8)):
            cursor += rng.randint(1, 24)
            length = rng.randint(1, 18)
            source.append((cursor, cursor + length, f"SYM_{slot}"))
            cursor += length
        sources.append(source)
    return sources


# ---------------------------------------------------------------------------
# AT-220 / TC-521 — the overlap counterexample
# ---------------------------------------------------------------------------


def test_at220_tc521_overlap_counterexample_resolves_enclosing_symbol() -> None:
    """AT-220 — an address inside an enclosing range resolves to its symbol.

    RED before the fix: the one-candidate bisect lands on ``INNER`` (the last
    range starting at or before ``0x5000``), sees ``INNER``'s end is below the
    address, and gives up rather than looking further back — returning
    ``(False, None)`` for an address plainly inside ``BIG_ARRAY``.
    """
    hit, symbol = _probe(PROBE_ADDRESS, PROBE_ADDRESS + 1, COUNTEREXAMPLE)

    assert (hit, symbol) == (True, "BIG_ARRAY"), (
        "an address inside BIG_ARRAY must resolve to BIG_ARRAY — the probe "
        "must not stop at the nearest-start candidate"
    )
    # The defect is specifically that the pre-fix shape answers differently
    # here; if this stops holding, the counterexample has gone stale.
    assert _pre_fix_probe(PROBE_ADDRESS, PROBE_ADDRESS + 1, COUNTEREXAMPLE) == (
        False,
        None,
    )
    assert _ground_truth(PROBE_ADDRESS, PROBE_ADDRESS + 1, COUNTEREXAMPLE) == (
        True,
        "BIG_ARRAY",
    )


def test_at220_tc521_swallowed_middle_range_keeps_the_cover_disjoint() -> None:
    """AT-220 (invariant arm) — a swallowed range must not rewind the frontier.

    Three ranges where a MIDDLE one is wholly swallowed and a LATER one
    partially overlaps.  Every other case in this module has at most two
    ranges, and two ranges cannot exercise the frontier's *running-maximum*
    property: only a swallowed range followed by a further range can, because
    only then does ``frontier`` have to remember an end belonging to neither
    neighbour.

    Asserts the cover is **disjoint**, not merely that the answer looks right —
    disjointness is the precondition ``_first_intersecting_symbol``'s
    soundness now depends on, so it is the thing worth pinning directly.
    """
    source: List[Tuple[int, int, Optional[str]]] = [
        (0x0000, 0x0064, "OUTER"),
        (0x000A, 0x0014, "SWALLOWED"),
        (0x001E, 0x00C8, "LATER_OVERLAP"),
    ]

    (starts, ends), symbols = _linkage_index(source)

    assert all(
        starts[i] >= ends[i - 1] for i in range(1, len(starts))
    ), f"cover is not disjoint: starts={starts} ends={ends}"
    assert len(symbols) == len(starts), "symbol list fell out of alignment"
    # 0x32 sits inside OUTER and inside LATER_OVERLAP; OUTER starts first.
    assert _probe(0x32, 0x33, source) == (True, "OUTER")
    assert _ground_truth(0x32, 0x33, source) == (True, "OUTER")
    # Past OUTER's end the later range owns the span.
    assert _probe(0x70, 0x71, source) == (True, "LATER_OVERLAP")


def test_at220_tc521_nested_overlap_resolves_first_by_start() -> None:
    """AT-220 (D-2 arm) — the smallest-start intersecting range wins.

    Distinguishes first-by-start from "whichever range has the largest end":
    at ``0x06`` both ranges intersect and the answer must be ``OUTER_FIRST``.
    """
    nested: List[Tuple[int, int, Optional[str]]] = [
        (0x00, 0x0A, "OUTER_FIRST"),
        (0x05, 0x64, "LATER_LONGER"),
    ]

    assert _probe(0x06, 0x07, nested) == (True, "OUTER_FIRST")
    assert _ground_truth(0x06, 0x07, nested) == (True, "OUTER_FIRST")
    # Past the first range's end only the second intersects.
    assert _probe(0x20, 0x21, nested) == (True, "LATER_LONGER")


# ---------------------------------------------------------------------------
# AT-221 / TC-522 — positive control over disjoint ranges
# ---------------------------------------------------------------------------


def test_at221_tc522_disjoint_ranges_match_pre_fix_and_ground_truth() -> None:
    """AT-221 — over disjoint ranges nothing changes.

    The fix's real risk is not that it fails to repair overlaps but that it
    perturbs the overwhelmingly common disjoint case.  Asserts a three-way
    agreement — live probe == frozen pre-fix implementation == linear-scan
    ground truth — so a cover that coalesces or mis-attributes anything on
    disjoint input reddens here even though every individual answer still
    "looks" plausible.
    """
    probes = 0
    hits = 0
    ranges_swept = 0
    sources = _disjoint_sources(seed=20260731, cases=400)
    for case, source in enumerate(sources):
        ceiling = (source[-1][1] if source else 0) + 40
        # Seeded on the case INDEX, not on len(source) — the latter takes only
        # 9 distinct values, so 400 sources would draw from 9 span streams.
        span_rng = random.Random(0xC0FFEE + case)
        ranges_swept += len(source)
        for _ in range(20):
            start = span_rng.randint(0, ceiling)
            length = span_rng.randint(1, 26)
            probes += 1
            live = _probe(start, start + length, source)
            hits += 1 if live[0] else 0
            assert live == _pre_fix_probe(start, start + length, source), (
                f"disjoint regression: span [{start:#x},{start + length:#x}) "
                f"over {source} answered {live}, pre-fix answered "
                f"{_pre_fix_probe(start, start + length, source)}"
            )
            assert live == _ground_truth(start, start + length, source), (
                f"disjoint answer disagrees with ground truth: span "
                f"[{start:#x},{start + length:#x}) over {source} -> {live}"
            )
    # Guard the sweep's PAYLOAD, not its loop arithmetic. ``probes == 8000``
    # alone is true by construction of the loop nest and would still hold if
    # every generated source were empty — it detects a short source list, not
    # a sweep that tested nothing.
    assert probes == 8000
    assert ranges_swept > 1000, (
        f"the generator emitted only {ranges_swept} ranges across "
        f"{len(sources)} sources — the sweep is not exercising the cover"
    )
    assert hits > 3000, (
        f"only {hits} of {probes} probes intersected anything — the spans are "
        "missing the ranges and the sweep proves little"
    )


# ---------------------------------------------------------------------------
# AT-223 / TC-524 — duplicate MAC point addresses (aliases)
# ---------------------------------------------------------------------------


def test_at223_tc524_duplicate_mac_addresses_resolve_to_first_declared() -> None:
    """AT-223 — aliases at one address resolve to the first declaration.

    ``examples/professional_validation/case_07_cross_reference_inconsistencies/
    firmware.mac`` ships exactly this shape (``ALIAS_1``/``ALIAS_2`` both at
    ``0x80200010``).  Two point records at one address are an overlap, so
    AT-221's disjoint sweep cannot reach it.  Pre-fix the bisect landed on the
    LAST duplicate — an artifact of ``bisect_right``, not a decision; D-2 makes
    the first declaration win.
    """
    mac_records = [
        {"name": "ALIAS_1", "address": 0x80200010, "parse_ok": True},
        {"name": "ALIAS_2", "address": 0x80200010, "parse_ok": True},
    ]
    source = _mac_linkage_source(mac_records)

    assert _probe(0x80200010, 0x80200011, source) == (True, "ALIAS_1")
    # Pins the direction of the change: the pre-fix shape answered ALIAS_2.
    assert _pre_fix_probe(0x80200010, 0x80200011, source) == (True, "ALIAS_2")


def test_at223_tc524_equal_start_unequal_length_uses_declaration_order() -> None:
    """AT-223 (tie-break arm) — equal starts break to DECLARATION order.

    ``R-CHG-002`` Amendment A states "ties resolving to declaration order",
    and the alias test above cannot pin it: two MAC records at one address
    project onto identical ``[a, a + 1)`` ranges, so start **and** end tie and
    every sort key yields the same order.

    Two A2L tags at one address with *different* lengths — a struct and its
    first member, or a duplicated ``CHARACTERISTIC`` — do discriminate.  A sort
    key of ``(start, end)`` instead of ``start`` would silently pick the
    SHORTER range, which is precisely the innermost/most-specific semantics
    D-2 REJECTED.  Without this test that drift ships green.
    """
    a2l_tags = [
        {"name": "DECLARED_FIRST", "address": 0x4000, "length": 0x100},
        {"name": "DECLARED_SECOND", "address": 0x4000, "length": 0x008},
    ]
    source = _a2l_linkage_source(a2l_tags)

    assert _probe(0x4002, 0x4003, source) == (True, "DECLARED_FIRST")
    assert _ground_truth(0x4002, 0x4003, source) == (True, "DECLARED_FIRST")
    # Reversing only the DECLARATION order must flip the answer — otherwise
    # this test is pinning the lengths, not the tie-break.
    reversed_source = _a2l_linkage_source(list(reversed(a2l_tags)))
    assert _probe(0x4002, 0x4003, reversed_source) == (True, "DECLARED_SECOND")


def test_at223_tc524_distinct_adjacent_mac_addresses_are_not_coalesced() -> None:
    """AT-223 (control) — adjacent-but-distinct MAC points keep their symbols.

    MAC records project onto ``[a, a + 1)``, so consecutive addresses abut
    exactly.  A cover that coalesced on ``>=`` instead of ``>`` would swallow
    ``NEXT_SYM`` here while leaving the alias test above green.
    """
    mac_records = [
        {"name": "FIRST_SYM", "address": 0x1000, "parse_ok": True},
        {"name": "NEXT_SYM", "address": 0x1001, "parse_ok": True},
    ]
    source = _mac_linkage_source(mac_records)

    assert _probe(0x1000, 0x1001, source) == (True, "FIRST_SYM")
    assert _probe(0x1001, 0x1002, source) == (True, "NEXT_SYM")


def test_at221_tc522_a2l_overlapping_tags_do_not_lose_attribution() -> None:
    """AT-221 (attribution arm) — coalescing must never drop the symbol.

    The rejected ``build_sorted_range_index(_merge_ranges(...))`` fix is
    correct for membership and wrong here: it destroys which symbol owned
    which span.  This asserts the surviving cover still names a symbol at
    every covered address.
    """
    a2l_tags = [
        {"name": "TABLE_A", "address": 0x4000, "length": 0x100},
        {"name": "TABLE_B", "address": 0x4080, "length": 0x100},
    ]
    source = _a2l_linkage_source(a2l_tags)

    for address in (0x4000, 0x4080, 0x40FF, 0x4100, 0x417F):
        hit, symbol = _probe(address, address + 1, source)
        assert hit is True, f"{address:#x} is covered but resolved to no linkage"
        assert symbol is not None, f"{address:#x} resolved to a nameless range"
    # Past both tags there is genuinely nothing.
    assert _probe(0x4180, 0x4181, source) == (False, None)


def test_at221_tc522_partial_overlap_region_reports_the_earlier_tag() -> None:
    """AT-221 (partial-overlap arm) — R-CHG-002 Amendment A, third row.

    Two A2L tags that overlap **partially** (neither nested) are the third
    documented behaviour change, and the one an operator is most likely to
    notice: pre-fix the overlap region reported a wrong-but-plausible NAME
    (``TABLE_B``), not ``None``, so comparing an old report against a new one
    shows a symbol *changing* rather than a gap being *filled*.

    The attribution arm above asserts only that *some* symbol survives, which
    cannot distinguish first-by-start from last-by-start.  This pins the value.
    """
    a2l_tags = [
        {"name": "TABLE_A", "address": 0x4000, "length": 0x100},
        {"name": "TABLE_B", "address": 0x4080, "length": 0x100},
    ]
    source = _a2l_linkage_source(a2l_tags)

    # Inside the overlap [0x4080, 0x4100): the EARLIER-declared tag wins.
    for address in (0x4080, 0x40C0, 0x40FF):
        assert _probe(address, address + 1, source) == (True, "TABLE_A")
        assert _pre_fix_probe(address, address + 1, source) == (True, "TABLE_B")
    # Past TABLE_A's end only TABLE_B remains — unchanged by the fix.
    assert _probe(0x4100, 0x4101, source) == (True, "TABLE_B")
    assert _pre_fix_probe(0x4100, 0x4101, source) == (True, "TABLE_B")


# ---------------------------------------------------------------------------
# AT-222 / TC-523 — the same guarantees through both public consumers
# ---------------------------------------------------------------------------


def _document(kind: str, entries: List[ChangeEntry]) -> ChangeDocument:
    """Build a minimal v2 document of ``kind`` around ``entries``."""
    return ChangeDocument(
        format=FORMAT_ID,
        version=FORMAT_VERSION,
        kind=kind,
        encoding="utf-8",
        value_mode="text",
        entries=entries,
    )


def test_at222_tc523_overlap_counterexample_through_apply_entry_point() -> None:
    """AT-222 (apply arm) — the fix is observable on ``ChangeSummary``.

    Drives the counterexample through ``apply_change_document`` so the
    assertion lands on the operator-visible ``linkage_symbol``, not on the
    module-private probe.
    """
    a2l_tags = [
        {"name": "BIG_ARRAY", "address": 0x1000, "length": 0x8000},
        {"name": "INNER", "address": 0x2000, "length": 0x10},
    ]
    mem_map = {address: 0x00 for address in range(0x1000, 0x9000)}
    document = _document("change", [ChangeEntry("bytes", PROBE_ADDRESS, (0xAA,))])

    summary = apply_change_document(
        document, mem_map, [(0x1000, 0x9000)], None, a2l_tags
    )

    assert summary.entries[0].linkage_symbol == "BIG_ARRAY"


def test_at222_tc523_overlap_counterexample_through_check_entry_point() -> None:
    """AT-222 (check arm) — the shared probe is fixed for BOTH consumers.

    ``check.py`` imports the linkage helpers from ``apply`` and builds its own
    indexes at ``check.py:293-294``.  A fix verified only through ``apply``
    leaves this consumer unproven, so it gets its own assertion rather than an
    argument that the code is shared.
    """
    a2l_tags = [
        {"name": "BIG_ARRAY", "address": 0x1000, "length": 0x8000},
        {"name": "INNER", "address": 0x2000, "length": 0x10},
    ]
    mem_map = {address: 0x00 for address in range(0x1000, 0x9000)}
    mem_map[PROBE_ADDRESS] = 0xAA
    document = _document("check", [ChangeEntry("bytes", PROBE_ADDRESS, (0xAA,))])

    result = run_check_document(
        document, mem_map, [(0x1000, 0x9000)], None, a2l_tags
    )

    assert result.entries[0].linkage_symbol == "BIG_ARRAY"


def test_at222_tc523_mac_alias_through_check_entry_point() -> None:
    """AT-222 (alias arm) — D-2's tie-break holds through ``check.py`` too."""
    mac_records = [
        {"name": "ALIAS_1", "address": 0x1010, "parse_ok": True},
        {"name": "ALIAS_2", "address": 0x1010, "parse_ok": True},
    ]
    mem_map = {address: 0x00 for address in range(0x1000, 0x1100)}
    mem_map[0x1010] = 0xAA
    document = _document("check", [ChangeEntry("bytes", 0x1010, (0xAA,))])

    result = run_check_document(
        document, mem_map, [(0x1000, 0x1100)], mac_records, None
    )

    assert result.entries[0].linkage_symbol == "ALIAS_1"
