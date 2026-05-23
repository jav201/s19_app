"""
Memory-change validation tests — s19_app batch-04, increment 2.

Covers the §5 catalogue cases for HLR-002 that depend on the loaded-image
validator (``s19_app/tui/cdfx/memory_validate.py``):

- TC-005 — ``validate_memory_changes`` stamps each entry ``inside`` /
  ``partial`` / ``outside`` against a real ``make_ranged_s19`` ``LoadedFile``;
  a gap-spanning run that touches two ranges receives the single status
  ``partial`` (LLR-002.1).
- TC-006 — an ``outside`` entry, a ``partial`` entry, and a gap-spanning entry
  each collect exactly one warning ``ValidationIssue``; the list stays usable;
  no issue message echoes the raw ``new_bytes`` (LLR-002.2).
- TC-007 — with no image loaded every entry is ``unvalidated-no-image``; the
  list is still buildable; no exception (LLR-002.3).
- TC-008 (overlap arm) — the ``memory_change_factory`` overlap pair, two
  distinct start addresses with intersecting runs, each collect exactly one
  overlap warning (LLR-002.4). The TC-008 ``ValueError`` arms are construction
  -time and live in ``test_memory_changelist.py``.

The validator's findings are also asserted to be ``ValidationIssue`` records
whose severity round-trips through ``css_class_for_severity`` (LLR-008.3).
"""

from __future__ import annotations

from s19_app.tui.cdfx import MemoryChangeList, MemoryStatus, validate_memory_changes
from s19_app.tui.cdfx.memory_validate import (
    MEMORY_OUTSIDE_CODE,
    MEMORY_OVERLAP_CODE,
    MEMORY_PARTIAL_CODE,
    MEMORY_VALIDATION_ARTIFACT,
)
from s19_app.tui.color_policy import css_class_for_severity
from s19_app.validation.model import ValidationIssue, ValidationSeverity
from tests.conftest import (
    MEMORY_OVERLAP_PAIR,
    RANGED_S19_RANGES,
    memory_change_factory,
)


# ---------------------------------------------------------------------------
# TC-005 — Validate an entry against the loaded image ranges (LLR-002.1)
# ---------------------------------------------------------------------------


def test_tc005_entry_fully_inside_a_range_is_inside(ranged_s19) -> None:
    """An entry whose whole run falls inside a loaded range is ``inside``."""
    ml = MemoryChangeList()
    # range 1 is [0x100, 0x180); a 4-byte run at 0x110 is fully contained.
    ml.add(0x110, [0x01, 0x02, 0x03, 0x04])

    validate_memory_changes(ml, ranged_s19.ranges)

    assert ml.get(0x110).status is MemoryStatus.INSIDE


def test_tc005_entry_crossing_a_range_end_is_partial(ranged_s19) -> None:
    """A run that starts in a range and runs past its end edge is ``partial``."""
    ml = memory_change_factory("partial")
    (entry,) = ml.entries

    validate_memory_changes(ml, ranged_s19.ranges)

    # 0x178 + 0x10 = 0x188 — past range 1's 0x180 end.
    assert entry.addressed_range == (0x178, 0x188)
    assert entry.status is MemoryStatus.PARTIAL


def test_tc005_entry_in_the_inter_range_gap_is_outside(ranged_s19) -> None:
    """A run that falls in the gap between two ranges is ``outside``."""
    ml = memory_change_factory("outside")
    (entry,) = ml.entries

    validate_memory_changes(ml, ranged_s19.ranges)

    # [0x190, 0x198) is wholly inside the [0x180, 0x200) gap.
    assert entry.addressed_range == (0x190, 0x198)
    assert entry.status is MemoryStatus.OUTSIDE


def test_tc005_gap_spanning_entry_is_a_single_partial(ranged_s19) -> None:
    """
    A run starting in range 1, crossing the gap, and ending in range 2 gets
    the single status ``partial`` — not one status per touched range.
    """
    ml = memory_change_factory("gap-spanning")
    (entry,) = ml.entries

    validate_memory_changes(ml, ranged_s19.ranges)

    # [0x170, 0x270) touches range 1, the gap, and range 2.
    assert entry.addressed_range == (0x170, 0x270)
    assert entry.status is MemoryStatus.PARTIAL


def test_tc005_validator_reads_loadedfile_ranges_no_reparse(ranged_s19) -> None:
    """
    The validator consumes the ``LoadedFile.ranges`` snapshot directly — the
    fixture's ranges are exactly the documented ``RANGED_S19_RANGES``, so the
    verdicts are pinned to known boundaries with no firmware re-parse.
    """
    assert tuple(ranged_s19.ranges) == RANGED_S19_RANGES


# ---------------------------------------------------------------------------
# TC-006 — Out-of-range / partial entries collect a warning, never abort
#          (LLR-002.2)
# ---------------------------------------------------------------------------


def test_tc006_outside_entry_collects_one_warning(ranged_s19) -> None:
    """An ``outside`` entry produces exactly one warning issue naming its
    address; the list stays usable."""
    ml = memory_change_factory("outside")

    issues = validate_memory_changes(ml, ranged_s19.ranges)

    outside = [i for i in issues if i.code == MEMORY_OUTSIDE_CODE]
    assert len(outside) == 1
    assert outside[0].severity is ValidationSeverity.WARNING
    assert outside[0].address == 0x190
    # The list is still usable after the flag.
    assert len(ml) == 1


def test_tc006_partial_entry_collects_one_warning(ranged_s19) -> None:
    """A ``partial`` entry produces exactly one warning issue."""
    ml = memory_change_factory("partial")

    issues = validate_memory_changes(ml, ranged_s19.ranges)

    partial = [i for i in issues if i.code == MEMORY_PARTIAL_CODE]
    assert len(partial) == 1
    assert partial[0].severity is ValidationSeverity.WARNING
    assert partial[0].address == 0x178


def test_tc006_gap_spanning_entry_collects_exactly_one_warning(
    ranged_s19,
) -> None:
    """
    A gap-spanning entry touching two loaded ranges produces exactly one
    warning issue — not one per touched range.
    """
    ml = memory_change_factory("gap-spanning")

    issues = validate_memory_changes(ml, ranged_s19.ranges)

    partial = [i for i in issues if i.code == MEMORY_PARTIAL_CODE]
    assert len(partial) == 1
    assert partial[0].address == 0x170


def test_tc006_inside_entry_collects_no_issue(ranged_s19) -> None:
    """An ``inside`` entry produces no issue at all."""
    ml = MemoryChangeList()
    ml.add(0x110, [0xAA, 0xBB])

    issues = validate_memory_changes(ml, ranged_s19.ranges)

    assert issues == []


def test_tc006_validator_never_raises(ranged_s19) -> None:
    """Collect-don't-abort: a list of problem entries returns issues, no raise."""
    ml = MemoryChangeList()
    ml.add(0x190, [0x01, 0x02])  # outside
    ml.add(0x178, [(0x178 + k) & 0xFF for k in range(0x10)])  # partial

    issues = validate_memory_changes(ml, ranged_s19.ranges)

    assert len(issues) == 2
    assert len(ml) == 2


def test_tc006_issue_message_omits_raw_new_bytes(ranged_s19) -> None:
    """
    No issue message embeds the raw ``new_bytes`` content verbatim (C-9): the
    distinctive sentinel byte values must not appear as two-digit hex tokens —
    the form the bytes would take if they leaked into the message text.
    """
    ml = MemoryChangeList()
    # Sentinel bytes whose hex form would be obvious if leaked into a message.
    ml.add(0x190, [0xCA, 0xFE, 0xBA, 0xBE])

    issues = validate_memory_changes(ml, ranged_s19.ranges)

    assert len(issues) == 1
    message = issues[0].message
    for sentinel in (0xCA, 0xFE, 0xBA, 0xBE):
        assert f"{sentinel:02X}" not in message
    # The address and a byte-count summary are present instead.
    assert "0x190" in message
    assert "4 bytes" in message


# ---------------------------------------------------------------------------
# TC-007 — Validation without a loaded image (LLR-002.3)
# ---------------------------------------------------------------------------


def test_tc007_no_image_marks_every_entry_unvalidated() -> None:
    """With no image (``None`` ranges) every entry is ``unvalidated-no-image``;
    no exception; the list stays buildable and listable."""
    ml = memory_change_factory("base")

    issues = validate_memory_changes(ml, None)

    assert issues == []
    assert len(ml) == 3
    for entry in ml.entries:
        assert entry.status is MemoryStatus.UNVALIDATED_NO_IMAGE


def test_tc007_empty_ranges_also_marks_unvalidated() -> None:
    """An empty ranges sequence is treated as no image loaded."""
    ml = MemoryChangeList()
    ml.add(0x100, [0x01])

    issues = validate_memory_changes(ml, [])

    assert issues == []
    assert ml.get(0x100).status is MemoryStatus.UNVALIDATED_NO_IMAGE


def test_tc007_empty_list_no_image_returns_no_issues() -> None:
    """An empty memory-change list with no image validates to no issues."""
    assert validate_memory_changes(MemoryChangeList(), None) == []


# ---------------------------------------------------------------------------
# TC-008 (overlap arm) — Inter-entry overlap check (LLR-002.4)
# ---------------------------------------------------------------------------


def test_tc008_overlap_pair_each_collects_one_overlap_warning(
    ranged_s19,
) -> None:
    """
    The factory overlap pair — distinct start addresses 0x100 and 0x104, each
    len 8, with intersecting runs — each produces exactly one overlap warning;
    the list stays usable, no exception.
    """
    ml = memory_change_factory("base")

    issues = validate_memory_changes(ml, ranged_s19.ranges)

    overlap = [i for i in issues if i.code == MEMORY_OVERLAP_CODE]
    assert len(overlap) == 2
    overlap_addresses = {i.address for i in overlap}
    assert overlap_addresses == {0x100, 0x104}
    for issue in overlap:
        assert issue.severity is ValidationSeverity.WARNING
    # The list is unchanged and still usable after the flag.
    assert len(ml) == 3


def test_tc008_overlap_pair_addresses_match_pinned_constant() -> None:
    """The overlap pair is the pinned 0x100/0x104 len-8 constant — distinct
    address keys, so identity dedup does not collapse them."""
    (first, _), (second, _) = MEMORY_OVERLAP_PAIR
    assert (first, second) == (0x100, 0x104)


def test_tc008_non_overlapping_entries_collect_no_overlap_warning(
    ranged_s19,
) -> None:
    """Two entries with disjoint addressed ranges produce no overlap warning."""
    ml = MemoryChangeList()
    ml.add(0x100, [0x01, 0x02])  # [0x100, 0x102)
    ml.add(0x110, [0x03, 0x04])  # [0x110, 0x112) — disjoint

    issues = validate_memory_changes(ml, ranged_s19.ranges)

    assert [i for i in issues if i.code == MEMORY_OVERLAP_CODE] == []


def test_tc008_overlap_message_omits_raw_new_bytes(ranged_s19) -> None:
    """An overlap issue message names both addresses, never the raw bytes."""
    ml = MemoryChangeList()
    ml.add(0x100, [0xDE, 0xAD])  # [0x100, 0x102)
    ml.add(0x101, [0xBE, 0xEF])  # [0x101, 0x103) — overlaps on [0x101, 0x102)

    issues = validate_memory_changes(ml, ranged_s19.ranges)

    overlap = [i for i in issues if i.code == MEMORY_OVERLAP_CODE]
    assert len(overlap) == 2
    for issue in overlap:
        for sentinel in (0xDE, 0xAD, 0xBE, 0xEF):
            assert f"{sentinel:02X}" not in issue.message
        # Both colliding addresses are named instead of the raw bytes.
        assert "0x100" in issue.message
        assert "0x101" in issue.message


# ---------------------------------------------------------------------------
# LLR-008.3 — findings are ValidationIssue, severity round-trips to a CSS class
# ---------------------------------------------------------------------------


def test_findings_are_validationissue_with_round_tripping_severity(
    ranged_s19,
) -> None:
    """
    Every finding is a ``ValidationIssue`` tagged with the memory-change
    artifact, and its severity round-trips through ``css_class_for_severity``
    to a valid ``sev-*`` CSS class (LLR-008.3 / C-5).
    """
    ml = MemoryChangeList()
    ml.add(0x190, [0x01])  # outside
    ml.add(0x178, [(0x178 + k) & 0xFF for k in range(0x10)])  # partial
    # An overlapping pair so an overlap finding is produced too.
    ml.add(0x110, [0x01, 0x02, 0x03])  # [0x110, 0x113)
    ml.add(0x111, [0x04, 0x05])  # [0x111, 0x113) — overlaps the previous

    issues = validate_memory_changes(ml, ranged_s19.ranges)

    assert issues, "expected findings for the seeded problem entries"
    for issue in issues:
        assert isinstance(issue, ValidationIssue)
        assert issue.artifact == MEMORY_VALIDATION_ARTIFACT
        css_class = css_class_for_severity(issue.severity)
        assert css_class.startswith("sev-")
