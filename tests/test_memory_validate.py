"""
Memory-change validation tests — s19_app batch-04, increment 2; re-pointed to
the v2 ``changes`` engine at batch-07 E3b (§6.6 dispositions).

Covers the loaded-image containment classification
(``s19_app/tui/changes/apply.py::classify_containment``) and the v2
intra-document collision rule (``changes/validate.py::collision_issues``):

- TC-005 — ``classify_containment`` stamps each entry ``inside`` /
  ``partial`` / ``outside`` against a real ``make_ranged_s19``
  ``LoadedFile``; a gap-spanning run that touches two ranges receives the
  single status ``partial``.
- TC-006 — REWRITTEN to the v2 contract: out-of-range / partial entries are
  no longer WARNING issues — they surface as apply **dispositions**
  (``skipped-outside`` / ``skipped-partial``, LLR-002.2), exactly one per
  entry, collect-don't-abort.
- TC-007 — with no image loaded every entry is ``unvalidated-no-image``; the
  document is still buildable; no exception.
- TC-008 (overlap arm) — REWRITTEN (D2, resolved by LLR-001.5 at the
  2026-06-10 gate): the overlap pair is now an ERROR-severity
  ``CHG-COLLISION`` per colliding entry — the batch-04 WARNING was promoted
  because an intra-file collision means one declared location would
  overwrite another.

The findings are also asserted to be ``ValidationIssue`` records whose
severity round-trips through ``css_class_for_severity``.
"""

from __future__ import annotations

from s19_app.tui.changes import (
    CHANGES_ARTIFACT,
    CHG_COLLISION,
    ChangeEntry,
    MemoryStatus,
    apply_change_document,
    classify_containment,
    collision_issues,
)
from s19_app.tui.changes.io import FORMAT_ID, FORMAT_VERSION
from s19_app.tui.changes.model import ChangeDocument
from s19_app.tui.color_policy import css_class_for_severity
from s19_app.validation.model import ValidationIssue, ValidationSeverity
from tests.conftest import (
    MEMORY_OVERLAP_PAIR,
    RANGED_S19_RANGES,
    memory_change_factory,
)


def _document(entries: list[ChangeEntry]) -> ChangeDocument:
    """Build a valid v2 change envelope around the given entries."""
    return ChangeDocument(
        format=FORMAT_ID,
        version=FORMAT_VERSION,
        kind="change",
        encoding="utf-8",
        value_mode="text",
        entries=entries,
    )


# ---------------------------------------------------------------------------
# TC-005 — Validate an entry against the loaded image ranges (LLR-001.6)
# ---------------------------------------------------------------------------


def test_tc005_entry_fully_inside_a_range_is_inside(ranged_s19) -> None:
    """An entry whose whole run falls inside a loaded range is ``inside``."""
    # range 1 is [0x100, 0x180); a 4-byte run at 0x110 is fully contained.
    document = _document([ChangeEntry("bytes", 0x110, (0x01, 0x02, 0x03, 0x04))])

    classify_containment(document, ranged_s19.ranges)

    assert document.entries[0].status is MemoryStatus.INSIDE


def test_tc005_entry_crossing_a_range_end_is_partial(ranged_s19) -> None:
    """A run that starts in a range and runs past its end edge is ``partial``."""
    document = memory_change_factory("partial")
    (entry,) = document.entries

    classify_containment(document, ranged_s19.ranges)

    # 0x178 + 0x10 = 0x188 — past range 1's 0x180 end.
    assert entry.addressed_range == (0x178, 0x188)
    assert entry.status is MemoryStatus.PARTIAL


def test_tc005_entry_in_the_inter_range_gap_is_outside(ranged_s19) -> None:
    """A run that falls in the gap between two ranges is ``outside``."""
    document = memory_change_factory("outside")
    (entry,) = document.entries

    classify_containment(document, ranged_s19.ranges)

    # [0x190, 0x198) is wholly inside the [0x180, 0x200) gap.
    assert entry.addressed_range == (0x190, 0x198)
    assert entry.status is MemoryStatus.OUTSIDE


def test_tc005_gap_spanning_entry_is_a_single_partial(ranged_s19) -> None:
    """
    A run starting in range 1, crossing the gap, and ending in range 2 gets
    the single status ``partial`` — not one status per touched range.
    """
    document = memory_change_factory("gap-spanning")
    (entry,) = document.entries

    classify_containment(document, ranged_s19.ranges)

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
# TC-006 — Out-of-range / partial entries are flagged, never aborted.
#
# REWRITTEN at E3b: the batch-04 per-entry MEMV-OUTSIDE / MEMV-PARTIAL
# WARNINGs do not exist under the v2 model — ``classify_containment`` emits
# no issues (LLR-001.6) and the visible flag is the apply DISPOSITION
# (``skipped-outside`` / ``skipped-partial``, LLR-002.2). The §6.6 SURVIVES
# label on these rows was a misclassification (re-dispositioned per the §6.6
# vocabulary note); the intent — a problem entry is visibly flagged exactly
# once and never aborts the run — is preserved against the v2 observable.
# ---------------------------------------------------------------------------


def test_tc006_outside_entry_yields_one_skipped_outside_disposition(
    ranged_s19,
) -> None:
    """An ``outside`` entry is flagged exactly once — disposition
    ``skipped-outside`` — and the document stays usable."""
    document = memory_change_factory("outside")

    summary = apply_change_document(
        document, dict(ranged_s19.mem_map), ranged_s19.ranges, None, None
    )

    assert summary.counts["skipped-outside"] == 1
    assert [e.disposition for e in summary.entries] == ["skipped-outside"]
    # The document is still usable after the flag.
    assert len(document.entries) == 1


def test_tc006_partial_entry_yields_one_skipped_partial_disposition(
    ranged_s19,
) -> None:
    """A ``partial`` entry is flagged exactly once — ``skipped-partial``."""
    document = memory_change_factory("partial")

    summary = apply_change_document(
        document, dict(ranged_s19.mem_map), ranged_s19.ranges, None, None
    )

    assert summary.counts["skipped-partial"] == 1
    assert summary.entries[0].address_start == 0x178


def test_tc006_gap_spanning_entry_is_flagged_exactly_once(
    ranged_s19,
) -> None:
    """
    A gap-spanning entry touching two loaded ranges is flagged exactly once —
    one ``skipped-partial`` disposition, not one per touched range.
    """
    document = memory_change_factory("gap-spanning")

    summary = apply_change_document(
        document, dict(ranged_s19.mem_map), ranged_s19.ranges, None, None
    )

    assert summary.counts["skipped-partial"] == 1
    assert summary.entries[0].address_start == 0x170


def test_tc006_inside_entry_collects_no_issue(ranged_s19) -> None:
    """An ``inside`` entry produces no issue at all.

    SURVIVES: containment stamping plus the collision rule on a clean
    single-entry document collect nothing — the v2 composite of the batch-04
    ``validate_memory_changes`` call.
    """
    document = _document([ChangeEntry("bytes", 0x110, (0xAA, 0xBB))])

    classify_containment(document, ranged_s19.ranges)
    issues = collision_issues(document.entries)

    assert issues == []


def test_tc006_validator_never_raises(ranged_s19) -> None:
    """Collect-don't-abort: a document of problem entries is classified and
    applied without a raise — every entry receives exactly one disposition."""
    document = _document(
        [
            ChangeEntry("bytes", 0x190, (0x01, 0x02)),  # outside
            ChangeEntry(
                "bytes",
                0x178,
                tuple((0x178 + k) & 0xFF for k in range(0x10)),
            ),  # partial
        ]
    )

    summary = apply_change_document(
        document, dict(ranged_s19.mem_map), ranged_s19.ranges, None, None
    )

    assert summary.counts["skipped-outside"] == 1
    assert summary.counts["skipped-partial"] == 1
    assert len(document.entries) == 2


# ---------------------------------------------------------------------------
# TC-007 — Validation without a loaded image
# ---------------------------------------------------------------------------


def test_tc007_no_image_marks_every_entry_unvalidated() -> None:
    """With no image (``None`` ranges) every entry is ``unvalidated-no-image``;
    no exception; the document stays buildable and listable."""
    document = memory_change_factory("base")

    classify_containment(document, None)

    assert len(document.entries) == 3
    for entry in document.entries:
        assert entry.status is MemoryStatus.UNVALIDATED_NO_IMAGE


def test_tc007_empty_ranges_marks_outside() -> None:
    """An empty ranges sequence is a loaded-but-empty image: ``outside``.

    REWRITTEN nuance (v2 contract, ``classify_containment`` docstring):
    batch-04 treated an empty range list as no image; v2 distinguishes
    ``None`` (no image → ``unvalidated-no-image``) from an empty sequence
    (loaded, nothing mapped → every run is ``outside``).
    """
    document = _document([ChangeEntry("bytes", 0x100, (0x01,))])

    classify_containment(document, [])

    assert document.entries[0].status is MemoryStatus.OUTSIDE


def test_tc007_empty_list_no_image_returns_no_issues() -> None:
    """An empty document with no image validates to no issues."""
    document = _document([])
    classify_containment(document, None)
    assert collision_issues(document.entries) == []


# ---------------------------------------------------------------------------
# TC-008 (overlap arm) — Inter-entry collision check.
#
# REWRITTEN (D2, resolved by LLR-001.5): WARNING ``MEMV-OVERLAP`` promoted to
# ERROR ``CHG-COLLISION`` — an intra-file collision means one declared
# location would overwrite another, so the document is not applicable.
# ---------------------------------------------------------------------------


def test_tc008_overlap_pair_each_collects_one_collision_error() -> None:
    """
    The factory overlap pair — distinct start addresses 0x100 and 0x104, each
    len 8, with intersecting runs — each produces exactly one ERROR-severity
    ``CHG-COLLISION``; the document stays usable, no exception.
    """
    document = memory_change_factory("base")

    issues = collision_issues(document.entries)

    collisions = [i for i in issues if i.code == CHG_COLLISION]
    assert len(collisions) == 2
    collision_addresses = {i.address for i in collisions}
    assert collision_addresses == {0x100, 0x104}
    for issue in collisions:
        assert issue.severity is ValidationSeverity.ERROR
    # The document is unchanged and still usable after the flag.
    assert len(document.entries) == 3


def test_tc008_overlap_pair_addresses_match_pinned_constant() -> None:
    """The overlap pair is the pinned 0x100/0x104 len-8 constant — distinct
    addresses, so the two declarations stay two entries."""
    (first, _), (second, _) = MEMORY_OVERLAP_PAIR
    assert (first, second) == (0x100, 0x104)


def test_tc008_non_overlapping_entries_collect_no_collision_error() -> None:
    """Two entries with disjoint addressed ranges produce no collision."""
    document = _document(
        [
            ChangeEntry("bytes", 0x100, (0x01, 0x02)),  # [0x100, 0x102)
            ChangeEntry("bytes", 0x110, (0x03, 0x04)),  # [0x110, 0x112)
        ]
    )

    issues = collision_issues(document.entries)

    assert [i for i in issues if i.code == CHG_COLLISION] == []


def test_tc008_collision_message_omits_raw_new_bytes() -> None:
    """A collision message names both addresses, never the raw bytes (C-9).

    This also carries the batch-04 TC-006 confidentiality intent forward:
    the v2 validators produce only collision messages, and none may embed
    the distinctive sentinel bytes as two-digit hex tokens.
    """
    document = _document(
        [
            ChangeEntry("bytes", 0x100, (0xDE, 0xAD)),  # [0x100, 0x102)
            ChangeEntry("bytes", 0x101, (0xBE, 0xEF)),  # [0x101, 0x103)
        ]
    )

    issues = collision_issues(document.entries)

    collisions = [i for i in issues if i.code == CHG_COLLISION]
    assert len(collisions) == 2
    for issue in collisions:
        for sentinel in (0xDE, 0xAD, 0xBE, 0xEF):
            assert f"{sentinel:02X}" not in issue.message
        # Both colliding addresses are named instead of the raw bytes.
        assert "0x100" in issue.message
        assert "0x101" in issue.message


# ---------------------------------------------------------------------------
# Findings are ValidationIssue, severity round-trips to a CSS class
# ---------------------------------------------------------------------------


def test_findings_are_validationissue_with_round_tripping_severity(
    ranged_s19,
) -> None:
    """
    Every finding is a ``ValidationIssue`` tagged with the changes artifact,
    and its severity round-trips through ``css_class_for_severity`` to a
    valid ``sev-*`` CSS class (C-5).
    """
    document = _document(
        [
            ChangeEntry("bytes", 0x190, (0x01,)),  # outside
            ChangeEntry(
                "bytes",
                0x178,
                tuple((0x178 + k) & 0xFF for k in range(0x10)),
            ),  # partial
            # An overlapping pair so a collision finding is produced too.
            ChangeEntry("bytes", 0x110, (0x01, 0x02, 0x03)),  # [0x110, 0x113)
            ChangeEntry("bytes", 0x111, (0x04, 0x05)),  # [0x111, 0x113)
        ]
    )

    classify_containment(document, ranged_s19.ranges)
    issues = collision_issues(document.entries)

    assert issues, "expected findings for the seeded problem entries"
    for issue in issues:
        assert isinstance(issue, ValidationIssue)
        assert issue.artifact == CHANGES_ARTIFACT
        css_class = css_class_for_severity(issue.severity)
        assert css_class.startswith("sev-")
