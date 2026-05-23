"""
Memory-field change validation — s19_app batch-04, increment 2.

This module is the raw-memory peer of the batch-03 parameter resolver: it takes
a :class:`MemoryChangeList` (increment 1) and the loaded firmware image's
address ranges, stamps every entry with a :class:`MemoryStatus` verdict, and
collects one :class:`ValidationIssue` per data-quality problem — never raising,
never aborting (the collect-don't-abort contract, LLR-002.2 / LLR-002.4).

Two independent checks run over the same list:

- **Range check (LLR-002.1 / .2 / .3)** — each entry's addressed half-open byte
  range ``(address, address + len(new_bytes))`` is tested against the loaded
  image's contiguous ``(start, end)`` ranges. The verdict is one of:
  ``inside`` (the run lies fully within a single loaded range), ``outside``
  (the run overlaps no loaded range at all), or ``partial`` (the run overlaps
  the loaded ranges but is not contained in a single one — this is the
  *single* verdict whether the run straddles one range edge or spans an
  inter-range gap touching two or more ranges). With no image loaded every
  entry is marked ``unvalidated-no-image``.

- **Inter-entry overlap check (LLR-002.4)** — every entry whose addressed byte
  range intersects the addressed byte range of another entry, with a distinct
  ``address``, collects one warning. This is a conflict between two distinct
  identities, separate from the LLR-001.3 same-address dedup.

The firmware image is consumed **read-only** through its ``ranges`` snapshot —
this module never re-parses a firmware file and never branches on the file
type (RK-4: ``S19File`` / ``IntelHexFile`` range parity). Membership is decided
with the shared :mod:`s19_app.range_index` binary-search primitive rather than
a linear scan, since many addresses are tested against many ranges.

Per constraint C-9 / S-006, an issue message references only the entry's
``address`` and a byte-count summary of the run — it never embeds the raw
``new_bytes`` content, keeping proprietary firmware bytes out of the rotating
log.

Implements LLR-002.1..LLR-002.4 and LLR-008.3.
"""

from __future__ import annotations

from typing import Optional, Sequence

from s19_app.range_index import (
    build_sorted_range_index,
    range_in_sorted_ranges,
)
from s19_app.validation.model import ValidationIssue, ValidationSeverity

from .memory import MemoryChange, MemoryChangeList, MemoryStatus

#: ``ValidationIssue.artifact`` tag for every finding this module produces, so
#: a consumer can tell a memory-change verdict from a parameter-change one
#: (LLR-008.3 — the artifact field identifies the producing concern).
MEMORY_VALIDATION_ARTIFACT = "memory-change"

#: Stable ``ValidationIssue.code`` for an entry whose addressed run lies
#: entirely outside every loaded image range (LLR-002.2).
MEMORY_OUTSIDE_CODE = "MEMV-OUTSIDE"

#: Stable ``ValidationIssue.code`` for an entry whose addressed run overlaps the
#: loaded ranges but is not contained in a single one — a range-edge straddle
#: or a gap-spanning run (LLR-002.1 / LLR-002.2).
MEMORY_PARTIAL_CODE = "MEMV-PARTIAL"

#: Stable ``ValidationIssue.code`` for an entry whose addressed byte range
#: intersects another entry's addressed byte range (LLR-002.4).
MEMORY_OVERLAP_CODE = "MEMV-OVERLAP"


def _range_status(
    entry: MemoryChange,
    range_index: tuple[list[int], list[int]],
    image_ranges: Sequence[tuple[int, int]],
) -> MemoryStatus:
    """
    Summary:
        Classify one memory-change entry's addressed byte range against the
        loaded image ranges as ``inside`` / ``partial`` / ``outside``
        (LLR-002.1).

    Args:
        entry (MemoryChange): The entry whose ``addressed_range`` is tested.
        range_index (tuple[list[int], list[int]]): The sorted ``(starts, ends)``
            binary-search index built from ``image_ranges``.
        image_ranges (Sequence[tuple[int, int]]): The loaded image's contiguous
            half-open ``(start, end)`` ranges — used for the overlap scan that
            distinguishes ``partial`` from ``outside``.

    Returns:
        MemoryStatus: ``INSIDE`` when the run is fully within one loaded range,
        ``OUTSIDE`` when it overlaps none, otherwise ``PARTIAL`` — the single
        verdict for a range-edge straddle and for a gap-spanning run alike.

    Data Flow:
        - First ask the binary-search index whether the whole run fits one
          range — that is the ``inside`` fast path.
        - Otherwise scan for any byte-level intersection with any range: at
          least one intersection means ``partial``, none means ``outside``.

    Dependencies:
        Uses:
            - range_in_sorted_ranges
            - MemoryStatus
    """
    start, end = entry.addressed_range
    length = end - start
    if range_in_sorted_ranges(start, length, range_index):
        return MemoryStatus.INSIDE
    # Not contained in a single range — does the run touch any range at all?
    # A run touching >= 2 ranges (gap-spanning) is still one PARTIAL verdict.
    for range_start, range_end in image_ranges:
        if start < range_end and range_start < end:
            return MemoryStatus.PARTIAL
    return MemoryStatus.OUTSIDE


def _range_issue(entry: MemoryChange) -> Optional[ValidationIssue]:
    """
    Summary:
        Build the one warning-level ``ValidationIssue`` for a ``partial`` or
        ``outside`` entry, or ``None`` for an ``inside`` /
        ``unvalidated-no-image`` entry (LLR-002.2).

    Args:
        entry (MemoryChange): The entry whose ``status`` has already been
            stamped by :func:`_range_status` (or left
            ``UNVALIDATED_NO_IMAGE``).

    Returns:
        Optional[ValidationIssue]: A warning issue naming the entry's
        ``address`` and the byte-run length when the status is ``PARTIAL`` or
        ``OUTSIDE``; ``None`` otherwise.

    Data Flow:
        - Branch on the stamped status; emit exactly one issue per problem
          entry — a gap-spanning entry is one ``PARTIAL`` entry, so it yields
          exactly one issue, not one per touched range.
        - The message carries only ``address`` and ``len(new_bytes)`` — never
          the raw bytes (constraint C-9).

    Dependencies:
        Uses:
            - ValidationIssue
    """
    byte_count = len(entry.new_bytes)
    if entry.status is MemoryStatus.OUTSIDE:
        return ValidationIssue(
            code=MEMORY_OUTSIDE_CODE,
            severity=ValidationSeverity.WARNING,
            message=(
                f"memory change at address 0x{entry.address:X} "
                f"({byte_count} bytes) targets memory outside every loaded "
                "image range"
            ),
            artifact=MEMORY_VALIDATION_ARTIFACT,
            address=entry.address,
        )
    if entry.status is MemoryStatus.PARTIAL:
        return ValidationIssue(
            code=MEMORY_PARTIAL_CODE,
            severity=ValidationSeverity.WARNING,
            message=(
                f"memory change at address 0x{entry.address:X} "
                f"({byte_count} bytes) is only partially within the loaded "
                "image ranges"
            ),
            artifact=MEMORY_VALIDATION_ARTIFACT,
            address=entry.address,
        )
    return None


def _overlap_issues(entries: list[MemoryChange]) -> list[ValidationIssue]:
    """
    Summary:
        Build one warning-level ``ValidationIssue`` for each entry whose
        addressed byte range intersects another entry's addressed byte range,
        the two entries having distinct ``address`` keys (LLR-002.4).

    Args:
        entries (list[MemoryChange]): The memory-change list's entries in
            deterministic insertion order.

    Returns:
        list[ValidationIssue]: One warning issue per overlapping entry, in
        entry order — so an intersecting pair yields two issues, one tagged on
        each entry's ``address``. The list is empty when no two entries
        overlap.

    Data Flow:
        - Compare every distinct pair of entries once; two half-open ranges
          ``[a0, a1)`` and ``[b0, b1)`` intersect when ``a0 < b1 and b0 < a1``.
        - An entry that overlaps any other entry is recorded once; its single
          issue names both colliding addresses.

    Dependencies:
        Uses:
            - ValidationIssue
    """
    overlapping: dict[int, int] = {}
    for i in range(len(entries)):
        a_start, a_end = entries[i].addressed_range
        for j in range(i + 1, len(entries)):
            b_start, b_end = entries[j].addressed_range
            if a_start < b_end and b_start < a_end:
                # Record the partner address for each side of the collision.
                overlapping.setdefault(entries[i].address, entries[j].address)
                overlapping.setdefault(entries[j].address, entries[i].address)
    issues: list[ValidationIssue] = []
    for entry in entries:
        partner = overlapping.get(entry.address)
        if partner is None:
            continue
        byte_count = len(entry.new_bytes)
        issues.append(
            ValidationIssue(
                code=MEMORY_OVERLAP_CODE,
                severity=ValidationSeverity.WARNING,
                message=(
                    f"memory change at address 0x{entry.address:X} "
                    f"({byte_count} bytes) overlaps the memory change at "
                    f"address 0x{partner:X}"
                ),
                artifact=MEMORY_VALIDATION_ARTIFACT,
                address=entry.address,
            )
        )
    return issues


def validate_memory_changes(
    memory_change_list: MemoryChangeList,
    loaded_file_ranges: Optional[Sequence[tuple[int, int]]],
) -> list[ValidationIssue]:
    """
    Summary:
        Validate every memory-change entry against the loaded firmware image's
        address ranges, stamping each entry's :class:`MemoryStatus` and
        collecting one :class:`ValidationIssue` per problem without aborting
        (HLR-002 / LLR-002.1..LLR-002.4).

    Args:
        memory_change_list (MemoryChangeList): The memory-change list to
            validate. Each entry's ``status`` field is updated in place.
        loaded_file_ranges (Optional[Sequence[tuple[int, int]]]): The loaded
            image's contiguous half-open ``(start, end)`` address ranges —
            normally ``LoadedFile.ranges``, consumed read-only. ``None`` (or an
            empty sequence) means no firmware image is loaded.

    Returns:
        list[ValidationIssue]: Every collected finding — one warning per
        ``partial`` / ``outside`` entry and one warning per overlapping entry —
        in a deterministic order (range issues in entry order, then overlap
        issues in entry order). Empty when no entry has a problem. The function
        never raises on a data-quality fault.

    Data Flow:
        - With no ranges, stamp every entry ``UNVALIDATED_NO_IMAGE`` and return
          no issues (LLR-002.3) — the list stays buildable before an image is
          loaded.
        - Otherwise build the binary-search range index once, then per entry:
          classify its addressed range (``inside`` / ``partial`` / ``outside``)
          and, for a ``partial`` / ``outside`` verdict, collect one issue.
        - Finally run the inter-entry overlap scan and append its issues.

    Dependencies:
        Uses:
            - build_sorted_range_index
            - _range_status
            - _range_issue
            - _overlap_issues
            - MemoryStatus
        Used by:
            - The Patch Editor's memory-change save / load / display path
              (later increments) and the unified change-set validation flow.

    Example:
        >>> from s19_app.tui.cdfx import MemoryChangeList
        >>> ml = MemoryChangeList()
        >>> _ = ml.add(0x100, [0x01, 0x02])
        >>> validate_memory_changes(ml, [(0x100, 0x200)])
        []
        >>> ml.get(0x100).status.value
        'inside'
    """
    entries = memory_change_list.entries

    # LLR-002.3 — no image: every entry is unvalidated, no issues, no raise.
    if not loaded_file_ranges:
        for entry in entries:
            entry.status = MemoryStatus.UNVALIDATED_NO_IMAGE
        return []

    image_ranges = list(loaded_file_ranges)
    range_index = build_sorted_range_index(image_ranges)

    issues: list[ValidationIssue] = []
    for entry in entries:
        entry.status = _range_status(entry, range_index, image_ranges)
        range_issue = _range_issue(entry)
        if range_issue is not None:
            issues.append(range_issue)

    # LLR-002.4 — inter-entry overlap is a separate, collect-don't-abort check.
    issues.extend(_overlap_issues(entries))
    return issues
