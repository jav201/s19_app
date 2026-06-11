"""
v2 intra-document collision rule — s19_app batch-07, increment E1.

Implements LLR-001.5: every entry's target byte range is the half-open span
``(address, address + encoded_byte_length)`` (:attr:`ChangeEntry.
addressed_range` — encoded length, never character count), and two entries
whose target ranges intersect — or that declare identical addresses — each
collect one ERROR-severity ``CHG-COLLISION`` finding naming both addresses.

This is the v2 evolution of the batch-04 inter-entry overlap check
(``cdfx/memory_validate.py::_overlap_issues`` — the predicate
``a0 < b1 and b0 < a1`` is reused verbatim) with two deliberate, spec-pinned
departures:

- **Severity promotion** — batch-04 ``MEMV-OVERLAP`` was WARNING; the v2
  ``CHG-COLLISION`` is ERROR, because an intra-file collision means one
  declared location would overwrite another (LLR-001.5, gate decision D1).
- **Identical addresses are an explicit error** — batch-04 silently
  dedup-updated a re-added address (``memory.py`` LLR-001.3); v2 documents
  keep both entries and flag the collision (gate decision D2). The pairwise
  bookkeeping is therefore keyed by **entry index**, not by address.

Per constraint C-9 (``memory_validate.py:33-36``), an issue message names
only addresses, indices, and byte counts — never the raw byte or value
content, keeping proprietary firmware bytes out of the rotating log.

This module imports stdlib + the ``changes`` model + ``validation.model``
only: no JSON, no filesystem, no Textual.
"""

from __future__ import annotations

from typing import Sequence

from ...validation.model import ValidationIssue, ValidationSeverity
from .model import CHANGES_ARTIFACT, ChangeEntry

#: Stable ``ValidationIssue.code`` for an entry whose target byte range
#: intersects another entry's target byte range, or that declares the same
#: address as another entry (LLR-001.5 — NEW, ERROR severity; the v2
#: replacement for the batch-04 WARNING ``MEMV-OVERLAP``).
CHG_COLLISION = "CHG-COLLISION"


def collision_issues(
    entries: Sequence[ChangeEntry],
) -> list[ValidationIssue]:
    """
    Summary:
        Build one ERROR-severity ``CHG-COLLISION`` ``ValidationIssue`` for
        each entry whose target byte range intersects another entry's target
        byte range or whose address equals another entry's address
        (LLR-001.5).

    Args:
        entries (Sequence[ChangeEntry]): The document's entries in document
            order. Target ranges are read from ``ChangeEntry.addressed_range``
            — the **encoded**-byte-length span, so a multi-byte-encoded string
            collides over its true on-image footprint.

    Returns:
        list[ValidationIssue]: One ERROR issue per colliding entry, in entry
        order — an intersecting pair yields two issues, a three-entry chain
        (A∩B, B∩C) yields exactly three. Each issue names the entry's own
        address and one colliding partner's address; messages never embed raw
        byte or value content (C-9). Empty when no two entries collide.

    Data Flow:
        - Compare every distinct pair of entries once; two half-open ranges
          ``[a0, a1)`` and ``[b0, b1)`` intersect when ``a0 < b1 and b0 < a1``
          (the ``_overlap_issues`` predicate, reused). Identical addresses on
          non-empty runs always satisfy the predicate, and are additionally
          tested explicitly so the rule reads as specified.
        - Bookkeeping is keyed by entry **index** (v2 documents may carry two
          entries at one address — that is precisely the collision being
          reported), recording the first colliding partner per entry.
        - Emit one issue per colliding entry, in entry order.

    Dependencies:
        Uses:
            - ChangeEntry.addressed_range
            - ValidationIssue / ValidationSeverity
        Used by:
            - changes.io.read_change_document (the read-path collision check)
            - The E2 apply gate (a colliding document is not applicable).

    Example:
        >>> a = ChangeEntry("bytes", 0x100, (0x01, 0x02, 0x03, 0x04))
        >>> b = ChangeEntry("bytes", 0x102, (0x05, 0x06))
        >>> [issue.code for issue in collision_issues([a, b])]
        ['CHG-COLLISION', 'CHG-COLLISION']
    """
    partner_by_index: dict[int, int] = {}
    for i in range(len(entries)):
        a_start, a_end = entries[i].addressed_range
        for j in range(i + 1, len(entries)):
            b_start, b_end = entries[j].addressed_range
            same_address = entries[i].address == entries[j].address
            intersecting = a_start < b_end and b_start < a_end
            if same_address or intersecting:
                partner_by_index.setdefault(i, j)
                partner_by_index.setdefault(j, i)
    issues: list[ValidationIssue] = []
    for index, entry in enumerate(entries):
        partner_index = partner_by_index.get(index)
        if partner_index is None:
            continue
        partner = entries[partner_index]
        byte_count = len(entry.encoded_bytes)
        issues.append(
            ValidationIssue(
                code=CHG_COLLISION,
                severity=ValidationSeverity.ERROR,
                message=(
                    f"change entry {index} at address 0x{entry.address:X} "
                    f"({byte_count} bytes) collides with the entry at "
                    f"address 0x{partner.address:X} — two declarations "
                    "target the same memory"
                ),
                artifact=CHANGES_ARTIFACT,
                address=entry.address,
            )
        )
    return issues
