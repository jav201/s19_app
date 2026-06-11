"""
TC-006 — image-containment classification of v2 change entries (LLR-001.6).

Five cases against a two-range image: fully inside, range-edge straddle,
inter-range gap spanning, fully outside, and the no-image blanket
``UNVALIDATED_NO_IMAGE`` stamp — plus the no-issues guarantee in both
branches.
"""

from __future__ import annotations

import pytest

from s19_app.tui.changes import (
    FORMAT_ID,
    FORMAT_VERSION,
    ChangeDocument,
    ChangeEntry,
    MemoryStatus,
    classify_containment,
)

#: Two contiguous loaded ranges with a gap 0x110-0x120 between them.
IMAGE_RANGES = [(0x100, 0x110), (0x120, 0x130)]


def _document(entries: list[ChangeEntry]) -> ChangeDocument:
    return ChangeDocument(
        format=FORMAT_ID,
        version=FORMAT_VERSION,
        kind="change",
        encoding="utf-8",
        value_mode="text",
        entries=entries,
    )


@pytest.mark.parametrize(
    ("address", "byte_run", "expected_status"),
    [
        pytest.param(
            0x100, (0x01, 0x02, 0x03, 0x04), MemoryStatus.INSIDE,
            id="inside-single-range",
        ),
        pytest.param(
            0x10E, (0x01, 0x02, 0x03, 0x04), MemoryStatus.PARTIAL,
            id="edge-straddle-is-partial",
        ),
        pytest.param(
            0x108, tuple(range(0x20)), MemoryStatus.PARTIAL,
            id="gap-spanning-is-partial",
        ),
        pytest.param(
            0x200, (0xFF,), MemoryStatus.OUTSIDE,
            id="outside-every-range",
        ),
    ],
)
def test_containment_status_with_image(
    address: int, byte_run: tuple[int, ...], expected_status: MemoryStatus
) -> None:
    document = _document([ChangeEntry("bytes", address, byte_run)])

    classify_containment(document, IMAGE_RANGES)

    assert document.entries[0].status is expected_status
    assert document.issues == []


def test_no_image_stamps_every_entry_unvalidated_with_no_issues() -> None:
    entries = [
        ChangeEntry("bytes", 0x100, (0x01,)),
        ChangeEntry("bytes", 0x200, (0x02,)),
        # Pre-stamped INSIDE to prove the no-image branch overwrites stale
        # verdicts rather than skipping already-classified entries.
        ChangeEntry("bytes", 0x104, (0x03,), status=MemoryStatus.INSIDE),
    ]
    document = _document(entries)

    classify_containment(document, None)

    assert all(
        entry.status is MemoryStatus.UNVALIDATED_NO_IMAGE
        for entry in document.entries
    )
    assert document.issues == []
