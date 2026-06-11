"""
v2 intra-document collision tests — batch-07 increment E1 (TC-005).

Covers LLR-001.5: target ranges derive from the ENCODED byte length
(``ChangeEntry.addressed_range``), intersecting ranges or identical
addresses are ERROR ``CHG-COLLISION`` — one issue per colliding entry
naming both addresses, never raw byte content (C-9). Six parametrized
overlap geometries with exact expected issue counts, the 3-entry chain
case, and the multi-byte-encoding case where the encoded length collides
while the character count would not.

All cases drive the full read pipeline (``read_change_document``) so the
collision rule is exercised exactly where HLR-001 statement 4 places it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from s19_app.tui.changes import (
    CHG_COLLISION,
    FORMAT_ID,
    FORMAT_VERSION,
    read_change_document,
)


def _write_doc(
    tmp_path: Path,
    entries: list[dict],
    value_mode: str = "text",
    name: str = "doc.json",
) -> str:
    """Write a valid v2 document carrying ``entries`` and return its path."""
    payload = {
        "format": FORMAT_ID,
        "version": FORMAT_VERSION,
        "kind": "change",
        "encoding": "utf-8",
        "value_mode": value_mode,
        "entries": entries,
    }
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def _bytes_entry(address: str, byte_count: int) -> dict:
    """Build a bytes entry of ``byte_count`` distinct tokens at ``address``."""
    tokens = " ".join(f"{(i + 1) & 0xFF:02X}" for i in range(byte_count))
    return {"type": "bytes", "address": address, "bytes": tokens}


# ---------------------------------------------------------------------------
# TC-005 — the 6 parametrized overlap geometries, exact issue counts.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("entries", "expected_collisions"),
    [
        pytest.param(
            [_bytes_entry("0x100", 2), _bytes_entry("0x200", 2)],
            0,
            id="disjoint",
        ),
        pytest.param(
            # [0x100, 0x102) and [0x102, 0x104) touch but do not intersect:
            # half-open adjacency is NOT a collision.
            [_bytes_entry("0x100", 2), _bytes_entry("0x102", 2)],
            0,
            id="adjacent",
        ),
        pytest.param(
            # [0x100, 0x104) and [0x102, 0x106): edge overlap of 2 bytes.
            [_bytes_entry("0x100", 4), _bytes_entry("0x102", 4)],
            2,
            id="edge-overlap",
        ),
        pytest.param(
            # [0x100, 0x108) fully contains [0x102, 0x104).
            [_bytes_entry("0x100", 8), _bytes_entry("0x102", 2)],
            2,
            id="containment",
        ),
        pytest.param(
            # Identical addresses: v2 keeps both entries and flags the
            # collision (the batch-04 silent dedup is retired — gate D2).
            [_bytes_entry("0x100", 1), _bytes_entry("0x100", 1)],
            2,
            id="identical-address",
        ),
        pytest.param(
            # Cross-kind: a 2-char ASCII string spans [0x100, 0x102); the
            # byte patch at 0x101 lands inside it.
            [
                {"type": "string", "address": "0x100", "value": "AB"},
                {"type": "bytes", "address": "0x101", "bytes": "FF"},
            ],
            2,
            id="string-vs-bytes-cross-kind",
        ),
    ],
)
def test_collision_geometries(
    tmp_path: Path, entries: list[dict], expected_collisions: int
) -> None:
    """Each geometry yields EXACTLY its expected CHG-COLLISION count, and a
    colliding document is marked not applicable (LLR-001.5 / HLR-001 (4))."""
    document = read_change_document(_write_doc(tmp_path, entries), tmp_path)

    collision_codes = [
        issue for issue in document.issues if issue.code == CHG_COLLISION
    ]
    assert len(collision_codes) == expected_collisions
    # Collisions are the only findings these fixtures can produce.
    assert len(document.issues) == expected_collisions
    assert document.has_errors is (expected_collisions > 0)
    # All entries parse — collision never drops an entry, it flags it.
    assert len(document.entries) == len(entries)


def test_collision_messages_name_both_addresses(tmp_path: Path) -> None:
    """Each collision issue names the entry's own address and its partner's
    address — and never the raw byte content (LLR-001.5 / C-9)."""
    entries = [_bytes_entry("0x100", 4), _bytes_entry("0x102", 4)]
    document = read_change_document(_write_doc(tmp_path, entries), tmp_path)

    assert len(document.issues) == 2
    first, second = document.issues
    assert "0x100" in first.message and "0x102" in first.message
    assert "0x102" in second.message and "0x100" in second.message
    assert first.address == 0x100
    assert second.address == 0x102
    # C-9: the fixture's token content never appears in a message.
    for issue in document.issues:
        assert "01 02 03 04" not in issue.message


# ---------------------------------------------------------------------------
# TC-005 — 3-entry chain: A∩B and B∩C → exactly 3 issues, one per entry.
# ---------------------------------------------------------------------------


def test_collision_three_entry_chain(tmp_path: Path) -> None:
    """A [0x100,0x104) ∩ B [0x103,0x107), B ∩ C [0x106,0x10A), A∌C — every
    chained entry collides, so exactly 3 CHG-COLLISION issues (one per
    colliding entry, not one per pair)."""
    entries = [
        _bytes_entry("0x100", 4),
        _bytes_entry("0x103", 4),
        _bytes_entry("0x106", 4),
    ]
    document = read_change_document(_write_doc(tmp_path, entries), tmp_path)

    codes = [issue.code for issue in document.issues]
    assert codes == [CHG_COLLISION, CHG_COLLISION, CHG_COLLISION]
    assert [issue.address for issue in document.issues] == [0x100, 0x103, 0x106]
    assert len(document.entries) == 3


# ---------------------------------------------------------------------------
# TC-005 — multi-byte encoding: ENCODED length collides, char count would not.
# ---------------------------------------------------------------------------


def test_collision_uses_encoded_length_not_char_count(tmp_path: Path) -> None:
    """"éé" is 2 characters but 4 UTF-8 bytes: its true span [0x100,0x104)
    collides with a byte patch at 0x102, which a char-count range
    [0x100,0x102) would have missed (LLR-001.5 — encoded length
    everywhere)."""
    entries = [
        {"type": "string", "address": "0x100", "value": "éé"},
        {"type": "bytes", "address": "0x102", "bytes": "FF"},
    ]
    document = read_change_document(_write_doc(tmp_path, entries), tmp_path)

    # The string entry's footprint is its encoded length.
    assert document.entries[0].encoded_bytes == tuple("éé".encode("utf-8"))
    assert document.entries[0].addressed_range == (0x100, 0x104)

    collision_issues = [
        issue for issue in document.issues if issue.code == CHG_COLLISION
    ]
    assert len(collision_issues) == 2
    assert document.has_errors
