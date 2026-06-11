"""
TC-014 — informative MAC/A2L linkage classification on the apply summary
(LLR-002.6).

One fixture drives all four exact classifications — MAC-only, A2L-only,
both, standalone — with the matching ``linkage_symbol`` captured; a second
test proves a both-linked OUTSIDE entry is still skipped (linkage never
influences disposition).
"""

from __future__ import annotations

from s19_app.tui.changes import (
    DISPOSITION_SKIPPED_OUTSIDE,
    FORMAT_ID,
    FORMAT_VERSION,
    LINKAGE_A2L,
    LINKAGE_BOTH,
    LINKAGE_MAC,
    LINKAGE_STANDALONE,
    ChangeDocument,
    ChangeEntry,
    apply_change_document,
)

IMAGE_RANGES = [(0x1000, 0x1100)]

MAC_RECORDS = [
    {"name": "MAC_SYM", "address": 0x1010, "parse_ok": True},
    {"name": "BOTH_SYM", "address": 0x1030, "parse_ok": True},
    # Non-parse-ok and address-less records must be ignored, never matched.
    {"name": "BROKEN", "address": 0x1080, "parse_ok": False},
    {"name": "NO_ADDR", "address": None, "parse_ok": True},
]

A2L_TAGS = [
    {"name": "A2L_SYM", "address": 0x1020, "length": 8},
    {"name": "BOTH_SYM", "address": 0x1030, "length": 4},
]


def _document(entries: list[ChangeEntry]) -> ChangeDocument:
    return ChangeDocument(
        format=FORMAT_ID,
        version=FORMAT_VERSION,
        kind="change",
        encoding="utf-8",
        value_mode="text",
        entries=entries,
    )


def _image_mem_map() -> dict[int, int]:
    return {address: 0x00 for address in range(0x1000, 0x1100)}


def test_four_linkage_classifications_with_symbols() -> None:
    document = _document(
        [
            ChangeEntry("bytes", 0x1010, (0xAA, 0xBB)),  # contains MAC point
            ChangeEntry("bytes", 0x1022, (0xCC,)),  # inside A2L_SYM range
            ChangeEntry("bytes", 0x1030, (0x01, 0x02)),  # MAC point + A2L range
            ChangeEntry("bytes", 0x1080, (0x99,)),  # touches neither
        ]
    )

    summary = apply_change_document(
        document, _image_mem_map(), IMAGE_RANGES, MAC_RECORDS, A2L_TAGS
    )

    assert [entry.linkage for entry in summary.entries] == [
        LINKAGE_MAC,
        LINKAGE_A2L,
        LINKAGE_BOTH,
        LINKAGE_STANDALONE,
    ]
    assert [entry.linkage_symbol for entry in summary.entries] == [
        "MAC_SYM",
        "A2L_SYM",
        "BOTH_SYM",
        None,
    ]
    # Linkage is informative: all four entries are INSIDE and were applied.
    assert summary.counts["applied"] == 4


def test_both_linked_outside_entry_is_still_skipped() -> None:
    # MAC record and A2L tag both sit at 0x2000 — outside the loaded image.
    mac_records = [{"name": "EXT_SYM", "address": 0x2000, "parse_ok": True}]
    a2l_tags = [{"name": "EXT_SYM", "address": 0x2000, "length": 4}]
    document = _document([ChangeEntry("bytes", 0x2000, (0xDE, 0xAD))])
    mem_map = _image_mem_map()
    before = dict(mem_map)

    summary = apply_change_document(
        document, mem_map, IMAGE_RANGES, mac_records, a2l_tags
    )

    entry = summary.entries[0]
    assert entry.linkage == LINKAGE_BOTH
    assert entry.linkage_symbol == "EXT_SYM"
    assert entry.disposition == DISPOSITION_SKIPPED_OUTSIDE
    assert entry.before_bytes is None
    assert mem_map == before
    assert summary.counts["skipped-outside"] == 1
    assert summary.counts["applied"] == 0
