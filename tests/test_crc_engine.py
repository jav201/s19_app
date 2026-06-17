"""
Engine tests for the headless CRC32 compute module (batch-12 CRC_F2, I1b).

Pins the engine's correctness and FR2/FR3/FR4/FR5/FR7/FR8/FR9 behavior with
the §5.2 TC-101..107 cases. TC-101 is the load-bearing known-answer anchor —
without it the engine is only proven self-consistent (§5.1). Every test is
written to FAIL on a logic regression (Rule 9): the chaining/gap/order/filter
cases compare against an oracle that diverges if the property breaks.
"""

from __future__ import annotations

import zlib

from s19_app.tui.operations.crc import (
    DEFAULT_FINAL_XOR,
    DEFAULT_INIT,
    DEFAULT_POLYNOMIAL,
    compute_region_crc,
    compute_region_crcs,
    crc32_stream,
    decode_le32,
    encode_le32,
)


def _mem_from_bytes(base: int, payload: bytes) -> dict[int, int]:
    """Build a contiguous ``mem_map`` from ``payload`` starting at ``base``."""
    return {base + offset: value for offset, value in enumerate(payload)}


def test_known_answer_vector() -> None:
    """TC-101 — KAT anchor: default config reproduces CRC-32 of the check
    string ``b"123456789"`` == ``0xCBF43926`` (proves it is *really* CRC-32,
    not just internally consistent)."""
    assert crc32_stream(b"123456789") == 0xCBF43926
    # The engine's default path must agree with the zlib oracle on arbitrary
    # bytes too, not only the canonical vector.
    payload = bytes(range(256)) * 7
    assert crc32_stream(payload) == zlib.crc32(payload)


def test_segment_chaining_does_not_reset_state() -> None:
    """TC-102 — two gap-separated segments are digested through ONE CRC state;
    the chained CRC differs from the CRC of either segment alone, so the test
    fails if a future edit resets state between segments."""
    seg_a = b"\x10\x11\x12"
    seg_b = b"\x20\x21"
    mem = _mem_from_bytes(0, seg_a)
    mem.update(_mem_from_bytes(len(seg_a) + 4, seg_b))  # gap of 4 addresses

    chained = compute_region_crc(mem, 0, 0x100)
    assert chained == crc32_stream(seg_a + seg_b)
    assert chained != crc32_stream(seg_a)
    assert chained != crc32_stream(seg_b)


def test_gap_splits_segments_no_inserted_bytes() -> None:
    """TC-103 — gap bytes never enter the digest: the gapped two-segment CRC
    equals the CRC of the gap-free concatenation (FR4/FR7). A gap-fill bug
    (e.g. inserting 0x00 padding) would change the result and fail here."""
    seg_a = b"\xaa\xbb"
    seg_b = b"\xcc\xdd\xee"
    mem = _mem_from_bytes(0x1000, seg_a)
    mem.update(_mem_from_bytes(0x1000 + len(seg_a) + 16, seg_b))  # 16-addr gap

    gapped = compute_region_crc(mem, 0x1000, 0x2000)
    gap_free = crc32_stream(seg_a + seg_b)
    assert gapped == gap_free
    # Guard: a single padding byte would have changed the answer.
    assert gapped != crc32_stream(seg_a + b"\x00" + seg_b)


def test_ascending_address_ordering() -> None:
    """TC-104 — descending-address input yields the ascending-order CRC (FR2):
    insertion order into the map must not affect the result."""
    payload = b"\x01\x02\x03\x04\x05"
    descending = {0x40 + i: payload[i] for i in reversed(range(len(payload)))}
    ascending = _mem_from_bytes(0x40, payload)

    assert compute_region_crc(descending, 0x40, 0x80) == crc32_stream(payload)
    assert compute_region_crc(descending, 0x40, 0x80) == compute_region_crc(
        ascending, 0x40, 0x80
    )


def test_region_filter_excludes_out_of_range() -> None:
    """TC-105 — only bytes inside the region enter the digest (FR3): bytes
    outside ``[start, end)`` must not affect the CRC."""
    in_region = b"\x11\x22\x33"
    mem = _mem_from_bytes(0x200, in_region)
    # Out-of-region noise on both sides of the half-open window.
    mem[0x1FF] = 0xFF
    mem[0x203] = 0xEE  # 0x200..0x202 are in region [0x200, 0x203)

    assert compute_region_crc(mem, 0x200, 0x203) == crc32_stream(in_region)
    # Multi-region entry point returns one CRC per region, in config order.
    crcs = compute_region_crcs(mem, [(0x200, 0x203), (0x1FF, 0x200)])
    assert crcs == [crc32_stream(in_region), crc32_stream(b"\xff")]


def test_config_params_change_result() -> None:
    """TC-106 — non-default poly/init/reverse/xorout CHANGE the digest vs the
    default, proving the params are real wired inputs (NOT a correctness
    anchor; absolute non-zlib correctness is RK-3-deferred)."""
    data = b"\xde\xad\xbe\xef"
    default = crc32_stream(data)

    assert crc32_stream(data, polynomial=0x1EDC6F41) != default  # CRC-32C poly
    assert crc32_stream(data, init=0x00000000) != default
    assert crc32_stream(data, reverse=False) != default
    assert crc32_stream(data, final_xor=0x00000000) != default
    # Sanity: re-passing the documented defaults reproduces the default.
    assert (
        crc32_stream(
            data,
            polynomial=DEFAULT_POLYNOMIAL,
            init=DEFAULT_INIT,
            reverse=True,
            final_xor=DEFAULT_FINAL_XOR,
        )
        == default
    )


def test_bitwise_path_reproduces_published_variant_kats() -> None:
    """TC-106b (review F1, HIGH) — the hand-rolled bitwise loop (the NON-default
    path; the default short-circuits to ``zlib.crc32``) must reproduce PUBLISHED
    CRC-32 variant known-answers for ``b"123456789"``, pinning the refin/refout
    and final-XOR machinery that TC-106's inequality-only checks cannot catch.
    A wrong final reflection (a classic refout bug) passes TC-106 but FAILS here.

    Reference values are standard catalog check constants (independent of this
    engine):
      * CRC-32/BZIP2  (poly 0x04C11DB7, refin/refout=False) = 0xFC891918
      * CRC-32C/Castagnoli (poly 0x1EDC6F41, refin/refout=True) = 0xE3069283
    """
    data = b"123456789"
    # reverse=False exercises the bitwise loop with NO reflection (refin/refout
    # both off) — the path most sensitive to a reflection bug.
    assert crc32_stream(data, reverse=False) == 0xFC891918
    # A non-default poly with the default reflected convention.
    assert crc32_stream(data, polynomial=0x1EDC6F41) == 0xE3069283


def test_le_codec_roundtrip() -> None:
    """TC-107 — the fixed 4-byte little-endian codec round-trips a known u32,
    and the byte layout is little-endian (low byte first)."""
    value = 0xCBF43926
    assert decode_le32(encode_le32(value)) == value
    assert encode_le32(0x04030201) == b"\x01\x02\x03\x04"
    # decode accepts a list sliced from a mem_map, not only a bytes object.
    assert decode_le32([0x01, 0x02, 0x03, 0x04]) == 0x04030201


def test_entry_point_does_not_mutate_mem_map() -> None:
    """LLR-001.3 — the entry point returns one CRC per region in config order
    and does not mutate the input ``mem_map`` (pure compute)."""
    mem = _mem_from_bytes(0, b"\x01\x02\x03\x04\x05\x06")
    snapshot = dict(mem)

    crcs = compute_region_crcs(mem, [(0, 3), (3, 6)])

    assert crcs == [
        compute_region_crc(mem, 0, 3),
        compute_region_crc(mem, 3, 6),
    ]
    assert mem == snapshot  # zero mutation
