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
    CrcTarget,
    compute_group_crc,
    compute_region_crc,
    compute_region_crcs,
    crc32_stream,
    decode_le,
    decode_le32,
    encode_le,
    encode_le32,
    normalized_targets,
    read_stored_crc_le,
)
from s19_app.tui.operations.crc_config import CrcConfig, CrcGroup, CrcRegion
from s19_app.tui.operations.model import OperationInput


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


# ---------------------------------------------------------------------------
# batch-32 (R-CRC-GROUP-001 / R-CRC-WIDTH-001) - group compute + width codec.
#
# AT-045a/b/e/f compute semantics (zlib / crc32_stream oracles), the B5
# contiguity identity and the AT-045d equivalence bridge (compute level),
# plus the LLR-WID-001.1/.2/.4 codec table (TC-202 family).
# ---------------------------------------------------------------------------

_SPAN_A = bytes(range(0x20, 0x60))          # 64 bytes
_SPAN_B = bytes(range(0xA0, 0xB0)) * 3      # 48 bytes


def _two_span_mem() -> "dict[int, int]":
    """Two disjoint fully-present spans: A @0x1000(64B), B @0x2000(48B)."""
    mem = _mem_from_bytes(0x1000, _SPAN_A)
    mem.update(_mem_from_bytes(0x2000, _SPAN_B))
    return mem


def test_at045a_group_crc_equals_zlib_over_declared_concat() -> None:
    """AT-045a: group CRC == zlib.crc32(bytes(A) + bytes(B)) (TC-202.1).

    Intent: the group stream is the declared-order concatenation digested by
    ONE non-resetting state - the independent zlib oracle proves it, not the
    engine's own primitives.
    """
    mem = _two_span_mem()
    crc = compute_group_crc(mem, [(0x1000, 0x1040), (0x2000, 0x2030)])
    assert crc == zlib.crc32(_SPAN_A + _SPAN_B)


def test_at045b_declared_order_not_address_order() -> None:
    """AT-045b: reversed declaration order gives the other oracle value and
    differs from AT-045a's (declared order, NOT address order) (TC-202.2)."""
    mem = _two_span_mem()
    crc_ba = compute_group_crc(mem, [(0x2000, 0x2030), (0x1000, 0x1040)])
    assert crc_ba == zlib.crc32(_SPAN_B + _SPAN_A)
    assert crc_ba != zlib.crc32(_SPAN_A + _SPAN_B), (
        "order-sensitive fixture required: A+B and B+A CRCs must differ"
    )


def test_at045e_non_default_params_flow_through_group_path() -> None:
    """AT-045e: non-default polynomial/init/reverse/final_xor flow through
    the group path - equals crc32_stream with the same params over the
    concatenated stream, and differs from the default-params CRC (TC-202.3)."""
    mem = _two_span_mem()
    spans = [(0x1000, 0x1040), (0x2000, 0x2030)]
    params = dict(
        polynomial=0x1EDC6F41, init=0x0, reverse=False, final_xor=0x0
    )
    crc = compute_group_crc(mem, spans, **params)
    assert crc == crc32_stream(_SPAN_A + _SPAN_B, **params)
    assert crc != compute_group_crc(mem, spans), (
        "non-default params must change the CRC or the wiring is unobserved"
    )


def test_at045f_duplicate_span_digested_each_time() -> None:
    """AT-045f / S-2: a span declared twice contributes its bytes twice -
    no dedup, no error (TC-202.4)."""
    mem = _mem_from_bytes(0x1000, _SPAN_A)
    crc = compute_group_crc(mem, [(0x1000, 0x1040), (0x1000, 0x1040)])
    assert crc == zlib.crc32(_SPAN_A + _SPAN_A)


def test_b5_adjacent_spans_equal_single_contiguous_range() -> None:
    """B5 contiguity identity: two adjacent spans declared in address order
    CRC identically to the single covering range (TC-202.5)."""
    mem = _mem_from_bytes(0x1000, _SPAN_A + _SPAN_B)
    split = compute_group_crc(
        mem, [(0x1000, 0x1000 + 64), (0x1000 + 64, 0x1000 + 112)]
    )
    whole = compute_group_crc(mem, [(0x1000, 0x1000 + 112)])
    assert split == whole == zlib.crc32(_SPAN_A + _SPAN_B)


def test_at045d_single_span_group_equals_legacy_region_crc() -> None:
    """AT-045d (compute level): a 1-span group CRC equals the legacy
    per-region CRC over the same (start, end) - the equivalence bridge
    (TC-202.6). The check/inject halves ride increment 3."""
    mem = _two_span_mem()
    assert compute_group_crc(mem, [(0x1000, 0x1040)]) == compute_region_crc(
        mem, 0x1000, 0x1040
    )


def test_at045c_gap_present_bytes_only_compute_half() -> None:
    """AT-045c (compute half): absent addresses inside a declared span
    contribute nothing - CRC covers present bytes only (TC-202.7; the
    diagnostic-note half rides increment 3)."""
    mem = _mem_from_bytes(0x1000, _SPAN_A)
    del mem[0x1010]  # one interior absent byte (B3 minimum segment split)
    expected = zlib.crc32(_SPAN_A[:0x10] + _SPAN_A[0x11:])
    assert compute_group_crc(mem, [(0x1000, 0x1040)]) == expected


def test_tc202_8_normalized_targets_order_and_widening() -> None:
    """LLR-GRP-001.4 / AT-044c (ordering oracle): legacy regions first
    (file order, single-span, width 4, is_group False), then groups (file
    order, is_group True) (TC-202.8)."""
    cfg = CrcConfig(
        regions=[CrcRegion(0x100, 0x200, 0x1FC), CrcRegion(0x300, 0x400, 0x3FC)],
        polynomial=DEFAULT_POLYNOMIAL,
        init=DEFAULT_INIT,
        reverse=True,
        final_xor=DEFAULT_FINAL_XOR,
        groups=[
            CrcGroup(spans=((0x500, 0x600), (0x700, 0x800)), output_address=0x7F8, output_bytes=8)
        ],
    )
    targets = normalized_targets(cfg)
    assert [t.is_group for t in targets] == [False, False, True]
    assert targets[0] == CrcTarget(
        spans=((0x100, 0x200),), output_address=0x1FC, output_bytes=4, is_group=False
    )
    assert targets[2].spans == ((0x500, 0x600), (0x700, 0x800))
    assert targets[2].output_bytes == 8


def test_tc202_9_encode_le_width_table() -> None:
    """LLR-WID-001.1: encode_le width table - 4 == encode_le32 byte-identical;
    8 zero-extends (high 4 bytes 0x00); 1/2 truncate to the low bytes
    (TC-202.9)."""
    crc = 0x04030201
    assert encode_le(crc, 4) == encode_le32(crc)
    assert encode_le(crc, 8) == b"\x01\x02\x03\x04\x00\x00\x00\x00"
    assert encode_le(crc, 2) == b"\x01\x02"
    assert encode_le(crc, 1) == b"\x01"


def test_tc202_10_decode_le_inverse_and_wrapper() -> None:
    """LLR-WID-001.2: decode_le is the length-driven inverse of encode_le at
    every allowed width; decode_le32 wrapper unchanged (TC-202.10)."""
    crc = 0xCBF43926
    for width in (1, 2, 4, 8):
        expected = crc & ((1 << (8 * width)) - 1)
        assert decode_le(encode_le(crc, width)) == expected
    assert decode_le32(encode_le32(crc)) == crc


def test_tc202_11_read_stored_width_and_absent_byte_tristate() -> None:
    """LLR-WID-001.4 / AT-046d (engine half) / B8: width-parameterized read;
    ANY absent byte of N (byte 0 and byte N-1 probed) yields None; legacy
    default-width call unchanged (TC-202.11)."""
    stored = encode_le(0xCBF43926, 8)
    mem = _mem_from_bytes(0x100, stored)
    op_input = OperationInput(
        mem_map=mem, ranges=[(0x100, 0x108)], input_path=None,
        variant_id=None, file_type="s19",
    )
    assert read_stored_crc_le(op_input, 0x100, 8) == 0xCBF43926
    # byte N-1 absent
    mem_hi = dict(mem)
    del mem_hi[0x107]
    op_hi = OperationInput(
        mem_map=mem_hi, ranges=[(0x100, 0x108)], input_path=None,
        variant_id=None, file_type="s19",
    )
    assert read_stored_crc_le(op_hi, 0x100, 8) is None
    # byte 0 absent
    mem_lo = dict(mem)
    del mem_lo[0x100]
    op_lo = OperationInput(
        mem_map=mem_lo, ranges=[(0x100, 0x108)], input_path=None,
        variant_id=None, file_type="s19",
    )
    assert read_stored_crc_le(op_lo, 0x100, 8) is None
    # legacy default-width call still reads exactly 4 bytes
    assert read_stored_crc_le(op_lo, 0x101) == decode_le(stored[1:5])
