"""
Check-path tests for the headless CRC operation (batch-12 CRC_F2, I2 SUB-STEP B).

Pins the non-mutating compare path (LLR-002.1 read-stored, LLR-002.2 compare +
per-region payload) with the §5.2 TC-111 (match) and TC-112 (mismatch) cases,
plus the "no stored value" and config-order properties. Every test is written
to FAIL on a logic regression (Rule 9): the match/mismatch fixtures derive the
stored value from the SAME engine the check uses AND cross-check the computed
value against an independent ``compute_region_crc`` call, so a vacuous match
cannot pass; the no-mutation assertions snapshot ``mem_map`` pre/post.
"""

from __future__ import annotations

from s19_app.tui.operations.crc import (
    DEFAULT_FINAL_XOR,
    DEFAULT_INIT,
    DEFAULT_POLYNOMIAL,
    DEFAULT_REVERSE,
    check_regions,
    compute_region_crc,
    encode_le32,
    read_stored_crc_le,
)
from s19_app.tui.operations.crc_config import CrcConfig, CrcRegion
from s19_app.tui.operations.model import OperationInput


def _op_input(mem_map: dict[int, int]) -> OperationInput:
    """Build a neutral :class:`OperationInput` over ``mem_map`` for the check.

    Only ``mem_map`` is load-bearing for the check path; ``ranges`` mirrors the
    region geometry for realism but the engine reads ``mem_map`` directly.
    """
    return OperationInput(
        mem_map=mem_map,
        ranges=sorted((addr, addr + 1) for addr in mem_map),
        input_path=None,
        variant_id=None,
        file_type="s19",
    )


def _default_config(regions: list[CrcRegion]) -> CrcConfig:
    """A :class:`CrcConfig` over ``regions`` using the zlib/PKZIP defaults."""
    return CrcConfig(
        regions=regions,
        polynomial=DEFAULT_POLYNOMIAL,
        init=DEFAULT_INIT,
        reverse=DEFAULT_REVERSE,
        final_xor=DEFAULT_FINAL_XOR,
    )


def _mem_from_bytes(base: int, payload: bytes) -> dict[int, int]:
    """Build a contiguous ``mem_map`` from ``payload`` starting at ``base``."""
    return {base + offset: value for offset, value in enumerate(payload)}


def test_check_reports_match_nonmutating() -> None:
    """TC-111 — MATCH: the stored 4-byte LE value at the output address equals
    the computed CRC → ``matched is True``, and ``mem_map`` is byte-for-byte
    unchanged across the check (LLR-002.2 non-mutation).

    The stored value is written as ``encode_le32(computed)``; the match is
    proven non-vacuous by ALSO asserting the computed value equals an
    independent ``compute_region_crc`` over the same region."""
    region_bytes = b"\x10\x11\x12\x13\x14"
    mem = _mem_from_bytes(0x1000, region_bytes)
    region = CrcRegion(start=0x1000, end=0x1000 + len(region_bytes),
                       output_address=0x2000)

    # Independent recompute of the region CRC (not via check_regions).
    expected = compute_region_crc(mem, region.start, region.end)
    # Store the matching CRC as 4-byte LE at the output address.
    mem.update(_mem_from_bytes(region.output_address, encode_le32(expected)))

    op_input = _op_input(mem)
    snapshot = dict(mem)

    results = check_regions(op_input, _default_config([region]))

    assert len(results) == 1
    result = results[0]
    assert result.computed_crc == expected  # non-vacuous: independent oracle
    assert result.stored_value == expected
    assert result.matched is True
    assert result.written is False
    assert op_input.mem_map == snapshot  # zero mutation


def test_check_reports_mismatch() -> None:
    """TC-112 — MISMATCH: the stored value differs from the computed CRC →
    ``matched is False``; ``mem_map`` untouched."""
    region_bytes = b"\xaa\xbb\xcc\xdd"
    mem = _mem_from_bytes(0x40, region_bytes)
    region = CrcRegion(start=0x40, end=0x40 + len(region_bytes),
                       output_address=0x80)

    expected = compute_region_crc(mem, region.start, region.end)
    # Store a value guaranteed to differ from the computed CRC.
    wrong = (expected ^ 0xFFFFFFFF) & 0xFFFFFFFF
    assert wrong != expected
    mem.update(_mem_from_bytes(region.output_address, encode_le32(wrong)))

    op_input = _op_input(mem)
    snapshot = dict(mem)

    results = check_regions(op_input, _default_config([region]))

    assert results[0].computed_crc == expected
    assert results[0].stored_value == wrong
    assert results[0].matched is False
    assert op_input.mem_map == snapshot  # zero mutation


def test_read_stored_missing_returns_none() -> None:
    """An output address with fewer than 4 present bytes → ``read_stored_crc_le``
    returns ``None`` and ``check_regions`` yields ``matched is None``, with no
    exception raised (LLR-002.1 "no stored value")."""
    region_bytes = b"\x01\x02\x03"
    mem = _mem_from_bytes(0, region_bytes)
    # Only 3 of the 4 output bytes present (0x10..0x12; 0x13 absent).
    mem.update({0x10: 0x00, 0x11: 0x00, 0x12: 0x00})
    region = CrcRegion(start=0, end=len(region_bytes), output_address=0x10)

    op_input = _op_input(mem)

    assert read_stored_crc_le(op_input, 0x10) is None

    results = check_regions(op_input, _default_config([region]))

    assert results[0].stored_value is None
    assert results[0].matched is None
    # Computed CRC is still reported even with no stored value to compare.
    assert results[0].computed_crc == compute_region_crc(mem, 0, len(region_bytes))


def test_check_multi_region_order() -> None:
    """Two regions → one ``CrcRegionResult`` per region, in config order
    (LLR-002.2 deterministic ordering)."""
    mem = _mem_from_bytes(0, b"\x11\x22\x33\x44\x55\x66")
    region_a = CrcRegion(start=0, end=3, output_address=0x100)
    region_b = CrcRegion(start=3, end=6, output_address=0x200)

    op_input = _op_input(mem)

    results = check_regions(op_input, _default_config([region_a, region_b]))

    assert len(results) == 2
    assert [r.output_address for r in results] == [0x100, 0x200]
    assert results[0].computed_crc == compute_region_crc(mem, 0, 3)
    assert results[1].computed_crc == compute_region_crc(mem, 3, 6)
