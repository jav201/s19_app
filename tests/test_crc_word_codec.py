"""Word codec (E4) tests — batch-58 Inc-1.

Covers AT-CRC-DSN-014 and LLR-E4.1 (encode_word), LLR-E4.2 (decode_word),
LLR-E4.3 (encode_le/decode_le kept byte-identical). The big-endian /
wider-field codec is the engine prerequisite a job's ``store_endianness="big"``
and padded ``store_width`` serialize through.
"""

from __future__ import annotations

import pytest

from s19_app.tui.operations.crc import (
    decode_le,
    decode_word,
    encode_le,
    encode_word,
)


def test_at_crc_dsn_014_encode_word_endianness() -> None:
    """AT-CRC-DSN-014 / LLR-E4.1: big stores MSB-first; little == encode_le."""
    assert (
        encode_word(0x01020304, store_width=4, endianness="big")
        == b"\x01\x02\x03\x04"
    )
    assert (
        encode_word(0x01020304, store_width=4, endianness="little")
        == b"\x04\x03\x02\x01"
    )
    # little is byte-identical to today's positional encode_le.
    assert encode_word(
        0x01020304, store_width=4, endianness="little"
    ) == encode_le(0x01020304, 4)


def test_tc_e4_1_wider_field_zero_extends() -> None:
    """LLR-E4.1: a 16-bit value in a 4-byte field zero-extends the right end."""
    assert encode_word(0xBEEF, store_width=4, endianness="little") == (
        b"\xef\xbe\x00\x00"
    )
    assert encode_word(0xBEEF, store_width=4, endianness="big") == (
        b"\x00\x00\xbe\xef"
    )


@pytest.mark.parametrize("endianness", ["little", "big"])
@pytest.mark.parametrize("width", [1, 2, 4, 8])
def test_tc_e4_2_decode_word_round_trip(width: int, endianness: str) -> None:
    """LLR-E4.2: decode_word inverts encode_word at every width/endianness."""
    value = 0x1234567890ABCDEF & ((1 << (8 * width)) - 1)
    encoded = encode_word(value, store_width=width, endianness=endianness)
    assert len(encoded) == width
    assert decode_word(encoded, endianness=endianness) == value


def test_tc_e4_1_overflow_raises() -> None:
    """LLR-E4.1: a value that does not fit store_width raises ValueError."""
    with pytest.raises(ValueError):
        encode_word(0x1_0000, store_width=2, endianness="little")
    with pytest.raises(ValueError):
        encode_word(0x1_0000, store_width=2, endianness="big")


def test_tc_e4_1_unknown_endianness_raises() -> None:
    """LLR-E4.1/E4.2: an unknown endianness raises ValueError (caller-caught)."""
    with pytest.raises(ValueError):
        encode_word(0x01, store_width=1, endianness="middle")
    with pytest.raises(ValueError):
        decode_word(b"\x01", endianness="middle")


def test_tc_e4_3_le_wrappers_byte_identical() -> None:
    """LLR-E4.3: encode_le/decode_le stay byte-identical, truncation included."""
    crc = 0x04030201
    for width in (1, 2, 4, 8):
        mask = (1 << (8 * width)) - 1
        assert encode_le(crc, width) == encode_word(
            crc & mask, store_width=width, endianness="little"
        )
        assert decode_le(encode_le(crc, width)) == decode_word(
            encode_le(crc, width), endianness="little"
        )
    # encode_le keeps its lenient truncation (does NOT raise on overflow).
    assert encode_le(0x04030201, 2) == b"\x01\x02"
