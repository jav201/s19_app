"""
Headless CRC32 compute engine (batch-12 CRC_F2, HLR-001 / increment I1b).

A pure-compute, parameterized CRC32 engine over one or more configured
memory regions of a loaded image. No Textual import, no file I/O, no
``mem_map`` mutation — exhaustively unit-testable against ``zlib.crc32``
oracles (LLR-001.1) and reusable by both the check (US-011) and inject
(US-012) paths.

Implements the operator's FR2/FR3/FR4/FR5/FR7/FR8/FR9 requirements:
ascending-address ordering (FR2), region filtering (FR3), contiguous-segment
reconstruction splitting on any gap (FR4/FR7), CRC32 over concatenated
segments through one non-resetting state (FR5/FR8), and final XOR (FR9).
Region membership reuses the frozen :mod:`s19_app.range_index` primitives
(import-only).
"""

from __future__ import annotations

import zlib
from typing import Iterable, Optional

from ...range_index import address_in_sorted_ranges, build_sorted_range_index

#: zlib/PKZIP CRC-32 default convention (§6.2 D-4). With these params the
#: engine reproduces ``zlib.crc32`` exactly (the LLR-001.1 oracle).
DEFAULT_POLYNOMIAL: int = 0x04C11DB7
DEFAULT_INIT: int = 0xFFFFFFFF
DEFAULT_REVERSE: bool = True
DEFAULT_FINAL_XOR: int = 0xFFFFFFFF

#: Fixed storage codec width (§6.2 D-5): the stored/written CRC is always
#: four little-endian bytes. NOT parameterized.
LE32_WIDTH: int = 4

_MASK32: int = 0xFFFFFFFF


def _reflect(value: int, width: int) -> int:
    """
    Summary:
        Reverse the low ``width`` bits of ``value`` — the bit-reflection a
        reflected-input/reflected-output CRC applies to each input byte and
        to the final register.

    Args:
        value (int): The integer whose low ``width`` bits are reflected.
        width (int): Number of low bits to reflect (8 for a byte, 32 for the
            register).

    Returns:
        int: ``value`` with its low ``width`` bits reversed.

    Data Flow:
        - Shift each of the ``width`` low bits into mirrored position.

    Dependencies:
        Used by:
            - :func:`crc32_stream` (non-default reflected path)
    """
    result = 0
    for _ in range(width):
        result = (result << 1) | (value & 1)
        value >>= 1
    return result


def crc32_stream(
    data: bytes,
    *,
    polynomial: int = DEFAULT_POLYNOMIAL,
    init: int = DEFAULT_INIT,
    reverse: bool = DEFAULT_REVERSE,
    final_xor: int = DEFAULT_FINAL_XOR,
) -> int:
    """
    Summary:
        Compute a parameterized CRC32 over an ordered byte stream (FR5). With
        the default params (poly ``0x04C11DB7``, init ``0xFFFFFFFF``,
        ``reverse=True``, xorout ``0xFFFFFFFF``) the result equals
        ``zlib.crc32`` over the same bytes (LLR-001.1); the default path is
        delegated to ``zlib.crc32`` and non-default params use a bitwise
        MSB-first loop with optional input/output reflection.

    Args:
        data (bytes): The ordered byte stream to digest.
        polynomial (int): The CRC generator polynomial (normal form).
        init (int): The initial register value (pre-reflection).
        reverse (bool): When ``True``, standard reflected-input /
            reflected-output (refin/refout) semantics; the zlib convention.
        final_xor (int): Value XORed into the register after the last byte.

    Returns:
        int: The finalized 32-bit CRC over ``data``.

    Data Flow:
        - Default params → ``zlib.crc32`` (the oracle path).
        - Otherwise run the bitwise loop seeded from ``init``, reflecting
          each input byte and the final register when ``reverse``, then XOR.

    Dependencies:
        Uses:
            - ``zlib.crc32`` (default-param fast path)
            - :func:`_reflect`
        Used by:
            - :func:`compute_region_crc`
            - tests/test_crc_engine.py (TC-101, TC-106)

    Example:
        >>> hex(crc32_stream(b"123456789"))
        '0xcbf43926'
    """
    is_default = (
        polynomial == DEFAULT_POLYNOMIAL
        and init == DEFAULT_INIT
        and reverse == DEFAULT_REVERSE
        and final_xor == DEFAULT_FINAL_XOR
    )
    if is_default:
        # zlib.crc32 applies the standard init (0xFFFFFFFF) and xorout
        # internally; its default seed (0) IS the zlib/PKZIP convention.
        return zlib.crc32(data) & _MASK32

    reg = _reflect(init, 32) if reverse else (init & _MASK32)
    for byte in data:
        if reverse:
            byte = _reflect(byte, 8)
        reg ^= byte << 24
        for _ in range(8):
            if reg & 0x80000000:
                reg = ((reg << 1) ^ polynomial) & _MASK32
            else:
                reg = (reg << 1) & _MASK32

    if reverse:
        reg = _reflect(reg, 32)
    return (reg ^ final_xor) & _MASK32


def region_segments(
    mem_map: dict[int, int], start: int, end: int
) -> list[bytes]:
    """
    Summary:
        Reconstruct the contiguous byte segments inside one half-open region
        ``[start, end)``: select only present ``mem_map`` addresses within
        the region (FR3), order ascending (FR2), and split into maximal
        contiguous runs on any gap (``current == previous + 1``, FR4),
        inserting NO bytes for gaps (FR7).

    Args:
        mem_map (dict[int, int]): Address-to-byte map (read only).
        start (int): Inclusive region start address.
        end (int): Exclusive region upper bound (half-open).

    Returns:
        list[bytes]: One ``bytes`` object per contiguous segment, in
        ascending-address order. Empty when the region contains no present
        address.

    Data Flow:
        - Filter ``mem_map`` keys to ``[start, end)`` via the frozen
          :func:`address_in_sorted_ranges` membership primitive.
        - Sort ascending, then break on each address gap into segments.

    Dependencies:
        Uses:
            - ``s19_app.range_index.build_sorted_range_index`` (import-only)
            - ``s19_app.range_index.address_in_sorted_ranges`` (import-only)
        Used by:
            - :func:`compute_region_crc`
            - tests/test_crc_engine.py (TC-103, TC-105)

    Example:
        >>> region_segments({0: 1, 1: 2, 3: 4}, 0, 4)
        [b'\\x01\\x02', b'\\x04']
    """
    index = build_sorted_range_index([(start, end)])
    in_region = sorted(
        addr for addr in mem_map if address_in_sorted_ranges(addr, index)
    )
    segments: list[bytes] = []
    current: list[int] = []
    previous: Optional[int] = None
    for addr in in_region:
        if previous is not None and addr != previous + 1:
            segments.append(bytes(current))
            current = []
        current.append(mem_map[addr] & 0xFF)
        previous = addr
    if current:
        segments.append(bytes(current))
    return segments


def compute_region_crc(
    mem_map: dict[int, int],
    start: int,
    end: int,
    *,
    polynomial: int = DEFAULT_POLYNOMIAL,
    init: int = DEFAULT_INIT,
    reverse: bool = DEFAULT_REVERSE,
    final_xor: int = DEFAULT_FINAL_XOR,
) -> int:
    """
    Summary:
        Compute one region's CRC32 over its contiguous segments. The segments
        are concatenated into a SINGLE ordered byte stream and digested by one
        :func:`crc32_stream` call — equivalent to threading one non-resetting
        CRC state across them (FR8), because gaps contribute no bytes (FR7)
        and digesting ``s1 + s2`` from one init is exactly a non-reset chain.
        The result is identical to the CRC of the gap-free byte concatenation.

    Args:
        mem_map (dict[int, int]): Address-to-byte map (read only).
        start (int): Inclusive region start address.
        end (int): Exclusive region upper bound (half-open).
        polynomial (int): CRC generator polynomial.
        init (int): Initial register value.
        reverse (bool): Reflected-in/out flag (zlib convention when ``True``).
        final_xor (int): Final-XOR value.

    Returns:
        int: The 32-bit CRC over the region's present bytes in ascending
        order, chained across segments without reset.

    Data Flow:
        - :func:`region_segments` assembles the ordered contiguous segments.
        - Concatenate the ordered segments into one byte stream and digest it
          with a single :func:`crc32_stream` call — equivalent to a
          non-resetting chain since gaps contribute no bytes; the final XOR is
          applied once inside :func:`crc32_stream`.

    Dependencies:
        Uses:
            - :func:`region_segments`
            - :func:`crc32_stream`
        Used by:
            - :func:`compute_region_crcs`
            - tests/test_crc_engine.py (TC-102, TC-104)

    Example:
        >>> hex(compute_region_crc({0: 0x31, 1: 0x32, 2: 0x33}, 0, 3))
        '0x884863d2'
    """
    stream = b"".join(region_segments(mem_map, start, end))
    return crc32_stream(
        stream,
        polynomial=polynomial,
        init=init,
        reverse=reverse,
        final_xor=final_xor,
    )


def compute_region_crcs(
    mem_map: dict[int, int],
    regions: Iterable[tuple[int, int]],
    *,
    polynomial: int = DEFAULT_POLYNOMIAL,
    init: int = DEFAULT_INIT,
    reverse: bool = DEFAULT_REVERSE,
    final_xor: int = DEFAULT_FINAL_XOR,
) -> list[int]:
    """
    Summary:
        The engine entry point (LLR-001.3): compute one CRC per configured
        region, in config order, WITHOUT mutating the input ``mem_map``.
        Returns plain ints — building the ``OperationResult`` / ``crc_regions``
        payload is the wiring increment (I2), not this pure-compute module.

    Args:
        mem_map (dict[int, int]): Address-to-byte map (read only; never
            mutated).
        regions (Iterable[tuple[int, int]]): Half-open ``(start, end)``
            region bounds in config order.
        polynomial (int): CRC generator polynomial.
        init (int): Initial register value.
        reverse (bool): Reflected-in/out flag.
        final_xor (int): Final-XOR value.

    Returns:
        list[int]: One 32-bit CRC per region, in the order ``regions`` was
        iterated.

    Data Flow:
        - For each region, delegate to :func:`compute_region_crc`; collect
          the CRCs in config order. ``mem_map`` is only read.

    Dependencies:
        Uses:
            - :func:`compute_region_crc`
        Used by:
            - tui.operations CRC check/inject paths (increment I2/I5)
            - tests/test_crc_engine.py (TC-103, TC-105, no-mutation assertion)

    Example:
        >>> compute_region_crcs({0: 0x31, 1: 0x32}, [(0, 2)]) == [
        ...     compute_region_crc({0: 0x31, 1: 0x32}, 0, 2)
        ... ]
        True
    """
    params = dict(
        polynomial=polynomial, init=init, reverse=reverse, final_xor=final_xor
    )
    return [
        compute_region_crc(mem_map, start, end, **params)
        for start, end in regions
    ]


def encode_le32(crc: int) -> bytes:
    """
    Summary:
        Encode a 32-bit CRC as 4 little-endian bytes (§6.2 D-5, FIXED codec):
        byte ``i`` = ``(crc >> (8 * i)) & 0xFF``.

    Args:
        crc (int): The CRC value; only its low 32 bits are encoded.

    Returns:
        bytes: Exactly 4 bytes, little-endian.

    Data Flow:
        - Mask to 32 bits, emit little-endian.

    Dependencies:
        Used by:
            - the inject path (LLR-003.1, increment I5)
            - tests/test_crc_engine.py (TC-107)

    Example:
        >>> encode_le32(0x04030201)
        b'\\x01\\x02\\x03\\x04'
    """
    return (crc & _MASK32).to_bytes(LE32_WIDTH, "little")


def decode_le32(data: Iterable[int]) -> int:
    """
    Summary:
        Decode 4 little-endian bytes into a 32-bit int (§6.2 D-5, FIXED
        codec) — the inverse of :func:`encode_le32`. Accepts any iterable of
        4 byte values (e.g. a ``bytes`` object or a list sliced from a
        ``mem_map``).

    Args:
        data (Iterable[int]): Exactly 4 byte values, low byte first.

    Returns:
        int: The decoded 32-bit value.

    Raises:
        ValueError: If ``data`` does not yield exactly 4 bytes.

    Data Flow:
        - Materialize 4 bytes; combine little-endian.

    Dependencies:
        Used by:
            - the check path (LLR-002.1, increment I2)
            - tests/test_crc_engine.py (TC-107)

    Example:
        >>> hex(decode_le32(b'\\x01\\x02\\x03\\x04'))
        '0x4030201'
    """
    payload = bytes(data)
    if len(payload) != LE32_WIDTH:
        raise ValueError(
            f"decode_le32 expects {LE32_WIDTH} bytes, got {len(payload)}"
        )
    return int.from_bytes(payload, "little")
