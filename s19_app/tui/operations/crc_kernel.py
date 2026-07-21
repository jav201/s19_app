"""
Width-general parametric CRC kernel (CRC Algorithm Designer, batch-52, HLR E1).

The pure-math building block for the designer: a table-less bitwise CRC for any
width in 8..64 under the canonical parametric ("Rocksoft") model —
``width / poly / init / refin / refout / xorout`` — with INDEPENDENT input and
output reflection. This is the width-general successor to
``operations.crc.crc32_stream`` (which is 32-bit-only and couples refin+refout
under a single ``reverse`` flag); the seed algorithm :data:`SEED_ALGORITHM`
reproduces that engine — and ``zlib.crc32`` — byte-for-byte.

Headless: no Textual import, no file I/O, no ``mem_map`` access. Exhaustively
unit-testable against the published catalogue check values (:data:`PRESETS`)
and ``zlib.crc32`` for the CRC-32 row.

This module is deliberately ADDITIVE — it does not modify the shipped
``operations.crc`` engine. Integration (having the CRC operation delegate here)
is a later /dev-flow step; the kernel stands alone so the designer view and its
tests can build on typed, verified primitives now.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Optional

#: The known-answer-test message: the CRC of these 9 ASCII bytes is the
#: ``check`` value every catalogue CRC variant publishes, so a wrong kernel
#: fails loudly the instant a preset is evaluated.
KAT_MESSAGE: bytes = b"123456789"

#: Inclusive width bounds the kernel supports (v1). The byte-aligned bitwise
#: loop below is correct for any ``width >= 8``; 64 is the upper practical
#: bound (and the widest seed preset, CRC-64/XZ).
MIN_WIDTH: int = 8
MAX_WIDTH: int = 64


def reflect(value: int, width: int) -> int:
    """
    Summary:
        Reverse the low ``width`` bits of ``value`` — the bit-reflection a
        reflected-input CRC applies to each input byte and a reflected-output
        CRC applies to the final register.

    Args:
        value (int): The integer whose low ``width`` bits are reversed.
        width (int): Number of low bits to reflect (8 for a byte, ``width`` for
            the register).

    Returns:
        int: ``value`` with its low ``width`` bits reversed, high bits cleared.

    Data Flow:
        - Shift each of the ``width`` low bits into its mirrored position.

    Dependencies:
        Used by:
            - :func:`crc_stream` (refin per byte, refout on the register)

    Example:
        >>> bin(reflect(0b1, 8))
        '0b10000000'
    """
    result = 0
    for _ in range(width):
        result = (result << 1) | (value & 1)
        value >>= 1
    return result


def crc_stream(
    data: bytes,
    *,
    width: int,
    poly: int,
    init: int,
    refin: bool,
    refout: bool,
    xorout: int,
) -> int:
    """
    Summary:
        Compute a width-general parametric CRC over an ordered byte stream
        (HLR E1). Table-less MSB-first bitwise division for any ``width`` in
        :data:`MIN_WIDTH`..:data:`MAX_WIDTH`, with independent input reflection
        (``refin``, applied per byte) and output reflection (``refout``, applied
        to the final register) before the final ``xorout``. With the CRC-32/
        ISO-HDLC params it equals ``zlib.crc32``.

    Args:
        data (bytes): The ordered byte stream to digest.
        width (int): CRC register size in bits (8..64) — the result word size.
        poly (int): Generator polynomial, normal (un-reflected) form.
        init (int): Initial register value (seed), pre-reflection.
        refin (bool): Reflect each input byte before feeding it.
        refout (bool): Reflect the final register before ``xorout``.
        xorout (int): Value XORed into the final register.

    Returns:
        int: The finalized ``width``-bit CRC over ``data``.

    Raises:
        ValueError: When ``width`` is outside :data:`MIN_WIDTH`..:data:`MAX_WIDTH`.

    Data Flow:
        - Seed the register from ``init``; for each byte (optionally reflected)
          XOR it into the high 8 bits and run 8 MSB-first division steps;
          reflect the register if ``refout``; XOR ``xorout``.

    Dependencies:
        Uses:
            - :func:`reflect`
        Used by:
            - :meth:`CrcAlgorithm.compute`
            - tests/test_crc_kernel.py (KAT table, zlib oracle)

    Example:
        >>> hex(crc_stream(b"123456789", width=32, poly=0x04C11DB7,
        ...                init=0xFFFFFFFF, refin=True, refout=True,
        ...                xorout=0xFFFFFFFF))
        '0xcbf43926'
    """
    if not (MIN_WIDTH <= width <= MAX_WIDTH):
        raise ValueError(
            f"width {width} out of range [{MIN_WIDTH}, {MAX_WIDTH}]"
        )
    mask = (1 << width) - 1
    topbit = 1 << (width - 1)
    reg = init & mask
    for byte in data:
        if refin:
            byte = reflect(byte, 8)
        reg ^= (byte << (width - 8)) & mask
        for _ in range(8):
            if reg & topbit:
                reg = ((reg << 1) ^ poly) & mask
            else:
                reg = (reg << 1) & mask
    if refout:
        reg = reflect(reg, width)
    return (reg ^ xorout) & mask


@lru_cache(maxsize=None)
def make_crc_table(width: int, poly: int) -> tuple[int, ...]:
    """
    Summary:
        Build the 256-entry MSB-first CRC table for ``(width, poly)`` (HLR E7,
        obs #4). Cached per ``(width, poly)`` so a whole-image digest builds the
        table once at "init". This is the tabelization of the exact bit loop in
        :func:`crc_stream`, so :func:`crc_lut` is result-identical to it.

    Args:
        width (int): CRC width in bits (8..64).
        poly (int): Generator polynomial, normal (un-reflected) form.

    Returns:
        tuple[int, ...]: 256 entries; ``table[b]`` = the register after feeding
        byte ``b`` into the high 8 bits and running 8 MSB-first division steps.

    Data Flow:
        - Per byte value 0..255, run the 8-step division; collect the register.

    Dependencies:
        Used by:
            - :func:`crc_lut`
            - tests/test_crc_kernel.py (LUT differential test)

    Example:
        >>> make_crc_table(32, 0x04C11DB7)[1] == make_crc_table(32, 0x04C11DB7)[1]
        True
    """
    mask = (1 << width) - 1
    topbit = 1 << (width - 1)
    shift = width - 8
    table: list[int] = []
    for b in range(256):
        crc = (b << shift) & mask
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & mask if (crc & topbit) else (crc << 1) & mask
        table.append(crc)
    return tuple(table)


def crc_lut(
    data: bytes,
    *,
    width: int,
    poly: int,
    init: int,
    refin: bool,
    refout: bool,
    xorout: int,
) -> int:
    """
    Summary:
        Table-driven parametric CRC (HLR E7) — the fast path for MB-scale
        firmware. Byte-for-byte identical to :func:`crc_stream` for every
        parameter set: it uses the same MSB-first table family and pre-reflects
        each input byte when ``refin`` (exactly as :func:`crc_stream` does), so
        the two are the same computation, one bit-at-a-time and one byte-at-a-time.

    Args:
        data (bytes): The ordered byte stream to digest.
        width (int): CRC width in bits (8..64).
        poly (int): Generator polynomial, normal form.
        init (int): Initial register value.
        refin (bool): Reflect each input byte before feeding it.
        refout (bool): Reflect the final register before ``xorout``.
        xorout (int): Value XORed into the final register.

    Returns:
        int: The finalized ``width``-bit CRC over ``data`` — equal to
        ``crc_stream`` with the same params.

    Raises:
        ValueError: When ``width`` is outside :data:`MIN_WIDTH`..:data:`MAX_WIDTH`.

    Data Flow:
        - Fetch/build the table via :func:`make_crc_table`; run the byte loop
          ``reg = (reg << 8) ^ table[((reg >> (width-8)) ^ byte) & 0xFF]``;
          reflect the register if ``refout``; XOR ``xorout``.

    Dependencies:
        Uses:
            - :func:`make_crc_table`, :func:`reflect`
        Used by:
            - :meth:`CrcAlgorithm.compute`
            - tests/test_crc_kernel.py (LUT differential test)

    Example:
        >>> hex(crc_lut(b"123456789", width=32, poly=0x04C11DB7,
        ...             init=0xFFFFFFFF, refin=True, refout=True, xorout=0xFFFFFFFF))
        '0xcbf43926'
    """
    if not (MIN_WIDTH <= width <= MAX_WIDTH):
        raise ValueError(
            f"width {width} out of range [{MIN_WIDTH}, {MAX_WIDTH}]"
        )
    table = make_crc_table(width, poly)
    mask = (1 << width) - 1
    shift = width - 8
    reg = init & mask
    for byte in data:
        if refin:
            byte = reflect(byte, 8)
        reg = ((reg << 8) ^ table[((reg >> shift) ^ byte) & 0xFF]) & mask
    if refout:
        reg = reflect(reg, width)
    return (reg ^ xorout) & mask


@dataclass(frozen=True)
class CrcAlgorithm:
    """
    Summary:
        A named parametric CRC algorithm — the reusable, placement-free "math"
        the CRC Algorithm Designer authors (requirements §3.1). Frozen and
        JSON-serializable (see :mod:`crc_designer_model`). Carries an optional
        ``check`` (the CRC of :data:`KAT_MESSAGE`) so a variant self-verifies.

    Args:
        name (str): Human name (e.g. ``"CRC-32/ISO-HDLC"``). Unique within the
            template library; normalized to a filename by the model layer.
        width (int): CRC width in bits (8..64).
        poly (int): Generator polynomial, normal form.
        init (int): Initial register value.
        refin (bool): Reflect input bytes.
        refout (bool): Reflect the final register.
        xorout (int): Final XOR value.
        check (Optional[int]): Expected CRC of :data:`KAT_MESSAGE`, or ``None``
            when the operator has not pinned a reference (a custom variant).

    Data Flow:
        - Built from a preset or parsed JSON; consumed by :func:`crc_stream`
          via :meth:`compute` and by the coverage layer.

    Dependencies:
        Uses:
            - crc_stream (compute)
        Used by:
            - PRESETS / SEED_ALGORITHM
            - crc_designer_model (CrcTemplate / CrcJob)

    Example:
        >>> SEED_ALGORITHM.kat_ok()
        True
    """

    name: str
    width: int
    poly: int
    init: int
    refin: bool
    refout: bool
    xorout: int
    check: Optional[int] = None

    def mask(self) -> int:
        """Return the ``width``-bit all-ones mask."""
        return (1 << self.width) - 1

    def store_bytes(self) -> int:
        """Return the minimum whole-byte storage width, ``ceil(width/8)``."""
        return (self.width + 7) // 8

    def compute(self, data: bytes) -> int:
        """
        Summary:
            Compute this algorithm's CRC over ``data`` via the table-driven fast
            path :func:`crc_lut` (result-identical to the :func:`crc_stream`
            bitwise oracle; HLR E7).

        Args:
            data (bytes): The ordered byte stream.

        Returns:
            int: The finalized CRC.

        Data Flow:
            - Forward the seven params to :func:`crc_lut` (which memoizes the
              256-entry table per ``(width, poly)``).

        Dependencies:
            Uses:
                - crc_lut
            Used by:
                - kat / kat_ok, the coverage compute path

        Example:
            >>> hex(SEED_ALGORITHM.compute(b"123456789"))
            '0xcbf43926'
        """
        return crc_lut(
            data,
            width=self.width,
            poly=self.poly,
            init=self.init,
            refin=self.refin,
            refout=self.refout,
            xorout=self.xorout,
        )

    def kat(self) -> int:
        """Return the CRC of :data:`KAT_MESSAGE` (the known-answer value)."""
        return self.compute(KAT_MESSAGE)

    def kat_ok(self) -> Optional[bool]:
        """
        Summary:
            Report whether the computed known-answer equals the pinned
            ``check``. ``None`` when no ``check`` is set (nothing to compare) —
            the tri-state the designer's live verdict renders as
            match / mismatch / no-expected.

        Returns:
            Optional[bool]: ``True`` match, ``False`` mismatch, ``None`` when
            ``check`` is ``None``.

        Data Flow:
            - Compare :meth:`kat` to ``check``.

        Dependencies:
            Used by:
                - the designer live-verify surface (R-CRC-DSN-002)
                - tests/test_crc_kernel.py (KAT table)
        """
        if self.check is None:
            return None
        return self.kat() == (self.check & self.mask())


#: The seed algorithm — today's zlib / PKZIP CRC-32 expressed in the parametric
#: model. Reproduces ``operations.crc.crc32_stream`` defaults and ``zlib.crc32``
#: byte-for-byte (AT-CRC-DSN-010): the designer's "first template = current
#: implementation" fidelity anchor.
SEED_ALGORITHM: CrcAlgorithm = CrcAlgorithm(
    name="CRC-32/ISO-HDLC",
    width=32,
    poly=0x04C11DB7,
    init=0xFFFFFFFF,
    refin=True,
    refout=True,
    xorout=0xFFFFFFFF,
    check=0xCBF43926,
)


#: The seed preset library (requirements §5). Each ``check`` is the published
#: catalogue CRC of :data:`KAT_MESSAGE`, so the KAT table test (E2) guards the
#: kernel against every one. These are read-only starting points; the operator
#: selects one, edits, and saves the result under a new name.
PRESETS: tuple[CrcAlgorithm, ...] = (
    CrcAlgorithm("CRC-8/SMBUS", 8, 0x07, 0x00, False, False, 0x00, 0xF4),
    CrcAlgorithm("CRC-16/CCITT-FALSE", 16, 0x1021, 0xFFFF, False, False, 0x0000, 0x29B1),
    CrcAlgorithm("CRC-16/MODBUS", 16, 0x8005, 0xFFFF, True, True, 0x0000, 0x4B37),
    CrcAlgorithm("CRC-16/XMODEM", 16, 0x1021, 0x0000, False, False, 0x0000, 0x31C3),
    SEED_ALGORITHM,
    CrcAlgorithm("CRC-32C/Castagnoli", 32, 0x1EDC6F41, 0xFFFFFFFF, True, True, 0xFFFFFFFF, 0xE3069283),
    CrcAlgorithm(
        "CRC-64/XZ", 64, 0x42F0E1EBA9EA3693, 0xFFFFFFFFFFFFFFFF,
        True, True, 0xFFFFFFFFFFFFFFFF, 0x995DC9BBDF1939FA,
    ),
)


def preset_by_name(name: str) -> Optional[CrcAlgorithm]:
    """
    Summary:
        Look up a seed preset by exact name (case-insensitive), or ``None``.

    Args:
        name (str): The preset name to find.

    Returns:
        Optional[CrcAlgorithm]: The matching preset, or ``None``.

    Data Flow:
        - Linear scan of :data:`PRESETS` (seven entries).

    Dependencies:
        Used by:
            - the designer preset selector (R-CRC-DSN-006)
            - crc_designer_model (algorithm_ref resolution against presets)
    """
    lowered = name.lower()
    return next((p for p in PRESETS if p.name.lower() == lowered), None)
