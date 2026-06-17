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
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, List, Optional

from ...range_index import address_in_sorted_ranges, build_sorted_range_index
from ..changes.io import emit_s19_from_mem_map
from ..changes.verify import VerifyResult, verify_written_image
from ..models import LoadedFile
from ..workspace import (
    WORKAREA_TEMP,
    WorkareaContainmentError,
    copy_into_workarea,
    ensure_workarea,
)
from .crc_config import CrcConfig
from .model import CrcRegionResult, Operation, OperationInput, OperationResult

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


def read_stored_crc_le(
    op_input: OperationInput, output_address: int
) -> Optional[int]:
    """
    Summary:
        Read the 4-byte little-endian value stored at ``output_address`` in the
        input's ``mem_map`` (LLR-002.1, §6.2 D-5 FIXED codec): the bytes at
        ``output_address .. output_address + 3`` decoded low-byte-first via
        :func:`decode_le32`. If ANY of the four addresses is absent from
        ``mem_map`` the region has "no stored value" and ``None`` is returned —
        the function never raises on a missing address.

    Args:
        op_input (OperationInput): The neutral operation input; only its
            ``mem_map`` is read (never mutated).
        output_address (int): The address at which the region's CRC is stored;
            the four consecutive addresses are read low-byte-first.

    Returns:
        Optional[int]: The decoded 32-bit stored value, or ``None`` when any of
        the four addresses is not present in ``mem_map``.

    Raises:
        None: A missing address yields ``None``; the codec ``decode_le32`` is
            only ever handed exactly four present bytes, so it never raises.

    Data Flow:
        - Probe the four addresses ``output_address + i`` in ``mem_map``; if any
          is absent return ``None``; else decode the four bytes via
          :func:`decode_le32`.

    Dependencies:
        Uses:
            - :func:`decode_le32`
        Used by:
            - :func:`check_regions`
            - tests/test_crc_operation.py (TC-111, TC-112, missing-bytes case)

    Example:
        >>> from pathlib import Path
        >>> op_input = OperationInput(
        ...     mem_map={0x100: 0x26, 0x101: 0x39, 0x102: 0xF4, 0x103: 0xCB},
        ...     ranges=[(0x100, 0x104)], input_path=None, variant_id=None,
        ...     file_type="s19",
        ... )
        >>> hex(read_stored_crc_le(op_input, 0x100))
        '0xcbf43926'
    """
    addresses = range(output_address, output_address + LE32_WIDTH)
    if any(addr not in op_input.mem_map for addr in addresses):
        return None
    return decode_le32(op_input.mem_map[addr] for addr in addresses)


def check_regions(
    op_input: OperationInput, config: CrcConfig
) -> list[CrcRegionResult]:
    """
    Summary:
        Run the non-mutating CRC check over every configured region (LLR-002.2):
        for each :class:`CrcRegion` compute the CRC over ``(start, end)`` with
        ``config``'s algorithm params, read the stored 4-byte LE value at the
        region's output address via :func:`read_stored_crc_le`, and build one
        :class:`CrcRegionResult` per region in config order. ``matched`` is
        ``True`` when a stored value is present and equals the computed CRC,
        ``False`` when present and differing, and ``None`` when there is no
        stored value to compare. ``written`` is always ``False`` (the check path
        never mutates). ``op_input.mem_map`` is only read.

    Args:
        op_input (OperationInput): The neutral operation input; its ``mem_map``
            is read for both the CRC compute and the stored-value read, never
            mutated.
        config (CrcConfig): The parsed CRC config supplying the regions and the
            algorithm params (polynomial / init / reverse / final_xor).

    Returns:
        list[CrcRegionResult]: One result per region, in ``config.regions``
        order, each carrying ``output_address`` / ``computed_crc`` /
        ``stored_value`` / ``matched`` / ``written=False``.

    Raises:
        None: Missing stored bytes yield ``stored_value=None`` /
            ``matched=None`` (collect-don't-abort), not an exception.

    Data Flow:
        - For each region: :func:`compute_region_crc` over ``(start, end)`` with
          ``config``'s params → :func:`read_stored_crc_le` at
          ``region.output_address`` → assemble one :class:`CrcRegionResult`.

    Dependencies:
        Uses:
            - :func:`compute_region_crc`
            - :func:`read_stored_crc_le`
            - :class:`s19_app.tui.operations.model.CrcRegionResult`
        Used by:
            - the CRC operation check path (CrcOperation.execute, increment I3)
            - tests/test_crc_operation.py (TC-111, TC-112, multi-region order)

    Example:
        >>> from pathlib import Path
        >>> from s19_app.tui.operations.crc_config import CrcConfig, CrcRegion
        >>> op_input = OperationInput(
        ...     mem_map={0: 0x31, 1: 0x32, 2: 0x33}, ranges=[(0, 3)],
        ...     input_path=None, variant_id=None, file_type="s19",
        ... )
        >>> config = CrcConfig(
        ...     regions=[CrcRegion(start=0, end=3, output_address=0x10)],
        ...     polynomial=DEFAULT_POLYNOMIAL, init=DEFAULT_INIT,
        ...     reverse=DEFAULT_REVERSE, final_xor=DEFAULT_FINAL_XOR,
        ... )
        >>> check_regions(op_input, config)[0].matched is None
        True
    """
    results: list[CrcRegionResult] = []
    for region in config.regions:
        computed = compute_region_crc(
            op_input.mem_map,
            region.start,
            region.end,
            polynomial=config.polynomial,
            init=config.init,
            reverse=config.reverse,
            final_xor=config.final_xor,
        )
        stored = read_stored_crc_le(op_input, region.output_address)
        matched = None if stored is None else (stored == computed)
        results.append(
            CrcRegionResult(
                output_address=region.output_address,
                computed_crc=computed,
                stored_value=stored,
                matched=matched,
                written=False,
            )
        )
    return results


#: Suffix appended to the input file stem for the auto-generated emitted-S19
#: name (LLR-003.2): ``<stem>-crc.s19``. NO operator-arbitrary path is ever
#: honored — the emit name is derived, never supplied.
EMITTED_NAME_SUFFIX: str = "-crc"

#: The default emitted-S19 output subdirectory under
#: ``.s19tool/workarea/`` — kept SEPARATE from ``temp/`` (the staging dir) so a
#: first write lands as ``<stem>-crc.s19`` rather than self-colliding with its
#: own staged copy; ``copy_into_workarea`` still name-dedups a genuine re-write
#: (F-S-03 no-overwrite).
CRC_OUTPUT_SUBDIR: str = "crc"

#: Fallback stem when the input snapshot has no source path
#: (``OperationInput.input_path is None``) — the emitted file is still named
#: deterministically rather than failing.
DEFAULT_EMITTED_STEM: str = "image"


def _emitted_file_name(input_path: Optional[Path]) -> str:
    """
    Summary:
        Derive the auto-generated emitted-S19 file name from the input path
        (LLR-003.2): ``<input stem>-crc.s19``, falling back to
        ``image-crc.s19`` when the input snapshot has no source path. The name
        is always derived — never operator-supplied — so the write target is
        a fixed stem under the contained work area, not an arbitrary path
        (F-S-01 posture).

    Args:
        input_path (Optional[Path]): The input snapshot's source path
            (``OperationInput.input_path``); ``None`` outside a file-backed
            load.

    Returns:
        str: The bare file name (no directory) ``"<stem>-crc.s19"``.

    Data Flow:
        - Take ``input_path.stem`` (or :data:`DEFAULT_EMITTED_STEM`), append
          :data:`EMITTED_NAME_SUFFIX` and the ``.s19`` suffix.

    Dependencies:
        Used by:
            - :func:`write_crc_image`

    Example:
        >>> _emitted_file_name(Path("/tmp/firmware.s19"))
        'firmware-crc.s19'
        >>> _emitted_file_name(None)
        'image-crc.s19'
    """
    stem = input_path.stem if input_path is not None and input_path.stem else DEFAULT_EMITTED_STEM
    return f"{stem}{EMITTED_NAME_SUFFIX}.s19"


def _extend_ranges(
    ranges: list[tuple[int, int]], new_start: int, new_end: int
) -> list[tuple[int, int]]:
    """
    Summary:
        Insert the half-open range ``[new_start, new_end)`` into ``ranges`` and
        return a NEW list that is SORTED by start and non-overlapping
        (D-6 / F-A-06): any range that touches or overlaps the new one
        (``a_start <= b_end`` and ``b_start <= a_end``) is merged into a single
        covering range. The input list is not mutated.

    Args:
        ranges (list[tuple[int, int]]): The existing half-open ``(start, end)``
            ranges; assumed already sorted + non-overlapping (the
            ``LoadedFile.ranges`` invariant), but the merge is correct for any
            input order.
        new_start (int): Inclusive start of the range to insert.
        new_end (int): Exclusive end of the range to insert.

    Returns:
        list[tuple[int, int]]: A fresh sorted, non-overlapping range list that
        covers every address of ``ranges`` plus ``[new_start, new_end)``.

    Data Flow:
        - Append the new range, sort by start, then sweep once merging any
          range whose start is ``<=`` the running merged end (touching ranges
          merge, so two adjacent extension writes never leave a seam).

    Dependencies:
        Used by:
            - :func:`inject_crcs`
            - tests/test_crc_operation.py (TC-122)

    Example:
        >>> _extend_ranges([(0, 4), (8, 12)], 4, 8)
        [(0, 12)]
    """
    combined = sorted([*ranges, (new_start, new_end)])
    merged: list[tuple[int, int]] = []
    for start, end in combined:
        if merged and start <= merged[-1][1]:
            prev_start, prev_end = merged[-1]
            merged[-1] = (prev_start, max(prev_end, end))
        else:
            merged.append((start, end))
    return merged


def inject_crcs(
    op_input: OperationInput,
    crc_regions: list[CrcRegionResult],
) -> tuple[dict[int, int], list[tuple[int, int]], list[CrcRegionResult]]:
    """
    Summary:
        Build a WORKING COPY of ``op_input``'s ``mem_map`` / ``ranges`` with
        each region's computed CRC written as 4 little-endian bytes at its
        output address (LLR-003.1, §6.2 D-5/D-6). The originally loaded
        ``mem_map`` / ``ranges`` are NEVER mutated — a fresh ``dict`` / ``list``
        is built. When an output address falls outside every loaded range, the
        working ``mem_map`` gains exactly the 4 missing keys AND the working
        ``ranges`` gains/merges a covering ``[output_address, output_address+4)``
        range, kept SORTED + non-overlapping via :func:`_extend_ranges`
        (guarding ``emit_s19_from_mem_map``'s ``KeyError`` on a range claiming an
        absent address). Each input :class:`CrcRegionResult` is re-emitted with
        ``written=True``.

    Args:
        op_input (OperationInput): The neutral input; its ``mem_map`` / ``ranges``
            are READ to seed the working copy, never mutated.
        crc_regions (list[CrcRegionResult]): The per-region check results from
            :func:`check_regions`, in config order; each supplies the
            ``output_address`` and the ``computed_crc`` to inject.

    Returns:
        tuple[dict[int, int], list[tuple[int, int]], list[CrcRegionResult]]:
        ``(working_mem_map, working_ranges, written_regions)`` — the injected
        memory map, its sorted non-overlapping ranges, and one
        ``CrcRegionResult`` per region carrying the same address/value with
        ``written=True``.

    Raises:
        None: A gapped output address is handled by extension, not an error;
            this is a pure in-memory transform.

    Data Flow:
        - Copy ``mem_map`` / ``ranges``. For each region: encode the computed
          CRC LE (:func:`encode_le32`), set the 4 addresses in the working map;
          if any of the 4 was absent from every loaded range, extend ``ranges``
          via :func:`_extend_ranges`. Re-emit each region with ``written=True``.

    Dependencies:
        Uses:
            - :func:`encode_le32`
            - :func:`_extend_ranges`
            - ``s19_app.range_index`` membership primitives (import-only)
        Used by:
            - :func:`write_crc_image`
            - tests/test_crc_operation.py (TC-121, TC-122)

    Example:
        >>> op_input = OperationInput(
        ...     mem_map={0: 0x31}, ranges=[(0, 1)], input_path=None,
        ...     variant_id=None, file_type="s19",
        ... )
        >>> region = CrcRegionResult(
        ...     output_address=0x10, computed_crc=0x04030201,
        ...     stored_value=None, matched=None, written=False,
        ... )
        >>> mem, ranges, written = inject_crcs(op_input, [region])
        >>> [mem[0x10 + i] for i in range(4)]
        [1, 2, 3, 4]
        >>> written[0].written
        True
    """
    working_mem: dict[int, int] = dict(op_input.mem_map)
    working_ranges: list[tuple[int, int]] = list(op_input.ranges)
    written_regions: list[CrcRegionResult] = []

    for region in crc_regions:
        payload = encode_le32(region.computed_crc)
        addresses = range(
            region.output_address, region.output_address + LE32_WIDTH
        )
        range_index = build_sorted_range_index(working_ranges)
        in_a_range = all(
            address_in_sorted_ranges(addr, range_index) for addr in addresses
        )
        for offset, value in enumerate(payload):
            working_mem[region.output_address + offset] = value
        if not in_a_range:
            working_ranges = _extend_ranges(
                working_ranges,
                region.output_address,
                region.output_address + LE32_WIDTH,
            )
        written_regions.append(
            CrcRegionResult(
                output_address=region.output_address,
                computed_crc=region.computed_crc,
                stored_value=region.stored_value,
                matched=region.matched,
                written=True,
            )
        )

    return working_mem, working_ranges, written_regions


@dataclass
class CrcWriteResult:
    """
    Summary:
        The headless outcome of the CRC write path (re-scoped LLR-003.5): the
        per-region results (``written=True`` on success), the emitted-S19 path,
        the verify verdict, and any collected findings. Returned by
        :func:`write_crc_image` so the I5b TUI layer can assemble the
        ``OperationResult`` (status / notes / ``crc_regions``) WITHOUT this
        headless module importing Textual. A containment / path / data fault
        is a collected ``findings`` string, never an exception.

    Args:
        crc_regions (list[CrcRegionResult]): Per-region results. On a written
            image each carries ``written=True``; when the write was refused
            (containment finding) the regions are the injected-but-unwritten
            results and the caller treats ``written_path is None`` as "no file".
        written_path (Optional[Path]): The emitted-S19 path inside the contained
            work area, or ``None`` when no file was written (containment /
            emit / verify-stage fault).
        verify_status (Optional[str]): ``verify.STATUS_VERIFIED`` /
            ``"mismatch"`` from :func:`verify_written_image`, or ``None`` when no
            file was written (so verify never ran).
        verify_runs (list): The :class:`VerifyResult.runs` diff runs; empty on a
            verified write, non-empty on a mismatch, empty when no file was
            written.
        findings (list[str]): Collected plain-text faults (containment refusal,
            emit / write OSError); empty on a clean verified write. Paths are
            interpolated as PLAIN text (F-S-04).

    Returns:
        None: Dataclass container.

    Data Flow:
        - Produced by :func:`write_crc_image`; consumed by the I5b confirm
          handler to build the ``OperationResult`` and render the op-result
          rows.

    Dependencies:
        Used by:
            - :func:`write_crc_image`
            - tests/test_crc_operation.py (TC-123, TC-124, TC-126, containment)

    Example:
        >>> CrcWriteResult(
        ...     crc_regions=[], written_path=None, verify_status=None,
        ...     verify_runs=[], findings=["refused"],
        ... ).written_path is None
        True
    """

    crc_regions: list[CrcRegionResult]
    written_path: Optional[Path]
    verify_status: Optional[str]
    verify_runs: List[object] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)


def write_crc_image(
    op_input: OperationInput,
    config: CrcConfig,
    *,
    workarea_base: Path,
    dest_dir: Optional[Path] = None,
) -> CrcWriteResult:
    """
    Summary:
        The side-effectful CRC write path, headless and only-writes-when-called
        (LLR-003.1/.2/.3, re-scoped LLR-003.5; §6.2 D-6/D-8). It computes the
        per-region CRCs (:func:`check_regions`), injects them into a working
        copy (:func:`inject_crcs`, original never mutated), serializes the
        injected map via ``emit_s19_from_mem_map``, stages the text under
        ``<workarea_base>/.s19tool/workarea/temp/`` and places it into the
        contained work area via ``copy_into_workarea`` — which enforces the
        REAL containment seam (``_find_workarea_root`` +
        ``is_relative_to(workarea_root)`` + ``_path_traverses_reparse_point``)
        AND name-dedups on collision (no overwrite, F-S-03) — then verifies the
        written file against the INJECTED map (F-Q-05) via
        ``verify_written_image``. A containment / path / write fault is a single
        collected finding with NO file written (collect-don't-abort; never
        raises on a data/path fault).

    Args:
        op_input (OperationInput): The neutral input; only ``mem_map`` / ``ranges``
            are read, never mutated.
        config (CrcConfig): The parsed CRC config supplying the regions and
            algorithm params.
        workarea_base (Path): The base directory whose ``.s19tool/workarea/`` is
            the staging + containment root (the caller / TUI supplies the app
            base dir; a test passes a ``tmp_path``). Kept injectable so the path
            is headless / testable.
        dest_dir (Optional[Path]): The directory the emitted S19 is placed into.
            ``None`` (the default) targets the contained
            ``.s19tool/workarea/crc/`` output dir (distinct from the ``temp/``
            staging dir, so a first write is not dedup-suffixed by its own
            staged copy). A ``dest_dir`` OUTSIDE the work area fails
            ``copy_into_workarea``'s containment check → one finding, no file
            (the security-relevant escape case).

    Returns:
        CrcWriteResult: On a clean write — ``written_path`` set, ``verify_status``
        ``"verified"`` (or ``"mismatch"`` if the re-read drifts), ``crc_regions``
        with ``written=True``, empty ``findings``. On a containment / write
        fault — ``written_path is None``, ``verify_status is None``, one
        ``findings`` entry.

    Raises:
        None: Every containment / path / OS fault is a collected ``findings``
            string (collect-don't-abort, D-8). The staged temp file is always
            cleaned up.

    Data Flow:
        - :func:`check_regions` → :func:`inject_crcs` (working copy) →
          ``emit_s19_from_mem_map(working_mem, working_ranges)`` →
          stage under ``temp/`` → ``copy_into_workarea(staged, dest_dir)``
          (containment + dedup) → ``verify_written_image(placed, working_mem,
          "s19")`` → assemble :class:`CrcWriteResult`.

    Dependencies:
        Uses:
            - :func:`check_regions`
            - :func:`inject_crcs`
            - ``changes.io.emit_s19_from_mem_map`` (import-only)
            - ``workspace.ensure_workarea`` / ``copy_into_workarea`` (import-only)
            - ``changes.verify.verify_written_image`` (import-only)
        Used by:
            - the I5b TUI confirm handler (assembles the OperationResult)
            - tests/test_crc_operation.py (TC-123, TC-124, TC-126, containment)
    """
    check_results = check_regions(op_input, config)
    working_mem, working_ranges, written_regions = inject_crcs(
        op_input, check_results
    )

    workarea = ensure_workarea(workarea_base)
    temp_dir = workarea / WORKAREA_TEMP
    target_dir = (workarea / CRC_OUTPUT_SUBDIR) if dest_dir is None else dest_dir
    file_name = _emitted_file_name(op_input.input_path)
    staged = temp_dir / file_name

    placed: Optional[Path] = None
    try:
        # F-S-06 defense-in-depth: emit is inside the try so a hypothetical
        # KeyError (an injected range claiming an address absent from the
        # working map — unreachable by construction since inject_crcs extends
        # the map, but guarded anyway on this side-effectful path) becomes a
        # collected finding, never an unhandled raise.
        s19_text = emit_s19_from_mem_map(working_mem, working_ranges)
        staged.parent.mkdir(parents=True, exist_ok=True)
        staged.write_text(s19_text, encoding="utf-8")
        placed = copy_into_workarea(staged, target_dir)
    except (WorkareaContainmentError, OSError, KeyError) as exc:
        return CrcWriteResult(
            crc_regions=written_regions,
            written_path=None,
            verify_status=None,
            verify_runs=[],
            findings=[
                "CRC write failed — no file was written: "
                f"{type(exc).__name__}: {exc}"
            ],
        )
    finally:
        try:
            staged.unlink()
        except OSError:
            pass

    verify_result: VerifyResult = verify_written_image(
        placed, working_mem, "s19"
    )
    return CrcWriteResult(
        crc_regions=written_regions,
        written_path=placed,
        verify_status=verify_result.status,
        verify_runs=verify_result.runs,
        findings=[],
    )


def _summarize_check(crc_regions: list[CrcRegionResult]) -> str:
    """
    Summary:
        Build the one-line CRC check note from a list of per-region results,
        counting matched (``matched is True``), mismatched (``matched is
        False``), and no-stored-value (``matched is None``) regions.

    Args:
        crc_regions (list[CrcRegionResult]): The per-region check results, in
            config order.

    Returns:
        str: The note ``"CRC: N region(s): M matched, K mismatched, J
        no-stored-value"``.

    Data Flow:
        - Partition ``crc_regions`` by their ``matched`` tri-state into the
          three counts; format the single summary line.

    Dependencies:
        Used by:
            - :meth:`CrcOperation.execute` (config-supplied check path)
    """
    matched = sum(1 for region in crc_regions if region.matched is True)
    mismatched = sum(1 for region in crc_regions if region.matched is False)
    no_stored = sum(1 for region in crc_regions if region.matched is None)
    return (
        f"CRC: {len(crc_regions)} region(s): {matched} matched, "
        f"{mismatched} mismatched, {no_stored} no-stored-value"
    )


class CrcOperation(Operation):
    """
    Summary:
        The real CRC check operation over a loaded image (CRC_F2, HLR/LLR
        check path). On the non-mutating check path (F-Q-02) it computes a
        CRC per configured region and compares it against the stored 4-byte
        little-endian value at each region's output address, reporting the
        per-region verdicts on ``OperationResult.crc_regions``. The input
        snapshot is never mutated; ``output`` is a fresh ``LoadedFile`` over
        the same ``mem_map`` / ``ranges``. With no config supplied there is
        nothing to check, so the result carries no regions and one explaining
        note.

    Data Flow:
        - Registered under id ``"crc"`` in ``operations.registry``; executed
          through the ``run_operation`` service seam (no config) or with a
          ``CrcConfig`` passed directly to :meth:`execute`.

    Dependencies:
        Uses:
            - Operation
            - check_regions
            - OperationResult / LoadedFile
        Used by:
            - operations.registry
            - tui.services.operation_service.run_operation
    """

    operation_id: str = "crc"
    title: str = "CRC"

    def describe(self) -> str:
        """
        Summary:
            Describe the CRC check operation (LLR-001.1).

        Returns:
            str: Non-empty description text.

        Data Flow:
            - Read by presentation surfaces and TC-009.

        Dependencies:
            Used by:
                - tests/test_operations.py (TC-009)
        """
        return (
            "Compute a CRC32 over each configured region of the loaded image "
            "and compare it against the stored value."
        )

    def execute(
        self,
        op_input: OperationInput,
        *,
        now_fn: Optional[Callable[[], datetime]] = None,
        config: Optional[CrcConfig] = None,
    ) -> OperationResult:
        """
        Summary:
            Run the non-mutating CRC check over ``op_input`` (F-Q-02). When
            ``config`` is supplied, compute one CRC per region and compare it
            against the stored 4-byte LE value via :func:`check_regions`,
            carrying the per-region verdicts on ``crc_regions`` and a summary
            note. When ``config`` is ``None`` there is nothing to check, so
            ``crc_regions`` is ``None`` and a single explaining note is
            returned. Either way ``status`` is ``"ok"`` and the input snapshot
            is never mutated; ``output`` is a fresh ``LoadedFile`` over the
            input's ``mem_map`` / ``ranges``.

        Args:
            op_input (OperationInput): The neutral input; only ``mem_map`` is
                read, never mutated.
            now_fn (Optional[Callable[[], datetime]]): Injectable UTC clock;
                ``None`` defaults to ``datetime.now(timezone.utc)`` (the
                ``changes.apply`` clock-seam idiom). The result records
                ``now_fn().isoformat()``.
            config (Optional[CrcConfig]): The parsed CRC config supplying the
                regions and algorithm params. ``None`` (the default, used by
                the generic ``run_operation`` seam) means there is nothing to
                check.

        Returns:
            OperationResult: ``status="ok"``; ``crc_regions`` is the list of
            per-region results when ``config`` is supplied, else ``None``;
            ``notes`` carries one summary (config path) or one
            nothing-to-check note (no-config path).

        Raises:
            None: The check path collects per-region verdicts (including
                no-stored-value) without raising.

        Data Flow:
            - Rebuild ``output`` as a ``LoadedFile`` over ``op_input`` (no
              mutation). ``config is None`` → one note, ``crc_regions=None``.
              Else :func:`check_regions` → :func:`_summarize_check` note.

        Dependencies:
            Uses:
                - check_regions
                - _summarize_check
                - OperationResult / LoadedFile
            Used by:
                - tui.services.operation_service.run_operation
                - tests/test_crc_operation.py (execute tests)
        """
        clock: Callable[[], datetime] = (
            now_fn if now_fn is not None else (lambda: datetime.now(timezone.utc))
        )
        output = LoadedFile(
            path=(
                op_input.input_path
                if op_input.input_path is not None
                else Path("")
            ),
            file_type=op_input.file_type,
            mem_map=op_input.mem_map,
            row_bases=[],
            ranges=op_input.ranges,
            range_validity=[],
            errors=[],
            a2l_path=None,
            a2l_data=None,
            variant_id=op_input.variant_id,
        )
        if config is None:
            crc_regions: Optional[list[CrcRegionResult]] = None
            notes = ["CRC: no config supplied — nothing to check"]
        else:
            crc_regions = check_regions(op_input, config)
            notes = [_summarize_check(crc_regions)]
        return OperationResult(
            operation_id=self.operation_id,
            status="ok",
            input_path=op_input.input_path,
            variant_id=op_input.variant_id,
            output=output,
            notes=notes,
            timestamp_utc=clock().isoformat(),
            crc_regions=crc_regions,
        )
