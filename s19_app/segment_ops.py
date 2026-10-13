"""
Split / Join / Export — the engine additions (batch-95, HLR-137 / LLR-137.1..137.4).

The three engine pieces the new screen rides, composed from shipped parts only:

- the **range slicer** (LLR-137.1) — one contiguous range ``[start, end)`` or a
  multi-range selection sliced out of a loaded image's ``get_memory_map`` as a
  standalone in-memory image, preserving each range's original offset (the
  join-fill input);
- the **BIN emitter + ``.addr`` sidecar** (LLR-137.2) — none ships today;
- the **pad-byte fill emitter** (LLR-137.3) — one gap-fill pass with the CRC
  editor's ``join="fill"`` semantics and the fixed
  ``on_gap_conflict="abort"`` law (ruling 8f): a fill that would clobber a real
  source byte refuses BEFORE a byte is emitted, naming the offending span.

The **join** composition rides here too (ruling Q2/8b — ``concat`` packs the
selection back-to-back from the FIRST/lowest range's base) so the screen stays
thin. The in-memory image shape everywhere is the shipped emitters' contract —
``(mem_map, ranges)`` with half-open ``(start, end)`` ranges — so the S19/HEX
emitters (``tui/changes/io.py``) consume every result without adaptation.

Placement: a new top-level module rather than ``core.py`` / ``hexfile.py``,
which the read-only-engine guard (TC-027) freezes vs ``main`` — this module
COMPOSES their shipped outputs, it does not touch the parsers.
"""

from __future__ import annotations

from pathlib import Path
from typing import Union

from .tui.changes.io import emit_intel_hex_from_mem_map, emit_s19_from_mem_map
from .tui.operations.crc_designer_model import (
    INTRA_GAP_VALUES,
    CrcTarget,
    gap_conflict,
)

#: The ruled default pad byte (Q1/8a) — deliberately NOT the CRC editor's
#: ``0xFF``: erased-flash ``0xFF`` and neutral ``0x00`` are different intents.
DEFAULT_PAD_BYTE: int = 0x00

#: The export formats the screen offers; ``s19`` / ``hex`` ride the shipped
#: mem_map emitters, ``bin`` the flat-bytes emitter minted here (LLR-137.2).
EXPORT_FORMATS: tuple[str, ...] = ("s19", "hex", "bin")


class GapConflictError(ValueError):
    """
    Summary:
        A fill or join would clobber real source bytes — or the input ranges
        overlap — under the fixed ``on_gap_conflict="abort"`` policy adopted
        from the CRC editor (ruling 8f). The export refuses before a single
        byte is emitted, and the reason names the offending span.
    """


# ---------------------------------------------------------------------------
# LLR-137.1 — the range slicer
# ---------------------------------------------------------------------------


def slice_range(
    mem_map: dict[int, int], start: int, end: int
) -> tuple[dict[int, int], list[tuple[int, int]]]:
    """
    Summary:
        Extract one contiguous range ``[start, end)`` from a loaded image's
        memory map as a standalone in-memory image — the covered sub-ranges
        composed from the shipped ``get_memory_map`` (the parse layer builds
        the map; the slicer filters it, P-14), without touching the parsers.

    Args:
        mem_map (dict[int, int]): The loaded image's address-to-byte map
            (``S19File.get_memory_map`` / ``IntelHexFile.memory``).
        start (int): The range's inclusive base.
        end (int): The range's exclusive end.

    Returns:
        tuple[dict[int, int], list[tuple[int, int]]]: ``(slice_map,
        covered_ranges)`` — ``slice_map`` maps ORIGINAL addresses to bytes
        (no offset remapping — join=fill needs the source offsets, ruling
        8d), holding exactly the covered addresses; ``covered_ranges`` are
        the covered sub-ranges as contiguous half-open ``(start, end)``
        spans, ascending — directly consumable by the shipped emitters.

    Data Flow:
        - Clamp to the covered sub-ranges: an address is sliced iff it is
          inside ``[start, end)`` AND present in ``mem_map``.
        - ``start >= end`` or an out-of-image range yields ``({}, [])`` —
          empty coverage, never a raise (LLR-137.1 boundary catalog).

    Dependencies:
        Used by:
            - the Split / Join / Export screen (split + join slicing)
            - tests/test_segment_ops.py (TC-683)
    """
    if end <= start:
        return {}, []
    covered = sorted(a for a in mem_map if start <= a < end)
    if not covered:
        return {}, []
    slice_map = {a: mem_map[a] for a in covered}

    ranges: list[tuple[int, int]] = []
    range_start = prev = covered[0]
    for addr in covered[1:]:
        if addr == prev + 1:
            prev = addr
        else:
            ranges.append((range_start, prev + 1))
            range_start = prev = addr
    ranges.append((range_start, prev + 1))
    return slice_map, ranges


def slice_ranges(
    mem_map: dict[int, int], ranges: list[tuple[int, int]]
) -> list[tuple[dict[int, int], list[tuple[int, int]]]]:
    """
    Summary:
        The multi-range slice: one :func:`slice_range` per requested range, in
        requested order, each preserving its range's original offset — the
        join-fill input (LLR-137.1).

    Args:
        mem_map (dict[int, int]): The loaded image's address-to-byte map.
        ranges (list[tuple[int, int]]): The selected half-open ranges.

    Returns:
        list[tuple[dict[int, int], list[tuple[int, int]]]]: One
        ``(slice_map, covered_ranges)`` pair per input range; an out-of-image
        range contributes ``({}, [])``, never a raise.
    """
    return [slice_range(mem_map, start, end) for start, end in ranges]


# ---------------------------------------------------------------------------
# LLR-137.2 — the BIN emitter and the .addr sidecar
# ---------------------------------------------------------------------------


def emit_bin_from_mem_map(
    mem_map: dict[int, int], ranges: list[tuple[int, int]]
) -> bytes:
    """
    Summary:
        Serialize an in-memory image as FLAT binary — the present bytes in
        address order across the covered sub-ranges. No gap padding inside a
        range (the split ``intra_gap="skip"`` semantics), no embedded base
        address, no header of any kind (LLR-137.2).

    Args:
        mem_map (dict[int, int]): Address-to-byte map (read only).
        ranges (list[tuple[int, int]]): The half-open ranges driving the
            emission order — the same contract the shipped S19/HEX emitters
            take, so one plan serializes byte-consistently in all formats.

    Returns:
        bytes: Exactly the covered bytes, ascending; a fully covered
            ``[base, base+size)`` yields exactly ``size`` bytes (0 extra,
            0 missing). A zero-coverage range yields ``b""`` — the empty
            file behind the LLR-136.6 confirm.

    Dependencies:
        Used by:
            - emit_image (the ``"bin"`` limb)
            - tests/test_segment_ops.py (TC-684)
    """
    return bytes(
        mem_map[addr]
        for start, end in ranges
        for addr in range(start, end)
        if addr in mem_map
    )


def bin_addr_sidecar(base: int) -> str:
    """
    Summary:
        The one-line ``.addr`` sidecar text carrying the segment's base
        address (LLR-137.2) — e.g. ``"0x08000000"`` — so the base stays
        recoverable from the file pair (the round's #2 recommendation; a flat
        BIN stores no address of its own).

    Args:
        base (int): The segment base (the FIRST range's declared base, even
            for a zero-coverage range).

    Returns:
        str: Exactly one line, ``0x`` + 8 uppercase hex digits + newline.
    """
    return f"0x{base:08X}\n"


def write_bin_with_sidecar(
    mem_map: dict[int, int],
    ranges: list[tuple[int, int]],
    dest: Path,
) -> tuple[Path, Path]:
    """
    Summary:
        Write the flat BIN and its ``.addr`` sidecar next to it — for
        ``‹name›.bin`` the sidecar is ``‹name›.addr`` (suffix swapped, the
        round's naming), one line from :func:`bin_addr_sidecar`.

    Args:
        mem_map (dict[int, int]): Address-to-byte map (read only).
        ranges (list[tuple[int, int]]): The emitted ranges; the sidecar base
            is the first range's declared base (0 when there is none).
        dest (Path): The ``.bin`` output path.

    Returns:
        tuple[Path, Path]: ``(bin_path, sidecar_path)``.
    """
    base = ranges[0][0] if ranges else 0
    dest.write_bytes(emit_bin_from_mem_map(mem_map, ranges))
    sidecar = dest.with_suffix(".addr")
    sidecar.write_text(bin_addr_sidecar(base), encoding="ascii")
    return dest, sidecar


# ---------------------------------------------------------------------------
# Shared range normalization (the abort law's overlap limb)
# ---------------------------------------------------------------------------


def _sorted_checked_ranges(
    ranges: list[tuple[int, int]], *, context: str
) -> list[tuple[int, int]]:
    """
    Summary:
        Normalize a range selection for the join/fill emitters: sort
        ascending by base and reject overlaps — two ranges claiming the same
        address would make the composed image ambiguous, so the export
        aborts naming both spans (the gap-conflict law's overlap limb).

    Args:
        ranges (list[tuple[int, int]]): The half-open ranges (declared order
            is irrelevant to the output; the join packs ascending per ruling
            Q2/8b).
        context (str): The emitter's name for the error reason.

    Returns:
        list[tuple[int, int]]: The sorted ranges (empties kept).

    Raises:
        ValueError: An inverted range (``end < start``).
        GapConflictError: Overlapping ranges — the reason names both spans.
    """
    normalized = sorted((int(start), int(end)) for start, end in ranges)
    for start, end in normalized:
        if end < start:
            raise ValueError(
                f"{context}: inverted range 0x{start:08X}-0x{end:08X}"
            )
    for prev, current in zip(normalized, normalized[1:]):
        if current[0] < prev[1]:
            raise GapConflictError(
                f"{context}: overlapping ranges 0x{prev[0]:08X}-0x{prev[1]:08X} "
                f"and 0x{current[0]:08X}-0x{current[1]:08X} — export aborted "
                f"(on_gap_conflict=abort)"
            )
    return normalized


# ---------------------------------------------------------------------------
# LLR-137.3 — the pad-byte fill emitter (intra-gap + join)
# ---------------------------------------------------------------------------


def _check_pad_byte(pad_byte: int) -> int:
    """Validate the pad byte (0..255), normalizing to int."""
    pad = int(pad_byte)
    if not 0 <= pad <= 0xFF:
        raise ValueError(f"pad_byte must be 0..255, got {pad_byte!r}")
    return pad


def fill_range(
    mem_map: dict[int, int],
    start: int,
    end: int,
    pad_byte: int = DEFAULT_PAD_BYTE,
    intra_gap: str = "fill",
) -> tuple[dict[int, int], list[tuple[int, int]]]:
    """
    Summary:
        The split ``intra_gap`` policy over ONE range (LLR-137.3): ``fill``
        materializes the whole ``[start, end)`` — absent addresses take the
        pad byte — while ``skip`` keeps the present bytes only. Present
        source bytes are never overwritten, so the intra-gap fill cannot
        conflict (the abort law is the JOIN fill's, see :func:`join_fill`).

    Args:
        mem_map (dict[int, int]): The loaded image's address-to-byte map.
        start (int): The range's inclusive base.
        end (int): The range's exclusive end.
        pad_byte (int): Fill value (0..255; default :data:`DEFAULT_PAD_BYTE`
            — the ruled ``0x00`, Q1/8a).
        intra_gap (str): ``"fill"`` or ``"skip"`` — the shipped
            :data:`INTRA_GAP_VALUES` vocabulary, verbatim.

    Returns:
        tuple[dict[int, int], list[tuple[int, int]]]: ``(map, ranges)`` —
        ``fill`` → a dense single ``[(start, end)]``; ``skip`` → the sparse
        covered image (identical to :func:`slice_range`). An empty range
        yields ``({}, [])``.
    """
    pad = _check_pad_byte(pad_byte)
    if intra_gap not in INTRA_GAP_VALUES:
        raise ValueError(
            f"intra_gap must be one of {list(INTRA_GAP_VALUES)}, got {intra_gap!r}"
        )
    if intra_gap == "skip":
        return slice_range(mem_map, start, end)
    if end <= start:
        return {}, []
    return {addr: mem_map.get(addr, pad) for addr in range(start, end)}, [
        (start, end)
    ]


def join_fill(
    mem_map: dict[int, int],
    ranges: list[tuple[int, int]],
    pad_byte: int = DEFAULT_PAD_BYTE,
) -> tuple[dict[int, int], list[tuple[int, int]]]:
    """
    Summary:
        The join ``fill`` export (LLR-137.3, ruling 8d): the selection stays
        at its ORIGINAL offsets, the inter-range gaps take the pad byte, and
        the result is ONE dense range ``[first_base, last_end)`` the shipped
        emitters write without adaptation.

    Args:
        mem_map (dict[int, int]): The loaded image's address-to-byte map
            (read only — never mutated).
        ranges (list[tuple[int, int]]): The selected half-open ranges.
        pad_byte (int): Fill value (0..255; default :data:`DEFAULT_PAD_BYTE`).

    Returns:
        tuple[dict[int, int], list[tuple[int, int]]]: ``(filled_map,
        [(first_base, last_end)])`` — every address in the span present:
        source bytes at their offsets, pad bytes across the gaps.

    Raises:
        ValueError: An inverted range or an invalid pad byte.
        GapConflictError: The shipped gap-conflict law (the CRC editor's
            ``join="fill"`` + fixed ``on_gap_conflict="abort"``, ruling 8f):
            a source byte present inside a padded gap and DIFFERING from the
            pad byte would be silently clobbered, so the export refuses
            before emitting anything, naming the offending addresses. A gap
            byte equal to the pad byte is erased flash, not a conflict.

    Dependencies:
        Uses:
            - gap_conflict / CrcTarget (the shipped CRC coverage law,
              reused verbatim — the serialization fields are inert dummies)
        Used by:
            - the Split / Join / Export screen (join=fill export)
            - tests/test_segment_ops.py (TC-685)
    """
    pad = _check_pad_byte(pad_byte)
    normalized = _sorted_checked_ranges(ranges, context="join fill")

    # The shipped safety detector (crc_designer_model.gap_conflict): present
    # bytes inside a padded inter-range span that differ from the pad byte.
    # intra_gap="skip" on the probe because the law probes the JOIN gaps; the
    # store fields are inert for detection.
    probe = CrcTarget(
        ranges=tuple(normalized),
        intra_gap="skip",
        join="fill",
        pad_byte=pad,
        output_address=0,
        store_width=1,
        store_endianness="little",
    )
    conflicts = gap_conflict(mem_map, probe)
    if conflicts:
        shown = ", ".join(f"0x{addr:08X}" for addr in conflicts[:8])
        more = "" if len(conflicts) <= 8 else f" (+{len(conflicts) - 8} more)"
        raise GapConflictError(
            f"join fill: {len(conflicts)} present byte(s) at {shown}{more} "
            f"inside a padded gap differ from pad byte 0x{pad:02X} — export "
            f"aborted (on_gap_conflict=abort)"
        )

    if not normalized:
        return {}, []
    first_base = normalized[0][0]
    last_end = max(end for _, end in normalized)
    if last_end <= first_base:
        return {}, []
    filled = {
        addr: mem_map.get(addr, pad) for addr in range(first_base, last_end)
    }
    return filled, [(first_base, last_end)]


# ---------------------------------------------------------------------------
# The join — concat (ruling Q2/8b)
# ---------------------------------------------------------------------------


def join_concat(
    mem_map: dict[int, int], ranges: list[tuple[int, int]]
) -> tuple[dict[int, int], list[tuple[int, int]]]:
    """
    Summary:
        The join ``concat`` export (ruling Q2/8b): the selection packed into
        ONE image, the present ranges butted back-to-back (skip semantics —
        no bytes invented) from the FIRST/lowest range's base. The base is
        otherwise arbitrary for a concat blob; the lowest range is the one
        firmware images conventionally boot from.

    Args:
        mem_map (dict[int, int]): The loaded image's address-to-byte map
            (read only — never mutated).
        ranges (list[tuple[int, int]]): The selected half-open ranges,
            packed in ASCENDING-base order regardless of declaration order
            (TC-694's ascending-base packing).

    Returns:
        tuple[dict[int, int], list[tuple[int, int]]]: ``(packed_map,
        [(lowest_base, lowest_base + total)])`` — dense, one range; empty
        coverage yields ``({}, [])``.

    Raises:
        ValueError: An inverted range.
        GapConflictError: Overlapping input ranges (the abort law — a packed
            address would be claimed twice).

    Dependencies:
        Used by:
            - the Split / Join / Export screen (join=concat export)
            - tests/test_segment_ops.py (TC-694)
    """
    normalized = _sorted_checked_ranges(ranges, context="join concat")
    if not normalized:
        return {}, []

    # Ruling Q2/8b: the packed image starts at the FIRST/lowest declared
    # range's base — not at the first covered byte (a leading hole stays a
    # leading hole in the source, not in the output).
    cursor = normalized[0][0]
    packed: dict[int, int] = {}
    for start, end in normalized:
        for addr in range(start, end):
            if addr in mem_map:
                packed[cursor] = mem_map[addr]
                cursor += 1
    if not packed:
        return {}, []
    return packed, [(normalized[0][0], cursor)]


# ---------------------------------------------------------------------------
# The one emit entry — the screen's export dispatch
# ---------------------------------------------------------------------------


def emit_image(
    mem_map: dict[int, int],
    ranges: list[tuple[int, int]],
    fmt: str,
    bytes_per_line: int = 32,
) -> Union[str, bytes]:
    """
    Summary:
        The split/join emit entry (HLR-137's boundary decomposition): one
        plan, three formats. ``"s19"`` / ``"hex"`` ride the shipped mem_map
        emitters (``tui/changes/io.py:1419/1569``) — byte-identical content
        for the same plan in every format; ``"bin"`` is the flat bytes
        (LLR-137.2). The fill runs BEFORE the emitters (LLR-137.3 — a fill
        pass after emission would leave the gaps unfilled).

    Args:
        mem_map (dict[int, int]): The planned image's address-to-byte map —
            every address inside ``ranges`` must be present (the shipped
            emitters' contract; join_fill/fill_range outputs satisfy it).
        ranges (list[tuple[int, int]]): The planned half-open ranges.
        fmt (str): One of :data:`EXPORT_FORMATS`.
        bytes_per_line (int): S19 record width, forwarded to the shipped
            emitter (16 or 32 per LLR-015.1).

    Returns:
        Union[str, bytes]: S19/HEX text, or the flat BIN bytes.

    Raises:
        ValueError: An unknown format.

    Dependencies:
        Uses:
            - emit_s19_from_mem_map / emit_intel_hex_from_mem_map (shipped)
            - emit_bin_from_mem_map (LLR-137.2)
        Used by:
            - the Split / Join / Export screen's export action
            - tests/test_segment_ops.py (TC-684/TC-685)
    """
    if fmt == "s19":
        return emit_s19_from_mem_map(
            mem_map, ranges, bytes_per_line=bytes_per_line
        )
    if fmt == "hex":
        return emit_intel_hex_from_mem_map(mem_map, ranges)
    if fmt == "bin":
        return emit_bin_from_mem_map(mem_map, ranges)
    raise ValueError(
        f"fmt must be one of {list(EXPORT_FORMATS)}, got {fmt!r}"
    )
