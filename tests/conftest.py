"""
Summary:
    Shared pytest fixtures and generator utilities that manufacture large, realistic
    S19, A2L, and MAC files for stress-loading the TUI end-to-end. The generators are
    also re-used by ``tests/generate_large_samples.py`` so developers can produce the
    same inputs outside pytest for manual TUI stress testing.

Dependencies:
    Used by:
        - Stress-load perf tests in ``tests/test_tui_app.py``
        - Developer entry-point ``tests/generate_large_samples.py``
"""

from __future__ import annotations

import random
from pathlib import Path
from typing import TYPE_CHECKING, Optional

import pytest

if TYPE_CHECKING:
    from s19_app.tui.changes import ChangeDocument
    from s19_app.tui.models import LoadedFile


# ---------------------------------------------------------------------------
# S19 generator
# ---------------------------------------------------------------------------


def _s19_checksum(byte_count: int, address: int, data: bytes, address_bytes: int) -> int:
    """Compute the S-record checksum (ones-complement of the byte sum)."""
    total = byte_count
    for shift in range(address_bytes):
        total += (address >> (8 * shift)) & 0xFF
    for value in data:
        total += value
    return (~total) & 0xFF


def _s19_data_record(address: int, data: bytes) -> str:
    """Format one S3 (32-bit address) data record."""
    address_bytes = 4
    byte_count = address_bytes + len(data) + 1  # address + data + checksum
    checksum = _s19_checksum(byte_count, address, data, address_bytes)
    return (
        f"S3{byte_count:02X}{address:08X}"
        + data.hex().upper()
        + f"{checksum:02X}"
    )


def _s19_header_record() -> str:
    """Emit an S0 header record carrying an arbitrary ASCII name."""
    header_bytes = b"STRESS"
    byte_count = 2 + len(header_bytes) + 1
    checksum = _s19_checksum(byte_count, 0, header_bytes, 2)
    return f"S0{byte_count:02X}0000{header_bytes.hex().upper()}{checksum:02X}"


def _s19_terminator() -> str:
    """Emit an S7 termination record (32-bit start address)."""
    address_bytes = 4
    byte_count = address_bytes + 1
    checksum = _s19_checksum(byte_count, 0, b"", address_bytes)
    return f"S7{byte_count:02X}{0:08X}{checksum:02X}"


def make_large_s19(
    path: Path,
    *,
    num_ranges: int = 200,
    bytes_per_range: int = 4096,
    base_address: int = 0x0800_0000,
    gap_bytes: int = 0x100,
    seed: int = 0,
) -> Path:
    """
    Summary:
        Write a deterministic, valid S19 file with ``num_ranges`` non-overlapping data
        ranges so the TUI must parse an S3-heavy image comparable to the user's >10 MB
        production workload.

    Args:
        path (Path): Output file path (overwritten if exists).
        num_ranges (int): Number of disjoint address ranges.
        bytes_per_range (int): Size of each range; must be a multiple of 16.
        base_address (int): Starting address of the first range.
        gap_bytes (int): Unused address gap between ranges; keeps ranges distinct.
        seed (int): Deterministic PRNG seed for data bytes.

    Returns:
        Path: The written file path.

    Data Flow:
        - Emit one S0 header.
        - For each range, walk 16 bytes at a time and emit one S3 record per chunk.
        - Emit one S7 terminator.

    Dependencies:
        Uses:
            - ``_s19_data_record`` / ``_s19_header_record`` / ``_s19_terminator``
        Used by:
            - ``large_s19`` fixture
            - ``tests/generate_large_samples.py`` CLI
    """
    if bytes_per_range % 16 != 0:
        raise ValueError("bytes_per_range must be a multiple of 16")
    rng = random.Random(seed)
    chunk_size = 16
    with path.open("w", encoding="ascii", newline="\n") as handle:
        handle.write(_s19_header_record() + "\n")
        current_base = base_address
        for _ in range(num_ranges):
            for offset in range(0, bytes_per_range, chunk_size):
                data = bytes(rng.randrange(0, 256) for _ in range(chunk_size))
                handle.write(_s19_data_record(current_base + offset, data) + "\n")
            current_base += bytes_per_range + gap_bytes
        handle.write(_s19_terminator() + "\n")
    return path


# ---------------------------------------------------------------------------
# A2L generator
# ---------------------------------------------------------------------------


def _a2l_measurement_block(name: str, address: int) -> str:
    return (
        f"    /begin MEASUREMENT {name}\n"
        f"      ECU_ADDRESS 0x{address:08X}\n"
        f"      DATA_SIZE 2\n"
        f"      LOWER_LIMIT 0\n"
        f"      UPPER_LIMIT 65535\n"
        f"      UNIT unit\n"
        f"      READ_ONLY\n"
        f"    /end MEASUREMENT\n"
    )


def _a2l_characteristic_block(name: str, address: int) -> str:
    return (
        f"    /begin CHARACTERISTIC {name}\n"
        f"      ECU_ADDRESS 0x{address:08X}\n"
        f"      LENGTH 4\n"
        f"      BYTE_ORDER LITTLE_ENDIAN\n"
        f"      FUNCTION FG\n"
        f"      CALIBRATABLE\n"
        f"    /end CHARACTERISTIC\n"
    )


def make_large_a2l(
    path: Path,
    *,
    num_measurements: int = 5000,
    num_characteristics: int = 1000,
    base_address: int = 0x0800_0000,
    in_memory_fraction: float = 0.7,
    memory_span_bytes: int = 200 * 4096,
    seed: int = 0,
) -> Path:
    """
    Summary:
        Write a minimally valid A2L file with a single MODULE, one MEMORY_SEGMENT,
        and the requested number of MEASUREMENT/CHARACTERISTIC blocks. Addresses are
        chosen so that ``in_memory_fraction`` of tags fall within the span covered
        by ``make_large_s19`` defaults and the rest land outside (out-of-range path).

    Args:
        path (Path): Output file path.
        num_measurements (int): Number of MEASUREMENT blocks.
        num_characteristics (int): Number of CHARACTERISTIC blocks.
        base_address (int): Start of the in-memory address span.
        in_memory_fraction (float): 0.0-1.0 ratio of tags that land in-image.
        memory_span_bytes (int): Size of the covered address span.
        seed (int): Deterministic PRNG seed for address jitter.

    Returns:
        Path: The written file path.

    Data Flow:
        - Walk the requested tag count, deterministically alternating in/out-of-memory.
        - Emit an ASAP2_VERSION header, PROJECT > MODULE > MOD_COMMON > MEMORY_SEGMENT.
        - Stream tag blocks one line at a time to avoid holding the whole file in RAM.

    Dependencies:
        Uses:
            - ``_a2l_measurement_block`` / ``_a2l_characteristic_block``
        Used by:
            - ``large_a2l`` fixture
            - ``tests/generate_large_samples.py``
    """
    rng = random.Random(seed)
    out_of_band_base = base_address + memory_span_bytes + 0x1000
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(
            "ASAP2_VERSION 1 71\n"
            "/begin PROJECT StressProject\n"
            "  /begin MODULE StressModule\n"
            "    /begin MOD_COMMON StressMod\n"
            "      BYTE_ORDER MSB_LAST\n"
            "      ALIGNMENT_BYTE 1\n"
            "    /end MOD_COMMON\n"
            f"    /begin MEMORY_SEGMENT main FLASH INTERN_FLASH EXTERN 0x{base_address:08X} 0x{memory_span_bytes:08X}\n"
            "    /end MEMORY_SEGMENT\n"
        )
        for i in range(num_measurements):
            if rng.random() < in_memory_fraction:
                address = base_address + (i * 4) % max(1, memory_span_bytes - 4)
            else:
                address = out_of_band_base + (i * 4)
            handle.write(_a2l_measurement_block(f"MEAS_{i:06d}", address))
        for i in range(num_characteristics):
            if rng.random() < in_memory_fraction:
                address = base_address + 2 + (i * 4) % max(1, memory_span_bytes - 8)
            else:
                address = out_of_band_base + 0x10000 + (i * 4)
            handle.write(_a2l_characteristic_block(f"CHAR_{i:06d}", address))
        handle.write("  /end MODULE\n/end PROJECT\n")
    return path


# ---------------------------------------------------------------------------
# MAC generator
# ---------------------------------------------------------------------------


def make_large_mac(
    path: Path,
    *,
    num_records: int = 32000,
    num_diagnostics: int = 13000,
    base_address: int = 0x0800_0000,
    memory_span_bytes: int = 200 * 4096,
    a2l_hit_ratio: float = 0.5,
    num_a2l_tags: int = 5000,
    seed: int = 0,
) -> Path:
    """
    Summary:
        Write a synthetic ``.mac`` file with ``num_records`` address records plus
        ``num_diagnostics`` intentionally malformed lines so the validation panel is
        exercised at production scale.

    Args:
        path (Path): Output file path.
        num_records (int): Number of TAG=hex lines to emit in total.
        num_diagnostics (int): Fraction of records replaced with malformed lines.
            Must be <= num_records.
        base_address (int): Start of the in-image address span.
        memory_span_bytes (int): Size of the in-image span for address mod.
        a2l_hit_ratio (float): 0.0-1.0 ratio of records whose names mirror A2L tags.
        num_a2l_tags (int): Expected measurement count in the companion A2L (used to
            build matching names for the hit fraction).
        seed (int): Deterministic PRNG seed.

    Returns:
        Path: The written file path.

    Data Flow:
        - Decide per-line whether to emit a valid record, an A2L-named record, or a
          diagnostic line (missing ``=`` or invalid hex).
        - Write one line at a time so the file size is bounded only by params.

    Dependencies:
        Used by:
            - ``large_mac`` fixture
            - ``tests/generate_large_samples.py`` CLI
    """
    if num_diagnostics > num_records:
        raise ValueError("num_diagnostics must be <= num_records")
    rng = random.Random(seed)
    diag_positions = set(rng.sample(range(num_records), k=num_diagnostics)) if num_diagnostics else set()
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("# Stress-generated MAC fixture\n")
        for i in range(num_records):
            if i in diag_positions:
                if i % 2 == 0:
                    handle.write(f"BAD_LINE_NO_EQUALS_{i}\n")
                else:
                    handle.write(f"BADHEX_{i}=not_hex_value\n")
                continue
            if rng.random() < a2l_hit_ratio and num_a2l_tags > 0:
                name = f"MEAS_{(i % num_a2l_tags):06d}"
                address = base_address + (i * 4) % max(1, memory_span_bytes - 4)
            else:
                name = f"MAC_TAG_{i:06d}"
                address = base_address + (i * 8) % max(1, memory_span_bytes - 4)
            handle.write(f"{name}=0x{address:08X}\n")
    return path


# ---------------------------------------------------------------------------
# Pytest fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def large_s19(tmp_path: Path) -> Path:
    """
    Summary:
        Write a small-but-representative S19 (200 ranges x 4 KB) to a temporary path
        so unit tests can exercise the real parser without multi-second I/O costs.
    """
    return make_large_s19(tmp_path / "stress.s19")


@pytest.fixture
def large_a2l(tmp_path: Path) -> Path:
    """Summary: Write a default-sized synthetic A2L fixture."""
    return make_large_a2l(tmp_path / "stress.a2l")


@pytest.fixture
def large_mac(tmp_path: Path) -> Path:
    """Summary: Write a default-sized synthetic MAC fixture."""
    return make_large_mac(tmp_path / "stress.mac")


@pytest.fixture
def large_project(tmp_path: Path) -> dict[str, Path]:
    """
    Summary:
        Produce S19, A2L, and MAC fixtures that share address conventions so
        coexistence and cross-artifact validation exercise realistic code paths.

    Returns:
        dict[str, Path]: ``{"s19": path, "a2l": path, "mac": path}``.
    """
    s19 = make_large_s19(tmp_path / "stress.s19")
    a2l = make_large_a2l(tmp_path / "stress.a2l")
    mac = make_large_mac(tmp_path / "stress.mac")
    return {"s19": s19, "a2l": a2l, "mac": mac}


# ---------------------------------------------------------------------------
# Cross-file incompatibility builders (LLR-007.2)
#
# Each builder produces the smallest deterministic input that triggers exactly
# one cross-file class not covered by ``large_project``. They follow the same
# style as ``make_large_s19/a2l/mac``: ``seed: int = 0`` default, programmatic
# content (no static fixture files on disk), and the same checksum/format
# helpers. These are intentionally tiny — the goal is "smallest input that
# triggers exactly one class", not stress.
# ---------------------------------------------------------------------------


def _intel_hex_data_record(address: int, data: bytes) -> str:
    """Format one Intel HEX type-00 (data) record with the trailing checksum."""
    byte_count = len(data)
    record_type = 0x00
    total = byte_count + ((address >> 8) & 0xFF) + (address & 0xFF) + record_type
    for value in data:
        total += value
    checksum = (-total) & 0xFF
    return (
        f":{byte_count:02X}{address:04X}{record_type:02X}"
        + data.hex().upper()
        + f"{checksum:02X}"
    )


def _intel_hex_eof_record() -> str:
    """Format the Intel HEX type-01 end-of-file record."""
    return ":00000001FF"


def make_overlap_s19_hex(
    tmp_path: Path,
    *,
    seed: int = 0,
) -> dict[str, Path]:
    """
    Summary:
        Build a tiny S19 file and a tiny Intel HEX file whose data ranges
        overlap on the same low-address window. The two artefacts disagree on
        the byte values written to the shared addresses, which is the
        S19/HEX overlap class (TC-062.a).

    Args:
        tmp_path (Path): Directory to write into (typically the pytest fixture).
        seed (int): Deterministic PRNG seed for the data bytes.

    Returns:
        dict[str, Path]: ``{"s19": path, "hex": path}``.

    Data Flow:
        - Emit one S19 S0 header, one S3 data record at 0x00001000, and an S7 terminator.
        - Emit one Intel HEX :10 data record at the same 0x1000 with different bytes,
          followed by the EOF marker.

    Dependencies:
        Uses:
            - ``_s19_data_record`` / ``_s19_header_record`` / ``_s19_terminator``
            - ``_intel_hex_data_record`` / ``_intel_hex_eof_record``
        Used by:
            - ``overlap_s19_hex`` fixture
    """
    rng = random.Random(seed)
    s19_path = tmp_path / "overlap.s19"
    hex_path = tmp_path / "overlap.hex"
    address = 0x0000_1000
    s19_bytes = bytes(rng.randrange(0, 256) for _ in range(16))
    hex_bytes = bytes(rng.randrange(0, 256) for _ in range(16))
    with s19_path.open("w", encoding="ascii", newline="\n") as handle:
        handle.write(_s19_header_record() + "\n")
        handle.write(_s19_data_record(address, s19_bytes) + "\n")
        handle.write(_s19_terminator() + "\n")
    with hex_path.open("w", encoding="ascii", newline="\n") as handle:
        handle.write(_intel_hex_data_record(address, hex_bytes) + "\n")
        handle.write(_intel_hex_eof_record() + "\n")
    return {"s19": s19_path, "hex": hex_path}


def make_duplicate_alias_mac(
    tmp_path: Path,
    *,
    seed: int = 0,
) -> Path:
    """
    Summary:
        Build a tiny MAC file with two distinct symbol names mapped to the
        same hex address (the duplicate-address alias class, TC-062.g).
        Under the default ``warn`` alias policy the validation engine emits a
        ``MAC_DUPLICATE_ADDRESS`` issue at WARNING severity.

    Args:
        tmp_path (Path): Directory to write into.
        seed (int): Reserved for parity with the other builders; the file
            content is fixed (deterministic regardless of seed) because
            duplicate-alias requires exact-address collision.

    Returns:
        Path: The written MAC file path.

    Dependencies:
        Used by:
            - ``duplicate_alias_mac`` fixture
    """
    del seed  # deterministic content; parameter retained for builder-style parity
    path = tmp_path / "dup_alias.mac"
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("# Duplicate-address alias fixture\n")
        handle.write("ALPHA=0x08000000\n")
        handle.write("BETA=0x08000000\n")
    return path


def make_corrupt_records(
    tmp_path: Path,
    *,
    seed: int = 0,
) -> dict[str, Path]:
    """
    Summary:
        Build small S19, A2L, and MAC files that each contain one intentionally
        corrupted record (parsed-record corruption class, TC-062.h):

        - S19: one valid S3 record plus a second record with a corrupted
          checksum byte. ``S19File`` collects the per-line error without
          aborting the load.
        - A2L: a malformed CHARACTERISTIC block missing its required
          ``ECU_ADDRESS`` line.
        - MAC: a line with invalid hex on the right-hand side.

    Args:
        tmp_path (Path): Directory to write into.
        seed (int): Deterministic PRNG seed for the valid S19 data bytes.

    Returns:
        dict[str, Path]: ``{"s19": path, "a2l": path, "mac": path}``.

    Dependencies:
        Uses:
            - ``_s19_data_record`` / ``_s19_header_record`` / ``_s19_terminator``
        Used by:
            - ``corrupt_records`` fixture
    """
    rng = random.Random(seed)
    s19_path = tmp_path / "corrupt.s19"
    a2l_path = tmp_path / "corrupt.a2l"
    mac_path = tmp_path / "corrupt.mac"

    valid_bytes = bytes(rng.randrange(0, 256) for _ in range(16))
    valid_record = _s19_data_record(0x0800_0000, valid_bytes)
    # Mutate the trailing checksum byte to force a checksum mismatch on the
    # second record while leaving every other field structurally valid.
    second_record = _s19_data_record(0x0800_0010, valid_bytes)
    bad_checksum = f"{(int(second_record[-2:], 16) ^ 0xFF):02X}"
    corrupted_record = second_record[:-2] + bad_checksum
    with s19_path.open("w", encoding="ascii", newline="\n") as handle:
        handle.write(_s19_header_record() + "\n")
        handle.write(valid_record + "\n")
        handle.write(corrupted_record + "\n")
        handle.write(_s19_terminator() + "\n")

    with a2l_path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(
            "ASAP2_VERSION 1 71\n"
            "/begin PROJECT CorruptProject\n"
            "  /begin MODULE CorruptModule\n"
            "    /begin CHARACTERISTIC BAD_CHAR\n"
            # ECU_ADDRESS deliberately omitted — required field missing.
            "      LENGTH 4\n"
            "      BYTE_ORDER LITTLE_ENDIAN\n"
            "    /end CHARACTERISTIC\n"
            "  /end MODULE\n"
            "/end PROJECT\n"
        )

    with mac_path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("# Corrupt-record fixture\n")
        handle.write("BADHEX=not_a_hex_value\n")

    return {"s19": s19_path, "a2l": a2l_path, "mac": mac_path}


@pytest.fixture
def overlap_s19_hex(tmp_path: Path) -> dict[str, Path]:
    """
    Summary:
        Pair of S19 + Intel HEX files with overlapping data ranges (TC-062.a).
    """
    return make_overlap_s19_hex(tmp_path)


@pytest.fixture
def duplicate_alias_mac(tmp_path: Path) -> Path:
    """
    Summary:
        MAC file containing two symbol names mapped to the same hex address (TC-062.g).
    """
    return make_duplicate_alias_mac(tmp_path)


@pytest.fixture
def corrupt_records(tmp_path: Path) -> dict[str, Path]:
    """
    Summary:
        Trio of S19/A2L/MAC fixtures with one intentionally corrupted record each (TC-062.h).
    """
    return make_corrupt_records(tmp_path)


# ---------------------------------------------------------------------------
# Memory-change factory (batch-04, increments 1 + 2; evolved to the v2
# ``changes`` model at batch-07 E3b)
#
# Per requirements §5.4, ``memory_change_factory`` is the in-memory builder
# for the memory-change tests. Batch-04 built a ``MemoryChangeList``; the v2
# hex-first change system (batch-07) replaced that collection with
# ``ChangeDocument`` + ``ChangeEntry`` — the factory now returns a v2
# ``ChangeDocument`` holding ``"bytes"``-kind entries at the same pinned
# addresses, so the surviving assertions keep their exact values.
#
# The pinned addresses are chosen relative to the ``make_ranged_s19`` ranges
# below so the increment-2 validator lands the ``inside`` / ``partial`` /
# ``outside`` / gap-spanning verdicts deterministically.
#
#   make_ranged_s19 ranges (half-open):
#     range 1  [0x100, 0x180)   128 bytes
#     gap      [0x180, 0x200)   no image data
#     range 2  [0x200, 0x280)   128 bytes
#     post-last addresses are >= 0x280.
# ---------------------------------------------------------------------------


# The two disjoint, gap-separated ranges ``make_ranged_s19`` writes. Module
# level so a test can assert verdicts against the exact same boundaries the
# fixture produced.
RANGED_S19_RANGES: tuple[tuple[int, int], tuple[int, int]] = (
    (0x100, 0x180),  # range 1 — 128 bytes
    (0x200, 0x280),  # range 2 — 128 bytes; gap [0x180, 0x200) between them
)


# The overlap pair (requirements §5.4, finding Q-03) — two entries built at
# DISTINCT start addresses whose byte runs intersect: ranges [0x100, 0x108) and
# [0x104, 0x10C) overlap on [0x104, 0x108). Distinct ``address`` keys mean the
# LLR-001.3 identity rule does not collapse them, so the overlap warning is
# genuinely provoked in increment 2's TC-008.
MEMORY_OVERLAP_PAIR: tuple[tuple[int, int], tuple[int, int]] = (
    (0x100, 8),  # (address, run length)
    (0x104, 8),
)


def memory_change_factory(variant: str = "base") -> "ChangeDocument":
    """
    Summary:
        Build a v2 ``ChangeDocument`` of well-formed ``"bytes"``-kind entries
        for reuse across the memory-change model, validation and service
        tests. The ``variant`` argument selects which range-coupled outcome
        the document is shaped for, all against the
        :data:`RANGED_S19_RANGES` / ``make_ranged_s19`` ranges.

    Args:
        variant (str): Which document to build. One of:
            - ``"base"`` (default) — an ``inside``-sized entry plus the
              pinned overlap pair. Entry addresses ``[0x200, 0x100, 0x104]``.
              Under the v2 model the overlap pair is an intra-document
              collision (``CHG-COLLISION`` ERROR when validated, LLR-001.5).
            - ``"partial"`` — one entry ``0x178 len 0x10`` whose run starts
              inside range 1 and crosses its ``0x180`` end edge (``partial``).
            - ``"outside"`` — one entry ``0x190 len 8`` whose run falls wholly
              in the inter-range gap ``[0x180, 0x200)`` (``outside``).
            - ``"gap-spanning"`` — one entry ``0x170 len 0x100`` whose run
              starts in range 1, crosses the gap, and ends in range 2 — the
              single-``partial`` multi-range case.

    Returns:
        ChangeDocument: A valid ``kind="change"`` v2 envelope whose entries
        are in deterministic insertion order. Every entry carries the default
        ``UNVALIDATED_NO_IMAGE`` status; ``classify_containment`` stamps the
        real status against a loaded image.

    Data Flow:
        - Constructs an empty v2 envelope and appends ``ChangeEntry``
          instances in a fixed order so dependent tests can assert on that
          order.
        - The ``"base"`` overlap-pair entries sit at distinct addresses with
          intersecting runs — the v2 collision rule flags both.

    Dependencies:
        Uses:
            - ChangeDocument / ChangeEntry
        Used by:
            - TC-001..TC-008 (``test_memory_changelist.py`` /
              ``test_memory_validate.py``); the unified-file v2 rewrites.

    Example:
        >>> [e.address for e in memory_change_factory().entries]
        [512, 256, 260]
        >>> [e.address for e in memory_change_factory("partial").entries]
        [376]
    """
    from s19_app.tui.changes import ChangeDocument, ChangeEntry
    from s19_app.tui.changes.io import FORMAT_ID, FORMAT_VERSION

    document = ChangeDocument(
        format=FORMAT_ID,
        version=FORMAT_VERSION,
        kind="change",
        encoding="utf-8",
        value_mode="text",
    )

    def _add(address: int, run: list[int]) -> None:
        document.entries.append(ChangeEntry("bytes", address, tuple(run)))

    if variant == "base":
        # An entry sized to fall fully inside loaded range 2 (`inside`).
        _add(0x200, [0xDE, 0xAD, 0xBE, 0xEF])
        # The pinned overlap pair — distinct start addresses, intersecting runs.
        for address, run_length in MEMORY_OVERLAP_PAIR:
            _add(
                address,
                [(address + offset) & 0xFF for offset in range(run_length)],
            )
        return document
    if variant == "partial":
        # Starts inside range 1, runs past its 0x180 end edge.
        _add(0x178, [(0x178 + offset) & 0xFF for offset in range(0x10)])
        return document
    if variant == "outside":
        # Falls wholly in the inter-range gap [0x180, 0x200).
        _add(0x190, [(0x190 + offset) & 0xFF for offset in range(8)])
        return document
    if variant == "gap-spanning":
        # Starts in range 1, crosses the gap, ends in range 2 — one `partial`.
        _add(0x170, [(0x170 + offset) & 0xFF for offset in range(0x100)])
        return document
    raise ValueError(f"unknown memory_change_factory variant: {variant!r}")


def make_ranged_s19(
    path: Path,
    *,
    seed: int = 0,
) -> Path:
    """
    Summary:
        Write a tiny synthetic S19 file with two known, disjoint,
        gap-separated 128-byte address ranges, so the batch-04 memory-change
        validator can be exercised against a real loaded image rather than a
        hand-built range stub. The exact ranges are :data:`RANGED_S19_RANGES`.

    Args:
        path (Path): Output file path (overwritten if it exists).
        seed (int): Deterministic PRNG seed for the data bytes.

    Returns:
        Path: The written file path.

    Data Flow:
        - For each of the two ranges in :data:`RANGED_S19_RANGES`, walk the
          range 16 bytes at a time and emit one S3 data record per chunk, so
          ``S19File`` coalesces each range into one contiguous ``(start, end)``
          range with the documented inter-range gap left empty.
        - Emit one S7 terminator. No S0 header record is written: an S0
          carries a data payload at address 0, which would otherwise surface
          as a spurious third low ``(0, n)`` range; ``S19File`` parses a
          header-less file cleanly.

    Dependencies:
        Uses:
            - ``_s19_data_record`` / ``_s19_terminator``
        Used by:
            - ``ranged_s19`` fixture; TC-005, TC-006, TC-008
              (``test_memory_validate.py``).
    """
    rng = random.Random(seed)
    chunk_size = 16
    with path.open("w", encoding="ascii", newline="\n") as handle:
        for range_start, range_end in RANGED_S19_RANGES:
            for address in range(range_start, range_end, chunk_size):
                data = bytes(rng.randrange(0, 256) for _ in range(chunk_size))
                handle.write(_s19_data_record(address, data) + "\n")
        handle.write(_s19_terminator() + "\n")
    return path


@pytest.fixture
def ranged_s19(tmp_path: Path) -> "LoadedFile":
    """
    Summary:
        Load a :func:`make_ranged_s19` image through the real ``load_service``
        so the memory-change validator consumes the actual ``LoadedFile.ranges``
        snapshot — two disjoint ranges with a documented gap (TC-005/006/008).

    Returns:
        LoadedFile: The loaded snapshot; ``ranges`` is ``RANGED_S19_RANGES``.
    """
    from s19_app.core import S19File
    from s19_app.tui.services.load_service import build_loaded_s19

    s19_path = make_ranged_s19(tmp_path / "ranged.s19")
    s19 = S19File(str(s19_path))
    return build_loaded_s19(s19_path, s19, a2l_path=None, a2l_data=None)


# ---------------------------------------------------------------------------
# v2 change-file helper (batch-07 E3b — evolves the batch-04
# ``make_unified_file``)
#
# ``make_change_file`` writes a well-formed v2 change-set JSON file to a real
# path, using the production serializer ``serialize_change_document`` so the
# file on disk is exactly what the writer emits — not a hand-built JSON
# literal that could silently drift from the format contract.
# ---------------------------------------------------------------------------


def change_document_factory(variant: str = "clean") -> "ChangeDocument":
    """
    Summary:
        Build an in-memory v2 ``ChangeDocument`` for the write / round-trip
        tests.

    Args:
        variant (str): ``"clean"`` (default) builds a collision-free
            three-entry document — two ``"bytes"`` entries (the pinned
            ``DE AD BE EF`` run at 0x200 and a disjoint ``01 02`` run at
            0x110) plus one ``"string"`` entry (``"REV_C"`` at 0x300) — so
            both entry kinds ride every write test. Any
            :func:`memory_change_factory` variant name returns that
            factory's document instead.

    Returns:
        ChangeDocument: A valid ``kind="change"`` v2 envelope.

    Dependencies:
        Uses:
            - memory_change_factory
        Used by:
            - make_change_file; the TC-015/017/018 write tests
              (``test_unified_write.py``) and the round-trip tests
              (``test_unified_roundtrip.py``).
    """
    from s19_app.tui.changes import ChangeDocument, ChangeEntry
    from s19_app.tui.changes.io import FORMAT_ID, FORMAT_VERSION

    if variant != "clean":
        return memory_change_factory(variant)
    return ChangeDocument(
        format=FORMAT_ID,
        version=FORMAT_VERSION,
        kind="change",
        encoding="utf-8",
        value_mode="text",
        entries=[
            ChangeEntry("bytes", 0x200, (0xDE, 0xAD, 0xBE, 0xEF)),
            ChangeEntry("bytes", 0x110, (0x01, 0x02)),
            ChangeEntry(
                "string",
                0x300,
                tuple("REV_C".encode("utf-8")),
                value="REV_C",
            ),
        ],
    )


def make_change_file(
    path: Path,
    *,
    memory_variant: str = "clean",
) -> Path:
    """
    Summary:
        Write a well-formed v2 change-set JSON file to ``path`` using the
        production
        :func:`~s19_app.tui.changes.io.serialize_change_document` serializer,
        so the on-disk file is byte-identical to what the writer emits.

    Args:
        path (Path): Output file path (overwritten if it exists). The file is
            written directly with the serializer bytes — no work-area
            containment is applied here; this helper is for *read*-side tests
            that need a real, well-formed v2 file on disk.
        memory_variant (str): ``"clean"`` (default) writes a collision-free
            three-entry document (two ``"bytes"`` entries — the pinned
            ``DE AD BE EF`` run at 0x200 and a disjoint run at 0x110 — plus
            one ``"string"`` entry at 0x300), so a read collects **zero**
            issues. Any :func:`memory_change_factory` variant name writes
            that factory's document instead (note: ``"base"`` carries the
            overlap pair, so a read collects two ``CHG-COLLISION`` errors).

    Returns:
        Path: The written file path — a valid v2 ``s19app-changeset``
        document, addresses in the canonical ``"0x..."`` string form.

    Data Flow:
        - Build the ``ChangeDocument`` via :func:`change_document_factory`.
        - Serialize it with the production ``serialize_change_document`` and
          write the bytes to ``path``.

    Dependencies:
        Uses:
            - change_document_factory
            - serialize_change_document
        Used by:
            - The v2 unified-file read / round-trip rewrites
              (``test_unified_read.py`` / ``test_unified_roundtrip.py``).

    Example:
        >>> p = make_change_file(tmp_path / "cs.json")  # doctest: +SKIP
    """
    from s19_app.tui.changes.io import serialize_change_document

    document = change_document_factory(memory_variant)
    path.write_bytes(serialize_change_document(document))
    return path


# ---------------------------------------------------------------------------
# Change-file READ fixtures (batch-04, increment 6; re-pointed to the v2
# reader at batch-07 E3b)
#
# Per requirements §5.4, these helpers manufacture the adversarial files the
# read TCs feed to ``read_change_document``: malformed JSON and deeply-nested
# JSON (the RecursionError arm). Every file is synthetic and built in-test
# (constraint C-9). The fixtures write *crafted* JSON literals — not the
# production serializer — precisely because they must produce shapes the
# writer would never emit.
# ---------------------------------------------------------------------------


def make_malformed_unified_file(path: Path, *, variant: str = "truncated") -> Path:
    """
    Summary:
        Write a change-file path whose content is **not** a well-formed v2
        change-set document, for the ``MF-JSON-PARSE`` /
        ``MF-BAD-STRUCTURE`` read TCs (TC-020, TC-014).

    Args:
        path (Path): Output file path (overwritten if it exists).
        variant (str): Which malformed content to write. One of:
            - ``"truncated"`` (default) — a syntactically truncated JSON object
              (``{"format": "s19app-changeset", "entr``) — provokes a
              ``json.JSONDecodeError`` → ``MF-JSON-PARSE``.
            - ``"garbage"`` — non-JSON bytes (``not json at all {{{``) →
              ``MF-JSON-PARSE``.
            - ``"bare-list"`` — a well-formed JSON ``[]`` (non-object top
              level) → ``MF-BAD-STRUCTURE``.
            - ``"bare-int"`` — a well-formed JSON ``42`` → ``MF-BAD-STRUCTURE``.
            - ``"bare-string"`` — a well-formed JSON string → ``MF-BAD-STRUCTURE``.
            - ``"no-envelope"`` — a well-formed JSON object ``{"foo": 1}``
              with none of the five v2 metadata fields → the faulted-envelope
              outcome (one ERROR per missing field, zero entries — F-A-16).

    Returns:
        Path: The written file path.

    Data Flow:
        - Maps ``variant`` to a fixed byte payload and writes it verbatim.

    Dependencies:
        Used by:
            - TC-020 (``test_unified_rules.py``), TC-014 (``test_unified_read.py``).

    Example:
        >>> p = make_malformed_unified_file(tmp_path / "bad.json")  # doctest: +SKIP
    """
    payloads: dict[str, bytes] = {
        "truncated": b'{"format": "s19app-changeset", "entr',
        "garbage": b"not json at all {{{",
        "bare-list": b"[]",
        "bare-int": b"42",
        "bare-string": b'"just a string"',
        "no-envelope": b'{"foo": 1, "bar": 2}',
    }
    if variant not in payloads:
        raise ValueError(f"unknown make_malformed_unified_file variant: {variant!r}")
    path.write_bytes(payloads[variant])
    return path


def make_deeply_nested_unified_file(path: Path, *, depth: int = 120_000) -> Path:
    """
    Summary:
        Write a change-file path whose content is a JSON document nested deep
        enough to overflow the stdlib ``json`` parser's recursion and raise
        ``RecursionError`` — the TC-035 deeply-nested arm (v2: LLR-001.7's
        parse guard).

    Args:
        path (Path): Output file path (overwritten if it exists).
        depth (int): Nesting depth — the number of stacked JSON arrays. The
            default (120_000) is far past the stdlib parser's recursion limit
            on any platform, so the reader's ``RecursionError`` catch is
            genuinely exercised. The file itself stays tiny (a few hundred KB).

    Returns:
        Path: The written file path. The content is ``[[[...]]]`` — ``depth``
        open brackets, then ``depth`` close brackets — well-formed JSON that
        the stdlib parser cannot decode without overflowing its recursion.

    Data Flow:
        - Writes ``depth`` ``[`` characters, then ``depth`` ``]`` characters.

    Dependencies:
        Used by:
            - TC-035 (``test_unified_read.py``).

    Example:
        >>> p = make_deeply_nested_unified_file(tmp_path / "deep.json")  # doctest: +SKIP
    """
    path.write_bytes(b"[" * depth + b"]" * depth)
    return path


# ---------------------------------------------------------------------------
# Batch-35 canonical report bytes (shared on third use — reviewer carry)
# ---------------------------------------------------------------------------

#: Placeholder replacing every spelling of the per-run pytest tmp root
#: inside canonical report bytes (LLR-054.4/055.3 canonical form).
RUN_ROOT_TOKEN = b"<RUN-ROOT>"

#: A run-root path span: the token plus its path remainder, stopping at the
#: delimiters the reports place around paths (whitespace, backtick, quote,
#: pipe, closing paren/bracket) — separator normalization applies ONLY
#: inside these spans, never to report content.
_RUN_ROOT_SPAN_RE = None  # compiled lazily so ``re`` stays a local import


def canonical_report_bytes(raw: bytes, run_root: Optional[Path] = None) -> bytes:
    """
    Summary:
        Map report bytes to the canonical form of the LLR-054.4/055.3
        byte-identity pin: platform newline translation undone (CRLF -> LF),
        every spelling of the per-run pytest tmp root replaced by
        ``<RUN-ROOT>``, and path separators normalized to ``/`` ONLY inside
        run-root path spans — content bytes are never rewritten. Shared
        home for the helper duplicated as ``_canonical_report_bytes`` in
        ``tests/test_before_after_report.py`` and
        ``tests/test_tui_report_seam.py`` (factored here on its THIRD use,
        per the Inc-2 reviewer recommendation; the two originals stay
        untouched to keep those increments' diffs closed).

    Args:
        raw (bytes): Report bytes as read from disk (a freshly written
            report, or a stored golden).
        run_root (Optional[Path]): The per-run root whose spellings are
            tokenized; ``None`` for stored goldens (already tokenized at
            capture time — only the CRLF undo applies).

    Returns:
        bytes: The canonical byte form compared by the byte-identity ATs.

    Data Flow:
        - written report bytes + per-run root -> canonical bytes; equality
          of two canonical forms IS the byte-identity gate.

    Dependencies:
        Uses:
            - RUN_ROOT_TOKEN
        Used by:
            - tests/test_tui_report_filter_surface.py (AT-056c/AT-056e)

    Example:
        >>> canonical_report_bytes(b"a\r\nb") == b"a\nb"
        True
    """
    import re

    global _RUN_ROOT_SPAN_RE
    if _RUN_ROOT_SPAN_RE is None:
        _RUN_ROOT_SPAN_RE = re.compile(rb"<RUN-ROOT>[^\s`\"'|)\]]*")
    data = raw.replace(b"\r\n", b"\n")
    if run_root is not None:
        forms = {str(run_root), str(run_root.resolve())}
        for form in sorted(forms, key=len, reverse=True):
            data = data.replace(form.encode("utf-8"), RUN_ROOT_TOKEN)
    return _RUN_ROOT_SPAN_RE.sub(
        lambda match: match.group(0).replace(b"\\", b"/"), data
    )
