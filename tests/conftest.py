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
from typing import TYPE_CHECKING, Any, Optional

import pytest

if TYPE_CHECKING:
    from s19_app.tui.cdfx import ChangeList, MemoryChangeList, UnifiedChangeSet
    from s19_app.tui.cdfx.resolve import ResolutionResult
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
# CDFX change-list factory (batch-03, increment 10)
#
# Relocated here from ``tests/test_cdfx_changelist.py`` (deferred to increment
# 10 by the increment plan §A.4 / increment-005 packet) so the writer /
# round-trip CDFX test modules share one fixture builder. ``change_list_factory``
# now also carries the **adversarial-float arm** — three IEEE binary64 values
# (``0.1``, the denormal ``5e-324``, a 17-significant-digit value) that no lossy
# ``str()`` / ``%g`` / fixed-width text representation can round-trip, so the
# round-trip test TC-024 genuinely fails if the writer ever drops full
# ``repr()`` precision (LLR-004.8).
# ---------------------------------------------------------------------------


# The three adversarial IEEE binary64 floats (requirements §5.5). Module-level
# so a test can assert the round-tripped value against the exact same object.
ADVERSARIAL_FLOATS: tuple[float, float, float] = (
    0.1,            # no short exact decimal — naive formatting loses precision.
    5e-324,         # smallest positive binary64 denormal — fixed-width → 0.0.
    8.98846567431158e307,  # a 17-significant-digit value — %g drops the tail.
)


def change_list_factory() -> "ChangeList":
    """
    Summary:
        Build a small change-list of resolved parameters — one scalar, one
        1-D array, one ASCII string, plus a 1-D array of the three adversarial
        IEEE floats — for reuse across the CDFX writer / round-trip tests.

    Returns:
        ChangeList: A change-list with, in insertion order:
            - ``IGN_ADVANCE_BASE`` — scalar, ``array_index=None``, value ``23``.
            - ``FUEL_TRIM_TABLE[0..2]`` — three array elements carrying integer
              indices 0/1/2, values 23/24/25.
            - ``CAL_LABEL`` — ASCII string, ``array_index=None``, value
              ``"REV_C"``.
            - ``FLOAT_ADV_BLOCK[0..2]`` — three array elements carrying the
              three :data:`ADVERSARIAL_FLOATS` (``0.1``, the denormal
              ``5e-324``, a 17-digit value).
        Every entry has status ``RESOLVED``.

    Data Flow:
        - Constructs an empty ``ChangeList`` and appends the entries in a fixed
          order so dependent tests can assert on that order. A scalar / string
          parameter carries ``array_index=None`` (LLR-001.1); an array
          parameter contributes one per-element ``(name, k)`` entry. The
          adversarial floats are carried as an array group so the round-trip
          exercises both the float-precision (LLR-004.8) and the coalesce →
          expand (LLR-004.9 / LLR-005.6) paths on the same entries.

    Dependencies:
        Uses:
            - ChangeList
        Used by:
            - TC-003 / TC-010 (``test_cdfx_changelist.py``); TC-024
              (``test_cdfx_roundtrip.py``).
    """
    from s19_app.tui.cdfx import ChangeList, ResolutionStatus

    cl = ChangeList()
    cl.add("IGN_ADVANCE_BASE", None, 23, ResolutionStatus.RESOLVED)
    cl.add("FUEL_TRIM_TABLE", 0, 23, ResolutionStatus.RESOLVED)
    cl.add("FUEL_TRIM_TABLE", 1, 24, ResolutionStatus.RESOLVED)
    cl.add("FUEL_TRIM_TABLE", 2, 25, ResolutionStatus.RESOLVED)
    cl.add("CAL_LABEL", None, "REV_C", ResolutionStatus.RESOLVED)
    for index, value in enumerate(ADVERSARIAL_FLOATS):
        cl.add("FLOAT_ADV_BLOCK", index, value, ResolutionStatus.RESOLVED)
    return cl


def change_list_resolution(change_list: "ChangeList") -> "ResolutionResult":
    """
    Summary:
        Build the ``ResolutionResult`` matching :func:`change_list_factory` so a
        write test can call ``write_cdfx`` without running the A2L pipeline.

    Args:
        change_list (ChangeList): A change-list — normally the one returned by
            :func:`change_list_factory`. Each entry's ``ResolvedType`` is keyed
            into the result by entry identity.

    Returns:
        ResolutionResult: A result whose ``resolved_types`` map carries, per
        entry identity, the ``ResolvedType`` the resolver (increment 2) would
        produce for that parameter — ``VALUE`` for a scalar integer, ``ASCII``
        for the string entry, ``VAL_BLK`` for the two array groups.

    Data Flow:
        - For each entry, pick the ``ResolvedType`` from the parameter name: an
          integer-valued scalar → ``VALUE``/``UWORD``; the ASCII string →
          ``ASCII``; an integer-``array_index`` entry → ``VAL_BLK``, with
          ``element_count`` the size of that parameter's array group. This is
          the exact shape ``write_cdfx`` reads via ``ResolutionResult.type_for``.

    Dependencies:
        Uses:
            - ResolutionResult
            - ResolvedType
        Used by:
            - TC-024 (``test_cdfx_roundtrip.py``).
    """
    from s19_app.tui.cdfx.resolve import ResolutionResult, ResolvedType

    # Per-parameter array-group sizes, so a VAL_BLK ResolvedType reports the
    # element_count the writer's coalescing produces a VG of.
    array_counts: dict[str, int] = {}
    for entry in change_list.entries:
        if isinstance(entry.array_index, int):
            array_counts[entry.parameter_name] = (
                array_counts.get(entry.parameter_name, 0) + 1
            )

    result = ResolutionResult(change_list=change_list)
    for entry in change_list.entries:
        if isinstance(entry.array_index, int):
            resolved = ResolvedType(
                char_type="VAL_BLK",
                datatype="FLOAT64_IEEE"
                if isinstance(entry.value, float)
                else "UWORD",
                element_count=array_counts[entry.parameter_name],
            )
        elif isinstance(entry.value, str):
            resolved = ResolvedType(
                char_type="ASCII", datatype=None, element_count=8
            )
        else:
            resolved = ResolvedType(
                char_type="VALUE", datatype="UWORD", element_count=1
            )
        result.resolved_types[entry.key] = resolved
    return result


# ---------------------------------------------------------------------------
# Memory-change factory (batch-04, increments 1 + 2)
#
# Per requirements §5.4, ``memory_change_factory`` is the in-memory
# ``MemoryChangeList`` builder for the batch-04 memory-field tests. Increment 1
# shipped the **bare-list build path** — the address-keyed entries and the
# overlap pair — for TC-001..TC-004 and TC-008's ValueError arms. Increment 2
# adds the range-coupled ``partial`` / ``outside`` / gap-spanning variants and
# ``make_ranged_s19``, the real ``LoadedFile`` they are validated against.
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


def memory_change_factory(variant: str = "base") -> "MemoryChangeList":
    """
    Summary:
        Build a ``MemoryChangeList`` of well-formed memory-change entries for
        reuse across the batch-04 memory-field model, validation and container
        tests. The ``variant`` argument selects which range-coupled outcome the
        list is shaped for, all against the :data:`RANGED_S19_RANGES` /
        ``make_ranged_s19`` ranges.

    Args:
        variant (str): Which list to build. One of:
            - ``"base"`` (default) — the increment-1 bare-list build path: an
              ``inside``-sized entry plus the pinned overlap pair. Entry
              addresses ``[0x200, 0x100, 0x104]``.
            - ``"partial"`` — one entry ``0x178 len 0x10`` whose run starts
              inside range 1 and crosses its ``0x180`` end edge (``partial``).
            - ``"outside"`` — one entry ``0x190 len 8`` whose run falls wholly
              in the inter-range gap ``[0x180, 0x200)`` (``outside``).
            - ``"gap-spanning"`` — one entry ``0x170 len 0x100`` whose run
              starts in range 1, crosses the gap, and ends in range 2 — the
              single-``partial``, single-issue multi-range case (LLR-002.1).

    Returns:
        MemoryChangeList: A memory-change list in deterministic insertion
        order. Every entry carries the default ``UNVALIDATED_NO_IMAGE`` status;
        the increment-2 validator stamps the real status against a loaded
        image.

    Data Flow:
        - Constructs an empty ``MemoryChangeList`` and appends entries in a
          fixed order so dependent tests can assert on that order (LLR-001.4).
        - The ``"base"`` overlap-pair entries are added at distinct ``address``
          keys so the LLR-001.3 identity rule keeps them as two entries.

    Dependencies:
        Uses:
            - MemoryChangeList
        Used by:
            - TC-001..TC-008 (``test_memory_changelist.py`` /
              ``test_memory_validate.py``); the container tests of increment 4.

    Example:
        >>> [e.address for e in memory_change_factory().entries]
        [512, 256, 260]
        >>> [e.address for e in memory_change_factory("partial").entries]
        [376]
    """
    from s19_app.tui.cdfx import MemoryChangeList

    ml = MemoryChangeList()
    if variant == "base":
        # An entry sized to fall fully inside loaded range 2 (`inside`).
        ml.add(0x200, [0xDE, 0xAD, 0xBE, 0xEF])
        # The pinned overlap pair — distinct start addresses, intersecting runs.
        for address, run_length in MEMORY_OVERLAP_PAIR:
            ml.add(
                address,
                [(address + offset) & 0xFF for offset in range(run_length)],
            )
        return ml
    if variant == "partial":
        # Starts inside range 1, runs past its 0x180 end edge.
        ml.add(0x178, [(0x178 + offset) & 0xFF for offset in range(0x10)])
        return ml
    if variant == "outside":
        # Falls wholly in the inter-range gap [0x180, 0x200).
        ml.add(0x190, [(0x190 + offset) & 0xFF for offset in range(8)])
        return ml
    if variant == "gap-spanning":
        # Starts in range 1, crosses the gap, ends in range 2 — one `partial`.
        ml.add(0x170, [(0x170 + offset) & 0xFF for offset in range(0x100)])
        return ml
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
# Unified change-set factory (batch-04, increment 4)
#
# Per requirements §5.4, ``unified_changeset_factory`` is the in-memory
# ``UnifiedChangeSet`` builder for the batch-04 unified-change-set container,
# write, read, round-trip and export tests. It **composes** the two halves
# from the existing per-kind factories — it does not hand-build entries — so
# the unified tests inherit exactly the parameter and memory entries the
# batch-03 / increment-1 tests already exercise:
#
#   - the parameter half is ``change_list_factory()`` — one scalar, one 1-D
#     array, one ASCII string, plus the three adversarial IEEE binary64 floats
#     (the Q-09 note: the adversarial floats are inherited from
#     ``change_list_factory``, not re-declared here), so the round-trip test
#     TC-025 genuinely stresses full binary64 precision.
#   - the memory half is ``memory_change_factory(variant)`` — by default the
#     "base" bare-list build path (an inside-sized entry plus the pinned
#     overlap pair).
# ---------------------------------------------------------------------------


def unified_changeset_factory(memory_variant: str = "base") -> "UnifiedChangeSet":
    """
    Summary:
        Build a ``UnifiedChangeSet`` whose two halves are composed from the
        existing :func:`change_list_factory` and :func:`memory_change_factory`
        generators, for reuse across the batch-04 unified container, write,
        read, round-trip and export tests.

    Args:
        memory_variant (str): The ``memory_change_factory`` variant selecting
            which memory-field half to compose — ``"base"`` (default),
            ``"partial"``, ``"outside"`` or ``"gap-spanning"``.

    Returns:
        UnifiedChangeSet: A container whose ``parameters`` half is the
        :func:`change_list_factory` change-list (scalar + 1-D array + ASCII
        string + the three adversarial IEEE floats) and whose ``memory`` half
        is the :func:`memory_change_factory` list for ``memory_variant``. The
        two halves are populated by replaying each source factory's entries
        into the container's own halves, so the container's identity-keyed
        insertion order matches each source factory exactly.

    Data Flow:
        - Construct an empty ``UnifiedChangeSet``.
        - Replay every :func:`change_list_factory` entry into the container's
          ``parameters`` half via ``ChangeList.add`` (preserving identity,
          value, resolution status and insertion order).
        - Replay every :func:`memory_change_factory` entry into the container's
          ``memory`` half via ``MemoryChangeList.add`` (preserving address,
          byte run and insertion order).

    Dependencies:
        Uses:
            - UnifiedChangeSet
            - change_list_factory
            - memory_change_factory
        Used by:
            - TC-012, TC-013, TC-026 (``test_unified_changeset.py``); the
              unified write / read / round-trip / export tests of increments
              5-7 and 9.

    Example:
        >>> cs = unified_changeset_factory()
        >>> cs.counts()
        (8, 3)
        >>> cs.is_empty()
        False
    """
    from s19_app.tui.cdfx import UnifiedChangeSet

    changeset = UnifiedChangeSet()

    source_parameters = change_list_factory()
    for entry in source_parameters.entries:
        changeset.parameters.add(
            entry.parameter_name,
            entry.array_index,
            entry.value,
            entry.status,
        )

    source_memory = memory_change_factory(memory_variant)
    for memory_entry in source_memory.entries:
        changeset.memory.add(
            memory_entry.address,
            memory_entry.new_bytes,
            memory_entry.status,
        )

    return changeset


# ---------------------------------------------------------------------------
# Unified change-set file helper (batch-04, increment 5)
#
# ``make_unified_file`` writes a well-formed unified change-set JSON file to a
# real path, using the production serializer ``serialize_unified`` so the file
# on disk is exactly what the writer emits — not a hand-built JSON literal that
# could silently drift from the format contract. Introduced in increment 5
# (the writer produces it); consumed by the increment-6 reader / round-trip
# tests (TC-019, TC-025).
# ---------------------------------------------------------------------------


def make_unified_file(
    path: Path,
    *,
    memory_variant: str = "base",
) -> Path:
    """
    Summary:
        Write a well-formed unified change-set JSON file to ``path`` using the
        production :func:`~s19_app.tui.cdfx.unified_io.serialize_unified`
        serializer, so the on-disk file is byte-identical to what the writer
        emits for an :func:`unified_changeset_factory` change-set.

    Args:
        path (Path): Output file path (overwritten if it exists). The file is
            written directly with ``serialize_unified`` bytes — no work-area
            containment is applied here; this helper is for *read*-side tests
            that need a real, well-formed unified file on disk.
        memory_variant (str): The ``memory_change_factory`` variant selecting
            the memory-field half — forwarded to :func:`unified_changeset_factory`.

    Returns:
        Path: The written file path. The file is a valid unified-change-set
        JSON document carrying the format identifier, version, the parameter
        half (scalar + 1-D array + ASCII + the three adversarial floats) and
        the memory-field half (array of objects, ``address`` as an integer
        field).

    Data Flow:
        - Build a ``UnifiedChangeSet`` via :func:`unified_changeset_factory`.
        - Serialize it with the production ``serialize_unified`` and write the
          bytes to ``path``.

    Dependencies:
        Uses:
            - unified_changeset_factory
            - serialize_unified
        Used by:
            - TC-019, TC-025 (the unified-file read / round-trip tests,
              increments 6 and 9).

    Example:
        >>> p = make_unified_file(tmp_path / "cs.json")  # doctest: +SKIP
    """
    from s19_app.tui.cdfx import serialize_unified

    changeset = unified_changeset_factory(memory_variant)
    path.write_bytes(serialize_unified(changeset))
    return path


# ---------------------------------------------------------------------------
# Unified change-set READ fixtures (batch-04, increment 6)
#
# Per requirements §5.4, these helpers manufacture the adversarial unified
# files the increment-6 read TCs feed to ``read_unified``: malformed JSON,
# per-entry / version rule violations, deeply-nested JSON (the RecursionError
# arm), and over-ceiling structures (the decoded-structure ceiling arm). Every
# file is synthetic and built in-test (constraint C-9). The fixtures write
# *crafted* JSON literals — not the production serializer — precisely because
# they must produce shapes the writer would never emit.
# ---------------------------------------------------------------------------


def make_malformed_unified_file(path: Path, *, variant: str = "truncated") -> Path:
    """
    Summary:
        Write a unified-file path whose content is **not** a well-formed
        unified change-set document, for the ``MF-JSON-PARSE`` /
        ``MF-BAD-STRUCTURE`` read TCs (TC-020, TC-014).

    Args:
        path (Path): Output file path (overwritten if it exists).
        variant (str): Which malformed content to write. One of:
            - ``"truncated"`` (default) — a syntactically truncated JSON object
              (``{"format": "s19app-unified-changeset", "param``) — provokes a
              ``json.JSONDecodeError`` → ``MF-JSON-PARSE``.
            - ``"garbage"`` — non-JSON bytes (``not json at all {{{``) →
              ``MF-JSON-PARSE``.
            - ``"bare-list"`` — a well-formed JSON ``[]`` with no halves →
              ``MF-BAD-STRUCTURE``.
            - ``"bare-int"`` — a well-formed JSON ``42`` → ``MF-BAD-STRUCTURE``.
            - ``"bare-string"`` — a well-formed JSON string → ``MF-BAD-STRUCTURE``.
            - ``"no-halves"`` — a well-formed JSON object ``{"foo": 1}`` with
              no recognised parameter / memory halves → ``MF-BAD-STRUCTURE``.

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
        "truncated": b'{"format": "s19app-unified-changeset", "param',
        "garbage": b"not json at all {{{",
        "bare-list": b"[]",
        "bare-int": b"42",
        "bare-string": b'"just a string"',
        "no-halves": b'{"foo": 1, "bar": 2}',
    }
    if variant not in payloads:
        raise ValueError(f"unknown make_malformed_unified_file variant: {variant!r}")
    path.write_bytes(payloads[variant])
    return path


def make_rule_violation_unified_file(path: Path, *, variant: str) -> Path:
    """
    Summary:
        Write a **well-formed-JSON** unified file whose memory-field half or
        version trips exactly one per-entry / version ``MF-*`` rule, for the
        per-entry rule read TCs (TC-023, TC-024).

    Args:
        path (Path): Output file path (overwritten if it exists).
        variant (str): Which single rule to provoke. One of:
            - ``"no-address"`` — a memory entry with no ``address`` field →
              ``MF-NO-ADDRESS``.
            - ``"empty-bytes"`` — a memory entry with an empty ``new_bytes``
              run → ``MF-EMPTY-BYTES``.
            - ``"byte-range"`` — a memory entry with a ``new_bytes`` value of
              ``256`` → ``MF-BYTE-RANGE``.
            - ``"version-unknown"`` — a structurally valid file declaring an
              unrecognised version token → ``MF-VERSION-UNKNOWN`` (info).
        Every variant keeps one **clean** memory entry alongside the offending
        one so a test can assert the clean entry still loads (collect-don't-abort).

    Returns:
        Path: The written file path.

    Data Flow:
        - Builds a unified-document ``dict`` with the format-id header, one
          clean memory entry, and one entry crafted to trip ``variant``'s rule,
          then dumps it with stdlib ``json``.

    Dependencies:
        Used by:
            - TC-023, TC-024 (``test_unified_rules.py``).

    Example:
        >>> p = make_rule_violation_unified_file(tmp_path / "v.json", variant="no-address")  # doctest: +SKIP
    """
    import json as _json

    clean_entry = {"address": 0x100, "new_bytes": [0x41, 0x42], "status": "inside"}
    version = "1.0"
    if variant == "no-address":
        bad_entry: dict[str, object] = {"new_bytes": [0x01], "status": "inside"}
        memory = [clean_entry, bad_entry]
    elif variant == "empty-bytes":
        bad_entry = {"address": 0x200, "new_bytes": [], "status": "inside"}
        memory = [clean_entry, bad_entry]
    elif variant == "byte-range":
        bad_entry = {"address": 0x200, "new_bytes": [0x01, 256], "status": "inside"}
        memory = [clean_entry, bad_entry]
    elif variant == "version-unknown":
        version = "99.0-from-the-future"
        memory = [clean_entry]
    else:
        raise ValueError(
            f"unknown make_rule_violation_unified_file variant: {variant!r}"
        )
    document = {
        "format": "s19app-unified-changeset",
        "version": version,
        "parameters": [],
        "memory": memory,
    }
    path.write_bytes((_json.dumps(document, indent=2) + "\n").encode("utf-8"))
    return path


def make_deeply_nested_unified_file(path: Path, *, depth: int = 120_000) -> Path:
    """
    Summary:
        Write a unified-file path whose content is a JSON document nested deep
        enough to overflow the stdlib ``json`` parser's recursion and raise
        ``RecursionError`` — the LLR-006.2 / TC-035 deeply-nested arm.

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


def make_over_ceiling_unified_file(path: Path, *, variant: str) -> Path:
    """
    Summary:
        Write a **well-formed, sub-256-MB** unified file whose decoded
        structure breaches a documented decoded-structure ceiling, for the
        LLR-006.5 / TC-037 read TC.

    Args:
        path (Path): Output file path (overwritten if it exists).
        variant (str): Which ceiling to breach. One of:
            - ``"entry-count"`` — declares ``MF_ENTRY_COUNT_CEILING + 5``
              memory-field entries; the reader drops the 5 past the ceiling
              with one ``MF-ENTRY-LIMIT`` issue and keeps the in-ceiling prefix.
            - ``"run-length"`` — declares two clean memory entries plus one
              whose ``new_bytes`` run is ``MF_RUN_LENGTH_CEILING + 1`` bytes
              long; the reader drops that one entry with one ``MF-ENTRY-LIMIT``
              issue and keeps the two clean entries.
        Both files stay comfortably under the 256 MB on-disk size cap — the
        point of the ceiling is to catch a structure the file-size cap does not.

    Returns:
        Path: The written file path.

    Data Flow:
        - Builds the unified document with stdlib ``json`` for the
          ``entry-count`` variant; for ``run-length`` it streams the long run
          rather than holding a giant Python list, keeping the fixture fast.

    Dependencies:
        Uses:
            - ``unified_io.MF_ENTRY_COUNT_CEILING`` / ``MF_RUN_LENGTH_CEILING``
              — the ceilings are read from the module so the fixture and the
              reader can never disagree.
        Used by:
            - TC-037 (``test_unified_read.py``).

    Example:
        >>> p = make_over_ceiling_unified_file(tmp_path / "big.json", variant="run-length")  # doctest: +SKIP
    """
    import json as _json

    from s19_app.tui.cdfx.unified_io import (
        MF_ENTRY_COUNT_CEILING,
        MF_RUN_LENGTH_CEILING,
    )

    if variant == "entry-count":
        memory = [
            {"address": index, "new_bytes": [index & 0xFF], "status": "inside"}
            for index in range(MF_ENTRY_COUNT_CEILING + 5)
        ]
        document = {
            "format": "s19app-unified-changeset",
            "version": "1.0",
            "parameters": [],
            "memory": memory,
        }
        path.write_bytes((_json.dumps(document) + "\n").encode("utf-8"))
        return path
    if variant == "run-length":
        # Two clean entries kept; one over-run-length entry dropped. The long
        # run is streamed straight into the file as text so the fixture never
        # materialises a giant Python list.
        head = (
            b'{"format": "s19app-unified-changeset", "version": "1.0", '
            b'"parameters": [], "memory": ['
            b'{"address": 256, "new_bytes": [1, 2], "status": "inside"}, '
            b'{"address": 512, "new_bytes": [3, 4], "status": "inside"}, '
            b'{"address": 1024, "new_bytes": ['
        )
        tail = b'], "status": "inside"}]}\n'
        with path.open("wb") as handle:
            handle.write(head)
            over = MF_RUN_LENGTH_CEILING + 1
            handle.write(b",".join(b"0" for _ in range(over)))
            handle.write(tail)
        return path
    raise ValueError(f"unknown make_over_ceiling_unified_file variant: {variant!r}")
