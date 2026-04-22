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
from typing import Any, Optional

import pytest


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
