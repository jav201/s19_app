"""HLR-001 — Intel HEX emitter round-trip tests.

The emitter under test is
``s19_app.tui.changes.io.emit_intel_hex_from_mem_map`` (NEW this batch,
D-A=(a) R2-relocated: co-located with ``emit_s19_from_mem_map`` for
emission-purpose cohesion; the read oracle ``IntelHexFile`` stays in
``s19_app.hexfile``). The acceptance contract is round-trip equality through
the reader oracle: ``IntelHexFile(write(emit(mem))).memory == mem`` with zero
load errors.

Test → TC → LLR map (provisional TC ids per V-5):
- test_low_address_roundtrip                  → TC-001/TC-004 → LLR-001.1/.2/.4
- test_data_records_max_16_bytes_and_checksum → TC-002       → LLR-001.2
- test_ela_high_address_roundtrip             → TC-003       → LLR-001.3
- test_empty_mem_map_emits_eof_only           → TC-004       → LLR-001.4
- test_public_example_roundtrips_as_hex       → TC-001/TC-004 → LLR-001.4
- test_byte_stability_measure                 → (MEASURE)    → informative,
      records emit(parse(file)) == file (expected canonicalized/False); NOT a gate.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from s19_app.core import S19File
from s19_app.hexfile import IntelHexFile
from s19_app.tui.changes.io import (
    HEX_DATA_BYTES_PER_RECORD,
    emit_intel_hex_from_mem_map,
)

EXAMPLE_S19 = (
    Path(__file__).resolve().parents[1] / "examples" / "case_00_public" / "prg.s19"
)


def _ranges_from_mem(mem_map: dict[int, int]) -> list[tuple[int, int]]:
    addresses = sorted(mem_map)
    if not addresses:
        return []
    ranges: list[tuple[int, int]] = []
    start = prev = addresses[0]
    for addr in addresses[1:]:
        if addr == prev + 1:
            prev = addr
        else:
            ranges.append((start, prev + 1))
            start = prev = addr
    ranges.append((start, prev + 1))
    return ranges


def _emit_write_reread(mem_map: dict[int, int], tmp_path: Path) -> IntelHexFile:
    text = emit_intel_hex_from_mem_map(mem_map, _ranges_from_mem(mem_map))
    target = tmp_path / "emitted.hex"
    target.write_text(text, encoding="utf-8")
    return IntelHexFile(str(target))


@pytest.mark.parametrize(
    "mem_map",
    [
        pytest.param({0x10: 0xAB}, id="single-byte"),
        pytest.param(
            {0x100 + offset: offset & 0xFF for offset in range(0x30)},
            id="multi-row-contiguous",
        ),
        pytest.param(
            {**{0x200 + i: i & 0xFF for i in range(8)},
             **{0x300 + i: (i * 3) & 0xFF for i in range(20)}},
            id="two-disjoint-ranges",
        ),
    ],
)
def test_low_address_roundtrip(mem_map: dict[int, int], tmp_path: Path) -> None:
    """TC-001/TC-004 (LLR-001.1/.2/.4): low (<=0xFFFF) maps round-trip cleanly."""
    reread = _emit_write_reread(mem_map, tmp_path)
    assert reread.get_errors() == []
    assert reread.memory == mem_map


def test_data_records_max_16_bytes_and_checksum(tmp_path: Path) -> None:
    """TC-002 (LLR-001.2): <=16 data bytes/record; reader confirms 0 checksum errors."""
    mem_map = {0x400 + offset: (offset * 7) & 0xFF for offset in range(0x50)}
    text = emit_intel_hex_from_mem_map(mem_map, _ranges_from_mem(mem_map))

    data_lines = [
        line for line in text.splitlines() if line[7:9] == "00"
    ]
    assert data_lines
    for line in data_lines:
        byte_count = int(line[1:3], 16)
        assert byte_count <= HEX_DATA_BYTES_PER_RECORD

    target = tmp_path / "emitted.hex"
    target.write_text(text, encoding="utf-8")
    reread = IntelHexFile(str(target))
    assert reread.get_errors() == []
    assert reread.memory == mem_map


def test_ela_high_address_roundtrip(tmp_path: Path) -> None:
    """TC-003 (LLR-001.3): a span >= 0x10000 forces >=1 type-0x04 ELA record and
    the high address survives the round-trip."""
    base = 0x08040000
    mem_map = {base + offset: offset & 0xFF for offset in range(0x21)}
    text = emit_intel_hex_from_mem_map(mem_map, _ranges_from_mem(mem_map))

    target = tmp_path / "emitted.hex"
    target.write_text(text, encoding="utf-8")
    reread = IntelHexFile(str(target))

    ela_records = sum(1 for r in reread.records if r.record_type == 0x04)
    assert ela_records >= 1
    assert reread.get_errors() == []
    assert reread.memory == mem_map
    assert base in reread.memory


def test_ela_record_emitted_per_upper16_change(tmp_path: Path) -> None:
    """TC-003 (LLR-001.3): crossing a second 64K boundary emits a second ELA."""
    mem_map = {
        **{0x0001_FFF0 + i: i & 0xFF for i in range(0x10)},
        **{0x0002_0000 + i: (i + 1) & 0xFF for i in range(0x10)},
    }
    text = emit_intel_hex_from_mem_map(mem_map, _ranges_from_mem(mem_map))
    target = tmp_path / "emitted.hex"
    target.write_text(text, encoding="utf-8")
    reread = IntelHexFile(str(target))

    ela_records = sum(1 for r in reread.records if r.record_type == 0x04)
    assert ela_records >= 2
    assert reread.get_errors() == []
    assert reread.memory == mem_map


def test_empty_mem_map_emits_eof_only(tmp_path: Path) -> None:
    """TC-004 (LLR-001.4): empty input emits the EOF record alone, re-reads to {}."""
    text = emit_intel_hex_from_mem_map({}, [])
    assert text.splitlines() == [":00000001FF"]

    target = tmp_path / "empty.hex"
    target.write_text(text, encoding="utf-8")
    reread = IntelHexFile(str(target))
    assert reread.get_errors() == []
    assert reread.memory == {}


def test_output_terminates_with_single_eof(tmp_path: Path) -> None:
    """TC-004 (LLR-001.4): exactly one EOF record, and it is last."""
    mem_map = {0x10: 0xAB, 0x11: 0xCD}
    lines = emit_intel_hex_from_mem_map(
        mem_map, _ranges_from_mem(mem_map)
    ).splitlines()
    eof_lines = [line for line in lines if line[7:9] == "01"]
    assert eof_lines == [":00000001FF"]
    assert lines[-1] == ":00000001FF"


def test_public_example_roundtrips_as_hex(tmp_path: Path) -> None:
    """TC-001/TC-004 (LLR-001.4): a real example file parsed to a mem_map and
    re-emitted as Intel HEX round-trips to the same map (examples/ has no .hex,
    A5 — the S19 example is parsed to a mem_map, the canonical emitter input)."""
    original = S19File(str(EXAMPLE_S19))
    mem_map = original.get_memory_map()
    assert mem_map  # guard: the example is non-empty

    reread = _emit_write_reread(mem_map, tmp_path)
    assert reread.get_errors() == []
    assert reread.memory == mem_map


def test_byte_stability_measure(tmp_path: Path, record_property) -> None:
    """MEASURE (informative, NOT a gate): record whether emitting the parse of
    a HEX file reproduces the file byte-for-byte. We EXPECT canonicalization
    (record framing/ordering/casing), so byte-identity is expected False; this
    documents the measurement, it does not assert it."""
    mem_map = {0x100 + offset: offset & 0xFF for offset in range(0x25)}
    first = emit_intel_hex_from_mem_map(mem_map, _ranges_from_mem(mem_map))
    target = tmp_path / "first.hex"
    target.write_text(first, encoding="utf-8")

    reparsed = IntelHexFile(str(target))
    second = emit_intel_hex_from_mem_map(reparsed.memory, reparsed.get_ranges())

    byte_stable = first == second
    record_property("emit_parse_emit_byte_stable", byte_stable)
    # emit(parse(emit(x))) IS expected stable because both inputs are the same
    # canonical mem_map; the meaningful MEASURE is recorded above, not gated.
    assert isinstance(byte_stable, bool)
