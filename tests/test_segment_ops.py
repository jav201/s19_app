"""Split / Join / Export — engine additions (batch-95, HLR-137 / LLR-137.1..137.4).

The module under test is ``s19_app.segment_ops`` — the three pieces the new
screen rides, composed from shipped parts only: the range slicer over a loaded
image's ``get_memory_map`` (LLR-137.1), the BIN emitter + ``.addr`` sidecar
(LLR-137.2 — none shipped today) and the pad-byte fill emitter with the CRC
editor's ``join="fill"`` semantics and the fixed ``on_gap_conflict="abort"``
law (LLR-137.3, ruling 8f). The join composition rides here too (ruling
Q2/8b — concat packs from the first/lowest range's base) so the screen stays
thin. The hardened ``extract_memory_segments`` (LLR-137.4) is pinned in
``tests/test_a2l_enriched.py`` (TC-682).

Test → TC → LLR map:
- test_tc683_*  → TC-683  → LLR-137.1 (the range slicer)
- test_tc684_*  → TC-684  → LLR-137.2 (the BIN emitter + the .addr sidecar)
- test_tc685_*  → TC-685  → LLR-137.3 (the pad-byte fill emitter)
- test_tc694_*  → TC-694  → LLR-136.2's engine limb (the join, concat/fill)

Negative controls (the RED arms the contract owes): a slicer that pads or
invents bytes reddens the byte-equality arms; a BIN with an embedded header
reddens the flat-bytes arm; a fill that clobbers source bytes and writes
reddens the abort arm; overlapping ranges after fill redden the overlap arm.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from s19_app.core import S19File
from s19_app.hexfile import IntelHexFile
from s19_app.segment_ops import (
    DEFAULT_PAD_BYTE,
    EXPORT_FORMATS,
    GapConflictError,
    bin_addr_sidecar,
    emit_bin_from_mem_map,
    emit_image,
    fill_range,
    join_concat,
    join_fill,
    slice_range,
    slice_ranges,
    write_bin_with_sidecar,
)
from s19_app.tui.changes.io import (
    emit_intel_hex_from_mem_map,
    emit_s19_from_mem_map,
)
from s19_app.tui.operations.crc_designer_model import CrcTarget, gather_target

EXAMPLE_PRG = (
    Path(__file__).resolve().parents[1] / "examples" / "case_00_public" / "prg.s19"
)

#: A synthetic sparse image: two 8-byte islands, 0x1000-0x1007 and
#: 0x1020-0x1027, with a 24-byte hole between them.
ISLAND_A = {0x1000 + i: (i * 7) & 0xFF for i in range(8)}
ISLAND_B = {0x1020 + i: (i * 3) & 0xFF for i in range(8)}
SPARSE_MAP = {**ISLAND_A, **ISLAND_B}
RANGE_A = (0x1000, 0x1008)
RANGE_B = (0x1020, 0x1028)


def _reparsed_s19_map(text: str, tmp_path: Path) -> dict:
    """Write S19 text to a temp file and re-parse it through the shipped oracle."""
    target = tmp_path / "emitted.s19"
    target.write_text(text, encoding="utf-8")
    reread = S19File(str(target))
    assert reread.load_errors == []
    return reread.get_memory_map()


def _reparsed_hex_map(text: str, tmp_path: Path) -> dict:
    """Write HEX text to a temp file and re-parse it through the shipped oracle."""
    target = tmp_path / "emitted.hex"
    target.write_text(text, encoding="utf-8")
    reread = IntelHexFile(str(target))
    assert reread.get_errors() == []
    return reread.memory


# ---------------------------------------------------------------------------
# TC-683 — LLR-137.1: the range slicer
# ---------------------------------------------------------------------------


def test_tc683_single_range_slice_roundtrips_byte_identical(tmp_path: Path) -> None:
    """TC-683 (LLR-137.1): a slice of prg.s19's dense range re-emits through
    the shipped S19/HEX emitters to byte-identical bytes (0 diffs vs source)."""
    source = S19File(str(EXAMPLE_PRG))
    assert source.load_errors == []
    mem_map = source.get_memory_map()
    start, end = 0xEB08, 0xFA2E  # the demo's dense sub-range

    slice_map, covered = slice_range(mem_map, start, end)

    assert slice_map == {addr: mem_map[addr] for addr in range(start, end)}
    assert covered == [(start, end)]

    s19_map = _reparsed_s19_map(
        emit_s19_from_mem_map(slice_map, covered), tmp_path
    )
    hex_map = _reparsed_hex_map(
        emit_intel_hex_from_mem_map(slice_map, covered), tmp_path
    )
    assert s19_map == slice_map
    assert hex_map == slice_map


def test_tc683_multi_range_slice_preserves_each_ranges_offset() -> None:
    """TC-683 (LLR-137.1): the multi-range slice keeps every range's ORIGINAL
    offset — the keys stay source addresses (the join-fill input, ruling 8d)."""
    slices = slice_ranges(SPARSE_MAP, [RANGE_B, RANGE_A])
    assert len(slices) == 2

    b_map, b_covered = slices[0]
    assert b_map == ISLAND_B
    assert b_covered == [RANGE_B]
    assert min(b_map) == 0x1020  # original offset preserved, never remapped

    a_map, a_covered = slices[1]
    assert a_map == ISLAND_A
    assert a_covered == [RANGE_A]


@pytest.mark.parametrize(
    "start, end, expected",
    [
        pytest.param(0x2000, 0x2100, {}, id="wholly-out-of-image"),
        pytest.param(0x1004, 0x1024, {
            0x1004: (4 * 7) & 0xFF,
            0x1005: (5 * 7) & 0xFF,
            0x1006: (6 * 7) & 0xFF,
            0x1007: (7 * 7) & 0xFF,
            **{0x1020 + i: (i * 3) & 0xFF for i in range(4)},
        }, id="partially-inside"),
        pytest.param(0x1008, 0x1020, {}, id="spanning-the-hole"),
    ],
)
def test_tc683_out_of_image_range_yields_empty_coverage_never_raises(
    start: int, end: int, expected: dict
) -> None:
    """TC-683 (LLR-137.1 boundary catalog): an out-of-image / hole-spanning
    range yields empty coverage — never a raise; a partially-inside range
    yields exactly the covered bytes."""
    slice_map, covered = slice_range(SPARSE_MAP, start, end)
    assert slice_map == expected
    expected_ranges: list = []
    if expected:
        addrs = sorted(expected)
        run_start = prev = addrs[0]
        for addr in addrs[1:]:
            if addr != prev + 1:
                expected_ranges.append((run_start, prev + 1))
                run_start = addr
            prev = addr
        expected_ranges.append((run_start, prev + 1))
    assert covered == expected_ranges


def test_tc683_empty_image_yields_empty_slice() -> None:
    """TC-683 (LLR-137.1 boundary catalog): an empty image slices to empty."""
    assert slice_range({}, 0x1000, 0x2000) == ({}, [])
    assert slice_ranges({}, [RANGE_A, RANGE_B]) == [({}, []), ({}, [])]


# ---------------------------------------------------------------------------
# TC-684 — LLR-137.2: the BIN emitter and the .addr sidecar
# ---------------------------------------------------------------------------


def test_tc684_bin_bytes_are_in_address_order_exact_length() -> None:
    """TC-684 (LLR-137.2): flat bytes in address order; a fully covered range
    yields exactly ``size`` bytes (0 extra, 0 missing); no embedded header —
    the first byte IS the first data byte."""
    source = S19File(str(EXAMPLE_PRG))
    assert source.load_errors == []
    mem_map = source.get_memory_map()
    start, end = 0xEB08, 0xFA2E

    blob = emit_bin_from_mem_map(mem_map, [(start, end)])

    assert len(blob) == end - start
    assert blob == bytes(mem_map[addr] for addr in range(start, end))

    # The sparse islands gather skip-style: the hole contributes NO bytes.
    sparse_blob = emit_bin_from_mem_map(SPARSE_MAP, [RANGE_A, RANGE_B])
    assert sparse_blob == bytes(
        list(ISLAND_A.values()) + list(ISLAND_B.values())
    )
    assert len(sparse_blob) == 16


def test_tc684_addr_sidecar_is_one_line_parsing_as_the_base() -> None:
    """TC-684 (LLR-137.2): the sidecar is one line carrying the base — the
    pair keeps the base recoverable (the round's #2 recommendation)."""
    text = bin_addr_sidecar(0x08000000)
    assert text == "0x08000000\n"
    assert int(text.strip(), 0) == 0x08000000
    assert text.count("\n") == 1


def test_tc684_write_bin_with_sidecar_round_trips(tmp_path: Path) -> None:
    """TC-684 (LLR-137.2): ‹name›.bin + ‹name›.addr land side by side; the
    sidecar's single line parses as the FIRST range's declared base."""
    dest = tmp_path / "prg_AscetCode.bin"
    bin_path, sidecar_path = write_bin_with_sidecar(
        SPARSE_MAP, [RANGE_A], dest
    )

    assert bin_path == dest
    assert sidecar_path == tmp_path / "prg_AscetCode.addr"
    assert dest.read_bytes() == bytes(ISLAND_A.values())
    assert int(sidecar_path.read_text(encoding="ascii").strip(), 0) == 0x1000


def test_tc684_zero_coverage_writes_zero_bytes_and_the_sidecar(tmp_path: Path) -> None:
    """TC-684 (LLR-137.2 boundary catalog): a zero-coverage range writes a
    0-byte BIN plus the sidecar carrying the declared base (behind the
    LLR-136.6 confirm at the screen)."""
    dest = tmp_path / "empty.bin"
    bin_path, sidecar_path = write_bin_with_sidecar({}, [RANGE_A], dest)

    assert bin_path.read_bytes() == b""
    assert int(sidecar_path.read_text(encoding="ascii").strip(), 0) == 0x1000


def test_tc684_shipped_emitters_stay_content_identical_for_the_same_plan(
    tmp_path: Path,
) -> None:
    """TC-684 (LLR-137.2): the same plan serializes content-identically in all
    three formats — S19 and HEX re-parse to the plan map, BIN is the covered
    bytes (the negative control: a diverging emitter reddens here)."""
    plan_map, plan_ranges = join_fill(SPARSE_MAP, [RANGE_A, RANGE_B])

    s19_map = _reparsed_s19_map(
        emit_s19_from_mem_map(plan_map, plan_ranges), tmp_path
    )
    hex_map = _reparsed_hex_map(
        emit_intel_hex_from_mem_map(plan_map, plan_ranges), tmp_path
    )
    assert s19_map == plan_map
    assert hex_map == plan_map
    assert emit_bin_from_mem_map(plan_map, plan_ranges) == bytes(
        plan_map[addr] for addr in range(*plan_ranges[0])
    )


# ---------------------------------------------------------------------------
# TC-685 — LLR-137.3: the pad-byte fill emitter
# ---------------------------------------------------------------------------


def test_tc685_join_fill_pads_gaps_with_the_default_00() -> None:
    """TC-685 (LLR-137.3 + LLR-136.4's default): gaps fill with 0x00 at every
    entry path (DEFAULT_PAD_BYTE), data bytes stay byte-identical."""
    assert DEFAULT_PAD_BYTE == 0x00  # the ruled default (Q1/8a), not 0xFF

    filled, out_ranges = join_fill(SPARSE_MAP, [RANGE_A, RANGE_B])

    assert out_ranges == [(0x1000, 0x1028)]  # one dense range
    assert filled == {
        **ISLAND_A,
        **{0x1008 + i: 0x00 for i in range(0x18)},
        **ISLAND_B,
    }
    # No source byte was clobbered: the islands read back byte-identical.
    for addr, byte in SPARSE_MAP.items():
        assert filled[addr] == byte


def test_tc685_join_fill_honours_a_custom_pad_byte() -> None:
    """TC-685 (LLR-137.3): a custom pad byte lands across every pad span."""
    filled, _ = join_fill(SPARSE_MAP, [RANGE_A, RANGE_B], pad_byte=0xA5)
    assert all(filled[0x1008 + i] == 0xA5 for i in range(0x18))

    filled_ff, _ = join_fill(SPARSE_MAP, [RANGE_A, RANGE_B], pad_byte=0xFF)
    assert all(filled_ff[0x1008 + i] == 0xFF for i in range(0x18))


def test_tc685_fill_range_pads_intra_range_holes() -> None:
    """TC-685 (LLR-137.3, the split intra_gap=fill limb): holes INSIDE one
    range take the pad byte; the range materializes dense."""
    gappy = {0x2000: 0x11, 0x2003: 0x44}  # holes at 0x2001 / 0x2002
    filled, out_ranges = fill_range(gappy, 0x2000, 0x2004)
    assert out_ranges == [(0x2000, 0x2004)]
    assert filled == {0x2000: 0x11, 0x2001: 0x00, 0x2002: 0x00, 0x2003: 0x44}

    # The skip limb stays sparse (the shipped vocabulary, verbatim).
    sparse, sparse_ranges = fill_range(gappy, 0x2000, 0x2004, intra_gap="skip")
    assert sparse == gappy
    assert sparse_ranges == [(0x2000, 0x2001), (0x2003, 0x2004)]


def test_tc685_gap_conflict_aborts_naming_the_offending_span() -> None:
    """TC-685 (LLR-137.3 + LLR-136.4's abort limb): a source byte inside a pad
    span that differs from the pad byte refuses BEFORE anything emits, naming
    the span (the fixed on_gap_conflict="abort" law, ruling 8f)."""
    planted = {**SPARSE_MAP, 0x1010: 0x77}
    with pytest.raises(GapConflictError) as excinfo:
        join_fill(planted, [RANGE_A, RANGE_B])
    reason = str(excinfo.value)
    assert "0x00001010" in reason  # the offending address is named
    assert "abort" in reason
    # The refusal fires at PLAN time — the emit entry is never reached, so
    # the export writes 0 bytes (the screen's ^E rides plan-then-emit).


def test_tc685_gap_bytes_equal_to_pad_are_not_a_conflict() -> None:
    """TC-685 (LLR-137.3): a gap byte EQUAL to the pad byte is erased flash,
    not a conflict — the shipped gap_conflict law, verbatim."""
    planted = {**SPARSE_MAP, 0x1010: 0xFF}
    filled, _ = join_fill(planted, [RANGE_A, RANGE_B], pad_byte=0xFF)
    assert filled[0x1010] == 0xFF


def test_tc685_overlapping_ranges_abort_instead_of_clobbering() -> None:
    """TC-685 (the gap-conflict law's overlap limb): overlapping ranges after
    fill = abort naming both spans — never a silent last-write-wins."""
    with pytest.raises(GapConflictError) as excinfo:
        join_fill(SPARSE_MAP, [RANGE_A, (0x1004, 0x100C)])
    assert "0x00001000" in str(excinfo.value)
    assert "0x00001004" in str(excinfo.value)

    with pytest.raises(GapConflictError):
        join_concat(SPARSE_MAP, [RANGE_A, (0x1004, 0x100C)])


def test_tc685_invalid_pad_byte_and_vocab_are_rejected() -> None:
    """TC-685 (LLR-137.3): the pad byte is 0..255 and the intra_gap vocabulary
    is the shipped one — garbage in is a loud ValueError, never a silent fill."""
    with pytest.raises(ValueError):
        join_fill(SPARSE_MAP, [RANGE_A, RANGE_B], pad_byte=0x100)
    with pytest.raises(ValueError):
        fill_range(SPARSE_MAP, *RANGE_A, intra_gap="stretch")


def test_tc685_filled_image_is_accepted_by_the_shipped_emitters(
    tmp_path: Path,
) -> None:
    """TC-685 (LLR-137.3's composition contract): the fill runs BEFORE the
    emitters — the filled image re-parses through the shipped S19/HEX
    emitters to the filled map, and the one emit entry dispatches all three
    formats from the same plan."""
    filled, out_ranges = join_fill(SPARSE_MAP, [RANGE_A, RANGE_B])

    s19_map = _reparsed_s19_map(
        emit_s19_from_mem_map(filled, out_ranges), tmp_path
    )
    hex_map = _reparsed_hex_map(
        emit_intel_hex_from_mem_map(filled, out_ranges), tmp_path
    )
    assert s19_map == filled
    assert hex_map == filled

    for fmt in EXPORT_FORMATS:
        out = emit_image(filled, out_ranges, fmt)
        if fmt == "bin":
            assert out == bytes(filled[addr] for addr in range(0x1000, 0x1028))
        else:
            assert isinstance(out, str)
    with pytest.raises(ValueError):
        emit_image(filled, out_ranges, "s37")


def test_tc685_fill_matches_the_crc_coverage_oracle() -> None:
    """TC-685 (LLR-137.3's executed verification): the fill emitter's bytes ==
    the CRC coverage path's gather over the same image — the shipped
    gather_target oracle under join="fill" with the same pad byte."""
    pad = 0x5A
    filled, _ = join_fill(SPARSE_MAP, [RANGE_A, RANGE_B], pad_byte=pad)
    oracle = gather_target(
        SPARSE_MAP,
        CrcTarget(
            ranges=(RANGE_A, RANGE_B),
            intra_gap="fill",
            join="fill",
            pad_byte=pad,
            output_address=0,
            store_width=1,
            store_endianness="little",
        ),
    )
    assert bytes(filled[addr] for addr in range(0x1000, 0x1028)) == oracle


# ---------------------------------------------------------------------------
# TC-694 — LLR-136.2's engine limb: the join (concat + fill composition)
# ---------------------------------------------------------------------------


def test_tc694_join_concat_packs_from_the_lowest_ranges_base() -> None:
    """TC-694 (LLR-136.2's engine limb, ruling Q2/8b): concat packs the
    selection back-to-back from the FIRST/lowest range's base — declared
    order irrelevant, the output base == the lowest base, one dense range."""
    # Deliberately declared out of order: B before A.
    packed, out_ranges = join_concat(SPARSE_MAP, [RANGE_B, RANGE_A])

    assert out_ranges == [(0x1000, 0x1010)]
    assert packed == {
        0x1000 + i: byte for i, byte in enumerate(list(ISLAND_A.values()) + list(ISLAND_B.values()))
    }
    # The packed base is the lowest DECLARED range's base, not the first
    # covered byte: a leading hole stays out of the output.
    gappy = {0x3001: 0xAB, 0x3002: 0xCD}
    packed_gappy, gappy_ranges = join_concat(gappy, [(0x3000, 0x3003)])
    assert gappy_ranges == [(0x3000, 0x3002)]
    assert packed_gappy == {0x3000: 0xAB, 0x3001: 0xCD}


def test_tc694_join_concat_matches_the_crc_coverage_oracle() -> None:
    """TC-694 (the join's oracle arm): the packed bytes == the shipped
    gather_target under join="concat" over the same image — the join rides
    the CRC coverage semantics, not a re-invention."""
    packed, _ = join_concat(SPARSE_MAP, [RANGE_A, RANGE_B])
    oracle = gather_target(
        SPARSE_MAP,
        CrcTarget(
            ranges=(RANGE_A, RANGE_B),
            intra_gap="skip",
            join="concat",
            pad_byte=0xFF,
            output_address=0,
            store_width=1,
            store_endianness="little",
        ),
    )
    assert bytes(packed[addr] for addr in range(0x1000, 0x1010)) == oracle


def test_tc694_join_over_empty_coverage_yields_empty_or_all_pad_never_raises() -> None:
    """TC-694 (boundary catalog): a join over zero coverage never raises —
    concat has nothing to pack (empty image), while fill still honours the
    selected spans, emitting the all-pad file the LLR-136.6 confirm guards."""
    assert join_concat({}, [RANGE_A, RANGE_B]) == ({}, [])
    filled, out_ranges = join_fill({}, [RANGE_A, RANGE_B])
    assert out_ranges == [(0x1000, 0x1028)]
    assert filled == {addr: 0x00 for addr in range(0x1000, 0x1028)}
    assert join_concat(SPARSE_MAP, []) == ({}, [])
    assert join_fill(SPARSE_MAP, []) == ({}, [])
