"""
Check-path tests for the headless CRC operation (batch-12 CRC_F2, I2 SUB-STEP B).

Pins the non-mutating compare path (LLR-002.1 read-stored, LLR-002.2 compare +
per-region payload) with the §5.2 TC-111 (match) and TC-112 (mismatch) cases,
plus the "no stored value" and config-order properties. Every test is written
to FAIL on a logic regression (Rule 9): the match/mismatch fixtures derive the
stored value from the SAME engine the check uses AND cross-check the computed
value against an independent ``compute_region_crc`` call, so a vacuous match
cannot pass; the no-mutation assertions snapshot ``mem_map`` pre/post.
"""

from __future__ import annotations

from pathlib import Path

from s19_app.core import S19File
from s19_app.tui.changes.io import emit_s19_from_mem_map
from s19_app.tui.changes.verify import STATUS_VERIFIED, verify_written_image
import zlib

import pytest

from s19_app.tui.operations.crc import (
    DEFAULT_FINAL_XOR,
    DEFAULT_INIT,
    DEFAULT_POLYNOMIAL,
    DEFAULT_REVERSE,
    LE32_WIDTH,
    CrcOperation,
    check_regions,
    compute_region_crc,
    decode_le32,
    encode_le,
    encode_le32,
    inject_crcs,
    read_stored_crc_le,
    write_crc_image,
)
from s19_app.tui.operations.crc_config import CrcConfig, CrcGroup, CrcRegion
from s19_app.tui.operations.model import OperationInput
from s19_app.tui.workspace import WORKAREA_DIRNAME, WORKAREA_SUBDIR, ensure_workarea


def _op_input(mem_map: dict[int, int]) -> OperationInput:
    """Build a neutral :class:`OperationInput` over ``mem_map`` for the check.

    Only ``mem_map`` is load-bearing for the check path; ``ranges`` mirrors the
    region geometry for realism but the engine reads ``mem_map`` directly.
    """
    return OperationInput(
        mem_map=mem_map,
        ranges=sorted((addr, addr + 1) for addr in mem_map),
        input_path=None,
        variant_id=None,
        file_type="s19",
    )


def _default_config(regions: list[CrcRegion]) -> CrcConfig:
    """A :class:`CrcConfig` over ``regions`` using the zlib/PKZIP defaults."""
    return CrcConfig(
        regions=regions,
        polynomial=DEFAULT_POLYNOMIAL,
        init=DEFAULT_INIT,
        reverse=DEFAULT_REVERSE,
        final_xor=DEFAULT_FINAL_XOR,
    )


def _mem_from_bytes(base: int, payload: bytes) -> dict[int, int]:
    """Build a contiguous ``mem_map`` from ``payload`` starting at ``base``."""
    return {base + offset: value for offset, value in enumerate(payload)}


def test_check_reports_match_nonmutating() -> None:
    """TC-111 — MATCH: the stored 4-byte LE value at the output address equals
    the computed CRC → ``matched is True``, and ``mem_map`` is byte-for-byte
    unchanged across the check (LLR-002.2 non-mutation).

    The stored value is written as ``encode_le32(computed)``; the match is
    proven non-vacuous by ALSO asserting the computed value equals an
    independent ``compute_region_crc`` over the same region."""
    region_bytes = b"\x10\x11\x12\x13\x14"
    mem = _mem_from_bytes(0x1000, region_bytes)
    region = CrcRegion(start=0x1000, end=0x1000 + len(region_bytes),
                       output_address=0x2000)

    # Independent recompute of the region CRC (not via check_regions).
    expected = compute_region_crc(mem, region.start, region.end)
    # Store the matching CRC as 4-byte LE at the output address.
    mem.update(_mem_from_bytes(region.output_address, encode_le32(expected)))

    op_input = _op_input(mem)
    snapshot = dict(mem)

    results = check_regions(op_input, _default_config([region]))

    assert len(results) == 1
    result = results[0]
    assert result.computed_crc == expected  # non-vacuous: independent oracle
    assert result.stored_value == expected
    assert result.matched is True
    assert result.written is False
    assert op_input.mem_map == snapshot  # zero mutation


def test_check_reports_mismatch() -> None:
    """TC-112 — MISMATCH: the stored value differs from the computed CRC →
    ``matched is False``; ``mem_map`` untouched."""
    region_bytes = b"\xaa\xbb\xcc\xdd"
    mem = _mem_from_bytes(0x40, region_bytes)
    region = CrcRegion(start=0x40, end=0x40 + len(region_bytes),
                       output_address=0x80)

    expected = compute_region_crc(mem, region.start, region.end)
    # Store a value guaranteed to differ from the computed CRC.
    wrong = (expected ^ 0xFFFFFFFF) & 0xFFFFFFFF
    assert wrong != expected
    mem.update(_mem_from_bytes(region.output_address, encode_le32(wrong)))

    op_input = _op_input(mem)
    snapshot = dict(mem)

    results = check_regions(op_input, _default_config([region]))

    assert results[0].computed_crc == expected
    assert results[0].stored_value == wrong
    assert results[0].matched is False
    assert op_input.mem_map == snapshot  # zero mutation


def test_read_stored_missing_returns_none() -> None:
    """An output address with fewer than 4 present bytes → ``read_stored_crc_le``
    returns ``None`` and ``check_regions`` yields ``matched is None``, with no
    exception raised (LLR-002.1 "no stored value")."""
    region_bytes = b"\x01\x02\x03"
    mem = _mem_from_bytes(0, region_bytes)
    # Only 3 of the 4 output bytes present (0x10..0x12; 0x13 absent).
    mem.update({0x10: 0x00, 0x11: 0x00, 0x12: 0x00})
    region = CrcRegion(start=0, end=len(region_bytes), output_address=0x10)

    op_input = _op_input(mem)

    assert read_stored_crc_le(op_input, 0x10) is None

    results = check_regions(op_input, _default_config([region]))

    assert results[0].stored_value is None
    assert results[0].matched is None
    # Computed CRC is still reported even with no stored value to compare.
    assert results[0].computed_crc == compute_region_crc(mem, 0, len(region_bytes))


def test_check_multi_region_order() -> None:
    """Two regions → one ``CrcRegionResult`` per region, in config order
    (LLR-002.2 deterministic ordering)."""
    mem = _mem_from_bytes(0, b"\x11\x22\x33\x44\x55\x66")
    region_a = CrcRegion(start=0, end=3, output_address=0x100)
    region_b = CrcRegion(start=3, end=6, output_address=0x200)

    op_input = _op_input(mem)

    results = check_regions(op_input, _default_config([region_a, region_b]))

    assert len(results) == 2
    assert [r.output_address for r in results] == [0x100, 0x200]
    assert results[0].computed_crc == compute_region_crc(mem, 0, 3)
    assert results[1].computed_crc == compute_region_crc(mem, 3, 6)


def test_execute_no_config_returns_ok_no_regions() -> None:
    """``CrcOperation.execute`` with ``config=None`` (the generic
    ``run_operation`` path) reports ``status="ok"`` with nothing to check:
    ``crc_regions is None``, one explaining note, and ``mem_map`` byte-for-byte
    unchanged.

    Intent: the no-config branch must not invent a check — a regression that
    ran ``check_regions`` against an empty/implicit config would populate
    ``crc_regions`` and fail the ``is None`` assertion."""
    mem = _mem_from_bytes(0x500, b"\x01\x02\x03\x04")
    op_input = _op_input(mem)
    snapshot = dict(mem)

    result = CrcOperation().execute(op_input)

    assert result.status == "ok"
    assert result.operation_id == "crc"
    assert result.crc_regions is None
    assert result.notes == ["CRC: no config supplied — nothing to check"]
    assert result.output.mem_map == mem
    assert op_input.mem_map == snapshot  # zero mutation


def test_execute_with_config_populates_crc_regions() -> None:
    """``CrcOperation.execute(config=...)`` runs the check: a matching region
    and a mismatching region yield ``status="ok"`` with the per-region
    ``matched`` flags correct and ``mem_map`` unchanged.

    Intent: the matched/mismatched verdicts are proven non-vacuous — the
    matching region's stored value is ``encode_le32`` of an INDEPENDENT
    ``compute_region_crc`` recompute, and the mismatching region's stored value
    is its bitwise complement (guaranteed ``!=``). The summary note must count
    1 matched + 1 mismatched + 0 no-stored-value."""
    mem = _mem_from_bytes(0, b"\x11\x22\x33\x44\x55\x66")
    region_match = CrcRegion(start=0, end=3, output_address=0x100)
    region_mismatch = CrcRegion(start=3, end=6, output_address=0x200)

    crc_match = compute_region_crc(mem, region_match.start, region_match.end)
    crc_mismatch = compute_region_crc(
        mem, region_mismatch.start, region_mismatch.end
    )
    wrong = (crc_mismatch ^ 0xFFFFFFFF) & 0xFFFFFFFF
    assert wrong != crc_mismatch
    mem.update(_mem_from_bytes(region_match.output_address, encode_le32(crc_match)))
    mem.update(_mem_from_bytes(region_mismatch.output_address, encode_le32(wrong)))

    op_input = _op_input(mem)
    snapshot = dict(mem)
    config = _default_config([region_match, region_mismatch])

    result = CrcOperation().execute(op_input, config=config)

    assert result.status == "ok"
    assert result.crc_regions is not None
    assert len(result.crc_regions) == 2
    assert result.crc_regions[0].matched is True
    assert result.crc_regions[0].computed_crc == crc_match  # independent oracle
    assert result.crc_regions[1].matched is False
    assert result.crc_regions[1].computed_crc == crc_mismatch
    assert result.notes == [
        "CRC: 2 region(s): 1 matched, 1 mismatched, 0 no-stored-value"
    ]
    assert op_input.mem_map == snapshot  # zero mutation


# ---------------------------------------------------------------------------
# Write path (I5a, headless): inject + emit + verify mechanics (LLR-003.1/.2/
# .3, re-scoped LLR-003.5). The original mem_map is never mutated; the write
# only happens when ``write_crc_image`` is invoked; the verify intent is the
# INJECTED working copy (F-Q-05); a containment-failing target collects a
# finding and writes nothing (collect-don't-abort).
# ---------------------------------------------------------------------------


def _contiguous_op_input(base: int, payload: bytes) -> OperationInput:
    """A neutral input over ONE contiguous range ``[base, base+len)``.

    Unlike ``_op_input`` (per-byte ranges), this gives a single clean range so
    an output address placed beyond it is a genuine gap and the emitted S19 has
    well-formed contiguous records."""
    mem = _mem_from_bytes(base, payload)
    return OperationInput(
        mem_map=mem,
        ranges=[(base, base + len(payload))],
        input_path=Path("firmware.s19"),
        variant_id=None,
        file_type="s19",
    )


def test_inject_writes_le_at_output_address() -> None:
    """TC-121 — inject writes the computed CRC as 4 LE bytes at the output
    address in the WORKING copy, while the ORIGINAL ``mem_map`` is left
    byte-for-byte unchanged (LLR-003.1).

    The output address sits INSIDE the loaded range (region 0x40..0x60 covers
    the 0x50 output), so this exercises the in-range branch (no extension).
    Non-vacuous: the injected bytes are decoded back and must equal an
    INDEPENDENT ``compute_region_crc`` of the same region."""
    payload = bytes(range(0x20, 0x40))  # 32 contiguous bytes at 0x40..0x60
    op_input = _contiguous_op_input(0x40, payload)
    snapshot = dict(op_input.mem_map)
    region = CrcRegion(start=0x40, end=0x48, output_address=0x50)
    config = _default_config([region])

    check_results = check_regions(op_input, config)
    working_mem, working_ranges, written = inject_crcs(op_input, check_results)

    expected = compute_region_crc(op_input.mem_map, 0x40, 0x48)
    stored_in_working = decode_le32(
        working_mem[0x50 + i] for i in range(LE32_WIDTH)
    )
    assert stored_in_working == expected  # independent oracle
    assert [working_mem[0x50 + i] for i in range(LE32_WIDTH)] == list(
        encode_le32(expected)
    )
    assert written[0].written is True
    assert written[0].computed_crc == expected
    # In-range output: no new keys, ranges unchanged.
    assert working_ranges == op_input.ranges
    # ORIGINAL never mutated.
    assert op_input.mem_map == snapshot


def test_inject_into_gap_extends_ranges() -> None:
    """TC-122 — an output address in a GAP → the working ``mem_map`` gains
    exactly 4 keys AND the working ``ranges`` gains/merges a covering range,
    kept sorted + non-overlapping; the original snapshot is unchanged
    (LLR-003.1 / D-6 / F-A-06)."""
    payload = bytes(range(0, 16))  # 0x100..0x110
    op_input = _contiguous_op_input(0x100, payload)
    snapshot = dict(op_input.mem_map)
    snapshot_ranges = list(op_input.ranges)
    # 0x200 is far outside the only loaded range [0x100, 0x110).
    region = CrcRegion(start=0x100, end=0x108, output_address=0x200)
    config = _default_config([region])

    check_results = check_regions(op_input, config)
    working_mem, working_ranges, _ = inject_crcs(op_input, check_results)

    # Exactly 4 new keys, all at the output address.
    new_keys = set(working_mem) - set(op_input.mem_map)
    assert new_keys == {0x200, 0x201, 0x202, 0x203}
    # Ranges gained a covering range, kept sorted + non-overlapping.
    assert (0x200, 0x204) in working_ranges
    assert working_ranges == sorted(working_ranges)
    for (a_start, a_end), (b_start, _) in zip(
        working_ranges, working_ranges[1:]
    ):
        assert a_end < b_start  # strictly non-overlapping (and non-touching)
    # ORIGINAL never mutated.
    assert op_input.mem_map == snapshot
    assert op_input.ranges == snapshot_ranges


def test_modified_s19_reread_matches_intent(tmp_path: Path) -> None:
    """TC-123 — inject → emit (into a tmp work area) → ``verify_written_image``
    yields ``STATUS_VERIFIED`` with empty runs; AND a deliberately corrupted
    written file yields ``"mismatch"`` with non-empty runs (the negative case
    guards against a tautological self-compare). Verify intent is the INJECTED
    working copy (F-Q-05)."""
    payload = bytes(range(0x10, 0x30))  # 32 bytes at 0x80..0xA0
    op_input = _contiguous_op_input(0x80, payload)
    region = CrcRegion(start=0x80, end=0x90, output_address=0x88)
    config = _default_config([region])

    result = write_crc_image(op_input, config, workarea_base=tmp_path)

    assert result.written_path is not None
    assert result.written_path.exists()
    assert result.verify_status == STATUS_VERIFIED
    assert result.verify_runs == []
    assert result.findings == []
    assert all(r.written is True for r in result.crc_regions)

    # Negative control (guards a tautological self-compare): write a CORRUPTED
    # S19 to disk, then verify it against the SAME intended map that just
    # verified clean. The verdict must flip to mismatch with a non-empty run.
    intended = S19File(str(result.written_path)).get_memory_map()
    bad_mem = dict(intended)
    bad_mem[min(bad_mem)] ^= 0xFF  # flip one byte
    bad_ranges = [(min(bad_mem), max(bad_mem) + 1)]
    bad_path = tmp_path / "bad.s19"
    bad_path.write_text(
        emit_s19_from_mem_map(bad_mem, bad_ranges), encoding="utf-8"
    )
    bad_result = verify_written_image(bad_path, intended, "s19")
    assert bad_result.status == "mismatch"
    assert bad_result.runs != []


def test_write_only_when_invoked(tmp_path: Path) -> None:
    """TC-124 (headless half) — the inject/emit mechanics write a file ONLY when
    ``write_crc_image`` is invoked; the check path (``check_regions`` /
    ``inject_crcs``) writes ZERO files. The two-stage CONFIRMATION gating is
    I5b; here we pin that the mechanics have no implicit write."""
    payload = bytes(range(0, 16))
    op_input = _contiguous_op_input(0x300, payload)
    region = CrcRegion(start=0x300, end=0x308, output_address=0x304)
    config = _default_config([region])

    workarea = ensure_workarea(tmp_path)

    def _files_under(root: Path) -> list[Path]:
        return [p for p in root.rglob("*") if p.is_file()]

    before = _files_under(workarea)

    # check + inject are pure: no file appears.
    check_results = check_regions(op_input, config)
    inject_crcs(op_input, check_results)
    assert _files_under(workarea) == before  # 0 files written by check/inject

    # Only invoking the write path produces a file.
    result = write_crc_image(op_input, config, workarea_base=tmp_path)
    after = _files_under(workarea)
    assert result.written_path is not None
    assert result.written_path in after
    assert len(after) == len(before) + 1  # exactly one new file


def test_write_result_records_emitted_path_and_verdict(tmp_path: Path) -> None:
    """TC-126 — the returned ``CrcWriteResult`` carries the emitted path +
    ``written=True`` per region + the verify verdict (re-scoped LLR-003.5),
    so the I5b layer can assemble the ``OperationResult``."""
    payload = bytes(range(0x40, 0x60))
    op_input = _contiguous_op_input(0x1000, payload)
    region_a = CrcRegion(start=0x1000, end=0x1008, output_address=0x1010)
    region_b = CrcRegion(start=0x1008, end=0x1010, output_address=0x1014)
    config = _default_config([region_a, region_b])

    result = write_crc_image(op_input, config, workarea_base=tmp_path)

    assert result.written_path is not None
    assert result.written_path.name == "firmware-crc.s19"  # derived name
    assert result.verify_status == STATUS_VERIFIED
    assert len(result.crc_regions) == 2
    assert [r.output_address for r in result.crc_regions] == [0x1010, 0x1014]
    assert all(r.written is True for r in result.crc_regions)
    # The written CRC values are the engine's computed values (non-vacuous).
    assert result.crc_regions[0].computed_crc == compute_region_crc(
        op_input.mem_map, 0x1000, 0x1008
    )


def test_write_outside_workarea_collects_finding_and_writes_no_file(
    tmp_path: Path,
) -> None:
    """Containment — a forced target OUTSIDE the contained work area fails the
    real ``copy_into_workarea`` seam (``is_relative_to(workarea_root)`` +
    reparse-point checks); the result collects exactly 1 finding and NO file is
    written, with no exception raised (collect-don't-abort, LLR-003.2 / D-8)."""
    payload = bytes(range(0, 16))
    op_input = _contiguous_op_input(0x500, payload)
    region = CrcRegion(start=0x500, end=0x508, output_address=0x504)
    config = _default_config([region])

    # A directory OUTSIDE any .s19tool/workarea/ root.
    escape_dir = tmp_path / "outside"
    escape_dir.mkdir()

    result = write_crc_image(
        op_input, config, workarea_base=tmp_path, dest_dir=escape_dir
    )

    assert result.written_path is None
    assert result.verify_status is None
    assert len(result.findings) == 1
    # The finding names the real seam's exception (F-S-04 plain-text disclosure);
    # WorkareaContainmentError is what copy_into_workarea raised on the escape.
    assert "WorkareaContainmentError" in result.findings[0]
    # No file landed in the escape directory.
    assert list(escape_dir.iterdir()) == []
    # And nothing leaked into the work area beyond the cleaned-up temp.
    workarea_root = tmp_path / WORKAREA_DIRNAME / WORKAREA_SUBDIR
    emitted = [
        p
        for p in workarea_root.rglob("firmware-crc*.s19")
        if p.is_file()
    ]
    assert emitted == []


def _s19_data_record_widths(s19_text: str) -> list[int]:
    """Per-record DATA-byte count for every S1/S2/S3 data record in ``s19_text``.

    Each S-record line is ``S<type><count><address><data><checksum>``; the
    one-byte ``count`` field covers address + data + checksum bytes, so the
    data-byte width is ``count - address_bytes - 1`` (address bytes: S1=2, S2=3,
    S3=4). S0/S5/S7/S8/S9 framing records carry no data and are skipped.

    Args:
        s19_text (str): The full text of an emitted S19 file.

    Returns:
        list[int]: The data-byte width of each S1/S2/S3 data record, in file order.
    """
    addr_bytes_by_type = {"S1": 2, "S2": 3, "S3": 4}
    widths: list[int] = []
    for line in s19_text.splitlines():
        tag = line[:2]
        if tag in addr_bytes_by_type:
            count = int(line[2:4], 16)
            widths.append(count - addr_bytes_by_type[tag] - 1)
    return widths


def test_crc_write_emits_32_byte_records(tmp_path: Path) -> None:
    """#7 lock-AT — the CRC save path emits the fixed 32-byte S19 record width.

    Intent: ``write_crc_image`` serialises via
    ``emit_s19_from_mem_map(working_mem, working_ranges)`` (crc.py:879) with NO
    ``bytes_per_line`` argument, so it rides the emitter's default 32-byte width.
    The map oracle the other CRC tests re-read through
    (``S19File.get_memory_map``) flattens records and is WIDTH-AGNOSTIC, so today
    nothing observes the emitted record width on this path. This locks the actual
    contract: read the written ``.s19`` back as TEXT and assert its data records
    carry 32 data bytes — a value-discriminating lock (a regression emitting
    16-byte records makes ``max == 32`` fail with 16 != 32, QC-2). US-019 makes
    the width operator-selectable; this test now pins the DEFAULT branch (no width
    passed -> 32, the prior contract). The selected-16 path is covered by
    ``test_crc_write_emits_16_byte_records_when_selected`` (TC-019.1) and the
    through-ConfirmWriteScreen ``AT-019b`` in test_tui_crc_surface.py.
    """
    # 64 contiguous bytes -> two full 32-byte data records on the S1 path
    # (addresses <= 0xFFFF); a 4-byte CRC record is injected into the 0x200 gap.
    payload = bytes((0x10 + i) & 0xFF for i in range(0x40))
    op_input = _contiguous_op_input(0x100, payload)
    region = CrcRegion(start=0x100, end=0x120, output_address=0x200)
    config = _default_config([region])

    result = write_crc_image(op_input, config, workarea_base=tmp_path)

    assert result.written_path is not None and result.written_path.exists(), (
        f"the CRC write must land a file; findings={result.findings!r}"
    )
    widths = _s19_data_record_widths(
        result.written_path.read_text(encoding="utf-8")
    )
    assert widths, "the written .s19 must contain at least one data record"
    # The fixed contract: full data records are 32 bytes wide, none exceed it.
    assert 32 in widths, (
        f"the CRC save must emit a full 32-byte record; widths={widths}"
    )
    assert max(widths) == 32, (
        f"the CRC save's record width must be the fixed 32, not {max(widths)}; "
        f"widths={widths}"
    )


def test_crc_write_emits_16_byte_records_when_selected(tmp_path: Path) -> None:
    """TC-019.1 — write_crc_image honours a selected 16-byte record width.

    Intent (US-019 white-box): with ``bytes_per_line=16`` the written .s19's data
    records are 16 bytes wide, not the default 32 — and the default call (no
    kwarg) still emits 32 (back-compat). Read the written file back as TEXT and
    assert per-record data-byte width; value-discriminating (16 path must NOT
    leave any 32-byte record).
    """
    # Same 64-byte payload as the default test -> at 16-wide it yields four full
    # 16-byte records (plus the 4-byte injected CRC).
    payload = bytes((0x10 + i) & 0xFF for i in range(0x40))
    op_input = _contiguous_op_input(0x100, payload)
    region = CrcRegion(start=0x100, end=0x120, output_address=0x200)
    config = _default_config([region])

    result = write_crc_image(
        op_input, config, workarea_base=tmp_path, bytes_per_line=16
    )

    assert result.written_path is not None and result.written_path.exists(), (
        f"the CRC write must land a file; findings={result.findings!r}"
    )
    widths = _s19_data_record_widths(
        result.written_path.read_text(encoding="utf-8")
    )
    assert widths, "the written .s19 must contain at least one data record"
    assert 16 in widths, (
        f"a 16-byte selected width must emit a full 16-byte record; widths={widths}"
    )
    assert max(widths) == 16, (
        f"with bytes_per_line=16 no record may exceed 16 data bytes; widths={widths}"
    )


# ---------------------------------------------------------------------------
# batch-32 (R-CRC-GROUP-001 / R-CRC-WIDTH-001) - group check/inject/notes/
# report wiring (TC-203 family): AT-047a/b/c/f/g, AT-046a/b/d (operation
# halves), AT-045c note half, AT-044a golden compat, AT-044c shipped-path
# ordering, S-7 scope pin, AT-047d serializer.
# ---------------------------------------------------------------------------


def _groups_config(groups, regions=None) -> CrcConfig:
    """A :class:`CrcConfig` with groups (and optional legacy regions), zlib defaults."""
    return CrcConfig(
        regions=list(regions or []),
        polynomial=DEFAULT_POLYNOMIAL,
        init=DEFAULT_INIT,
        reverse=DEFAULT_REVERSE,
        final_xor=DEFAULT_FINAL_XOR,
        groups=list(groups),
    )


def test_at047a_mixed_check_per_target_verdicts_and_order(tmp_path: Path) -> None:
    """AT-047a + AT-044c (shipped check path): a mixed config reports one
    result per target - legacy region FIRST, then groups (file order) - with
    per-target matched True/False and each result carrying its
    output_address and output_bytes (TC-203.1)."""
    payload_a = bytes(range(0x40, 0x60))  # 32B @ 0x1000
    payload_b = bytes(range(0x80, 0x90))  # 16B @ 0x2000
    mem = _mem_from_bytes(0x1000, payload_a)
    mem.update(_mem_from_bytes(0x2000, payload_b))
    group_match_crc = zlib.crc32(payload_a[:8] + payload_b[:8])
    # Stored value for the MATCHING group (width 2 -> low 2 bytes) @ 0x3000.
    mem.update(_mem_from_bytes(0x3000, encode_le(group_match_crc, 2)))
    # Stored value for the MISMATCHING group @ 0x3010 (wrong bytes).
    mem.update(_mem_from_bytes(0x3010, b"\xde\xad\xbe\xef"))
    op_input = OperationInput(
        mem_map=mem, ranges=[(0x1000, 0x1020), (0x2000, 0x2010), (0x3000, 0x3014)],
        input_path=None, variant_id=None, file_type="s19",
    )
    config = _groups_config(
        groups=[
            CrcGroup(spans=((0x1000, 0x1008), (0x2000, 0x2008)),
                     output_address=0x3000, output_bytes=2),
            CrcGroup(spans=((0x2008, 0x2010),), output_address=0x3010,
                     output_bytes=4),
        ],
        regions=[CrcRegion(start=0x1000, end=0x1010, output_address=0x5000)],
    )
    results = check_regions(op_input, config)
    assert [r.output_address for r in results] == [0x5000, 0x3000, 0x3010]
    assert [r.output_bytes for r in results] == [4, 2, 4]
    legacy, grp_match, grp_mismatch = results
    assert legacy.matched is None  # nothing stored at 0x5000
    assert grp_match.matched is True
    assert grp_match.computed_crc == group_match_crc
    assert grp_mismatch.matched is False


def test_at045c_gap_note_names_group_and_count_legacy_stays_silent() -> None:
    """AT-045c (note half) + Q4/AT-044a branch: a gapped GROUP span emits ONE
    aggregate coverage note naming the group and absent count; a gapped
    LEGACY region in the same run emits nothing (TC-203.2)."""
    payload = bytes(range(0x20, 0x40))  # 32B @ 0x1000
    mem = _mem_from_bytes(0x1000, payload)
    del mem[0x1005]
    del mem[0x1006]
    op_input = OperationInput(
        mem_map=mem, ranges=[(0x1000, 0x1020)], input_path=None,
        variant_id=None, file_type="s19",
    )
    config = _groups_config(
        groups=[CrcGroup(spans=((0x1000, 0x1010),), output_address=0x4000,
                         output_bytes=4)],
        regions=[CrcRegion(start=0x1000, end=0x1010, output_address=0x5000)],
    )
    result = CrcOperation().execute(op_input, config=config)
    coverage_notes = [n for n in result.notes if "absent byte(s)" in n]
    assert len(coverage_notes) == 1, (
        f"exactly ONE coverage note (group only, never legacy); got {result.notes}"
    )
    assert "CRC group 1" in coverage_notes[0]
    assert "2 absent byte(s)" in coverage_notes[0]
    assert "present bytes only" in coverage_notes[0]


@pytest.mark.parametrize("width", [1, 2])
def test_at046b_truncation_note_per_narrow_width(width: int) -> None:
    """AT-046b (note half): width < 4 fires one truncation warning naming the
    target; widths 4/8 fire none (TC-203.3, parametrized per width)."""
    payload = bytes(range(0x10, 0x30))
    mem = _mem_from_bytes(0x1000, payload)
    op_input = OperationInput(
        mem_map=mem, ranges=[(0x1000, 0x1020)], input_path=None,
        variant_id=None, file_type="s19",
    )
    config = _groups_config(
        groups=[
            CrcGroup(spans=((0x1000, 0x1010),), output_address=0x4000,
                     output_bytes=width),
            CrcGroup(spans=((0x1010, 0x1020),), output_address=0x4010,
                     output_bytes=8),
        ]
    )
    result = CrcOperation().execute(op_input, config=config)
    trunc = [n for n in result.notes if "truncates the 32-bit CRC" in n]
    assert len(trunc) == 1
    assert "0x00004000" in trunc[0]
    assert f"output bytes {width}" in trunc[0]


def test_at047c_group_self_overlap_warns_and_completes() -> None:
    """AT-047c: a GROUP whose output window overlaps its own input span (by
    exactly 1 byte at span end, B10) warns with the self-overlap wording and
    the run still yields results for every target (TC-203.4)."""
    payload = bytes(range(0x10, 0x30))
    mem = _mem_from_bytes(0x1000, payload)
    op_input = OperationInput(
        mem_map=mem, ranges=[(0x1000, 0x1020)], input_path=None,
        variant_id=None, file_type="s19",
    )
    config = _groups_config(
        groups=[CrcGroup(spans=((0x1000, 0x1010),), output_address=0x100F,
                         output_bytes=4)]
    )
    result = CrcOperation().execute(op_input, config=config)
    own = [n for n in result.notes if "its own input span" in n]
    assert len(own) == 1 and "0x0000100F" in own[0]
    assert result.crc_regions is not None and len(result.crc_regions) == 1


def test_at047g_cross_target_overlap_distinct_warning() -> None:
    """AT-047g: a group's output window inside ANOTHER target's input span
    warns with the cross-target wording (distinct from self-overlap) and the
    run completes with all results (TC-203.5)."""
    payload = bytes(range(0x10, 0x50))
    mem = _mem_from_bytes(0x1000, payload)
    op_input = OperationInput(
        mem_map=mem, ranges=[(0x1000, 0x1040)], input_path=None,
        variant_id=None, file_type="s19",
    )
    config = _groups_config(
        groups=[
            CrcGroup(spans=((0x1000, 0x1010),), output_address=0x1020,
                     output_bytes=4),
            CrcGroup(spans=((0x1020, 0x1030),), output_address=0x5000,
                     output_bytes=4),
        ]
    )
    result = CrcOperation().execute(op_input, config=config)
    cross = [n for n in result.notes if "another target's input span" in n]
    assert len(cross) == 1 and "0x00001020" in cross[0]
    assert not any("its own input span" in n for n in result.notes)
    assert len(result.crc_regions) == 2


def test_s7_scope_pin_legacy_self_overlap_stays_silent() -> None:
    """S-7 scope pin (Phase-2 F-2) / AT-044a notes half: a LEGACY-only config
    whose output sits inside its own region (the committed dummy-config
    pattern) emits ZERO overlap/coverage/truncation notes - the notes list
    is exactly the legacy summary (TC-203.6)."""
    payload = bytes(range(0x10, 0x50))
    mem = _mem_from_bytes(0x1000, payload)
    op_input = OperationInput(
        mem_map=mem, ranges=[(0x1000, 0x1040)], input_path=None,
        variant_id=None, file_type="s19",
    )
    config = _default_config(
        [CrcRegion(start=0x1000, end=0x1040, output_address=0x103C)]
    )
    result = CrcOperation().execute(op_input, config=config)
    assert result.notes == [
        "CRC: 1 region(s): 0 matched, 1 mismatched, 0 no-stored-value"
    ]


def test_at047f_all_computes_precede_all_writes(tmp_path: Path) -> None:
    """AT-047f / S-6: when target 1's output window lies INSIDE target 2's
    input span (and target 1 is evaluated first per the Q3 order - the m-5
    precondition), target 2's computed CRC and injected bytes reflect the
    ORIGINAL pristine bytes, not target 1's write (TC-203.7). A naive
    compute-inject-compute loop fails this."""
    payload = bytes(range(0x10, 0x50))  # 64B @ 0x1000
    mem = _mem_from_bytes(0x1000, payload)
    op_input = OperationInput(
        mem_map=mem, ranges=[(0x1000, 0x1040)], input_path=None,
        variant_id=None, file_type="s19",
    )
    # Group 1 (evaluated first) writes INTO [0x1020, 0x1024) - inside
    # group 2's span [0x1020, 0x1030).
    config = _groups_config(
        groups=[
            CrcGroup(spans=((0x1000, 0x1010),), output_address=0x1020,
                     output_bytes=4),
            CrcGroup(spans=((0x1020, 0x1030),), output_address=0x5000,
                     output_bytes=4),
        ]
    )
    pristine_g2 = zlib.crc32(payload[0x20:0x30])
    results = check_regions(op_input, config)
    assert results[1].computed_crc == pristine_g2
    working_mem, _ranges, written = inject_crcs(op_input, results)
    injected_g2 = bytes(working_mem[0x5000 + i] for i in range(4))
    assert injected_g2 == encode_le(pristine_g2, 4), (
        "target 2's injected value must be the pristine-input CRC"
    )


def test_at046a_inject_width8_zero_extends_and_extends_ranges() -> None:
    """AT-046a: width 8 writes exactly 8 LE bytes (low 4 = CRC, high 4 =
    0x00) at a gapped output and the working ranges gain [out, out+8)
    (TC-203.8; B7/B9 in-gap extension at width != 4)."""
    payload = bytes(range(0x10, 0x30))
    mem = _mem_from_bytes(0x1000, payload)
    op_input = OperationInput(
        mem_map=mem, ranges=[(0x1000, 0x1020)], input_path=None,
        variant_id=None, file_type="s19",
    )
    config = _groups_config(
        groups=[CrcGroup(spans=((0x1000, 0x1020),), output_address=0x2000,
                         output_bytes=8)]
    )
    results = check_regions(op_input, config)
    working_mem, working_ranges, written = inject_crcs(op_input, results)
    new_keys = set(working_mem) - set(op_input.mem_map)
    assert new_keys == set(range(0x2000, 0x2008))
    crc = zlib.crc32(payload)
    assert bytes(working_mem[0x2000 + i] for i in range(8)) == encode_le(crc, 8)
    assert bytes(working_mem[0x2004 + i] for i in range(4)) == b"\x00" * 4
    assert (0x2000, 0x2008) in working_ranges
    assert written[0].written is True and written[0].output_bytes == 8


def test_at046d_check_absent_stored_byte_tri_state_operation_half() -> None:
    """AT-046d (operation half): one absent byte of the N stored bytes on
    check yields stored_value None / matched None without raising
    (TC-203.9)."""
    payload = bytes(range(0x10, 0x30))
    mem = _mem_from_bytes(0x1000, payload)
    mem.update(_mem_from_bytes(0x2000, b"\x01\x02\x03\x04\x05\x06\x07"))  # 7 of 8
    op_input = OperationInput(
        mem_map=mem, ranges=[(0x1000, 0x1020), (0x2000, 0x2007)],
        input_path=None, variant_id=None, file_type="s19",
    )
    config = _groups_config(
        groups=[CrcGroup(spans=((0x1000, 0x1020),), output_address=0x2000,
                         output_bytes=8)]
    )
    result = check_regions(op_input, config)[0]
    assert result.stored_value is None and result.matched is None


def test_at047b_write_reread_groups_c12(tmp_path: Path) -> None:
    """AT-047b - the C-12 output-then-consume joined node (TC-203.10):
    drive the SHIPPED write_crc_image path with a MIXED legacy+groups config
    (one group width 8, one width 2 - the m-6 non-default-width pin), take
    the emitted path FROM THE RESULT, re-read with a fresh S19File parse,
    and decode exactly output_bytes LE bytes at each target's output
    address, asserting equality against BOTH the run's computed_crc AND an
    independent zlib oracle; verify_status is verified on the same result.
    """
    payload = bytes(range(0x10, 0x50))  # 64B @ 0x1000
    op_input = _contiguous_op_input(0x1000, payload)
    config = _groups_config(
        groups=[
            CrcGroup(spans=((0x1000, 0x1010), (0x1020, 0x1030)),
                     output_address=0x2000, output_bytes=8),
            CrcGroup(spans=((0x1030, 0x1040),), output_address=0x2010,
                     output_bytes=2),
        ],
        regions=[CrcRegion(start=0x1000, end=0x1020, output_address=0x2020)],
    )
    result = write_crc_image(op_input, config, workarea_base=tmp_path)
    assert result.written_path is not None and result.written_path.exists()
    assert result.verify_status == STATUS_VERIFIED

    reread = S19File(str(result.written_path)).get_memory_map()

    oracle_g1 = zlib.crc32(payload[0x00:0x10] + payload[0x20:0x30])
    oracle_g2 = zlib.crc32(payload[0x30:0x40]) & 0xFFFF
    oracle_legacy = zlib.crc32(payload[0x00:0x20])
    expectations = [
        (0x2020, 4, oracle_legacy),   # legacy first (result order)
        (0x2000, 8, oracle_g1),
        (0x2010, 2, oracle_g2),
    ]
    by_addr = {r.output_address: r for r in result.crc_regions}
    for addr, width, oracle in expectations:
        stored = bytes(reread[addr + i] for i in range(width))
        assert stored == encode_le(oracle, width), (
            f"on-disk bytes at 0x{addr:X} must decode to the oracle CRC"
        )
        run_result = by_addr[addr]
        mask = (1 << (8 * width)) - 1
        assert (run_result.computed_crc & mask) == oracle
        assert run_result.output_bytes == width


def test_at044a_legacy_gapped_golden_compat(tmp_path: Path) -> None:
    """AT-044a - the compat pin (must PASS pre- and post-change): a
    legacy-only config over a GAPPED region produces the FROZEN golden
    results (literal values derived from the independent zlib oracle at
    authoring time, never recomputed through the pipeline under test),
    exactly the one summary note (zero new notes - the Q4 branch), the
    unchanged serializer keys, and a verified on-disk write whose stored
    bytes decode to the golden (TC-203.11)."""
    payload = bytes(range(0x10, 0x50))  # 64B @ 0x1000
    mem = _mem_from_bytes(0x1000, payload)
    del mem[0x1015]  # the gap: legacy path must stay SILENT about it
    # Ranges reflect the gap (the parse layer derives ranges from present
    # keys; emit_s19_from_mem_map requires every in-range address present).
    op_input = OperationInput(
        mem_map=mem, ranges=[(0x1000, 0x1015), (0x1016, 0x1040)],
        input_path=None, variant_id=None, file_type="s19",
    )
    config = _default_config(
        [CrcRegion(start=0x1000, end=0x1020, output_address=0x1038)]
    )
    # FROZEN golden: zlib.crc32 over the 31 present bytes of [0x1000,0x1020)
    # (the gap at 0x1015 is payload offset 0x15).
    golden = zlib.crc32(payload[0x00:0x15] + payload[0x16:0x20])

    result = CrcOperation().execute(op_input, config=config)
    assert result.notes == [
        "CRC: 1 region(s): 0 matched, 1 mismatched, 0 no-stored-value"
    ]
    entry = result.crc_regions[0]
    assert entry.computed_crc == golden
    assert entry.output_bytes == 4  # legacy default
    serialized = result.to_dict()["crc_regions"][0]
    assert set(serialized) == {
        "output_address", "computed_crc", "stored_value", "matched",
        "written", "output_bytes",
    }

    write_result = write_crc_image(op_input, config, workarea_base=tmp_path)
    assert write_result.verify_status == STATUS_VERIFIED
    reread = S19File(str(write_result.written_path)).get_memory_map()
    assert bytes(reread[0x1038 + i] for i in range(4)) == encode_le(golden, 4)
