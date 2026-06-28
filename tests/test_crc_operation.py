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
    encode_le32,
    inject_crcs,
    read_stored_crc_le,
    write_crc_image,
)
from s19_app.tui.operations.crc_config import CrcConfig, CrcRegion
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
