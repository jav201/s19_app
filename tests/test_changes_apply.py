"""
TC-009..TC-013 + TC-051 (engine half) — v2 apply engine, change summary, and
S19 save-back (LLR-002.1/.2/.3/.5/.7).

Covers: the apply gate (ERROR issues and ``kind`` ≠ ``"change"`` → zero
writes, all ``blocked``), all five dispositions, exact before/after byte
tuples with outside-keys-unchanged, the §6.2 C-6 summary shape with
serialization determinism under an injected fixed clock (B-4), the
``emit_s19_from_mem_map`` re-parse acceptance contract, and the F-S-01
save-back filename containment (engine half; the TUI prompt rides E3a).
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

import pytest

from s19_app.core import S19File
from s19_app.hexfile import IntelHexFile
from s19_app.tui.changes import (
    DISPOSITION_DOMAIN,
    FORMAT_ID,
    FORMAT_VERSION,
    MF_WRITE_CONTAINMENT,
    STATUS_MISMATCH,
    STATUS_VERIFIED,
    ChangeDocument,
    ChangeEntry,
    apply_change_document,
    collision_issues,
    emit_s19_from_mem_map,
    save_patched_image,
    verify_written_image,
)
import s19_app.tui.changes.apply as apply_module
import s19_app.tui.changes.io as io_module
from s19_app.tui.workspace import ensure_workarea

EXAMPLE_S19 = (
    Path(__file__).resolve().parents[1] / "examples" / "case_00_public" / "prg.s19"
)

IMAGE_RANGES = [(0x100, 0x110), (0x120, 0x130)]

FIXED_CLOCK = lambda: datetime(2026, 6, 10, 12, 0, 0, tzinfo=timezone.utc)  # noqa: E731


def _document(
    entries: list[ChangeEntry],
    *,
    kind: str = "change",
    issues: list | None = None,
) -> ChangeDocument:
    return ChangeDocument(
        format=FORMAT_ID,
        version=FORMAT_VERSION,
        kind=kind,
        encoding="utf-8",
        value_mode="text",
        entries=entries,
        issues=list(issues or []),
    )


def _image_mem_map() -> dict[int, int]:
    mem_map = {address: address & 0xFF for address in range(0x100, 0x110)}
    mem_map.update({address: 0x55 for address in range(0x120, 0x130)})
    return mem_map


# ---------------------------------------------------------------------------
# TC-009 — apply gate (LLR-002.1).
# ---------------------------------------------------------------------------


def test_error_blocks_apply_zero_writes_all_blocked() -> None:
    colliding = [
        ChangeEntry("bytes", 0x100, (0x01, 0x02, 0x03, 0x04)),
        ChangeEntry("bytes", 0x102, (0x05, 0x06)),
    ]
    document = _document(colliding, issues=collision_issues(colliding))
    assert document.has_errors
    mem_map = _image_mem_map()
    before = dict(mem_map)

    summary = apply_change_document(document, mem_map, IMAGE_RANGES, None, None)

    assert mem_map == before
    assert summary.counts == {
        "applied": 0,
        "skipped-partial": 0,
        "skipped-outside": 0,
        "skipped-no-image": 0,
        "blocked": 2,
    }
    assert all(entry.disposition == "blocked" for entry in summary.entries)
    assert all(entry.before_bytes is None for entry in summary.entries)
    # LLR-002.8: the document's declaration faults ride on the summary.
    assert [issue.code for issue in summary.issues] == [
        "CHG-COLLISION",
        "CHG-COLLISION",
    ]


def test_non_change_kind_blocks_apply() -> None:
    document = _document(
        [ChangeEntry("bytes", 0x100, (0xAA,))], kind="check"
    )
    assert not document.has_errors
    mem_map = _image_mem_map()
    before = dict(mem_map)

    summary = apply_change_document(document, mem_map, IMAGE_RANGES, None, None)

    assert mem_map == before
    assert summary.counts["blocked"] == 1
    assert summary.counts["applied"] == 0
    assert summary.entries[0].disposition == "blocked"


# ---------------------------------------------------------------------------
# TC-010 — per-entry dispositions (LLR-002.2).
# ---------------------------------------------------------------------------


def test_dispositions_inside_partial_outside() -> None:
    document = _document(
        [
            ChangeEntry("bytes", 0x100, (0xAA, 0xBB)),  # INSIDE
            ChangeEntry("bytes", 0x10E, (0x01, 0x02, 0x03, 0x04)),  # PARTIAL
            ChangeEntry("bytes", 0x200, (0xFF,)),  # OUTSIDE
        ]
    )
    mem_map = _image_mem_map()

    summary = apply_change_document(document, mem_map, IMAGE_RANGES, None, None)

    assert [entry.disposition for entry in summary.entries] == [
        "applied",
        "skipped-partial",
        "skipped-outside",
    ]
    assert summary.counts == {
        "applied": 1,
        "skipped-partial": 1,
        "skipped-outside": 1,
        "skipped-no-image": 0,
        "blocked": 0,
    }
    # Only the INSIDE entry was written.
    assert (mem_map[0x100], mem_map[0x101]) == (0xAA, 0xBB)
    assert mem_map[0x10E] == 0x0E and mem_map[0x10F] == 0x0F
    assert 0x200 not in mem_map


def test_disposition_no_image() -> None:
    document = _document([ChangeEntry("bytes", 0x100, (0xAA,))])

    summary = apply_change_document(document, None, None, None, None)

    assert summary.entries[0].disposition == "skipped-no-image"
    assert summary.counts["skipped-no-image"] == 1
    assert summary.entries[0].before_bytes is None


# ---------------------------------------------------------------------------
# TC-011 — before-capture and write (LLR-002.3).
# ---------------------------------------------------------------------------


def test_before_after_capture_exact_tuples_outside_keys_unchanged() -> None:
    document = _document([ChangeEntry("bytes", 0x104, (0xAA, 0xBB))])
    mem_map = _image_mem_map()
    untouched_expected = {
        address: value
        for address, value in _image_mem_map().items()
        if address not in (0x104, 0x105)
    }

    summary = apply_change_document(document, mem_map, IMAGE_RANGES, None, None)

    entry = summary.entries[0]
    assert entry.before_bytes == (0x04, 0x05)
    assert entry.after_bytes == (0xAA, 0xBB)
    assert (mem_map[0x104], mem_map[0x105]) == (0xAA, 0xBB)
    # Re-reading the written range yields exactly after_bytes (LLR-002.3).
    assert tuple(mem_map[a] for a in range(0x104, 0x106)) == entry.after_bytes
    # Every key outside the applied range is byte-identical.
    assert {
        address: value
        for address, value in mem_map.items()
        if address not in (0x104, 0x105)
    } == untouched_expected


# ---------------------------------------------------------------------------
# TC-012/TC-013 — summary shape + serialization determinism (LLR-002.5, B-4).
# ---------------------------------------------------------------------------


def test_summary_shape_and_serialization_determinism() -> None:
    def build_document() -> ChangeDocument:
        return _document(
            [
                ChangeEntry("string", 0x100, (0x36, 0x38), value="68"),
                ChangeEntry("bytes", 0x200, (0xFF,)),
            ]
        )

    base_mem = _image_mem_map()
    mem_one = deepcopy(base_mem)
    mem_two = deepcopy(base_mem)

    summary = apply_change_document(
        build_document(), mem_one, IMAGE_RANGES, None, None,
        now_fn=FIXED_CLOCK, variant_id="variant-a",
    )

    # --- C-6 field assertions (>= 12) -------------------------------------
    assert summary.source_path is None
    assert summary.kind == "change"
    assert summary.encoding == "utf-8"
    assert summary.value_mode == "text"
    assert summary.timestamp_utc == "2026-06-10T12:00:00+00:00"
    assert summary.variant_id == "variant-a"
    assert set(summary.counts) == set(DISPOSITION_DOMAIN)
    assert summary.counts["applied"] == 1
    assert summary.counts["skipped-outside"] == 1
    assert summary.saved_path is None
    assert summary.issues == []
    first, second = summary.entries
    assert first.entry_type == "string"
    assert (first.address_start, first.address_end) == (0x100, 0x102)
    assert first.before_bytes == (0x00, 0x01)
    assert first.after_bytes == (0x36, 0x38)
    assert first.disposition == "applied"
    assert first.linkage == "standalone"
    assert first.linkage_symbol is None
    assert second.disposition == "skipped-outside"

    # --- determinism: same object, two to_dict() calls ---------------------
    assert summary.to_dict() == summary.to_dict()

    # --- determinism: second apply over an independent deep copy -----------
    summary_two = apply_change_document(
        build_document(), mem_two, IMAGE_RANGES, None, None,
        now_fn=FIXED_CLOCK, variant_id="variant-a",
    )
    assert summary.to_dict() == summary_two.to_dict()
    assert mem_one == mem_two

    # to_dict is JSON-shaped: counts in canonical order, entries in document
    # order, byte tuples as lists.
    payload = summary.to_dict()
    assert list(payload["counts"]) == list(DISPOSITION_DOMAIN)
    assert payload["entries"][0]["before_bytes"] == [0x00, 0x01]
    assert payload["entries"][0]["after_bytes"] == [0x36, 0x38]
    assert payload["timestamp_utc"] == "2026-06-10T12:00:00+00:00"


# ---------------------------------------------------------------------------
# TC-051 (engine half) — S19 emitter acceptance (LLR-002.7).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("mem_map", "expected_data_prefix"),
    [
        pytest.param(
            {address: address & 0xFF for address in range(0x100, 0x125)},
            "S1",
            id="16-bit-addresses-emit-s1",
        ),
        pytest.param(
            {0x80001000 + offset: offset & 0xFF for offset in range(0x21)},
            "S3",
            id="32-bit-addresses-emit-s3",
        ),
    ],
)
def test_emit_s19_reparses_to_equal_mem_map(
    tmp_path: Path, mem_map: dict[int, int], expected_data_prefix: str
) -> None:
    addresses = sorted(mem_map)
    ranges = [(addresses[0], addresses[-1] + 1)]

    text = emit_s19_from_mem_map(mem_map, ranges)

    data_lines = [line for line in text.splitlines() if not line.startswith("S0")][:-1]
    assert data_lines and all(
        line.startswith(expected_data_prefix) for line in data_lines
    )
    target = tmp_path / "emitted.s19"
    target.write_text(text, encoding="ascii")
    reparsed = S19File(str(target))
    assert reparsed.get_errors() == []
    assert reparsed.get_memory_map() == mem_map


def test_emit_s19_roundtrips_public_example_file(tmp_path: Path) -> None:
    original = S19File(str(EXAMPLE_S19))
    mem_map = original.get_memory_map()
    ranges = original.get_memory_ranges()

    text = emit_s19_from_mem_map(mem_map, ranges)
    target = tmp_path / "roundtrip.s19"
    target.write_text(text, encoding="ascii")

    reparsed = S19File(str(target))
    assert reparsed.get_errors() == []
    assert reparsed.get_memory_map() == mem_map


# ---------------------------------------------------------------------------
# TC-051 (engine half) — save-back containment + refusals (LLR-002.7/F-S-01).
# ---------------------------------------------------------------------------


def _project_dir(tmp_path: Path) -> Path:
    workarea = ensure_workarea(tmp_path)
    return workarea / "proj"


def test_save_back_written_file_reparses_to_post_apply_map(
    tmp_path: Path,
) -> None:
    document = _document([ChangeEntry("bytes", 0x104, (0xAA, 0xBB))])
    mem_map = _image_mem_map()
    summary = apply_change_document(document, mem_map, IMAGE_RANGES, None, None)
    assert summary.counts["applied"] == 1
    dest_dir = _project_dir(tmp_path)

    saved_path, issues = save_patched_image(
        mem_map, IMAGE_RANGES, dest_dir, "patched.s19", source_kind="s19"
    )

    assert issues == []
    assert saved_path is not None
    assert saved_path.is_file()
    assert dest_dir.resolve() in saved_path.resolve().parents
    reparsed = S19File(str(saved_path))
    assert reparsed.get_errors() == []
    assert reparsed.get_memory_map() == mem_map
    # LLR-002.7 linkage: the caller records the path on the summary.
    summary.saved_path = saved_path
    assert summary.to_dict()["saved_path"] == str(saved_path)


def test_save_back_declined_saved_path_none_and_no_file(tmp_path: Path) -> None:
    document = _document([ChangeEntry("bytes", 0x104, (0xAA,))])
    mem_map = _image_mem_map()
    dest_dir = _project_dir(tmp_path)

    summary = apply_change_document(document, mem_map, IMAGE_RANGES, None, None)

    # Operator declined: save_patched_image is never invoked — the summary
    # keeps its default and the project directory holds no image file.
    assert summary.saved_path is None
    assert summary.to_dict()["saved_path"] is None
    if dest_dir.exists():
        assert list(dest_dir.glob("*.s19")) == []


@pytest.mark.parametrize(
    "hostile_name",
    [
        pytest.param("..\\escape.s19", id="relative-traversal"),
        pytest.param("C:\\Windows\\Temp\\escape.s19", id="absolute-drive-path"),
        pytest.param("CON.s19", id="windows-reserved-device"),
        pytest.param("escape.s19.", id="trailing-dot"),
    ],
)
def test_save_back_adversarial_filenames_contained_or_refused(
    tmp_path: Path, hostile_name: str
) -> None:
    mem_map = _image_mem_map()
    dest_dir = _project_dir(tmp_path)

    saved_path, issues = save_patched_image(
        mem_map, IMAGE_RANGES, dest_dir, hostile_name, source_kind="s19"
    )

    if saved_path is None:
        assert [issue.code for issue in issues] == [MF_WRITE_CONTAINMENT]
    else:
        assert issues == []
        assert dest_dir.resolve() in saved_path.resolve().parents
    # Whatever the outcome, nothing landed outside the work area.
    assert not (tmp_path / "escape.s19").exists()
    assert not (tmp_path / ".s19tool" / "escape.s19").exists()


def test_save_back_unsupported_source_refused_with_clear_issue(
    tmp_path: Path,
) -> None:
    """TC-006 — a non-(s19|hex) source is still refused; no file written.

    Intent: LLR-002.2 — the ``CHG-HEX-SAVE-UNSUPPORTED`` code stays defined
    and refuses any source that is neither ``"s19"`` nor ``"hex"`` (here
    ``"mac"``), with zero writes; only HEX was promoted, not everything.
    """
    mem_map = _image_mem_map()
    dest_dir = _project_dir(tmp_path)

    saved_path, issues = save_patched_image(
        mem_map, IMAGE_RANGES, dest_dir, "patched.mac", source_kind="mac"
    )

    assert saved_path is None
    assert len(issues) == 1
    assert issues[0].code == "CHG-HEX-SAVE-UNSUPPORTED"
    assert "not supported" in issues[0].message
    if dest_dir.exists():
        assert list(dest_dir.glob("*")) == []


# ---------------------------------------------------------------------------
# TC-005/TC-006 — HEX save-back (LLR-002.1/002.2) — engine half.
# ---------------------------------------------------------------------------


def test_hex_save_writes_hex_file_that_reparses_to_post_apply_map(
    tmp_path: Path,
) -> None:
    """TC-005 — a HEX source writes one .hex file re-reading to the map.

    Intent: LLR-002.1 — a ``"hex"`` source is NOT refused; it serializes via
    ``emit_intel_hex_from_mem_map``, lands a ``.hex`` file inside the work
    area, and ``IntelHexFile`` re-reads it to the intended post-apply map.
    """
    document = _document([ChangeEntry("bytes", 0x104, (0xAA, 0xBB))])
    mem_map = _image_mem_map()
    summary = apply_change_document(document, mem_map, IMAGE_RANGES, None, None)
    assert summary.counts["applied"] == 1
    dest_dir = _project_dir(tmp_path)

    saved_path, issues = save_patched_image(
        mem_map, IMAGE_RANGES, dest_dir, "patched.hex", source_kind="hex"
    )

    assert issues == []
    assert saved_path is not None
    assert saved_path.is_file()
    assert saved_path.suffix == ".hex"
    assert dest_dir.resolve() in saved_path.resolve().parents
    reparsed = IntelHexFile(str(saved_path))
    assert reparsed.get_errors() == []
    assert reparsed.memory == mem_map


def test_hex_save_forces_hex_suffix_when_name_lacks_it(tmp_path: Path) -> None:
    """TC-005 — the sanitizer forces .hex on the HEX branch (m-7).

    Intent: LLR-002.1 — a suffix-less (or wrong-suffix) name on a HEX save
    is normalized to ``.hex`` by the one parametric sanitizer, not by a
    forked HEX-only path.
    """
    mem_map = _image_mem_map()
    dest_dir = _project_dir(tmp_path)

    saved_path, issues = save_patched_image(
        mem_map, IMAGE_RANGES, dest_dir, "patched", source_kind="hex"
    )

    assert issues == []
    assert saved_path is not None
    assert saved_path.name == "patched.hex"


def test_s19_save_still_forces_s19_suffix(tmp_path: Path) -> None:
    """TC-007 — the default suffix stays .s19 for an S19 source.

    Intent: LLR-002.1 AC — making the sanitizer parametric must not change
    the S19 default: a suffix-less S19 save still becomes ``.s19``.
    """
    mem_map = _image_mem_map()
    dest_dir = _project_dir(tmp_path)

    saved_path, issues = save_patched_image(
        mem_map, IMAGE_RANGES, dest_dir, "patched", source_kind="s19"
    )

    assert issues == []
    assert saved_path is not None
    assert saved_path.name == "patched.s19"


@pytest.mark.parametrize(
    "hostile_name",
    [
        pytest.param("..\\escape.hex", id="relative-traversal"),
        pytest.param("C:\\Windows\\Temp\\escape.hex", id="absolute-drive-path"),
        pytest.param("CON.hex", id="windows-reserved-device"),
        pytest.param("escape.hex.", id="trailing-dot"),
    ],
)
def test_hex_save_adversarial_filenames_contained_or_refused(
    tmp_path: Path, hostile_name: str
) -> None:
    """TC-005 — the three rejection rules still hold on the HEX branch.

    Intent: LLR-002.1 AC — traversal, reserved device names, and trailing
    dot/space are rejected the same way for ``.hex`` as for ``.s19`` (the
    rules live unforked in one sanitizer); nothing escapes the work area.
    """
    mem_map = _image_mem_map()
    dest_dir = _project_dir(tmp_path)

    saved_path, issues = save_patched_image(
        mem_map, IMAGE_RANGES, dest_dir, hostile_name, source_kind="hex"
    )

    if saved_path is None:
        assert [issue.code for issue in issues] == [MF_WRITE_CONTAINMENT]
    else:
        assert issues == []
        assert saved_path.suffix == ".hex"
        assert dest_dir.resolve() in saved_path.resolve().parents
    assert not (tmp_path / "escape.hex").exists()
    assert not (tmp_path / ".s19tool" / "escape.hex").exists()


# ---------------------------------------------------------------------------
# TC-010 — verify-on-save wired in, collect-don't-abort (LLR-003.3).
# ---------------------------------------------------------------------------


def test_verify_written_hex_image_is_verified(tmp_path: Path) -> None:
    """TC-010 — a faithful HEX write verifies clean against the intended map.

    Intent: LLR-003.3 — re-reading the just-written .hex and diffing it
    against the intended map yields an empty diff and status ``verified``.
    """
    mem_map = _image_mem_map()
    dest_dir = _project_dir(tmp_path)
    saved_path, issues = save_patched_image(
        mem_map, IMAGE_RANGES, dest_dir, "patched.hex", source_kind="hex"
    )
    assert saved_path is not None and issues == []

    result = verify_written_image(saved_path, mem_map, "hex")

    assert result.status == STATUS_VERIFIED
    assert result.runs == []


def test_verify_on_dropped_byte_is_mismatch_file_kept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TC-010 — an emitter that DROPS a byte yields a mismatch; file kept.

    Intent: LLR-003.3 — inject an emitter dropping one address; the file is
    still written (collect-don't-abort), and verifying it against the
    intended map yields exactly one ``only_a`` run of length 1 (the dropped
    byte is absent from re-read map B, so it classifies ``only_a``).
    """
    mem_map = _image_mem_map()
    dest_dir = _project_dir(tmp_path)
    dropped_addr = 0x104

    real_emit = apply_module.emit_intel_hex_from_mem_map

    def _dropping_emit(map_arg, ranges_arg):
        trimmed = {a: v for a, v in map_arg.items() if a != dropped_addr}
        trimmed_ranges = []
        for s, e in ranges_arg:
            if s <= dropped_addr < e:
                # Split the range so ONLY the dropped address is omitted.
                if s < dropped_addr:
                    trimmed_ranges.append((s, dropped_addr))
                if dropped_addr + 1 < e:
                    trimmed_ranges.append((dropped_addr + 1, e))
            else:
                trimmed_ranges.append((s, e))
        return real_emit(trimmed, trimmed_ranges)

    monkeypatch.setitem(
        apply_module._SAVE_BACK_EMITTERS, "hex", (_dropping_emit, ".hex")
    )

    saved_path, issues = save_patched_image(
        mem_map, IMAGE_RANGES, dest_dir, "patched.hex", source_kind="hex"
    )
    assert saved_path is not None and saved_path.is_file()

    result = verify_written_image(saved_path, mem_map, "hex")

    assert saved_path.is_file()  # collect-don't-abort: file not unlinked
    assert result.status == STATUS_MISMATCH
    assert len(result.runs) == 1
    assert result.runs[0].kind == "only_a"
    assert result.runs[0].length == 1


# ---------------------------------------------------------------------------
# US-015 / LLR-015.1/.2/.4 — selectable record width + populated S0 header.
# Reader-as-oracle: re-parse every emission via the frozen ``S19File``.
# ---------------------------------------------------------------------------


def _wide_mem_map() -> dict[int, int]:
    """A single contiguous 80-byte 32-bit-address image (forces S3, >2 rows)."""
    return {0x80001000 + offset: offset & 0xFF for offset in range(80)}


def _data_byte_counts(text: str) -> list[int]:
    """Data-byte length of every S1/S2/S3 data record in ``text``."""
    counts = []
    for line in text.splitlines():
        if line[:2] in ("S1", "S2", "S3"):
            byte_count = int(line[2:4], 16)
            address_length = {"S1": 2, "S2": 3, "S3": 4}[line[:2]]
            counts.append(byte_count - address_length - 1)
    return counts


def test_tc212_default_emit_packs_32_byte_rows() -> None:
    """TC-212 — default (omitted) width packs ≤32-byte rows, ≥1 row >16."""
    mem_map = _wide_mem_map()
    ranges = [(0x80001000, 0x80001000 + 80)]

    text = emit_s19_from_mem_map(mem_map, ranges)

    counts = _data_byte_counts(text)
    assert counts, "expected at least one data record"
    assert all(count <= 32 for count in counts)
    assert any(count > 16 for count in counts)


def test_tc213_bytes_per_line_16_back_compat_byte_identical() -> None:
    """TC-213 — bpl=16 output is byte-identical to the legacy framing."""
    mem_map = _wide_mem_map()
    ranges = [(0x80001000, 0x80001000 + 80)]

    # Build the legacy expectation directly from the same record builder, in
    # explicit 16-byte rows — this is what the pre-change emitter produced.
    expected_lines = [io_module._s19_record("S0", 2, 0, ())]
    for row_start in range(0x80001000, 0x80001000 + 80, 16):
        row_end = min(row_start + 16, 0x80001000 + 80)
        data = tuple(mem_map[addr] for addr in range(row_start, row_end))
        expected_lines.append(io_module._s19_record("S3", 4, row_start, data))
    expected_lines.append(io_module._s19_record("S7", 4, 0, ()))
    expected = "\n".join(expected_lines) + "\n"

    text = emit_s19_from_mem_map(mem_map, ranges, bytes_per_line=16)

    assert text == expected
    assert all(count <= 16 for count in _data_byte_counts(text))


@pytest.mark.parametrize("bad_width", [0, 24, 64])
def test_tc214_invalid_bytes_per_line_raises_and_emits_nothing(
    bad_width: int,
) -> None:
    """TC-214 — bpl ∉ {16,32} raises ValueError before any record is built."""
    mem_map = _wide_mem_map()
    ranges = [(0x80001000, 0x80001000 + 80)]

    with pytest.raises(ValueError):
        emit_s19_from_mem_map(mem_map, ranges, bytes_per_line=bad_width)


def _data_record_map(s19: S19File) -> dict[int, int]:
    """Memory map from S1/S2/S3 data records ONLY (excludes S0 / terminators).

    ``S19File.get_memory_map`` (``core.py:485``) folds EVERY record's data —
    including the S0 header at address 0 — into the map, so a populated S0
    contributes low-address keys. The firmware payload is the data records;
    this helper isolates it for S0-inertness assertions (premise correction,
    §6.5 amendment).
    """
    mem_map: dict[int, int] = {}
    for record in s19.records:
        if record.type in ("S1", "S2", "S3"):
            for offset, byte in enumerate(record.data):
                mem_map[record.address + offset] = byte
    return mem_map


def test_tc215_populated_s0_is_inert_to_data_and_empty_when_none(
    tmp_path: Path,
) -> None:
    """TC-215 — s0_header populates an S0 that is inert to the firmware data
    records; s0_header=None keeps the empty S0.

    NOTE (§6.5 premise correction): the frozen reader's ``get_memory_map``
    folds S0 data into the map, so "inert" is asserted against the DATA-record
    map, not the full ``get_memory_map`` (which the spec's "+0 addresses"
    threshold assumed). The S0 sits at address 0 and never collides with the
    high-address firmware payload.
    """
    mem_map = _wide_mem_map()
    ranges = [(0x80001000, 0x80001000 + 80)]
    header = b"MODULE_X v1.0"

    populated = emit_s19_from_mem_map(mem_map, ranges, s0_header=header)
    s0_line = next(line for line in populated.splitlines() if line.startswith("S0"))
    s0_byte_count = int(s0_line[2:4], 16)
    assert s0_byte_count - 2 - 1 == len(header)  # S0 data field non-empty

    target = tmp_path / "populated.s19"
    target.write_text(populated, encoding="ascii")
    reparsed = S19File(str(target))
    assert reparsed.get_errors() == []
    assert _data_record_map(reparsed) == mem_map  # S0 adds 0 DATA addresses

    empty = emit_s19_from_mem_map(mem_map, ranges, s0_header=None)
    empty_s0 = next(line for line in empty.splitlines() if line.startswith("S0"))
    assert int(empty_s0[2:4], 16) - 2 - 1 == 0  # empty S0 data field


def test_tc216_32_byte_emit_reparses_byte_equal(tmp_path: Path) -> None:
    """TC-216 — 32-byte emit re-parses to a map byte-equal to the intended."""
    mem_map = _wide_mem_map()
    ranges = [(0x80001000, 0x80001000 + 80)]

    text = emit_s19_from_mem_map(mem_map, ranges, bytes_per_line=32)
    target = tmp_path / "w32.s19"
    target.write_text(text, encoding="ascii")

    reparsed = S19File(str(target))
    assert reparsed.get_errors() == []
    assert reparsed.get_memory_map() == mem_map


def test_tc217_16_byte_emit_reparses_byte_equal(tmp_path: Path) -> None:
    """TC-217 — 16-byte emit re-parses to a map byte-equal to the intended."""
    mem_map = _wide_mem_map()
    ranges = [(0x80001000, 0x80001000 + 80)]

    text = emit_s19_from_mem_map(mem_map, ranges, bytes_per_line=16)
    target = tmp_path / "w16.s19"
    target.write_text(text, encoding="ascii")

    reparsed = S19File(str(target))
    assert reparsed.get_errors() == []
    assert reparsed.get_memory_map() == mem_map


def test_tc218_negative_control_corrupt_data_byte_detected(
    tmp_path: Path,
) -> None:
    """TC-218 — corrupting a DATA-record byte breaks the oracle (non-vacuous).

    Corrupts a byte of an S3 data record (NOT the inert S0): the re-parsed
    map must differ from the intended map OR the reader must report errors.
    """
    mem_map = _wide_mem_map()
    ranges = [(0x80001000, 0x80001000 + 80)]
    text = emit_s19_from_mem_map(mem_map, ranges, bytes_per_line=32)

    lines = text.splitlines()
    data_idx = next(i for i, line in enumerate(lines) if line.startswith("S3"))
    line = lines[data_idx]
    # Flip the first data byte's high nibble (data starts after type+count+addr).
    data_start = 4 + 4 * 2  # 'S3' + byte_count(2) + address(4 bytes = 8 hex)
    original = line[data_start]
    flipped = "0" if original != "0" else "F"
    lines[data_idx] = line[:data_start] + flipped + line[data_start + 1:]
    corrupt = "\n".join(lines) + "\n"

    target = tmp_path / "corrupt.s19"
    target.write_text(corrupt, encoding="ascii")
    reparsed = S19File(str(target))
    assert reparsed.get_memory_map() != mem_map or reparsed.get_errors() != []


def test_tc226_cross_format_round_trip_integrity(tmp_path: Path) -> None:
    """TC-226 — map-equality in all directions at the 32 default.

    S19→reparse; HEX-source map → emit S19(32) → reparse;
    S19-source map → emit_intel_hex → reparse. All byte-equal, 0 errors.
    """
    mem_map = _wide_mem_map()
    ranges = [(0x80001000, 0x80001000 + 80)]

    # Direction 1: S19 emit(32) → re-parse.
    s19_text = emit_s19_from_mem_map(mem_map, ranges, bytes_per_line=32)
    s19_path = tmp_path / "d1.s19"
    s19_path.write_text(s19_text, encoding="ascii")
    s19_reparsed = S19File(str(s19_path))
    assert s19_reparsed.get_errors() == []
    assert s19_reparsed.get_memory_map() == mem_map

    # Direction 2: HEX source map → emit S19(32) → re-parse.
    hex_text = io_module.emit_intel_hex_from_mem_map(mem_map, ranges)
    hex_path = tmp_path / "src.hex"
    hex_path.write_text(hex_text, encoding="ascii")
    hex_map = IntelHexFile(str(hex_path)).memory
    s19_from_hex = emit_s19_from_mem_map(dict(hex_map), ranges, bytes_per_line=32)
    s19_from_hex_path = tmp_path / "d2.s19"
    s19_from_hex_path.write_text(s19_from_hex, encoding="ascii")
    d2 = S19File(str(s19_from_hex_path))
    assert d2.get_errors() == []
    assert d2.get_memory_map() == mem_map

    # Direction 3: S19 source map → emit Intel HEX → re-parse.
    hex_from_s19 = io_module.emit_intel_hex_from_mem_map(
        s19_reparsed.get_memory_map(), ranges
    )
    d3_path = tmp_path / "d3.hex"
    d3_path.write_text(hex_from_s19, encoding="ascii")
    d3 = IntelHexFile(str(d3_path))
    assert d3.get_errors() == []
    assert dict(d3.memory) == mem_map


def test_c4_overlong_s0_header_raises(tmp_path: Path) -> None:
    """C4 / F-S-02 — s0_header > 252 bytes raises, no malformed record emitted."""
    mem_map = _wide_mem_map()
    ranges = [(0x80001000, 0x80001000 + 80)]

    with pytest.raises(ValueError):
        emit_s19_from_mem_map(mem_map, ranges, s0_header=b"\x00" * 253)

    # The 252-byte boundary is accepted and re-parses cleanly (inert to the
    # firmware data records; see TC-215 note re: the reader folding S0).
    boundary = emit_s19_from_mem_map(mem_map, ranges, s0_header=b"\x00" * 252)
    target = tmp_path / "boundary.s19"
    target.write_text(boundary, encoding="ascii")
    reparsed = S19File(str(target))
    assert reparsed.get_errors() == []
    assert _data_record_map(reparsed) == mem_map


def test_fq05_hex_emitter_unmodified_16_byte_rows(tmp_path: Path) -> None:
    """F-Q-05 — the Intel HEX emitter is unmodified: width constant stays 16
    and emitted HEX data rows never exceed 16 bytes (backs AT-015.2)."""
    assert io_module.HEX_DATA_BYTES_PER_RECORD == 16

    mem_map = _wide_mem_map()
    ranges = [(0x80001000, 0x80001000 + 80)]
    hex_text = io_module.emit_intel_hex_from_mem_map(mem_map, ranges)
    for line in hex_text.splitlines():
        if line.startswith(":"):
            byte_count = int(line[1:3], 16)
            assert byte_count <= 16


# ---------------------------------------------------------------------------
# US-015 / LLR-015.2 — source S0 capture at the load seam (read-only).
# ---------------------------------------------------------------------------


def test_build_loaded_s19_captures_source_s0_header() -> None:
    """LLR-015.2 — build_loaded_s19 captures the source S0 header bytes, and
    is None when the source carries no S0 record."""
    from s19_app.tui.services.load_service import build_loaded_s19

    with_s0 = (
        Path(__file__).resolve().parents[1]
        / "examples"
        / "case_01_basic_valid"
        / "firmware.s19"
    )
    loaded = build_loaded_s19(with_s0, S19File(str(with_s0)), None, None)
    assert loaded.source_s0_header == b"CASE01_BASIC"

    # prg.s19 has 0 S0 records (Phase-1 finding) → capture is None.
    loaded_none = build_loaded_s19(EXAMPLE_S19, S19File(str(EXAMPLE_S19)), None, None)
    assert loaded_none.source_s0_header is None


# ---------------------------------------------------------------------------
# US-015 / LLR-015.3 — width + S0 header threaded through the save call-sites.
# Reader-as-oracle on the DATA-record map (a populated S0 sits at address 0
# and the frozen reader folds it into get_memory_map; the firmware payload is
# the data records — see _data_record_map / TC-215, §6.5 Amendment B).
# ---------------------------------------------------------------------------

_WIDE_RANGES = [(0x80001000, 0x80001000 + 80)]


def test_tc219_save_patched_image_threads_width_and_s0_header(
    tmp_path: Path,
) -> None:
    """TC-219 — save_patched_image forwards bytes_per_line + s0_header to the
    S19 emitter; the written file packs >16/≤32-byte data rows AND carries a
    populated S0, re-parsing byte-equal on the DATA-record map. Omitting the
    width ⇒ 32.

    Intent: LLR-015.3 — the engine save call-site honors the selector and the
    captured header, not only the bare emitter; a default (omitted) width
    still emits 32-byte rows.
    """
    mem_map = _wide_mem_map()
    dest_dir = _project_dir(tmp_path)

    saved_path, issues = save_patched_image(
        mem_map,
        _WIDE_RANGES,
        dest_dir,
        "patched.s19",
        source_kind="s19",
        bytes_per_line=32,
        s0_header=b"HDR",
    )

    assert issues == []
    assert saved_path is not None and saved_path.is_file()
    written = saved_path.read_text(encoding="ascii")
    counts = _data_byte_counts(written)
    assert counts, "expected at least one data record"
    assert all(count <= 32 for count in counts)
    assert any(count > 16 for count in counts)  # 32-byte packing reached
    s0_line = next(line for line in written.splitlines() if line.startswith("S0"))
    assert int(s0_line[2:4], 16) - 2 - 1 == len(b"HDR")  # populated S0

    reparsed = S19File(str(saved_path))
    assert reparsed.get_errors() == []
    assert _data_record_map(reparsed) == mem_map  # inert S0, payload intact

    # Default (omitted) ⇒ 32: the same >16-byte packing without passing width.
    default_path, default_issues = save_patched_image(
        mem_map, _WIDE_RANGES, dest_dir, "default.s19", source_kind="s19"
    )
    assert default_issues == []
    assert default_path is not None
    default_counts = _data_byte_counts(default_path.read_text(encoding="ascii"))
    assert any(count > 16 for count in default_counts)


def test_tc220_change_service_save_patched_threads_to_emitter(
    tmp_path: Path,
) -> None:
    """TC-220 — ChangeService.save_patched (the project/service save path)
    threads bytes_per_line + s0_header two hops to the emitter: the written
    .s19 packs >16/≤32-byte rows, carries the populated S0, and re-parses
    byte-equal on the DATA-record map.

    Intent: LLR-015.3 AC — partial threading (emitter-only, not the service
    call-site) fails here; the service signature must forward both params.
    """
    from s19_app.tui.services.change_service import ChangeService

    service = ChangeService()
    mem_map = _wide_mem_map()
    dest_dir = _project_dir(tmp_path)

    result = service.save_patched(
        mem_map,
        _WIDE_RANGES,
        dest_dir,
        "service-patched.s19",
        source_kind="s19",
        bytes_per_line=32,
        s0_header=b"HDR",
    )

    assert result.ok, result.message
    saved = next(dest_dir.glob("service-patched*.s19"))
    written = saved.read_text(encoding="ascii")
    assert any(count > 16 for count in _data_byte_counts(written))  # 32 reached
    s0_line = next(line for line in written.splitlines() if line.startswith("S0"))
    assert int(s0_line[2:4], 16) - 2 - 1 == len(b"HDR")  # populated S0

    reparsed = S19File(str(saved))
    assert reparsed.get_errors() == []
    assert _data_record_map(reparsed) == mem_map


def test_tc220b_hex_save_unaffected_by_s19_only_kwargs(tmp_path: Path) -> None:
    """C1 — the HEX branch ignores the S19-only width/header kwargs: a HEX
    save with bytes_per_line set still writes a valid Intel-HEX file and does
    NOT raise (the HEX emitter takes no such kwargs).

    Intent: LLR-015.3 C1 — the new params are dispatched on the S19 branch
    only; passing them to a HEX save must not TypeError, and the re-parsed
    .hex carries 0 errors with the intended map.
    """
    mem_map = _wide_mem_map()
    dest_dir = _project_dir(tmp_path)

    saved_path, issues = save_patched_image(
        mem_map,
        _WIDE_RANGES,
        dest_dir,
        "patched.hex",
        source_kind="hex",
        bytes_per_line=32,
    )

    assert issues == []
    assert saved_path is not None and saved_path.suffix == ".hex"
    reparsed = IntelHexFile(str(saved_path))
    assert reparsed.get_errors() == []
    assert reparsed.memory == mem_map
