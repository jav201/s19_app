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
from s19_app.tui.changes import (
    DISPOSITION_DOMAIN,
    FORMAT_ID,
    FORMAT_VERSION,
    MF_WRITE_CONTAINMENT,
    ChangeDocument,
    ChangeEntry,
    apply_change_document,
    collision_issues,
    emit_s19_from_mem_map,
    save_patched_image,
)
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


def test_save_back_hex_source_refused_with_clear_issue(tmp_path: Path) -> None:
    mem_map = _image_mem_map()
    dest_dir = _project_dir(tmp_path)

    saved_path, issues = save_patched_image(
        mem_map, IMAGE_RANGES, dest_dir, "patched.s19", source_kind="hex"
    )

    assert saved_path is None
    assert len(issues) == 1
    assert issues[0].code == "CHG-HEX-SAVE-UNSUPPORTED"
    assert "not supported" in issues[0].message
    if dest_dir.exists():
        assert list(dest_dir.glob("*")) == []
