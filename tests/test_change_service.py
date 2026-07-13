"""
Change-service tests — s19_app batch-07, increment E3a (LLR-003.4).

These tests verdict ``services/change_service.py`` — the v2 evolution of
``CdfxService`` — through the F-Q-15 named case set:

- add / edit / remove of a **string** entry;
- add / edit / remove of a **bytes** entry;
- v2 save → load round-trip through the canonical wire grammar;
- validate-with-collision (ERROR, recomputed over the live entries);
- apply-with-save (the LLR-002.7 service half stamping ``saved_path``);
- legacy-path rejection passthrough (v1 JSON → exactly one
  ``CHG-V1-FORMAT`` ERROR);
- retired-method-names-absent inspection (HLR-003 statement 2);
- the run-checks seam (the REAL E4 engine by default since increment E4;
  aggregate shaping with an injected stub — the seam stays injectable).

The service is headless by contract: the no-Textual-import case inspects
the module source (an in-session ``sys.modules`` assertion is unreliable —
F-Q-07).
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from s19_app.validation.model import ValidationSeverity
from s19_app.tui.changes import (
    CHG_COLLISION,
    CHG_V1_FORMAT,
    ChangeDocument,
    ChangeEntry,
    FORMAT_ID,
    FORMAT_VERSION,
    STATUS_VERIFIED,
)
from s19_app.tui.changes.check import run_check_document
from s19_app.tui.services.change_service import (
    ChangeService,
    parse_address,
    parse_new_bytes,
)


def _service_with_image() -> tuple[ChangeService, dict[int, int], list[tuple[int, int]]]:
    """Build a service plus a 16-byte synthetic image at 0x100."""
    service = ChangeService()
    mem_map = {0x100 + offset: 0x00 for offset in range(16)}
    ranges = [(0x100, 0x110)]
    return service, mem_map, ranges


# ===========================================================================
# F-Q-15 case 1 — add / edit / remove a string entry
# ===========================================================================


def test_add_edit_remove_string_entry() -> None:
    """String entries mutate through the evolved both-kind methods.

    Intent: LLR-003.4 — the service handles the v2 ``"string"`` kind
    natively: the declared value is encoded with the document encoding, an
    edit replaces the entry at its address, and a remove empties the list.
    """
    service = ChangeService()
    entry = service.add_entry("0x200", "REV_C", "")
    assert entry.entry_type == "string"
    assert entry.encoded_bytes == tuple("REV_C".encode("utf-8"))
    assert entry.value == "REV_C"

    edited = service.edit_entry("0x200", "REV_D", "")
    assert edited.encoded_bytes == tuple("REV_D".encode("utf-8"))
    assert len(service.document.entries) == 1

    service.remove_entry("0x200")
    assert service.is_empty()


# ===========================================================================
# F-Q-15 case 2 — add / edit / remove a bytes entry
# ===========================================================================


def test_add_edit_remove_bytes_entry() -> None:
    """Bytes entries mutate through the evolved both-kind methods.

    Intent: LLR-003.4 — the permissive TUI-input grammar (bare hex, commas,
    ``0x`` prefixes) feeds the ``"bytes"`` kind; edit replaces in place and
    remove deletes by address.
    """
    service = ChangeService()
    entry = service.add_entry("0x100", "", "DE AD BE EF")
    assert entry.entry_type == "bytes"
    assert entry.encoded_bytes == (0xDE, 0xAD, 0xBE, 0xEF)

    edited = service.edit_entry("0x100", "", "0x01, 2, FF")
    assert edited.encoded_bytes == (0x01, 0x02, 0xFF)

    service.remove_entry("0x100")
    assert service.is_empty()


def test_add_duplicate_address_is_rejected() -> None:
    """An interactive re-add of an existing address raises, not duplicates.

    Intent: the v2 file format keeps duplicate addresses as collisions, but
    the interactive add treats one as an operator mistake — Edit is the
    update path, so the table never silently grows a colliding twin.
    """
    service = ChangeService()
    service.add_entry("0x100", "", "AA")
    with pytest.raises(ValueError):
        service.add_entry("0x100", "", "BB")


def test_edit_or_remove_missing_address_raises_key_error() -> None:
    """Edit / remove of an unknown address is a KeyError the app reports."""
    service = ChangeService()
    with pytest.raises(KeyError):
        service.edit_entry("0x500", "", "AA")
    with pytest.raises(KeyError):
        service.remove_entry("0x500")


# ===========================================================================
# F-Q-15 case 3 — v2 save / load round-trip
# ===========================================================================


def test_v2_save_load_round_trip(tmp_path: Path) -> None:
    """Save writes the canonical v2 wire form and load recovers it.

    Intent: LLR-003.4 save/load evolve to v2 — the service's document
    round-trips through ``write_change_document`` / ``read_change_document``
    preserving both entry kinds, addresses, and encoded bytes.
    """
    service = ChangeService()
    service.add_entry("0x100", "", "AA BB")
    service.add_entry("0x200", "HELLO", "")

    result = service.save(tmp_path, file_name="roundtrip.json")
    assert result.ok, result.message
    # HLR-031: change-file saves now land in the dedicated patches folder, not
    # the workarea root — discover recursively so the round-trip intent holds.
    written = list(
        (tmp_path / ".s19tool" / "workarea").rglob("roundtrip*.json")
    )
    assert len(written) == 1

    fresh = ChangeService()
    load_result = fresh.load(str(written[0]), tmp_path)
    assert load_result.ok, load_result.message
    assert [
        (e.entry_type, e.address, e.encoded_bytes)
        for e in fresh.document.entries
    ] == [
        ("bytes", 0x100, (0xAA, 0xBB)),
        ("string", 0x200, tuple("HELLO".encode("utf-8"))),
    ]


# ===========================================================================
# F-Q-15 case 4 — validate with collision
# ===========================================================================


def test_validate_flags_interactive_collision() -> None:
    """Two overlapping interactive entries validate to CHG-COLLISION ERRORs.

    Intent: LLR-003.4 validate recomputes the LLR-001.5 collision rule over
    the live entries — an interactively created overlap must surface as
    ERROR findings (one per colliding entry) and flip ``ok`` to False.
    """
    service = ChangeService()
    service.add_entry("0x100", "", "01 02 03 04")
    service.add_entry("0x102", "", "05 06")

    result = service.validate(None)
    assert not result.ok
    collision_codes = [
        issue.code for issue in service.issues if issue.code == CHG_COLLISION
    ]
    assert len(collision_codes) == 2
    assert all(
        issue.severity is ValidationSeverity.ERROR
        for issue in service.issues
        if issue.code == CHG_COLLISION
    )


def test_clean_revalidate_clears_stale_collision_faults() -> None:
    """Removing the colliding entry and re-validating clears the faults.

    Intent: LLR-002.8 — declaration faults persist until a clean
    re-validate; once the collision is fixed, validate must leave zero
    issues (the panel's fault area then clears).
    """
    service = ChangeService()
    service.add_entry("0x100", "", "01 02 03 04")
    service.add_entry("0x102", "", "05 06")
    assert not service.validate(None).ok

    service.remove_entry("0x102")
    result = service.validate(None)
    assert result.ok
    assert service.issues == []
    assert service.issue_lines() == []


# ===========================================================================
# F-Q-15 case 5 — apply with save-back
# ===========================================================================


def test_apply_with_save_stamps_saved_path(tmp_path: Path) -> None:
    """Apply writes the image and save_patched stamps ``saved_path``.

    Intent: LLR-002.7 service half — after a successful apply, persisting
    under an operator filename records the written path on the summary;
    the file lands inside the work area.
    """
    service, mem_map, ranges = _service_with_image()
    service.add_entry("0x100", "", "AA BB")

    summary = service.apply(mem_map, ranges, None, None, variant_id="img")
    assert summary.counts["applied"] == 1
    assert mem_map[0x100] == 0xAA and mem_map[0x101] == 0xBB
    assert summary.saved_path is None

    workarea = tmp_path / ".s19tool" / "workarea"
    project_dir = workarea / "proj"
    project_dir.mkdir(parents=True)
    result = service.save_patched(
        mem_map, ranges, project_dir, "img-patched.s19", source_kind="s19"
    )
    assert result.ok, result.message
    assert summary.saved_path is not None
    assert summary.saved_path.is_file()
    assert workarea in summary.saved_path.parents


def test_hex_save_stamps_verified_result_on_summary(tmp_path: Path) -> None:
    """A HEX save persists a .hex and stamps a verified VerifyResult.

    Intent: HLR-002 + HLR-003 / §6.2 C-10 — a ``"hex"`` source is persisted
    (refusal retired) and verify-on-save rides the back-compatible carrier:
    ``last_summary.verify_result`` is stamped ``verified`` on a faithful
    write, with ``save_patched``'s ChangeActionResult still ``ok``.
    """
    service, mem_map, ranges = _service_with_image()
    service.add_entry("0x100", "", "AA BB")

    summary = service.apply(mem_map, ranges, None, None, variant_id="img")
    assert summary.counts["applied"] == 1
    assert summary.verify_result is None  # nothing saved yet

    project_dir = tmp_path / ".s19tool" / "workarea" / "proj"
    project_dir.mkdir(parents=True)
    result = service.save_patched(
        mem_map, ranges, project_dir, "img-patched.hex", source_kind="hex"
    )

    assert result.ok, result.message
    assert summary.saved_path is not None
    assert summary.saved_path.suffix == ".hex"
    assert summary.verify_result is not None
    assert summary.verify_result.status == STATUS_VERIFIED
    assert summary.verify_result.written_path == summary.saved_path


def test_refused_save_leaves_verify_result_none(tmp_path: Path) -> None:
    """A refused save never runs verify — verify_result stays None.

    Intent: §6.2 C-10 — verify is wired AFTER a successful write only; a
    refusal (here a ``"mac"`` source) returns early with no VerifyResult
    stamped on the summary.
    """
    service, mem_map, ranges = _service_with_image()
    service.add_entry("0x100", "", "AA")
    summary = service.apply(mem_map, ranges, None, None)

    project_dir = tmp_path / ".s19tool" / "workarea" / "proj"
    project_dir.mkdir(parents=True)
    result = service.save_patched(
        mem_map, ranges, project_dir, "img.mac", source_kind="mac"
    )

    assert not result.ok
    assert summary.saved_path is None
    assert summary.verify_result is None


def test_declined_or_refused_save_leaves_saved_path_none(
    tmp_path: Path,
) -> None:
    """A refused filename (reserved device name) keeps ``saved_path`` None.

    Intent: F-S-01 — the engine sanitizer's refusal must flow through the
    service unchanged: no file, ``saved_path`` stays ``None``, and the
    refusal arrives as a collected issue.
    """
    service, mem_map, ranges = _service_with_image()
    service.add_entry("0x100", "", "AA")
    summary = service.apply(mem_map, ranges, None, None)

    project_dir = tmp_path / ".s19tool" / "workarea" / "proj"
    project_dir.mkdir(parents=True)
    result = service.save_patched(
        mem_map, ranges, project_dir, "CON.s19", source_kind="s19"
    )
    assert not result.ok
    assert summary.saved_path is None
    assert result.issues, "the refusal must surface as a collected issue"


# ===========================================================================
# Batch-24 — LLR-038.2 (B-2 provenance stamp): save_patched stamps
# source_image_path beside saved_path; the field never serializes.
# ===========================================================================


def test_save_patched_stamps_source_image_path(tmp_path: Path) -> None:
    """save_patched(source_image_path=...) stamps the summary's provenance.

    Intent: LLR-038.2 / B-2 — the image the patched map was loaded from is
    recorded beside ``saved_path`` in the SAME service seam, so the
    before/after composer (I4) can detect a stale summary. Threshold: the
    stamped value equals the passed path; ``saved_path`` stamping unchanged.
    """
    service, mem_map, ranges = _service_with_image()
    service.add_entry("0x100", "", "AA BB")
    summary = service.apply(mem_map, ranges, None, None, variant_id="img")
    assert summary.source_image_path is None  # nothing saved yet

    project_dir = tmp_path / ".s19tool" / "workarea" / "proj"
    project_dir.mkdir(parents=True)
    original = tmp_path / "original.s19"
    result = service.save_patched(
        mem_map,
        ranges,
        project_dir,
        "img-patched.s19",
        source_kind="s19",
        source_image_path=original,
    )

    assert result.ok, result.message
    assert summary.saved_path is not None
    assert summary.source_image_path == original


def test_save_patched_without_kwarg_leaves_source_image_path_none(
    tmp_path: Path,
) -> None:
    """Omitting the kwarg keeps ``source_image_path`` None after a save.

    Intent: LLR-038.2 — the stamp is opt-in for the I4 handler; existing
    callers that never pass a source are unchanged. Threshold: a successful
    save with the kwarg omitted leaves the field ``None`` while ``saved_path``
    is stamped.
    """
    service, mem_map, ranges = _service_with_image()
    service.add_entry("0x100", "", "AA")
    summary = service.apply(mem_map, ranges, None, None)

    project_dir = tmp_path / ".s19tool" / "workarea" / "proj"
    project_dir.mkdir(parents=True)
    result = service.save_patched(
        mem_map, ranges, project_dir, "img-patched.s19", source_kind="s19"
    )

    assert result.ok, result.message
    assert summary.saved_path is not None
    assert summary.source_image_path is None


def test_to_dict_excludes_source_image_path_and_stays_byte_stable(
    tmp_path: Path,
) -> None:
    """``source_image_path`` never serializes — to_dict output byte-unchanged.

    Intent: LLR-038.2 — the field mirrors ``verify_result``'s runtime-only
    treatment: stamping it must not perturb the deterministic serialized
    summary. Threshold: the JSON dump of ``to_dict()`` before and after
    setting the field is byte-equal; the key is absent from the dict.
    """
    service, mem_map, ranges = _service_with_image()
    service.add_entry("0x100", "", "AA BB")
    summary = service.apply(mem_map, ranges, None, None, variant_id="img")

    baseline = json.dumps(summary.to_dict(), sort_keys=True)
    summary.source_image_path = tmp_path / "original.s19"
    stamped = json.dumps(summary.to_dict(), sort_keys=True)

    assert stamped == baseline  # byte-stable serialization
    assert "source_image_path" not in summary.to_dict()


# ===========================================================================
# F-Q-15 case 6 — legacy-path rejection passthrough
# ===========================================================================


def test_legacy_v1_load_rejected_with_single_error(tmp_path: Path) -> None:
    """A v1 unified JSON loads as exactly one CHG-V1-FORMAT ERROR.

    Intent: LLR-003.5 / LLR-001.8 — the v1 hard break flows through the
    service: one ERROR finding naming the v2 token, zero entries, no raise.
    """
    v1 = tmp_path / "legacy.json"
    v1.write_text(
        json.dumps(
            {
                "format": "s19app-unified-changeset",
                "version": "1.0",
                "parameters": [],
                "memory": [],
            }
        ),
        encoding="utf-8",
    )
    service = ChangeService()
    result = service.load(str(v1), tmp_path)
    assert not result.ok
    errors = [
        issue
        for issue in service.issues
        if issue.severity is ValidationSeverity.ERROR
    ]
    assert len(errors) == 1
    assert errors[0].code == CHG_V1_FORMAT
    assert service.document.entries == []


# ===========================================================================
# F-Q-15 case 7 — retired method names absent (inspection)
# ===========================================================================


def test_retired_method_names_absent() -> None:
    """The CdfxService parameter / export / unified methods do not exist.

    Intent: LLR-003.4 — the evolved service provides no parameter-by-name
    change list, no selective ``.cdfx`` export, and no v1 unified-file
    methods (HLR-003 statement 2); their names must be absent, not stubbed.
    """
    service = ChangeService()
    retired = [
        "export_selective",
        "save_unified",
        "load_unified",
        "add_memory_change",
        "edit_memory_change",
        "remove_memory_change",
        "memory_rows",
        "memory_validation_issues",
        "memory_is_empty",
        "change_list",
    ]
    for name in retired:
        assert not hasattr(service, name), f"retired method present: {name}"


# ===========================================================================
# F-Q-15 case 8 — the run-checks seam (real E4 engine by default)
# ===========================================================================


def test_run_checks_default_seam_is_real_engine() -> None:
    """A fresh service runs checks through the real E4 engine.

    Intent: LLR-004.4/004.5 at E4 — ``CHG-CHECKS-PENDING`` is gone: the
    ``check_runner`` seam defaults to ``run_check_document`` (re-pinned
    from the E3a pending-finding contract), so a check document executes
    with no injection and the status line states the three real aggregate
    counts.
    """
    service, mem_map, ranges = _service_with_image()
    assert service.check_runner is run_check_document
    service.document = ChangeDocument(
        format=FORMAT_ID,
        version=FORMAT_VERSION,
        kind="check",
        encoding="utf-8",
        value_mode="text",
        entries=[
            ChangeEntry("bytes", 0x100, (0x00,)),  # pass (image is zeroed)
            ChangeEntry("bytes", 0x500, (0x01,)),  # OUTSIDE -> uncheckable
        ],
    )
    result = service.run_checks(mem_map, ranges)
    assert result.ok
    assert result.message == "Checks: 1 passed, 0 failed, 1 uncheckable"
    assert service.last_check_result is not None
    assert [row.css_class for row in service.check_rows()] == [
        "sev-ok",
        "sev-warning",
    ]


def test_run_checks_with_injected_runner_shapes_display() -> None:
    """An injected runner's result shapes coloured rows + the 3-count line.

    Intent: LLR-004.5 — the seam consumes the LLR-004.3 duck shape: one row
    per entry coloured pass→sev-ok / fail→sev-error /
    uncheckable→sev-warning, and the status message states the three
    aggregate counts.
    """
    service, mem_map, ranges = _service_with_image()
    stub = SimpleNamespace(
        entries=[
            SimpleNamespace(
                address_start=0x100,
                address_end=0x102,
                expected_bytes=(0xAA, 0xBB),
                actual_bytes=(0xAA, 0xBB),
                result="pass",
            ),
            SimpleNamespace(
                address_start=0x104,
                address_end=0x105,
                expected_bytes=(0x01,),
                actual_bytes=(0x02,),
                result="fail",
            ),
            SimpleNamespace(
                address_start=0x10E,
                address_end=0x112,
                expected_bytes=(0x01, 0x02, 0x03, 0x04),
                actual_bytes=None,
                result="uncheckable",
            ),
        ],
        aggregates={"passed": 1, "failed": 1, "uncheckable": 1},
        issues=[],
    )
    service.check_runner = lambda *args, **kwargs: stub
    result = service.run_checks(mem_map, ranges)
    assert result.message == "Checks: 1 passed, 1 failed, 1 uncheckable"
    rows = service.check_rows()
    assert [row.css_class for row in rows] == [
        "sev-ok",
        "sev-error",
        "sev-warning",
    ]
    assert "pass" in rows[0].text and "fail" in rows[1].text


# ===========================================================================
# Display shaping + headless contract
# ===========================================================================


def test_rows_render_kind_address_status_and_fault_marker() -> None:
    """Entry rows expose kind / hex address / containment / fault marker.

    Intent: LLR-003.1 columns + the LLR-002.8 per-entry status arm — a row
    whose address carries an ERROR finding is suffixed `` / fault``.
    """
    service, _mem_map, ranges = _service_with_image()
    service.add_entry("0x100", "", "01 02 03 04")
    service.add_entry("0x102", "", "05 06")
    service.validate(ranges)

    rows = service.rows(ranges)
    assert [row.kind_text for row in rows] == ["bytes", "bytes"]
    assert [row.address_text for row in rows] == ["0x100", "0x102"]
    assert all(row.status_text.endswith(" / fault") for row in rows)
    assert all(row.linkage_text == "-" for row in rows)


def test_change_service_module_imports_no_textual() -> None:
    """The service module source contains no Textual import (LLR-002.4 arm).

    Intent: the service layer is headless by contract; a source-level
    inspection is the reliable check (in-session ``sys.modules`` assertions
    are polluted by earlier tests — F-Q-07).
    """
    import s19_app.tui.services.change_service as module

    source = Path(module.__file__).read_text(encoding="utf-8")
    for line in source.splitlines():
        stripped = line.strip()
        assert not stripped.startswith("import textual"), line
        assert not stripped.startswith("from textual"), line


def test_parse_helpers_follow_tui_input_grammar() -> None:
    """The permissive TUI-input grammar parses; garbage raises ValueError."""
    assert parse_address("0x100") == 256
    assert parse_address("512") == 512
    with pytest.raises(ValueError):
        parse_address("")
    with pytest.raises(ValueError):
        parse_address("-4")
    assert parse_new_bytes("DE AD") == [0xDE, 0xAD]
    assert parse_new_bytes("0x01, 2") == [1, 2]
    with pytest.raises(ValueError):
        parse_new_bytes("ZZ")


# ---------------------------------------------------------------------------
# batch-33 Inc-3 — AT-051c: the COMPOSED path (pasted faulted envelope +
# editor-added entries) blocks with the doc-fault reason (R-B02-6 smoke).
# ---------------------------------------------------------------------------


def test_at051c_composed_faulted_envelope_blocks_with_doc_fault() -> None:
    """AT-051c: paste a check document whose envelope carries a blocking
    fault (CHG-VALUE-MODE-UNKNOWN — orthogonal to encoding per the m-1
    fixture note), compose BYTES entries onto it via the editor seam, run
    checks: the run blocks with the doc-fault reason naming the code, and
    the composed entries enumerate as uncheckable with the short pointer.
    """
    service = ChangeService()
    faulted = json.dumps(
        {
            "format": "s19app-changeset",
            "version": "2.0",
            "kind": "check",
            "encoding": "utf-8",
            "value_mode": "banana",
            "entries": [],
        }
    )
    load_result = service.load_text(faulted)
    assert load_result.ok is False
    assert service.document is not None
    assert service.document.entries == []  # F-A-16 envelope fault

    service.add_entry("0x100", "", "00 01")  # BYTES entry (m-1)
    service.add_entry("0x104", "", "02")
    assert len(service.document.entries) == 2

    mem_map = {0x100 + offset: offset for offset in range(16)}
    action = service.run_checks(mem_map, [(0x100, 0x110)])
    assert action.ok is False
    assert "Checks: not run" in action.message
    assert "CHG-VALUE-MODE-UNKNOWN" in action.message
    assert "fix the document" in action.message
    assert "(0 passed, 0 failed, 2 uncheckable)" in action.message

    rows = service.check_rows()
    assert len(rows) == 2
    assert all("run blocked [doc-fault]" in row.text for row in rows)


# ===========================================================================
# US-068a (B-19a) — bounded deep-copy change-set history (LLR-068a.1/.2)
# ===========================================================================


def test_tc338_history_bounded_and_deep_copy_no_alias() -> None:
    """Snapshotting is deep-copy and the undo stack is bounded (TC-338).

    Intent: LLR-068a.1 — each entry mutation pushes exactly one snapshot; the
    undo stack never grows past ``_HISTORY_MAX`` (oldest evicted); and every
    stored snapshot is a TRUE deep copy — mutating ``document.entries`` after a
    push must NOT alter any stored snapshot (risk R-B, the graded no-alias
    point). Verified at the service level (no Textual).
    """
    from s19_app.tui.services.change_service import _HISTORY_MAX

    service = ChangeService()
    # One snapshot per mutation, more than the bound so eviction is exercised.
    for offset in range(_HISTORY_MAX + 5):
        service.add_entry(hex(0x100 + offset), "", "AA")
    assert len(service.document.entries) == _HISTORY_MAX + 5
    assert len(service._undo_stack) == _HISTORY_MAX, (
        "the undo history must be bounded at _HISTORY_MAX, got "
        f"{len(service._undo_stack)}"
    )

    # No-alias: the top snapshot is a deep copy. Mutating the LIVE document's
    # entries must leave the stored snapshot byte/field-for-field unchanged.
    snapshot = service._undo_stack[-1]
    assert snapshot.entries is not service.document.entries
    snapshot_len = len(snapshot.entries)
    snapshot_first_addr = snapshot.entries[0].address
    service.document.entries.clear()
    service.document.entries.append(ChangeEntry("bytes", 0x999, (0x01,)))
    assert len(snapshot.entries) == snapshot_len, (
        "mutating the live document must not alias a stored snapshot"
    )
    assert snapshot.entries[0].address == snapshot_first_addr


def test_tc339_undo_redo_restore_semantics_and_empty_noop() -> None:
    """undo/redo round-trip the document; empty stacks are no-ops (TC-339).

    Intent: LLR-068a.2 — ``undo`` restores the immediately-prior change-set and
    ``redo`` re-applies it (content-level, not "object changed"); an empty
    source stack makes undo/redo a no-op that leaves ``document`` identical; a
    fresh mutation after an undo clears the redo stack.
    """
    service = ChangeService()

    # Empty-stack no-op: undo/redo on a fresh service change nothing.
    doc0 = service.document
    assert service.undo() is doc0
    assert service.redo() is doc0
    assert service.document is doc0

    service.add_entry("0x200", "REV_A", "")
    assert [entry.address for entry in service.document.entries] == [0x200]

    # undo restores the pre-mutation (empty) change-set.
    service.undo()
    assert [entry.address for entry in service.document.entries] == [], (
        "undo must restore the pre-mutation (empty) document"
    )

    # redo re-applies the entry — byte/field-for-field.
    service.redo()
    assert [entry.address for entry in service.document.entries] == [0x200]
    restored = service.document.entries[0]
    assert restored.entry_type == "string"
    assert restored.value == "REV_A"

    # A fresh mutation after an undo clears the redo stack.
    service.undo()  # back to empty; redo stack now holds the 0x200 state
    assert service._redo_stack, "undo must populate the redo stack"
    service.add_entry("0x300", "", "DE AD")
    assert service._redo_stack == [], (
        "a fresh mutation must clear the redo stack"
    )
