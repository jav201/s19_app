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
- the run-checks E4 seam (pending finding without a runner; aggregate
  shaping with an injected stub).

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
from s19_app.tui.changes import CHG_COLLISION, CHG_V1_FORMAT
from s19_app.tui.services.change_service import (
    CHG_CHECKS_PENDING,
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
    written = list((tmp_path / ".s19tool" / "workarea").glob("roundtrip*.json"))
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
# F-Q-15 case 8 — the run-checks E4 seam
# ===========================================================================


def test_run_checks_without_engine_reports_pending() -> None:
    """With no injected runner, run_checks reports the E4-pending finding.

    Intent: LLR-004.5 at E3a — the check engine does not exist until E4, so
    the seam must surface exactly one clear ``CHG-CHECKS-PENDING`` status
    finding and execute nothing.
    """
    service, mem_map, ranges = _service_with_image()
    result = service.run_checks(mem_map, ranges)
    assert not result.ok
    assert "check engine pending (E4)" in result.message
    assert len(result.issues) == 1
    assert result.issues[0].code == CHG_CHECKS_PENDING
    assert service.last_check_result is None
    assert service.check_rows() == []


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
