"""
Operations-package tests — s19_app batch-08, increment I1 (HLR-001/HLR-002).

These tests verdict the operations abstraction headless — no Textual app
anywhere:

- **TC-001** — ``test_operation_result_schema`` (LLR-001.2): the §6.2 C-2
  canonical 7-field ``to_dict()``, fixed-clock double-run equality, the
  ``ValueError`` domain check against :data:`STATUS_DOMAIN`, and the
  disclosure guard (``output`` serialized as exactly
  ``{path, file_type, byte_count}``, never ``mem_map``).
- **TC-002** — ``test_identity_passthrough_s19`` (LLR-001.3): for each of
  the 3 placeholders over a real parsed S19 snapshot
  (``examples/case_00_public/prg.s19`` via ``S19File`` +
  ``build_loaded_s19``): ``output is loaded``, ``status="placeholder"``,
  and ``mem_map``/``ranges``/``errors`` unmutated — 15 assertions.
- **TC-003** — ``test_identity_passthrough_hex`` (LLR-001.4): the same
  15-assertion set over a HEX snapshot built from inline Intel HEX records
  written to ``tmp_path`` (the ``tests/test_hexfile.py`` idiom) via
  ``IntelHexFile`` + ``build_loaded_hex``.
- **TC-004** — ``test_placeholders_registered`` (LLR-002.1): the 3 classes
  resolve from the registry by their exact ids and each ``execute`` carries
  exactly one ``"placeholder: <operation_id> not yet implemented"`` note.
- **TC-005** — ``test_registry_deterministic_order`` (LLR-002.2): two
  successive ``list_operation_ids()`` calls equal the literal
  ``["crc", "extract", "split_by_segment"]`` and ``get_operation``
  round-trips all 3 ids.
- **TC-006** — ``test_unknown_operation_raises`` (LLR-002.3): an unknown id
  raises ``KeyError`` whose message contains the requested id verbatim.
- **TC-007** — ``test_run_operation_service`` (LLR-003.1, increment I2):
  ``run_operation`` returns an ``OperationResult`` with matching
  ``operation_id`` for all 3 placeholder ids, propagates the LLR-002.3
  ``KeyError`` unchanged for an unknown id, forwards ``now_fn`` unchanged,
  and resolves through the injectable ``operation_resolver`` seam
  (stub substitution observed).
- **TC-009** — ``test_operation_interface`` (LLR-001.1): non-empty unique
  ``operation_id``, non-empty ``title`` and ``describe()`` per placeholder;
  a subclass omitting ``execute`` is rejected by the ABC machinery
  (``TypeError`` on instantiation).

Every fixture is public (``examples/case_00_public/``) or synthetic
in-test.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
from pathlib import Path

import pytest

from s19_app.core import S19File
from s19_app.hexfile import IntelHexFile
from s19_app.tui.models import LoadedFile
from s19_app.tui.operations import (
    CrcOperation,
    ExtractOperation,
    Operation,
    OperationResult,
    SplitBySegmentOperation,
    get_operation,
    list_operation_ids,
)
from s19_app.tui.services import operation_service
from s19_app.tui.services.load_service import build_loaded_hex, build_loaded_s19
from s19_app.tui.services.operation_service import run_operation

REPO_ROOT = Path(__file__).resolve().parents[1]
PUBLIC_S19 = REPO_ROOT / "examples" / "case_00_public" / "prg.s19"

ALL_PLACEHOLDERS = (CrcOperation, ExtractOperation, SplitBySegmentOperation)


def _fixed_clock() -> datetime:
    """Fixed UTC instant for the TC-001 determinism equality."""
    return datetime(2026, 6, 11, 12, 0, 0, tzinfo=timezone.utc)


def _load_s19_snapshot() -> LoadedFile:
    """Real parsed S19 snapshot (LLR-001.3 acceptance criterion)."""
    return build_loaded_s19(PUBLIC_S19, S19File(str(PUBLIC_S19)), None, None)


def _build_hex_record(
    byte_count: int, address: int, record_type: int, data: list[int]
) -> str:
    """Build one Intel HEX record line (the ``tests/test_hexfile.py`` idiom)."""
    values = [byte_count, (address >> 8) & 0xFF, address & 0xFF, record_type] + data
    checksum = (-sum(values)) & 0xFF
    return ":" + "".join(f"{value:02X}" for value in values) + f"{checksum:02X}"


def _load_hex_snapshot(tmp_path: Path) -> LoadedFile:
    """Minimal in-test Intel HEX image parsed into a snapshot (LLR-001.4)."""
    lines = [
        _build_hex_record(2, 0x0000, 0x04, [0x00, 0x01]),
        _build_hex_record(4, 0x0010, 0x00, [0xAA, 0xBB, 0xCC, 0xDD]),
        _build_hex_record(0, 0x0000, 0x01, []),
    ]
    hex_path = tmp_path / "sample.hex"
    hex_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return build_loaded_hex(hex_path, IntelHexFile(str(hex_path)), None, None)


def _assert_identity_passthrough(loaded: LoadedFile) -> None:
    """The shared TC-002/TC-003 assertion set: 15 assertions, 0 mutations."""
    for operation_cls in ALL_PLACEHOLDERS:
        mem_map_before = copy.deepcopy(loaded.mem_map)
        ranges_before = copy.deepcopy(loaded.ranges)
        errors_before = copy.deepcopy(loaded.errors)

        result = operation_cls().execute(loaded)

        assert result.output is loaded
        assert result.status == "placeholder"
        assert loaded.mem_map == mem_map_before
        assert loaded.ranges == ranges_before
        assert loaded.errors == errors_before


def test_operation_result_schema(tmp_path):
    """TC-001 / LLR-001.2 — canonical schema, determinism, domain, disclosure."""
    loaded = _load_hex_snapshot(tmp_path)

    serialized = CrcOperation().execute(loaded, now_fn=_fixed_clock).to_dict()
    assert "operation_id" in serialized
    assert "status" in serialized
    assert "input_path" in serialized
    assert "variant_id" in serialized
    assert "output" in serialized
    assert "notes" in serialized
    assert "timestamp_utc" in serialized

    second = CrcOperation().execute(loaded, now_fn=_fixed_clock).to_dict()
    assert serialized == second

    with pytest.raises(ValueError):
        OperationResult(
            operation_id="crc",
            status="bogus-status",
            input_path=loaded.path,
            variant_id=None,
            output=loaded,
            notes=[],
            timestamp_utc=_fixed_clock().isoformat(),
        )

    assert "mem_map" not in serialized["output"]
    assert set(serialized["output"].keys()) == {"path", "file_type", "byte_count"}


def test_identity_passthrough_s19():
    """TC-002 / LLR-001.3 — identity + no-mutation over a real S19 snapshot."""
    loaded = _load_s19_snapshot()
    assert loaded.file_type == "s19"
    _assert_identity_passthrough(loaded)


def test_identity_passthrough_hex(tmp_path):
    """TC-003 / LLR-001.4 — identity + no-mutation over a HEX-built snapshot."""
    loaded = _load_hex_snapshot(tmp_path)
    assert loaded.file_type == "hex"
    _assert_identity_passthrough(loaded)


def test_placeholders_registered(tmp_path):
    """TC-004 / LLR-002.1 — exact ids resolve; exactly one placeholder note."""
    loaded = _load_hex_snapshot(tmp_path)
    expected = {
        "crc": CrcOperation,
        "extract": ExtractOperation,
        "split_by_segment": SplitBySegmentOperation,
    }
    for operation_id, operation_cls in expected.items():
        assert type(get_operation(operation_id)) is operation_cls
        result = get_operation(operation_id).execute(loaded)
        assert result.notes == [
            f"placeholder: {operation_id} not yet implemented"
        ]


def test_registry_deterministic_order():
    """TC-005 / LLR-002.2 — fixed literal order on every call; id round-trip."""
    assert list_operation_ids() == ["crc", "extract", "split_by_segment"]
    assert list_operation_ids() == ["crc", "extract", "split_by_segment"]
    for operation_id in ("crc", "extract", "split_by_segment"):
        assert get_operation(operation_id).operation_id == operation_id


def test_unknown_operation_raises():
    """TC-006 / LLR-002.3 — unknown id is a loud KeyError naming the id."""
    with pytest.raises(KeyError) as excinfo:
        get_operation("no_such_operation")
    assert "no_such_operation" in str(excinfo.value)


def test_run_operation_service(tmp_path, monkeypatch):
    """TC-007 / LLR-003.1 — registry-routed execution, ``now_fn`` forwarding,
    ``KeyError`` propagation, and seam substitution."""
    loaded = _load_hex_snapshot(tmp_path)

    for operation_id in ("crc", "extract", "split_by_segment"):
        result = run_operation(operation_id, loaded, now_fn=_fixed_clock)
        assert isinstance(result, OperationResult)
        assert result.operation_id == operation_id

    with pytest.raises(KeyError) as excinfo:
        run_operation("no_such_operation", loaded)
    assert "no_such_operation" in str(excinfo.value)

    class _StubOperation(Operation):
        operation_id = "stub"
        title = "Stub"

        def __init__(self) -> None:
            self.seen_now_fn: object = None

        def describe(self) -> str:
            return "seam-substitution stub"

        def execute(self, loaded, *, now_fn=None):
            self.seen_now_fn = now_fn
            return OperationResult(
                operation_id=self.operation_id,
                status="ok",
                input_path=loaded.path,
                variant_id=loaded.variant_id,
                output=loaded,
                notes=["stub executed"],
                timestamp_utc=_fixed_clock().isoformat(),
            )

    stub = _StubOperation()
    monkeypatch.setattr(
        operation_service, "operation_resolver", lambda operation_id: stub
    )
    result = run_operation("stub", loaded, now_fn=_fixed_clock)
    assert result.notes == ["stub executed"]
    assert stub.seen_now_fn is _fixed_clock


def test_operation_interface():
    """TC-009 / LLR-001.1 — interface contract + ABC rejection of subclasses
    that omit ``execute``."""
    seen_ids: set[str] = set()
    for operation_cls in ALL_PLACEHOLDERS:
        operation = operation_cls()
        assert isinstance(operation.operation_id, str) and operation.operation_id
        assert isinstance(operation.title, str) and operation.title
        description = operation.describe()
        assert isinstance(description, str) and description
        seen_ids.add(operation.operation_id)
    assert len(seen_ids) == 3

    class _MissingExecute(Operation):
        operation_id = "missing_execute"
        title = "Missing execute"

        def describe(self) -> str:
            return "subclass without execute"

    with pytest.raises(TypeError):
        _MissingExecute()
