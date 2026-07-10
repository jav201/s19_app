"""
Check-engine tests — s19_app batch-07, increment E4 (HLR-004).

These tests verdict the declarative check engine headless — no Textual app
anywhere:

- **TC-020** — schema sharing (LLR-004.1): one reader serves both kinds; the
  same entry fixture read as ``kind="change"`` vs ``kind="check"`` yields
  identical issue lists (incl. the colliding-expectations ERROR — operator
  decision D-3).
- **TC-021** — comparison semantics (LLR-004.2): the loaded-image 2-1-2 run
  (2 pass, 1 fail, 2 uncheckable — one PARTIAL, one OUTSIDE) with exact
  actual tuples and ``mem_map`` immutability; the no-image all-uncheckable
  run; the not-runnable gate (ERROR-faulted document / wrong ``kind`` —
  the apply-gate mirror).
- **TC-022** — result shape (LLR-004.3): the C-6 ``CheckRunResult`` field
  set plus fixed-clock double-run ``to_dict()`` equality (B-4).
- **TC-023** — headless project run (LLR-004.4):
  ``run_checks_for_project`` on ``examples/case_00_public/prg.s19`` plus the
  static import-graph no-Textual inspection (never an in-session
  ``sys.modules`` assertion — F-Q-07; see the probe test's docstring for
  why the subprocess dotted-import alternative cannot apply here).

Every fixture is synthetic or public (``examples/case_00_public/`` —
constraint C-9).
"""

from __future__ import annotations

import ast
import json
from datetime import datetime, timezone
from pathlib import Path

from s19_app.tui.changes import (
    CHG_COLLISION,
    ChangeDocument,
    ChangeEntry,
    FORMAT_ID,
    FORMAT_VERSION,
    MemoryStatus,
)
from s19_app.tui.changes.check import run_check_document
from s19_app.tui.changes.io import read_change_document
from s19_app.tui.changes.model import CheckRunResult
from s19_app.tui.services.change_service import run_checks_for_project

REPO_ROOT = Path(__file__).resolve().parents[1]
PUBLIC_EXAMPLES = REPO_ROOT / "examples" / "case_00_public"


def _write_document(path: Path, entries: list[dict], kind: str) -> Path:
    """Write a v2 ``s19app-changeset`` JSON document fixture."""
    path.write_text(
        json.dumps(
            {
                "format": "s19app-changeset",
                "version": "2.0",
                "kind": kind,
                "encoding": "utf-8",
                "value_mode": "text",
                "entries": entries,
            }
        ),
        encoding="utf-8",
    )
    return path


def _check_document(entries: list[ChangeEntry]) -> ChangeDocument:
    """Build an in-memory clean ``kind="check"`` document."""
    return ChangeDocument(
        format=FORMAT_ID,
        version=FORMAT_VERSION,
        kind="check",
        encoding="utf-8",
        value_mode="text",
        entries=entries,
    )


def _image() -> tuple[dict[int, int], list[tuple[int, int]]]:
    """A 16-byte synthetic image at 0x100 whose byte values equal offsets."""
    return (
        {0x100 + offset: offset for offset in range(16)},
        [(0x100, 0x110)],
    )


def _two_one_two_entries() -> list[ChangeEntry]:
    """The LLR-004.2 2-1-2 fixture: 2 pass, 1 fail, 1 PARTIAL, 1 OUTSIDE."""
    return [
        ChangeEntry("bytes", 0x100, (0x00, 0x01)),  # pass
        ChangeEntry("bytes", 0x104, (0x04,)),  # pass
        ChangeEntry("bytes", 0x106, (0xFF,)),  # fail (actual 0x06)
        ChangeEntry("bytes", 0x10E, (0x01, 0x02, 0x03, 0x04)),  # PARTIAL
        ChangeEntry("bytes", 0x500, (0x05, 0x06)),  # OUTSIDE
    ]


# ===========================================================================
# TC-020 — schema sharing across kinds (LLR-004.1, D-3)
# ===========================================================================


def test_check_schema_shared(tmp_path: Path) -> None:
    """The same fixture read as change vs check yields identical issues.

    Intent: LLR-004.1 — one reader serves both kinds with one rule table:
    metadata, entry shapes, and the intra-document collision rule apply
    identically, and a colliding pair of expectations is ERROR exactly as a
    colliding pair of changes (operator decision D-3 — no severity fork).
    """
    entries = [
        {"type": "bytes", "address": "0x200", "bytes": "DE AD BE EF"},
        {"type": "bytes", "address": "0x202", "bytes": "01 02"},  # collides
        {"type": "string", "address": "0x300", "value": "REV_C"},
    ]
    change_doc = read_change_document(
        str(_write_document(tmp_path / "as_change.json", entries, "change")),
        tmp_path,
    )
    check_doc = read_change_document(
        str(_write_document(tmp_path / "as_check.json", entries, "check")),
        tmp_path,
    )

    assert change_doc.kind == "change"
    assert check_doc.kind == "check"
    assert len(change_doc.entries) == 3
    assert len(check_doc.entries) == 3

    def issue_view(doc: ChangeDocument) -> list[tuple[str, str, str]]:
        return [
            (issue.code, issue.severity.value, issue.message)
            for issue in doc.issues
        ]

    assert issue_view(change_doc) == issue_view(check_doc), (
        "the shared reader must collect identical findings for both kinds"
    )
    assert [issue.code for issue in check_doc.issues] == [
        CHG_COLLISION,
        CHG_COLLISION,
    ]
    assert all(
        issue.severity.value == "error" for issue in check_doc.issues
    ), "colliding expectations must be ERROR exactly as in change documents"


# ===========================================================================
# TC-021 — comparison semantics (LLR-004.2)
# ===========================================================================


def test_results_two_one_two_with_immutability() -> None:
    """The loaded-image run is exactly (2 pass, 1 fail, 2 uncheckable).

    Intent: LLR-004.2 — equal→pass, readable-unequal→fail with the actual
    bytes captured, not-fully-INSIDE→uncheckable with actual ``None`` (both
    provocations: one PARTIAL-range entry, one OUTSIDE-range entry), and the
    execution mutates nothing in the memory map.
    """
    mem_map, ranges = _image()
    snapshot = dict(mem_map)
    document = _check_document(_two_one_two_entries())

    result = run_check_document(document, mem_map, ranges, None, None)

    assert [entry.result for entry in result.entries] == [
        "pass",
        "pass",
        "fail",
        "uncheckable",
        "uncheckable",
    ]
    assert result.aggregates == {"passed": 2, "failed": 1, "uncheckable": 2}
    assert result.entries[0].actual_bytes == (0x00, 0x01)
    assert result.entries[1].actual_bytes == (0x04,)
    assert result.entries[2].actual_bytes == (0x06,)
    assert result.entries[2].expected_bytes == (0xFF,)
    assert result.entries[3].actual_bytes is None
    assert result.entries[4].actual_bytes is None
    assert document.entries[3].status is MemoryStatus.PARTIAL
    assert document.entries[4].status is MemoryStatus.OUTSIDE
    assert mem_map == snapshot, "a check run must never mutate the image"


def test_results_no_image_all_uncheckable() -> None:
    """With no image loaded, every entry is uncheckable.

    Intent: LLR-004.2 — the third uncheckable provocation (F-Q-16): no
    image means no entry can be compared; every actual is ``None``.
    """
    document = _check_document(_two_one_two_entries())
    result = run_check_document(document, None, None, None, None)
    assert [entry.result for entry in result.entries] == ["uncheckable"] * 5
    assert result.aggregates == {"passed": 0, "failed": 0, "uncheckable": 5}
    assert all(entry.actual_bytes is None for entry in result.entries)


def test_faulted_or_wrong_kind_document_not_runnable(tmp_path: Path) -> None:
    """An ERROR-faulted or non-check document performs no comparison.

    Intent: LLR-004.1/004.2, apply-gate mirror of LLR-002.1 — a check
    document with an ERROR issue is not runnable: every entry uncheckable
    with actual ``None`` even where the range is fully readable, the memory
    map untouched, and the declaration faults carried in ``result.issues``
    (B-2). Same gate for ``kind="change"`` fed to the check engine.
    """
    mem_map, ranges = _image()
    snapshot = dict(mem_map)

    faulted = read_change_document(
        str(
            _write_document(
                tmp_path / "colliding.json",
                [
                    {"type": "bytes", "address": "0x100", "bytes": "00 01"},
                    {"type": "bytes", "address": "0x101", "bytes": "01"},
                ],
                "check",
            )
        ),
        tmp_path,
    )
    assert faulted.has_errors
    result = run_check_document(faulted, mem_map, ranges, None, None)
    assert [entry.result for entry in result.entries] == ["uncheckable"] * 2
    assert all(entry.actual_bytes is None for entry in result.entries)
    assert [issue.code for issue in result.issues] == [
        CHG_COLLISION,
        CHG_COLLISION,
    ]
    assert mem_map == snapshot

    wrong_kind = ChangeDocument(
        format=FORMAT_ID,
        version=FORMAT_VERSION,
        kind="change",
        encoding="utf-8",
        value_mode="text",
        entries=[ChangeEntry("bytes", 0x100, (0x00,))],
    )
    result = run_check_document(wrong_kind, mem_map, ranges, None, None)
    assert [entry.result for entry in result.entries] == ["uncheckable"]
    assert result.entries[0].actual_bytes is None
    assert mem_map == snapshot


# ===========================================================================
# TC-022 — result shape + determinism (LLR-004.3, B-4)
# ===========================================================================


def test_result_shape_deterministic() -> None:
    """The C-6 result fields are exact; fixed-clock double runs are equal.

    Intent: LLR-004.3 — ``CheckRunResult`` carries source_path /
    timestamp_utc / variant_id / issues / all-three-key aggregates and the
    per-entry C-6 field set with informative linkage; ``to_dict()`` is
    deterministic (same object, same dict) and two runs over the same
    inputs under an injected fixed clock serialize identically (B-4).
    """
    mem_map, ranges = _image()
    mac_records = [{"name": "MAC_TAG", "address": 0x100, "parse_ok": True}]
    a2l_tags = [{"name": "A2L_TAG", "address": 0x500, "length": 2}]
    fixed = datetime(2026, 6, 10, 12, 0, 0, tzinfo=timezone.utc)

    def run() -> CheckRunResult:
        return run_check_document(
            _check_document(_two_one_two_entries()),
            mem_map,
            ranges,
            mac_records,
            a2l_tags,
            now_fn=lambda: fixed,
            variant_id="img",
        )

    result = run()
    rendered = result.to_dict()

    # >= 10 field assertions on the canonical shape.
    assert rendered["source_path"] is None
    assert rendered["timestamp_utc"] == "2026-06-10T12:00:00+00:00"
    assert rendered["variant_id"] == "img"
    assert list(rendered["aggregates"]) == ["passed", "failed", "uncheckable"]
    assert rendered["aggregates"] == {
        "passed": 2,
        "failed": 1,
        "uncheckable": 2,
    }
    assert rendered["issues"] == []
    first = rendered["entries"][0]
    assert first["entry_type"] == "bytes"
    assert first["address_start"] == 0x100
    assert first["address_end"] == 0x102
    assert first["expected_bytes"] == [0x00, 0x01]
    assert first["actual_bytes"] == [0x00, 0x01]
    assert first["result"] == "pass"
    assert first["linkage"] == "mac-linked"
    assert first["linkage_symbol"] == "MAC_TAG"
    last = rendered["entries"][4]
    assert last["linkage"] == "a2l-linked"
    assert last["linkage_symbol"] == "A2L_TAG"
    assert last["actual_bytes"] is None

    assert result.to_dict() == rendered, "same object, same dict"
    assert run().to_dict() == rendered, "fixed-clock double run equality"


# ===========================================================================
# TC-023 — headless project run + no-Textual probe (LLR-004.4)
# ===========================================================================


def test_headless_project_run(tmp_path: Path) -> None:
    """run_checks_for_project executes a check file against prg.s19.

    Intent: LLR-004.4 — paths in, ONE ``CheckRunResult`` out, reusing the
    load-service parse path; expected/actual values asserted against the
    public ``examples/case_00_public/prg.s19`` bytes (0xEB00 = 20 59,
    0xEB04 = CC); the optional MAC source feeds informative linkage.
    """
    check_path = _write_document(
        tmp_path / "prg-checks.json",
        [
            {"type": "bytes", "address": "0xEB00", "bytes": "20 59"},  # pass
            {"type": "bytes", "address": "0xEB04", "bytes": "FF"},  # fail
            {"type": "bytes", "address": "0x10", "bytes": "00"},  # outside
        ],
        "check",
    )
    mac_path = tmp_path / "prg.mac"
    mac_path.write_text("TAG1=EB00\n", encoding="ascii")

    result = run_checks_for_project(
        check_path, PUBLIC_EXAMPLES / "prg.s19", mac_path=mac_path
    )

    assert isinstance(result, CheckRunResult)
    assert result.variant_id == "prg"
    assert result.source_path is not None
    assert result.source_path.name == "prg-checks.json"
    assert result.issues == []
    assert result.aggregates == {"passed": 1, "failed": 1, "uncheckable": 1}
    assert [entry.result for entry in result.entries] == [
        "pass",
        "fail",
        "uncheckable",
    ]
    assert result.entries[0].actual_bytes == (0x20, 0x59)
    assert result.entries[0].linkage == "mac-linked"
    assert result.entries[0].linkage_symbol == "TAG1"
    assert result.entries[1].actual_bytes == (0xCC,)
    assert result.entries[2].actual_bytes is None


def _module_file(name: str) -> Path | None:
    """Map an ``s19_app``-internal dotted module name to its source file."""
    if name != "s19_app" and not name.startswith("s19_app."):
        return None
    relative = Path(*name.split("."))
    module_path = REPO_ROOT / f"{relative}.py"
    if module_path.exists():
        return module_path
    package_path = REPO_ROOT / relative / "__init__.py"
    return package_path if package_path.exists() else None


def _imported_names(path: Path, module_name: str) -> set[str]:
    """Collect every dotted name a module's source imports (AST-level)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    is_package = path.name == "__init__.py"
    package_parts = module_name.split(".")
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                base = node.module or ""
            else:
                anchor = (
                    package_parts if is_package else package_parts[:-1]
                )
                anchor = anchor[: len(anchor) - (node.level - 1)]
                base = ".".join(
                    anchor + (node.module.split(".") if node.module else [])
                )
            if base:
                names.add(base)
            for alias in node.names:
                names.add(f"{base}.{alias.name}" if base else alias.name)
    return names


def test_no_textual_in_static_import_graph() -> None:
    """The engine + headless entry point reach no Textual import.

    Intent: LLR-004.4 / F-Q-07 — the no-Textual guarantee verified by
    static import-graph inspection: every ``s19_app``-internal source file
    transitively reachable from ``changes/check.py`` and
    ``services/change_service.py`` imports neither ``textual`` nor any
    ``textual.*`` submodule. The subprocess dotted-import alternative is
    deliberately NOT used here: importing ``s19_app.tui.changes.check``
    executes the parent ``s19_app/tui/__init__.py``, which legitimately
    imports the Textual app for the ``s19tui`` entry point — a packaging
    artifact, not a dependency of the engine's code. The static graph is
    the LLR's named alternative and inspects the code-level dependencies
    themselves (and an in-session ``sys.modules`` assertion stays banned —
    F-Q-07).
    """
    roots = [
        "s19_app.tui.changes.check",
        "s19_app.tui.services.change_service",
    ]
    pending = list(roots)
    visited: set[str] = set()
    offenders: list[tuple[str, str]] = []
    while pending:
        module_name = pending.pop()
        if module_name in visited:
            continue
        visited.add(module_name)
        path = _module_file(module_name)
        if path is None:
            continue
        for imported in sorted(_imported_names(path, module_name)):
            if imported == "textual" or imported.startswith("textual."):
                offenders.append((module_name, imported))
            elif imported not in visited:
                pending.append(imported)
    assert "s19_app.tui.changes.check" in visited
    assert "s19_app.tui.services.change_service" in visited
    assert len(visited) > 10, "graph walk must actually traverse the tree"
    assert offenders == [], (
        f"textual reached the headless check path: {offenders}"
    )


# ---------------------------------------------------------------------------
# batch-33 (R-B02) Inc-1 — reason vocabulary + model carriage (TC-051.1).
# ---------------------------------------------------------------------------


def test_tc051_1_reason_vocabulary_and_model_defaults() -> None:
    """TC-051.1: the reason domain is the canonical 6-token set; entry and
    run reason fields default to None (pass/fail entries carry no reason,
    AT-051d's model half); to_dict is ADDITIVE — the four new keys are
    present and None-safe while every pre-batch-33 key survives unchanged.
    """
    from s19_app.tui.changes.model import (
        CHECK_REASON_DOC_FAULT,
        CHECK_REASON_DOC_KIND,
        CHECK_REASON_ENTRY_FAULT,
        CHECK_REASON_NO_IMAGE,
        CHECK_REASON_OUTSIDE,
        CHECK_REASON_PARTIAL,
        CHECK_UNCHECKABLE_REASON_DOMAIN,
        CheckRunEntry,
        CheckRunResult,
    )

    assert CHECK_UNCHECKABLE_REASON_DOMAIN == (
        CHECK_REASON_DOC_KIND,
        CHECK_REASON_DOC_FAULT,
        CHECK_REASON_ENTRY_FAULT,
        CHECK_REASON_PARTIAL,
        CHECK_REASON_OUTSIDE,
        CHECK_REASON_NO_IMAGE,
    )
    assert len(set(CHECK_UNCHECKABLE_REASON_DOMAIN)) == 6

    entry = CheckRunEntry(
        entry_type="bytes",
        address_start=0x100,
        address_end=0x104,
        expected_bytes=(1, 2, 3, 4),
        actual_bytes=(1, 2, 3, 4),
        result="pass",
        linkage="standalone",
        linkage_symbol=None,
    )
    assert entry.reason_code is None and entry.reason is None

    result = CheckRunResult(
        source_path=None,
        timestamp_utc="2026-07-09T00:00:00+00:00",
        variant_id=None,
        aggregates={"passed": 1, "failed": 0, "uncheckable": 0},
        entries=[entry],
    )
    assert result.run_blocked_reason_code is None
    assert result.run_blocked_reason is None

    payload = result.to_dict()
    # Additive run-level keys.
    assert payload["run_blocked_reason_code"] is None
    assert payload["run_blocked_reason"] is None
    # Additive per-entry keys beside the intact pre-batch-33 key set.
    entry_payload = payload["entries"][0]
    assert entry_payload["reason_code"] is None
    assert entry_payload["reason"] is None
    assert set(entry_payload) == {
        "entry_type", "address_start", "address_end", "expected_bytes",
        "actual_bytes", "result", "linkage", "linkage_symbol",
        "reason_code", "reason",
    }
    assert payload["aggregates"] == {"passed": 1, "failed": 0, "uncheckable": 0}
