"""
Selective-export coordinator tests — s19_app batch-04, increment 7.

Covers the selective-export coordinator (``s19_app/tui/cdfx/export.py``) —
``export_unified``, which splits a ``UnifiedChangeSet`` into the two artifacts
each downstream consumer expects: a CDFX file for the parameter half and a
separate memory-field JSON file for the memory-field half.

  - TC-028 — the CDFX parameter file is produced via the **unchanged** batch-03
             writer (LLR-007.1): the export feeds ``write_cdfx_to_workarea`` a
             re-resolved ``ResolutionResult`` and lands a ``.cdfx`` file; a spy
             confirms the call routes through the batch-03 writer.
  - TC-029 — the memory-field JSON file is produced (LLR-007.2): a separate
             ``.json`` file is written, valid JSON, carrying the format-id /
             version header and every memory-change entry in the LLR-005.3
             array-of-objects shape (``address`` an integer field), resolving
             under ``.s19tool/workarea/``.
  - TC-030 — the export yields two distinct files and ``writer.py`` is
             byte-unchanged (LLR-007.3 / constraint C-1): one ``.cdfx`` + one
             ``.json``, never merged; a source-hash assertion confirms the
             batch-03 CDFX writer module was not edited.
  - TC-031 — each half's issues are collected and tagged with their per-half
             origin (LLR-007.4): every combined-result issue carries an
             ``artifact`` of ``param-half`` or ``memory-half``; a containment
             rejection on the memory-field half still produces the CDFX file
             (collect-don't-abort across the two halves).
  - TC-036 — export-time re-resolution of the parameter half (LLR-007.5): with
             an A2L loaded the export re-resolves via ``resolve_against_a2l``
             (a spy confirms the call and that its result feeds the CDFX
             writer); with **no** A2L loaded the export still proceeds, collects
             one informational issue, and does not raise.

These tests encode WHY each behaviour matters. TC-030's byte-unchanged
assertion is the constraint-C-1 guard — the batch-03 CDFX writer must be
*reused*, never forked or edited, so the CDFX format contract stays stable.
TC-036's re-resolution arm is the resolution of the Phase-2 A-1 blocker: the
unified change-set carries the parameter half as a plain ``ChangeList`` with no
``ResolutionResult``, so the coordinator must re-resolve it against the loaded
A2L before the CDFX write — getting this wrong reproduces the original
``TypeError``-at-export defect. TC-031's per-half tag is asserted on the
existing ``ValidationIssue.artifact`` field — no new model field (constraint
C-5 / A-5).

Every fixture is synthetic and built in-test (constraint C-9). This increment
carries the memory-field export write-path containment and is a Phase-2
security-reviewer hand-off surface (§5.5).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from s19_app.tui.a2l import enrich_a2l_tags_with_values, parse_a2l_file
from s19_app.tui.cdfx import (
    UnifiedChangeSet,
    export_unified,
)
from s19_app.tui.cdfx import export as export_mod
from s19_app.tui.cdfx import writer as writer_mod
from s19_app.tui.cdfx.changelist import ResolutionStatus
from s19_app.tui.cdfx.export import (
    EXPORT_NO_A2L,
    MEMORY_HALF_ARTIFACT,
    PARAM_HALF_ARTIFACT,
    ExportResult,
    write_memory_field_to_workarea,
)
from s19_app.tui.cdfx.resolve import ResolutionResult
from s19_app.tui.cdfx.unified_io import (
    MF_WRITE_CONTAINMENT,
    UNIFIED_FORMAT_ID,
    UNIFIED_FORMAT_VERSION,
)
from s19_app.tui.workspace import (
    WORKAREA_DIRNAME,
    WORKAREA_SUBDIR,
    WorkareaContainmentError,
)

from tests.conftest import unified_changeset_factory


# ---------------------------------------------------------------------------
# Synthetic A2L — a named scalar / 1-D array / ASCII string matching the
# parameter half of ``unified_changeset_factory`` (``change_list_factory``).
# Parsed through the real ``parse_a2l_file`` → ``enrich_a2l_tags_with_values``
# pipeline so the export re-resolution runs against the genuine enriched-tag
# shape (constraint C-1 / Phase-2 finding A-01).
# ---------------------------------------------------------------------------

_EXPORT_A2L_TEXT = """/begin PROJECT P
/begin MODULE M
/begin RECORD_LAYOUT RL_SCALAR
  UWORD
/end RECORD_LAYOUT
/begin RECORD_LAYOUT RL_ARRAY3
  UWORD 3
/end RECORD_LAYOUT
/begin RECORD_LAYOUT RL_ASCII
  UBYTE 8
/end RECORD_LAYOUT
/begin CHARACTERISTIC IGN_ADVANCE_BASE
VALUE 0x8000 RL_SCALAR 0 NO_COMPU_METHOD 0 65535
/end CHARACTERISTIC
/begin CHARACTERISTIC FUEL_TRIM_TABLE
VAL_BLK 0x8100 RL_ARRAY3 0 NO_COMPU_METHOD 0 65535
/end CHARACTERISTIC
/begin CHARACTERISTIC FLOAT_ADV_BLOCK
VAL_BLK 0x8200 RL_ARRAY3 0 NO_COMPU_METHOD 0 65535
/end CHARACTERISTIC
/begin CHARACTERISTIC CAL_LABEL
ASCII 0x8300 RL_ASCII 0 NO_COMPU_METHOD 0 255
/end CHARACTERISTIC
/end MODULE
/end PROJECT
"""


def _enriched_export_tags(tmp_path: Path) -> list[dict]:
    """Build the enriched A2L tags for the synthetic export A2L — the input
    shape ``export_unified`` re-resolves the parameter half against."""
    a2l_path = tmp_path / "export.a2l"
    a2l_path.write_text(_EXPORT_A2L_TEXT, encoding="utf-8")
    return enrich_a2l_tags_with_values(parse_a2l_file(a2l_path), None)


def _workarea(base_dir: Path) -> Path:
    """Return the ``.s19tool/workarea/`` containment root under ``base_dir``."""
    return base_dir / WORKAREA_DIRNAME / WORKAREA_SUBDIR


# ---------------------------------------------------------------------------
# TC-028 — the CDFX parameter file is produced via the unchanged writer
# (LLR-007.1)
# ---------------------------------------------------------------------------


def test_tc028_export_produces_a_cdfx_file_under_the_workarea(
    tmp_path: Path,
) -> None:
    """TC-028 — a selective export lands a ``.cdfx`` file in the work area (LLR-007.1).

    LLR-007.1 requires the parameter half to be exported as a CDFX file. This
    asserts ``export_unified`` returns a ``cdfx_path`` that exists, carries the
    ``.cdfx`` suffix, and resolves under ``.s19tool/workarea/`` — so an export
    that skips the parameter half, or writes it outside containment, fails.
    """
    changeset = unified_changeset_factory()
    tags = _enriched_export_tags(tmp_path)

    result = export_unified(changeset, tags, tmp_path)

    assert isinstance(result, ExportResult)
    assert result.cdfx_path is not None, (
        f"no .cdfx produced: {[i.code for i in result.issues]}"
    )
    assert result.cdfx_path.exists()
    assert result.cdfx_path.suffix == ".cdfx"
    assert result.cdfx_path.resolve().is_relative_to(
        _workarea(tmp_path).resolve()
    ), f"the .cdfx was written outside the work area: {result.cdfx_path}"


def test_tc028_cdfx_write_routes_through_the_batch03_writer(
    tmp_path: Path, monkeypatch
) -> None:
    """TC-028 — the CDFX write is delegated to the batch-03 ``write_cdfx_to_workarea``.

    LLR-007.1 / constraint C-1: the coordinator must *invoke the unchanged*
    batch-03 CDFX write path, not re-implement CDFX serialization. This spies
    on ``export.write_cdfx_to_workarea`` and asserts it is called exactly once
    with the change-set's own parameter ``ChangeList`` and a ``ResolutionResult``
    — so a coordinator that hand-rolls the CDFX bytes fails the test.
    """
    changeset = unified_changeset_factory()
    tags = _enriched_export_tags(tmp_path)

    calls: list[tuple[object, object]] = []
    real_writer = export_mod.write_cdfx_to_workarea

    def spy(change_list, resolution, base_dir, **kwargs):
        calls.append((change_list, resolution))
        return real_writer(change_list, resolution, base_dir, **kwargs)

    monkeypatch.setattr(export_mod, "write_cdfx_to_workarea", spy)

    export_unified(changeset, tags, tmp_path)

    assert len(calls) == 1, "the batch-03 CDFX writer was not called exactly once"
    passed_change_list, passed_resolution = calls[0]
    # The writer is fed the change-set's own parameter half and a typed
    # ResolutionResult (LLR-007.1) — never a bare, unresolved ChangeList.
    assert passed_change_list is changeset.parameters
    assert isinstance(passed_resolution, ResolutionResult)


# ---------------------------------------------------------------------------
# TC-029 — the memory-field JSON file is produced (LLR-007.2)
# ---------------------------------------------------------------------------


def test_tc029_export_produces_a_memory_field_json_file(
    tmp_path: Path,
) -> None:
    """TC-029 — a selective export lands a memory-field ``.json`` file (LLR-007.2).

    LLR-007.2 requires the memory-field half to be exported as a separate JSON
    file, contained in the work area. This asserts ``memory_field_path`` exists,
    carries the ``.json`` suffix, and resolves under ``.s19tool/workarea/``.
    """
    changeset = unified_changeset_factory()
    tags = _enriched_export_tags(tmp_path)

    result = export_unified(changeset, tags, tmp_path)

    assert result.memory_field_path is not None, (
        f"no memory-field file produced: {[i.code for i in result.issues]}"
    )
    assert result.memory_field_path.exists()
    assert result.memory_field_path.suffix == ".json"
    assert result.memory_field_path.resolve().is_relative_to(
        _workarea(tmp_path).resolve()
    ), "the memory-field file was written outside the work area"


def test_tc029_memory_field_file_carries_header_and_array_of_objects(
    tmp_path: Path,
) -> None:
    """TC-029 — the memory-field file is valid JSON in the LLR-005.3 shape (LLR-007.2).

    LLR-007.2 pins the memory-field file to the format-id / version header plus
    the memory entries in the LLR-005.3 array-of-objects shape — ``address`` an
    integer-valued field, never an object key. This asserts the file re-parses
    with ``json``, carries the header, and every memory object carries an
    integer ``address`` and a ``new_bytes`` integer array; the exact entries of
    the factory's memory half survive with no loss.
    """
    changeset = unified_changeset_factory()
    tags = _enriched_export_tags(tmp_path)

    result = export_unified(changeset, tags, tmp_path)
    document = json.loads(result.memory_field_path.read_bytes())

    assert document["format"] == UNIFIED_FORMAT_ID
    assert document["version"] == UNIFIED_FORMAT_VERSION

    memory = document["memory"]
    assert isinstance(memory, list)
    assert len(memory) == len(changeset.memory.entries)
    for element in memory:
        assert isinstance(element, dict)
        assert isinstance(element["address"], int)
        assert isinstance(element["new_bytes"], list)

    # The exact integer addresses and ordered byte runs of the factory survive.
    expected = {e.address: list(e.new_bytes) for e in changeset.memory.entries}
    written = {el["address"]: el["new_bytes"] for el in memory}
    assert written == expected

    # `address` is a JSON number field, never a quoted object key (LLR-005.3).
    raw_text = result.memory_field_path.read_text(encoding="utf-8")
    assert '"address": 256' in raw_text
    assert '"256":' not in raw_text


def test_tc029_memory_field_export_is_byte_deterministic(
    tmp_path: Path,
) -> None:
    """TC-029 — two exports of the same change-set write byte-identical memory JSON.

    The memory-field export must be reproducible (LLR-001.4 carries through the
    file). This asserts two exports produce byte-identical memory-field file
    content, so a save is diff-stable.
    """
    changeset = unified_changeset_factory()
    tags = _enriched_export_tags(tmp_path)

    first = export_unified(changeset, tags, tmp_path)
    second = export_unified(changeset, tags, tmp_path)

    assert first.memory_field_path.read_bytes() == (
        second.memory_field_path.read_bytes()
    )


# ---------------------------------------------------------------------------
# TC-030 — two distinct files; writer.py is byte-unchanged (LLR-007.3 / C-1)
# ---------------------------------------------------------------------------


def test_tc030_export_yields_two_distinct_files_never_merged(
    tmp_path: Path,
) -> None:
    """TC-030 — a selective export yields exactly two distinct files (LLR-007.3).

    LLR-007.3: the export must split, not merge — one ``.cdfx`` for the
    parameter half, one ``.json`` for the memory-field half, two distinct
    paths. This asserts both paths are produced, differ, and have the expected
    distinct suffixes.
    """
    changeset = unified_changeset_factory()
    tags = _enriched_export_tags(tmp_path)

    result = export_unified(changeset, tags, tmp_path)

    assert result.cdfx_path is not None
    assert result.memory_field_path is not None
    assert result.cdfx_path != result.memory_field_path, (
        "the two halves were written to one merged file"
    )
    assert result.cdfx_path.suffix == ".cdfx"
    assert result.memory_field_path.suffix == ".json"
    # Both land inside the work area.
    workarea = _workarea(tmp_path).resolve()
    assert result.cdfx_path.resolve().is_relative_to(workarea)
    assert result.memory_field_path.resolve().is_relative_to(workarea)


# The SHA-256 of ``s19_app/tui/cdfx/writer.py`` content at the batch-04
# increment-7 baseline. Constraint C-1 forbids any edit to the batch-03 CDFX
# writer; this hash pins that. If a future change genuinely needs to touch
# writer.py, this constant must be updated deliberately — never silently.
_WRITER_PY_SHA256 = (
    "82d527c0d89e18e32c02b55a9132b1b31ec482b29f869229807dae77c9afe4ac"
)


def test_tc030_batch03_cdfx_writer_module_is_byte_unchanged() -> None:
    """TC-030 — ``cdfx/writer.py`` is byte-unchanged by this batch (constraint C-1).

    Constraint C-1 forbids re-implementing, forking or modifying the batch-03
    CDFX writer — the coordinator must *reuse* it. This hashes the on-disk
    ``writer.py`` source content and asserts it matches the pinned baseline, so
    any accidental edit to the writer is caught at the increment boundary. The
    file *content* is hashed (not the directory) so line-ending / ``__pycache__``
    noise cannot perturb the verdict.
    """
    writer_path = Path(writer_mod.__file__)
    actual = hashlib.sha256(writer_path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()

    assert actual == _WRITER_PY_SHA256, (
        "s19_app/tui/cdfx/writer.py changed since the increment-7 baseline — "
        "constraint C-1 forbids editing the batch-03 CDFX writer. If the change "
        f"was deliberate, update _WRITER_PY_SHA256 to {actual!r}."
    )


# ---------------------------------------------------------------------------
# TC-031 — per-half issue origin tagging; collect-don't-abort (LLR-007.4)
# ---------------------------------------------------------------------------


def test_tc031_every_combined_issue_carries_a_per_half_artifact_tag(
    tmp_path: Path,
) -> None:
    """TC-031 — each combined-result issue is tagged with its per-half origin (LLR-007.4).

    LLR-007.4: the export must identify which half each issue came from by
    setting the existing ``ValidationIssue.artifact`` field — ``param-half`` or
    ``memory-half``. The no-A2L arm is used so the export is guaranteed to
    produce issues (the no-A2L info issue plus the CDFX writer's ``W-*``
    exclusion / empty warnings); this asserts every combined-result issue
    carries one of the two per-half tags and nothing else — never the writer's
    own raw ``cdfx`` / ``unified`` tag.
    """
    changeset = unified_changeset_factory()

    result = export_unified(changeset, None, tmp_path)

    assert result.issues, "expected at least one issue from this export"
    for issue in result.issues:
        assert issue.artifact in (PARAM_HALF_ARTIFACT, MEMORY_HALF_ARTIFACT), (
            f"issue {issue.code} carries an untagged artifact "
            f"{issue.artifact!r} — LLR-007.4 requires a per-half origin"
        )


def test_tc031_parameter_half_issues_are_tagged_param_half(
    tmp_path: Path,
) -> None:
    """TC-031 — the CDFX write's ``W-*`` issues are re-tagged ``param-half``.

    The batch-03 CDFX writer stamps its own ``artifact='cdfx'``; the coordinator
    must re-stamp it to the per-half origin. This export passes no A2L, so the
    parameter half cannot resolve and the CDFX writer emits ``W-*`` warnings;
    this asserts every such issue (and the no-A2L info issue) carries
    ``param-half``, not the writer's own ``cdfx`` tag.
    """
    changeset = unified_changeset_factory()

    result = export_unified(changeset, None, tmp_path)

    param_codes = [
        i.code for i in result.issues if i.artifact == PARAM_HALF_ARTIFACT
    ]
    # The no-A2L info issue plus the writer's W-* exclusion / empty warnings.
    assert EXPORT_NO_A2L in param_codes
    assert any(code.startswith("W-") for code in param_codes), (
        "the CDFX writer's W-* issues were not re-tagged param-half"
    )
    # None of the export's issues kept the writer's raw 'cdfx' artifact.
    assert all(i.artifact != "cdfx" for i in result.issues)


def test_tc031_memory_half_rejection_does_not_block_the_cdfx_file(
    tmp_path: Path,
) -> None:
    """TC-031 — a memory-field containment rejection still produces the CDFX file.

    LLR-007.4 collect-don't-abort *across the two halves*: a problem in one half
    must not abort the other. This forces the memory-field write to be rejected
    (an injected ``copy_fn`` raising ``WorkareaContainmentError``) and asserts
    the ``.cdfx`` file is still produced, the memory-field path is ``None``, and
    the rejection surfaces as one ``memory-half``-tagged ``MF-WRITE-CONTAINMENT``
    issue — not an exception.
    """
    changeset = unified_changeset_factory()
    tags = _enriched_export_tags(tmp_path)

    def reject(*_args, **_kwargs):
        raise WorkareaContainmentError(
            "Refusing to copy: destination traverses a reparse point"
        )

    result = export_unified(changeset, tags, tmp_path, copy_fn=reject)

    # The parameter half exported despite the memory-half failure.
    assert result.cdfx_path is not None and result.cdfx_path.exists()
    # The memory-field half was rejected — no file, one tagged issue.
    assert result.memory_field_path is None
    containment = [
        i for i in result.issues if i.code == MF_WRITE_CONTAINMENT
    ]
    assert len(containment) == 1
    assert containment[0].artifact == MEMORY_HALF_ARTIFACT
    assert containment[0].severity.value == "warning"


def test_tc031_memory_field_oserror_surfaces_issue_not_exception(
    tmp_path: Path, monkeypatch
) -> None:
    """TC-031 — an OSError from the memory-field staged write is a
    ``ValidationIssue``, never an uncaught exception (security finding S57-02).

    The increment-7 security review flagged (S57-02) that
    ``write_memory_field_to_workarea`` caught only ``WorkareaContainmentError``,
    so an ``OSError`` from the staged-temp ``write_bytes`` — a full disk, a
    denied permission — would escape uncaught and break the LLR-007.2
    collect-don't-abort claim. This forces a ``PermissionError`` (an ``OSError``
    subclass) out of the staged write and asserts the function catches it and
    returns ``(None, [MF-WRITE-CONTAINMENT])`` with the ``memory-half`` tag —
    no exception propagates.
    """
    changeset = unified_changeset_factory()

    real_write_bytes = Path.write_bytes

    def failing_write_bytes(self: Path, data: bytes) -> int:
        # Only the staged temp .json file fails — isolates the OSError arm.
        if "temp" in self.parts and self.suffix == ".json":
            raise PermissionError("simulated: permission denied on staged temp")
        return real_write_bytes(self, data)

    monkeypatch.setattr(Path, "write_bytes", failing_write_bytes)

    path, issues = write_memory_field_to_workarea(
        changeset, tmp_path, "memory-field.json"
    )

    assert path is None, "a write that hit an OSError must not return a path"
    assert [i.code for i in issues] == [MF_WRITE_CONTAINMENT], (
        f"expected exactly one MF-WRITE-CONTAINMENT issue from the OSError, "
        f"got {[i.code for i in issues]}"
    )
    issue = issues[0]
    assert issue.severity.value == "warning"
    assert issue.artifact == MEMORY_HALF_ARTIFACT
    assert "PermissionError" in issue.message


# ---------------------------------------------------------------------------
# TC-036 — export-time re-resolution of the parameter half (LLR-007.5)
# ---------------------------------------------------------------------------


def test_tc036_export_re_resolves_the_parameter_half_via_resolve_against_a2l(
    tmp_path: Path,
) -> None:
    """TC-036 — with an A2L loaded the export re-resolves via ``resolve_against_a2l``.

    LLR-007.5: before the CDFX write the coordinator must re-resolve the
    parameter ``ChangeList`` against the loaded A2L through the batch-03
    ``resolve_against_a2l``. This spies on the resolver (via the injectable
    ``resolve_fn`` seam) and asserts it is called once with the change-set's own
    ``ChangeList`` and the loaded tags — the A-1 blocker's fix.
    """
    changeset = unified_changeset_factory()
    tags = _enriched_export_tags(tmp_path)

    calls: list[tuple[object, object]] = []
    real_resolve = export_mod.resolve_against_a2l

    def spy(change_list, enriched_tags):
        calls.append((change_list, enriched_tags))
        return real_resolve(change_list, enriched_tags)

    export_unified(changeset, tags, tmp_path, resolve_fn=spy)

    assert len(calls) == 1, "the parameter half was not re-resolved exactly once"
    passed_change_list, passed_tags = calls[0]
    assert passed_change_list is changeset.parameters
    assert passed_tags is tags


def test_tc036_re_resolution_result_feeds_the_cdfx_writer(
    tmp_path: Path, monkeypatch
) -> None:
    """TC-036 — the re-resolution's ``ResolutionResult`` is fed to the CDFX writer.

    LLR-007.5 → LLR-007.1: the ``ResolutionResult`` from the export-time
    re-resolution is exactly what ``write_cdfx_to_workarea`` is invoked with.
    This spies on both the resolver and the writer and asserts the writer
    receives the *same* ``ResolutionResult`` object the resolver returned — so a
    coordinator that re-resolves but then discards the result fails the test.
    """
    changeset = unified_changeset_factory()
    tags = _enriched_export_tags(tmp_path)

    produced: list[ResolutionResult] = []
    real_resolve = export_mod.resolve_against_a2l

    def resolve_spy(change_list, enriched_tags):
        result = real_resolve(change_list, enriched_tags)
        produced.append(result)
        return result

    fed: list[object] = []
    real_writer = export_mod.write_cdfx_to_workarea

    def writer_spy(change_list, resolution, base_dir, **kwargs):
        fed.append(resolution)
        return real_writer(change_list, resolution, base_dir, **kwargs)

    monkeypatch.setattr(export_mod, "write_cdfx_to_workarea", writer_spy)
    export_unified(changeset, tags, tmp_path, resolve_fn=resolve_spy)

    assert len(produced) == 1 and len(fed) == 1
    assert fed[0] is produced[0], (
        "the CDFX writer was not fed the export-time ResolutionResult"
    )


def test_tc036_resolved_parameter_is_written_into_the_cdfx(
    tmp_path: Path,
) -> None:
    """TC-036 — a parameter resolved at export time is written into the ``.cdfx``.

    The re-resolution is not cosmetic: a parameter whose name matches the loaded
    A2L resolves ``RESOLVED`` and the batch-03 writer then emits it as a
    ``SW-INSTANCE``. This asserts the scalar ``IGN_ADVANCE_BASE`` (present in
    the synthetic A2L) appears in the exported CDFX text — proving the
    re-resolved result genuinely drove a real CDFX write, not an empty one.
    """
    changeset = unified_changeset_factory()
    tags = _enriched_export_tags(tmp_path)

    result = export_unified(changeset, tags, tmp_path)
    cdfx_text = result.cdfx_path.read_text(encoding="utf-8")

    assert "IGN_ADVANCE_BASE" in cdfx_text, (
        "the export-time re-resolved parameter did not reach the CDFX writer"
    )
    # No no-A2L issue when an A2L was supplied.
    assert EXPORT_NO_A2L not in [i.code for i in result.issues]


def test_tc036_no_a2l_export_proceeds_with_one_info_issue_and_no_raise(
    tmp_path: Path,
) -> None:
    """TC-036 — with no A2L loaded the export still proceeds, collects one issue (LLR-007.5).

    LLR-007.5 / DD-11: with no A2L loaded the coordinator must mirror the
    batch-03 ``unresolved-no-a2l`` collect-don't-abort pattern — produce an
    unresolved result, collect one ``ValidationIssue`` rather than abort, and
    not raise. This asserts ``export_unified(..., None, ...)`` returns both
    files, collects exactly one informational ``MF-EXPORT-NO-A2L`` issue tagged
    ``param-half``, and raises nothing.
    """
    changeset = unified_changeset_factory()

    result = export_unified(changeset, None, tmp_path)

    # Both files are still produced — the export did not abort.
    assert result.cdfx_path is not None and result.cdfx_path.exists()
    assert result.memory_field_path is not None
    assert result.memory_field_path.exists()

    no_a2l = [i for i in result.issues if i.code == EXPORT_NO_A2L]
    assert len(no_a2l) == 1, "expected exactly one MF-EXPORT-NO-A2L info issue"
    assert no_a2l[0].severity.value == "info"
    assert no_a2l[0].artifact == PARAM_HALF_ARTIFACT


def test_tc036_no_a2l_export_resolves_every_parameter_unresolved_no_a2l(
    tmp_path: Path,
) -> None:
    """TC-036 — with no A2L, every parameter entry resolves ``UNRESOLVED_NO_A2L``.

    The no-A2L arm must still *run* the resolver (against ``None`` tags) so the
    batch-03 ``unresolved-no-a2l`` semantics are reproduced exactly — not skip
    resolution. This asserts every parameter-half entry's status is
    ``UNRESOLVED_NO_A2L`` after the export, so the CDFX writer correctly
    excludes them all.
    """
    changeset = unified_changeset_factory()

    export_unified(changeset, None, tmp_path)

    statuses = {e.status for e in changeset.parameters.entries}
    assert statuses == {ResolutionStatus.UNRESOLVED_NO_A2L}


def test_tc036_empty_a2l_list_is_treated_as_no_a2l(tmp_path: Path) -> None:
    """TC-036 — an empty enriched-tag list is treated the same as no A2L.

    An empty ``[]`` tag list carries no A2L parameters; the coordinator must
    treat it like ``None`` — the same way ``resolve_against_a2l`` does. This
    asserts an empty list also collects the ``MF-EXPORT-NO-A2L`` info issue.
    """
    changeset = unified_changeset_factory()

    result = export_unified(changeset, [], tmp_path)

    assert EXPORT_NO_A2L in [i.code for i in result.issues]
