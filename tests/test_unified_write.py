"""
Unified change-set file write tests — s19_app batch-04, increment 5.

Covers the write half of the unified change-set JSON file handler
(``s19_app/tui/cdfx/unified_io.py``):

  - TC-015 — unified file JSON structure (LLR-005.1): the written file is valid
             JSON re-parseable by ``json.loads`` and carries a
             format-identifier field, a version field, a parameter half and a
             memory-field half.
  - TC-016 — the parameter half encodes each parameter entry (LLR-005.2): a
             ``ChangeListEntry`` round-trips its ``parameter_name``,
             ``array_index`` (including the ``None`` scalar/string shape),
             ``value`` and resolution ``status`` through the file.
  - TC-017 — the memory-field half encodes each memory entry (LLR-005.3): the
             memory half is a JSON **array of objects**, each carrying
             ``address`` as an integer-valued field (a JSON number, never an
             object key) and ``new_bytes`` as an integer array; the exact
             integer address and the exact ordered byte run survive with no
             loss.
  - TC-018 — the write is work-area-contained (LLR-005.4): a save produces a
             JSON file resolving under ``.s19tool/workarea/``; a write target
             that is, or whose traversed parents include, a symbolic link /
             NTFS reparse point is rejected with a write-side
             ``MF-WRITE-CONTAINMENT`` ``ValidationIssue`` (not a crash); a
             colliding file name is dedup-suffixed, never a silent clobber.

These tests encode WHY each behaviour matters. The structure / encoding
assertions (TC-015..TC-017) pin the on-disk wire format normatively — the
``address``-as-integer-field shape (LLR-005.3 / DD-10) is asserted directly
here because a wrong shape is otherwise invisible until the increment-9
round-trip; getting it wrong would let two implementations agree by accident.
The containment assertions (TC-018) back constraint C-10 — the reused, hardened
``workspace.copy_into_workarea`` primitive must guard every write, and a
rejection must surface as a collected ``ValidationIssue``, never an uncaught
exception (collect-don't-abort).

**Reparse-point arm — deterministic mechanism.** TC-018's reparse-point arm is
exercised two ways so a CI skip is never silent (the batch-03 CV-03 pattern):
  1. an **injectable copy-helper seam** — ``write_unified_to_workarea`` takes
     ``copy_fn`` as a parameter; the test stubs it to raise
     ``WorkareaContainmentError``, exercising the rejection path with no OS
     symlink privilege. This arm always runs.
  2. a **real reparse point** — ``.s19tool/workarea`` is made a symbolic link
     to an out-of-containment directory; the reused helper resolves the target
     out of the work area and rejects it. This arm needs the privilege to
     create a symlink; it carries a recorded-reason ``skipif`` so the skip is
     visible in the report (CV-03), never silent.

Every fixture is synthetic and built in-test (constraint C-9). This increment
carries the unified-file write-path containment and is a Phase-2
security-reviewer hand-off surface (§5.5).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from s19_app.tui.cdfx import (
    ResolutionStatus,
    UnifiedChangeSet,
    serialize_unified,
    write_unified_to_workarea,
)
from s19_app.tui.cdfx import unified_io
from s19_app.tui.cdfx.unified_io import (
    MF_WRITE_CONTAINMENT,
    UNIFIED_ARTIFACT,
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
# Symlink-capability probe — TC-018's real-reparse-point arm needs OS privilege
# (the batch-03 CV-03 pattern, reused verbatim).
# ---------------------------------------------------------------------------


def _can_create_symlink(tmp_path: Path) -> bool:
    """Return True when this process can create a directory symlink — false on
    CI images / accounts without the privilege (Windows ``SeCreateSymbolicLink``
    or a POSIX restriction)."""
    probe_target = tmp_path / "_symlink_probe_target"
    probe_link = tmp_path / "_symlink_probe_link"
    try:
        probe_target.mkdir()
        os.symlink(probe_target, probe_link, target_is_directory=True)
    except (OSError, NotImplementedError):
        return False
    finally:
        for path in (probe_link, probe_target):
            try:
                if path.is_symlink() or path.exists():
                    if path.is_dir() and not path.is_symlink():
                        path.rmdir()
                    else:
                        path.unlink()
            except OSError:
                pass
    return True


# ---------------------------------------------------------------------------
# TC-015 — unified file JSON structure (LLR-005.1)
# ---------------------------------------------------------------------------


def test_tc015_written_file_is_valid_json_with_all_four_top_level_keys(
    tmp_path: Path,
) -> None:
    """TC-015 — the written file parses as JSON and carries the four parts (LLR-005.1).

    LLR-005.1 requires a single JSON document with a format identifier, a
    version, a parameter half and a memory-field half. This asserts the file
    re-parses with ``json.loads`` and carries exactly those keys, so a writer
    that drops the self-describing header or a half fails the test.
    """
    changeset = unified_changeset_factory()

    path, issues = write_unified_to_workarea(changeset, tmp_path, "cs.json")

    assert path is not None, f"write was rejected: {[i.code for i in issues]}"
    assert issues == []

    document = json.loads(path.read_bytes())
    assert document["format"] == UNIFIED_FORMAT_ID
    assert document["version"] == UNIFIED_FORMAT_VERSION
    # Both halves are present and are JSON arrays.
    assert isinstance(document["parameters"], list)
    assert isinstance(document["memory"], list)


def test_tc015_serialize_unified_is_byte_deterministic() -> None:
    """TC-015 — two serializations of the same change-set are byte-identical (LLR-001.4).

    The unified file must be reproducible — LLR-001.4 carries through to the
    file. This asserts ``serialize_unified`` adds no second ordering rule and
    no nondeterministic field, so a save is diff-stable.
    """
    changeset = unified_changeset_factory()

    first = serialize_unified(changeset)
    second = serialize_unified(changeset)

    assert first == second


def test_tc015_empty_change_set_still_writes_a_valid_document(
    tmp_path: Path,
) -> None:
    """TC-015 — an empty change-set still produces a valid, complete document.

    A save of an empty patch set must still be a well-formed unified file —
    the header and both (empty) halves present — so a later load does not trip
    the structural check. This asserts the empty case is not a special-cased
    crash or a malformed stub.
    """
    path, issues = write_unified_to_workarea(
        UnifiedChangeSet(), tmp_path, "empty.json"
    )

    assert path is not None and issues == []
    document = json.loads(path.read_bytes())
    assert document["format"] == UNIFIED_FORMAT_ID
    assert document["parameters"] == []
    assert document["memory"] == []


# ---------------------------------------------------------------------------
# TC-016 — the parameter half encodes each parameter entry (LLR-005.2)
# ---------------------------------------------------------------------------


def test_tc016_parameter_entry_round_trips_its_fields(tmp_path: Path) -> None:
    """TC-016 — a parameter entry encodes name / index / value / status (LLR-005.2).

    LLR-005.2 names exactly the four ``ChangeListEntry`` fields the parameter
    half must carry. This asserts a scalar (``array_index`` is ``None``), an
    array element (``array_index`` an integer) and an ASCII string entry each
    carry all four fields with the right values, so a writer that drops a field
    or mis-encodes the ``None`` scalar shape fails the test.
    """
    changeset = unified_changeset_factory()

    path, _ = write_unified_to_workarea(changeset, tmp_path, "params.json")
    document = json.loads(path.read_bytes())
    parameters = document["parameters"]

    by_key = {(p["parameter_name"], p["array_index"]): p for p in parameters}

    # Scalar entry — array_index is the JSON null / Python None.
    scalar = by_key[("IGN_ADVANCE_BASE", None)]
    assert scalar["value"] == 23
    assert scalar["status"] == ResolutionStatus.RESOLVED.value

    # Array-element entry — array_index is an integer.
    array_elem = by_key[("FUEL_TRIM_TABLE", 1)]
    assert array_elem["value"] == 24
    assert array_elem["status"] == ResolutionStatus.RESOLVED.value

    # ASCII string entry — value survives as a plain JSON string.
    ascii_entry = by_key[("CAL_LABEL", None)]
    assert ascii_entry["value"] == "REV_C"


def test_tc016_parameter_half_preserves_insertion_order(
    tmp_path: Path,
) -> None:
    """TC-016 — the parameter half is written in change-list insertion order.

    The deterministic order of the in-memory ``ChangeList`` (LLR-001.4) must
    carry into the file so a load reconstructs the same order. This asserts the
    written ``parameters`` array order matches ``ChangeList.entries`` exactly.
    """
    changeset = unified_changeset_factory()
    expected = [
        (e.parameter_name, e.array_index) for e in changeset.parameters.entries
    ]

    path, _ = write_unified_to_workarea(changeset, tmp_path, "order.json")
    document = json.loads(path.read_bytes())
    written = [
        (p["parameter_name"], p["array_index"]) for p in document["parameters"]
    ]

    assert written == expected


def test_tc016_adversarial_floats_survive_full_binary64_precision(
    tmp_path: Path,
) -> None:
    """TC-016 — the three adversarial IEEE floats survive with no precision loss.

    The parameter half carries the three adversarial binary64 floats; stdlib
    ``json`` preserves full binary64. This asserts each round-trips by **exact
    ``==``, no tolerance**, so a lossy intermediate string conversion in the
    serializer would fail the test (the same sensitivity the increment-9
    round-trip relies on).
    """
    changeset = unified_changeset_factory()

    path, _ = write_unified_to_workarea(changeset, tmp_path, "floats.json")
    document = json.loads(path.read_bytes())
    float_values = [
        p["value"]
        for p in document["parameters"]
        if p["parameter_name"] == "FLOAT_ADV_BLOCK"
    ]

    assert float_values == [0.1, 5e-324, 8.98846567431158e307]


# ---------------------------------------------------------------------------
# TC-017 — the memory-field half encodes each memory entry (LLR-005.3)
# ---------------------------------------------------------------------------


def test_tc017_memory_half_is_an_array_of_objects(tmp_path: Path) -> None:
    """TC-017 — the memory half is a JSON array of objects (LLR-005.3 / DD-10).

    LLR-005.3 normatively pins the memory half as a JSON **array of objects**,
    not a name-keyed object. This asserts the half is a ``list`` whose every
    element is a ``dict`` carrying ``address`` and ``new_bytes`` — so a writer
    that keys entries by address (an object) fails the test directly.
    """
    changeset = unified_changeset_factory()

    path, _ = write_unified_to_workarea(changeset, tmp_path, "mem.json")
    memory = json.loads(path.read_bytes())["memory"]

    assert isinstance(memory, list)
    assert len(memory) == 3
    for element in memory:
        assert isinstance(element, dict)
        assert "address" in element
        assert "new_bytes" in element


def test_tc017_address_is_an_integer_field_never_an_object_key(
    tmp_path: Path,
) -> None:
    """TC-017 — ``address`` is a JSON number field, never an object key (LLR-005.3).

    The crux of LLR-005.3 / DD-10: ``address`` must be an integer-valued field
    inside an array element, not a (string) JSON object key. This asserts the
    raw JSON text carries ``address`` as a bare number — and that re-parsing
    yields a Python ``int`` — so an address-as-key shape (which JSON would
    force to a string) fails the test.
    """
    changeset = unified_changeset_factory()

    path, _ = write_unified_to_workarea(changeset, tmp_path, "addr.json")
    raw_text = path.read_text(encoding="utf-8")
    # The address appears as a JSON number field — `"address": 512` — not as a
    # quoted object key like `"512":`.
    assert '"address": 512' in raw_text
    assert '"512":' not in raw_text

    memory = json.loads(raw_text)["memory"]
    for element in memory:
        assert isinstance(element["address"], int)


def test_tc017_memory_entry_round_trips_address_and_byte_run(
    tmp_path: Path,
) -> None:
    """TC-017 — the exact integer address and ordered byte run survive (LLR-005.3).

    LLR-005.3 requires a reader to recover the exact integer ``address`` and
    the exact ordered ``new_bytes`` sequence with no loss. This asserts the
    written memory objects carry the precise addresses and byte runs the
    factory built — order and length preserved — so a re-ordering or
    value-losing encode fails the test.
    """
    changeset = unified_changeset_factory()
    expected = {e.address: list(e.new_bytes) for e in changeset.memory.entries}

    path, _ = write_unified_to_workarea(changeset, tmp_path, "run.json")
    memory = json.loads(path.read_bytes())["memory"]

    written = {element["address"]: element["new_bytes"] for element in memory}
    assert written == expected
    # The base variant's first entry is the pinned DEADBEEF run at 0x200.
    assert written[0x200] == [0xDE, 0xAD, 0xBE, 0xEF]


def test_tc017_memory_half_preserves_insertion_order(tmp_path: Path) -> None:
    """TC-017 — the memory half is written in memory-change-list insertion order.

    The deterministic order of the ``MemoryChangeList`` (LLR-001.4) must carry
    into the file. This asserts the written ``memory`` array's address order
    matches ``MemoryChangeList.entries`` exactly.
    """
    changeset = unified_changeset_factory()
    expected = [e.address for e in changeset.memory.entries]

    path, _ = write_unified_to_workarea(changeset, tmp_path, "memorder.json")
    memory = json.loads(path.read_bytes())["memory"]

    assert [element["address"] for element in memory] == expected


# ---------------------------------------------------------------------------
# TC-018 — the write is work-area-contained (LLR-005.4)
# ---------------------------------------------------------------------------


def test_tc018_write_target_resolves_under_workarea(tmp_path: Path) -> None:
    """TC-018 — a save places the JSON file under ``.s19tool/workarea/`` (LLR-005.4).

    LLR-005.4 requires every unified-file write to land inside the work area
    through the reused containment path. This asserts the returned path
    resolves under ``.s19tool/workarea/`` and the save is clean — no
    containment issue on a normal write.
    """
    changeset = unified_changeset_factory()

    path, issues = write_unified_to_workarea(changeset, tmp_path, "cs.json")

    assert path is not None, f"write was rejected: {[i.code for i in issues]}"
    workarea = tmp_path / WORKAREA_DIRNAME / WORKAREA_SUBDIR
    assert path.resolve().is_relative_to(workarea.resolve()), (
        f"the unified file was written outside the work area: {path}"
    )
    assert path.exists() and path.suffix == ".json"
    assert MF_WRITE_CONTAINMENT not in [i.code for i in issues]


def test_tc018_filename_with_path_separators_is_contained(
    tmp_path: Path,
) -> None:
    """TC-018 — a file name carrying path separators cannot escape the work area.

    A requested name like ``../../escape.json`` must not let the write land
    outside the work area — only the bare name component is used. This asserts
    the written file is still inside ``.s19tool/workarea/`` and carries only
    the bare ``escape.json`` name.
    """
    changeset = unified_changeset_factory()

    path, issues = write_unified_to_workarea(
        changeset, tmp_path, "../../escape.json"
    )

    assert path is not None, f"write was rejected: {[i.code for i in issues]}"
    workarea = tmp_path / WORKAREA_DIRNAME / WORKAREA_SUBDIR
    assert path.resolve().is_relative_to(workarea.resolve())
    assert path.name == "escape.json"


def test_tc018_name_without_json_suffix_gets_one(tmp_path: Path) -> None:
    """TC-018 — a requested name with no ``.json`` suffix is given one.

    The unified file is a JSON document; the writer forces a ``.json`` suffix
    so the on-disk name reflects the content. This asserts a bare name without
    a suffix is written as ``<name>.json``.
    """
    changeset = unified_changeset_factory()

    path, _ = write_unified_to_workarea(changeset, tmp_path, "patchset")

    assert path is not None
    assert path.name == "patchset.json"


def test_tc018_existing_name_is_dedup_suffixed(tmp_path: Path) -> None:
    """TC-018 — a save onto an existing filename is dedup-suffixed (LLR-005.4).

    LLR-005.4 forbids a silent clobber: a second save under the same name must
    produce a distinct ``_<N>``-suffixed file. This asserts the second write
    lands at ``cs_1.json`` and both files survive on disk.
    """
    changeset = unified_changeset_factory()

    first, _ = write_unified_to_workarea(changeset, tmp_path, "cs.json")
    second, _ = write_unified_to_workarea(changeset, tmp_path, "cs.json")

    assert first is not None and second is not None
    assert first != second, "the second save silently clobbered the first"
    assert first.name == "cs.json"
    assert second.name == "cs_1.json"
    assert first.exists() and second.exists()


def test_tc018_no_temp_file_is_left_behind_after_a_clean_write(
    tmp_path: Path,
) -> None:
    """TC-018 — the staging temp file is removed after a clean write.

    The writer stages the bytes in ``.s19tool/workarea/temp/`` before the
    containment-checked copy. This asserts the staged file does not survive a
    successful save — only the final placed file remains.
    """
    changeset = unified_changeset_factory()

    path, _ = write_unified_to_workarea(changeset, tmp_path, "cs.json")

    assert path is not None
    temp_dir = tmp_path / WORKAREA_DIRNAME / WORKAREA_SUBDIR / "temp"
    leftover = list(temp_dir.glob("*.json")) if temp_dir.exists() else []
    assert leftover == [], f"a staging temp file was left behind: {leftover}"


def test_tc018_containment_rejection_surfaces_issue_not_exception(
    tmp_path: Path,
) -> None:
    """TC-018 — a containment failure is a ``ValidationIssue``, never a crash (LLR-005.4).

    LLR-005.4 collect-don't-abort: a containment / reparse-point rejection must
    be a returned ``MF-WRITE-CONTAINMENT`` issue, not an uncaught exception.
    This arm forces the rejection **deterministically** via the injectable
    ``copy_fn`` seam — a stub raising ``WorkareaContainmentError`` — so it runs
    on every OS with no symlink privilege. ``write_unified_to_workarea`` must
    catch it and return ``(None, [MF-WRITE-CONTAINMENT])``.
    """
    changeset = unified_changeset_factory()

    def reject(*_args, **_kwargs):
        raise WorkareaContainmentError(
            "Refusing to copy: destination traverses a reparse point"
        )

    path, issues = write_unified_to_workarea(
        changeset, tmp_path, "cs.json", copy_fn=reject
    )

    assert path is None, "a rejected write must not return a path"
    codes = [i.code for i in issues]
    assert codes == [MF_WRITE_CONTAINMENT], (
        f"expected exactly one MF-WRITE-CONTAINMENT issue, got {codes}"
    )
    issue = issues[0]
    assert issue.severity is unified_io.ValidationSeverity.WARNING
    assert issue.artifact == UNIFIED_ARTIFACT


def test_tc018_oserror_from_staged_write_surfaces_issue_not_exception(
    tmp_path: Path, monkeypatch
) -> None:
    """TC-018 — an OSError from the staged-temp write is a ``ValidationIssue``,
    never an uncaught exception (security finding S57-02).

    LLR-005.4's collect-don't-abort / "never an uncaught exception" claim must
    hold not only for a ``WorkareaContainmentError`` from the copy helper but
    also for an ``OSError`` from the staged-temp ``write_bytes`` itself — a full
    disk, a denied permission, a name too long. The increment-7 security review
    flagged (S57-02) that the original ``try`` caught only
    ``WorkareaContainmentError``, so such an ``OSError`` would escape and crash
    the save. This forces a ``PermissionError`` (an ``OSError`` subclass) out of
    the staged write and asserts ``write_unified_to_workarea`` catches it,
    returns ``(None, [MF-WRITE-CONTAINMENT])`` and does not propagate.
    """
    changeset = unified_changeset_factory()

    real_write_bytes = Path.write_bytes

    def failing_write_bytes(self: Path, data: bytes) -> int:
        # Only the staged temp file under .s19tool/workarea/temp/ fails — the
        # work-area scaffolding (ensure_workarea) writes nothing through this
        # path, so this isolates the staged-write OSError arm.
        if "temp" in self.parts and self.suffix == ".json":
            raise PermissionError("simulated: permission denied on staged temp")
        return real_write_bytes(self, data)

    monkeypatch.setattr(Path, "write_bytes", failing_write_bytes)

    path, issues = write_unified_to_workarea(changeset, tmp_path, "cs.json")

    assert path is None, "a write that hit an OSError must not return a path"
    assert [i.code for i in issues] == [MF_WRITE_CONTAINMENT], (
        f"expected exactly one MF-WRITE-CONTAINMENT issue from the OSError, "
        f"got {[i.code for i in issues]}"
    )
    issue = issues[0]
    assert issue.severity is unified_io.ValidationSeverity.WARNING
    assert issue.artifact == UNIFIED_ARTIFACT
    # The issue detail names the OSError kind so an operator can act on it.
    assert "PermissionError" in issue.message


def test_tc018_containment_rejection_via_monkeypatched_helper(
    tmp_path: Path, monkeypatch
) -> None:
    """TC-018 — the rejection path also holds when the module-level helper is
    stubbed (the batch-03 CV-03 monkeypatch arm).

    Beside the ``copy_fn`` parameter seam, the reused ``copy_into_workarea``
    symbol imported into ``unified_io`` is itself replaceable. This asserts the
    default-argument path (no explicit ``copy_fn``) still routes through that
    symbol, so a future refactor that bypasses the reused helper is caught.
    """

    def reject(*_args, **_kwargs):
        raise WorkareaContainmentError("Refusing to copy: outside the work area")

    monkeypatch.setattr(unified_io, "copy_into_workarea", reject)

    changeset = unified_changeset_factory()
    path, issues = write_unified_to_workarea(changeset, tmp_path, "cs.json")

    assert path is None
    assert [i.code for i in issues] == [MF_WRITE_CONTAINMENT]


def test_tc018_real_reparse_point_traversal_rejected(tmp_path: Path) -> None:
    """TC-018 — a write whose work-area directory is a real symbolic link to an
    out-of-containment location is rejected with ``MF-WRITE-CONTAINMENT``,
    not a crash (LLR-005.4).

    Making ``.s19tool/workarea`` itself a symlink means the destination
    ``Path.resolve()`` collapses to a location with no ``.s19tool/workarea``
    ancestor — the reused ``copy_into_workarea`` then fails containment, exactly
    the reparse-point defense being exercised through the unchanged helper.

    The real-reparse-point arm needs OS privilege to create a symlink; it is
    skipped with a **recorded reason** on images that lack it, so the skip is
    visible in the report (CV-03), never silent. The deterministic
    ``copy_fn`` / monkeypatch arms above cover the rejection logic on every OS.
    """
    if not _can_create_symlink(tmp_path):
        pytest.skip(
            "no privilege to create a symbolic link on this OS / account — "
            "the real-reparse-point arm of TC-018 cannot run; the injectable "
            "copy_fn arm covers the rejection deterministically (CV-03)"
        )

    # The real work-area content lives outside any .s19tool/workarea tree.
    real_target = tmp_path / "outside_target"
    real_target.mkdir()
    (real_target / "temp").mkdir()

    # .s19tool/workarea is a symlink pointing at that out-of-containment dir.
    s19tool = tmp_path / ".s19tool"
    s19tool.mkdir()
    os.symlink(real_target, s19tool / "workarea", target_is_directory=True)

    changeset = unified_changeset_factory()
    path, issues = write_unified_to_workarea(changeset, tmp_path, "cs.json")

    assert path is None, "a reparse-point-traversing target must not be written"
    codes = [i.code for i in issues]
    assert MF_WRITE_CONTAINMENT in codes, (
        f"expected an MF-WRITE-CONTAINMENT rejection, got {codes}"
    )
    containment = next(i for i in issues if i.code == MF_WRITE_CONTAINMENT)
    assert containment.severity.value == "warning"
    assert containment.artifact == UNIFIED_ARTIFACT
