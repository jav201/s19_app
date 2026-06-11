"""
Change-set file write tests — s19_app batch-04, increment 5; re-pointed to
the v2 writer (``s19_app/tui/changes/io.py``) at batch-07 E3b (§6.6
dispositions).

Covers the write half of the v2 change-set JSON file handler:

  - TC-015 — file JSON structure (REWRITTEN to the v2 envelope): the written
             file is valid JSON re-parseable by ``json.loads`` and carries
             the five LLR-001.1 metadata fields plus the ``entries`` array;
             serialization is byte-deterministic; an empty document still
             writes a valid, complete envelope.
  - TC-016 — RETIRED at E3b: the parameter half (``ChangeListEntry`` name /
             index / value / status encoding, adversarial-float precision)
             does not exist in the address-only v2 format (operator decision
             2026-06-10; LLR-003.3).
  - TC-017 — entry encoding (REWRITTEN to the v2 wire grammar, LLR-001.2):
             ``entries`` is a JSON **array of objects**; ``address`` is the
             canonical ``"0x..."`` uppercase-hex **string** field (the
             deliberate departure from the batch-04 integer form — hex-first,
             gate-confirmed); a bytes entry's run is the strict
             space-separated two-hex-digit token string; the exact address
             and ordered byte run survive with no loss, in insertion order.
  - TC-018 — the write is work-area-contained (SURVIVES — zero
             schema-dependent assertions): a save produces a JSON file
             resolving under ``.s19tool/workarea/``; a write target that is,
             or whose traversed parents include, a symbolic link / NTFS
             reparse point is rejected with a write-side
             ``MF-WRITE-CONTAINMENT`` ``ValidationIssue`` (not a crash); a
             colliding file name is dedup-suffixed, never a silent clobber.

The containment assertions (TC-018) back the staged-containment pattern — the
reused, hardened ``workspace.copy_into_workarea`` primitive must guard every
write, and a rejection must surface as a collected ``ValidationIssue``, never
an uncaught exception (collect-don't-abort).

**Reparse-point arm — deterministic mechanism.** TC-018's reparse-point arm is
exercised two ways so a CI skip is never silent (the batch-03 CV-03 pattern):
  1. an **injectable copy-helper seam** — ``write_change_document`` takes
     ``copy_fn`` as a parameter; the test stubs it to raise
     ``WorkareaContainmentError``, exercising the rejection path with no OS
     symlink privilege. This arm always runs.
  2. a **real reparse point** — ``.s19tool/workarea`` is made a symbolic link
     to an out-of-containment directory; the reused helper resolves the target
     out of the work area and rejects it. This arm needs the privilege to
     create a symlink; it carries a recorded-reason ``skipif`` so the skip is
     visible in the report (CV-03), never silent.

Every fixture is synthetic and built in-test (constraint C-9).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from s19_app.tui.changes import io as changes_io
from s19_app.tui.changes.io import (
    CHANGES_ARTIFACT,
    FORMAT_ID,
    FORMAT_VERSION,
    MF_WRITE_CONTAINMENT,
    serialize_change_document,
    write_change_document,
)
from s19_app.tui.changes.model import ChangeDocument
from s19_app.tui.workspace import (
    WORKAREA_DIRNAME,
    WORKAREA_SUBDIR,
    WorkareaContainmentError,
)

from tests.conftest import change_document_factory


def _empty_document() -> ChangeDocument:
    """A valid v2 envelope with no entries."""
    return ChangeDocument(
        format=FORMAT_ID,
        version=FORMAT_VERSION,
        kind="change",
        encoding="utf-8",
        value_mode="text",
    )


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
# TC-015 — change-file JSON structure (LLR-001.1)
# ---------------------------------------------------------------------------


def test_tc015_written_file_is_valid_json_with_the_v2_envelope(
    tmp_path: Path,
) -> None:
    """TC-015 — the written file parses as JSON and carries the v2 envelope.

    LLR-001.1 requires a single JSON document with the five metadata fields
    and the ``entries`` array. This asserts the file re-parses with
    ``json.loads`` and carries exactly those keys, so a writer that drops the
    self-describing header or the entries array fails the test.
    """
    document = change_document_factory()

    path, issues = write_change_document(document, tmp_path, "cs.json")

    assert path is not None, f"write was rejected: {[i.code for i in issues]}"
    assert issues == []

    written = json.loads(path.read_bytes())
    assert written["format"] == FORMAT_ID
    assert written["version"] == FORMAT_VERSION
    assert written["kind"] == "change"
    assert written["encoding"] == "utf-8"
    assert written["value_mode"] == "text"
    assert isinstance(written["entries"], list)


def test_tc015_serialize_is_byte_deterministic() -> None:
    """TC-015 — two serializations of the same document are byte-identical.

    The change file must be reproducible — the deterministic-order contract
    carries through to the file. This asserts ``serialize_change_document``
    adds no second ordering rule and no nondeterministic field, so a save is
    diff-stable.
    """
    document = change_document_factory()

    first = serialize_change_document(document)
    second = serialize_change_document(document)

    assert first == second


def test_tc015_empty_document_still_writes_a_valid_envelope(
    tmp_path: Path,
) -> None:
    """TC-015 — an empty document still produces a valid, complete envelope.

    A save of an empty change set must still be a well-formed v2 file — the
    five metadata fields present and an empty ``entries`` array — so a later
    load does not trip the structural check. This asserts the empty case is
    not a special-cased crash or a malformed stub.
    """
    path, issues = write_change_document(
        _empty_document(), tmp_path, "empty.json"
    )

    assert path is not None and issues == []
    written = json.loads(path.read_bytes())
    assert written["format"] == FORMAT_ID
    assert written["kind"] == "change"
    assert written["entries"] == []


# ---------------------------------------------------------------------------
# TC-017 — entry encoding on the wire (LLR-001.2)
# ---------------------------------------------------------------------------


def test_tc017_entries_is_an_array_of_objects(tmp_path: Path) -> None:
    """TC-017 — ``entries`` is a JSON array of objects (LLR-001.2).

    The v2 wire format pins ``entries`` as a JSON **array of objects**, not
    an address-keyed object. This asserts the array's every element is a
    ``dict`` carrying ``type`` and ``address`` — so a writer that keys
    entries by address fails the test directly.
    """
    document = change_document_factory()

    path, _ = write_change_document(document, tmp_path, "mem.json")
    entries = json.loads(path.read_bytes())["entries"]

    assert isinstance(entries, list)
    assert len(entries) == 3
    for element in entries:
        assert isinstance(element, dict)
        assert "type" in element
        assert "address" in element


def test_tc017_address_is_the_canonical_hex_string_field(
    tmp_path: Path,
) -> None:
    """TC-017 — ``address`` is the canonical ``"0x..."`` hex string field.

    REWRITTEN re-pin: LLR-001.2 deliberately departs from the batch-04
    integer-address wire shape — the canonical writer emits the unambiguous,
    hex-first ``"0x..."`` uppercase string form (gate-confirmed 2026-06-10).
    This asserts the raw JSON text carries ``"address": "0x200"`` — and that
    no address-as-object-key shape (``"512":``) appears.
    """
    document = change_document_factory()

    path, _ = write_change_document(document, tmp_path, "addr.json")
    raw_text = path.read_text(encoding="utf-8")
    assert '"address": "0x200"' in raw_text
    assert '"512":' not in raw_text

    entries = json.loads(raw_text)["entries"]
    for element in entries:
        assert isinstance(element["address"], str)
        assert element["address"].startswith("0x")


def test_tc017_entry_round_trips_address_and_byte_run(tmp_path: Path) -> None:
    """TC-017 — the exact address and ordered byte run survive (LLR-001.2).

    A reader must recover the exact address and the exact ordered byte
    sequence with no loss. This asserts the written bytes entries carry the
    precise addresses and the strict wire-grammar token runs the factory
    built — order and length preserved — so a re-ordering or value-losing
    encode fails the test.
    """
    document = change_document_factory()

    path, _ = write_change_document(document, tmp_path, "run.json")
    entries = json.loads(path.read_bytes())["entries"]

    bytes_entries = {
        e["address"]: e["bytes"] for e in entries if e["type"] == "bytes"
    }
    # The strict wire grammar: uppercase, two-hex-digit, space-separated.
    assert bytes_entries == {"0x200": "DE AD BE EF", "0x110": "01 02"}
    # The string entry re-emits its raw declaration, not its encoding.
    string_entry = next(e for e in entries if e["type"] == "string")
    assert string_entry["value"] == "REV_C"


def test_tc017_entries_preserve_insertion_order(tmp_path: Path) -> None:
    """TC-017 — the entries array is written in document insertion order.

    The deterministic order of the in-memory document must carry into the
    file so a load reconstructs the same order. This asserts the written
    ``entries`` order matches ``ChangeDocument.entries`` exactly.
    """
    document = change_document_factory()
    expected = [f"0x{e.address:X}" for e in document.entries]

    path, _ = write_change_document(document, tmp_path, "order.json")
    entries = json.loads(path.read_bytes())["entries"]

    assert [element["address"] for element in entries] == expected


# ---------------------------------------------------------------------------
# TC-018 — the write is work-area-contained
# ---------------------------------------------------------------------------


def test_tc018_write_target_resolves_under_workarea(tmp_path: Path) -> None:
    """TC-018 — a save places the JSON file under ``.s19tool/workarea/``.

    Every change-file write lands inside the work area through the reused
    containment path. This asserts the returned path resolves under
    ``.s19tool/workarea/`` and the save is clean — no containment issue on a
    normal write.
    """
    document = change_document_factory()

    path, issues = write_change_document(document, tmp_path, "cs.json")

    assert path is not None, f"write was rejected: {[i.code for i in issues]}"
    workarea = tmp_path / WORKAREA_DIRNAME / WORKAREA_SUBDIR
    assert path.resolve().is_relative_to(workarea.resolve()), (
        f"the change file was written outside the work area: {path}"
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
    document = change_document_factory()

    path, issues = write_change_document(
        document, tmp_path, "../../escape.json"
    )

    assert path is not None, f"write was rejected: {[i.code for i in issues]}"
    workarea = tmp_path / WORKAREA_DIRNAME / WORKAREA_SUBDIR
    assert path.resolve().is_relative_to(workarea.resolve())
    assert path.name == "escape.json"


def test_tc018_name_without_json_suffix_gets_one(tmp_path: Path) -> None:
    """TC-018 — a requested name with no ``.json`` suffix is given one.

    The change file is a JSON document; the writer forces a ``.json`` suffix
    so the on-disk name reflects the content. This asserts a bare name without
    a suffix is written as ``<name>.json``.
    """
    document = change_document_factory()

    path, _ = write_change_document(document, tmp_path, "patchset")

    assert path is not None
    assert path.name == "patchset.json"


def test_tc018_existing_name_is_dedup_suffixed(tmp_path: Path) -> None:
    """TC-018 — a save onto an existing filename is dedup-suffixed.

    A silent clobber is forbidden: a second save under the same name must
    produce a distinct ``_<N>``-suffixed file. This asserts the second write
    lands at ``cs_1.json`` and both files survive on disk.
    """
    document = change_document_factory()

    first, _ = write_change_document(document, tmp_path, "cs.json")
    second, _ = write_change_document(document, tmp_path, "cs.json")

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
    document = change_document_factory()

    path, _ = write_change_document(document, tmp_path, "cs.json")

    assert path is not None
    temp_dir = tmp_path / WORKAREA_DIRNAME / WORKAREA_SUBDIR / "temp"
    leftover = list(temp_dir.glob("*.json")) if temp_dir.exists() else []
    assert leftover == [], f"a staging temp file was left behind: {leftover}"


def test_tc018_containment_rejection_surfaces_issue_not_exception(
    tmp_path: Path,
) -> None:
    """TC-018 — a containment failure is a ``ValidationIssue``, never a crash.

    Collect-don't-abort: a containment / reparse-point rejection must be a
    returned ``MF-WRITE-CONTAINMENT`` issue, not an uncaught exception. This
    arm forces the rejection **deterministically** via the injectable
    ``copy_fn`` seam — a stub raising ``WorkareaContainmentError`` — so it
    runs on every OS with no symlink privilege. ``write_change_document``
    must catch it and return ``(None, [MF-WRITE-CONTAINMENT])``.
    """
    document = change_document_factory()

    def reject(*_args, **_kwargs):
        raise WorkareaContainmentError(
            "Refusing to copy: destination traverses a reparse point"
        )

    path, issues = write_change_document(
        document, tmp_path, "cs.json", copy_fn=reject
    )

    assert path is None, "a rejected write must not return a path"
    codes = [i.code for i in issues]
    assert codes == [MF_WRITE_CONTAINMENT], (
        f"expected exactly one MF-WRITE-CONTAINMENT issue, got {codes}"
    )
    issue = issues[0]
    assert issue.severity is changes_io.ValidationSeverity.WARNING
    assert issue.artifact == CHANGES_ARTIFACT


def test_tc018_oserror_from_staged_write_surfaces_issue_not_exception(
    tmp_path: Path, monkeypatch
) -> None:
    """TC-018 — an OSError from the staged-temp write is a ``ValidationIssue``,
    never an uncaught exception (security finding S57-02).

    The collect-don't-abort / "never an uncaught exception" claim must hold
    not only for a ``WorkareaContainmentError`` from the copy helper but also
    for an ``OSError`` from the staged-temp ``write_bytes`` itself — a full
    disk, a denied permission, a name too long. The batch-04 security review
    flagged (S57-02) that an original ``try`` caught only
    ``WorkareaContainmentError``, so such an ``OSError`` would escape and
    crash the save. This forces a ``PermissionError`` (an ``OSError``
    subclass) out of the staged write and asserts ``write_change_document``
    catches it, returns ``(None, [MF-WRITE-CONTAINMENT])`` and does not
    propagate.
    """
    document = change_document_factory()

    real_write_bytes = Path.write_bytes

    def failing_write_bytes(self: Path, data: bytes) -> int:
        # Only the staged temp file under .s19tool/workarea/temp/ fails — the
        # work-area scaffolding (ensure_workarea) writes nothing through this
        # path, so this isolates the staged-write OSError arm.
        if "temp" in self.parts and self.suffix == ".json":
            raise PermissionError("simulated: permission denied on staged temp")
        return real_write_bytes(self, data)

    monkeypatch.setattr(Path, "write_bytes", failing_write_bytes)

    path, issues = write_change_document(document, tmp_path, "cs.json")

    assert path is None, "a write that hit an OSError must not return a path"
    assert [i.code for i in issues] == [MF_WRITE_CONTAINMENT], (
        f"expected exactly one MF-WRITE-CONTAINMENT issue from the OSError, "
        f"got {[i.code for i in issues]}"
    )
    issue = issues[0]
    assert issue.severity is changes_io.ValidationSeverity.WARNING
    assert issue.artifact == CHANGES_ARTIFACT
    # The issue detail names the OSError kind so an operator can act on it.
    assert "PermissionError" in issue.message


def test_tc018_containment_rejection_via_monkeypatched_helper(
    tmp_path: Path, monkeypatch
) -> None:
    """TC-018 — the rejection path also holds when the module-level helper is
    stubbed (the batch-03 CV-03 monkeypatch arm).

    Beside the ``copy_fn`` parameter seam, the reused ``copy_into_workarea``
    symbol imported into ``changes.io`` is itself replaceable. This asserts
    the default-argument path (no explicit ``copy_fn``) still routes through
    that symbol, so a future refactor that bypasses the reused helper is
    caught.
    """

    def reject(*_args, **_kwargs):
        raise WorkareaContainmentError("Refusing to copy: outside the work area")

    monkeypatch.setattr(changes_io, "copy_into_workarea", reject)

    document = change_document_factory()
    path, issues = write_change_document(document, tmp_path, "cs.json")

    assert path is None
    assert [i.code for i in issues] == [MF_WRITE_CONTAINMENT]


def test_tc018_real_reparse_point_traversal_rejected(tmp_path: Path) -> None:
    """TC-018 — a write whose work-area directory is a real symbolic link to an
    out-of-containment location is rejected with ``MF-WRITE-CONTAINMENT``,
    not a crash.

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

    document = change_document_factory()
    path, issues = write_change_document(document, tmp_path, "cs.json")

    assert path is None, "a reparse-point-traversing target must not be written"
    codes = [i.code for i in issues]
    assert MF_WRITE_CONTAINMENT in codes, (
        f"expected an MF-WRITE-CONTAINMENT rejection, got {codes}"
    )
    containment = next(i for i in issues if i.code == MF_WRITE_CONTAINMENT)
    assert containment.severity.value == "warning"
    assert containment.artifact == CHANGES_ARTIFACT
