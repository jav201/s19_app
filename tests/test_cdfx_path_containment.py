"""
CDFX load / write path-containment tests — s19_app batch-03, increment 8.

Covers the path-containment seam of the CDFX handler — the load-path resolution
of ``s19_app/tui/cdfx/reader.py`` and the work-area-contained write path of
``s19_app/tui/cdfx/writer.py``, both **reusing** the existing
``s19_app/tui/workspace.py`` helpers rather than re-implementing them
(``01-requirements.md`` LLR-005.5 / LLR-007.7):

  - TC-036 — the ``.cdfx`` write target is work-area-contained at the function
             level: ``write_cdfx_to_workarea`` places the file under
             ``.s19tool/workarea/``; a target whose traversed parents include a
             symbolic link / NTFS reparse point is rejected with a write-side
             ``ValidationIssue`` (not a crash); an existing-name target is
             dedup-suffixed — no silent clobber (LLR-007.7).
  - TC-037 — the CDFX load path resolves the user-supplied path through
             ``workspace.resolve_input_path``; an unresolvable path yields
             exactly one ``R-XML-PARSE`` issue and **no file is opened**
             (asserted via a no-open spy on the file-open seam) (LLR-005.5).

Every fixture is synthetic and built in-test (constraint C-9). The reparse-point
arm of TC-036 carries a recorded-reason ``skipif`` for CI images that lack the
privilege to create a symbolic link (Phase-2 closure CV-03).

This increment is reviewed by the Phase 2 security-reviewer — these tests are
the validation hook for LLR-005.5 / LLR-007.7.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from s19_app.tui.cdfx import read_cdfx, write_cdfx_to_workarea
from s19_app.tui.cdfx import reader as cdfx_reader
from s19_app.tui.cdfx.changelist import ChangeList, ResolutionStatus
from s19_app.tui.cdfx.resolve import ResolutionResult, ResolvedType
from s19_app.tui.workspace import WORKAREA_DIRNAME, WORKAREA_SUBDIR


# ---------------------------------------------------------------------------
# Symlink-capability probe — TC-036's reparse-point arm needs OS privilege.
# ---------------------------------------------------------------------------


def _can_create_symlink(tmp_path: Path) -> bool:
    """Return True when this process can create a directory symlink — false on
    CI images / accounts without the privilege (Windows ``SeCreateSymbolicLink``
    or POSIX restriction)."""
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
# Helpers — a minimal resolved change-list for the writer.
# ---------------------------------------------------------------------------


def _resolved_scalar_change_list() -> tuple[ChangeList, ResolutionResult]:
    """Build a one-entry resolved change-list the writer can serialize."""
    change_list = ChangeList()
    change_list.add("IGN_ADVANCE", None, 12.5, ResolutionStatus.RESOLVED)
    resolution = ResolutionResult(change_list=change_list)
    for entry in change_list.entries:
        resolution.resolved_types[entry.key] = ResolvedType(
            "VALUE", "FLOAT32_IEEE", 1
        )
    return change_list, resolution


def _make_minimal_cdfx() -> bytes:
    """A well-formed ``.cdfx`` for the load-path tests."""
    return (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b"<MSRSW><SHORT-NAME>X</SHORT-NAME><CATEGORY>CDF20</CATEGORY>"
        b"<SW-SYSTEMS><SW-SYSTEM><SHORT-NAME>E</SHORT-NAME>"
        b"<SW-INSTANCE-SPEC><SW-INSTANCE-TREE><SHORT-NAME>P</SHORT-NAME>"
        b"<SW-INSTANCE><SHORT-NAME>IGN</SHORT-NAME><CATEGORY>VALUE</CATEGORY>"
        b"<SW-VALUE-CONT><SW-VALUES-PHYS><V>12.5</V>"
        b"</SW-VALUES-PHYS></SW-VALUE-CONT></SW-INSTANCE>"
        b"</SW-INSTANCE-TREE></SW-INSTANCE-SPEC></SW-SYSTEM></SW-SYSTEMS>"
        b"</MSRSW>"
    )


# ---------------------------------------------------------------------------
# TC-036 — write target is work-area-contained.
# ---------------------------------------------------------------------------


def test_tc036_write_target_resolves_under_workarea(tmp_path: Path) -> None:
    """TC-036 — a save places the ``.cdfx`` under ``.s19tool/workarea/``
    (LLR-007.7)."""
    change_list, resolution = _resolved_scalar_change_list()

    path, issues = write_cdfx_to_workarea(
        change_list, resolution, tmp_path, "patch.cdfx"
    )

    assert path is not None, f"write was rejected: {[i.code for i in issues]}"
    workarea = tmp_path / WORKAREA_DIRNAME / WORKAREA_SUBDIR
    assert path.resolve().is_relative_to(workarea.resolve()), (
        f"the .cdfx was written outside the work area: {path}"
    )
    assert path.exists() and path.suffix == ".cdfx"
    # The write itself is clean — no containment issue on a normal save.
    assert "W-WRITE-CONTAINMENT" not in [i.code for i in issues]


def test_tc036_existing_name_is_dedup_suffixed(tmp_path: Path) -> None:
    """TC-036 — a save onto an existing filename produces a dedup-suffixed file
    (``_<N>`` before the suffix), never a silent clobber (LLR-007.7)."""
    change_list, resolution = _resolved_scalar_change_list()

    first, _ = write_cdfx_to_workarea(
        change_list, resolution, tmp_path, "patch.cdfx"
    )
    second, _ = write_cdfx_to_workarea(
        change_list, resolution, tmp_path, "patch.cdfx"
    )

    assert first is not None and second is not None
    assert first != second, "the second save silently clobbered the first"
    assert first.name == "patch.cdfx"
    assert second.name == "patch_1.cdfx"
    # Both files survive on disk — no clobber.
    assert first.exists() and second.exists()


def test_tc036_filename_with_path_separators_is_contained(
    tmp_path: Path,
) -> None:
    """TC-036 — a requested file name carrying path separators cannot escape
    the work area: only the bare name component is used (LLR-007.7)."""
    change_list, resolution = _resolved_scalar_change_list()

    path, issues = write_cdfx_to_workarea(
        change_list, resolution, tmp_path, "../../escape.cdfx"
    )

    assert path is not None, f"write was rejected: {[i.code for i in issues]}"
    workarea = tmp_path / WORKAREA_DIRNAME / WORKAREA_SUBDIR
    assert path.resolve().is_relative_to(workarea.resolve())
    assert path.name == "escape.cdfx"


def test_tc036_reparse_point_traversal_rejected(tmp_path: Path) -> None:
    """TC-036 — a write whose work-area directory is a symbolic link to an
    out-of-containment location is rejected with a ``W-WRITE-CONTAINMENT``
    ``ValidationIssue``, not a crash (LLR-007.7).

    Making ``.s19tool/workarea`` itself a symlink means the destination
    ``Path.resolve()`` collapses to a location with no ``.s19tool/workarea``
    ancestor — ``copy_into_workarea`` then fails containment, exactly the
    reparse-point defense being exercised through the reused helper.

    The reparse-point arm needs OS privilege to create a symlink; it is skipped
    with a recorded reason on CI images that lack it (Phase-2 closure CV-03).
    """
    if not _can_create_symlink(tmp_path):
        pytest.skip(
            "no privilege to create a symbolic link on this OS / account — "
            "the reparse-point traversal arm of TC-036 cannot run (CV-03)"
        )

    # The real workarea content lives outside any .s19tool/workarea tree.
    real_target = tmp_path / "outside_target"
    real_target.mkdir()
    (real_target / "temp").mkdir()

    # .s19tool/workarea is a symlink pointing at that out-of-containment dir.
    s19tool = tmp_path / ".s19tool"
    s19tool.mkdir()
    workarea_link = s19tool / "workarea"
    os.symlink(real_target, workarea_link, target_is_directory=True)

    change_list, resolution = _resolved_scalar_change_list()

    # The save resolves its target through the symlink; copy_into_workarea
    # resolves it out of the .s19tool/workarea tree and rejects it.
    path, issues = write_cdfx_to_workarea(
        change_list, resolution, tmp_path, "patch.cdfx"
    )

    assert path is None, "a reparse-point-traversing target must not be written"
    codes = [i.code for i in issues]
    assert "W-WRITE-CONTAINMENT" in codes, (
        f"expected a W-WRITE-CONTAINMENT rejection, got {codes}"
    )
    containment = next(i for i in issues if i.code == "W-WRITE-CONTAINMENT")
    assert containment.severity.value == "warning"
    assert containment.artifact == "cdfx"


def test_tc036_containment_rejection_surfaces_issue_not_exception(
    tmp_path: Path, monkeypatch
) -> None:
    """TC-036 — a containment failure is a ``ValidationIssue``, never an
    uncaught exception: ``write_cdfx_to_workarea`` always returns a tuple
    (LLR-007.7 collect-don't-abort).

    The reparse-point case is privilege-gated; this arm forces the rejection
    deterministically by stubbing the reused ``copy_into_workarea`` helper to
    raise ``WorkareaContainmentError`` — the writer must catch it.
    """
    from s19_app.tui import workspace
    from s19_app.tui.cdfx import writer as cdfx_writer

    def reject(*_args, **_kwargs):
        raise workspace.WorkareaContainmentError(
            "Refusing to copy: destination traverses a reparse point"
        )

    monkeypatch.setattr(cdfx_writer, "copy_into_workarea", reject)

    change_list, resolution = _resolved_scalar_change_list()
    path, issues = write_cdfx_to_workarea(
        change_list, resolution, tmp_path, "patch.cdfx"
    )

    assert path is None
    assert [i.code for i in issues if i.code == "W-WRITE-CONTAINMENT"] == [
        "W-WRITE-CONTAINMENT"
    ]


# ---------------------------------------------------------------------------
# TC-037 — load path resolves the user-supplied path.
# ---------------------------------------------------------------------------


def test_tc037_valid_path_is_resolved_and_read(tmp_path: Path) -> None:
    """TC-037 — a valid ``.cdfx`` path is resolved via ``resolve_input_path``
    and read into change-list entries (LLR-005.5)."""
    cdfx_file = tmp_path / "loadable.cdfx"
    cdfx_file.write_bytes(_make_minimal_cdfx())

    change_list, issues = read_cdfx(cdfx_file, base_dir=tmp_path)

    assert [i.code for i in issues] == []
    assert len(change_list.entries) == 1
    assert change_list.entries[0].parameter_name == "IGN"


def test_tc037_relative_path_resolved_against_base_dir(tmp_path: Path) -> None:
    """TC-037 — a relative ``.cdfx`` path is resolved against ``base_dir`` by
    the shared ``resolve_input_path`` helper (LLR-005.5)."""
    cdfx_file = tmp_path / "relative.cdfx"
    cdfx_file.write_bytes(_make_minimal_cdfx())

    # Pass the bare name + base_dir — resolution must locate it under base_dir.
    change_list, issues = read_cdfx("relative.cdfx", base_dir=tmp_path)

    assert [i.code for i in issues] == []
    assert len(change_list.entries) == 1


def test_tc037_unresolvable_path_yields_one_parse_issue(
    tmp_path: Path,
) -> None:
    """TC-037 — an unresolvable ``.cdfx`` path yields exactly one
    ``R-XML-PARSE`` issue and an empty change-list (LLR-005.5)."""
    missing = tmp_path / "does_not_exist.cdfx"

    change_list, issues = read_cdfx(missing, base_dir=tmp_path)

    assert change_list.entries == []
    assert len(issues) == 1
    assert issues[0].code == "R-XML-PARSE"
    assert issues[0].artifact == "cdfx"
    assert "could not be resolved" in issues[0].message


def test_tc037_unresolvable_path_opens_no_file(
    tmp_path: Path, monkeypatch
) -> None:
    """TC-037 — when the path does not resolve, **no file is opened**: the
    file-open seam is never reached (LLR-005.5).

    Asserted with a no-open spy: ``Path.read_bytes`` is wrapped and must record
    zero calls for an unresolvable path.
    """
    opened: list[Path] = []
    real_read_bytes = Path.read_bytes

    def spy_read_bytes(self):
        opened.append(self)
        return real_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", spy_read_bytes)

    missing = tmp_path / "never_opened.cdfx"
    change_list, issues = read_cdfx(missing, base_dir=tmp_path)

    assert change_list.entries == []
    assert [i.code for i in issues] == ["R-XML-PARSE"]
    assert opened == [], (
        f"a file was opened for an unresolvable path: {opened}"
    )


def test_tc037_resolved_path_does_open_the_file(
    tmp_path: Path, monkeypatch
) -> None:
    """TC-037 — the no-open spy is meaningful: a *resolvable* path **does**
    reach the file-open seam exactly once (control for the no-open assertion)."""
    opened: list[Path] = []
    real_read_bytes = Path.read_bytes

    def spy_read_bytes(self):
        opened.append(self)
        return real_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", spy_read_bytes)

    cdfx_file = tmp_path / "real.cdfx"
    cdfx_file.write_bytes(_make_minimal_cdfx())

    read_cdfx(cdfx_file, base_dir=tmp_path)

    assert len(opened) == 1, (
        "a resolvable .cdfx path must open the file exactly once"
    )


def test_tc037_bytes_source_skips_path_resolution(monkeypatch) -> None:
    """TC-037 — a ``bytes`` source has no path to resolve: ``resolve_input_path``
    is not invoked and no file is opened (the in-memory read path)."""
    resolve_calls: list[object] = []
    real_resolve = cdfx_reader.resolve_input_path

    def spy_resolve(raw_path, base_dir):
        resolve_calls.append(raw_path)
        return real_resolve(raw_path, base_dir)

    monkeypatch.setattr(cdfx_reader, "resolve_input_path", spy_resolve)

    change_list, issues = read_cdfx(_make_minimal_cdfx())

    assert [i.code for i in issues] == []
    assert len(change_list.entries) == 1
    assert resolve_calls == [], (
        "resolve_input_path was called for a bytes source — there is no path "
        "to resolve"
    )
