"""Manifest writer (HLR-001 serialize) — the WRITE side of ``project.json``.

The project manifest is read-only today: ``read_project_manifest``
(``variant_execution_service.py``) parses ``project.json`` and is the schema
oracle. This module adds the missing serializer that turns an in-memory
project composition into the canonical envelope that the reader parses back
without findings — the round-trip-to-reader correctness criterion (D-2), the
JSON analogue of the batch-10 emitter that round-trips against
``IntelHexFile``.

Increment I1 covers SERIALIZE (HLR-001 + LLR-001.1..001.5). Increment I2 adds
the CONTAINED WRITE (HLR-002 + LLR-002.1..002.3): stage the serialized bytes
under ``.s19tool/workarea/temp/``, re-run ``copy_into_workarea``'s containment
CHECKS against the destination, then ATOMIC ``os.replace`` onto the fixed
``project.json`` name (D-3 locked mechanism) — NOT ``copy_into_workarea``'s
dedup body, so a re-save overwrites in place rather than producing
``project_1.json``.

Increment I3 adds VERIFY-ON-WRITE (HLR-003 + LLR-003.1..003.3): re-read the
just-written ``project.json`` via ``read_project_manifest`` addressed by the
CANONICAL fixed name (``project_dir / PROJECT_MANIFEST_NAME``, M-1) — never the
path the write helper returned — and compare the re-read
``active_variant`` / ``batch`` / ``assignments`` against the intended
composition in the C-1 canonical comparison form (intent resolved against
``project_root``). The outcome is a :class:`ManifestVerifyResult` modeled on
the batch-10 ``VerifyResult`` SHAPE (status / drift / issues / written_path)
but compared key-wise over the manifest dict, NOT via ``diff_mem_maps`` (D-1:
a manifest is a JSON dict, not a mem_map). Any re-read reader ``issues`` force
MISMATCH (R-1) — a write the reader degrades must never falsely verify.

Headless by contract (C-3 / LLR-004.3): stdlib + sibling-service imports only,
no ``textual`` symbol and no ``logging`` — so the serializer stays reusable and
testable without a running app.

Security input gate (LLR-001.5 / M-3): an absolute or project-escaping
``batch`` / ``assignments`` entry is REFUSED up front — the serializer returns
``(None, [finding])`` and emits nothing, reusing the reader's own rejection
predicate (``_resolve_manifest_entry``) so there is no second, divergent
path-safety implementation.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Optional, Sequence

from ...validation.model import ValidationIssue, ValidationSeverity
from ..models import ProjectVariantSet
from .report_addendum import DeclaredRegion
from ..workspace import (
    WorkareaContainmentError,
    _guarded_destination,
    _is_reparse_point,
    _private_stage_dir,
    ensure_workarea,
)
from .variant_execution_service import (
    ENTRY_MODE_MANIFEST_KEYS,
    MANIFEST_ARTIFACT,
    PROBLEM_CHANGED,
    PROBLEM_MISSING,
    PROBLEM_NO_DIGESTS,
    PROBLEM_NO_MANIFEST,
    PROBLEM_NOT_READABLE,
    PROBLEM_NOT_RECORDED,
    PROJECT_MANIFEST_NAME,
    PROJECT_RECORDED_SUFFIXES,
    DOCUMENT_REASON_IO_ERROR,
    STEP_CHECK_THEN_LOAD,
    DerivedFrom,
    FileRecord,
    ProjectFileProblem,
    ProjectManifest,
    _EntryWalk,
    _plain_entry,
    _resolve_manifest_entry,
    document_problem_file,
    is_active_document_form,
    manifest_is_damaged,
    manifest_problems,
    read_project_manifest,
)

#: The manifest schema version the serializer emits. The reader accepts any
#: ``int | str | None`` (``variant_execution_service.py:395``); ``1`` is the
#: stable literal (§6.3.2 item 6).
DEFAULT_SCHEMA_VERSION = 1

#: Serialize-path security finding: a ``batch`` / ``assignments`` entry is
#: absolute or resolves outside the project directory, so the whole serialize
#: is refused (LLR-001.5). Distinct from the reader's read-path
#: ``MANIFEST-PATH-ESCAPE`` so a refusal-to-write reads unambiguously.
MANIFEST_WRITE_ESCAPE = "MANIFEST-WRITE-ESCAPE"

#: Write-path containment finding: the destination failed the work-area
#: containment checks, or staging / the atomic ``os.replace`` raised an
#: ``OSError`` (LLR-002.3). Collect-don't-abort — the write returns
#: ``(None, [finding])`` instead of raising, mirroring ``write_change_document``'s
#: ``MF-WRITE-CONTAINMENT`` (``io.py``).
MANIFEST_WRITE_CONTAINMENT = "MANIFEST-WRITE-CONTAINMENT"


def _manifest_write_issue(
    message: str,
    severity: ValidationSeverity = ValidationSeverity.ERROR,
) -> ValidationIssue:
    """
    Summary:
        Build one serialize-path ``ValidationIssue`` tagged
        ``artifact=MANIFEST_ARTIFACT`` with the ``MANIFEST-WRITE-ESCAPE``
        code (LLR-001.5).

    Args:
        message (str): Human-readable finding — names the offending entry and
            its context only.
        severity (ValidationSeverity): Defaults to ERROR (a refused write is
            an error, mirroring the reader's manifest rules).

    Returns:
        ValidationIssue: The finding.

    Data Flow:
        - Created only on the refusal path of :func:`serialize_manifest`.

    Dependencies:
        Uses:
            - ValidationIssue / ValidationSeverity
        Used by:
            - serialize_manifest
    """
    return ValidationIssue(
        code=MANIFEST_WRITE_ESCAPE,
        severity=severity,
        message=message,
        artifact=MANIFEST_ARTIFACT,
    )


def _manifest_write_containment_issue(
    message: str, details: Optional[dict[str, str]] = None
) -> ValidationIssue:
    """
    Summary:
        Build one write-path ``ValidationIssue`` tagged
        ``artifact=MANIFEST_ARTIFACT`` with the ``MANIFEST-WRITE-CONTAINMENT``
        code at WARNING severity (LLR-002.3), mirroring
        ``write_change_document``'s ``MF-WRITE-CONTAINMENT`` finding.

    Args:
        message (str): Human-readable finding describing the failed write.
        details (Optional[dict[str, str]]): ``{"exception": "<class>: <text>"}``
            for the caller's log only, never painted (SEC7-R2-3).

    Returns:
        ValidationIssue: The finding.

    Data Flow:
        - Created only on the containment / IO failure path of
          :func:`write_project_manifest`.

    Dependencies:
        Uses:
            - ValidationIssue / ValidationSeverity
        Used by:
            - write_project_manifest
    """
    return ValidationIssue(
        code=MANIFEST_WRITE_CONTAINMENT,
        severity=ValidationSeverity.WARNING,
        message=message,
        artifact=MANIFEST_ARTIFACT,
        details=dict(details or {}),
    )


def _posix_entries(raw_entries: Sequence[str]) -> list[str]:
    """
    Summary:
        Normalize each path entry to a forward-slash POSIX string so the
        emitted manifest round-trips on both Windows and POSIX (LLR-001.2).

    Args:
        raw_entries (Sequence[str]): Project-relative path strings, possibly
            using back-slashes on Windows.

    Returns:
        list[str]: The same entries with separators normalized to ``/`` and
        in input order (stable — LLR-001.4).

    Data Flow:
        - ``PurePath``-free string transform: ``str.replace("\\\\", "/")``
          keeps already-POSIX entries byte-identical and rewrites Windows
          separators without resolving against the filesystem.

    Dependencies:
        Used by:
            - serialize_manifest
    """
    return [entry.replace("\\", "/") for entry in raw_entries]


def _reject_unsafe_entry(
    project_root: Path,
    entry: str,
    context: str,
    walk: _EntryWalk,
) -> Optional[ValidationIssue]:
    """
    Summary:
        Apply the reader's own rejection predicate to one ``batch`` /
        ``assignments`` entry and report a refusal finding if the entry is
        absolute or escapes ``project_root`` (LLR-001.5).

    Args:
        project_root (Path): The project directory the entry must stay inside
            — the same root the reader resolves against.
        entry (str): The project-relative path string to check.
        context (str): Display context for the finding (``"batch"`` or
            ``"assignments[<id>]"``).
        walk (_EntryWalk): The one walk of this serialize, shared by every
            entry (its cache and folder ceiling, SEC7-R2-2).

    Returns:
        Optional[ValidationIssue]: A ``MANIFEST-WRITE-ESCAPE`` finding when the
        entry is unsafe; ``None`` when the entry resolves cleanly inside the
        project root.

    Data Flow:
        - Delegate to ``_resolve_manifest_entry`` (the reader's predicate) in
          its manifest-keys mode (LLR-169.8, B100-I21) with a throwaway
          issue sink; a ``None`` return OR any appended reader
          issue means the entry is unsafe — re-reported as one refusal finding
          naming the entry, so there is no second path-safety implementation.

    Dependencies:
        Uses:
            - _resolve_manifest_entry
            - _manifest_write_issue
        Used by:
            - serialize_manifest
    """
    probe: list[ValidationIssue] = []
    resolved = _resolve_manifest_entry(
        project_root, entry, context, probe, ENTRY_MODE_MANIFEST_KEYS, walk
    )
    if resolved is not None and not probe:
        return None
    return _manifest_write_issue(
        f"refusing to serialize manifest {context} entry that is absolute or "
        f"escapes the project directory: {entry!r}"
    )


def serialize_manifest(
    variant_set: ProjectVariantSet,
    project_root: Path,
    *,
    batch: Sequence[str] = (),
    assignments: Optional[Mapping[str, Sequence[str]]] = None,
    declared_regions: Sequence[DeclaredRegion] = (),
    gathered: Optional[Mapping[str, Sequence[str]]] = None,
    files: Optional[Mapping[str, FileRecord]] = None,
    derived_from: Optional[Mapping[str, DerivedFrom]] = None,
    schema_version: int = DEFAULT_SCHEMA_VERSION,
    active_document: Optional[str] = None,
) -> tuple[Optional[str], list[ValidationIssue]]:
    """
    Summary:
        Serialize a project composition into the canonical ``project.json``
        envelope text the reader parses back without findings (HLR-001 /
        LLR-001.1..001.5). The envelope carries
        ``{schema_version, active_variant, batch, assignments}`` plus an
        OPTIONAL ``declared_regions`` array, written only when regions are
        declared (LLR-026.1); emission is via the stdlib ``json`` encoder,
        never string assembly (LLR-001.1).

        Security input gate (LLR-001.5): if ANY ``batch`` / ``assignments``
        entry is absolute or resolves outside ``project_root``, the whole
        operation is refused — returns ``(None, [finding, ...])`` and emits no
        text — reusing the reader's rejection predicate.

    Args:
        variant_set (ProjectVariantSet): The in-memory variant inventory;
            ``active_variant`` is its ``active_id`` (``None`` for an empty
            project → JSON ``null``).
        project_root (Path): The project directory every ``batch`` /
            ``assignments`` entry must stay inside — the same root the reader
            resolves against.
        batch (Sequence[str]): Project-wide change/check file entries as
            project-relative path strings (forward- or back-slash; normalized
            to POSIX on emit). Defaults to empty.
        assignments (Optional[Mapping[str, Sequence[str]]]): Per-variant file
            entries keyed by ``variant_id``; each value is a sequence of
            project-relative path strings. ``None`` → empty object.
        declared_regions (Sequence[DeclaredRegion]): Operator-declared memory
            regions (LLR-026.1). Each is serialized as ``{name, start, end}``;
            the key is omitted entirely when empty (back-compat).
        gathered (Optional[Mapping[str, Sequence[str]]]): The change-1 gather
            rows (HLR-138) — project home name (``patches`` / ``checks`` /
            ``templates``) → project-relative POSIX paths, exactly as
            produced by ``project_gather_service.gather_project_artifacts``.
            Each entry is run through the same refusal predicate as
            ``batch`` / ``assignments`` (context ``gathered[<home>]``); the
            key is omitted entirely when ``None`` / empty (back-compat —
            the reader ignores unknown keys, so a pre-change-1 reader
            round-trips a gathered manifest without findings).
        files (Optional[Mapping[str, FileRecord]]): The B100-I1 ``files``
            records (LLR-169.1): project-relative path -> size and file
            digest. Each key goes through the refusal predicate; the key is
            omitted when ``None`` / empty (byte-identical output).
        derived_from (Optional[Mapping[str, DerivedFrom]]): The B100-I16
            records (LLR-168.4): patched variant file -> ``{"base",
            "sha256", "differ"}``. Each key and each ``base`` go through the
            refusal predicate; omitted when ``None`` / empty.
        schema_version (int): The literal written for ``schema_version``;
            defaults to :data:`DEFAULT_SCHEMA_VERSION` (``1``).
        active_document (Optional[str]): The project-relative POSIX text of
            the Patch Editor's document (LLR-170.1), e.g.
            ``"patches/boost.json"``. It must pass
            ``is_active_document_form`` (the reader's predicate) and then
            the refusal predicate; it is checked FIRST in the serialize's
            one walk (S3-11) and emitted LAST, verbatim. ``None`` → no key
            (byte-identical output). It also allows the one ``files`` key
            equal to it; any other ``files`` key with more than one
            component is refused (LLR-169.4 at the writer, P-B3).

    Returns:
        tuple[Optional[str], list[ValidationIssue]]: ``(text, [])`` with the
        serialized JSON text on success; ``(None, [finding, ...])`` when any
        entry is refused (LLR-001.5) — no text is produced in that case.

    Raises:
        None: An unsafe entry is a returned finding, never an exception
            (collect-don't-abort, C-5).

    Data Flow:
        - ``active_document`` first: a text outside the form → one finding
          and no walk; otherwise :func:`_reject_unsafe_entry` on the shared
          walk, so a link or junction on the way or as the file refuses it.
        - Check every ``batch`` then every ``assignments`` entry through
          :func:`_reject_unsafe_entry`; collect all refusals. The change-1
          ``gathered`` rows (HLR-138) go through the same predicate
          (context ``gathered[<home>]``).
        - A ``files`` key with more than one component that is not the
          ``active_document`` text → one finding (the reader refuses it).
        - On any refusal → return ``(None, findings)`` (write nothing).
        - Otherwise normalize entries to POSIX, build the 4-key dict, and
          ``json.dumps`` it with stable key order (``sort_keys=False``,
          insertion order) and ``indent=2`` for a deterministic byte string
          (LLR-001.4).

    Dependencies:
        Uses:
            - _reject_unsafe_entry
            - _posix_entries
            - json.dumps
        Used by:
            - write_project_manifest (I2, NEW)
            - the TUI project-save pipeline (I4, NEW)

    Example:
        >>> text, issues = serialize_manifest(vset, project_dir)  # doctest: +SKIP
        >>> issues
        []
    """
    assignments = assignments or {}
    findings: list[ValidationIssue] = []
    # SEC7-R2-2: one walk for the whole serialize, so each distinct folder
    # or file is checked once and the folder ceiling bounds the writer too.
    walk = _EntryWalk(project_root)

    # S3-11: the document is walked before every other entry, so its folder
    # check is never past the walk's folder ceiling.
    if active_document is not None:
        if not is_active_document_form(active_document):
            findings.append(
                _manifest_write_issue(
                    "refusing to serialize manifest active_document that is not "
                    "a .json file directly in patches/ or checks/: "
                    f"{active_document!r}"
                )
            )
        else:
            issue = _reject_unsafe_entry(
                project_root, active_document, "active_document", walk
            )
            if issue is not None:
                findings.append(issue)

    for entry in batch:
        issue = _reject_unsafe_entry(project_root, entry, "batch", walk)
        if issue is not None:
            findings.append(issue)
    for variant_id, entries in assignments.items():
        context = f"assignments[{variant_id!r}]"
        for entry in entries:
            issue = _reject_unsafe_entry(project_root, entry, context, walk)
            if issue is not None:
                findings.append(issue)
    gathered = gathered or {}
    for home, entries in gathered.items():
        context = f"gathered[{home!r}]"
        for entry in entries:
            issue = _reject_unsafe_entry(project_root, entry, context, walk)
            if issue is not None:
                findings.append(issue)
    files = files or {}
    derived_from = derived_from or {}
    for context, entry in (
        *(("files", key) for key in files),
        *(("derived_from", key) for key in derived_from),
        *(("derived_from base", record.base) for record in derived_from.values()),
    ):
        if (
            context == "files"
            and entry != active_document
            and len(re.split(r"[\\/]", entry)) != 1
        ):
            findings.append(
                _manifest_write_issue(
                    "refusing to serialize manifest files key that is neither a "
                    f"top-level file nor the active document: {entry!r}"
                )
            )
            continue
        issue = _reject_unsafe_entry(project_root, entry, context, walk)
        if issue is not None:
            findings.append(issue)

    if findings:
        return None, findings

    envelope = {
        "schema_version": schema_version,
        "active_variant": variant_set.active_id,
        "batch": _posix_entries(list(batch)),
        "assignments": {
            variant_id: _posix_entries(list(entries))
            for variant_id, entries in assignments.items()
        },
    }
    # Optional, additive key (LLR-026.1): written ONLY when regions are
    # declared, so a project with none serializes byte-identically to before
    # (back-compat — no schema_version bump). The reader treats an absent key
    # as zero regions.
    if declared_regions:
        envelope["declared_regions"] = [
            {"name": region.name, "start": region.start, "end": region.end}
            for region in declared_regions
        ]
    # Optional, additive key (HLR-138): the change-1 gather rows, written
    # ONLY when the save gathered at least one artifact — a zero-used save
    # serializes byte-identically to before (back-compat, same idiom as
    # ``declared_regions`` above).
    if gathered:
        envelope["gathered"] = {
            home: _posix_entries(list(entries))
            for home, entries in gathered.items()
        }
    # Optional, additive keys of the B100-I1 envelope (LLR-169.1,
    # LLR-168.4): written ONLY when non-empty, so a manifest without them
    # serializes byte-identically to before (same idiom as above).
    if files:
        envelope["files"] = {
            key.replace("\\", "/"): {"size": record.size, "sha256": record.sha256}
            for key, record in files.items()
        }
    if derived_from:
        envelope["derived_from"] = {
            key.replace("\\", "/"): {
                "base": record.base,
                "sha256": record.sha256,
                "differ": record.differ,
            }
            for key, record in derived_from.items()
        }
    # LLR-170.1: emitted LAST and only when set, so every manifest without
    # it stays byte-identical (TC-B100-21).
    if active_document is not None:
        envelope["active_document"] = active_document
    return json.dumps(envelope, indent=2), []


def _check_destination_contained(destination: Path, workarea_root: Path) -> None:
    """
    Summary:
        Validate the manifest destination before the atomic replace with the
        ONE placement guard (SEC PDR-C1, SEC6-3, LLR-171.4): the project
        folder is judged UNRESOLVED against THIS app's work area, so a
        project folder swapped for a junction after placement can never
        carry ``project.json`` into another work area.

    Args:
        destination (Path): The intended ``project_dir / "project.json"``
            path, as the caller named it (never resolved first).
        workarea_root (Path): This app's ``.s19tool/workarea`` root.

    Returns:
        None: The destination is contained when the function returns normally.

    Raises:
        WorkareaContainmentError: When the project folder has no work-area
            anchor, traverses a link or junction, or resolves outside this
            work area (``_guarded_destination``).

    Data Flow:
        - ``_guarded_destination(destination.parent, workarea_root)`` walks
          the unresolved chain for reparse points, then requires
          ``contained_in_workarea`` for the resolved pair.

    Dependencies:
        Uses:
            - workspace._guarded_destination
        Used by:
            - write_project_manifest
    """
    _guarded_destination(destination.parent, workarea_root)


def write_project_manifest(
    variant_set: ProjectVariantSet,
    project_root: Path,
    base_dir: Path,
    *,
    batch: Sequence[str] = (),
    assignments: Optional[Mapping[str, Sequence[str]]] = None,
    declared_regions: Sequence[DeclaredRegion] = (),
    gathered: Optional[Mapping[str, Sequence[str]]] = None,
    files: Optional[Mapping[str, FileRecord]] = None,
    derived_from: Optional[Mapping[str, DerivedFrom]] = None,
    schema_version: int = DEFAULT_SCHEMA_VERSION,
    active_document: Optional[str] = None,
) -> tuple[Optional[Path], list[ValidationIssue]]:
    """
    Summary:
        Serialize a project composition and WRITE it atomically to
        ``project_root / "project.json"`` inside the contained work area
        (HLR-002 / LLR-002.1..002.3). The bytes are staged in a PRIVATE
        per-write directory (``_private_stage_dir``, LLR-169.7 / O-11 — never
        the shared ``temp/project.json``), the project folder is validated
        unresolved against this work area (``_guarded_destination``, SEC
        PDR-C1), and the staged file is then moved onto the FIXED
        ``project.json`` name via an atomic ``os.replace`` (D-3 locked
        mechanism). A re-save overwrites the prior manifest in place
        — the writer never dedup-suffixes to ``project_1.json`` (LLR-002.2),
        which the reader (opening only ``project_dir / PROJECT_MANIFEST_NAME``)
        would never see.

    Args:
        variant_set (ProjectVariantSet): The in-memory variant inventory —
            passed through to :func:`serialize_manifest`.
        project_root (Path): The project directory the manifest is written
            into; ``project.json`` lands directly here. Must be a
            ``.s19tool/workarea/<project>/`` directory so the destination
            passes containment and the reader finds it later.
        base_dir (Path): The app base directory whose ``.s19tool/workarea/`` is
            the staging + containment root; created if absent
            (``ensure_workarea``). Source (``temp/``) and destination share
            this work-area tree, so they sit on one filesystem and the
            ``os.replace`` is atomic.
        batch (Sequence[str]): Project-wide change/check entries — see
            :func:`serialize_manifest`.
        assignments (Optional[Mapping[str, Sequence[str]]]): Per-variant file
            entries — see :func:`serialize_manifest`.
        declared_regions (Sequence[DeclaredRegion]): Operator-declared
            regions (LLR-026.1) — see :func:`serialize_manifest`.
        gathered (Optional[Mapping[str, Sequence[str]]]): The change-1
            gather rows (HLR-138) — see :func:`serialize_manifest`.
        files (Optional[Mapping[str, FileRecord]]): The ``files`` records —
            see :func:`serialize_manifest`.
        derived_from (Optional[Mapping[str, DerivedFrom]]): The
            ``derived_from`` records — see :func:`serialize_manifest`.
        schema_version (int): The literal written for ``schema_version``.
        active_document (Optional[str]): The ``active_document`` text — see
            :func:`serialize_manifest`; a refused value writes nothing.

    Returns:
        tuple[Optional[Path], list[ValidationIssue]]: ``(written_path, [])`` on
        success, where ``written_path`` is ``project_root / "project.json"``;
        ``(None, [finding, ...])`` when serialization is refused (LLR-001.5
        escape findings) OR when the destination fails containment / staging /
        the atomic replace raises ``OSError`` (one ``MANIFEST-WRITE-CONTAINMENT``
        finding).

    Raises:
        None: A refused serialize, a containment failure, or an ``OSError`` is a
            returned finding, never an exception (collect-don't-abort, C-5).

    Data Flow:
        - :func:`serialize_manifest` first; a ``None`` text short-circuits to
          ``(None, refusal_findings)`` — nothing is staged or written.
        - ``ensure_workarea(base_dir)`` →
          :func:`_check_destination_contained` on ``project_root /
          "project.json"`` → stage the text in a private directory →
          atomic ``os.replace(staged, destination)``. Concurrent writers
          never share a staging path (the QA race probe: 12 cross-content
          and 60 failed writes of 80 through the shared name).
        - The private staging directory is always removed in a ``finally``.
        - After the replace the destination is checked again (SEC7-2): a
          project folder swapped for a link or junction inside the window
          gives ``(None, [MANIFEST-WRITE-CONTAINMENT naming where the
          bytes landed])``, never a written path.

    Dependencies:
        Uses:
            - serialize_manifest
            - ensure_workarea / workspace._private_stage_dir
            - _check_destination_contained
            - os.replace
        Used by:
            - verify_written_manifest (I3, NEW)
            - the TUI project-save pipeline (I4, NEW)

    Example:
        >>> path, issues = write_project_manifest(  # doctest: +SKIP
        ...     vset, project_dir, base_dir
        ... )
    """
    text, findings = serialize_manifest(
        variant_set,
        project_root,
        batch=batch,
        assignments=assignments,
        declared_regions=declared_regions,
        gathered=gathered,
        files=files,
        derived_from=derived_from,
        schema_version=schema_version,
        active_document=active_document,
    )
    if text is None:
        return None, findings

    destination = project_root / PROJECT_MANIFEST_NAME
    stage_dir: Optional[Path] = None
    try:
        workarea = ensure_workarea(base_dir)
        _check_destination_contained(destination, workarea)
        stage_dir = _private_stage_dir(workarea)
        staged = stage_dir / PROJECT_MANIFEST_NAME
        staged.write_text(text, encoding="utf-8")
        destination.parent.mkdir(parents=True, exist_ok=True)
        os.replace(staged, destination)
    except (WorkareaContainmentError, OSError) as exc:
        # F9 (as SEC7-R2-3): the message is painted; the exception class
        # rides in ``details`` for the caller's log only.
        return None, [
            _manifest_write_containment_issue(
                "the manifest write target failed work-area containment "
                "validation — no file was written",
                details={"exception": f"{type(exc).__name__}: {exc}"},
            )
        ]
    finally:
        if stage_dir is not None:
            shutil.rmtree(stage_dir, ignore_errors=True)
    # SEC7-2: the replace opens the project folder by name again; a folder
    # swapped for a link or junction after the check carried the manifest
    # elsewhere. Detect it, never report it as written.
    try:
        _check_destination_contained(destination, workarea)
    except (WorkareaContainmentError, OSError) as exc:
        landed = os.path.realpath(destination)
        # SEC7-R2-3: the message is painted; the exception class rides in
        # ``details`` for the caller's log only (this module stays headless,
        # LLR-004.3).
        return None, [
            _manifest_write_containment_issue(
                "the project folder changed during the manifest write - "
                f"project.json landed outside this work area at {landed}",
                details={"exception": f"{type(exc).__name__}: {exc}"},
            )
        ]
    return destination, []


#: Verify-on-write outcome — the re-read manifest equals intent with zero
#: reader issues. Mirrors ``verify.py``'s ``STATUS_VERIFIED`` (HLR-003).
MANIFEST_VERIFIED = "verified"

#: Verify-on-write outcome — the re-read manifest drifts from intent OR the
#: reader collected issues on the re-read (R-1). Mirrors ``verify.py``'s
#: ``STATUS_MISMATCH``.
MANIFEST_MISMATCH = "mismatch"


@dataclass(slots=True)
class ManifestVerifyResult:
    """
    Summary:
        The outcome of a manifest verify-on-write check (HLR-003) — the JSON
        analogue of the batch-10 :class:`~s19_app.tui.changes.verify.VerifyResult`.
        ``status`` is :data:`MANIFEST_VERIFIED` when the re-read manifest
        equals the intended composition (in the C-1 canonical comparison form)
        AND carries no reader ``issues``; :data:`MANIFEST_MISMATCH` otherwise.
        ``drift`` names the canonical-form fields that differed; ``issues``
        carries the re-read reader findings so a consumer can name what failed.

    Args:
        status (str): :data:`MANIFEST_VERIFIED` or :data:`MANIFEST_MISMATCH`.
        drift (list[str]): The subset of ``{"active_variant", "batch",
            "assignments"}`` whose re-read value differs from intent — empty
            iff the three compared fields all matched (a reader-issue-only
            mismatch has an empty ``drift`` but a non-empty ``issues``).
        issues (list[ValidationIssue]): The re-read ``ProjectManifest.issues``
            — non-empty forces MISMATCH (R-1: a write the reader degrades must
            never falsely verify). Empty on a faithful write.
        written_path (Optional[Path]): The canonical manifest path that was
            re-read (``project_dir / PROJECT_MANIFEST_NAME``) — stamped so a
            mismatch notice can name it (LLR-004.2). ``None`` only when the
            manifest file was absent at the canonical name.

    Returns:
        None: Dataclass container.

    Data Flow:
        - Produced by :func:`verify_written_manifest` from the re-read
          ``ProjectManifest`` and the resolved intended composition.
        - Consumed by the TUI project-save surfacing (LLR-004.1/004.2, I4).

    Dependencies:
        Uses:
            - ValidationIssue
        Used by:
            - verify_written_manifest

    Example:
        >>> result = verify_written_manifest(  # doctest: +SKIP
        ...     project_dir, vset, project_dir
        ... )
        >>> result.status
        'verified'
    """

    status: str
    drift: list[str] = field(default_factory=list)
    issues: list[ValidationIssue] = field(default_factory=list)
    written_path: Optional[Path] = None


def _resolve_intended_entries(
    project_root: Path,
    raw_entries: Sequence[str],
) -> list[Path]:
    """
    Summary:
        Resolve intended ``batch`` / ``assignments`` path strings against
        ``project_root`` into resolved-absolute ``Path``s — the C-1 canonical
        comparison form, so the intent compares against the reader's resolved
        re-read ``Path``s on the same footing (LLR-003.1).

    Args:
        project_root (Path): The project directory intent resolves against —
            the same root the reader uses (``read_project_manifest`` resolves
            ``project_dir.resolve()``).
        raw_entries (Sequence[str]): Project-relative path strings as held in
            the intended composition.

    Returns:
        list[Path]: The resolved project root joined with each entry, ``.``
        and ``..`` applied to the text, in input order — the form the
        reader's manifest-keys walk returns (SEC7-1), with no filesystem call
        per entry (SEC7-R2-2).

    Data Flow:
        - Pure transform over already-safe entries (the serializer refused any
          escaping entry up front, LLR-001.5), so no containment re-check is
          needed here — this only mirrors the reader's relative→absolute
          form for an apples-to-apples comparison.

    Dependencies:
        Used by:
            - verify_written_manifest
    """
    root = project_root.resolve()
    return [Path(os.path.normpath(root / entry)) for entry in raw_entries]


def verify_written_manifest(
    project_dir: Path,
    variant_set: ProjectVariantSet,
    project_root: Path,
    *,
    batch: Sequence[str] = (),
    assignments: Optional[Mapping[str, Sequence[str]]] = None,
    files: Optional[Mapping[str, FileRecord]] = None,
    derived_from: Optional[Mapping[str, DerivedFrom]] = None,
    active_document: Optional[str] = None,
) -> ManifestVerifyResult:
    """
    Summary:
        Re-read the just-written ``project.json`` and compare it against the
        intended composition, returning a :class:`ManifestVerifyResult`
        (HLR-003 / LLR-003.1..003.3). The re-read is addressed by the CANONICAL
        fixed name ``project_dir / PROJECT_MANIFEST_NAME`` (M-1) — NOT a path a
        write helper returned — so a stale dedup-suffixed file can never
        produce a false verify. The status is :data:`MANIFEST_VERIFIED` iff the
        re-read ``active_variant`` / ``batch`` / ``assignments`` equal intent in
        the C-1 canonical comparison form AND the re-read carries no reader
        ``issues``; otherwise :data:`MANIFEST_MISMATCH` naming the drift.

    Args:
        project_dir (Path): The project directory the manifest was written
            into; the re-read opens ``project_dir / PROJECT_MANIFEST_NAME``.
        variant_set (ProjectVariantSet): The intended composition's variant
            inventory; ``active_variant`` intent is its ``active_id``.
        project_root (Path): The project directory intent's ``batch`` /
            ``assignments`` entries resolve against — the same root the reader
            resolves against (normally equal to ``project_dir``).
        batch (Sequence[str]): The intended project-wide entries as the
            project-relative strings passed to :func:`write_project_manifest`.
        assignments (Optional[Mapping[str, Sequence[str]]]): The intended
            per-variant entries, keyed by ``variant_id``. ``None`` → empty.
        files (Optional[Mapping[str, FileRecord]]): The intended ``files``
            records (LLR-169.3); ``None`` → empty.
        derived_from (Optional[Mapping[str, DerivedFrom]]): The intended
            ``derived_from`` records (LLR-169.3); ``None`` → empty.
        active_document (Optional[str]): The intended ``active_document``
            text (LLR-169.3), compared as text with the re-read value;
            ``None`` equals an absent key.

    Returns:
        ManifestVerifyResult: ``status`` + ``drift`` + ``issues`` +
        ``written_path``. ``drift`` lists every field of
        ``{"active_variant", "batch", "assignments", "files",
        "derived_from", "active_document"}`` that differs (LLR-169.3); ``issues``
        carries any re-read reader findings (non-empty → MISMATCH, R-1).

    Raises:
        None: A reader fault is a collected re-read ``issue`` classified as
            MISMATCH, never an exception (collect-don't-abort, C-5).

    Data Flow:
        - ``read_project_manifest(project_dir)`` re-reads the canonical name.
        - An ABSENT manifest (reader returns ``None``) → MISMATCH with an
          ``active_variant`` drift and ``written_path=None`` (nothing to read).
        - Resolve intended ``batch`` / ``assignments`` against ``project_root``
          (:func:`_resolve_intended_entries`); compare each field against the
          re-read manifest; collect the differing field names into ``drift``.
        - ``status`` is VERIFIED iff ``drift`` is empty AND the re-read
          ``issues`` are empty; MISMATCH otherwise (R-1 honors reader issues).

    Dependencies:
        Uses:
            - read_project_manifest
            - _resolve_intended_entries
        Used by:
            - the TUI project-save pipeline (I4, NEW)

    Example:
        >>> verify_written_manifest(  # doctest: +SKIP
        ...     project_dir, vset, project_dir, batch=["doc.json"]
        ... ).status
        'verified'
    """
    assignments = assignments or {}
    canonical_path = project_dir / PROJECT_MANIFEST_NAME

    manifest = read_project_manifest(project_dir)
    if manifest is None:
        return ManifestVerifyResult(
            status=MANIFEST_MISMATCH,
            drift=[
                "active_variant",
                "batch",
                "assignments",
                "files",
                "derived_from",
                "active_document",
            ],
            issues=[],
            written_path=None,
        )

    intended_active = variant_set.active_id
    intended_batch = _resolve_intended_entries(project_root, list(batch))
    intended_assignments = {
        variant_id: _resolve_intended_entries(project_root, list(entries))
        for variant_id, entries in assignments.items()
    }

    root = project_root.resolve()
    intended_files = {
        (root / key).resolve(): record for key, record in (files or {}).items()
    }
    intended_derived = {
        (root / key).resolve(): record for key, record in (derived_from or {}).items()
    }

    drift: list[str] = []
    if manifest.active_variant != intended_active:
        drift.append("active_variant")
    if manifest.batch != intended_batch:
        drift.append("batch")
    if manifest.assignments != intended_assignments:
        drift.append("assignments")
    if manifest.files != intended_files:
        drift.append("files")
    if manifest.derived_from != intended_derived:
        drift.append("derived_from")
    if manifest.active_document != active_document:
        drift.append("active_document")

    status = (
        MANIFEST_VERIFIED
        if not drift and not manifest.issues
        else MANIFEST_MISMATCH
    )
    return ManifestVerifyResult(
        status=status,
        drift=drift,
        issues=list(manifest.issues),
        written_path=canonical_path,
    )


def file_record(path: Path) -> FileRecord:
    """
    Summary:
        The size and streamed SHA-256 file digest of one project file
        (LLR-169.1, B100-I3).

    Args:
        path (Path): The file.

    Returns:
        FileRecord: ``(size, sha256)``, the digest as 64 lowercase hex.

    Raises:
        OSError: The file cannot be read.

    Data Flow:
        - Read in 1 MiB chunks into ``hashlib.sha256``; never the whole
          file at once.

    Dependencies:
        Used by:
            - project_file_records / check_project_files / derive_record
    """
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
            size += len(chunk)
    return FileRecord(size, digest.hexdigest())


def _top_level_project_files(project_dir: Path) -> list[Path]:
    """
    Summary:
        The O-2 scope (LLR-169.2): the top-level regular files of
        ``project_dir`` with a project data or A2L suffix, by name. No
        sub-folder is walked, and no link or junction is followed.

    Args:
        project_dir (Path): The project folder.

    Returns:
        list[Path]: The files, sorted by name; empty when the folder cannot
            be listed.

    Dependencies:
        Used by:
            - project_file_records / check_project_files
    """
    found: list[Path] = []
    try:
        with os.scandir(project_dir) as entries:
            for entry in entries:
                if Path(entry.name).suffix.lower() not in PROJECT_RECORDED_SUFFIXES:
                    continue
                path = Path(entry.path)
                if entry.is_file(follow_symlinks=False) and not _is_reparse_point(path):
                    found.append(path)
    except OSError:
        return []
    return sorted(found, key=lambda item: item.name)


def project_file_records(
    project_dir: Path, active_document: Optional[str] = None
) -> dict[str, FileRecord]:
    """
    Summary:
        The ``files`` map the manifest seam writes (LLR-169.2): one record
        per top-level data or A2L file, plus the active document, computed
        from disk after every copy has landed.

    Args:
        project_dir (Path): The project folder.
        active_document (Optional[str]): The ``active_document`` text the
            save records (e.g. ``"patches/boost.json"``); ``None`` → the
            top-level records only.

    Returns:
        dict[str, FileRecord]: Project-relative POSIX key -> record, sorted
            by key. A file that cannot be read is left out (Load then
            reports it as ``not recorded``) rather than failing the write.
            The document gets a record, keyed by its exact text, only when
            the text passes ``is_active_document_form`` and both its home
            folder and the file are regular and not links or junctions
            (S3-8); otherwise no record and no raise.

    Data Flow:
        - The O-2 top-level scan (no sub-folder listing).
        - The document: two ``os.lstat`` calls (home, file) and one read to
          hash it; the home folder is never listed.

    Dependencies:
        Uses:
            - _top_level_project_files / file_record / _plain_entry
            - is_active_document_form
        Used by:
            - s19_app.tui.app.S19TuiApp._write_and_verify_manifest
    """
    records: dict[str, FileRecord] = {}
    for path in _top_level_project_files(project_dir):
        try:
            records[path.name] = file_record(path)
        except OSError:
            continue
    if active_document is not None and is_active_document_form(active_document):
        home, name = active_document.split("/")
        path = project_dir / home / name
        if _plain_entry(project_dir / home, folder=True) and _plain_entry(
            path, folder=False
        ):
            try:
                records[active_document] = file_record(path)
            except OSError:
                pass
    return dict(sorted(records.items()))


def count_differing_bytes(base: Mapping[int, int], derived: Mapping[int, int]) -> int:
    """
    Summary:
        How many addresses differ between two images (LLR-168.4): a
        different byte, or an address present in only one of them.

    Args:
        base (Mapping[int, int]): The base image's address -> byte map.
        derived (Mapping[int, int]): The patched image's map.

    Returns:
        int: The count.

    Dependencies:
        Used by:
            - derive_record
    """
    return sum(
        1
        for address in base.keys() | derived.keys()
        if base.get(address) != derived.get(address)
    )


def derive_record(
    base_path: Path, base_map: Mapping[int, int], derived_map: Mapping[int, int]
) -> DerivedFrom:
    """
    Summary:
        The ``derived_from`` record of a patched variant (LLR-168.4,
        B100-I16), computed at the write while both images are in hand.

    Args:
        base_path (Path): The base image file (it need not be in the
            project).
        base_map (Mapping[int, int]): The base image's data.
        derived_map (Mapping[int, int]): The patched image's data.

    Returns:
        DerivedFrom: The base's file name and file digest and the number of
            differing bytes.

    Raises:
        OSError: The base file cannot be read.

    Dependencies:
        Uses:
            - file_record / count_differing_bytes
        Used by:
            - s19_app.tui.app.S19TuiApp (the save-back and Save project's
              emit)
    """
    return DerivedFrom(
        base_path.name,
        file_record(base_path).sha256,
        count_differing_bytes(base_map, derived_map),
    )


def _disk_problem(
    path: Path, record: FileRecord, name: Optional[str] = None
) -> Optional[ProjectFileProblem]:
    """
    Summary:
        Compare one recorded file with disk (LLR-169.5): ``missing``,
        ``not readable`` (not a regular file, or unreadable), ``changed on
        disk`` (size, then digest), or ``None`` when it matches.

    Args:
        path (Path): The recorded file, resolved inside the project.
        record (FileRecord): Its record.
        name (Optional[str]): The recorded ``active_document`` text, or
            ``None`` for any other file (named ``path.name``). The document
            is labelled ``change document <text>`` (E3 R20), the label the
            reopen uses, so Load keeps one row for it; its read failure
            carries the R16 reason and next-step mark the reopen uses.

    Returns:
        Optional[ProjectFileProblem]: The problem, or ``None``.

    Data Flow:
        - ``os.lstat``: absent → ``missing``; any other error → ``not
          readable``.
        - Only ``S_ISREG`` non-link files are hashed; a device, a folder or
          a link is ``not readable``.
        - A size difference needs no hash; an equal size is hashed.

    Dependencies:
        Uses:
            - file_record
        Used by:
            - check_project_files
    """
    # R16 / R20: the document's read failure carries the one io_error
    # reason, mark and label the reopen uses, so the merged Load row reads
    # the same whichever is kept.
    if name is None:
        label = path.name
        unreadable = ProjectFileProblem(
            PROBLEM_NOT_READABLE, label, "the file cannot be read"
        )
    else:
        label = document_problem_file(name)
        unreadable = ProjectFileProblem(
            PROBLEM_NOT_READABLE,
            label,
            DOCUMENT_REASON_IO_ERROR,
            step=STEP_CHECK_THEN_LOAD,
        )
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return ProjectFileProblem(
            PROBLEM_MISSING, label, "recorded in project.json, not on disk"
        )
    except (OSError, ValueError):
        return unreadable
    if not stat.S_ISREG(info.st_mode) or _is_reparse_point(path):
        return ProjectFileProblem(PROBLEM_NOT_READABLE, label, "not a regular file")
    if info.st_size != record.size:
        return ProjectFileProblem(
            PROBLEM_CHANGED, label, f"saved {record.size} B, now {info.st_size} B"
        )
    try:
        actual = file_record(path)
    except OSError:
        return unreadable
    if actual != record:
        return ProjectFileProblem(
            PROBLEM_CHANGED, label, f"same size ({record.size} B), different content"
        )
    return None


def _active_document_missing(
    project_dir: Path, manifest: ProjectManifest
) -> Optional[ProjectFileProblem]:
    """
    Summary:
        The ``missing`` problem of a recorded ``active_document`` that has
        no ``files`` record (LLR-169.5); a recorded one is judged by
        :func:`_disk_problem` instead, so it is never reported twice.

    Args:
        project_dir (Path): The project folder.
        manifest (ProjectManifest): Its read manifest.

    Returns:
        Optional[ProjectFileProblem]: One ``missing`` labelled ``change
            document <text>`` (E3 R20) when ``os.lstat`` of the file raises ``FileNotFoundError``;
            ``None`` otherwise (no document, a ``files`` record, a present
            file of any type, or any other error: a present but unreadable
            document is the reopen's ``not readable``, LLR-170.3).

    Raises:
        None.

    Dependencies:
        Used by:
            - check_project_files
    """
    text = manifest.active_document
    if text is None:
        return None
    if project_dir.resolve() / text in manifest.files:
        return None
    try:
        os.lstat(project_dir / text)
    except FileNotFoundError:
        return ProjectFileProblem(
            PROBLEM_MISSING,
            document_problem_file(text),
            "recorded in project.json, not on disk",
        )
    except (OSError, ValueError):
        pass
    return None


def check_project_files(
    project_dir: Path, manifest: Optional[ProjectManifest]
) -> list[ProjectFileProblem]:
    """
    Summary:
        The Load-side project check (LLR-169.5, B100-I3): the manifest's
        problems and what changed on disk since the manifest was written.
        It never raises and never parses an image; ``not readable`` from an
        install is added by the load itself (LLR-169.9).

    Args:
        project_dir (Path): The project folder.
        manifest (Optional[ProjectManifest]): Its read manifest; ``None``
            when it has no ``project.json``.

    Returns:
        list[ProjectFileProblem]: Every problem found, possibly several per
            file; the load keeps one per file by precedence.

    Data Flow:
        - No manifest → ``no project.json``.
        - The manifest's own findings → ``manifest damaged`` (one per
          skipped entry, or one for ``project.json``); a manifest damaged
          as a whole stops here.
        - A recorded ``active_document`` without a ``files`` record and
          absent from disk → one ``missing`` named by its text
          (:func:`_active_document_missing`), before the next step.
        - No ``files`` records → ``no digests saved``.
        - Each record → :func:`_disk_problem`; the document's record is
          labelled ``change document <text>`` (E3 R20), every other is
          named by file name.
        - Each top-level data or A2L file without a record → ``not
          recorded`` (three writers still place files without the seam,
          P-36).

    Dependencies:
        Uses:
            - manifest_problems / manifest_is_damaged / _disk_problem /
              _active_document_missing / _top_level_project_files
        Used by:
            - s19_app.tui.app.S19TuiApp._handle_load_project
    """
    if manifest is None:
        return [ProjectFileProblem(PROBLEM_NO_MANIFEST, PROJECT_MANIFEST_NAME)]
    problems = manifest_problems(manifest)
    if manifest_is_damaged(manifest):
        return problems
    document_missing = _active_document_missing(project_dir, manifest)
    if document_missing is not None:
        problems.append(document_missing)
    if not manifest.files:
        problems.append(ProjectFileProblem(PROBLEM_NO_DIGESTS, PROJECT_MANIFEST_NAME))
        return problems
    document_path = (
        None
        if manifest.active_document is None
        else project_dir.resolve() / manifest.active_document
    )
    for path, record in manifest.files.items():
        problem = _disk_problem(
            path,
            record,
            manifest.active_document if path == document_path else None,
        )
        if problem is not None:
            problems.append(problem)
    recorded = {path.name for path in manifest.files}
    for path in _top_level_project_files(project_dir):
        if path.name not in recorded:
            problems.append(
                ProjectFileProblem(
                    PROBLEM_NOT_RECORDED, path.name, "in the project, not in project.json"
                )
            )
    return problems
