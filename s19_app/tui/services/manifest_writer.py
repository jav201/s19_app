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

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Optional, Sequence

from ...validation.model import ValidationIssue, ValidationSeverity
from ..models import ProjectVariantSet
from ..workspace import (
    WORKAREA_TEMP,
    WorkareaContainmentError,
    _find_workarea_root,
    _path_traverses_reparse_point,
    ensure_workarea,
)
from .variant_execution_service import (
    MANIFEST_ARTIFACT,
    PROJECT_MANIFEST_NAME,
    _resolve_manifest_entry,
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


def _manifest_write_containment_issue(message: str) -> ValidationIssue:
    """
    Summary:
        Build one write-path ``ValidationIssue`` tagged
        ``artifact=MANIFEST_ARTIFACT`` with the ``MANIFEST-WRITE-CONTAINMENT``
        code at WARNING severity (LLR-002.3), mirroring
        ``write_change_document``'s ``MF-WRITE-CONTAINMENT`` finding.

    Args:
        message (str): Human-readable finding describing the failed write.

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

    Returns:
        Optional[ValidationIssue]: A ``MANIFEST-WRITE-ESCAPE`` finding when the
        entry is unsafe; ``None`` when the entry resolves cleanly inside the
        project root.

    Data Flow:
        - Delegate to ``_resolve_manifest_entry`` (the reader's predicate) with
          a throwaway issue sink; a ``None`` return OR any appended reader
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
    resolved = _resolve_manifest_entry(project_root, entry, context, probe)
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
    schema_version: int = DEFAULT_SCHEMA_VERSION,
) -> tuple[Optional[str], list[ValidationIssue]]:
    """
    Summary:
        Serialize a project composition into the canonical ``project.json``
        envelope text the reader parses back without findings (HLR-001 /
        LLR-001.1..001.5). The envelope carries exactly
        ``{schema_version, active_variant, batch, assignments}``; emission is
        via the stdlib ``json`` encoder, never string assembly (LLR-001.1).

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
        schema_version (int): The literal written for ``schema_version``;
            defaults to :data:`DEFAULT_SCHEMA_VERSION` (``1``).

    Returns:
        tuple[Optional[str], list[ValidationIssue]]: ``(text, [])`` with the
        serialized JSON text on success; ``(None, [finding, ...])`` when any
        entry is refused (LLR-001.5) — no text is produced in that case.

    Raises:
        None: An unsafe entry is a returned finding, never an exception
            (collect-don't-abort, C-5).

    Data Flow:
        - Check every ``batch`` then every ``assignments`` entry through
          :func:`_reject_unsafe_entry`; collect all refusals.
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

    for entry in batch:
        issue = _reject_unsafe_entry(project_root, entry, "batch")
        if issue is not None:
            findings.append(issue)
    for variant_id, entries in assignments.items():
        context = f"assignments[{variant_id!r}]"
        for entry in entries:
            issue = _reject_unsafe_entry(project_root, entry, context)
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
    return json.dumps(envelope, indent=2), []


def _check_destination_contained(destination: Path) -> None:
    """
    Summary:
        Re-run ``copy_into_workarea``'s containment CHECKS against the manifest
        destination ``project.json`` path: locate its ``.s19tool/workarea``
        root, confirm the resolved path stays inside it, and confirm no parent
        up to the workarea root traverses a symlink / NTFS junction (LLR-002.1).
        This validates the FINAL target before the atomic replace, reusing the
        reader-side checks rather than the copy-with-dedup body.

    Args:
        destination (Path): The intended ``project_dir / "project.json"`` path.

    Returns:
        None: The destination is contained when the function returns normally.

    Raises:
        WorkareaContainmentError: When the destination has no ``.s19tool/
            workarea`` ancestor, escapes that root, or traverses a reparse
            point — the same rejection conditions ``copy_into_workarea`` raises.

    Data Flow:
        - Resolve the destination, then apply ``_find_workarea_root`` +
          ``is_relative_to(workarea_root)`` + ``_path_traverses_reparse_point``
          (``workspace.py`` containment seam) — the exact checks
          ``copy_into_workarea`` runs before placing a file.

    Dependencies:
        Uses:
            - _find_workarea_root
            - _path_traverses_reparse_point
        Used by:
            - write_project_manifest
    """
    resolved = destination.resolve()
    workarea_root = _find_workarea_root(resolved)
    if workarea_root is None or not resolved.is_relative_to(workarea_root):
        raise WorkareaContainmentError(
            "Refusing to write manifest: destination is not contained inside a "
            f".s19tool/workarea/ root: {resolved}"
        )
    if _path_traverses_reparse_point(resolved, stop_at=workarea_root.parent):
        raise WorkareaContainmentError(
            "Refusing to write manifest: destination traverses a symbolic link "
            f"or reparse point: {resolved}"
        )


def write_project_manifest(
    variant_set: ProjectVariantSet,
    project_root: Path,
    base_dir: Path,
    *,
    batch: Sequence[str] = (),
    assignments: Optional[Mapping[str, Sequence[str]]] = None,
    schema_version: int = DEFAULT_SCHEMA_VERSION,
) -> tuple[Optional[Path], list[ValidationIssue]]:
    """
    Summary:
        Serialize a project composition and WRITE it atomically to
        ``project_root / "project.json"`` inside the contained work area
        (HLR-002 / LLR-002.1..002.3). The bytes are staged under
        ``.s19tool/workarea/temp/``, the final destination is validated with
        ``copy_into_workarea``'s containment CHECKS, and the staged file is then
        moved onto the FIXED ``project.json`` name via an atomic ``os.replace``
        (D-3 locked mechanism). A re-save overwrites the prior manifest in place
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
        schema_version (int): The literal written for ``schema_version``.

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
        - ``ensure_workarea(base_dir)`` → stage the text under ``temp/`` →
          :func:`_check_destination_contained` on ``project_root / "project.json"``
          → atomic ``os.replace(staged, destination)``.
        - The staged temp file is always removed in a ``finally``.

    Dependencies:
        Uses:
            - serialize_manifest
            - ensure_workarea
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
        schema_version=schema_version,
    )
    if text is None:
        return None, findings

    destination = project_root / PROJECT_MANIFEST_NAME
    workarea = ensure_workarea(base_dir)
    staged = workarea / WORKAREA_TEMP / PROJECT_MANIFEST_NAME
    try:
        _check_destination_contained(destination)
        staged.parent.mkdir(parents=True, exist_ok=True)
        staged.write_text(text, encoding="utf-8")
        destination.parent.mkdir(parents=True, exist_ok=True)
        os.replace(staged, destination)
        return destination, []
    except (WorkareaContainmentError, OSError) as exc:
        return None, [
            _manifest_write_containment_issue(
                "the manifest write target failed work-area containment "
                f"validation — no file was written: {type(exc).__name__}: {exc}"
            )
        ]
    finally:
        try:
            staged.unlink()
        except OSError:
            pass


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
        list[Path]: ``(project_root / entry).resolve()`` for each entry, in
        input order — matching the reader-side idiom
        ``test_variant_execution.py:163``.

    Data Flow:
        - Pure transform over already-safe entries (the serializer refused any
          escaping entry up front, LLR-001.5), so no containment re-check is
          needed here — this only mirrors the reader's relative→absolute
          resolution for an apples-to-apples comparison.

    Dependencies:
        Used by:
            - verify_written_manifest
    """
    root = project_root.resolve()
    return [(root / entry).resolve() for entry in raw_entries]


def verify_written_manifest(
    project_dir: Path,
    variant_set: ProjectVariantSet,
    project_root: Path,
    *,
    batch: Sequence[str] = (),
    assignments: Optional[Mapping[str, Sequence[str]]] = None,
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

    Returns:
        ManifestVerifyResult: ``status`` + ``drift`` + ``issues`` +
        ``written_path``. ``drift`` lists every field of
        ``{"active_variant", "batch", "assignments"}`` that differs; ``issues``
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
            drift=["active_variant", "batch", "assignments"],
            issues=[],
            written_path=None,
        )

    intended_active = variant_set.active_id
    intended_batch = _resolve_intended_entries(project_root, list(batch))
    intended_assignments = {
        variant_id: _resolve_intended_entries(project_root, list(entries))
        for variant_id, entries in assignments.items()
    }

    drift: list[str] = []
    if manifest.active_variant != intended_active:
        drift.append("active_variant")
    if manifest.batch != intended_batch:
        drift.append("batch")
    if manifest.assignments != intended_assignments:
        drift.append("assignments")

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
