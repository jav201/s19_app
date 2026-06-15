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
``project_1.json``. Verify-on-write (HLR-003) lands in I3.

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
