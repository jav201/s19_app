"""Manifest writer (HLR-001 serialize) — the WRITE side of ``project.json``.

The project manifest is read-only today: ``read_project_manifest``
(``variant_execution_service.py``) parses ``project.json`` and is the schema
oracle. This module adds the missing serializer that turns an in-memory
project composition into the canonical envelope that the reader parses back
without findings — the round-trip-to-reader correctness criterion (D-2), the
JSON analogue of the batch-10 emitter that round-trips against
``IntelHexFile``.

Increment I1 covers SERIALIZE ONLY (HLR-001 + LLR-001.1..001.5). The contained
write (HLR-002) and verify-on-write (HLR-003) land in later increments.

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
from pathlib import Path
from typing import Mapping, Optional, Sequence

from ...validation.model import ValidationIssue, ValidationSeverity
from ..models import ProjectVariantSet
from .variant_execution_service import (
    MANIFEST_ARTIFACT,
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
