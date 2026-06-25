"""
Variant execution service — batch / per-variant change+check execution (E6).

This module is the batch-07 E6 execution layer (HLR-006): it owns the
project **manifest** io (LLR-006.1 — placed here rather than in
``workspace.py`` because this service is the manifest's primary consumer and
the project-load override in ``app.py`` can import it without widening the
workspace surface), the **deterministic execution plan** (LLR-006.2), and
the **per-variant isolated execution loop** (LLR-006.3/006.4).

Manifest (``.s19tool/workarea/<project>/project.json``, LLR-006.1 + F-S-03):

- Read through a CAPPED path: an on-disk size probe precedes ``json.load``
  (the shared 256 MB ``workspace.DEFAULT_COPY_SIZE_CAP_BYTES``), and the
  parse arm catches ``RecursionError`` alongside ``JSONDecodeError`` /
  ``UnicodeDecodeError`` — the ``changes/io.py`` read-path pattern.
- ``batch`` / ``assignments`` entries resolve AGAINST THE PROJECT DIRECTORY
  ONLY — never through ``workspace.resolve_input_path``. An absolute path
  (either separator convention), a path resolving outside the project
  directory, or a path traversing a symlink / NTFS reparse point is ONE
  ERROR ``ValidationIssue`` and the entry is skipped (collect-don't-abort).
- A manifest that is absent yields ``None`` from
  :func:`read_project_manifest` — the caller falls back to batch mode over
  all variants (the LLR-006.1 default).

Execution (LLR-006.3..006.5):

- Each variant's image is parsed INSIDE the execution call via
  ``build_loaded_s19`` / ``build_loaded_hex`` — the TUI's active
  ``LoadedFile`` is never read or mutated. Variants run sequentially, one
  parsed image at a time; the image reference is dropped before the next
  variant parses.
- The service computes NO linkage and NO verdicts itself: every per-file
  outcome is the ``apply_change_document`` / ``run_check_document`` output,
  kind-discriminated (``kind == "check"`` runs checks; everything else goes
  to the apply engine, whose gate blocks non-``"change"`` documents). The
  ``variant_id`` is stamped through the engines' existing parameter.
- One failing variant never aborts the rest (LLR-006.4):
  ``len(results) == planned variant count`` always.
- Save-back is headless (LLR-002.7 headless parameter): when a change file
  applies ≥1 entry on an S19 variant, the patched image is written to the
  project directory under the default ``<variant_id>-patched.s19`` filename
  — no prompt in batch mode. HEX variants record a diagnostic instead (D-1).

This module imports stdlib + the parse layer + the ``changes`` package +
sibling services + ``validation.model`` only — **no Textual import**
(service-layer contract, constraint C-7; verified by the grep probe in the
E6 verification list and by ``tests/test_variant_execution.py``).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Callable, Optional, Sequence, Tuple, Union

from ...core import S19File
from ...hexfile import IntelHexFile
from ...validation.model import ValidationIssue, ValidationSeverity
from ..a2l_parse import parse_a2l_file
from ..changes import (
    ChangeSummary,
    apply_change_document,
    read_change_document,
    save_patched_image,
)
from ..changes.check import run_check_document
from ..changes.model import CheckRunResult
from ..mac import parse_mac_file
from ..models import ProjectVariantSet, VariantDescriptor
from ..workspace import (
    DEFAULT_COPY_SIZE_CAP_BYTES,
    MAC_EXTENSIONS,
    _path_traverses_reparse_point,
    validate_project_files,
)
from .a2l_service import enrich_tags_and_render
from .load_service import build_loaded_hex, build_loaded_s19

#: The on-disk manifest filename inside a project directory (LLR-006.1).
#: ``.json`` is already ignored by ``workspace.validate_project_files``, so
#: the manifest never registers as project data.
PROJECT_MANIFEST_NAME = "project.json"

#: Pre-parse size cap for the manifest read — the shared workspace copy cap
#: so one consistent limit governs every file the app reads (F-S-03).
MANIFEST_SIZE_CAP_BYTES = DEFAULT_COPY_SIZE_CAP_BYTES

#: ``ValidationIssue.artifact`` tag for every manifest finding.
MANIFEST_ARTIFACT = "manifest"

#: Manifest read-path: the file exceeds the pre-parse size cap.
MANIFEST_SIZE_CAP = "MANIFEST-SIZE-CAP"
#: Manifest read-path: not well-formed JSON (including parser recursion
#: overflow) or unreadable.
MANIFEST_JSON_PARSE = "MANIFEST-JSON-PARSE"
#: Manifest read-path: well-formed JSON whose structure is not the manifest
#: envelope (non-object top level, non-array ``batch``, non-object
#: ``assignments``, non-string entry).
MANIFEST_BAD_STRUCTURE = "MANIFEST-BAD-STRUCTURE"
#: Manifest read-path: a ``batch`` / ``assignments`` entry is absolute,
#: resolves outside the project directory, or traverses a reparse point
#: (F-S-03) — the entry is skipped.
MANIFEST_PATH_ESCAPE = "MANIFEST-PATH-ESCAPE"

#: The three execution scopes of the E6 TUI trigger (LLR-006.6).
SCOPE_ACTIVE = "active"
SCOPE_ALL = "all"
SCOPE_ASSIGNMENTS = "assignments"
EXECUTION_SCOPES: tuple[str, ...] = (SCOPE_ACTIVE, SCOPE_ALL, SCOPE_ASSIGNMENTS)

#: Per-variant outcome tokens (LLR-006.4).
VARIANT_STATUS_OK = "ok"
VARIANT_STATUS_ERROR = "error"

#: The size-probe seam — injectable so a test can report an over-cap byte
#: size without manufacturing a real 256 MB file (the ``changes/io.py``
#: ``SizeProbe`` pattern).
SizeProbe = Callable[[Path], int]

#: The between-variant status sink (F-Q-18): the TUI worker passes a
#: ``call_from_thread``-wrapped ``set_status``; headless callers pass None.
StatusCallback = Callable[[str], None]


def _manifest_issue(
    code: str,
    message: str,
    severity: ValidationSeverity = ValidationSeverity.ERROR,
) -> ValidationIssue:
    """
    Summary:
        Build one manifest ``ValidationIssue`` tagged
        ``artifact=MANIFEST_ARTIFACT``.

    Args:
        code (str): The ``MANIFEST-*`` rule code.
        message (str): Human-readable finding — names paths and counts only.
        severity (ValidationSeverity): Defaults to ERROR (every manifest
            read rule is an ERROR per F-S-03).

    Returns:
        ValidationIssue: The finding.

    Dependencies:
        Used by:
            - read_project_manifest / _resolve_manifest_entry
    """
    return ValidationIssue(
        code=code,
        severity=severity,
        message=message,
        artifact=MANIFEST_ARTIFACT,
    )


@dataclass(slots=True)
class ProjectManifest:
    """
    Summary:
        The parsed per-project manifest (LLR-006.1) — the schema version,
        the recorded active variant, the project-wide ``batch`` file list,
        and the per-variant ``assignments`` map, plus every finding the
        capped read collected.

    Args:
        schema_version (Union[int, str, None]): The ``schema_version`` token
            as found; ``None`` when absent.
        active_variant (Optional[str]): The recorded active variant id, or
            ``None`` when absent — the project-load override of LLR-005.6.
        batch (list[Path]): Resolved, project-contained change/check file
            paths in MANIFEST ORDER (LLR-006.2 inner order, first half).
            Entries that failed containment are skipped, not carried.
        assignments (dict[str, list[Path]]): Per-variant resolved file paths
            in manifest order (LLR-006.2 inner order, second half), keyed by
            ``variant_id``.
        issues (list[ValidationIssue]): Every collected size / parse /
            structure / containment finding (collect-don't-abort).

    Returns:
        None: Dataclass container.

    Data Flow:
        - Built by :func:`read_project_manifest`.
        - Consumed by :func:`plan_variant_executions` (file mapping) and by
          ``app.py::_handle_load_project`` (the ``active_variant`` override).

    Dependencies:
        Used by:
            - read_project_manifest
            - plan_variant_executions
            - s19_app.tui.app.S19TuiApp (project load + execute_scope)
    """

    schema_version: Union[int, str, None]
    active_variant: Optional[str]
    batch: list[Path] = field(default_factory=list)
    assignments: dict[str, list[Path]] = field(default_factory=dict)
    issues: list[ValidationIssue] = field(default_factory=list)


def _resolve_manifest_entry(
    project_root: Path,
    raw_entry: object,
    context: str,
    issues: list[ValidationIssue],
) -> Optional[Path]:
    """
    Summary:
        Resolve one ``batch`` / ``assignments`` entry against the project
        directory ONLY, enforcing the F-S-03 containment rules — an unsafe
        entry records exactly one ERROR finding and is skipped.

    Args:
        project_root (Path): The resolved project directory the entry must
            stay inside.
        raw_entry (object): The JSON entry value — must be a relative path
            string.
        context (str): Display context for the finding message (``"batch"``
            or ``"assignments[<id>]"``).
        issues (list[ValidationIssue]): The manifest's finding collector —
            appended in place.

    Returns:
        Optional[Path]: The resolved absolute path inside the project
        directory, or ``None`` when the entry was skipped.

    Data Flow:
        - Non-string entry → one ``MANIFEST-BAD-STRUCTURE``.
        - Absolute under EITHER separator convention (``PureWindowsPath`` /
          ``PurePosixPath``) → one ``MANIFEST-PATH-ESCAPE`` — checked before
          any filesystem touch so a drive-qualified path is refused on every
          platform.
        - ``(project_root / entry).resolve()`` escaping ``project_root`` →
          one ``MANIFEST-PATH-ESCAPE``.
        - The resolved path traversing a symlink / NTFS reparse point below
          the project root → one ``MANIFEST-PATH-ESCAPE``
          (``workspace._path_traverses_reparse_point``, security finding
          S-N01 reuse).
        - Existence is NOT checked here: a missing file surfaces later as
          the per-file ``MF-PATH-UNRESOLVED`` finding of the shared reader.

    Dependencies:
        Uses:
            - workspace._path_traverses_reparse_point
            - _manifest_issue
        Used by:
            - read_project_manifest
    """
    if not isinstance(raw_entry, str) or not raw_entry.strip():
        issues.append(
            _manifest_issue(
                MANIFEST_BAD_STRUCTURE,
                f"manifest {context} entry is not a path string - entry "
                "skipped",
            )
        )
        return None
    text = raw_entry.strip()
    if PureWindowsPath(text).is_absolute() or PurePosixPath(text).is_absolute():
        issues.append(
            _manifest_issue(
                MANIFEST_PATH_ESCAPE,
                f"manifest {context} entry is an absolute path - entries "
                f"resolve against the project directory only; entry "
                f"skipped: {text!r}",
            )
        )
        return None
    resolved = (project_root / text).resolve()
    if not resolved.is_relative_to(project_root):
        issues.append(
            _manifest_issue(
                MANIFEST_PATH_ESCAPE,
                f"manifest {context} entry escapes the project directory - "
                f"entry skipped: {text!r}",
            )
        )
        return None
    if _path_traverses_reparse_point(resolved, stop_at=project_root):
        issues.append(
            _manifest_issue(
                MANIFEST_PATH_ESCAPE,
                f"manifest {context} entry traverses a symbolic link or "
                f"reparse point - entry skipped: {text!r}",
            )
        )
        return None
    return resolved


def read_project_manifest(
    project_dir: Path,
    size_probe: Optional[SizeProbe] = None,
) -> Optional[ProjectManifest]:
    """
    Summary:
        Read ``<project_dir>/project.json`` into a :class:`ProjectManifest`
        through the capped, collect-don't-abort path (LLR-006.1 + F-S-03).
        An ABSENT manifest returns ``None`` — the caller's signal to default
        to batch mode over all variants.

    Args:
        project_dir (Path): The project directory
            (``.s19tool/workarea/<project>/``).
        size_probe (Optional[SizeProbe]): On-disk byte-size measurement
            seam; ``None`` resolves to ``Path.stat().st_size``. Injectable
            so a test can report an over-cap size without a real 256 MB
            file.

    Returns:
        Optional[ProjectManifest]: ``None`` when no manifest file exists;
        otherwise a manifest whose ``issues`` carry every size / parse /
        structure / containment finding — a faulted manifest comes back
        with empty ``batch`` / ``assignments`` rather than raising.

    Raises:
        None: Every failure mode is a collected ``ValidationIssue``.

    Data Flow:
        - Probe the size BEFORE ``json.load`` (over cap → one
          ``MANIFEST-SIZE-CAP``, empty manifest).
        - Parse catching ``JSONDecodeError`` / ``RecursionError`` /
          ``UnicodeDecodeError`` / ``OSError`` → one
          ``MANIFEST-JSON-PARSE``.
        - Non-object top level → one ``MANIFEST-BAD-STRUCTURE``.
        - ``batch`` (array) and ``assignments`` (object of arrays) entries
          each resolve through :func:`_resolve_manifest_entry`; unsafe
          entries are skipped with one ERROR each.

    Dependencies:
        Uses:
            - _resolve_manifest_entry / _manifest_issue
            - json.load
        Used by:
            - execute_project_variants
            - s19_app.tui.app.S19TuiApp._handle_load_project
            - tests/test_variant_execution.py

    Example:
        >>> manifest = read_project_manifest(project_dir)  # doctest: +SKIP
    """
    manifest_path = project_dir / PROJECT_MANIFEST_NAME
    if not manifest_path.exists():
        return None
    issues: list[ValidationIssue] = []
    empty = ProjectManifest(
        schema_version=None, active_variant=None, issues=issues
    )
    probe: SizeProbe = (
        (lambda candidate: candidate.stat().st_size)
        if size_probe is None
        else size_probe
    )
    size_bytes = probe(manifest_path)
    if size_bytes > MANIFEST_SIZE_CAP_BYTES:
        issues.append(
            _manifest_issue(
                MANIFEST_SIZE_CAP,
                f"the project manifest is {size_bytes} bytes, over the "
                f"{MANIFEST_SIZE_CAP_BYTES}-byte read cap - the file was "
                f"not loaded",
            )
        )
        return empty
    try:
        with manifest_path.open("rb") as handle:
            payload = json.load(handle)
    except (
        json.JSONDecodeError,
        RecursionError,
        UnicodeDecodeError,
        OSError,
    ) as exc:
        issues.append(
            _manifest_issue(
                MANIFEST_JSON_PARSE,
                f"the project manifest is not readable well-formed JSON - "
                f"ignored: {type(exc).__name__}",
            )
        )
        return empty
    if not isinstance(payload, dict):
        issues.append(
            _manifest_issue(
                MANIFEST_BAD_STRUCTURE,
                "the project manifest top level is not a JSON object - "
                "ignored",
            )
        )
        return empty

    project_root = project_dir.resolve()
    schema_version = payload.get("schema_version")
    if not isinstance(schema_version, (int, str)) and schema_version is not None:
        issues.append(
            _manifest_issue(
                MANIFEST_BAD_STRUCTURE,
                "manifest schema_version is neither a number nor a string",
            )
        )
        schema_version = None
    active_raw = payload.get("active_variant")
    active_variant = active_raw if isinstance(active_raw, str) else None
    if active_raw is not None and not isinstance(active_raw, str):
        issues.append(
            _manifest_issue(
                MANIFEST_BAD_STRUCTURE,
                "manifest active_variant is not a string - ignored",
            )
        )

    batch: list[Path] = []
    batch_raw = payload.get("batch", [])
    if not isinstance(batch_raw, list):
        issues.append(
            _manifest_issue(
                MANIFEST_BAD_STRUCTURE,
                "manifest batch is not an array - ignored",
            )
        )
    else:
        for entry in batch_raw:
            resolved = _resolve_manifest_entry(
                project_root, entry, "batch", issues
            )
            if resolved is not None:
                batch.append(resolved)

    assignments: dict[str, list[Path]] = {}
    assignments_raw = payload.get("assignments", {})
    if not isinstance(assignments_raw, dict):
        issues.append(
            _manifest_issue(
                MANIFEST_BAD_STRUCTURE,
                "manifest assignments is not an object - ignored",
            )
        )
    else:
        for variant_id, entries in assignments_raw.items():
            if not isinstance(entries, list):
                issues.append(
                    _manifest_issue(
                        MANIFEST_BAD_STRUCTURE,
                        f"manifest assignments[{variant_id!r}] is not an "
                        "array - ignored",
                    )
                )
                continue
            resolved_entries: list[Path] = []
            for entry in entries:
                resolved = _resolve_manifest_entry(
                    project_root,
                    entry,
                    f"assignments[{variant_id!r}]",
                    issues,
                )
                if resolved is not None:
                    resolved_entries.append(resolved)
            assignments[str(variant_id)] = resolved_entries

    return ProjectManifest(
        schema_version=schema_version,
        active_variant=active_variant,
        batch=batch,
        assignments=assignments,
        issues=issues,
    )


@dataclass(slots=True)
class VariantExecutionResult:
    """
    Summary:
        The isolated outcome of executing one variant's file list
        (LLR-006.4). Lists (not single optionals) carry the per-file engine
        outputs — the documented E6 design choice, because the manifest can
        map MULTIPLE change/check files onto one variant (``batch`` plus
        ``assignments``); each engine output keeps its own ``variant_id``
        stamp and ``source_path``.

    Args:
        variant_id (str): The executed variant's id.
        status (str): ``"ok"`` when every file produced an engine output;
            ``"error"`` when an exception interrupted this variant — the
            other variants still execute (LLR-006.4 isolation).
        change_summaries (list[ChangeSummary]): One per executed change
            file, in execution (plan) order.
        check_results (list[CheckRunResult]): One per executed check file,
            in execution (plan) order.
        diagnostics (list[str]): Human-readable notes — the failure text on
            an ``"error"`` status, save-back refusals, and the HEX
            save-back-unsupported note.
        mem_map (Optional[dict[int, int]]): The variant's POST-CHANGE
            address-to-byte map — the E7 report generator's hexdump input
            (LLR-007.8, additive E7 extension). Captured only when the
            caller requested ``capture_mem_maps=True``; ``None`` otherwise,
            preserving the LLR-006.3 release-each-image memory profile for
            callers that produce no report.

    Returns:
        None: Dataclass container.

    Data Flow:
        - Built by :func:`execute_variant_plan`, one per planned variant —
          ``len(results)`` always equals the planned variant count.
        - Consumed by the E6 TUI status reporting and the E7 report
          generator (``services/report_service.py``).

    Dependencies:
        Used by:
            - execute_variant_plan / execute_project_variants
            - s19_app.tui.app.S19TuiApp (execute_scope reporting)
            - s19_app.tui.services.report_service.generate_project_report
    """

    variant_id: str
    status: str
    change_summaries: list[ChangeSummary] = field(default_factory=list)
    check_results: list[CheckRunResult] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)
    mem_map: Optional[dict[int, int]] = None


def plan_variant_executions(
    variant_set: ProjectVariantSet,
    manifest: Optional[ProjectManifest],
    scope: str = SCOPE_ALL,
    fallback_batch: Sequence[Path] = (),
) -> list[Tuple[VariantDescriptor, Tuple[Path, ...]]]:
    """
    Summary:
        Build the deterministic execution plan (LLR-006.2): variants in
        ``ProjectVariantSet`` order (outer), and per variant the manifest
        ``batch`` list order followed by the ``assignments[variant_id]``
        order (inner). A pure function — two calls over the same inputs
        return identical plans.

    Args:
        variant_set (ProjectVariantSet): The project's ordered variant
            inventory.
        manifest (Optional[ProjectManifest]): The parsed manifest, or
            ``None`` when absent — the LLR-006.1 default: batch mode over
            all variants using ``fallback_batch``.
        scope (str): One of :data:`EXECUTION_SCOPES` — ``"active"`` plans
            only the active variant, ``"all"`` every variant,
            ``"assignments"`` only variants holding a non-empty manifest
            assignment (and only their assignment files, no batch).
        fallback_batch (Sequence[Path]): The file list applied to every
            in-scope variant when no manifest exists (e.g. the TUI's
            currently loaded change/check file).

    Returns:
        list[Tuple[VariantDescriptor, Tuple[Path, ...]]]: One
        ``(descriptor, files)`` pair per in-scope variant in variant-set
        order; ``files`` in the LLR-006.2 inner order.

    Raises:
        ValueError: When ``scope`` is not one of :data:`EXECUTION_SCOPES`.

    Data Flow:
        - Select the in-scope descriptors from ``variant_set.variants``
          (set order preserved).
        - Map files: manifest present → ``batch + assignments[id]``
          (``assignments`` only for the ``"assignments"`` scope); manifest
          absent → ``fallback_batch`` (empty for the ``"assignments"``
          scope, which has nothing to assign).

    Dependencies:
        Used by:
            - execute_project_variants
            - tests/test_variant_execution.py (determinism, LLR-006.2)
    """
    if scope not in EXECUTION_SCOPES:
        raise ValueError(f"unknown execution scope {scope!r}")
    if scope == SCOPE_ACTIVE:
        selected = [
            variant
            for variant in variant_set.variants
            if variant.variant_id == variant_set.active_id
        ]
    elif scope == SCOPE_ALL:
        selected = list(variant_set.variants)
    else:
        assignments = manifest.assignments if manifest is not None else {}
        selected = [
            variant
            for variant in variant_set.variants
            if assignments.get(variant.variant_id)
        ]
    plan: list[Tuple[VariantDescriptor, Tuple[Path, ...]]] = []
    for variant in selected:
        if manifest is None:
            files: Tuple[Path, ...] = (
                () if scope == SCOPE_ASSIGNMENTS else tuple(fallback_batch)
            )
        elif scope == SCOPE_ASSIGNMENTS:
            files = tuple(manifest.assignments.get(variant.variant_id, ()))
        else:
            files = tuple(manifest.batch) + tuple(
                manifest.assignments.get(variant.variant_id, ())
            )
        plan.append((variant, files))
    return plan


def _execute_one_variant(
    variant: VariantDescriptor,
    files: Sequence[Path],
    project_dir: Path,
    mac_records: Optional[Sequence[dict]],
    a2l_data: Optional[dict],
    capture_mem_map: bool = False,
) -> VariantExecutionResult:
    """
    Summary:
        Execute one variant's file list against a FRESH parse of its image
        (LLR-006.3/006.5): change files ride ``apply_change_document`` with
        headless save-back, check files ride ``run_check_document`` — the
        service computes no linkage or verdict of its own.

    Args:
        variant (VariantDescriptor): The variant to execute.
        files (Sequence[Path]): The planned change/check files in
            LLR-006.2 inner order.
        project_dir (Path): The project directory — the change-file
            resolution base and the save-back destination.
        mac_records (Optional[Sequence[dict]]): Parsed project MAC records
            (shared linkage source), or ``None``.
        a2l_data (Optional[dict]): Parsed project A2L payload (shared
            linkage source), or ``None`` — enriched against THIS variant's
            memory map before use.
        capture_mem_map (bool): When ``True``, the variant's memory map is
            referenced on ``result.mem_map`` — the apply engine mutates it
            in place, so the reference IS the post-change map the E7
            report generator consumes (LLR-007.8). Defaults to ``False``
            (the LLR-006.3 release-each-image profile).

    Returns:
        VariantExecutionResult: ``status="ok"`` with the per-file engine
        outputs, or ``status="error"`` carrying the failure diagnostic
        (the caller continues with the next variant — LLR-006.4).

    Data Flow:
        - Parse the image via ``build_loaded_s19`` / ``build_loaded_hex``
          (``variant.file_type`` discriminates) — never the TUI snapshot.
        - Per file: ``read_change_document(file, project_dir)``;
          ``kind == "check"`` → check engine; anything else → apply engine
          (its gate blocks non-change documents).
        - A change apply with ``counts["applied"] > 0`` on an S19 variant
          saves back headlessly as ``<variant_id>-patched.s19`` into
          ``project_dir`` (LLR-002.7 headless parameter; the engine's
          F-S-01 sanitizer and dedup-on-collision apply); a HEX variant
          records the unsupported-save diagnostic (D-1).
        - Any exception → ``status="error"``, diagnostics carry the text.

    Dependencies:
        Uses:
            - build_loaded_s19 / build_loaded_hex
            - read_change_document / apply_change_document /
              run_check_document / save_patched_image
            - enrich_tags_and_render
        Used by:
            - execute_variant_plan
    """
    result = VariantExecutionResult(
        variant_id=variant.variant_id, status=VARIANT_STATUS_OK
    )
    try:
        if variant.file_type == "hex":
            loaded = build_loaded_hex(
                variant.path, IntelHexFile(str(variant.path)), None, a2l_data
            )
        else:
            loaded = build_loaded_s19(
                variant.path, S19File(str(variant.path)), None, a2l_data
            )
        if capture_mem_map:
            result.mem_map = loaded.mem_map
        a2l_tags = (
            enrich_tags_and_render(a2l_data, loaded.mem_map)[0]
            if a2l_data
            else None
        )
        for file_path in files:
            document = read_change_document(str(file_path), project_dir)
            if document.kind == "check":
                result.check_results.append(
                    run_check_document(
                        document,
                        loaded.mem_map,
                        loaded.ranges,
                        mac_records,
                        a2l_tags,
                        variant_id=variant.variant_id,
                    )
                )
                continue
            summary = apply_change_document(
                document,
                loaded.mem_map,
                loaded.ranges,
                mac_records,
                a2l_tags,
                variant_id=variant.variant_id,
            )
            result.change_summaries.append(summary)
            if summary.counts.get("applied", 0) > 0:
                if variant.file_type == "s19":
                    saved_path, save_issues = save_patched_image(
                        loaded.mem_map,
                        loaded.ranges,
                        project_dir,
                        f"{variant.variant_id}-patched.s19",
                        source_kind="s19",
                        bytes_per_line=32,
                    )
                    summary.saved_path = saved_path
                    if saved_path is None:
                        result.diagnostics.extend(
                            f"[{issue.code}] {issue.message}"
                            for issue in save_issues
                        )
                else:
                    result.diagnostics.append(
                        "HEX save-back not supported this batch - patched "
                        "image not persisted"
                    )
    except Exception as exc:  # noqa: BLE001 — LLR-006.4 isolation boundary
        result.status = VARIANT_STATUS_ERROR
        result.diagnostics.append(f"{type(exc).__name__}: {exc}")
    return result


def execute_variant_plan(
    plan: Sequence[Tuple[VariantDescriptor, Tuple[Path, ...]]],
    project_dir: Path,
    *,
    mac_path: Optional[Path] = None,
    a2l_path: Optional[Path] = None,
    status_callback: Optional[StatusCallback] = None,
    capture_mem_maps: bool = False,
) -> list[VariantExecutionResult]:
    """
    Summary:
        Execute a planned variant list sequentially — one parsed image at a
        time, each variant isolated (LLR-006.3/006.4), with a between-
        variant status line per F-Q-18.

    Args:
        plan (Sequence[Tuple[VariantDescriptor, Tuple[Path, ...]]]): The
            :func:`plan_variant_executions` output.
        project_dir (Path): The project directory — change-file resolution
            base and save-back destination.
        mac_path (Optional[Path]): The project's MAC overlay, parsed ONCE
            and shared across variants as the linkage source.
        a2l_path (Optional[Path]): The project's A2L file, parsed ONCE; the
            per-variant enrichment happens inside each variant's execution.
        status_callback (Optional[StatusCallback]): Receives one line as
            each variant starts and one as it finishes — the TUI worker
            passes a ``call_from_thread``-wrapped ``set_status``.
        capture_mem_maps (bool): When ``True``, every result retains its
            variant's post-change memory map for the E7 report generator
            (LLR-007.8) — N maps stay alive for the caller's lifetime.
            Defaults to ``False``: the LLR-006.3 one-image-at-a-time
            memory profile is preserved.

    Returns:
        list[VariantExecutionResult]: Exactly ``len(plan)`` results in plan
        order — a failing variant yields its ``"error"`` result and the
        loop continues (LLR-006.4).

    Data Flow:
        - Parse the shared MAC / A2L linkage sources once.
        - Loop the plan; each iteration delegates to
          :func:`_execute_one_variant` and drops the variant's parsed image
          before the next iteration begins (one image at a time) — unless
          ``capture_mem_maps`` pins each map onto its result.

    Dependencies:
        Uses:
            - parse_mac_file / parse_a2l_file
            - _execute_one_variant
        Used by:
            - execute_project_variants
            - tests/test_variant_execution.py
    """
    mac_records = (
        parse_mac_file(mac_path)["records"] if mac_path is not None else None
    )
    a2l_data = parse_a2l_file(a2l_path) if a2l_path is not None else None
    results: list[VariantExecutionResult] = []
    for variant, files in plan:
        if status_callback is not None:
            status_callback(
                f"Executing variant '{variant.variant_id}' "
                f"({len(files)} file(s))..."
            )
        result = _execute_one_variant(
            variant,
            files,
            project_dir,
            mac_records,
            a2l_data,
            capture_mem_map=capture_mem_maps,
        )
        results.append(result)
        if status_callback is not None:
            status_callback(
                f"Variant '{variant.variant_id}': {result.status} - "
                f"{len(result.change_summaries)} change, "
                f"{len(result.check_results)} check"
            )
    return results


def execute_project_variants(
    project_dir: Path,
    variant_set: ProjectVariantSet,
    *,
    scope: str = SCOPE_ALL,
    fallback_batch: Sequence[Path] = (),
    status_callback: Optional[StatusCallback] = None,
    capture_mem_maps: bool = False,
) -> Tuple[list[VariantExecutionResult], list[ValidationIssue]]:
    """
    Summary:
        The one-call E6 entry point: read the manifest (capped), locate the
        project's shared MAC / A2L overlays, build the deterministic plan,
        and execute it variant-by-variant (HLR-006).

    Args:
        project_dir (Path): The project directory
            (``.s19tool/workarea/<project>/``).
        variant_set (ProjectVariantSet): The project's ordered variant
            inventory.
        scope (str): One of :data:`EXECUTION_SCOPES`; see
            :func:`plan_variant_executions`.
        fallback_batch (Sequence[Path]): The manifest-absent default file
            list (LLR-006.1 batch mode over all variants).
        status_callback (Optional[StatusCallback]): Forwarded to
            :func:`execute_variant_plan` (F-Q-18).
        capture_mem_maps (bool): Forwarded to
            :func:`execute_variant_plan` — ``True`` retains each variant's
            post-change memory map for the E7 report generator
            (LLR-007.8).

    Returns:
        Tuple[list[VariantExecutionResult], list[ValidationIssue]]: The
        per-variant results (``len == planned variant count``) plus the
        manifest's collected findings (empty when the manifest is absent or
        clean) so the caller can surface containment skips.

    Data Flow:
        - ``read_project_manifest`` → manifest or ``None`` (default mode).
        - ``validate_project_files`` locates the single MAC / A2L overlays
          (a cardinality-faulted project yields no overlays rather than
          aborting the execution).
        - ``plan_variant_executions`` → ``execute_variant_plan``.

    Dependencies:
        Uses:
            - read_project_manifest / plan_variant_executions /
              execute_variant_plan
            - validate_project_files
        Used by:
            - s19_app.tui.app.S19TuiApp._start_execute_scope_worker
            - tests/test_variant_execution.py
    """
    manifest = read_project_manifest(project_dir)
    manifest_issues = list(manifest.issues) if manifest is not None else []
    data_files, a2l_files, error = validate_project_files(project_dir)
    if error is not None:
        data_files = []
        a2l_files = []
    mac_path = next(
        (
            item
            for item in data_files
            if item.suffix.lower() in MAC_EXTENSIONS
        ),
        None,
    )
    a2l_path = a2l_files[0] if a2l_files else None
    plan = plan_variant_executions(
        variant_set, manifest, scope=scope, fallback_batch=fallback_batch
    )
    results = execute_variant_plan(
        plan,
        project_dir,
        mac_path=mac_path,
        a2l_path=a2l_path,
        status_callback=status_callback,
        capture_mem_maps=capture_mem_maps,
    )
    return results, manifest_issues
