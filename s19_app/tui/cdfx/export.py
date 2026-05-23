"""
Selective-export coordinator — s19_app batch-04, increment 7.

Selective export is the hand-off step of the unified change-set: it splits the
in-app :class:`~s19_app.tui.cdfx.changeset.UnifiedChangeSet` back into the two
artifacts each downstream consumer expects (HLR-007 / US-005):

- a **CDFX (.cdfx) file** for the parameter half — produced by the **unchanged**
  batch-03 CDFX write path (``writer.write_cdfx_to_workarea``), so vCDM can
  consume it (LLR-007.1);
- a **separate memory-field JSON file** for the memory-field half — a stdlib
  ``json`` document carrying the format identifier, the version, and the
  memory-change entries in the LLR-005.3 array-of-objects shape (LLR-007.2).

The two files are **never merged** (LLR-007.3): a selective export yields
exactly one ``.cdfx`` and one ``.json``, each placed inside the work area
through the existing ``workspace.py`` containment path.

The crux of this module — and the resolution of the Phase-2 A-1 blocker — is
**export-time re-resolution** (LLR-007.5). The unified change-set holds the
parameter half as a plain batch-03 ``ChangeList`` with **no** ``ResolutionResult``
attached (LLR-004.1, A-7), but ``write_cdfx_to_workarea`` requires a typed
``ResolutionResult`` argument. So this coordinator re-resolves the bare
``ChangeList`` against the currently loaded A2L through the **unchanged**
batch-03 ``resolve.resolve_against_a2l`` — exactly as ``cdfx_service.save``
does before a CDFX write — and feeds the writer a freshly-computed,
transient ``ResolutionResult``. The writer itself is invoked literally
unchanged (constraint C-1); the unified file format stays resolution-free.

With **no A2L loaded** the coordinator mirrors the batch-03 ``unresolved-no-a2l``
collect-don't-abort pattern (DD-11): ``resolve_against_a2l`` is still called
(with ``None`` tags), every parameter entry resolves ``UNRESOLVED_NO_A2L``, the
coordinator collects one informational ``ValidationIssue`` rather than aborting,
and the export proceeds — the CDFX writer simply excludes every unresolved
entry. No exception is raised.

Each half exports **independently** (LLR-007.4): a problem in the parameter
half never blocks the memory-field write, and vice versa. The coordinator
collects the ``ValidationIssue`` list of each write into one combined result
and tags every issue's **per-half origin** on the existing
``ValidationIssue.artifact`` field — :data:`PARAM_HALF_ARTIFACT` (``param-half``)
for the CDFX-write issues, :data:`MEMORY_HALF_ARTIFACT` (``memory-half``) for the
memory-field-write issues. No new field is added and the ``ValidationIssue``
model is not changed (constraint C-5 / A-5); the per-half tag is written onto
the existing field.

The memory-field JSON write reuses the same serialize-to-temp-then-
``copy_into_workarea`` containment path as the unified-file writer (constraint
C-10): :func:`write_memory_field_to_workarea` serializes the memory half with
:func:`serialize_memory_field` and lets the hardened ``copy_into_workarea``
helper perform the containment-checked final placement — no new write path.

Implements LLR-007.1..LLR-007.5.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ...validation.model import ValidationIssue, ValidationSeverity
from ..workspace import (
    WORKAREA_TEMP,
    WorkareaContainmentError,
    copy_into_workarea,
    ensure_workarea,
)
from .changeset import UnifiedChangeSet
from .resolve import resolve_against_a2l
from .unified_io import (
    CopyIntoWorkarea,
    UNIFIED_FORMAT_ID,
    UNIFIED_FORMAT_VERSION,
    _encode_memory_entry,
)
from .writer import write_cdfx_to_workarea

# ---------------------------------------------------------------------------
# Per-half origin tags (LLR-007.4) — written onto the existing
# ``ValidationIssue.artifact`` field so the combined result records which half
# each finding came from. No new ValidationIssue field is introduced (C-5 / A-5).
# ---------------------------------------------------------------------------

# The artifact tag stamped on every issue produced by the parameter-half
# (CDFX) export — the re-resolution issue and every write-time ``W-*`` issue.
PARAM_HALF_ARTIFACT = "param-half"

# The artifact tag stamped on every issue produced by the memory-field-half
# (JSON) export — the memory-field-write containment issue.
MEMORY_HALF_ARTIFACT = "memory-half"

# ---------------------------------------------------------------------------
# Issue code emitted by this coordinator (the others come from the unchanged
# batch-03 writer and the increment-5/6 unified_io module).
# ---------------------------------------------------------------------------

# Export-time: a selective export was requested with no A2L loaded, so the
# parameter half could not be resolved (LLR-007.5). Informational, not an
# error — the export still proceeds, mirroring ``unresolved-no-a2l`` (DD-11).
EXPORT_NO_A2L = "MF-EXPORT-NO-A2L"

# The default file names a selective export uses when the caller passes none.
DEFAULT_CDFX_FILE_NAME = "patchset.cdfx"
DEFAULT_MEMORY_FIELD_FILE_NAME = "memory-field.json"


@dataclass(slots=True)
class ExportResult:
    """
    Summary:
        The outcome of a selective export — the two written file paths and the
        combined, per-half-tagged ``ValidationIssue`` list (LLR-007.3,
        LLR-007.4).

    Args:
        cdfx_path (Path | None): The absolute path of the written ``.cdfx``
            parameter-half file, or ``None`` when the CDFX write was rejected
            by work-area containment validation (LLR-007.1).
        memory_field_path (Path | None): The absolute path of the written
            memory-field ``.json`` file, or ``None`` when that write was
            rejected by containment validation (LLR-007.2).
        issues (list[ValidationIssue]): Every ``ValidationIssue`` from both
            half exports, combined into one list. Each issue's ``artifact``
            field carries its per-half origin — :data:`PARAM_HALF_ARTIFACT` or
            :data:`MEMORY_HALF_ARTIFACT` (LLR-007.4). May be empty.

    Returns:
        None: Dataclass container.

    Data Flow:
        - Built and returned by :func:`export_unified`.
        - The CDFX service / Patch Editor reads the two paths for the status
          line and ``issues`` to render the finding list (increment 8).

    Dependencies:
        Uses:
            - ValidationIssue
        Used by:
            - export_unified (returned to its callers)
    """

    cdfx_path: Path | None
    memory_field_path: Path | None
    issues: list[ValidationIssue] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Memory-field JSON file — serialization (LLR-007.2).
# ---------------------------------------------------------------------------


def serialize_memory_field(changeset: UnifiedChangeSet) -> bytes:
    """
    Summary:
        Serialize the memory-field half of a unified change-set to a standalone
        JSON document as UTF-8 bytes (LLR-007.2).

    Args:
        changeset (UnifiedChangeSet): The container whose ``memory`` half is
            serialized. Only the memory-field half is written — the parameter
            half is exported separately as CDFX. The memory entries are written
            in their deterministic insertion order (LLR-001.4), so two exports
            of the same change-set are byte-identical.

    Returns:
        bytes: The memory-field JSON document, UTF-8 encoded. A single JSON
        object carrying ``format`` (:data:`UNIFIED_FORMAT_ID`), ``version``
        (:data:`UNIFIED_FORMAT_VERSION`) and ``memory`` — the memory-field half
        as a JSON **array of objects**, each carrying ``address`` as an
        integer-valued field and ``new_bytes`` as an integer array (the
        LLR-005.3 wire shape, reused). Always valid JSON re-parseable by
        ``json.loads``.

    Raises:
        None: Every ``MemoryChange`` was already validated at construction
            (LLR-002.5), so a well-formed ``UnifiedChangeSet`` always
            serializes — the writer never raises on change-set content.

    Data Flow:
        - Build the memory-field array by reusing ``unified_io._encode_memory_entry``
          — the exact LLR-005.3 array-of-objects encoder the unified-file
          writer uses, so the memory half is wire-identical between the two
          file kinds.
        - Wrap the array under the format-id / version header and dump with
          stdlib ``json`` (``indent=2`` keeps the file human-inspectable).

    Dependencies:
        Uses:
            - _encode_memory_entry (the shared LLR-005.3 encoder)
            - json.dumps
        Used by:
            - write_memory_field_to_workarea

    Example:
        >>> from s19_app.tui.cdfx import UnifiedChangeSet
        >>> cs = UnifiedChangeSet()
        >>> cs.memory.add(0x100, [0x41, 0x42])
        >>> import json
        >>> json.loads(serialize_memory_field(cs))["memory"][0]["address"]
        256
    """
    document = {
        "format": UNIFIED_FORMAT_ID,
        "version": UNIFIED_FORMAT_VERSION,
        "memory": [
            _encode_memory_entry(entry) for entry in changeset.memory.entries
        ],
    }
    text = json.dumps(document, indent=2) + "\n"
    return text.encode("utf-8")


def _memory_field_safe_name(file_name: str) -> str:
    """
    Summary:
        Reduce a requested memory-field-file name to its bare name component
        with a ``.json`` suffix, so the write target cannot escape the work
        area via the file name itself.

    Args:
        file_name (str): The engineer-requested file name — possibly carrying
            path separators or no suffix.

    Returns:
        str: The bare name (``Path.name`` — directory components stripped) with
        a ``.json`` suffix forced on. An empty result falls back to
        :data:`DEFAULT_MEMORY_FIELD_FILE_NAME`.

    Data Flow:
        - Strip any directory component with ``Path(...).name``.
        - Force a ``.json`` suffix; fall back to the default name when empty.

    Dependencies:
        Used by:
            - write_memory_field_to_workarea
    """
    bare = Path(file_name).name.strip()
    if not bare:
        return DEFAULT_MEMORY_FIELD_FILE_NAME
    if not bare.lower().endswith(".json"):
        bare = f"{bare}.json"
    return bare


def _memory_field_containment_issue(detail: str) -> ValidationIssue:
    """
    Summary:
        Build the warning ``ValidationIssue`` for a memory-field-file write
        target that failed work-area containment validation (LLR-007.2).

    Args:
        detail (str): The ``WorkareaContainmentError`` detail message — names
            the rejected target and the reason (outside the work area, or a
            reparse-point traversal).

    Returns:
        ValidationIssue: A warning-level issue with code
        :data:`~s19_app.tui.cdfx.unified_io.MF_WRITE_CONTAINMENT` and the
        per-half artifact :data:`MEMORY_HALF_ARTIFACT`. The write produced no
        file.

    Dependencies:
        Used by:
            - write_memory_field_to_workarea
    """
    # Import the shared code at call time to avoid widening the module-level
    # import surface; the constant is defined in unified_io (the rule-code home).
    from .unified_io import MF_WRITE_CONTAINMENT

    return ValidationIssue(
        code=MF_WRITE_CONTAINMENT,
        severity=ValidationSeverity.WARNING,
        message=(
            f"the memory-field export write target failed work-area "
            f"containment validation — no file was written: {detail}"
        ),
        artifact=MEMORY_HALF_ARTIFACT,
    )


def write_memory_field_to_workarea(
    changeset: UnifiedChangeSet,
    base_dir: Path,
    file_name: str = DEFAULT_MEMORY_FIELD_FILE_NAME,
    copy_fn: CopyIntoWorkarea | None = None,
) -> tuple[Path | None, list[ValidationIssue]]:
    """
    Summary:
        Serialize the memory-field half of a unified change-set to a JSON file
        placed inside the work area, containment-validating the write target
        through the existing ``workspace.copy_into_workarea`` helper
        (LLR-007.2).

    Args:
        changeset (UnifiedChangeSet): The change-set whose memory half is
            serialized — passed to :func:`serialize_memory_field`.
        base_dir (Path): The app base directory whose ``.s19tool/workarea/`` is
            the containment root the JSON file is written into. The work-area
            structure is created if absent (``ensure_workarea``).
        file_name (str): The desired memory-field-file name. Directory
            components are stripped and a ``.json`` suffix is forced, so the
            file name itself cannot escape the work area. A name that collides
            with an existing file is dedup-suffixed (``_<N>`` before the
            suffix) by ``copy_into_workarea`` — never a silent clobber.
        copy_fn (CopyIntoWorkarea | None): The work-area placement helper.
            ``None`` (the default) resolves to ``workspace.copy_into_workarea``
            — the hardened containment / reparse-point / dedup primitive — at
            call time. It is injectable so a test can stub the
            containment-checked placement without OS symlink privilege; this
            mirrors ``write_unified_to_workarea`` exactly.

    Returns:
        tuple[Path | None, list[ValidationIssue]]: The absolute path of the
        written memory-field JSON file and the issue list, or ``(None, issues)``
        when the write target failed containment validation. A containment /
        reparse-point rejection adds exactly one ``MF-WRITE-CONTAINMENT``
        warning ``ValidationIssue`` (artifact :data:`MEMORY_HALF_ARTIFACT`) and
        the path is ``None``; a clean write returns the path and an empty
        issue list.

    Raises:
        None: A containment / reparse-point / overwrite failure is reported as
            an ``MF-WRITE-CONTAINMENT`` ``ValidationIssue``, never raised
            (LLR-007.2 collect-don't-abort). ``WorkareaContainmentError`` from
            the reused helper is caught and converted here; an ``OSError`` from
            the staged-temp ``write_bytes`` (a full disk, a denied permission)
            is likewise caught and converted, so no I/O fault escapes uncaught
            (security finding S57-02).

    Data Flow:
        - Serialize the memory half with :func:`serialize_memory_field`.
        - Ensure the ``.s19tool/workarea/`` structure; stage the bytes under
          the chosen name in ``.s19tool/workarea/temp/`` — itself inside the
          work area, so no bytes ever land outside it, and ``copy_into_workarea``
          is a file-*copy* primitive that needs a real source file (S-004 /
          constraint C-10 — the unified-file writer's pattern, reused).
        - Call the copy helper to place the staged file in the work-area root:
          it resolves the target under ``.s19tool/workarea/``, rejects a
          reparse-point traversal, and dedup-suffixes a name collision.
        - A ``WorkareaContainmentError`` becomes one ``MF-WRITE-CONTAINMENT``
          warning and a ``None`` path; the staged temp file is removed either
          way.

    Dependencies:
        Uses:
            - serialize_memory_field
            - ensure_workarea
            - copy_into_workarea (via the injectable copy_fn)
            - _memory_field_safe_name
            - _memory_field_containment_issue
        Used by:
            - export_unified

    Example:
        >>> path, issues = write_memory_field_to_workarea(cs, base_dir)  # doctest: +SKIP
    """
    data = serialize_memory_field(changeset)
    issues: list[ValidationIssue] = []

    placement: CopyIntoWorkarea = (
        copy_into_workarea if copy_fn is None else copy_fn
    )

    workarea = ensure_workarea(base_dir)
    staged = workarea / WORKAREA_TEMP / _memory_field_safe_name(file_name)
    try:
        staged.write_bytes(data)
        target = placement(staged, workarea)
        return target, issues
    except WorkareaContainmentError as exc:
        issues.append(_memory_field_containment_issue(str(exc)))
        return None, issues
    except OSError as exc:
        # The staged-temp ``write_bytes`` (or the copy helper's own filesystem
        # work) can raise an OSError — a full disk, a denied permission, a name
        # too long. Without this arm the OSError escapes uncaught and breaks
        # the LLR-007.2 collect-don't-abort / "never an uncaught exception"
        # contract (security finding S57-02). Convert it, like a containment
        # rejection, to one MF-WRITE-CONTAINMENT issue and a None path.
        issues.append(_memory_field_containment_issue(f"{type(exc).__name__}: {exc}"))
        return None, issues
    finally:
        try:
            staged.unlink()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Selective-export coordinator (LLR-007.1..LLR-007.5).
# ---------------------------------------------------------------------------


def _no_a2l_issue() -> ValidationIssue:
    """
    Summary:
        Build the informational ``ValidationIssue`` recording that a selective
        export ran with no A2L loaded, so the parameter half could not be
        resolved (LLR-007.5 / DD-11).

    Returns:
        ValidationIssue: An info-level issue with code :data:`EXPORT_NO_A2L`
        and the parameter-half artifact :data:`PARAM_HALF_ARTIFACT`. The export
        still proceeds — every parameter entry resolves ``UNRESOLVED_NO_A2L``
        and the CDFX writer excludes it — so this is informational, not an
        error, mirroring the batch-03 ``unresolved-no-a2l`` collect-don't-abort
        pattern.

    Dependencies:
        Used by:
            - export_unified
    """
    return ValidationIssue(
        code=EXPORT_NO_A2L,
        severity=ValidationSeverity.INFO,
        message=(
            "the selective export ran with no A2L loaded — the parameter half "
            "could not be resolved, so every parameter entry is excluded from "
            "the .cdfx; the memory-field export is unaffected"
        ),
        artifact=PARAM_HALF_ARTIFACT,
    )


def _tag_artifact(
    issues: list[ValidationIssue],
    artifact: str,
) -> list[ValidationIssue]:
    """
    Summary:
        Stamp the per-half origin tag onto every issue's existing
        ``ValidationIssue.artifact`` field (LLR-007.4).

    Args:
        issues (list[ValidationIssue]): The issues produced by one half's
            export — the ``W-*`` issues of the CDFX write, or the
            ``MF-WRITE-CONTAINMENT`` issue of the memory-field write.
        artifact (str): The per-half tag to write — :data:`PARAM_HALF_ARTIFACT`
            or :data:`MEMORY_HALF_ARTIFACT`.

    Returns:
        list[ValidationIssue]: The same list, returned for call-site chaining.
        Each issue's ``artifact`` field is overwritten in place with the
        per-half tag — no new ``ValidationIssue`` field is added and the model
        is unchanged (constraint C-5 / A-5).

    Data Flow:
        - Overwrite ``issue.artifact`` for every issue in the list. The
          underlying writers stamp their own artifact (``cdfx`` / ``unified``);
          the coordinator re-stamps it to the per-half origin so the combined
          result records which half each issue came from.

    Dependencies:
        Used by:
            - export_unified
    """
    for issue in issues:
        issue.artifact = artifact
    return issues


def export_unified(
    unified_change_set: UnifiedChangeSet,
    loaded_a2l: list[dict[str, Any]] | None,
    base_dir: Path,
    cdfx_file_name: str = DEFAULT_CDFX_FILE_NAME,
    memory_field_file_name: str = DEFAULT_MEMORY_FIELD_FILE_NAME,
    copy_fn: CopyIntoWorkarea | None = None,
    resolve_fn: Callable[..., Any] = resolve_against_a2l,
) -> ExportResult:
    """
    Summary:
        Selectively export a unified change-set — produce a CDFX file for the
        parameter half and a separate JSON file for the memory-field half, each
        contained in the work area, and collect both halves' issues tagged with
        their per-half origin (HLR-007 / LLR-007.1..LLR-007.5).

    Args:
        unified_change_set (UnifiedChangeSet): The container to export. Its
            parameter half (a plain ``ChangeList``) is exported as CDFX; its
            memory-field half (a ``MemoryChangeList``) is exported as a JSON
            file. The two halves are exported independently and never merged
            (LLR-007.3).
        loaded_a2l (list[dict] | None): The enriched A2L tags the parameter
            half is re-resolved against (the app's enriched-tag cache, the same
            shape ``cdfx_service`` passes). ``None`` (or an empty list) means
            no A2L is loaded — the export still proceeds and collects one
            informational :data:`EXPORT_NO_A2L` issue (LLR-007.5 / DD-11).
        base_dir (Path): The app base directory whose ``.s19tool/workarea/`` is
            the containment root both files are written into.
        cdfx_file_name (str): The desired ``.cdfx`` file name for the parameter
            half. A collision is dedup-suffixed by ``write_cdfx_to_workarea``.
        memory_field_file_name (str): The desired ``.json`` file name for the
            memory-field half. A collision is dedup-suffixed by
            ``write_memory_field_to_workarea``.
        copy_fn (CopyIntoWorkarea | None): The work-area placement helper for
            the **memory-field** write — injectable so a test can exercise the
            containment-rejection path deterministically (the
            ``write_unified_to_workarea`` seam, reused). ``None`` (the default)
            uses ``workspace.copy_into_workarea``. The CDFX write always uses
            the unchanged ``write_cdfx_to_workarea`` (constraint C-1).
        resolve_fn (Callable): The export-time resolver, defaulting to the
            unchanged batch-03 :func:`~s19_app.tui.cdfx.resolve.resolve_against_a2l`
            (LLR-007.5). Injectable only so a test can spy on the re-resolution
            call (TC-036); production callers leave it at the default.

    Returns:
        ExportResult: The two written file paths (``cdfx_path`` /
        ``memory_field_path``, each ``None`` only when its write was rejected by
        containment validation) and the combined ``ValidationIssue`` list. Each
        issue's ``artifact`` field carries its per-half origin —
        :data:`PARAM_HALF_ARTIFACT` for the parameter-half (CDFX + re-resolution)
        issues, :data:`MEMORY_HALF_ARTIFACT` for the memory-field-half issues
        (LLR-007.4).

    Raises:
        None: Every failure mode — no A2L loaded, an unresolved parameter
            entry, a containment rejection on either write — is a collected
            ``ValidationIssue``, never an exception (collect-don't-abort
            across the two halves, LLR-007.4 / LLR-007.5). The CDFX writer and
            the resolver are the unchanged batch-03 ones, which also never
            raise on change-set content.

    Data Flow:
        - **Parameter half (LLR-007.5 → LLR-007.1):** re-resolve the parameter
          ``ChangeList`` against ``loaded_a2l`` via ``resolve_fn`` (the
          unchanged ``resolve_against_a2l``) to obtain a transient
          ``ResolutionResult``. With no A2L loaded the resolution still runs
          (every entry → ``UNRESOLVED_NO_A2L``) and one informational
          :data:`EXPORT_NO_A2L` issue is collected. Then invoke the **unchanged**
          ``write_cdfx_to_workarea`` with the ``ChangeList`` and that
          ``ResolutionResult`` — producing the ``.cdfx`` file. Every issue from
          this half is tagged :data:`PARAM_HALF_ARTIFACT`.
        - **Memory-field half (LLR-007.2):** serialize the memory half and
          write it through :func:`write_memory_field_to_workarea` — the
          serialize-to-temp-then-``copy_into_workarea`` containment path, reused
          (constraint C-10). Every issue from this half is tagged
          :data:`MEMORY_HALF_ARTIFACT`.
        - The two halves run independently: a containment rejection on one does
          not stop the other (LLR-007.4). Combine both issue lists into the
          returned ``ExportResult``.

    Dependencies:
        Uses:
            - resolve_against_a2l (the unchanged batch-03 resolver — LLR-007.5)
            - write_cdfx_to_workarea (the unchanged batch-03 CDFX writer — C-1)
            - write_memory_field_to_workarea
            - _tag_artifact
            - _no_a2l_issue
        Used by:
            - The CDFX service / Patch Editor selective-export action
              (increment 8).

    Example:
        >>> result = export_unified(cs, enriched_tags, base_dir)  # doctest: +SKIP
        >>> result.cdfx_path is not None and result.memory_field_path is not None  # doctest: +SKIP
        True
    """
    issues: list[ValidationIssue] = []

    # --- Parameter half: re-resolve, then the unchanged CDFX write ----------
    # The unified change-set carries the parameter half as a plain ChangeList
    # with no ResolutionResult (LLR-004.1 / A-7); write_cdfx_to_workarea needs
    # a typed ResolutionResult. Re-resolve here against the loaded A2L (the
    # exact pattern cdfx_service.save uses), so the batch-03 writer is fed a
    # transient, export-time argument and stays literally unchanged (C-1).
    if not loaded_a2l:
        # No A2L loaded — mirror unresolved-no-a2l (DD-11): still resolve (every
        # entry becomes UNRESOLVED_NO_A2L), collect one info issue, do not abort.
        issues.append(_no_a2l_issue())
    resolution = resolve_fn(unified_change_set.parameters, loaded_a2l)

    cdfx_path, cdfx_issues = write_cdfx_to_workarea(
        unified_change_set.parameters,
        resolution,
        base_dir,
        file_name=cdfx_file_name,
    )
    issues.extend(_tag_artifact(cdfx_issues, PARAM_HALF_ARTIFACT))

    # --- Memory-field half: the separate JSON file (LLR-007.2, LLR-007.3) ---
    # Independent of the parameter half — a containment rejection above does
    # not stop this write (LLR-007.4 collect-don't-abort across the halves).
    memory_field_path, memory_issues = write_memory_field_to_workarea(
        unified_change_set,
        base_dir,
        file_name=memory_field_file_name,
        copy_fn=copy_fn,
    )
    issues.extend(_tag_artifact(memory_issues, MEMORY_HALF_ARTIFACT))

    return ExportResult(
        cdfx_path=cdfx_path,
        memory_field_path=memory_field_path,
        issues=issues,
    )
