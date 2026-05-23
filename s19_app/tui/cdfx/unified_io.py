"""
Unified change-set JSON file handler — s19_app batch-04, increment 5 (write).

This module is the on-disk side of the unified change-set: it serializes a
:class:`~s19_app.tui.cdfx.changeset.UnifiedChangeSet` to a single JSON document
and writes that document into the work area through the existing, already
hardened ``workspace.py`` containment path. The unified file is the
**working-document** format the engineer saves, loads and exchanges; CDFX is
only the parameter-half *export* format (selective export, increment 7).

The JSON document this writer produces (LLR-005.1) is a single object with
four top-level keys:

- ``format`` — the format identifier :data:`UNIFIED_FORMAT_ID`, so the reader
  (increment 6) can recognise the file;
- ``version`` — the format version :data:`UNIFIED_FORMAT_VERSION`, so a future
  format revision can be tolerated;
- ``parameters`` — the parameter half: a JSON array, one object per
  ``ChangeListEntry``, each carrying ``parameter_name``, ``array_index``,
  ``value`` and ``status`` as **plain JSON fields** — the batch-03
  ``ChangeListEntry`` shape, **not** CDFX XML (LLR-005.2);
- ``memory`` — the memory-field half: a JSON **array of objects**, one object
  per ``MemoryChange``, each carrying ``address`` as an **integer-valued
  field** (a JSON number, never an object key) and ``new_bytes`` as a JSON
  array of integers (LLR-005.3 / DD-10).

Encoding ``address`` as an integer field rather than an object key is pinned
normatively (LLR-005.3): JSON object keys are always strings, so an
``address``-as-key shape would force every reader to re-parse the key and open
an undocumented hex-vs-decimal ambiguity; an integer *field* survives natively
through stdlib ``json`` and the round-trip test (TC-025, increment 9).

:func:`write_unified_to_workarea` is the **work-area-contained write path**
(LLR-005.4): it serializes the change-set with :func:`serialize_unified`, then
places the bytes on disk through ``workspace.copy_into_workarea`` — the
existing containment helper, **reused, not re-implemented** (constraint C-10).
The final target must resolve under a ``.s19tool/workarea/`` root; a target
that is, or whose traversed parents include, a symbolic link / NTFS reparse
point is rejected; an existing-name target is dedup-suffixed — no silent
clobber. A containment / reparse-point rejection is surfaced as one
``MF-WRITE-CONTAINMENT`` ``ValidationIssue``, never an uncaught exception
(collect-don't-abort). This mirrors ``writer.write_cdfx_to_workarea`` exactly:
the writer holds in-memory JSON, so it stages the bytes to a transient file
inside ``.s19tool/workarea/temp/`` (itself inside the work area) and lets
``copy_into_workarea`` perform the containment-checked final placement — no new
write path is introduced (LLR-005.4 rationale / S-004).

The ``MF-*`` rule codes are defined here as named constants: this module is
their home (the §5.8 / §D pinned-code list), so the increment-6 reader and its
tests reference one authoritative spelling.

:func:`read_unified` is the **read half** (increment 6): it resolves a
user-supplied path through ``workspace.resolve_input_path``, applies a 256 MB
pre-parse on-disk size cap, parses the document with stdlib ``json`` (catching
both ``json.JSONDecodeError`` **and** ``RecursionError`` — a deeply-nested
document overflows the C recursion of the stdlib parser and ``RecursionError``
is a ``RuntimeError``, not a ``JSONDecodeError``, so a bare
``except json.JSONDecodeError`` would let it escape and crash the load),
checks the decoded document's top-level shape **before** indexing either half
(so a well-formed-but-wrong-shape document yields one ``MF-BAD-STRUCTURE``
issue, never an uncaught ``KeyError``), applies the per-entry ``MF-*`` rule set
collect-don't-abort, and enforces a decoded-structure ceiling on the
memory-field entry count and on any single ``new_bytes`` run length
(``MF-ENTRY-LIMIT``). Every finding is surfaced as a ``ValidationIssue`` and
never raised; an issue message references an entry's ``address`` / a count, not
the raw ``new_bytes`` content (constraint C-9). The reader always returns a
``UnifiedChangeSet`` — empty when the file could not be parsed at all.

Implements LLR-005.1..LLR-005.4 (the write half) and LLR-006.1..LLR-006.5 plus
LLR-008.1..LLR-008.2 (the read half + the ``MF-*`` rule set).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from ...validation.model import ValidationIssue, ValidationSeverity
from ..workspace import (
    DEFAULT_COPY_SIZE_CAP_BYTES,
    WORKAREA_TEMP,
    WorkareaContainmentError,
    copy_into_workarea,
    ensure_workarea,
    resolve_input_path,
)
from .changelist import ChangeListEntry, ResolutionStatus
from .changeset import UnifiedChangeSet
from .memory import MemoryChange, MemoryStatus

# ---------------------------------------------------------------------------
# Format contract — the self-describing tokens of the unified-file JSON.
# ---------------------------------------------------------------------------

# The format-identifier field value the writer always emits and the reader
# recognises (LLR-005.1). A self-describing token, the JSON peer of the CDFX
# ``CATEGORY=CDF20`` marker.
UNIFIED_FORMAT_ID = "s19app-unified-changeset"

# The format-version field value (LLR-005.1). A reader that meets an
# unrecognised version still reads the file (LLR-008.2, increment 6) — the
# version field exists so a future revision is tolerable, not so old readers
# reject new files.
UNIFIED_FORMAT_VERSION = "1.0"

# The artifact tag every unified-file ValidationIssue carries — the per-half
# origin tag (`param-half` / `memory-half`) is added by the selective-export
# coordinator (increment 7), not here.
UNIFIED_ARTIFACT = "unified"

# ---------------------------------------------------------------------------
# MF-* rule codes — the fixed, documented memory-field / unified-file rule set
# (HLR-008). Defined here as this module is the rule-code home (§5.8 / §D); the
# increment-6 reader and its tests reference these exact spellings. Only
# MF-WRITE-CONTAINMENT is *emitted* by this increment's write path; the rest
# are the read-path codes the increment-6 reader will emit.
# ---------------------------------------------------------------------------

# Read-path: the file is not well-formed JSON, or its nesting overflowed the
# stdlib parser (a RecursionError) — increment 6.
MF_JSON_PARSE = "MF-JSON-PARSE"
# Read-path: well-formed JSON whose top-level shape is not a unified document
# (no recognised parameter / memory halves) — increment 6.
MF_BAD_STRUCTURE = "MF-BAD-STRUCTURE"
# Read-path: a memory-field entry object has no `address` field — increment 6.
MF_NO_ADDRESS = "MF-NO-ADDRESS"
# Read-path: a memory-field entry has an empty `new_bytes` run — increment 6.
MF_EMPTY_BYTES = "MF-EMPTY-BYTES"
# Read-path: a memory-field byte value is outside 0-255 — increment 6.
MF_BYTE_RANGE = "MF-BYTE-RANGE"
# Read-path: the file declares an unrecognised version token (info) — incr. 6.
MF_VERSION_UNKNOWN = "MF-VERSION-UNKNOWN"
# Read-path: the on-disk file exceeds the 256 MB size cap — increment 6.
MF_SIZE_CAP = "MF-SIZE-CAP"
# Read-path: the decoded structure breaches the entry-count or run-length
# ceiling — increment 6.
MF_ENTRY_LIMIT = "MF-ENTRY-LIMIT"
# Read-path: a user-supplied input path could not be resolved — increment 6.
MF_PATH_UNRESOLVED = "MF-PATH-UNRESOLVED"
# Write-path: the write target failed work-area containment validation — this
# increment's only emitted code.
MF_WRITE_CONTAINMENT = "MF-WRITE-CONTAINMENT"

# The default unified-file name a save uses when the caller passes none.
DEFAULT_UNIFIED_FILE_NAME = "changeset.json"

# ---------------------------------------------------------------------------
# Read-path resource bounds (LLR-006.4, LLR-006.5) — pinned, documented limits.
# ---------------------------------------------------------------------------

# Read-path on-disk size cap (LLR-006.4): the 256 MB byte ceiling a unified
# file may not exceed before it is parsed. This is the shared
# ``workspace.DEFAULT_COPY_SIZE_CAP_BYTES`` (268_435_456) so one consistent
# size limit governs every file the app reads — re-exported here under a
# read-path name so the reader and its tests reference one spelling.
READ_SIZE_CAP_BYTES = DEFAULT_COPY_SIZE_CAP_BYTES

# Read-path decoded-structure ceiling — memory-field entry count (LLR-006.5).
# The 256 MB on-disk cap bounds the *file*; it does not bound the *decoded*
# structure — a sub-cap JSON file can still declare millions of memory-field
# entries that expand several-fold once parsed into Python objects. A realistic
# patch set is tens-to-hundreds of memory-field entries; 100_000 is a generous
# documented headroom above any genuine use while still capping the
# resource-exhaustion vector. A file declaring more than this many memory-field
# entries has every entry past the ceiling dropped with one MF-ENTRY-LIMIT
# issue; the in-ceiling entries are kept.
MF_ENTRY_COUNT_CEILING = 100_000

# Read-path decoded-structure ceiling — single ``new_bytes`` run length
# (LLR-006.5). A genuine raw-memory edit is realistically tens-to-thousands of
# bytes; 1_048_576 (1 MiB) is a generous documented headroom. A memory-field
# entry whose ``new_bytes`` run is longer than this is dropped with one
# MF-ENTRY-LIMIT issue; the remaining entries are kept.
MF_RUN_LENGTH_CEILING = 1_048_576

# The ``copy_into_workarea`` seam type — the write path takes the helper as an
# injectable callable so a test can stub the containment-checked placement
# (TC-018's deterministic reparse-point arm) without OS symlink privilege.
# ``None`` (the default) resolves to the module-level ``copy_into_workarea`` at
# call time, so monkeypatching that symbol also redirects the write path.
CopyIntoWorkarea = Callable[[Path, Path], Path]

# The size-probe seam type — the read path takes the on-disk size measurement
# as an injectable callable so a test can report an over-cap byte size without
# manufacturing a real 256 MB file (TC-022's size-probe seam). ``None`` (the
# default) resolves to a real ``Path.stat().st_size`` measurement at call time.
SizeProbe = Callable[[Path], int]


# ---------------------------------------------------------------------------
# Serialization (LLR-005.1, LLR-005.2, LLR-005.3).
# ---------------------------------------------------------------------------


def serialize_unified(changeset: UnifiedChangeSet) -> bytes:
    """
    Summary:
        Serialize a unified change-set to a single JSON document as UTF-8 bytes
        (LLR-005.1).

    Args:
        changeset (UnifiedChangeSet): The container to serialize. Its parameter
            half (``changeset.parameters``) and memory-field half
            (``changeset.memory``) are each written in their own deterministic
            insertion order — the writer adds no second ordering rule, so two
            serializations of the same change-set are byte-identical
            (LLR-001.4).

    Returns:
        bytes: The unified-file JSON document, UTF-8 encoded. The document is a
        single JSON object carrying ``format`` (:data:`UNIFIED_FORMAT_ID`),
        ``version`` (:data:`UNIFIED_FORMAT_VERSION`), ``parameters`` (the
        parameter-half array, LLR-005.2) and ``memory`` (the memory-field-half
        array of objects, LLR-005.3). It is always valid JSON re-parseable by
        ``json.loads``.

    Raises:
        None: A well-formed ``UnifiedChangeSet`` always serializes — every
            ``MemoryChange`` was already validated at construction (LLR-002.5),
            and a ``ChangeListEntry`` value is always a JSON-encodable
            ``int`` / ``float`` / ``str`` / ``None`` (the ``PhysicalValue``
            type). The writer never raises on change-set content.

    Data Flow:
        - Build the parameter-half array: one object per ``ChangeListEntry``,
          carrying ``parameter_name`` / ``array_index`` / ``value`` / ``status``
          as plain JSON fields (LLR-005.2).
        - Build the memory-field-half array: one object per ``MemoryChange``,
          carrying ``address`` as an integer field and ``new_bytes`` as an
          integer array (LLR-005.3) — ``address`` is never an object key.
        - Wrap both halves under the format-id / version header and dump with
          stdlib ``json`` (``indent=2`` keeps the file human-inspectable, the
          format the owner asked for — §6.2.1 OQ-3).

    Dependencies:
        Uses:
            - _encode_parameter_entry
            - _encode_memory_entry
            - json.dumps
        Used by:
            - write_unified_to_workarea
            - The unified-file round-trip test (TC-025, increment 9).

    Example:
        >>> from s19_app.tui.cdfx import UnifiedChangeSet
        >>> cs = UnifiedChangeSet()
        >>> cs.memory.add(0x100, [0x41, 0x42])
        >>> data = serialize_unified(cs)
        >>> import json
        >>> json.loads(data)["memory"][0]["address"]
        256
    """
    document = {
        "format": UNIFIED_FORMAT_ID,
        "version": UNIFIED_FORMAT_VERSION,
        "parameters": [
            _encode_parameter_entry(entry)
            for entry in changeset.parameters.entries
        ],
        "memory": [
            _encode_memory_entry(entry) for entry in changeset.memory.entries
        ],
    }
    # indent=2 + a trailing newline keeps the working-document file readable
    # (OQ-3); ensure_ascii is left at its True default so the bytes are
    # pure-ASCII safe regardless of any non-ASCII string value.
    text = json.dumps(document, indent=2) + "\n"
    return text.encode("utf-8")


def _encode_parameter_entry(entry: ChangeListEntry) -> dict[str, object]:
    """
    Summary:
        Encode one parameter ``ChangeListEntry`` as a plain JSON object for the
        unified file's parameter half (LLR-005.2).

    Args:
        entry (ChangeListEntry): A parameter change-list entry — its
            ``parameter_name``, ``array_index``, ``value`` and resolution
            ``status`` are written.

    Returns:
        dict[str, object]: A JSON-encodable object with the four fields
        ``parameter_name`` (str), ``array_index`` (int or ``None``), ``value``
        (the ``PhysicalValue`` — int / float / str / ``None``, JSON-native)
        and ``status`` (the ``ResolutionStatus`` stable string token). This is
        the batch-03 ``ChangeListEntry`` shape serialized verbatim — **not**
        CDFX XML (LLR-005.2 / §6.2.1 OQ-3).

    Data Flow:
        - Read the entry's four fields; ``status`` is rendered as its enum
          ``.value`` string token so it survives JSON as a plain string.

    Dependencies:
        Used by:
            - serialize_unified
    """
    return {
        "parameter_name": entry.parameter_name,
        "array_index": entry.array_index,
        "value": entry.value,
        "status": entry.status.value,
    }


def _encode_memory_entry(entry: MemoryChange) -> dict[str, object]:
    """
    Summary:
        Encode one ``MemoryChange`` as a JSON object for the unified file's
        memory-field half (LLR-005.3).

    Args:
        entry (MemoryChange): A memory-change entry — its ``address``,
            ``new_bytes`` run and validation ``status`` are written.

    Returns:
        dict[str, object]: A JSON-encodable object with ``address`` as an
        **integer-valued field** (a JSON number, never an object key —
        LLR-005.3 / DD-10), ``new_bytes`` as a JSON array of integers built
        from the stored ``tuple[int, ...]``, and ``status`` as the
        ``MemoryStatus`` stable string token. A reader recovers the exact
        integer ``address`` and the exact ordered byte sequence with no loss.

    Data Flow:
        - Render ``address`` as a bare ``int`` field and ``new_bytes`` as a
          ``list`` so stdlib ``json`` emits a number and an array of numbers.
        - The ``status`` is written for completeness; the reader re-derives the
          real status against the loaded image and does not trust this field
          (the equality predicate of TC-025 excludes it).

    Dependencies:
        Used by:
            - serialize_unified
    """
    return {
        "address": entry.address,
        "new_bytes": list(entry.new_bytes),
        "status": entry.status.value,
    }


# ---------------------------------------------------------------------------
# Work-area-contained write path (LLR-005.4).
# ---------------------------------------------------------------------------


def write_unified_to_workarea(
    changeset: UnifiedChangeSet,
    base_dir: Path,
    file_name: str = DEFAULT_UNIFIED_FILE_NAME,
    copy_fn: CopyIntoWorkarea | None = None,
) -> tuple[Path | None, list[ValidationIssue]]:
    """
    Summary:
        Serialize a unified change-set to a JSON file placed inside the work
        area, containment-validating the write target through the existing
        ``workspace.copy_into_workarea`` helper (LLR-005.4).

    Args:
        changeset (UnifiedChangeSet): The change-set to serialize — passed
            straight to :func:`serialize_unified`.
        base_dir (Path): The app base directory whose ``.s19tool/workarea/`` is
            the containment root the JSON file is written into. The work-area
            structure is created if absent (``ensure_workarea``).
        file_name (str): The desired unified-file name. Directory components in
            the name are stripped and a ``.json`` suffix is forced, so the file
            name itself cannot escape the work area. A name that collides with
            an existing file in the work area is dedup-suffixed (``_<N>`` before
            the suffix) by ``copy_into_workarea`` — never a silent clobber.
        copy_fn (CopyIntoWorkarea | None): The work-area placement helper.
            ``None`` (the default) resolves to ``workspace.copy_into_workarea``
            — the hardened containment / reparse-point / dedup primitive — at
            call time, so monkeypatching that module symbol also redirects the
            write path. It is injectable so a test can stub the
            containment-checked placement (TC-018's deterministic reparse-point
            arm) without the OS privilege to create a real symbolic link;
            production callers leave it ``None``.

    Returns:
        tuple[Path | None, list[ValidationIssue]]: The absolute path of the
        written unified JSON file and the issue list, or ``(None, issues)``
        when the write target failed containment validation. A containment /
        reparse-point rejection adds exactly one ``MF-WRITE-CONTAINMENT``
        warning ``ValidationIssue`` and the path is ``None``; a clean save
        returns the path and an empty issue list.

    Raises:
        None: A containment, reparse-point, or overwrite failure is reported as
            an ``MF-WRITE-CONTAINMENT`` ``ValidationIssue``, never raised
            (LLR-005.4 collect-don't-abort). ``WorkareaContainmentError`` from
            the reused helper is caught and converted here; an ``OSError`` from
            the staged-temp ``write_bytes`` (a full disk, a denied permission)
            is likewise caught and converted, so no I/O fault escapes uncaught
            (security finding S57-02).

    Data Flow:
        - Serialize ``changeset`` with :func:`serialize_unified`.
        - Ensure the ``.s19tool/workarea/`` structure; stage the bytes under
          the engineer's chosen name in ``.s19tool/workarea/temp/`` — itself
          inside the work area, so no bytes ever land outside it, and
          ``copy_into_workarea`` is a file-*copy* primitive that needs a real
          source file (LLR-005.4 rationale / S-004).
        - Call the copy helper (``copy_fn`` if given, else the module-level
          ``copy_into_workarea``) to place the staged file in the work-area
          root: it resolves the target under ``.s19tool/workarea/``, rejects a
          reparse-point traversal, and dedup-suffixes a name collision —
          reused, not re-implemented (constraint C-10).
        - A ``WorkareaContainmentError`` becomes one ``MF-WRITE-CONTAINMENT``
          warning and a ``None`` path; the staged temp file is removed either
          way.

    Dependencies:
        Uses:
            - serialize_unified
            - ensure_workarea
            - copy_into_workarea (via the injectable copy_fn)
            - _safe_name
            - _containment_issue
        Used by:
            - The CDFX service / Patch Editor save action (increment 8).

    Example:
        >>> path, issues = write_unified_to_workarea(cs, base_dir)  # doctest: +SKIP
    """
    data = serialize_unified(changeset)
    issues: list[ValidationIssue] = []

    # Resolve the copy helper at call time so monkeypatching the module symbol
    # redirects the write path (the batch-03 CV-03 test seam) and an explicit
    # copy_fn argument still overrides it (the deterministic injectable seam).
    placement: CopyIntoWorkarea = (
        copy_into_workarea if copy_fn is None else copy_fn
    )

    workarea = ensure_workarea(base_dir)
    # Stage the bytes under the engineer's chosen name inside the work-area
    # temp/ dir, so copy_into_workarea's dedup keys off that name. temp/ is
    # itself inside the work area — no bytes ever land outside it (S-004).
    staged = workarea / WORKAREA_TEMP / _safe_name(file_name)
    try:
        staged.write_bytes(data)
        target = placement(staged, workarea)
        return target, issues
    except WorkareaContainmentError as exc:
        issues.append(_containment_issue(str(exc)))
        return None, issues
    except OSError as exc:
        # The staged-temp ``write_bytes`` (or the copy helper's own filesystem
        # work) can raise an OSError — a full disk, a denied permission, a name
        # too long. Without this arm the OSError escapes uncaught and breaks
        # the LLR-005.4 collect-don't-abort / "never an uncaught exception"
        # contract (security finding S57-02). Convert it, like a containment
        # rejection, to one MF-WRITE-CONTAINMENT issue and a None path.
        issues.append(_containment_issue(f"{type(exc).__name__}: {exc}"))
        return None, issues
    finally:
        try:
            staged.unlink()
        except OSError:
            pass


def _safe_name(file_name: str) -> str:
    """
    Summary:
        Reduce a requested unified-file name to its bare name component with a
        ``.json`` suffix, so the write target cannot escape the work area via
        the file name itself.

    Args:
        file_name (str): The engineer-requested file name — possibly carrying
            path separators or no suffix.

    Returns:
        str: The bare name (``Path.name`` — directory components stripped) with
        a ``.json`` suffix forced on. An empty result falls back to
        :data:`DEFAULT_UNIFIED_FILE_NAME`.

    Data Flow:
        - Strip any directory component with ``Path(...).name``.
        - Force a ``.json`` suffix; fall back to the default name when empty.

    Dependencies:
        Used by:
            - write_unified_to_workarea
    """
    bare = Path(file_name).name.strip()
    if not bare:
        return DEFAULT_UNIFIED_FILE_NAME
    if not bare.lower().endswith(".json"):
        bare = f"{bare}.json"
    return bare


def _containment_issue(detail: str) -> ValidationIssue:
    """
    Summary:
        Build the warning ``ValidationIssue`` for a unified-file write target
        that failed work-area containment validation (LLR-005.4).

    Args:
        detail (str): The ``WorkareaContainmentError`` detail message — names
            the rejected target and the reason (outside the work area, or a
            reparse-point traversal).

    Returns:
        ValidationIssue: A warning-level issue with code
        :data:`MF_WRITE_CONTAINMENT` and artifact :data:`UNIFIED_ARTIFACT`. The
        write produced no file.

    Dependencies:
        Used by:
            - write_unified_to_workarea
    """
    return ValidationIssue(
        code=MF_WRITE_CONTAINMENT,
        severity=ValidationSeverity.WARNING,
        message=(
            f"the unified change-set write target failed work-area "
            f"containment validation — no file was written: {detail}"
        ),
        artifact=UNIFIED_ARTIFACT,
    )


# ---------------------------------------------------------------------------
# Read-path issue builders — one per MF-* read-path rule code (HLR-008).
# Each builds a ValidationIssue with the documented code / severity / artifact;
# messages reference an address / a count, never the raw new_bytes content
# (constraint C-9 / LLR-002.2).
# ---------------------------------------------------------------------------


def _read_issue(
    code: str,
    severity: ValidationSeverity,
    message: str,
    address: int | None = None,
) -> ValidationIssue:
    """
    Summary:
        Build one read-path ``ValidationIssue`` with the unified-file artifact
        tag.

    Args:
        code (str): The ``MF-*`` rule code (one of the read-path constants).
        severity (ValidationSeverity): The documented severity for the rule —
            ``ERROR`` for every read-path rule except ``MF-VERSION-UNKNOWN``,
            which is ``INFO`` (LLR-008.2).
        message (str): The human-readable finding. Never embeds raw
            ``new_bytes`` content (constraint C-9).
        address (int | None): The memory-field entry ``address`` the finding
            concerns, when applicable; carried in the issue's ``address`` field
            for the UI / log.

    Returns:
        ValidationIssue: The finding, tagged ``artifact=UNIFIED_ARTIFACT``.

    Dependencies:
        Used by:
            - read_unified and its private rule helpers.
    """
    return ValidationIssue(
        code=code,
        severity=severity,
        message=message,
        artifact=UNIFIED_ARTIFACT,
        address=address,
    )


# ---------------------------------------------------------------------------
# Work-area-uncontained read path (LLR-006.1..LLR-006.5).
# ---------------------------------------------------------------------------


def read_unified(
    path_text: str,
    base_dir: Path,
    size_probe: SizeProbe | None = None,
) -> tuple[UnifiedChangeSet, list[ValidationIssue]]:
    """
    Summary:
        Read a unified change-set JSON file into a ``UnifiedChangeSet``,
        collecting every structural and per-entry finding as a
        ``ValidationIssue`` without ever raising (LLR-006.1..LLR-006.5).

    Args:
        path_text (str): The user-supplied unified-file path, resolved through
            ``workspace.resolve_input_path`` (cwd + repo-root walk +
            ``exists()`` check) before the file is opened — an unresolvable
            path is reported as one ``MF-PATH-UNRESOLVED`` issue and no file is
            opened (LLR-006.3).
        base_dir (Path): The app base directory ``resolve_input_path`` resolves
            the path against.
        size_probe (SizeProbe | None): The on-disk byte-size measurement seam.
            ``None`` (the default) resolves to a real ``Path.stat().st_size``
            measurement at call time. It is injectable so a test can report an
            over-cap size without manufacturing a real 256 MB file (TC-022).

    Returns:
        tuple[UnifiedChangeSet, list[ValidationIssue]]: The reconstructed
        change-set and the collected issue list. The change-set is **empty**
        when the file could not be resolved, exceeded the size cap, or failed
        to parse / was the wrong shape; it is **populated, possibly partially**
        when per-entry rules or the decoded-structure ceiling dropped some
        entries. The reader never raises on a data-quality fault.

    Raises:
        None: Every failure mode — an unresolvable path, an over-cap file, a
            malformed or deeply-nested document, a wrong-shape document, a
            malformed per-entry object, an over-ceiling structure — is a
            collected ``ValidationIssue`` (collect-don't-abort, A-4). The only
            paths to a raise are programming errors outside this contract.

    Data Flow:
        - Resolve ``path_text`` via ``resolve_input_path``; an unresolvable
          path → one ``MF-PATH-UNRESOLVED`` issue, an empty change-set, the
          file is never opened (LLR-006.3).
        - Probe the on-disk byte size; a size over :data:`READ_SIZE_CAP_BYTES`
          → one ``MF-SIZE-CAP`` issue, an empty change-set, ``json.load`` is
          never reached — the size check precedes parsing (LLR-006.4).
        - Parse with stdlib ``json``; a ``JSONDecodeError`` **or** a
          ``RecursionError`` (a deeply-nested document — ``RecursionError`` is
          a ``RuntimeError``, not a ``JSONDecodeError``) → one
          ``MF-JSON-PARSE`` issue, an empty change-set (LLR-006.2).
        - Check the decoded document's top-level shape **before** indexing
          either half; a non-object or an object with no recognised halves →
          one ``MF-BAD-STRUCTURE`` issue, an empty change-set, no ``KeyError``
          (LLR-006.2).
        - Check the ``version`` token; an unrecognised version → one info-level
          ``MF-VERSION-UNKNOWN`` issue, parsing continues (LLR-008.2).
        - Reconstruct each half with the per-entry ``MF-*`` rule set and the
          decoded-structure ceiling, collecting issues per entry (LLR-006.1,
          LLR-006.5, LLR-008.1).

    Dependencies:
        Uses:
            - resolve_input_path
            - json.load
            - _decode_parameter_half
            - _decode_memory_half
            - _read_issue
        Used by:
            - The CDFX service / Patch Editor load action (increment 8).

    Example:
        >>> changeset, issues = read_unified("changeset.json", base_dir)  # doctest: +SKIP
    """
    issues: list[ValidationIssue] = []
    empty = UnifiedChangeSet()

    # --- Path resolution (LLR-006.3) ---------------------------------------
    resolved = resolve_input_path(Path(path_text), base_dir)
    if resolved is None:
        issues.append(
            _read_issue(
                MF_PATH_UNRESOLVED,
                ValidationSeverity.ERROR,
                f"the unified change-set file path could not be resolved — "
                f"no file was opened: {path_text!r}",
            )
        )
        return empty, issues

    # --- Pre-parse size cap (LLR-006.4) — precedes json.load ---------------
    probe: SizeProbe = (
        (lambda candidate: candidate.stat().st_size)
        if size_probe is None
        else size_probe
    )
    size_bytes = probe(resolved)
    if size_bytes > READ_SIZE_CAP_BYTES:
        issues.append(
            _read_issue(
                MF_SIZE_CAP,
                ValidationSeverity.ERROR,
                f"the unified change-set file is {size_bytes} bytes, over the "
                f"{READ_SIZE_CAP_BYTES}-byte read cap — the file was not "
                f"loaded into memory",
            )
        )
        return empty, issues

    # --- Parse (LLR-006.2) — catch JSONDecodeError AND RecursionError ------
    # RecursionError is a RuntimeError, NOT a JSONDecodeError: a deeply-nested
    # document overflows the stdlib parser's C recursion and raises it; an
    # `except json.JSONDecodeError` alone would let it escape and crash the
    # load. Both are caught here as one MF-JSON-PARSE finding.
    try:
        with resolved.open("rb") as handle:
            document = json.load(handle)
    except (json.JSONDecodeError, RecursionError, UnicodeDecodeError) as exc:
        issues.append(
            _read_issue(
                MF_JSON_PARSE,
                ValidationSeverity.ERROR,
                f"the unified change-set file is not well-formed JSON — the "
                f"load produced an empty change-set: {type(exc).__name__}",
            )
        )
        return empty, issues
    except OSError as exc:
        issues.append(
            _read_issue(
                MF_PATH_UNRESOLVED,
                ValidationSeverity.ERROR,
                f"the unified change-set file could not be opened — no "
                f"change-set was loaded: {type(exc).__name__}",
            )
        )
        return empty, issues

    # --- Structural shape guard (LLR-006.2) — BEFORE indexing either half --
    # A well-formed-but-wrong-shape document (a bare [], a bare 42, a bare
    # string, an object with no recognised halves) trips no parse error and no
    # per-entry rule; without this guard, indexing document["memory"] would
    # raise an uncaught KeyError / TypeError. The guard closes that gap.
    if not _is_unified_shape(document):
        issues.append(
            _read_issue(
                MF_BAD_STRUCTURE,
                ValidationSeverity.ERROR,
                "the unified change-set file is well-formed JSON but is not a "
                "unified change-set document (no recognised parameter / "
                "memory halves) — the load produced an empty change-set",
            )
        )
        return empty, issues

    # --- Version check (LLR-008.2) — info-level, parsing continues ---------
    version = document.get("version")
    if version != UNIFIED_FORMAT_VERSION:
        issues.append(
            _read_issue(
                MF_VERSION_UNKNOWN,
                ValidationSeverity.INFO,
                f"the unified change-set file declares version {version!r}, "
                f"not the recognised {UNIFIED_FORMAT_VERSION!r} — the file "
                f"was read anyway",
            )
        )

    # --- Reconstruct both halves (LLR-006.1, LLR-006.5, LLR-008.1) ---------
    changeset = UnifiedChangeSet()
    _decode_parameter_half(document.get("parameters"), changeset, issues)
    _decode_memory_half(document.get("memory"), changeset, issues)
    return changeset, issues


def _is_unified_shape(document: object) -> bool:
    """
    Summary:
        Report whether a parsed JSON document has the top-level shape of a
        unified change-set — a JSON object carrying a ``parameters`` and a
        ``memory`` half (LLR-006.2).

    Args:
        document (object): The value ``json.load`` produced — any JSON type.

    Returns:
        bool: ``True`` only when ``document`` is a ``dict`` carrying both a
        ``parameters`` key and a ``memory`` key; ``False`` for a bare list, a
        bare scalar, a bare string, or an object missing either half. This is
        the guard that lets the reader index the two halves without an
        uncaught ``KeyError``.

    Data Flow:
        - Tests the type and the presence of both half keys; the per-half
          decoders tolerate a non-list value under either key, so only key
          *presence* is required here.

    Dependencies:
        Used by:
            - read_unified
    """
    return (
        isinstance(document, dict)
        and "parameters" in document
        and "memory" in document
    )


def _decode_parameter_half(
    raw: object,
    changeset: UnifiedChangeSet,
    issues: list[ValidationIssue],
) -> None:
    """
    Summary:
        Reconstruct the parameter ``ChangeList`` half of a unified change-set
        from the parsed ``parameters`` value, collect-don't-abort (LLR-006.1).

    Args:
        raw (object): The parsed value under the document's ``parameters`` key
            — expected to be a JSON array of entry objects. A non-list value or
            a non-object element is skipped with one ``MF-BAD-STRUCTURE``
            issue rather than crashing the load.
        changeset (UnifiedChangeSet): The container being populated — its
            ``parameters`` half is mutated in place.
        issues (list[ValidationIssue]): The shared issue list; findings are
            appended.

    Returns:
        None: ``changeset.parameters`` is populated as a side effect.

    Data Flow:
        - A non-list ``raw`` → one ``MF-BAD-STRUCTURE`` issue, no entries.
        - For each element: a non-object element → one ``MF-BAD-STRUCTURE``
          issue, the element is skipped; otherwise the four
          ``parameter_name`` / ``array_index`` / ``value`` / ``status`` fields
          are read and added via ``ChangeList.add``. The persisted ``status``
          is decoded leniently — an unrecognised token falls back to
          ``UNRESOLVED_NO_A2L`` (the reader does not trust the persisted
          status; it is re-derived at export time — A-7).

    Dependencies:
        Uses:
            - _coerce_resolution_status
        Used by:
            - read_unified
    """
    if not isinstance(raw, list):
        issues.append(
            _read_issue(
                MF_BAD_STRUCTURE,
                ValidationSeverity.ERROR,
                "the unified change-set file's parameter half is not a JSON "
                "array — the parameter half was read as empty",
            )
        )
        return
    for index, element in enumerate(raw):
        if not isinstance(element, dict):
            issues.append(
                _read_issue(
                    MF_BAD_STRUCTURE,
                    ValidationSeverity.ERROR,
                    f"parameter-half entry {index} is not a JSON object — the "
                    f"entry was skipped",
                )
            )
            continue
        name = element.get("parameter_name")
        if not isinstance(name, str):
            issues.append(
                _read_issue(
                    MF_BAD_STRUCTURE,
                    ValidationSeverity.ERROR,
                    f"parameter-half entry {index} has no string "
                    f"'parameter_name' field — the entry was skipped",
                )
            )
            continue
        array_index = element.get("array_index")
        if array_index is not None and not isinstance(array_index, int):
            array_index = None
        changeset.parameters.add(
            name,
            array_index,
            element.get("value"),
            _coerce_resolution_status(element.get("status")),
        )


def _coerce_resolution_status(token: object) -> ResolutionStatus:
    """
    Summary:
        Decode a persisted resolution-status token to a ``ResolutionStatus``,
        falling back to ``UNRESOLVED_NO_A2L`` for an unrecognised value.

    Args:
        token (object): The value stored under a parameter entry's ``status``
            field — expected to be one of the ``ResolutionStatus`` string
            tokens.

    Returns:
        ResolutionStatus: The matching member, or ``UNRESOLVED_NO_A2L`` when
        the token is missing or unrecognised. The reader does not trust the
        persisted status (it is re-derived against the loaded A2L at
        export time — A-7), so an unknown token is tolerated, never an error.

    Dependencies:
        Used by:
            - _decode_parameter_half
    """
    try:
        return ResolutionStatus(token)
    except ValueError:
        return ResolutionStatus.UNRESOLVED_NO_A2L


def _decode_memory_half(
    raw: object,
    changeset: UnifiedChangeSet,
    issues: list[ValidationIssue],
) -> None:
    """
    Summary:
        Reconstruct the ``MemoryChangeList`` half of a unified change-set from
        the parsed ``memory`` value, applying the per-entry ``MF-*`` rule set
        and the decoded-structure ceiling, collect-don't-abort (LLR-006.1,
        LLR-006.5, LLR-008.1).

    Args:
        raw (object): The parsed value under the document's ``memory`` key —
            expected to be a JSON array of entry objects (LLR-005.3). A
            non-list value is reported with one ``MF-BAD-STRUCTURE`` issue.
        changeset (UnifiedChangeSet): The container being populated — its
            ``memory`` half is mutated in place.
        issues (list[ValidationIssue]): The shared issue list; findings are
            appended.

    Returns:
        None: ``changeset.memory`` is populated as a side effect.

    Data Flow:
        - A non-list ``raw`` → one ``MF-BAD-STRUCTURE`` issue, no entries.
        - The entry-count ceiling (LLR-006.5): every element at or past index
          :data:`MF_ENTRY_COUNT_CEILING` is dropped with **one**
          ``MF-ENTRY-LIMIT`` issue for the whole overflow — only the in-ceiling
          prefix is reconstructed.
        - Per in-ceiling element, in order: a non-object element →
          ``MF-BAD-STRUCTURE``, skipped; a missing/invalid ``address`` →
          ``MF-NO-ADDRESS``, skipped; an empty ``new_bytes`` run →
          ``MF-EMPTY-BYTES``, skipped; a run longer than
          :data:`MF_RUN_LENGTH_CEILING` → ``MF-ENTRY-LIMIT``, dropped; a byte
          outside 0-255 → ``MF-BYTE-RANGE``, the entry is skipped. A clean
          element is added via ``MemoryChangeList.add``.

    Dependencies:
        Uses:
            - _decode_memory_entry
        Used by:
            - read_unified
    """
    if not isinstance(raw, list):
        issues.append(
            _read_issue(
                MF_BAD_STRUCTURE,
                ValidationSeverity.ERROR,
                "the unified change-set file's memory-field half is not a "
                "JSON array — the memory-field half was read as empty",
            )
        )
        return

    # Entry-count ceiling (LLR-006.5): one MF-ENTRY-LIMIT issue for the whole
    # overflow, only the in-ceiling prefix is reconstructed.
    in_ceiling = raw
    if len(raw) > MF_ENTRY_COUNT_CEILING:
        issues.append(
            _read_issue(
                MF_ENTRY_LIMIT,
                ValidationSeverity.ERROR,
                f"the unified change-set file declares {len(raw)} memory-field "
                f"entries, over the {MF_ENTRY_COUNT_CEILING}-entry ceiling — "
                f"the {len(raw) - MF_ENTRY_COUNT_CEILING} entries past the "
                f"ceiling were dropped",
            )
        )
        in_ceiling = raw[:MF_ENTRY_COUNT_CEILING]

    for index, element in enumerate(in_ceiling):
        _decode_memory_entry(index, element, changeset, issues)


def _decode_memory_entry(
    index: int,
    element: object,
    changeset: UnifiedChangeSet,
    issues: list[ValidationIssue],
) -> None:
    """
    Summary:
        Validate and reconstruct one memory-field entry from a parsed array
        element, applying the per-entry ``MF-*`` rule set collect-don't-abort
        (LLR-006.5, LLR-008.1).

    Args:
        index (int): The element's position in the memory-field array — used
            in a finding message when the element carries no usable
            ``address``.
        element (object): The parsed array element — expected to be a JSON
            object carrying ``address`` (an integer field, LLR-005.3) and
            ``new_bytes`` (an integer array).
        changeset (UnifiedChangeSet): The container being populated.
        issues (list[ValidationIssue]): The shared issue list.

    Returns:
        None: A clean entry is added to ``changeset.memory``; a rule violation
        appends one issue and drops the entry.

    Data Flow:
        - ``MF-BAD-STRUCTURE`` — the element is not a JSON object.
        - ``MF-NO-ADDRESS`` — no ``address`` field, a non-integer ``address``,
          or a negative ``address`` (LLR-008.1).
        - ``MF-EMPTY-BYTES`` — ``new_bytes`` is absent, not a list, or an empty
          run (LLR-008.1).
        - ``MF-ENTRY-LIMIT`` — the ``new_bytes`` run is longer than
          :data:`MF_RUN_LENGTH_CEILING` (LLR-006.5).
        - ``MF-BYTE-RANGE`` — a ``new_bytes`` element is not an integer or is
          outside 0-255 (LLR-008.1).
        A clean element reaches ``MemoryChangeList.add``; its persisted
        ``status`` is intentionally **not** trusted — the entry is added with
        the default ``UNVALIDATED_NO_IMAGE`` and the real status is re-derived
        against the loaded image (A-7).

    Dependencies:
        Uses:
            - _read_issue
        Used by:
            - _decode_memory_half
    """
    if not isinstance(element, dict):
        issues.append(
            _read_issue(
                MF_BAD_STRUCTURE,
                ValidationSeverity.ERROR,
                f"memory-field entry {index} is not a JSON object — the entry "
                f"was skipped",
            )
        )
        return

    # MF-NO-ADDRESS — bool is a subclass of int; reject it explicitly so a
    # JSON `true` is never read as address 1.
    address = element.get("address")
    if (
        not isinstance(address, int)
        or isinstance(address, bool)
        or address < 0
    ):
        issues.append(
            _read_issue(
                MF_NO_ADDRESS,
                ValidationSeverity.ERROR,
                f"memory-field entry {index} has no valid non-negative integer "
                f"'address' field — the entry was skipped",
            )
        )
        return

    # MF-EMPTY-BYTES — absent, not a list, or an empty run.
    new_bytes = element.get("new_bytes")
    if not isinstance(new_bytes, list) or len(new_bytes) == 0:
        issues.append(
            _read_issue(
                MF_EMPTY_BYTES,
                ValidationSeverity.ERROR,
                f"the memory-field entry at address {address} has an empty or "
                f"missing 'new_bytes' run — the entry was skipped",
                address=address,
            )
        )
        return

    # MF-ENTRY-LIMIT — single-run length ceiling (LLR-006.5).
    if len(new_bytes) > MF_RUN_LENGTH_CEILING:
        issues.append(
            _read_issue(
                MF_ENTRY_LIMIT,
                ValidationSeverity.ERROR,
                f"the memory-field entry at address {address} declares a "
                f"new_bytes run of {len(new_bytes)} bytes, over the "
                f"{MF_RUN_LENGTH_CEILING}-byte run-length ceiling — the entry "
                f"was dropped",
                address=address,
            )
        )
        return

    # MF-BYTE-RANGE — every element must be an integer in 0-255.
    for byte_value in new_bytes:
        if (
            not isinstance(byte_value, int)
            or isinstance(byte_value, bool)
            or byte_value < 0
            or byte_value > 255
        ):
            issues.append(
                _read_issue(
                    MF_BYTE_RANGE,
                    ValidationSeverity.ERROR,
                    f"the memory-field entry at address {address} has a "
                    f"new_bytes value outside the range 0-255 — the entry was "
                    f"skipped",
                    address=address,
                )
            )
            return

    # Clean entry — add it. The persisted status is not trusted (A-7); the
    # entry takes the default UNVALIDATED_NO_IMAGE status.
    changeset.memory.add(address, new_bytes, MemoryStatus.UNVALIDATED_NO_IMAGE)
