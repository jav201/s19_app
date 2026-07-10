"""
v2 change-file JSON reader/writer — s19_app batch-07, increment E1.

This module is the on-disk side of the v2 hex-first change system
(`s19app-changeset`, HLR-001 / LLR-001.1..001.8 minus the E2-deferred 001.6):
it reads a v2 JSON document into a :class:`ChangeDocument` collecting every
finding as a ``ValidationIssue`` (collect-don't-abort — the reader always
returns a document and never raises on a data-quality fault), and it writes a
canonical v2 document into the work area through the staged-containment
pattern of ``cdfx/unified_io.py::write_unified_to_workarea``.

**Wire grammar (LLR-001.2 / §6.2 C-1 — strict, file-format-defining):**

- ``address`` — a JSON string matching ``^0x[0-9A-Fa-f]+$`` or a non-negative
  JSON integer; the canonical writer always emits the ``0x`` string form.
- ``bytes`` — whitespace-separated two-hex-digit tokens ONLY (``"DE AD BE
  EF"``). Commas, decimals, and ``0x`` prefixes are the permissive
  **TUI-input grammar** of ``services/cdfx_service.py::parse_new_bytes`` and
  are NOT valid in a file (grammar split, F-Q-04).
- ``value`` — under ``value_mode="text"`` a literal JSON string encoded with
  the document ``encoding``; under ``value_mode="codes"`` a JSON array of
  code points joined and encoded with the document ``encoding``.

**Issue-code policy (§6.2 C-5):** the structural ``MF-*`` spellings of
``cdfx/unified_io.py`` are preserved as local constants with identical string
values (defined here, not imported — increment E3b deletes ``unified_io.py``);
new v2 rules use the NEW ``CHG-*`` family. ``CHG-COLLISION`` is defined in
``changes/validate.py`` (its emitting home) and re-exported here.

**v1 hard break (LLR-001.8 / C-3):** a batch-04 v1 document — recognised by
its ``"s19app-unified-changeset"`` format token or by its
``parameters``/``memory`` top-level shape — yields exactly one ERROR
``CHG-V1-FORMAT`` and zero entries; v1 detection runs BEFORE generic format
validation and suppresses ``CHG-FORMAT`` (F-A-03). No read-compat shim exists.

**Faulted envelope (LLR-001.3 / F-A-16):** when any metadata-level ERROR is
recorded (``CHG-FORMAT``, ``CHG-V1-FORMAT``, ``CHG-KIND-UNKNOWN``,
``CHG-ENCODING-UNKNOWN``, ``CHG-VALUE-MODE-UNKNOWN``, or a structural
``MF-BAD-STRUCTURE`` envelope fault) the returned document carries zero
entries — entry content is not interpreted under a faulted envelope.

Per constraint C-9, issue messages name addresses, indices, and counts —
never raw byte or value content. No Textual import anywhere in this module.
"""

from __future__ import annotations

import codecs
import json
import re
from pathlib import Path
from typing import Callable, Optional, Union

from ...validation.model import ValidationIssue, ValidationSeverity
from ..workspace import (
    DEFAULT_COPY_SIZE_CAP_BYTES,
    WORKAREA_PATCHES,
    WORKAREA_TEMP,
    WorkareaContainmentError,
    copy_into_workarea,
    ensure_workarea,
    resolve_input_path,
)
from .model import CHANGES_ARTIFACT, ChangeDocument, ChangeEntry
from .validate import CHG_COLLISION, collision_issues

__all__ = [
    "FORMAT_ID",
    "FORMAT_VERSION",
    "V1_FORMAT_ID",
    "DOCUMENT_KINDS",
    "VALUE_MODES",
    "DEFAULT_CHANGE_FILE_NAME",
    "DUMMY_CHANGESET_TEXT",
    "READ_SIZE_CAP_BYTES",
    "MF_ENTRY_COUNT_CEILING",
    "MF_RUN_LENGTH_CEILING",
    "MF_JSON_PARSE",
    "MF_BAD_STRUCTURE",
    "CHG_DECL_STRUCTURE",
    "MF_SIZE_CAP",
    "MF_PATH_UNRESOLVED",
    "MF_ENTRY_LIMIT",
    "MF_WRITE_CONTAINMENT",
    "CHG_FORMAT",
    "CHG_KIND_UNKNOWN",
    "CHG_VALUE_MODE_UNKNOWN",
    "CHG_ENCODING_UNKNOWN",
    "CHG_ADDRESS_SYNTAX",
    "CHG_BYTES_SYNTAX",
    "CHG_VALUE_EMPTY",
    "CHG_ENCODE_FAIL",
    "CHG_V1_FORMAT",
    "CHG_COLLISION",
    "parse_change_document",
    "read_change_document",
    "serialize_change_document",
    "write_change_document",
    "emit_s19_from_mem_map",
    "emit_intel_hex_from_mem_map",
    "HEX_DATA_BYTES_PER_RECORD",
]

# ---------------------------------------------------------------------------
# Format contract — the self-describing tokens of the v2 JSON (LLR-001.1).
# ---------------------------------------------------------------------------

#: The v2 format-identifier field value (LLR-001.1 — NEW, replacing the v1
#: ``UNIFIED_FORMAT_ID``).
FORMAT_ID = "s19app-changeset"

#: The v2 format-version field value (LLR-001.1).
FORMAT_VERSION = "2.0"

#: The RETIRED v1 format token (``unified_io.py:99`` spelling) — recognised
#: only to reject it with ``CHG-V1-FORMAT`` (LLR-001.8). Defined locally; E3b
#: deletes the v1 module.
V1_FORMAT_ID = "s19app-unified-changeset"

#: The recognised document discriminators (LLR-001.1): ``"change"`` declares
#: modifications, ``"check"`` declares expected values (HLR-004, one schema
#: family).
DOCUMENT_KINDS = frozenset({"change", "check"})

#: The recognised string-value interpretation modes (LLR-001.1/.2).
VALUE_MODES = frozenset({"text", "codes"})

#: The default change-file name a save uses when the caller passes none.
DEFAULT_CHANGE_FILE_NAME = "changes.json"

#: A syntactically valid ``s19app-changeset`` (kind=change) carrying FAKE
#: values only, pre-loaded into the Patch Editor paste field as a format
#: reference (LLR-014.1). Authored WITHOUT a trailing newline so a Textual
#: ``TextArea`` round-trips it on mount (F-Q-07). Never under ``examples/`` —
#: it is a module constant, not a committed file (JSON-never-in-repo, F-S-04).
DUMMY_CHANGESET_TEXT = (
    '{\n'
    f'  "format": "{FORMAT_ID}",\n'
    f'  "version": "{FORMAT_VERSION}",\n'
    '  "kind": "change",\n'
    '  "encoding": "utf-8",\n'
    '  "value_mode": "text",\n'
    '  "entries": [\n'
    '    {"type": "bytes", "address": "0x00000000", "bytes": "DE AD BE EF"},\n'
    '    {"type": "string", "address": "0x00000010", "value": "ABC"}\n'
    '  ]\n'
    '}'
)

# ---------------------------------------------------------------------------
# MF-* structural rule codes — spellings preserved from the v1
# ``cdfx/unified_io.py`` constants (§6.2 C-5: constants migrate; defined
# locally with identical string values, never imported — E3b deletes the v1
# module). Issue codes are public contract.
# ---------------------------------------------------------------------------

#: Read-path: the file is not well-formed JSON, or its nesting overflowed the
#: stdlib parser (a ``RecursionError``).
MF_JSON_PARSE = "MF-JSON-PARSE"
#: Read-path: well-formed JSON whose structure is not a v2 document envelope
#: (non-object top level, non-array ``entries``, non-object entry element).
MF_BAD_STRUCTURE = "MF-BAD-STRUCTURE"
#: Read-path: the on-disk file exceeds the pre-parse size cap.
MF_SIZE_CAP = "MF-SIZE-CAP"
#: Read-path: a user-supplied input path could not be resolved or opened.
MF_PATH_UNRESOLVED = "MF-PATH-UNRESOLVED"
#: Read-path: the decoded structure breaches the entry-count ceiling, a
#: single entry's run-length ceiling (on **encoded** length), or the
#: pre-encode raw-length guard (F-S-04).
MF_ENTRY_LIMIT = "MF-ENTRY-LIMIT"
#: Write-path: the write target failed work-area containment validation.
MF_WRITE_CONTAINMENT = "MF-WRITE-CONTAINMENT"

# ---------------------------------------------------------------------------
# CHG-* v2 rule codes (LLR-001.3/.4/.8 — NEW family; public contract).
# CHG-COLLISION lives in ``changes/validate.py`` and is re-exported above.
# ---------------------------------------------------------------------------

#: Metadata: unrecognised ``format`` token (suppressed for a v1 document —
#: F-A-03 precedence).
CHG_FORMAT = "CHG-FORMAT"
#: Metadata: ``kind`` is not one of :data:`DOCUMENT_KINDS`.
CHG_KIND_UNKNOWN = "CHG-KIND-UNKNOWN"
#: Metadata: ``value_mode`` is not one of :data:`VALUE_MODES`.
CHG_VALUE_MODE_UNKNOWN = "CHG-VALUE-MODE-UNKNOWN"
#: Metadata: ``encoding`` does not resolve to a **text** codec —
#: ``codecs.lookup(encoding)._is_text_encoding`` must be truthy; lookup
#: success alone is NOT sufficient (F-S-02: ``zlib_codec`` resolves but is
#: not a text codec).
CHG_ENCODING_UNKNOWN = "CHG-ENCODING-UNKNOWN"
#: Entry: the DECLARATION itself is structurally junk — not a JSON object,
#: or an unknown ``type`` — and was skipped (skip-and-continue). Split out
#: of the envelope-level :data:`MF_BAD_STRUCTURE` in batch-33 (R-B02,
#: Phase-2 F1) so the check engine classifies it entry-scoped/non-blocking:
#: one junk declaration must not block checking the document's healthy
#: entries (the envelope variant stays run-blocking).
CHG_DECL_STRUCTURE = "CHG-DECL-STRUCTURE"
#: Entry: ``address`` is not a ``^0x[0-9A-Fa-f]+$`` string nor a non-negative
#: integer (the strict wire grammar, LLR-001.2).
CHG_ADDRESS_SYNTAX = "CHG-ADDRESS-SYNTAX"
#: Entry: ``bytes`` is not whitespace-separated two-hex-digit tokens only.
CHG_BYTES_SYNTAX = "CHG-BYTES-SYNTAX"
#: Entry: ``value`` / ``bytes`` is missing, empty, or of an unusable type.
CHG_VALUE_EMPTY = "CHG-VALUE-EMPTY"
#: Entry: encoding the declared value under the document ``encoding`` failed
#: (``UnicodeEncodeError`` / ``ValueError`` / ``TypeError`` / ``LookupError``
#: / ``OverflowError`` — broadened coverage, F-S-02).
CHG_ENCODE_FAIL = "CHG-ENCODE-FAIL"
#: Document: a retired batch-04 v1 unified document — hard break, no shim
#: (LLR-001.8 / C-3).
CHG_V1_FORMAT = "CHG-V1-FORMAT"

# ---------------------------------------------------------------------------
# Read-path resource bounds (LLR-001.7) — pinned, documented limits. Values
# preserved from ``unified_io.py:157,168,175``; referenced as module globals
# at call time so the test seam can lower them without 100k-entry fixtures.
# ---------------------------------------------------------------------------

#: Read-path on-disk size cap, enforced BEFORE ``json.load`` — the shared
#: ``workspace.DEFAULT_COPY_SIZE_CAP_BYTES`` (256 MB) so one consistent size
#: limit governs every file the app reads.
READ_SIZE_CAP_BYTES = DEFAULT_COPY_SIZE_CAP_BYTES

#: Decoded-structure ceiling — entry count. Entries past the ceiling are
#: dropped with one ``MF-ENTRY-LIMIT`` issue; the in-ceiling prefix is kept.
MF_ENTRY_COUNT_CEILING = 100_000

#: Decoded-structure ceiling — single entry's byte-run length, enforced on
#: the **encoded** byte length (LLR-001.7) AND, pre-encode, on the raw
#: ``value`` character count / ``codes`` array length, so an oversized
#: declaration can never force an unbounded encode (F-S-04).
MF_RUN_LENGTH_CEILING = 1_048_576

#: The strict wire-grammar address pattern (LLR-001.2).
_ADDRESS_RE = re.compile(r"^0x[0-9A-Fa-f]+$")

#: The strict wire-grammar ``bytes`` token pattern: exactly two hex digits.
_BYTES_TOKEN_RE = re.compile(r"^[0-9A-Fa-f]{2}$")

#: The ``copy_into_workarea`` seam type — the write path takes the helper as
#: an injectable callable so a test can stub the containment-checked
#: placement without OS symlink privilege. ``None`` (the default) resolves to
#: the module-level ``copy_into_workarea`` at call time.
CopyIntoWorkarea = Callable[[Path, Path], Path]

#: The size-probe seam type — the read path takes the on-disk size
#: measurement as an injectable callable so a test can report an over-cap
#: byte size without manufacturing a real 256 MB file. ``None`` (the default)
#: resolves to a real ``Path.stat().st_size`` measurement at call time.
SizeProbe = Callable[[Path], int]


def _issue(
    code: str,
    message: str,
    severity: ValidationSeverity = ValidationSeverity.ERROR,
    address: Optional[int] = None,
) -> ValidationIssue:
    """
    Summary:
        Build one v2 change-file ``ValidationIssue`` with the
        :data:`CHANGES_ARTIFACT` tag.

    Args:
        code (str): The ``MF-*`` / ``CHG-*`` rule code.
        message (str): The human-readable finding. Names addresses, indices,
            and counts — never raw byte or value content (C-9).
        severity (ValidationSeverity): The finding severity — ``ERROR`` for
            every read-path rule; the write path's containment finding is
            ``WARNING`` (the ``unified_io.py`` convention, preserved).
        address (Optional[int]): The entry address the finding concerns, when
            applicable.

    Returns:
        ValidationIssue: The finding, tagged ``artifact=CHANGES_ARTIFACT``.

    Dependencies:
        Used by:
            - read_change_document and its private rule helpers
            - write_change_document
    """
    return ValidationIssue(
        code=code,
        severity=severity,
        message=message,
        artifact=CHANGES_ARTIFACT,
        address=address,
    )


# ---------------------------------------------------------------------------
# Read path (LLR-001.1..001.5, 001.7, 001.8).
# ---------------------------------------------------------------------------


def read_change_document(
    path_text: str,
    base_dir: Path,
    size_probe: Optional[SizeProbe] = None,
) -> ChangeDocument:
    """
    Summary:
        Read a v2 change/check JSON file into a :class:`ChangeDocument`,
        collecting every structural, metadata, per-entry, collision, and
        resource-ceiling finding as a ``ValidationIssue`` without ever
        raising (HLR-001 statement 3; LLR-001.1..001.5/.7/.8).

    Args:
        path_text (str): The user-supplied change-file path, resolved through
            ``workspace.resolve_input_path`` (cwd + repo-root walk) before the
            file is opened — an unresolvable path is one
            ``MF-PATH-UNRESOLVED`` issue and no file is opened (LLR-001.7).
        base_dir (Path): The app base directory ``resolve_input_path``
            resolves the path against.
        size_probe (Optional[SizeProbe]): The on-disk byte-size measurement
            seam. ``None`` (the default) resolves to a real
            ``Path.stat().st_size`` at call time; injectable so a test can
            report an over-cap size without a real 256 MB file.

    Returns:
        ChangeDocument: The parsed document. ``entries`` is **always empty**
        when the file could not be resolved/parsed, when it is a v1 document
        (``CHG-V1-FORMAT`` hard break), or when any metadata-level ERROR was
        recorded (faulted envelope, F-A-16); it is **populated, possibly
        partially** when only per-entry rules or ceilings dropped entries.
        ``issues`` carries every collected finding, including the LLR-001.5
        intra-document collision findings. The reader never raises on a
        data-quality fault.

    Raises:
        None: Every failure mode is a collected ``ValidationIssue``
            (collect-don't-abort). The only paths to a raise are programming
            errors outside this contract.

    Data Flow:
        - Resolve ``path_text`` via ``resolve_input_path``; unresolvable →
          one ``MF-PATH-UNRESOLVED``, empty document.
        - Probe the on-disk size; over :data:`READ_SIZE_CAP_BYTES` → one
          ``MF-SIZE-CAP``, empty document — ``json.load`` is never reached
          (the size check precedes parsing, LLR-001.7).
        - Parse with stdlib ``json`` catching ``JSONDecodeError`` AND
          ``RecursionError`` AND ``UnicodeDecodeError`` → ``MF-JSON-PARSE``.
        - Non-object top level → ``MF-BAD-STRUCTURE``, empty document.
        - **v1 detection BEFORE generic format validation** (F-A-03): the v1
          format token or the v1 ``parameters``/``memory`` shape → exactly
          one ``CHG-V1-FORMAT``, zero entries, ``CHG-FORMAT`` suppressed.
        - Metadata validation (LLR-001.3): unrecognised ``format`` / ``kind``
          / ``value_mode``, a non-text ``encoding``
          (``codecs.lookup(...)._is_text_encoding`` falsy — F-S-02), or a
          non-array ``entries`` each record one ERROR; any metadata ERROR →
          zero entries (faulted envelope).
        - Entry parsing (LLR-001.2/.4/.7): entry-count ceiling, strict wire
          grammar, pre-encode raw-length guard, broadened encode-failure
          coverage, encoded-length ceiling — per entry, skip-and-continue.
        - Collision check (LLR-001.5): ``changes.validate.collision_issues``
          over the parsed entries; findings appended.

    Dependencies:
        Uses:
            - resolve_input_path
            - json.load
            - _is_v1_document / _document_metadata / _metadata_issues
            - _parse_entries
            - collision_issues
            - _issue
        Used by:
            - The E2 apply engine / E3a change service (later increments)
            - tests/test_changes_schema.py, tests/test_changes_collision.py

    Example:
        >>> doc = read_change_document("changes.json", base_dir)  # doctest: +SKIP
    """
    issues: list[ValidationIssue] = []

    # --- Path resolution (LLR-001.7) ----------------------------------------
    resolved = resolve_input_path(Path(path_text), base_dir)
    if resolved is None:
        issues.append(
            _issue(
                MF_PATH_UNRESOLVED,
                f"the change-file path could not be resolved — no file was "
                f"opened: {path_text!r}",
            )
        )
        return ChangeDocument(
            *_document_metadata(None),
            entries=[],
            issues=issues,
            source_path=None,
        )

    # --- Pre-parse size cap (LLR-001.7) — precedes the read -----------------
    probe: SizeProbe = (
        (lambda candidate: candidate.stat().st_size)
        if size_probe is None
        else size_probe
    )
    size_bytes = probe(resolved)
    if size_bytes > READ_SIZE_CAP_BYTES:
        issues.append(
            _issue(
                MF_SIZE_CAP,
                f"the change file is {size_bytes} bytes, over the "
                f"{READ_SIZE_CAP_BYTES}-byte read cap — the file was not "
                f"loaded into memory",
            )
        )
        return ChangeDocument(
            *_document_metadata(None),
            entries=[],
            issues=issues,
            source_path=resolved,
        )

    # --- Read the file (LLR-001.7) — OSError is the only path-side fault ----
    try:
        with resolved.open("rb") as handle:
            payload = handle.read()
    except OSError as exc:
        issues.append(
            _issue(
                MF_PATH_UNRESOLVED,
                f"the change file could not be opened — no document was "
                f"loaded: {type(exc).__name__}",
            )
        )
        return ChangeDocument(
            *_document_metadata(None),
            entries=[],
            issues=issues,
            source_path=resolved,
        )

    # --- Delegate the json-decode + interpretation to the shared seam -------
    document = parse_change_document(payload)
    document.source_path = resolved
    return document


def parse_change_document(text: str) -> ChangeDocument:
    """
    Summary:
        Parse an in-memory change/check document (the raw JSON text of an
        ``s19app-changeset``) into a :class:`ChangeDocument`, collecting every
        structural, metadata, per-entry, collision, and resource-ceiling
        finding as a ``ValidationIssue`` without ever raising. This is the
        string seam shared by the file reader (``read_change_document``
        delegates here after resolve + size-cap + read) and the Patch Editor
        paste field (LLR-014.2).

    Args:
        text (str): The raw JSON document text. ``bytes`` is also accepted
            (``json.loads`` decodes it) so the file reader can hand its
            on-disk payload straight through; an invalid UTF-8 byte payload is
            one ``MF-JSON-PARSE`` finding (collect-don't-abort).

    Returns:
        ChangeDocument: The parsed document with ``source_path=None`` (a string
        seam has no on-disk path — F-A-06; ``read_change_document`` re-stamps
        the resolved path on its returned document). ``entries`` is **always
        empty** when the text is not well-formed JSON, when its top level is
        not an object, when it is a v1 document (``CHG-V1-FORMAT`` hard break),
        or when any metadata-level ERROR was recorded; it is **populated,
        possibly partially** when only per-entry rules or ceilings dropped
        entries. ``issues`` carries every collected finding.

    Raises:
        None: Every failure mode is a collected ``ValidationIssue``
            (collect-don't-abort). A malformed string yields a document
            carrying ``MF-JSON-PARSE``, not an exception.

    Data Flow:
        - Decode with stdlib ``json.loads`` catching ``JSONDecodeError`` AND
          ``RecursionError`` AND ``UnicodeDecodeError`` → ``MF-JSON-PARSE``
          (the same three-exception catch that previously wrapped
          ``json.load(handle)`` — F-A-01).
        - Non-object top level → ``MF-BAD-STRUCTURE``, empty document.
        - **v1 detection BEFORE generic format validation** (F-A-03): the v1
          format token or the v1 ``parameters``/``memory`` shape → exactly
          one ``CHG-V1-FORMAT``, zero entries, ``CHG-FORMAT`` suppressed.
        - Metadata validation (LLR-001.3): any metadata ERROR → zero entries
          (faulted envelope).
        - Entry parsing (LLR-001.2/.4/.7) then the collision check
          (LLR-001.5); findings appended.

    Dependencies:
        Uses:
            - json.loads
            - _is_v1_document / _document_metadata / _metadata_issues
            - _parse_entries
            - collision_issues
            - _issue
        Used by:
            - read_change_document (file seam, delegates here)
            - ChangeService.load_text (paste seam, LLR-014.2)
            - tests/test_changes_schema.py

    Example:
        >>> doc = parse_change_document(DUMMY_CHANGESET_TEXT)
        >>> doc.kind
        'change'
    """
    issues: list[ValidationIssue] = []

    def _empty(found: Optional[dict] = None) -> ChangeDocument:
        fmt, version, kind, encoding, value_mode = _document_metadata(found)
        return ChangeDocument(
            format=fmt,
            version=version,
            kind=kind,
            encoding=encoding,
            value_mode=value_mode,
            entries=[],
            issues=issues,
            source_path=None,
        )

    # --- Parse — catch JSONDecodeError AND RecursionError AND UnicodeDecode -
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, RecursionError, UnicodeDecodeError) as exc:
        issues.append(
            _issue(
                MF_JSON_PARSE,
                f"the change file is not well-formed JSON — the load "
                f"produced an empty document: {type(exc).__name__}",
            )
        )
        return _empty()

    # --- Top-level shape guard ----------------------------------------------
    if not isinstance(document, dict):
        issues.append(
            _issue(
                MF_BAD_STRUCTURE,
                "the change file is well-formed JSON but its top level is "
                "not a JSON object — the load produced an empty document",
            )
        )
        return _empty()

    # --- v1 hard break (LLR-001.8) — PRECEDES format validation (F-A-03) ----
    if _is_v1_document(document):
        issues.append(
            _issue(
                CHG_V1_FORMAT,
                f"this is a retired v1 unified change-set document — the v2 "
                f"format is {FORMAT_ID!r} version {FORMAT_VERSION!r}; v1 "
                f"files are not supported and are not migrated",
            )
        )
        return _empty(document)

    # --- Metadata validation (LLR-001.3) — collect-don't-abort --------------
    metadata_faulted = _metadata_issues(document, issues)

    # Faulted envelope (F-A-16): zero entries under any metadata-level ERROR.
    if metadata_faulted:
        return _empty(document)

    fmt, version, kind, encoding, value_mode = _document_metadata(document)
    entries = _parse_entries(document["entries"], encoding, value_mode, issues)

    # --- Intra-document collision check (LLR-001.5) --------------------------
    issues.extend(collision_issues(entries))

    return ChangeDocument(
        format=fmt,
        version=version,
        kind=kind,
        encoding=encoding,
        value_mode=value_mode,
        entries=entries,
        issues=issues,
        source_path=None,
    )


def _document_metadata(
    document: Optional[dict],
) -> tuple[str, str, str, str, str]:
    """
    Summary:
        Extract the five LLR-001.1 metadata fields from a parsed document as
        strings, coercing absent or non-string values to ``""``.

    Args:
        document (Optional[dict]): The parsed top-level object, or ``None``
            when the file never parsed (the empty-document paths).

    Returns:
        tuple[str, str, str, str, str]: ``(format, version, kind, encoding,
        value_mode)`` — the as-found string values, so a faulted document
        still reports what was declared; ``""`` for anything absent or
        non-string.

    Data Flow:
        - Reads the five keys; a non-``str`` value becomes ``""`` so the
          ``ChangeDocument`` fields stay ``str``-typed.

    Dependencies:
        Used by:
            - read_change_document
    """
    if not isinstance(document, dict):
        document = {}

    def _text(key: str) -> str:
        value = document.get(key)
        return value if isinstance(value, str) else ""

    return (
        _text("format"),
        _text("version"),
        _text("kind"),
        _text("encoding"),
        _text("value_mode"),
    )


def _is_v1_document(document: dict) -> bool:
    """
    Summary:
        Report whether a parsed JSON object is a retired batch-04 v1 unified
        change-set document (LLR-001.8).

    Args:
        document (dict): The parsed top-level JSON object.

    Returns:
        bool: ``True`` when the document declares the v1 format token
        (:data:`V1_FORMAT_ID`) or matches the v1 top-level shape — both a
        ``parameters`` and a ``memory`` key (the ``_is_unified_shape``
        predicate of ``unified_io.py:752-782``, spelled locally).

    Data Flow:
        - Tests the format token first, then the two-half shape; either match
          triggers the ``CHG-V1-FORMAT`` hard break in the caller.

    Dependencies:
        Used by:
            - read_change_document
    """
    if document.get("format") == V1_FORMAT_ID:
        return True
    return "parameters" in document and "memory" in document


def _metadata_issues(
    document: dict,
    issues: list[ValidationIssue],
) -> bool:
    """
    Summary:
        Validate the document envelope — ``format``, ``kind``, ``encoding``,
        ``value_mode``, and the ``entries`` array shape — collecting one
        ERROR per fault without aborting (LLR-001.3).

    Args:
        document (dict): The parsed top-level JSON object (already past the
            v1 hard-break check, so ``CHG-FORMAT`` here is never a v1 file —
            F-A-03 precedence).
        issues (list[ValidationIssue]): The shared issue list; findings are
            appended.

    Returns:
        bool: ``True`` when any metadata-level ERROR was recorded — the
        caller then returns a zero-entry document (faulted envelope,
        F-A-16); ``False`` when the envelope is clean.

    Data Flow:
        - ``format`` ≠ :data:`FORMAT_ID` → ``CHG-FORMAT``.
        - ``kind`` ∉ :data:`DOCUMENT_KINDS` → ``CHG-KIND-UNKNOWN``.
        - ``encoding`` non-string, unresolvable, or resolving to a non-text
          codec (``codecs.lookup(...)._is_text_encoding`` falsy — F-S-02:
          lookup success alone admits ``zlib_codec``) →
          ``CHG-ENCODING-UNKNOWN``.
        - ``value_mode`` ∉ :data:`VALUE_MODES` → ``CHG-VALUE-MODE-UNKNOWN``.
        - ``entries`` absent or not a JSON array → ``MF-BAD-STRUCTURE``.
        All checks run (collect-don't-abort); any fault makes the envelope
        faulted.

    Dependencies:
        Uses:
            - codecs.lookup
            - _issue
        Used by:
            - read_change_document
    """
    faulted = False

    fmt = document.get("format")
    if fmt != FORMAT_ID:
        faulted = True
        issues.append(
            _issue(
                CHG_FORMAT,
                f"the change file declares format {fmt!r}, not the v2 "
                f"format {FORMAT_ID!r} — no entries were read",
            )
        )

    kind = document.get("kind")
    if kind not in DOCUMENT_KINDS:
        faulted = True
        issues.append(
            _issue(
                CHG_KIND_UNKNOWN,
                f"the change file declares kind {kind!r}, not one of "
                f"'change' / 'check' — no entries were read",
            )
        )

    encoding = document.get("encoding")
    if not isinstance(encoding, str) or not _is_text_encoding(encoding):
        faulted = True
        issues.append(
            _issue(
                CHG_ENCODING_UNKNOWN,
                f"the change file declares encoding {encoding!r}, which does "
                f"not resolve to a text codec — no entries were read",
            )
        )

    value_mode = document.get("value_mode")
    if value_mode not in VALUE_MODES:
        faulted = True
        issues.append(
            _issue(
                CHG_VALUE_MODE_UNKNOWN,
                f"the change file declares value_mode {value_mode!r}, not "
                f"one of 'text' / 'codes' — no entries were read",
            )
        )

    if not isinstance(document.get("entries"), list):
        faulted = True
        issues.append(
            _issue(
                MF_BAD_STRUCTURE,
                "the change file's 'entries' field is absent or not a JSON "
                "array — no entries were read",
            )
        )

    return faulted


def _is_text_encoding(encoding: str) -> bool:
    """
    Summary:
        Report whether ``encoding`` resolves to a Python **text** codec
        (LLR-001.3 / F-S-02).

    Args:
        encoding (str): The declared codec name.

    Returns:
        bool: ``True`` only when ``codecs.lookup(encoding)`` succeeds AND the
        resolved ``CodecInfo._is_text_encoding`` flag is truthy. Lookup
        success alone is NOT sufficient: ``codecs.lookup("zlib_codec")``
        succeeds, then ``str.encode`` raises ``LookupError`` — a non-text
        codec must be rejected at metadata level.

    Data Flow:
        - ``codecs.lookup`` raising ``LookupError`` → ``False``.
        - Otherwise the ``_is_text_encoding`` attribute decides (absent →
          ``False``, the conservative default).

    Dependencies:
        Uses:
            - codecs.lookup
        Used by:
            - _metadata_issues
    """
    try:
        info = codecs.lookup(encoding)
    except LookupError:
        return False
    return bool(getattr(info, "_is_text_encoding", False))


def _parse_entries(
    raw_entries: list,
    encoding: str,
    value_mode: str,
    issues: list[ValidationIssue],
) -> list[ChangeEntry]:
    """
    Summary:
        Parse the document's ``entries`` array into :class:`ChangeEntry`
        objects, applying the entry-count ceiling and the per-entry rule set
        collect-don't-abort (LLR-001.2/.4/.7).

    Args:
        raw_entries (list): The parsed JSON array under ``entries``.
        encoding (str): The validated document text codec.
        value_mode (str): The validated string-value mode
            (``"text"`` / ``"codes"``).
        issues (list[ValidationIssue]): The shared issue list.

    Returns:
        list[ChangeEntry]: The clean entries in document order. A faulty
        element appends one issue and is skipped while parsing continues.

    Data Flow:
        - Entry-count ceiling (LLR-001.7): elements at or past
          :data:`MF_ENTRY_COUNT_CEILING` are dropped with **one**
          ``MF-ENTRY-LIMIT`` issue for the whole overflow; only the
          in-ceiling prefix is parsed.
        - Each in-ceiling element goes through :func:`_parse_entry`.

    Dependencies:
        Uses:
            - _parse_entry
            - _issue
        Used by:
            - read_change_document
    """
    in_ceiling = raw_entries
    if len(raw_entries) > MF_ENTRY_COUNT_CEILING:
        issues.append(
            _issue(
                MF_ENTRY_LIMIT,
                f"the change file declares {len(raw_entries)} entries, over "
                f"the {MF_ENTRY_COUNT_CEILING}-entry ceiling — the "
                f"{len(raw_entries) - MF_ENTRY_COUNT_CEILING} entries past "
                f"the ceiling were dropped",
            )
        )
        in_ceiling = raw_entries[:MF_ENTRY_COUNT_CEILING]

    entries: list[ChangeEntry] = []
    for index, element in enumerate(in_ceiling):
        entry = _parse_entry(index, element, encoding, value_mode, issues)
        if entry is not None:
            entries.append(entry)
    return entries


def _parse_entry(
    index: int,
    element: object,
    encoding: str,
    value_mode: str,
    issues: list[ValidationIssue],
) -> Optional[ChangeEntry]:
    """
    Summary:
        Validate and parse one ``entries`` element under the strict wire
        grammar, skip-and-continue (LLR-001.2/.4/.7).

    Args:
        index (int): The element's position in the ``entries`` array — named
            in findings that have no usable address.
        element (object): The parsed array element — expected to be a JSON
            object carrying ``type``, ``address``, and ``value`` / ``bytes``.
        encoding (str): The validated document text codec.
        value_mode (str): The validated string-value mode.
        issues (list[ValidationIssue]): The shared issue list.

    Returns:
        Optional[ChangeEntry]: The parsed entry, or ``None`` when a rule
        fired (one issue appended, entry skipped).

    Data Flow:
        - Non-object element / unrecognised ``type`` → ``MF-BAD-STRUCTURE``.
        - ``address`` outside the wire grammar → ``CHG-ADDRESS-SYNTAX``
          (:func:`_parse_address`).
        - ``"string"`` entry → :func:`_resolve_string_entry` (empty/wrong
          type → ``CHG-VALUE-EMPTY``; pre-encode raw-length guard →
          ``MF-ENTRY-LIMIT``; encode failure → ``CHG-ENCODE-FAIL``;
          over-ceiling encoded length → ``MF-ENTRY-LIMIT``).
        - ``"bytes"`` entry → :func:`_resolve_bytes_entry` (empty →
          ``CHG-VALUE-EMPTY``; non-token spelling → ``CHG-BYTES-SYNTAX``;
          over-ceiling token count → ``MF-ENTRY-LIMIT``).

    Dependencies:
        Uses:
            - _parse_address
            - _resolve_string_entry
            - _resolve_bytes_entry
            - _issue
        Used by:
            - _parse_entries
    """
    if not isinstance(element, dict):
        issues.append(
            _issue(
                CHG_DECL_STRUCTURE,
                f"entry {index} is not a JSON object — the entry was skipped",
            )
        )
        return None

    entry_type = element.get("type")
    if entry_type not in ("string", "bytes"):
        issues.append(
            _issue(
                CHG_DECL_STRUCTURE,
                f"entry {index} declares type {entry_type!r}, not one of "
                f"'string' / 'bytes' — the entry was skipped",
            )
        )
        return None

    address = _parse_address(index, element.get("address"), issues)
    if address is None:
        return None

    if entry_type == "string":
        return _resolve_string_entry(
            index, address, element.get("value"), encoding, value_mode, issues
        )
    return _resolve_bytes_entry(index, address, element.get("bytes"), issues)


def _parse_address(
    index: int,
    raw_address: object,
    issues: list[ValidationIssue],
) -> Optional[int]:
    """
    Summary:
        Parse one entry ``address`` under the strict wire grammar: a JSON
        string matching ``^0x[0-9A-Fa-f]+$`` or a non-negative JSON integer
        (LLR-001.2).

    Args:
        index (int): The entry's array position — named in the finding.
        raw_address (object): The parsed ``address`` field value.
        issues (list[ValidationIssue]): The shared issue list.

    Returns:
        Optional[int]: The integer address, or ``None`` with one
        ``CHG-ADDRESS-SYNTAX`` issue appended. ``bool`` is rejected
        explicitly (a JSON ``true`` is never address 1); a negative integer
        and any other string spelling (no ``0x``, decimal text, empty) are
        rejected.

    Data Flow:
        - String arm: full-match against the wire regex, then ``int(..., 16)``.
        - Integer arm: ``isinstance(int)`` minus ``bool``, ``>= 0``.

    Dependencies:
        Uses:
            - _ADDRESS_RE
            - _issue
        Used by:
            - _parse_entry
    """
    if isinstance(raw_address, str):
        if _ADDRESS_RE.match(raw_address):
            return int(raw_address, 16)
    elif isinstance(raw_address, int) and not isinstance(raw_address, bool):
        if raw_address >= 0:
            return raw_address
    issues.append(
        _issue(
            CHG_ADDRESS_SYNTAX,
            f"entry {index} has no valid address — expected a "
            f"'0x...' hex string or a non-negative integer — the entry "
            f"was skipped",
        )
    )
    return None


def _resolve_string_entry(
    index: int,
    address: int,
    raw_value: object,
    encoding: str,
    value_mode: str,
    issues: list[ValidationIssue],
) -> Optional[ChangeEntry]:
    """
    Summary:
        Resolve one ``"string"`` entry's declared ``value`` to its encoded
        byte run under the document ``encoding`` / ``value_mode``, with the
        pre-encode raw-length guard and broadened encode-failure coverage
        (LLR-001.2/.4/.7, F-S-02/F-S-04).

    Args:
        index (int): The entry's array position.
        address (int): The parsed entry address — named in findings.
        raw_value (object): The parsed ``value`` field — a JSON string under
            ``value_mode="text"``, a JSON array of code points under
            ``value_mode="codes"``.
        encoding (str): The validated document text codec.
        value_mode (str): The validated string-value mode.
        issues (list[ValidationIssue]): The shared issue list.

    Returns:
        Optional[ChangeEntry]: The entry with ``encoded_bytes`` = the encoded
        run and ``value`` = the raw declaration (string, or code-point
        tuple), or ``None`` with exactly one issue appended.

    Data Flow:
        - Missing / empty / wrong-typed ``value`` → ``CHG-VALUE-EMPTY``.
        - **Pre-encode guard (F-S-04):** the raw character count / code-point
          array length is checked against :data:`MF_RUN_LENGTH_CEILING`
          BEFORE any encode, so an oversized declaration never forces an
          unbounded encode → ``MF-ENTRY-LIMIT``.
        - Encode: ``value.encode(encoding)`` (text) or
          ``"".join(chr(c) ...).encode(encoding)`` (codes), catching
          ``UnicodeEncodeError`` / ``ValueError`` / ``TypeError`` /
          ``LookupError`` / ``OverflowError`` → ``CHG-ENCODE-FAIL`` (an
          out-of-range or negative code point raises ``ValueError`` from
          ``chr``, not ``UnicodeEncodeError`` — F-S-02).
        - **Post-encode ceiling:** the ENCODED byte length over
          :data:`MF_RUN_LENGTH_CEILING` → ``MF-ENTRY-LIMIT`` (LLR-001.7).
        - Findings never embed the declared value or its bytes (C-9).

    Dependencies:
        Uses:
            - ChangeEntry
            - _issue
        Used by:
            - _parse_entry
    """
    if value_mode == "codes":
        usable = isinstance(raw_value, list) and len(raw_value) > 0
    else:
        usable = isinstance(raw_value, str) and len(raw_value) > 0
    if not usable:
        issues.append(
            _issue(
                CHG_VALUE_EMPTY,
                f"the string entry at address 0x{address:X} has a missing, "
                f"empty, or wrong-typed 'value' field — the entry was "
                f"skipped",
                address=address,
            )
        )
        return None

    # Pre-encode raw-length guard (F-S-04) — BEFORE any encode attempt.
    raw_length = len(raw_value)
    if raw_length > MF_RUN_LENGTH_CEILING:
        issues.append(
            _issue(
                MF_ENTRY_LIMIT,
                f"the string entry at address 0x{address:X} declares a raw "
                f"value of {raw_length} characters/code points, over the "
                f"{MF_RUN_LENGTH_CEILING} run-length ceiling — the entry was "
                f"dropped before encoding",
                address=address,
            )
        )
        return None

    try:
        if value_mode == "codes":
            text = "".join(chr(code) for code in raw_value)
        else:
            text = raw_value
        encoded = text.encode(encoding)
    except (
        UnicodeEncodeError,
        ValueError,
        TypeError,
        LookupError,
        OverflowError,
    ) as exc:
        issues.append(
            _issue(
                CHG_ENCODE_FAIL,
                f"the string entry at address 0x{address:X} could not be "
                f"encoded with {encoding!r}: {type(exc).__name__} — the "
                f"entry was skipped",
                address=address,
            )
        )
        return None

    # Encoded-length ceiling (LLR-001.7) — on the ENCODED byte length.
    if len(encoded) > MF_RUN_LENGTH_CEILING:
        issues.append(
            _issue(
                MF_ENTRY_LIMIT,
                f"the string entry at address 0x{address:X} encodes to "
                f"{len(encoded)} bytes, over the {MF_RUN_LENGTH_CEILING}-byte "
                f"run-length ceiling — the entry was dropped",
                address=address,
            )
        )
        return None

    stored_value: Union[str, tuple[int, ...]]
    stored_value = tuple(raw_value) if value_mode == "codes" else raw_value
    return ChangeEntry(
        entry_type="string",
        address=address,
        encoded_bytes=tuple(encoded),
        value=stored_value,
    )


def _resolve_bytes_entry(
    index: int,
    address: int,
    raw_bytes: object,
    issues: list[ValidationIssue],
) -> Optional[ChangeEntry]:
    """
    Summary:
        Parse one ``"bytes"`` entry's ``bytes`` field under the strict wire
        grammar — whitespace-separated two-hex-digit tokens ONLY
        (LLR-001.2 / §6.2 C-1 / F-Q-04).

    Args:
        index (int): The entry's array position.
        address (int): The parsed entry address — named in findings.
        raw_bytes (object): The parsed ``bytes`` field value.
        issues (list[ValidationIssue]): The shared issue list.

    Returns:
        Optional[ChangeEntry]: The entry with ``encoded_bytes`` = the parsed
        token values, or ``None`` with exactly one issue appended.

    Data Flow:
        - Missing / non-string / blank ``bytes`` → ``CHG-VALUE-EMPTY``.
        - Any token that is not exactly two hex digits (commas, decimals,
          ``0x`` prefixes, odd-length tokens — the permissive TUI-input
          grammar is NOT the wire grammar) → ``CHG-BYTES-SYNTAX``.
        - Token count over :data:`MF_RUN_LENGTH_CEILING` →
          ``MF-ENTRY-LIMIT`` (LLR-001.7).
        - Findings never embed the token content (C-9).

    Dependencies:
        Uses:
            - _BYTES_TOKEN_RE
            - ChangeEntry
            - _issue
        Used by:
            - _parse_entry
    """
    if not isinstance(raw_bytes, str) or not raw_bytes.strip():
        issues.append(
            _issue(
                CHG_VALUE_EMPTY,
                f"the bytes entry at address 0x{address:X} has a missing or "
                f"empty 'bytes' field — the entry was skipped",
                address=address,
            )
        )
        return None

    tokens = raw_bytes.split()
    for token in tokens:
        if not _BYTES_TOKEN_RE.match(token):
            issues.append(
                _issue(
                    CHG_BYTES_SYNTAX,
                    f"the bytes entry at address 0x{address:X} has a token "
                    f"outside the wire grammar (whitespace-separated "
                    f"two-hex-digit tokens only) — the entry was skipped",
                    address=address,
                )
            )
            return None

    if len(tokens) > MF_RUN_LENGTH_CEILING:
        issues.append(
            _issue(
                MF_ENTRY_LIMIT,
                f"the bytes entry at address 0x{address:X} declares "
                f"{len(tokens)} bytes, over the {MF_RUN_LENGTH_CEILING}-byte "
                f"run-length ceiling — the entry was dropped",
                address=address,
            )
        )
        return None

    return ChangeEntry(
        entry_type="bytes",
        address=address,
        encoded_bytes=tuple(int(token, 16) for token in tokens),
        value=None,
    )


# ---------------------------------------------------------------------------
# Write path (LLR-001.1/.2 canonical form; staged-containment per LLR-001.7).
# ---------------------------------------------------------------------------


def serialize_change_document(document: ChangeDocument) -> bytes:
    """
    Summary:
        Serialize a :class:`ChangeDocument` to the canonical v2 JSON wire
        form as UTF-8 bytes (LLR-001.1/.2).

    Args:
        document (ChangeDocument): The document to serialize. Its five
            metadata fields are written verbatim; entries are written in
            document order, so two serializations of the same document are
            byte-identical.

    Returns:
        bytes: The v2 JSON document, UTF-8 encoded, ``indent=2`` plus a
        trailing newline (human-inspectable, the unified-file convention).
        Addresses are emitted in the canonical ``"0x..."`` uppercase-hex
        string form; a bytes entry's run is emitted as uppercase
        space-separated two-hex-digit tokens (the strict wire grammar); a
        string entry re-emits its raw declaration (``value`` string, or
        code-point array under ``value_mode="codes"``).

    Raises:
        None: A well-formed ``ChangeDocument`` always serializes — every
            entry's bytes were validated at construction.

    Data Flow:
        - Build the five-field header + the ``entries`` array via
          :func:`_encode_entry`; dump with stdlib ``json``.

    Dependencies:
        Uses:
            - _encode_entry
            - json.dumps
        Used by:
            - write_change_document
            - The metadata round-trip test (TC-001).

    Example:
        >>> from s19_app.tui.changes.model import ChangeDocument, ChangeEntry
        >>> doc = ChangeDocument(
        ...     format=FORMAT_ID, version=FORMAT_VERSION, kind="change",
        ...     encoding="utf-8", value_mode="text",
        ...     entries=[ChangeEntry("bytes", 0x800020, (0xFF,))],
        ... )
        >>> json.loads(serialize_change_document(doc))["entries"][0]["address"]
        '0x800020'
    """
    payload = {
        "format": document.format,
        "version": document.version,
        "kind": document.kind,
        "encoding": document.encoding,
        "value_mode": document.value_mode,
        "entries": [_encode_entry(entry) for entry in document.entries],
    }
    text = json.dumps(payload, indent=2) + "\n"
    return text.encode("utf-8")


def _encode_entry(entry: ChangeEntry) -> dict[str, object]:
    """
    Summary:
        Encode one :class:`ChangeEntry` as its canonical wire-form JSON
        object (LLR-001.2).

    Args:
        entry (ChangeEntry): The entry to encode.

    Returns:
        dict[str, object]: ``{"type", "address", "value"|"bytes"}`` —
        ``address`` as the canonical ``"0x..."`` uppercase-hex string; a
        string entry's ``value`` as its raw declaration (a code-point tuple
        becomes a JSON array); a bytes entry's ``bytes`` as uppercase
        space-separated two-hex-digit tokens.

    Data Flow:
        - Branch on ``entry_type``; bytes entries re-derive the token string
          from ``encoded_bytes`` (the normalization point of the C-1 grammar
          split — any permissive TUI-input spelling leaves here canonical).

    Dependencies:
        Used by:
            - serialize_change_document
    """
    address_text = f"0x{entry.address:X}"
    if entry.entry_type == "string":
        raw = entry.value
        value: object = list(raw) if isinstance(raw, tuple) else raw
        return {"type": "string", "address": address_text, "value": value}
    return {
        "type": "bytes",
        "address": address_text,
        "bytes": " ".join(f"{b:02X}" for b in entry.encoded_bytes),
    }


def write_change_document(
    document: ChangeDocument,
    base_dir: Path,
    file_name: str = DEFAULT_CHANGE_FILE_NAME,
    copy_fn: Optional[CopyIntoWorkarea] = None,
) -> tuple[Optional[Path], list[ValidationIssue]]:
    """
    Summary:
        Serialize a v2 change document to a JSON file placed inside the work
        area through the staged-containment pattern: stage the bytes under
        ``.s19tool/workarea/temp/`` and let ``workspace.copy_into_workarea``
        perform the containment-checked final placement (the
        ``write_unified_to_workarea`` pattern, reused not re-invented).

    Args:
        document (ChangeDocument): The document to serialize — passed to
            :func:`serialize_change_document`.
        base_dir (Path): The app base directory whose ``.s19tool/workarea/``
            is the containment root. Created if absent (``ensure_workarea``).
        file_name (str): The desired file name. Directory components are
            stripped and a ``.json`` suffix is forced (:func:`_safe_name`),
            so the name itself cannot escape the work area; a collision is
            dedup-suffixed by ``copy_into_workarea`` — never a silent
            clobber.
        copy_fn (Optional[CopyIntoWorkarea]): The work-area placement helper.
            ``None`` (the default) resolves to ``workspace.
            copy_into_workarea`` at call time, so monkeypatching that symbol
            also redirects the write path; injectable so a test can stub the
            containment-checked placement without OS symlink privilege.

    Returns:
        tuple[Optional[Path], list[ValidationIssue]]: The absolute path of
        the written file and the issue list, or ``(None, issues)`` when the
        write target failed containment validation — one
        ``MF-WRITE-CONTAINMENT`` warning, never an uncaught exception.

    Raises:
        None: A containment, reparse-point, or I/O failure
            (``WorkareaContainmentError`` / ``OSError``) is reported as one
            ``MF-WRITE-CONTAINMENT`` ``ValidationIssue``
            (collect-don't-abort).

    Data Flow:
        - Serialize ``document``; ensure the work-area structure; stage the
          bytes in ``.s19tool/workarea/temp/`` — itself inside the work area,
          so no bytes ever land outside it.
        - Place the staged file into the dedicated patches folder
          ``.s19tool/workarea/patches/`` via the copy helper (containment +
          reparse point + dedup checks reused; the helper creates the patches
          subdir on demand); remove the staged temp file either way.

    Dependencies:
        Uses:
            - serialize_change_document
            - ensure_workarea
            - copy_into_workarea (via the injectable copy_fn)
            - _safe_name
            - _issue
        Used by:
            - The E3a change service save action (later increment)
            - tests/test_changes_schema.py::test_metadata_roundtrip

    Example:
        >>> path, issues = write_change_document(doc, base_dir)  # doctest: +SKIP
    """
    data = serialize_change_document(document)
    issues: list[ValidationIssue] = []

    placement: CopyIntoWorkarea = (
        copy_into_workarea if copy_fn is None else copy_fn
    )

    workarea = ensure_workarea(base_dir)
    staged = workarea / WORKAREA_TEMP / _safe_name(file_name)
    try:
        staged.parent.mkdir(parents=True, exist_ok=True)
        staged.write_bytes(data)
        target = placement(staged, workarea / WORKAREA_PATCHES)
        return target, issues
    except (WorkareaContainmentError, OSError) as exc:
        issues.append(
            _issue(
                MF_WRITE_CONTAINMENT,
                f"the change-file write target failed work-area containment "
                f"validation — no file was written: "
                f"{type(exc).__name__}: {exc}",
                severity=ValidationSeverity.WARNING,
            )
        )
        return None, issues
    finally:
        try:
            staged.unlink()
        except OSError:
            pass


def _safe_name(file_name: str) -> str:
    """
    Summary:
        Reduce a requested change-file name to its bare name component with a
        ``.json`` suffix, so the write target cannot escape the work area via
        the file name itself.

    Args:
        file_name (str): The caller-requested file name — possibly carrying
            path separators or no suffix.

    Returns:
        str: The bare name (``Path.name`` — directory components stripped)
        with a ``.json`` suffix forced on. An empty result falls back to
        :data:`DEFAULT_CHANGE_FILE_NAME`.

    Data Flow:
        - Strip any directory component with ``Path(...).name``.
        - Force a ``.json`` suffix; fall back to the default name when empty.

    Dependencies:
        Used by:
            - write_change_document
    """
    bare = Path(file_name).name.strip()
    if not bare:
        return DEFAULT_CHANGE_FILE_NAME
    if not bare.lower().endswith(".json"):
        bare = f"{bare}.json"
    return bare


# ---------------------------------------------------------------------------
# S19 emitter (LLR-002.7 / D-1) — mem_map-pure save-back serializer.
# ---------------------------------------------------------------------------


def emit_s19_from_mem_map(
    mem_map: dict[int, int],
    ranges: list[tuple[int, int]],
    bytes_per_line: int = 32,
    s0_header: bytes | None = None,
) -> str:
    """
    Summary:
        Serialize a sparse memory map into structurally valid Motorola S19
        text — the NEW mem_map-based emitter of LLR-002.7 (the CLI
        ``patch-hex --save-as`` path serializes an ``S19File`` object and is
        not reusable here, F-A-05). LLR-015.1/.2 add a selectable record
        width and an optional populated S0 header.

    Args:
        mem_map (dict[int, int]): Address-to-byte map of the (post-apply)
            image. Every address inside ``ranges`` must be present — the
            ranges are derived from the map's keys by the parse layer, and
            the apply engine mutates values only at existing keys, so the
            contract holds for every internal caller.
        ranges (list[tuple[int, int]]): The image's contiguous half-open
            ``(start, end)`` ranges (``LoadedFile.ranges`` ordering), driving
            record emission order.
        bytes_per_line (int): Data bytes per emitted record, constrained to
            ``{16, 32}`` (default 32). Any other value raises ``ValueError``
            before a single record is emitted (LLR-015.1 / F-S-03).
        s0_header (bytes | None): Optional S0 header payload. When provided
            the emitter writes a populated ``S0`` carrying these bytes; when
            ``None`` it writes the legacy empty ``S0``. The S0 is inert to the
            memory map either way. Bounded to ``len(s0_header) <= 252`` so the
            single-byte ``byte_count`` field cannot overflow (C4 / F-S-02);
            an over-long header raises ``ValueError`` (LLR-015.2).

    Returns:
        str: S19 text, one record per line with a trailing newline: an S0
        header (empty by default, or populated from ``s0_header``; inert to
        the memory map either way), data records of ``bytes_per_line`` data
        bytes max, and the matching terminator. The data record type is chosen
        from the highest emitted address — S1/S9 up to 0xFFFF, S2/S8 up to
        0xFFFFFF, S3/S7 above — and every record carries the one's-complement
        checksum ``core.SRecord._calculate_checksum`` validates.

    Raises:
        ValueError: If ``bytes_per_line`` is not in ``{16, 32}`` (no records
            emitted), or if ``s0_header`` exceeds 252 bytes.
        KeyError: If ``ranges`` claims an address absent from ``mem_map`` —
            a programming error in the caller, not a data-quality fault.

    Data Flow:
        - Validate ``bytes_per_line`` and the ``s0_header`` length at entry,
          before emitting anything.
        - Pick the address width from the highest ``end − 1`` over ``ranges``.
        - Emit ``S0`` (empty, or populated from ``s0_header``), then walk each
          range in ``bytes_per_line``-byte rows reading bytes from ``mem_map``,
          then emit the width-matched terminator (address 0, no data).
        - Acceptance contract: the emitted text re-parses via
          ``s19_app.core.S19File`` to a memory map equal to ``mem_map`` with
          zero load errors.

    Dependencies:
        Uses:
            - _s19_record
        Used by:
            - changes.apply.save_patched_image
            - tests/test_changes_apply.py (round-trip assertions)

    Example:
        >>> emit_s19_from_mem_map({0x10: 0xAB}, [(0x10, 0x11)]).splitlines()[1]
        'S1040010AB40'
    """
    if bytes_per_line not in (16, 32):
        raise ValueError(
            f"bytes_per_line must be 16 or 32, got {bytes_per_line!r}"
        )
    if s0_header is not None and len(s0_header) > 252:
        raise ValueError(
            f"s0_header must be at most 252 bytes, got {len(s0_header)}"
        )

    highest = max((end - 1 for _, end in ranges), default=0)
    if highest <= 0xFFFF:
        data_type, address_length, terminator_type = "S1", 2, "S9"
    elif highest <= 0xFFFFFF:
        data_type, address_length, terminator_type = "S2", 3, "S8"
    else:
        data_type, address_length, terminator_type = "S3", 4, "S7"

    s0_data = () if s0_header is None else tuple(s0_header)
    lines = [_s19_record("S0", 2, 0, s0_data)]
    for start, end in ranges:
        for row_start in range(start, end, bytes_per_line):
            row_end = min(row_start + bytes_per_line, end)
            data = tuple(mem_map[addr] for addr in range(row_start, row_end))
            lines.append(_s19_record(data_type, address_length, row_start, data))
    lines.append(_s19_record(terminator_type, address_length, 0, ()))
    return "\n".join(lines) + "\n"


def _s19_record(
    record_type: str,
    address_length: int,
    address: int,
    data: tuple[int, ...],
) -> str:
    """
    Summary:
        Build one S-record line: type, byte count, zero-padded address, data
        bytes, and the one's-complement checksum (the ``core.py`` reference
        structure).

    Args:
        record_type (str): The two-character record tag (``"S0"``…``"S9"``).
        address_length (int): Address field width in bytes (2, 3, or 4 — the
            ``ADDRESS_LENGTH_MAP`` widths).
        address (int): The record address; must fit ``address_length`` bytes.
        data (tuple[int, ...]): The data bytes — empty for the header and
            terminator records this module emits.

    Returns:
        str: The uppercase-hex record line without a newline. ``byte_count``
        is ``address_length + len(data) + 1``; the checksum is the
        one's-complement of the LSB of ``byte_count + address bytes + data``
        (matching ``SRecord._calculate_checksum``).

    Dependencies:
        Used by:
            - emit_s19_from_mem_map
    """
    byte_count = address_length + len(data) + 1
    address_bytes = [
        (address >> (8 * shift)) & 0xFF
        for shift in reversed(range(address_length))
    ]
    checksum = (~(byte_count + sum(address_bytes) + sum(data))) & 0xFF
    data_text = "".join(f"{byte:02X}" for byte in data)
    return (
        f"{record_type}{byte_count:02X}"
        f"{address:0{address_length * 2}X}{data_text}{checksum:02X}"
    )


# ---------------------------------------------------------------------------
# Intel HEX emitter (HLR-001 / LLR-001.1..4 / D-A=(a) relocated to io.py for
# emission-purpose cohesion alongside emit_s19_from_mem_map) — the mem_map-pure
# write counterpart of hexfile.IntelHexFile's read path.
# ---------------------------------------------------------------------------

HEX_DATA_BYTES_PER_RECORD = 16


def emit_intel_hex_from_mem_map(
    mem_map: dict[int, int],
    ranges: list[tuple[int, int]],
) -> str:
    """
    Summary:
        Serialize a sparse memory map into structurally valid Intel HEX text —
        the write counterpart of ``hexfile.IntelHexFile`` (HLR-001). Mirrors
        the shape of the S19 emitter (``emit_s19_from_mem_map`` above): a pure
        ``(mem_map, ranges) -> str`` with no I/O side effect, headless
        (stdlib-only, no ``textual`` import).

    Args:
        mem_map (dict[int, int]): Address-to-byte map of the image. Every
            address inside ``ranges`` must be present — the apply engine only
            mutates values at existing keys, so the contract holds for every
            internal caller.
        ranges (list[tuple[int, int]]): The image's contiguous half-open
            ``(start, end)`` ranges, driving record emission order. The
            function sorts them so output is deterministic and ascending
            regardless of caller ordering.

    Returns:
        str: Intel HEX text, one record per line with a trailing newline:
        type-0x04 extended-linear-address records whenever the active upper-16
        bits of the address change — which includes the very first data row, so
        a low-address-only image still carries an explicit ``0x0000`` base ELA
        (valid and round-trip-stable, if non-minimal) — type-0x00 data records
        of at most 16 data bytes each, and exactly one type-0x01 EOF record
        (``:00000001FF``). Empty input emits the EOF record alone. Each record
        carries the Intel HEX checksum: the two's complement of the low byte of
        the sum of all preceding record bytes.

    Raises:
        KeyError: If ``ranges`` claims an address absent from ``mem_map`` — a
            programming error in the caller, not a data-quality fault.

    Data Flow:
        - Sort ``ranges`` ascending for deterministic output.
        - Walk each range in 16-byte rows; before each row, if the row's
          upper-16 address differs from the active upper-16, emit a type-0x04
          ELA record and update the active upper-16.
        - Emit a type-0x00 data record per row using the low-16 of the row
          address (the upper-16 is carried by the active ELA).
        - Terminate with one type-0x01 EOF record.
        - Acceptance contract (LLR-001.4): the emitted text, written to a file
          and re-parsed via ``hexfile.IntelHexFile``, reconstructs a memory map
          equal to ``mem_map`` with zero load errors.

    Dependencies:
        Uses:
            - _intel_hex_record
        Used by:
            - tests/test_hex_emit.py (round-trip assertions)
            - changes.apply.save_patched_image (HEX branch — I3, future)

    Example:
        >>> emit_intel_hex_from_mem_map({0x10: 0xAB}, [(0x10, 0x11)]).splitlines()
        [':020000040000FA', ':01001000AB44', ':00000001FF']
    """
    lines: list[str] = []
    active_upper = None
    for start, end in sorted(ranges):
        for row_start in range(start, end, HEX_DATA_BYTES_PER_RECORD):
            row_end = min(row_start + HEX_DATA_BYTES_PER_RECORD, end)
            upper = (row_start >> 16) & 0xFFFF
            if upper != active_upper:
                lines.append(_intel_hex_record(0x04, 0, [upper >> 8, upper & 0xFF]))
                active_upper = upper
            data = [mem_map[addr] for addr in range(row_start, row_end)]
            lines.append(_intel_hex_record(0x00, row_start & 0xFFFF, data))
    lines.append(_intel_hex_record(0x01, 0, []))
    return "\n".join(lines) + "\n"


def _intel_hex_record(
    record_type: int,
    address: int,
    data: list[int],
) -> str:
    """
    Summary:
        Build one Intel HEX record line ``:LLAAAATT[DD..]CC`` with the
        two's-complement-of-sum checksum the ``hexfile.IntelHexFile`` reader
        verifies (``hexfile.py:66-74``).

    Args:
        record_type (int): The record type byte — 0x00 data, 0x01 EOF, 0x04
            extended linear address.
        address (int): The 16-bit address field; the low-16 of the data
            address for type-0x00, 0 for type-0x01/0x04.
        data (list[int]): The data bytes (<= 16 for data records; the two
            upper-address bytes for ELA; empty for EOF).

    Returns:
        str: The uppercase-hex record line without a newline. ``byte_count``
        is ``len(data)``; the checksum is the two's complement of the low byte
        of ``byte_count + addr_hi + addr_lo + record_type + sum(data)`` — so
        the reader's full-line sum (``hexfile.py:66-74``) is 0 mod 256.

    Dependencies:
        Used by:
            - emit_intel_hex_from_mem_map
    """
    byte_count = len(data)
    addr_hi = (address >> 8) & 0xFF
    addr_lo = address & 0xFF
    checksum = (-(byte_count + addr_hi + addr_lo + record_type + sum(data))) & 0xFF
    data_text = "".join(f"{byte:02X}" for byte in data)
    return f":{byte_count:02X}{address:04X}{record_type:02X}{data_text}{checksum:02X}"
