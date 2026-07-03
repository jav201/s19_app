"""
v2 change-file object model — s19_app batch-07, increments E1/E2/E4.

This module is the **pure-data half** of the v2 hex-first change system
(`s19app-changeset`, HLR-001): the per-entry container :class:`ChangeEntry`,
the document container :class:`ChangeDocument`, the
:class:`MemoryStatus` containment verdict migrated from ``cdfx/memory.py``,
the E2 apply-summary carriers (:class:`ChangeSummary`), and the E4
check-result carriers (:class:`CheckRunResult` — the §6.2 C-6 canonical
results object of LLR-004.3).

A v2 entry comes in exactly two kinds (LLR-001.2): a **string patch**
(``entry_type="string"``) whose declared ``value`` is resolved to bytes via
the document's ``encoding`` / ``value_mode``, and a **byte patch**
(``entry_type="bytes"``) whose bytes come from the strict wire-grammar hex
tokens. Both kinds store their resolved target bytes as the immutable
``encoded_bytes`` tuple, and the entry's addressed byte span —
:attr:`ChangeEntry.addressed_range` — is always derived from the **encoded**
byte length (LLR-001.5), never from the declared character count: multi-byte
encodings make the two differ, and collision math uses encoded length
everywhere.

This module imports stdlib + ``s19_app.validation.model`` only: no JSON
parsing, no filesystem, no Textual. The reader/writer live in
``changes/io.py``; the collision rule lives in ``changes/validate.py``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Optional, Union

from ...validation.model import ValidationIssue, ValidationSeverity

if TYPE_CHECKING:  # annotation-only; keeps model.py free of the verify import
    from .verify import VerifyResult

#: ``ValidationIssue.artifact`` tag for every finding the v2 change system
#: produces (reader, writer, collision rule), so a consumer can tell a
#: change-document finding from a parser or cross-artifact one. Defined here —
#: the dependency root of the ``changes/`` package — so ``io.py`` and
#: ``validate.py`` share one spelling without a circular import.
CHANGES_ARTIFACT = "changes"


class MemoryStatus(str, Enum):
    """
    Summary:
        Validation state of a memory-change entry against the loaded image.

    The four states are the verdict the memory-change validator
    writes onto each entry after testing its addressed byte range against the
    loaded firmware image's address ranges. Increment E1 only constructs
    entries with the ``UNVALIDATED_NO_IMAGE`` default — the image-containment
    stamping (LLR-001.6) rides increment E2.

    Members:
        INSIDE: The addressed byte range lies fully within one loaded range.
        PARTIAL: The addressed range overlaps the loaded ranges but is not
            contained within a single one (including the gap-spanning case).
        OUTSIDE: The addressed range does not overlap any loaded range.
        UNVALIDATED_NO_IMAGE: No firmware image is loaded, so no entry can be
            validated yet — mirrors the batch-03 ``unresolved-no-a2l`` state.

    The value of each member is the stable string token used by tests and by
    issue messages; mirrors the ``ResolutionStatus`` / ``ValidationSeverity``
    ``str``-enum convention. Migrated verbatim from ``cdfx/memory.py:38``
    (the cdfx original is deleted at E3b, not here).
    """

    INSIDE = "inside"
    PARTIAL = "partial"
    OUTSIDE = "outside"
    UNVALIDATED_NO_IMAGE = "unvalidated-no-image"


@dataclass(slots=True)
class ChangeEntry:
    """
    Summary:
        One v2 change/check entry: a kind discriminator, an explicit memory
        start address, the resolved encoded byte run, and the raw declared
        value preserved for canonical re-serialization (LLR-001.2).

    Args:
        entry_type (str): The entry kind — ``"string"`` or ``"bytes"`` (the
            wire field ``type``; renamed per the §6.2 C-6 canonical schema).
        address (int): Non-negative integer memory start address — parsed from
            the wire form (``"0x..."`` string or non-negative integer).
        encoded_bytes (tuple[int, ...]): The resolved target byte run — the
            encoded ``value`` for a string entry, the parsed hex tokens for a
            bytes entry. Coerced to an immutable tuple by ``__post_init__``;
            an empty run or an out-of-range byte raises ``ValueError`` (the
            ``MemoryChange`` construction-time byte-validity rules, migrated
            from ``cdfx/memory.py``).
        value (str | tuple[int, ...] | None): The raw declared value of a
            string entry — the literal string under ``value_mode="text"``, the
            code-point tuple under ``value_mode="codes"`` — preserved so the
            canonical writer re-emits the declaration, not the encoding.
            ``None`` for a bytes entry.
        status (MemoryStatus): Image-containment verdict. Defaults to
            ``UNVALIDATED_NO_IMAGE``; stamped by the E2 containment validator.

    Returns:
        None: Dataclass container.

    Raises:
        ValueError: If ``encoded_bytes`` is an empty run, or contains a value
            outside 0-255. A malformed run does not describe a recordable edit
            intent, so it is rejected at construction; the reader validates
            wire content first and never constructs an invalid entry.

    Data Flow:
        - ``__post_init__`` materialises ``encoded_bytes`` into a tuple, then
          rejects an empty run or any out-of-range byte with ``ValueError``.
        - ``addressed_range`` derives the half-open
          ``(address, address + len(encoded_bytes))`` span — the **encoded**
          length (LLR-001.5) — used by the collision rule and, at E2, by the
          image-containment validator.

    Dependencies:
        Uses:
            - MemoryStatus
        Used by:
            - ChangeDocument
            - changes.io.read_change_document / serialize_change_document
            - changes.validate.collision_issues

    Example:
        >>> ChangeEntry("bytes", 0x100, (0x41, 0x42)).addressed_range
        (256, 258)
    """

    entry_type: str
    address: int
    encoded_bytes: tuple[int, ...]
    value: Optional[Union[str, tuple[int, ...]]] = None
    status: MemoryStatus = MemoryStatus.UNVALIDATED_NO_IMAGE

    def __post_init__(self) -> None:
        """
        Summary:
            Coerce ``encoded_bytes`` to an immutable tuple and reject a
            malformed byte run at construction time (the ``MemoryChange``
            byte-validity rules, migrated).

        Raises:
            ValueError: If ``encoded_bytes`` is empty, or holds a value that
                is negative or greater than 255.

        Data Flow:
            - Materialise the (possibly lazy) ``encoded_bytes`` iterable to a
              tuple so it is stored immutably and can be re-scanned safely.
            - Reject an empty run, then reject any byte outside 0-255.
        """
        materialised = tuple(self.encoded_bytes)
        if not materialised:
            raise ValueError(
                f"change entry at address {self.address} has an empty "
                "encoded byte run"
            )
        for byte_value in materialised:
            if byte_value < 0 or byte_value > 255:
                raise ValueError(
                    f"change entry at address {self.address} has a byte "
                    f"value {byte_value} outside the range 0-255"
                )
        self.encoded_bytes = materialised

    @property
    def addressed_range(self) -> tuple[int, int]:
        """
        Summary:
            Return this entry's addressed byte range as the half-open span
            ``(address, address + len(encoded_bytes))`` (LLR-001.5).

        Returns:
            tuple[int, int]: The ``(start, end)`` half-open range, ``end``
            exclusive — derived from the **encoded** byte length, so a
            multi-byte-encoded string spans its true on-image footprint, not
            its character count.
        """
        return (self.address, self.address + len(self.encoded_bytes))


@dataclass(slots=True)
class ChangeDocument:
    """
    Summary:
        One v2 change/check document: the five LLR-001.1 metadata fields, the
        ordered entry list, and every finding collected while reading or
        validating it (collect-don't-abort, HLR-001 statement 3).

    Args:
        format (str): The format token as found — ``"s19app-changeset"`` for a
            recognised v2 document.
        version (str): The format-version token as found — ``"2.0"`` current.
        kind (str): The document discriminator — ``"change"`` or ``"check"``.
        encoding (str): The Python text-codec name resolving string values to
            bytes (e.g. ``"utf-8"``).
        value_mode (str): How string-entry values are read — ``"text"`` (a
            literal string) or ``"codes"`` (an array of code points).
        entries (list[ChangeEntry]): The parsed entries in document order.
            Always empty when a metadata-level ERROR was recorded — entry
            content is not interpreted under a faulted envelope (F-A-16).
        issues (list[ValidationIssue]): Every collected schema, metadata,
            per-entry, collision, and resource-ceiling finding.
        source_path (Optional[Path]): The resolved on-disk path the document
            was read from — stamped by ``changes.io.read_change_document`` so
            the E2 apply engine can record it as ``ChangeSummary.source_path``
            (§6.2 C-6). ``None`` for a programmatically composed document or
            when path resolution failed.

    Returns:
        None: Dataclass container.

    Data Flow:
        - Built by ``changes.io.read_change_document`` (read path) or by a
          caller composing entries programmatically (write path).
        - ``has_errors`` is the apply gate's predicate (E2): a document with
          any ERROR-severity issue is not applicable (HLR-001 statement 4).

    Dependencies:
        Uses:
            - ChangeEntry
            - ValidationIssue / ValidationSeverity
        Used by:
            - changes.io (read/write)
            - changes.validate.collision_issues consumers
            - The E2 apply engine and E4 check engine (later increments).

    Example:
        >>> doc = ChangeDocument(
        ...     format="s19app-changeset", version="2.0", kind="change",
        ...     encoding="utf-8", value_mode="text",
        ... )
        >>> doc.has_errors
        False
    """

    format: str
    version: str
    kind: str
    encoding: str
    value_mode: str
    entries: list[ChangeEntry] = field(default_factory=list)
    issues: list[ValidationIssue] = field(default_factory=list)
    source_path: Optional[Path] = None

    @property
    def has_errors(self) -> bool:
        """
        Summary:
            Report whether any collected issue is ERROR-severity — the
            not-applicable marker of HLR-001 statement 4.

        Returns:
            bool: ``True`` when at least one issue has
            ``ValidationSeverity.ERROR``; ``False`` otherwise.
        """
        return any(
            issue.severity is ValidationSeverity.ERROR for issue in self.issues
        )


# ---------------------------------------------------------------------------
# E2 apply-summary vocabulary (LLR-002.5 / §6.2 C-6).
# ---------------------------------------------------------------------------

#: Disposition token — the entry's encoded run was written to the memory map
#: (its containment verdict was ``INSIDE``, LLR-002.2).
DISPOSITION_APPLIED = "applied"

#: Disposition token — unwritten: the run straddles a loaded-range edge or
#: spans an inter-range gap (``PARTIAL``, LLR-002.2).
DISPOSITION_SKIPPED_PARTIAL = "skipped-partial"

#: Disposition token — unwritten: the run overlaps no loaded range
#: (``OUTSIDE``, LLR-002.2).
DISPOSITION_SKIPPED_OUTSIDE = "skipped-outside"

#: Disposition token — unwritten: no firmware image is loaded
#: (``UNVALIDATED_NO_IMAGE``, LLR-002.2).
DISPOSITION_SKIPPED_NO_IMAGE = "skipped-no-image"

#: Disposition token — unwritten: the apply gate refused the whole document
#: (an ERROR-severity issue, or ``kind`` ≠ ``"change"`` — LLR-002.1).
DISPOSITION_BLOCKED = "blocked"

#: The full disposition domain in its canonical order (F-A-04). Every
#: ``ChangeSummary.counts`` dict carries exactly these keys, all present even
#: when zero, so report tables never branch on missing keys.
DISPOSITION_DOMAIN: tuple[str, ...] = (
    DISPOSITION_APPLIED,
    DISPOSITION_SKIPPED_PARTIAL,
    DISPOSITION_SKIPPED_OUTSIDE,
    DISPOSITION_SKIPPED_NO_IMAGE,
    DISPOSITION_BLOCKED,
)

#: Linkage token — the entry's range touches no MAC record and no A2L tag
#: range (LLR-002.6).
LINKAGE_STANDALONE = "standalone"

#: Linkage token — the entry's range contains at least one MAC record
#: address (LLR-002.6).
LINKAGE_MAC = "mac-linked"

#: Linkage token — the entry's range intersects at least one A2L tag range
#: (LLR-002.6).
LINKAGE_A2L = "a2l-linked"

#: Linkage token — both a MAC record and an A2L tag range are touched
#: (LLR-002.6).
LINKAGE_BOTH = "both"


@dataclass(slots=True)
class ChangeSummaryEntry:
    """
    Summary:
        One per-entry record of a :class:`ChangeSummary` — the §6.2 C-6
        canonical per-entry field set produced by the E2 apply engine
        (LLR-002.5).

    Args:
        entry_type (str): The source entry's kind — ``"string"`` or
            ``"bytes"``.
        address_start (int): Inclusive start of the entry's addressed byte
            range (``ChangeEntry.addressed_range[0]``).
        address_end (int): Exclusive end of the addressed byte range —
            ``address_end − address_start`` is the encoded byte length.
        before_bytes (Optional[tuple[int, ...]]): The prior byte values read
            from the memory map immediately before mutation (LLR-002.3).
            ``None`` for every non-``applied`` disposition — no bytes were
            read because none were written.
        after_bytes (tuple[int, ...]): The entry's declared encoded run — what
            the range holds after an ``applied`` write, and what it *would*
            have held for a skipped or blocked entry.
        disposition (str): One token of :data:`DISPOSITION_DOMAIN`.
        linkage (str): The informative classification —
            :data:`LINKAGE_STANDALONE` / :data:`LINKAGE_MAC` /
            :data:`LINKAGE_A2L` / :data:`LINKAGE_BOTH` (LLR-002.6). Never
            affects ``disposition``.
        linkage_symbol (Optional[str]): The matching MAC/A2L symbol name when
            linked (MAC name preferred on a ``both`` classification);
            ``None`` when standalone or the matching record is unnamed.

    Returns:
        None: Dataclass container.

    Data Flow:
        - Built by ``changes.apply.apply_change_document``, one per document
          entry in document order; consumed by ``ChangeSummary.to_dict`` and,
          in later increments, by the report generator (LLR-007.4).

    Dependencies:
        Used by:
            - ChangeSummary
            - changes.apply.apply_change_document
    """

    entry_type: str
    address_start: int
    address_end: int
    before_bytes: Optional[tuple[int, ...]]
    after_bytes: tuple[int, ...]
    disposition: str
    linkage: str
    linkage_symbol: Optional[str]


@dataclass(slots=True)
class ChangeSummary:
    """
    Summary:
        The change-summary object returned by the E2 apply engine — the §6.2
        C-6 canonical producer schema consumed by the execution and report
        layers (LLR-002.5, extended per B-1/B-2/F-A-04).

    Args:
        source_path (Optional[Path]): The change file the document was read
            from (``ChangeDocument.source_path``); ``None`` for a
            programmatically composed document.
        kind (str): The document discriminator as declared — ``"change"`` for
            an applicable document; a non-``"change"`` kind is part of why a
            summary came back all-``blocked``.
        encoding (str): The document's declared text codec.
        value_mode (str): The document's declared value mode.
        timestamp_utc (str): ISO-8601 UTC timestamp of the apply run, taken
            from the engine's injectable ``now_fn`` clock (B-4).
        variant_id (Optional[str]): The project variant the apply targeted;
            ``None`` outside multi-variant execution (US-005 arrives at E5/E6).
        counts (dict[str, int]): Aggregate entry counts keyed by every token
            of :data:`DISPOSITION_DOMAIN` — all five keys always present
            (F-A-04).
        entries (list[ChangeSummaryEntry]): Per-entry records in document
            order.
        issues (list[ValidationIssue]): The document's collected declaration
            faults, carried so they reach the Patch Editor panel and the
            project report (LLR-002.8).
        saved_path (Optional[Path]): Where the patched image was persisted
            (LLR-002.7) — recorded by the save-back caller after
            ``changes.apply.save_patched_image`` succeeds; ``None`` when the
            operator declined or no save happened.
        verify_result (Optional[VerifyResult]): The verify-on-save outcome
            (HLR-003, §6.2 C-10 back-compatible carrier) — stamped by the
            save-back handler after a successful write via
            ``changes.verify.verify_written_image``; ``None`` when no save
            happened. Kept off :meth:`to_dict` (a runtime-only carrier the TUI
            reads, not part of the deterministic serialized summary).
        source_image_path (Optional[Path]): The image file the summary was
            saved FROM (LLR-038.2, B-2 provenance stamp, batch-24) — stamped
            by ``ChangeService.save_patched`` beside ``saved_path`` so the
            before/after report composer can detect a stale summary
            (``LoadedFile.path`` no longer matching). ``None`` when no save
            happened or the caller passed no source. Kept off
            :meth:`to_dict`, mirroring ``verify_result``'s runtime-only
            treatment, so the serialized summary stays byte-stable.

    Returns:
        None: Dataclass container.

    Data Flow:
        - Built by ``changes.apply.apply_change_document``; ``saved_path`` is
          stamped afterwards by the save-back flow (TUI prompt at E3a,
          explicit filename parameter headless).
        - ``to_dict`` is the serialization consumed by the report generator
          (LLR-007.4) and by determinism tests (LLR-002.5).

    Dependencies:
        Uses:
            - ChangeSummaryEntry
            - ValidationIssue
        Used by:
            - changes.apply.apply_change_document
            - The E6 execution layer and E7 report generator (later
              increments).

    Example:
        >>> summary = ChangeSummary(
        ...     source_path=None, kind="change", encoding="utf-8",
        ...     value_mode="text", timestamp_utc="2026-06-10T12:00:00+00:00",
        ...     variant_id=None,
        ...     counts={token: 0 for token in DISPOSITION_DOMAIN},
        ... )
        >>> summary.to_dict()["counts"]["applied"]
        0
    """

    source_path: Optional[Path]
    kind: str
    encoding: str
    value_mode: str
    timestamp_utc: str
    variant_id: Optional[str]
    counts: dict[str, int]
    entries: list[ChangeSummaryEntry] = field(default_factory=list)
    issues: list[ValidationIssue] = field(default_factory=list)
    saved_path: Optional[Path] = None
    verify_result: Optional["VerifyResult"] = None
    source_image_path: Optional[Path] = None

    def to_dict(self) -> dict[str, object]:
        """
        Summary:
            Serialize this summary to a deterministic plain-data dict — same
            object, same dict, every call; entries in document order
            (LLR-002.5). ``verify_result`` and ``source_image_path`` are
            deliberately EXCLUDED — both are runtime-only carriers (LLR-038.2)
            and serializing them would break the summary's byte-stability.

        Returns:
            dict[str, object]: JSON-compatible mapping: paths as strings (or
            ``None``), byte tuples as lists, ``counts`` with all five
            :data:`DISPOSITION_DOMAIN` keys in canonical order, ``issues`` as
            ``{code, severity, message, artifact, symbol, address}`` dicts,
            and ``entries`` as per-entry dicts in document order.

        Data Flow:
            - Rebuilt from the dataclass fields on every call — no caching,
              no mutation — so two calls on one object compare equal and two
              applies over deep-copied inputs under a fixed clock compare
              equal (B-4).

        Dependencies:
            Uses:
                - ChangeSummaryEntry
            Used by:
                - tests/test_changes_apply.py (determinism assertions)
                - The E7 report generator (later increment).
        """
        return {
            "source_path": (
                str(self.source_path) if self.source_path is not None else None
            ),
            "kind": self.kind,
            "encoding": self.encoding,
            "value_mode": self.value_mode,
            "timestamp_utc": self.timestamp_utc,
            "variant_id": self.variant_id,
            "counts": {
                token: self.counts.get(token, 0)
                for token in DISPOSITION_DOMAIN
            },
            "saved_path": (
                str(self.saved_path) if self.saved_path is not None else None
            ),
            "issues": [
                {
                    "code": issue.code,
                    "severity": issue.severity.value,
                    "message": issue.message,
                    "artifact": issue.artifact,
                    "symbol": issue.symbol,
                    "address": issue.address,
                }
                for issue in self.issues
            ],
            "entries": [
                {
                    "entry_type": entry.entry_type,
                    "address_start": entry.address_start,
                    "address_end": entry.address_end,
                    "before_bytes": (
                        list(entry.before_bytes)
                        if entry.before_bytes is not None
                        else None
                    ),
                    "after_bytes": list(entry.after_bytes),
                    "disposition": entry.disposition,
                    "linkage": entry.linkage,
                    "linkage_symbol": entry.linkage_symbol,
                }
                for entry in self.entries
            ],
        }


# ---------------------------------------------------------------------------
# E4 check-result vocabulary (LLR-004.2 / LLR-004.3 / §6.2 C-6).
# ---------------------------------------------------------------------------

#: Result token — the entry's expected bytes equal the bytes read from the
#: loaded image over its addressed range (LLR-004.2).
CHECK_PASS = "pass"

#: Result token — the addressed range was fully readable but the actual
#: bytes differ from the expected bytes (LLR-004.2).
CHECK_FAIL = "fail"

#: Result token — no comparison was possible: the range is not fully inside
#: the loaded image (``PARTIAL`` / ``OUTSIDE``), no image is loaded, or the
#: document itself is not runnable (ERROR-faulted or ``kind`` != ``"check"``
#: — the apply-gate mirror, LLR-004.1/004.2).
CHECK_UNCHECKABLE = "uncheckable"

#: The full check-result domain in its canonical order.
CHECK_RESULT_DOMAIN: tuple[str, ...] = (
    CHECK_PASS,
    CHECK_FAIL,
    CHECK_UNCHECKABLE,
)

#: The aggregate-count keys of :attr:`CheckRunResult.aggregates` in their
#: canonical order — all three always present, even when zero, mirroring
#: :data:`DISPOSITION_DOMAIN` (F-A-04), so report tables never branch on
#: missing keys.
CHECK_AGGREGATE_KEYS: tuple[str, ...] = ("passed", "failed", "uncheckable")


@dataclass(slots=True)
class CheckRunEntry:
    """
    Summary:
        One per-entry record of a :class:`CheckRunResult` — the §6.2 C-6
        canonical per-entry field set produced by the E4 check engine
        (LLR-004.3).

    Args:
        entry_type (str): The source entry's kind — ``"string"`` or
            ``"bytes"``.
        address_start (int): Inclusive start of the entry's addressed byte
            range (``ChangeEntry.addressed_range[0]``).
        address_end (int): Exclusive end of the addressed byte range —
            ``address_end - address_start`` is the expected byte length.
        expected_bytes (tuple[int, ...]): The entry's declared encoded run —
            the **source of expected values** (US-003).
        actual_bytes (Optional[tuple[int, ...]]): The bytes read from the
            loaded image over the addressed range — captured only when the
            range was fully readable (``pass`` / ``fail``); ``None`` on
            every ``uncheckable`` outcome (LLR-004.2).
        result (str): One token of :data:`CHECK_RESULT_DOMAIN`.
        linkage (str): The informative classification —
            :data:`LINKAGE_STANDALONE` / :data:`LINKAGE_MAC` /
            :data:`LINKAGE_A2L` / :data:`LINKAGE_BOTH`. Never affects
            ``result``.
        linkage_symbol (Optional[str]): The matching MAC/A2L symbol name
            when linked; ``None`` when standalone or unnamed.

    Returns:
        None: Dataclass container.

    Data Flow:
        - Built by ``changes.check.run_check_document``, one per document
          entry in document order; consumed by ``CheckRunResult.to_dict``,
          the Patch Editor check rows (LLR-004.5), and the E7 report
          generator.

    Dependencies:
        Used by:
            - CheckRunResult
            - changes.check.run_check_document
    """

    entry_type: str
    address_start: int
    address_end: int
    expected_bytes: tuple[int, ...]
    actual_bytes: Optional[tuple[int, ...]]
    result: str
    linkage: str
    linkage_symbol: Optional[str]


@dataclass(slots=True)
class CheckRunResult:
    """
    Summary:
        The check-results object returned by the E4 check engine — the §6.2
        C-6 canonical producer schema (LLR-004.3) consumed by the Patch
        Editor display, the execution layer, and the report generator. The
        **single complete carrier** of a check run (B-2): aggregates,
        per-entry records, and the check document's collected declaration
        faults travel together.

    Args:
        source_path (Optional[Path]): The check file the document was read
            from (``ChangeDocument.source_path``); ``None`` for a
            programmatically composed document.
        timestamp_utc (str): ISO-8601 UTC timestamp of the check run, taken
            from the engine's injectable ``now_fn`` clock (B-4).
        variant_id (Optional[str]): The project variant the run targeted;
            ``None`` outside multi-variant execution (US-005 arrives at
            E5/E6).
        aggregates (dict[str, int]): Aggregate entry counts keyed by every
            token of :data:`CHECK_AGGREGATE_KEYS` — all three keys always
            present.
        entries (list[CheckRunEntry]): Per-entry records in document order.
        issues (list[ValidationIssue]): The check document's collected
            declaration faults, mirroring ``ChangeSummary.issues`` — without
            this carrier, check declaration faults would be silently dropped
            on the execution-to-report chain (B-2).

    Returns:
        None: Dataclass container.

    Data Flow:
        - Built by ``changes.check.run_check_document``; ``to_dict`` is the
          serialization consumed by the E7 report generator (LLR-007.4) and
          by determinism tests (LLR-004.3).

    Dependencies:
        Uses:
            - CheckRunEntry
            - ValidationIssue
        Used by:
            - changes.check.run_check_document
            - services.change_service (run-checks display + headless entry)
            - The E6 execution layer and E7 report generator (later
              increments).

    Example:
        >>> result = CheckRunResult(
        ...     source_path=None,
        ...     timestamp_utc="2026-06-10T12:00:00+00:00",
        ...     variant_id=None,
        ...     aggregates={key: 0 for key in CHECK_AGGREGATE_KEYS},
        ... )
        >>> result.to_dict()["aggregates"]["passed"]
        0
    """

    source_path: Optional[Path]
    timestamp_utc: str
    variant_id: Optional[str]
    aggregates: dict[str, int]
    entries: list[CheckRunEntry] = field(default_factory=list)
    issues: list[ValidationIssue] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        """
        Summary:
            Serialize this result to a deterministic plain-data dict — same
            object, same dict, every call; entries in document order
            (LLR-004.3).

        Returns:
            dict[str, object]: JSON-compatible mapping: ``source_path`` as a
            string (or ``None``), ``aggregates`` with all three
            :data:`CHECK_AGGREGATE_KEYS` in canonical order, ``issues`` as
            ``{code, severity, message, artifact, symbol, address}`` dicts,
            and ``entries`` as per-entry dicts (byte tuples as lists,
            ``actual_bytes`` ``None`` when uncheckable) in document order.

        Data Flow:
            - Rebuilt from the dataclass fields on every call — no caching,
              no mutation — so two calls on one object compare equal and two
              runs over the same inputs under a fixed clock compare equal
              (B-4).

        Dependencies:
            Uses:
                - CheckRunEntry
            Used by:
                - tests/test_checks_engine.py (determinism assertions)
                - The E7 report generator (later increment).
        """
        return {
            "source_path": (
                str(self.source_path) if self.source_path is not None else None
            ),
            "timestamp_utc": self.timestamp_utc,
            "variant_id": self.variant_id,
            "aggregates": {
                key: self.aggregates.get(key, 0)
                for key in CHECK_AGGREGATE_KEYS
            },
            "issues": [
                {
                    "code": issue.code,
                    "severity": issue.severity.value,
                    "message": issue.message,
                    "artifact": issue.artifact,
                    "symbol": issue.symbol,
                    "address": issue.address,
                }
                for issue in self.issues
            ],
            "entries": [
                {
                    "entry_type": entry.entry_type,
                    "address_start": entry.address_start,
                    "address_end": entry.address_end,
                    "expected_bytes": list(entry.expected_bytes),
                    "actual_bytes": (
                        list(entry.actual_bytes)
                        if entry.actual_bytes is not None
                        else None
                    ),
                    "result": entry.result,
                    "linkage": entry.linkage,
                    "linkage_symbol": entry.linkage_symbol,
                }
                for entry in self.entries
            ],
        }
