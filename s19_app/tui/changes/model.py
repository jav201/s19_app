"""
v2 change-file object model — s19_app batch-07, increment E1.

This module is the **pure-data half** of the v2 hex-first change system
(`s19app-changeset`, HLR-001): the per-entry container :class:`ChangeEntry`,
the document container :class:`ChangeDocument`, and the
:class:`MemoryStatus` containment verdict migrated from
``cdfx/memory.py`` (the cdfx original is untouched here — increment E3b
performs the deletions).

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
from typing import Optional, Union

from ...validation.model import ValidationIssue, ValidationSeverity

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
