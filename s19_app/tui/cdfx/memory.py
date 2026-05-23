"""
Memory-field change model — s19_app batch-04, increment 1.

The memory-change list is the second change kind the Patch Editor records: a
set of raw ``(memory address -> new bytes)`` edits the engineer intends to
apply to the loaded firmware image, keyed by a memory **address** rather than
by an A2L parameter name. It is the raw-memory peer of the batch-03 parameter
``ChangeList`` (``changelist.py``) and the foundation every later batch-04
increment composes — validation, display, the unified change-set, the JSON
file handler, and selective export are all layered on top.

This module is **pure data**: it does not parse JSON, does not touch XML, and
imports no Textual. It imports stdlib only (``dataclasses``, ``enum``,
``typing``). Validation of an entry's addressed range against the loaded image
(``inside`` / ``partial`` / ``outside``) is increment 2; the only validation
performed here is the construction-time rejection of a malformed ``new_bytes``
run (LLR-002.5), which raises ``ValueError``.

``MemoryChange.new_bytes`` is stored as an immutable ``tuple[int, ...]``: the
tuple choice keeps the stored bytes un-mutatable so the display layer
(increment 3) can never alter them (LLR-003.3), and it is the natural fit for
the LLR-005.3 on-disk wire shape (a JSON array of integers). Ordering is
**insertion order**, realised exactly as ``ChangeList`` does it — entries are
held in a ``dict`` keyed on ``address`` (Python 3.7+ dicts are
insertion-ordered), so repeated serialization of the same list is
byte-identical (LLR-001.4).

Implements LLR-001.1..LLR-001.4 and the construction-time half of LLR-002.5.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable


class MemoryStatus(str, Enum):
    """
    Summary:
        Validation state of a memory-change entry against the loaded image.

    The four states are the verdict the memory-change validator (increment 2)
    writes onto each entry after testing its addressed byte range against the
    loaded firmware image's address ranges. Increment 1 only constructs entries
    with the ``UNVALIDATED_NO_IMAGE`` default — the validator assigns the rest.

    Members:
        INSIDE: The addressed byte range lies fully within one loaded range.
        PARTIAL: The addressed range overlaps the loaded ranges but is not
            contained within a single one (including the gap-spanning case).
        OUTSIDE: The addressed range does not overlap any loaded range.
        UNVALIDATED_NO_IMAGE: No firmware image is loaded, so no entry can be
            validated yet — mirrors the batch-03 ``unresolved-no-a2l`` state.

    The value of each member is the stable string token used by tests and by
    issue messages; mirrors the ``ResolutionStatus`` / ``ValidationSeverity``
    ``str``-enum convention.
    """

    INSIDE = "inside"
    PARTIAL = "partial"
    OUTSIDE = "outside"
    UNVALIDATED_NO_IMAGE = "unvalidated-no-image"


@dataclass(slots=True)
class MemoryChange:
    """
    Summary:
        One raw memory-field change: a memory start address, a contiguous run
        of new byte values for that address, and a validation status.

    Args:
        address (int): Non-negative integer memory start address — the entry
            identity (LLR-001.3) and the start of the addressed byte range.
        new_bytes (Iterable[int]): An ordered, non-empty sequence of integer
            byte values, each in the range 0-255. Coerced to an immutable
            ``tuple[int, ...]`` by ``__post_init__`` and stored as such, so the
            display layer (increment 3) can never mutate it (LLR-003.3).
        status (MemoryStatus): Validation verdict against the loaded image.
            Defaults to ``UNVALIDATED_NO_IMAGE`` — an entry is unvalidated
            until the validator (increment 2) runs.

    Returns:
        None: Dataclass container.

    Raises:
        ValueError: If ``new_bytes`` is an empty run, contains a negative byte
            value, or contains a byte value greater than 255 (LLR-002.5). A
            malformed byte run does not describe a recordable edit intent, so
            it is rejected at construction rather than collected as a
            ``ValidationIssue``.

    Data Flow:
        - ``__post_init__`` materialises ``new_bytes`` into a tuple, then
          rejects an empty run or any out-of-range byte with ``ValueError``.
        - ``addressed_range`` derives the half-open ``(address, address +
          len(new_bytes))`` span used by the increment-2 range validator.

    Dependencies:
        Uses:
            - MemoryStatus
        Used by:
            - MemoryChangeList
            - The memory-change validator and display layer (later increments).

    Example:
        >>> MemoryChange(0x100, [0x41, 0x42]).addressed_range
        (256, 258)
    """

    address: int
    new_bytes: tuple[int, ...]
    status: MemoryStatus = MemoryStatus.UNVALIDATED_NO_IMAGE

    def __post_init__(self) -> None:
        """
        Summary:
            Coerce ``new_bytes`` to an immutable tuple and reject a malformed
            byte run at construction time (LLR-002.5).

        Raises:
            ValueError: If ``new_bytes`` is empty, or holds a byte value that
                is negative or greater than 255.

        Data Flow:
            - Materialise the (possibly lazy) ``new_bytes`` iterable to a tuple
              so it is stored immutably and can be re-scanned safely.
            - Reject an empty run, then reject any byte outside 0-255.
        """
        materialised = tuple(self.new_bytes)
        if not materialised:
            raise ValueError(
                f"memory change at address {self.address} has an empty "
                "new_bytes run"
            )
        for byte_value in materialised:
            if byte_value < 0 or byte_value > 255:
                raise ValueError(
                    f"memory change at address {self.address} has a byte "
                    f"value {byte_value} outside the range 0-255"
                )
        self.new_bytes = materialised

    @property
    def addressed_range(self) -> tuple[int, int]:
        """
        Summary:
            Return this entry's addressed byte range as the half-open span
            ``(address, address + len(new_bytes))`` (LLR-001.1).

        Returns:
            tuple[int, int]: The ``(start, end)`` half-open range, ``end``
            exclusive — the span the increment-2 validator tests against the
            loaded image's address ranges.
        """
        return (self.address, self.address + len(self.new_bytes))


class MemoryChangeList:
    """
    Summary:
        An ordered, address-keyed collection of memory-change entries.

    The memory-change list backs the memory half of the Patch Editor:
    ``add`` / ``edit`` / ``remove`` mutate it (LLR-001.2), the ``address`` field
    is the entry identity so a re-add updates in place rather than duplicating
    (LLR-001.3), and ``entries`` exposes a deterministic order (LLR-001.4).

    Ordering is **insertion order**, realised by storing entries in a ``dict``
    keyed on ``address`` — Python 3.7+ dicts are insertion-ordered, so the
    order is stable across iterations and across processes. This mirrors the
    batch-03 ``ChangeList`` exactly, so the increment-5 unified-file writer
    produces byte-identical output from two serializations with no second
    ordering rule.

    Args:
        None: Construct an empty memory-change list.

    Data Flow:
        - ``add`` inserts a new entry or updates an existing address in place.
        - ``edit`` / ``remove`` look an entry up by ``address``.
        - ``entries`` returns the entries in insertion order for display and
          for unified-file serialization.

    Dependencies:
        Uses:
            - MemoryChange
        Used by:
            - The memory-change validator, the unified change-set container,
              and the unified-file writer (later increments).
    """

    def __init__(self) -> None:
        # dict keyed on address; 3.7+ insertion-ordered, which IS the
        # LLR-001.4 deterministic-ordering guarantee.
        self._entries: dict[int, MemoryChange] = {}

    def __len__(self) -> int:
        """Return the number of entries in the memory-change list."""
        return len(self._entries)

    def __contains__(self, address: int) -> bool:
        """Return whether an entry with the given ``address`` exists."""
        return address in self._entries

    @property
    def entries(self) -> list[MemoryChange]:
        """
        Summary:
            Return all entries in deterministic insertion order (LLR-001.4).

        Returns:
            list[MemoryChange]: A new list of the entries, oldest-inserted
            first. The list is a copy — mutating it does not change the
            memory-change list — but the ``MemoryChange`` objects are shared.

        Data Flow:
            - Iterates the insertion-ordered backing ``dict``.

        Dependencies:
            Used by:
                - The unified-file writer (increment 5) for entry ordering.
        """
        return list(self._entries.values())

    def add(
        self,
        address: int,
        new_bytes: Iterable[int],
        status: MemoryStatus = MemoryStatus.UNVALIDATED_NO_IMAGE,
    ) -> MemoryChange:
        """
        Summary:
            Add a memory change, or update it in place if its ``address``
            already exists (LLR-001.2 add, LLR-001.3 dedup).

        Args:
            address (int): Non-negative integer memory start address.
            new_bytes (Iterable[int]): Ordered, non-empty run of byte values
                (0-255 each); coerced to an immutable tuple by ``MemoryChange``.
            status (MemoryStatus): Initial validation status.

        Returns:
            MemoryChange: The entry now held under ``address`` — newly created,
            or the existing entry updated.

        Raises:
            ValueError: Propagated from ``MemoryChange.__post_init__`` if
                ``new_bytes`` is malformed (empty, or a byte outside 0-255).

        Data Flow:
            - If ``address`` is already present, the existing entry's
              ``new_bytes`` and ``status`` are overwritten and its position in
              the insertion order is preserved.
            - Otherwise a new entry is appended at the end of the order.

        Dependencies:
            Uses:
                - MemoryChange

        Example:
            >>> ml = MemoryChangeList()
            >>> ml.add(0x100, [0x01])
            >>> ml.add(0x100, [0x09])  # same address — updates, no duplicate
            >>> [(e.address, e.new_bytes) for e in ml.entries]
            [(256, (9,))]
        """
        # Build the entry first so a malformed run raises before any mutation.
        entry = MemoryChange(address=address, new_bytes=new_bytes, status=status)
        existing = self._entries.get(address)
        if existing is not None:
            # Same identity: update in place, keep insertion position (no
            # duplicate row in the memory-change list — LLR-001.3).
            existing.new_bytes = entry.new_bytes
            existing.status = entry.status
            return existing
        self._entries[address] = entry
        return entry

    def edit(
        self,
        address: int,
        new_bytes: Iterable[int],
        status: MemoryStatus = MemoryStatus.UNVALIDATED_NO_IMAGE,
    ) -> MemoryChange:
        """
        Summary:
            Change the stored bytes of an existing entry identified by its
            ``address`` (LLR-001.2 edit).

        Args:
            address (int): Memory start address of the target entry.
            new_bytes (Iterable[int]): New byte run (0-255 each).
            status (MemoryStatus): Validation status to record on the entry.

        Returns:
            MemoryChange: The updated entry.

        Raises:
            KeyError: If no entry with that ``address`` exists.
            ValueError: Propagated from ``MemoryChange.__post_init__`` if
                ``new_bytes`` is malformed.

        Data Flow:
            - Validates the new run by building a throw-away ``MemoryChange``,
              then overwrites only the target entry's ``new_bytes`` and
              ``status``; its insertion position is untouched.

        Dependencies:
            Uses:
                - MemoryChange
            Used by:
                - The Patch Editor edit action (increment 8).
        """
        entry = self._entries.get(address)
        if entry is None:
            raise KeyError(f"no memory-change entry for address {address}")
        # Validate the run before mutating the live entry.
        validated = MemoryChange(
            address=address, new_bytes=new_bytes, status=status
        )
        entry.new_bytes = validated.new_bytes
        entry.status = validated.status
        return entry

    def remove(self, address: int) -> None:
        """
        Summary:
            Remove the entry identified by its ``address`` (LLR-001.2 remove).

        Args:
            address (int): Memory start address of the target entry.

        Raises:
            KeyError: If no entry with that ``address`` exists.

        Data Flow:
            - Deletes the entry from the backing ``dict``; remaining entries
              keep their relative insertion order.

        Dependencies:
            Used by:
                - The Patch Editor remove action (increment 8).
        """
        try:
            del self._entries[address]
        except KeyError:
            raise KeyError(
                f"no memory-change entry for address {address}"
            ) from None

    def get(self, address: int) -> MemoryChange | None:
        """
        Summary:
            Return the entry identified by ``address``, or ``None`` if it is
            not present.

        Args:
            address (int): Memory start address of the wanted entry.

        Returns:
            MemoryChange | None: The matching entry, or ``None``.
        """
        return self._entries.get(address)
