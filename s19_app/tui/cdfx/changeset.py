"""
Unified change-set container — s19_app batch-04, increment 4.

The unified change-set is the single in-app container that holds **both** the
batch-03 parameter ``ChangeList`` and the batch-04 ``MemoryChangeList`` — the
two distinct change kinds the Patch Editor records. Holding both behind one
container is what makes one save, one load and one screen possible for the
whole patch set, while keeping the two halves separate is what makes selective
export (a CDFX file for the parameter half, a JSON file for the memory-field
half) possible.

This module is **pure data**: it does not parse JSON, does not touch XML, and
imports no Textual. The unified-file writer (increment 5), reader (increment 6)
and selective-export coordinator (increment 7) are layered on top.

``UnifiedChangeSet`` **composes** the two list types — it holds a ``ChangeList``
and a ``MemoryChangeList`` as two distinct member attributes — and does **not**
subclass either of them, nor ``dict`` (constraint C-3 / LLR-004.2). The
parameter half is a plain batch-03 ``ChangeList`` carrying no
``ResolutionResult``: resolution against the loaded A2L is a transient,
export-time computation, never part of the container (LLR-004.1, A-7).

Implements LLR-004.1..LLR-004.5.
"""

from __future__ import annotations

from .changelist import ChangeList
from .memory import MemoryChangeList


class UnifiedChangeSet:
    """
    Summary:
        One in-app container holding both the parameter ``ChangeList`` and the
        memory-field ``MemoryChangeList`` of a patch set.

    The container exposes each half as a distinct attribute (``parameters`` /
    ``memory``) for independent inspection and mutation, reports the per-half
    entry counts separately, and answers whether the whole set is empty. It is
    a **thin container**: it adds no validation, no I/O and no merging logic —
    those concerns are the unified-file writer/reader and the selective-export
    coordinator (increments 5-7).

    The two halves are held by **composition**, not inheritance:
    ``UnifiedChangeSet`` is not a subclass of ``ChangeList``,
    ``MemoryChangeList`` or ``dict`` (constraint C-3 / LLR-004.2). All mutation
    goes through each half's own ``add`` / ``edit`` / ``remove`` API, so a
    mutation of one half never touches the other (LLR-004.3).

    Args:
        None: Construct an empty unified change-set — an empty ``ChangeList``
            and an empty ``MemoryChangeList``.

    Data Flow:
        - ``__init__`` builds one empty ``ChangeList`` and one empty
          ``MemoryChangeList`` and binds them to the ``parameters`` and
          ``memory`` attributes.
        - Callers mutate each half directly through its own API.
        - ``counts`` and ``is_empty`` read the two halves' lengths.

    Dependencies:
        Uses:
            - ChangeList
            - MemoryChangeList
        Used by:
            - The unified-file writer / reader and the selective-export
              coordinator (later increments); the Patch Editor service.

    Example:
        >>> cs = UnifiedChangeSet()
        >>> cs.is_empty()
        True
        >>> cs.memory.add(0x100, [0x01])
        >>> cs.parameters.add("IGN_ADVANCE_BASE", None, 23)
        >>> cs.counts()
        (1, 1)
        >>> cs.is_empty()
        False
    """

    def __init__(self) -> None:
        # Two distinct member attributes — composition, not subclassing
        # (constraint C-3 / LLR-004.2). The parameter half is a plain
        # ChangeList with no ResolutionResult (LLR-004.1).
        self.parameters: ChangeList = ChangeList()
        self.memory: MemoryChangeList = MemoryChangeList()

    def counts(self) -> tuple[int, int]:
        """
        Summary:
            Report the parameter-half and memory-field-half entry counts
            separately (LLR-004.4).

        Returns:
            tuple[int, int]: A ``(parameter_count, memory_count)`` pair — the
            number of entries in the parameter ``ChangeList`` first, the number
            of entries in the ``MemoryChangeList`` second. The two counts are
            never summed or merged.

        Data Flow:
            - Reads ``len(self.parameters)`` and ``len(self.memory)``.

        Example:
            >>> cs = UnifiedChangeSet()
            >>> cs.counts()
            (0, 0)
        """
        return (len(self.parameters), len(self.memory))

    def is_empty(self) -> bool:
        """
        Summary:
            Report whether the unified change-set is empty — both halves hold
            zero entries (LLR-004.5).

        Returns:
            bool: ``True`` when the parameter half and the memory-field half
            both have zero entries; ``False`` if either half holds at least
            one entry.

        Data Flow:
            - Reads both half lengths and returns whether their total is zero.

        Example:
            >>> cs = UnifiedChangeSet()
            >>> cs.is_empty()
            True
            >>> cs.memory.add(0x100, [0x01])
            >>> cs.is_empty()
            False
        """
        parameter_count, memory_count = self.counts()
        return parameter_count == 0 and memory_count == 0
