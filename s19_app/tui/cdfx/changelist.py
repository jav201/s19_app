"""
Parameter change-list model — s19_app batch-03, CDFX increment 1.

The change-list is the central artifact of the Patch Editor: a set of
parameter changes the calibration engineer builds, each entry keyed to an A2L
parameter name and array index (e.g. ``PARAMETER[0] : 23``). This module is
pure data — it does not parse A2L, does not touch XML, and imports no Textual.
Resolution against the A2L (increment 2) and CDFX serialization (increment 4)
are layered on top.

Implements LLR-001.1..LLR-001.4 and the storage half of LLR-003.3.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

# A change-list entry's physical value: an unsigned/signed integer, an IEEE
# float (LLR-004.8 pins the float case as binary64), an ASCII string, or None
# while no value has been entered. No A2L-type validation happens here — that
# is resolution (increment 2).
PhysicalValue = int | float | str | None

# An entry's identity: the (parameter_name, array_index) pair. array_index is
# None for a scalar (VALUE/BOOLEAN) or ASCII-string parameter and an integer k
# for element k of a 1-D array (VAL_BLK) — so (name, None) and (name, 0) are
# distinct identities (LLR-001.1 / LLR-001.3).
EntryKey = tuple[str, int | None]


class ResolutionStatus(str, Enum):
    """
    Summary:
        Resolution state of a change-list entry against the loaded A2L.

    The four states are the verdict the resolution step (increment 2) writes
    onto each entry. ``RESOLVED`` means the entry's parameter name and array
    index matched a loaded A2L parameter; the other three are the documented
    LLR-002.2/002.3/002.4 failure modes. Increment 1 only constructs entries
    with the ``RESOLVED`` default and the ``UNRESOLVED_NO_A2L`` initial state;
    the resolver assigns the rest.

    Members:
        RESOLVED: Name + index matched an A2L parameter.
        UNRESOLVED: Name matched no A2L parameter (LLR-002.2).
        INDEX_OUT_OF_RANGE: Array index outside the A2L element count
            (LLR-002.3).
        UNRESOLVED_NO_A2L: No A2L is loaded, so no entry can resolve
            (LLR-002.4).

    The value of each member is the stable string token used by tests and by
    issue messages; mirrors the ``ValidationSeverity`` ``str``-enum convention.
    """

    RESOLVED = "resolved"
    UNRESOLVED = "unresolved"
    INDEX_OUT_OF_RANGE = "index-out-of-range"
    UNRESOLVED_NO_A2L = "unresolved-no-a2l"


@dataclass(slots=True)
class ChangeListEntry:
    """
    Summary:
        One parameter change: an A2L parameter name, an array index, the
        entered physical value, and a resolution status.

    Args:
        parameter_name (str): A2L parameter (``CHARACTERISTIC``) name — the
            join key against the A2L and the CDFX ``SW-INSTANCE/SHORT-NAME``.
        array_index (Optional[int]): ``None`` for a scalar (``VALUE`` /
            ``BOOLEAN``) or ASCII-string parameter, a non-negative integer
            ``k`` for element ``k`` of a 1-D array (``VAL_BLK``). Defaults to
            ``None``. This is the scalar-vs-array discriminator the CDFX writer
            (increment 6) uses to choose a bare ``V`` / ``VT`` versus a ``VG``.
        value (PhysicalValue): The entered physical value — ``int``, ``float``,
            ``str``, or ``None`` while unset. Stored verbatim; display
            rendering (increment 3) derives hex/ASCII forms without mutating
            it (LLR-003.3).
        status (ResolutionStatus): Resolution verdict against the loaded A2L.
            Defaults to ``UNRESOLVED_NO_A2L`` — an entry is unresolved until
            the resolver (increment 2) runs.

    Returns:
        None: Dataclass container.

    Data Flow:
        - The Patch Editor builds entries via ``ChangeList.add``.
        - Increment 2's resolver reads ``parameter_name``/``array_index`` and
          writes ``status`` (and, later, type metadata).
        - Increment 4's writer reads resolved entries to emit ``SW-INSTANCE``.

    Dependencies:
        Uses:
            - ResolutionStatus
        Used by:
            - ChangeList

    Example:
        >>> ChangeListEntry("IGN_ADVANCE_BASE", value=23).key
        ('IGN_ADVANCE_BASE', None)
    """

    parameter_name: str
    array_index: Optional[int] = None
    value: PhysicalValue = None
    status: ResolutionStatus = ResolutionStatus.UNRESOLVED_NO_A2L

    @property
    def key(self) -> EntryKey:
        """
        Summary:
            Return this entry's identity — the ``(parameter_name,
            array_index)`` pair used for dedup and lookup (LLR-001.3).

        Returns:
            EntryKey: The ``(parameter_name, array_index)`` tuple.
        """
        return (self.parameter_name, self.array_index)


class ChangeList:
    """
    Summary:
        An ordered, identity-keyed collection of parameter change entries.

    The change-list backs the Patch Editor: ``add`` / ``edit`` / ``remove``
    mutate it (LLR-001.2), the ``(parameter_name, array_index)`` pair is the
    entry identity so a re-add updates in place rather than duplicating
    (LLR-001.3), and ``entries`` exposes a deterministic order (LLR-001.4).
    Because ``array_index`` is ``Optional[int]`` (LLR-001.1), ``(name, None)``
    — a scalar/string entry — and ``(name, 0)`` — element 0 of an array — are
    **distinct** identities.

    Ordering is **insertion order**, realised by storing entries in a ``dict``
    keyed on ``(parameter_name, array_index)`` — Python 3.7+ dicts are
    insertion-ordered, so the order is stable across iterations and across
    processes. Increment 4's CDFX writer iterates this same ``entries``
    accessor, so two serializations of the same change-list produce
    byte-identical ``SW-INSTANCE`` order with no second ordering rule.

    Args:
        None: Construct an empty change-list.

    Data Flow:
        - ``add`` inserts a new entry or updates an existing identity.
        - ``edit`` / ``remove`` look up an entry by ``(name, index)``.
        - ``entries`` returns the entries in insertion order for display and
          for CDFX serialization.

    Dependencies:
        Uses:
            - ChangeListEntry
        Used by:
            - The CDFX resolver, writer, and Patch Editor screen (later
              increments).
    """

    def __init__(self) -> None:
        # dict keyed on (parameter_name, array_index); 3.7+ insertion-ordered,
        # which IS the LLR-001.4 deterministic-ordering guarantee.
        self._entries: dict[EntryKey, ChangeListEntry] = {}

    def __len__(self) -> int:
        """Return the number of entries in the change-list."""
        return len(self._entries)

    def __contains__(self, key: EntryKey) -> bool:
        """Return whether an entry with the given ``(name, index)`` exists."""
        return key in self._entries

    @property
    def entries(self) -> list[ChangeListEntry]:
        """
        Summary:
            Return all entries in deterministic insertion order (LLR-001.4).

        Returns:
            list[ChangeListEntry]: A new list of the entries, oldest-inserted
            first. The list is a copy — mutating it does not change the
            change-list — but the ``ChangeListEntry`` objects are shared.

        Data Flow:
            - Iterates the insertion-ordered backing ``dict``.

        Dependencies:
            Used by:
                - The CDFX writer (increment 4) for ``SW-INSTANCE`` ordering.
        """
        return list(self._entries.values())

    def add(
        self,
        parameter_name: str,
        array_index: Optional[int] = None,
        value: PhysicalValue = None,
        status: ResolutionStatus = ResolutionStatus.UNRESOLVED_NO_A2L,
    ) -> ChangeListEntry:
        """
        Summary:
            Add a change entry, or update it in place if its identity already
            exists (LLR-001.2 add, LLR-001.3 dedup).

        Args:
            parameter_name (str): A2L parameter name.
            array_index (Optional[int]): ``None`` for a scalar/string entry,
                an integer ``k`` for element ``k`` of a 1-D array.
            value (PhysicalValue): Physical value to store.
            status (ResolutionStatus): Initial resolution status.

        Returns:
            ChangeListEntry: The entry now held under ``(parameter_name,
            array_index)`` — newly created, or the existing entry updated.

        Data Flow:
            - If ``(parameter_name, array_index)`` is already present, the
              existing entry's ``value`` and ``status`` are overwritten and
              its position in the insertion order is preserved.
            - Otherwise a new entry is appended at the end of the order.

        Dependencies:
            Uses:
                - ChangeListEntry

        Example:
            >>> cl = ChangeList()
            >>> cl.add("PARAM", None, 1)
            >>> cl.add("PARAM", None, 9)  # same identity — updates, no duplicate
            >>> [(e.key, e.value) for e in cl.entries]
            [(('PARAM', None), 9)]
        """
        key: EntryKey = (parameter_name, array_index)
        existing = self._entries.get(key)
        if existing is not None:
            # Same identity: update in place, keep insertion position (no
            # duplicate row in the change-list — LLR-001.3).
            existing.value = value
            existing.status = status
            return existing
        entry = ChangeListEntry(
            parameter_name=parameter_name,
            array_index=array_index,
            value=value,
            status=status,
        )
        self._entries[key] = entry
        return entry

    def edit(
        self,
        parameter_name: str,
        array_index: Optional[int],
        value: PhysicalValue,
    ) -> ChangeListEntry:
        """
        Summary:
            Change the stored value of an existing entry identified by
            ``(parameter_name, array_index)`` (LLR-001.2 edit).

        Args:
            parameter_name (str): A2L parameter name of the target entry.
            array_index (Optional[int]): ``None`` for a scalar/string entry,
                an integer for an array-element entry.
            value (PhysicalValue): New physical value.

        Returns:
            ChangeListEntry: The updated entry.

        Raises:
            KeyError: If no entry with that identity exists.

        Data Flow:
            - Looks the entry up by identity and overwrites only its
              ``value``; ``status`` and insertion position are untouched.

        Dependencies:
            Used by:
                - The Patch Editor edit action (increment 7).
        """
        entry = self._entries.get((parameter_name, array_index))
        if entry is None:
            raise KeyError(
                f"no change-list entry for {parameter_name}[{array_index}]"
            )
        entry.value = value
        return entry

    def remove(self, parameter_name: str, array_index: Optional[int]) -> None:
        """
        Summary:
            Remove the entry identified by ``(parameter_name, array_index)``
            (LLR-001.2 remove).

        Args:
            parameter_name (str): A2L parameter name of the target entry.
            array_index (Optional[int]): ``None`` for a scalar/string entry,
                an integer for an array-element entry.

        Raises:
            KeyError: If no entry with that identity exists.

        Data Flow:
            - Deletes the entry from the backing ``dict``; remaining entries
              keep their relative insertion order.

        Dependencies:
            Used by:
                - The Patch Editor remove action (increment 7).
        """
        try:
            del self._entries[(parameter_name, array_index)]
        except KeyError:
            raise KeyError(
                f"no change-list entry for {parameter_name}[{array_index}]"
            ) from None

    def get(
        self, parameter_name: str, array_index: Optional[int] = None
    ) -> ChangeListEntry | None:
        """
        Summary:
            Return the entry identified by ``(parameter_name, array_index)``,
            or ``None`` if it is not present.

        Args:
            parameter_name (str): A2L parameter name.
            array_index (Optional[int]): ``None`` for a scalar/string entry,
                an integer for an array-element entry.

        Returns:
            ChangeListEntry | None: The matching entry, or ``None``.
        """
        return self._entries.get((parameter_name, array_index))
