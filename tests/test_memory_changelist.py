"""
Memory-field change model tests — s19_app batch-04, increment 1.

Covers the pure memory-change model (``s19_app/tui/cdfx/memory.py``):

  - TC-001 — entry construction (LLR-001.1): an entry holds ``address``,
             ``new_bytes`` and a ``status`` field, preserves byte order and
             length, and exposes its addressed range as the half-open span
             ``(address, address + len(new_bytes))``.
  - TC-002 — add / edit / remove + identity de-duplication (LLR-001.2,
             LLR-001.3): add-then-remove leaves the list empty; edit touches
             only the target entry; a re-add at the same ``address`` updates in
             place with no duplicate.
  - TC-003 — deterministic ordering (LLR-001.4): two passes over ``entries``
             yield identical entry order, so repeated serialization is
             byte-identical.
  - TC-004 — HLR-001 model-coherence roll-up: a list built, edited and queried
             through the model API reports a consistent entry set.
  - TC-008 (ValueError arms only) — malformed ``new_bytes`` rejected at
             construction (LLR-002.5): a byte of ``256``, a negative byte, or
             an empty run each raises ``ValueError``. TC-008's overlap arm is
             increment 2.

These tests encode WHY each behaviour matters: the addressed-range derivation
backs the increment-2 range validator, the identity rule backs one
authoritative entry per address, and the deterministic order backs reproducible
unified-file serialization. A field rename, an ordering change, or a dropped
construction-time check fails the matching test.
"""

from __future__ import annotations

import pytest

from s19_app.tui.cdfx import MemoryChange, MemoryChangeList, MemoryStatus

from tests.conftest import MEMORY_OVERLAP_PAIR, memory_change_factory


# ---------------------------------------------------------------------------
# TC-001 — entry construction (LLR-001.1)
# ---------------------------------------------------------------------------


def test_tc001_entry_reports_its_fields() -> None:
    """A memory-change entry reports its documented fields (LLR-001.1).

    LLR-001.1 requires the entry to hold an ``address``, a ``new_bytes`` run
    and a validation-status field; this asserts each is readable as constructed
    so a field rename or drop fails the test.
    """
    entry = MemoryChange(
        address=0x100,
        new_bytes=[0x01, 0x02, 0x03],
        status=MemoryStatus.INSIDE,
    )

    assert entry.address == 0x100
    assert entry.new_bytes == (0x01, 0x02, 0x03)
    assert entry.status is MemoryStatus.INSIDE


def test_tc001_status_defaults_to_unvalidated_no_image() -> None:
    """A freshly-built entry is ``unvalidated-no-image`` (LLR-001.1 / A-2).

    An entry is buildable before any image is loaded; until the increment-2
    validator runs it carries the default ``UNVALIDATED_NO_IMAGE`` status,
    mirroring the batch-03 ``unresolved-no-a2l`` pattern.
    """
    entry = MemoryChange(address=0x10, new_bytes=[0xFF])

    assert entry.status is MemoryStatus.UNVALIDATED_NO_IMAGE


def test_tc001_new_bytes_preserves_order_and_length() -> None:
    """The byte run preserves order and length (LLR-001.1 acceptance).

    The stored bytes are the source of truth for display and serialization, so
    the run must round-trip its exact ordered contents and count.
    """
    run = [0x10, 0x00, 0xAB, 0x10]
    entry = MemoryChange(address=0x4000, new_bytes=run)

    assert entry.new_bytes == (0x10, 0x00, 0xAB, 0x10)
    assert len(entry.new_bytes) == len(run)


def test_tc001_new_bytes_is_stored_as_an_immutable_tuple() -> None:
    """``new_bytes`` is stored as an immutable tuple (LLR-001.1 / LLR-003.3).

    Storing the run as a ``tuple`` is what lets the increment-3 display layer
    derive hex/ASCII/decimal forms with no risk of mutating the stored bytes;
    this pins the storage type so a regression to a mutable ``list`` fails.
    """
    entry = MemoryChange(address=0x100, new_bytes=[0x41, 0x42])

    assert isinstance(entry.new_bytes, tuple)


def test_tc001_addressed_range_is_the_half_open_span() -> None:
    """The entry exposes ``(address, address + len)`` (LLR-001.1 acceptance).

    The addressed range is the span the increment-2 validator tests against the
    loaded image's ranges; it must be the half-open ``(start, end)`` pair with
    ``end`` exclusive.
    """
    entry = MemoryChange(address=0x100, new_bytes=[0x41, 0x42])

    assert entry.addressed_range == (0x100, 0x102)


# ---------------------------------------------------------------------------
# TC-002 — add / edit / remove + identity de-duplication (LLR-001.2, LLR-001.3)
# ---------------------------------------------------------------------------


def test_tc002_add_then_remove_leaves_the_list_empty() -> None:
    """Adding then removing the same address leaves the list empty (LLR-001.2).

    The acceptance criterion is explicit: add then remove the same address ->
    empty list. This pins ``remove`` as the inverse of ``add``.
    """
    ml = MemoryChangeList()
    ml.add(0x100, [0x01, 0x02])
    assert len(ml) == 1

    ml.remove(0x100)

    assert len(ml) == 0
    assert ml.get(0x100) is None


def test_tc002_edit_touches_only_the_target_entry() -> None:
    """Editing one entry changes only that entry's bytes (LLR-001.2).

    LLR-001.2 requires ``edit`` to be surgical; this asserts a sibling entry's
    bytes are untouched so a broadcast bug is caught.
    """
    ml = MemoryChangeList()
    ml.add(0x100, [0x01])
    ml.add(0x200, [0x02])

    ml.edit(0x100, [0xAA, 0xBB])

    assert ml.get(0x100).new_bytes == (0xAA, 0xBB)
    assert ml.get(0x200).new_bytes == (0x02,)


def test_tc002_readd_same_address_updates_in_place_no_duplicate() -> None:
    """A re-add at the same address updates in place (LLR-001.3).

    The acceptance criterion: adding the same address twice yields one entry
    carrying the latest bytes — the address is the entry identity, so the
    second add must not create a duplicate row.
    """
    ml = MemoryChangeList()
    ml.add(0x100, [0x01])
    ml.add(0x100, [0x09, 0x0A])

    assert len(ml) == 1
    assert ml.get(0x100).new_bytes == (0x09, 0x0A)


def test_tc002_readd_preserves_insertion_position() -> None:
    """A re-add keeps the entry's insertion position (LLR-001.3 / LLR-001.4).

    Updating in place must not move the entry to the end of the order, or
    repeated serialization would not be byte-identical after an edit.
    """
    ml = MemoryChangeList()
    ml.add(0x100, [0x01])
    ml.add(0x200, [0x02])
    ml.add(0x100, [0x09])  # re-add of the first entry

    assert [e.address for e in ml.entries] == [0x100, 0x200]


def test_tc002_edit_missing_address_raises_keyerror() -> None:
    """Editing an absent address raises ``KeyError`` (LLR-001.2 contract).

    ``edit`` targets an existing identity; addressing a non-existent entry is a
    caller error, surfaced as ``KeyError`` exactly as ``ChangeList.edit`` does.
    """
    ml = MemoryChangeList()

    with pytest.raises(KeyError):
        ml.edit(0xDEAD, [0x00])


def test_tc002_remove_missing_address_raises_keyerror() -> None:
    """Removing an absent address raises ``KeyError`` (LLR-001.2 contract).

    ``remove`` targets an existing identity; a missing address is a caller
    error, surfaced as ``KeyError`` — mirrors ``ChangeList.remove``.
    """
    ml = MemoryChangeList()

    with pytest.raises(KeyError):
        ml.remove(0xDEAD)


# ---------------------------------------------------------------------------
# TC-003 — deterministic ordering (LLR-001.4)
# ---------------------------------------------------------------------------


def test_tc003_two_serializations_have_identical_entry_order() -> None:
    """Two passes over ``entries`` yield identical order (LLR-001.4).

    ``entries`` is the accessor the increment-5 unified-file writer iterates;
    if its order were not deterministic, two serializations of the same list
    would differ byte-for-byte. The model pins **insertion order** (the same
    guarantee batch-03 ``ChangeList`` gives), so two reads must match.
    """
    ml = MemoryChangeList()
    ml.add(0x300, [0x03])
    ml.add(0x100, [0x01])
    ml.add(0x200, [0x02])

    first = [e.address for e in ml.entries]
    second = [e.address for e in ml.entries]

    assert first == second
    # Pins the chosen rule: insertion order, NOT ascending address.
    assert first == [0x300, 0x100, 0x200]


def test_tc003_entries_is_a_copy_not_the_backing_store() -> None:
    """``entries`` returns a fresh list each call (LLR-001.4 robustness).

    Mutating the returned list must not corrupt the memory-change list, or a
    caller iterating it could silently change the serialization order.
    """
    ml = MemoryChangeList()
    ml.add(0x100, [0x01])

    snapshot = ml.entries
    snapshot.clear()

    assert len(ml) == 1


# ---------------------------------------------------------------------------
# TC-004 — HLR-001 model-coherence roll-up (LLR-001.1, LLR-001.2)
# ---------------------------------------------------------------------------


def test_tc004_built_edited_queried_list_is_consistent() -> None:
    """A built/edited/queried list reports a consistent entry set (HLR-001).

    The HLR-001 roll-up: exercise the whole model API — build via the factory,
    edit one entry, remove another, add a fresh one — and assert the final
    entry set is exactly what those operations imply, with each entry's fields
    coherent.
    """
    ml = memory_change_factory()
    assert len(ml) == 3  # 0x200 + the two overlap-pair entries

    ml.edit(0x200, [0x11, 0x22])
    ml.remove(0x104)
    ml.add(0x500, [0x55])

    addresses = [e.address for e in ml.entries]
    assert addresses == [0x200, 0x100, 0x500]
    assert ml.get(0x200).new_bytes == (0x11, 0x22)
    assert ml.get(0x104) is None
    assert ml.get(0x500).new_bytes == (0x55,)


def test_tc004_factory_overlap_pair_stays_two_distinct_entries() -> None:
    """The factory's overlap pair is two entries, not one (LLR-001.3 / Q-03).

    The overlap pair is pinned at distinct start addresses (0x100, 0x104) so
    the identity rule does not collapse it — this is the precondition for the
    increment-2 overlap-warning test to provoke anything at all.
    """
    ml = memory_change_factory()

    (addr_a, len_a), (addr_b, len_b) = MEMORY_OVERLAP_PAIR
    assert addr_a != addr_b
    assert ml.get(addr_a) is not None
    assert ml.get(addr_b) is not None
    # The two addressed ranges genuinely intersect.
    assert ml.get(addr_a).addressed_range[1] > addr_b
    assert ml.get(addr_b).addressed_range[0] < ml.get(addr_a).addressed_range[1]


# ---------------------------------------------------------------------------
# TC-008 — malformed-new_bytes rejection, ValueError arms only (LLR-002.5)
#
# The overlap arm of TC-008 is increment 2 (it needs the loaded-image
# validator). Increment 1 covers the three construction-time ValueError arms.
# ---------------------------------------------------------------------------


def test_tc008_byte_value_256_raises_valueerror() -> None:
    """A byte value of 256 is rejected at construction (LLR-002.5).

    LLR-002.5 names "a byte value greater than 255" as a malformed run; 256 is
    the boundary case and must raise ``ValueError`` — not be collected as a
    ``ValidationIssue``, which is the opposite (collect-don't-abort) semantics.
    """
    with pytest.raises(ValueError):
        MemoryChange(address=0x100, new_bytes=[0x01, 256, 0x03])


def test_tc008_negative_byte_value_raises_valueerror() -> None:
    """A negative byte value is rejected at construction (LLR-002.5).

    LLR-002.5 names "a byte value that is negative" explicitly, so this
    assertion traces to an exact normative phrase (the Q-02 traceability fix).
    """
    with pytest.raises(ValueError):
        MemoryChange(address=0x100, new_bytes=[0x01, -1, 0x03])


def test_tc008_empty_new_bytes_run_raises_valueerror() -> None:
    """An empty ``new_bytes`` run is rejected at construction (LLR-002.5).

    LLR-002.5 names "an empty run" — an entry with no bytes does not describe a
    recordable edit intent, so construction must raise ``ValueError``.
    """
    with pytest.raises(ValueError):
        MemoryChange(address=0x100, new_bytes=[])


def test_tc008_malformed_run_also_rejected_via_changelist_add() -> None:
    """``MemoryChangeList.add`` propagates the malformed-run ``ValueError``.

    The rejection must hold on the collection's ``add`` path too — a malformed
    run entered through the Patch Editor must never land a half-built entry in
    the list; ``add`` builds the entry before mutating, so it raises and the
    list stays empty.
    """
    ml = MemoryChangeList()

    with pytest.raises(ValueError):
        ml.add(0x100, [256])

    assert len(ml) == 0


def test_tc008_malformed_run_rejected_via_changelist_edit() -> None:
    """``MemoryChangeList.edit`` rejects a malformed run without corrupting.

    An edit that supplies a malformed run must raise ``ValueError`` and leave
    the target entry's existing bytes intact — the edit validates before it
    mutates the live entry.
    """
    ml = MemoryChangeList()
    ml.add(0x100, [0x01, 0x02])

    with pytest.raises(ValueError):
        ml.edit(0x100, [-1])

    assert ml.get(0x100).new_bytes == (0x01, 0x02)
