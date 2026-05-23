"""
CDFX change-list model tests — s19_app batch-03, increment 1 (migrated by
increment 5 to the ``Optional[int]`` ``array_index`` contract).

Covers the pure change-list model (``s19_app/tui/cdfx/changelist.py``):

  - TC-001 — entry construction (LLR-001.1): a scalar and an ASCII entry each
             carry ``array_index is None``; an array-element entry carries an
             integer index; ``(name, None)`` and ``(name, 0)`` are distinct.
  - TC-002 — add / edit / remove + identity de-duplication (LLR-001.2,
             LLR-001.3), including that a scalar ``(name, None)`` and array
             element ``(name, 0)`` are distinct dedup keys.
  - TC-003 — deterministic ordering, model arm (LLR-001.4). The "byte-identical
             ``SW-INSTANCE`` order" verdict is re-asserted through the real
             writer in increment 6; here the stand-in for "serialization" is
             the model's ordered ``entries`` accessor.
  - TC-010 — physical-value storage arm (LLR-003.3). The display-derivation
             half (with ``format_value``) is completed in increment 3.

The ``change_list_factory`` helper this module formerly defined was relocated
to ``tests/conftest.py`` by increment 10 (its adversarial-float arm landed
there too), so the writer / round-trip CDFX modules share one builder; this
module now imports it.
"""

from __future__ import annotations

from s19_app.tui.cdfx import ChangeList, ChangeListEntry, ResolutionStatus

from tests.conftest import change_list_factory


# ---------------------------------------------------------------------------
# TC-001 — entry construction (LLR-001.1)
# ---------------------------------------------------------------------------


def test_tc001_array_element_entry_reports_its_four_fields() -> None:
    """An array-element entry reports all four documented fields (LLR-001.1).

    LLR-001.1 requires the entry to hold ``parameter_name``, ``array_index``,
    ``value`` and a resolution-status field; an array-element entry carries an
    integer index, so this asserts each field is readable as constructed and a
    field rename or drop fails the test.
    """
    entry = ChangeListEntry(
        parameter_name="PARAM",
        array_index=2,
        value=23,
        status=ResolutionStatus.RESOLVED,
    )

    assert entry.parameter_name == "PARAM"
    assert entry.array_index == 2
    assert entry.value == 23
    assert entry.status is ResolutionStatus.RESOLVED


def test_tc001_scalar_entry_carries_array_index_none() -> None:
    """A scalar entry carries ``array_index is None`` (LLR-001.1 acceptance).

    The migrated contract: ``None`` means "not an array element". A scalar
    parameter must default to ``None``, not ``0`` — ``0`` now means array
    element 0, which the writer must serialize as a ``VAL_BLK``, not a scalar.
    """
    entry = ChangeListEntry(parameter_name="SCALAR_PARAM")

    assert entry.array_index is None
    assert entry.value is None
    assert entry.key == ("SCALAR_PARAM", None)


def test_tc001_ascii_string_entry_carries_array_index_none() -> None:
    """An ASCII-string entry carries ``array_index is None`` (LLR-001.1).

    LLR-001.1 makes ``None`` cover both the scalar (``VALUE`` / ``BOOLEAN``)
    case and the ASCII-string case — an ASCII parameter is one CDFX ``VT``, not
    an array — so a string entry built without an index resolves on name alone.
    """
    entry = ChangeListEntry(parameter_name="CAL_LABEL", value="REV_C")

    assert entry.array_index is None
    assert entry.key == ("CAL_LABEL", None)


def test_tc001_entry_key_is_name_index_pair() -> None:
    """The entry identity is the ``(parameter_name, array_index)`` pair.

    LLR-001.3 makes this pair the identity used for dedup; the test pins the
    ``key`` property so the identity definition cannot drift silently.
    """
    assert ChangeListEntry("P", 3).key == ("P", 3)


def test_tc001_scalar_and_array_element_zero_are_distinct_identities() -> None:
    """``(name, None)`` and ``(name, 0)`` are distinct identities (LLR-001.3).

    The whole point of the ``Optional[int]`` migration: a scalar entry and
    element 0 of an array under the same name are different rows, so the writer
    can pick a scalar ``VALUE`` versus a ``VAL_BLK``. If the two collapsed, the
    iteration-3 scalar-vs-array ambiguity would still be present.
    """
    scalar_key = ChangeListEntry("P", None).key
    element_zero_key = ChangeListEntry("P", 0).key

    assert scalar_key == ("P", None)
    assert element_zero_key == ("P", 0)
    assert scalar_key != element_zero_key


# ---------------------------------------------------------------------------
# TC-002 — add / edit / remove + identity de-duplication (LLR-001.2, 001.3)
# ---------------------------------------------------------------------------


def test_tc002_add_then_remove_leaves_list_empty() -> None:
    """Adding then removing the same key leaves the change-list empty.

    LLR-001.2 acceptance: ``remove`` must actually drop the entry, not merely
    blank it — an emptied list is the precondition for the empty-state UI.
    """
    cl = ChangeList()
    cl.add("PARAM", None, 1, ResolutionStatus.RESOLVED)
    assert len(cl) == 1

    cl.remove("PARAM", None)

    assert len(cl) == 0
    assert cl.entries == []
    assert ("PARAM", None) not in cl


def test_tc002_edit_changes_only_the_targeted_entry() -> None:
    """Editing one entry changes only that entry's value (LLR-001.2).

    The test holds a second untouched entry so a wrongly broad edit (e.g. one
    that overwrites every entry) would be caught — the test fails if the edit
    is not surgical.
    """
    cl = ChangeList()
    cl.add("A", None, 10, ResolutionStatus.RESOLVED)
    cl.add("B", None, 20, ResolutionStatus.RESOLVED)

    cl.edit("A", None, 99)

    assert cl.get("A").value == 99
    assert cl.get("B").value == 20  # untouched neighbour


def test_tc002_edit_preserves_resolution_status() -> None:
    """Editing a value does not reset the entry's resolution status.

    The change-list stores the resolver's verdict on ``status``; an edit
    changes only the physical value. If ``edit`` clobbered ``status`` the
    resolved/unresolved colour state would silently regress.
    """
    cl = ChangeList()
    cl.add("A", None, 10, ResolutionStatus.RESOLVED)

    cl.edit("A", None, 11)

    assert cl.get("A").status is ResolutionStatus.RESOLVED


def test_tc002_adding_same_scalar_key_twice_yields_one_updated_entry() -> None:
    """Adding a scalar ``PARAM`` twice yields one entry with the latest value.

    LLR-001.3 dedup: the second ``add`` on an existing identity updates in
    place rather than creating a duplicate row. A duplicate would be written
    as two ``SW-INSTANCE`` elements for the same parameter.
    """
    cl = ChangeList()
    cl.add("PARAM", None, 1, ResolutionStatus.RESOLVED)
    cl.add("PARAM", None, 9, ResolutionStatus.RESOLVED)

    assert len(cl) == 1
    assert cl.get("PARAM").value == 9


def test_tc002_dedup_distinguishes_array_index() -> None:
    """``PARAM[0]`` and ``PARAM[1]`` are distinct identities, not duplicates.

    Identity is the full ``(name, index)`` pair: two elements of the same 1-D
    array must coexist. A name-only identity would wrongly collapse them.
    """
    cl = ChangeList()
    cl.add("PARAM", 0, 1, ResolutionStatus.RESOLVED)
    cl.add("PARAM", 1, 2, ResolutionStatus.RESOLVED)

    assert len(cl) == 2
    assert cl.get("PARAM", 0).value == 1
    assert cl.get("PARAM", 1).value == 2


def test_tc002_dedup_distinguishes_scalar_none_from_array_element_zero() -> None:
    """A scalar ``(PARAM, None)`` and array element ``(PARAM, 0)`` coexist.

    LLR-001.3: with ``array_index`` now ``Optional[int]``, ``(name, None)`` and
    ``(name, 0)`` are distinct identities. The dedup ``dict`` must keep both
    rows — collapsing them would re-introduce the iteration-3 scalar-vs-array
    ambiguity the migration exists to remove. (The two never legitimately
    coexist for one real A2L parameter; the model still keeps them separate.)
    """
    cl = ChangeList()
    cl.add("PARAM", None, 1, ResolutionStatus.RESOLVED)
    cl.add("PARAM", 0, 2, ResolutionStatus.RESOLVED)

    assert len(cl) == 2
    assert cl.get("PARAM", None).value == 1
    assert cl.get("PARAM", 0).value == 2


def test_tc002_edit_missing_entry_raises_keyerror() -> None:
    """Editing a non-existent identity raises ``KeyError``, not a silent no-op.

    ``edit`` is a targeted operation; a missing target is a caller error the
    Patch Editor must surface, so it must fail loudly rather than do nothing.
    """
    cl = ChangeList()
    try:
        cl.edit("MISSING", None, 1)
    except KeyError:
        pass
    else:  # pragma: no cover - failure path
        raise AssertionError("edit on a missing entry must raise KeyError")


def test_tc002_remove_missing_entry_raises_keyerror() -> None:
    """Removing a non-existent identity raises ``KeyError``, not a silent no-op."""
    cl = ChangeList()
    try:
        cl.remove("MISSING", None)
    except KeyError:
        pass
    else:  # pragma: no cover - failure path
        raise AssertionError("remove on a missing entry must raise KeyError")


# ---------------------------------------------------------------------------
# TC-003 — deterministic ordering, model arm (LLR-001.4)
# ---------------------------------------------------------------------------


def test_tc003_repeated_iteration_yields_identical_order() -> None:
    """Two iterations of the same change-list produce identical entry order.

    LLR-001.4 requires deterministic ordering so increment 4's writer emits
    byte-identical ``SW-INSTANCE`` order on repeated writes. The model arm of
    that verdict is: the ``entries`` accessor is stable across iterations.
    """
    cl = change_list_factory()

    first = [e.key for e in cl.entries]
    second = [e.key for e in cl.entries]

    assert first == second


def test_tc003_ordering_is_insertion_order() -> None:
    """Entry order is insertion order — the pinned LLR-001.4 ordering rule.

    The rule is pinned (not sorted-by-name) so increment 4's writer can
    reproduce it by iterating the same ``entries`` accessor with no second
    ordering rule. A switch to sorted order would fail this test.
    """
    cl = ChangeList()
    cl.add("ZEBRA", None, 1, ResolutionStatus.RESOLVED)
    cl.add("ALPHA", None, 2, ResolutionStatus.RESOLVED)
    cl.add("MIKE", None, 3, ResolutionStatus.RESOLVED)

    assert [e.parameter_name for e in cl.entries] == ["ZEBRA", "ALPHA", "MIKE"]


def test_tc003_in_place_update_preserves_insertion_position() -> None:
    """A re-add (dedup update) keeps the entry at its original position.

    If a dedup update moved the entry to the end, repeated edits would reorder
    the change-list and break the byte-identical-write guarantee.
    """
    cl = ChangeList()
    cl.add("FIRST", None, 1, ResolutionStatus.RESOLVED)
    cl.add("SECOND", None, 2, ResolutionStatus.RESOLVED)
    cl.add("THIRD", None, 3, ResolutionStatus.RESOLVED)

    cl.add("FIRST", None, 99, ResolutionStatus.RESOLVED)  # update, not append

    assert [e.parameter_name for e in cl.entries] == ["FIRST", "SECOND", "THIRD"]


# ---------------------------------------------------------------------------
# TC-010 — physical-value storage arm (LLR-003.3)
# ---------------------------------------------------------------------------


def test_tc010_stored_value_equals_entered_physical_value() -> None:
    """The stored value equals the entered physical value, byte-for-byte.

    LLR-003.3: the change-list stores the *physical* value; the model must not
    transform it on the way in. Display rendering (increment 3) derives hex /
    ASCII forms separately and does not alter the stored value.
    """
    cl = ChangeList()
    cl.add("INT_PARAM", None, 23, ResolutionStatus.RESOLVED)
    cl.add("FLOAT_PARAM", None, 12.5, ResolutionStatus.RESOLVED)
    cl.add("STR_PARAM", None, "REV_C", ResolutionStatus.RESOLVED)

    assert cl.get("INT_PARAM").value == 23
    assert cl.get("FLOAT_PARAM").value == 12.5
    assert cl.get("STR_PARAM").value == "REV_C"


def test_tc010_value_accepts_int_float_str_and_none() -> None:
    """The ``value`` field carries ``int`` / ``float`` / ``str`` / ``None``.

    The increment plan pins ``value`` as ``int | float | str | None`` — no A2L
    type validation in increment 1. This test exercises every arm of that
    union so an over-narrow type contract is caught.
    """
    cl = ChangeList()
    cl.add("AS_INT", None, 7, ResolutionStatus.RESOLVED)
    cl.add("AS_FLOAT", None, 0.5, ResolutionStatus.RESOLVED)
    cl.add("AS_STR", None, "txt", ResolutionStatus.RESOLVED)
    cl.add("AS_NONE")  # value unset

    assert isinstance(cl.get("AS_INT").value, int)
    assert isinstance(cl.get("AS_FLOAT").value, float)
    assert isinstance(cl.get("AS_STR").value, str)
    assert cl.get("AS_NONE").value is None


def test_tc010_edit_replaces_physical_value_verbatim() -> None:
    """An edit replaces the stored physical value verbatim, no transform.

    Re-asserts the storage invariant across the ``edit`` path: the value
    written is the value read back, unchanged.
    """
    cl = ChangeList()
    cl.add("P", None, 1, ResolutionStatus.RESOLVED)

    cl.edit("P", None, 255)

    assert cl.get("P").value == 255
