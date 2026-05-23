"""
Unified change-set container tests — s19_app batch-04, increment 4.

Covers the pure unified change-set container
(``s19_app/tui/cdfx/changeset.py``):

  - TC-012 — the container holds both halves (LLR-004.1): a ``UnifiedChangeSet``
             exposes its parameter ``ChangeList`` and its ``MemoryChangeList``
             as two distinct, independently accessible attributes; the
             parameter half carries no ``ResolutionResult``.
  - TC-013 — independent mutation, per-half counts, empty-state (LLR-004.3,
             LLR-004.4, LLR-004.5): mutating one half leaves the other
             unchanged; an empty container reports counts ``(0, 0)`` and
             reports empty; after two memory + one parameter change the counts
             are ``(1, 2)`` and the container does not report empty.
  - TC-026 — the container composes the two existing list types, it does not
             subclass them (LLR-004.1, LLR-004.2 / constraint C-3): the
             parameter half is an instance of the batch-03 ``ChangeList`` held
             by composition, the memory half a ``MemoryChangeList``, and
             ``UnifiedChangeSet`` is not a subclass of ``ChangeList``,
             ``MemoryChangeList`` or ``dict`` — the runtime corroboration of
             the TC-027 byte-unchanged inspection clause.

These tests encode WHY each behaviour matters: per-half access and independent
mutation back the one-screen / one-save patch set; the compose-not-subclass
check backs constraint C-3, which keeps the batch-03 ``changelist.py``
byte-unchanged and the CDFX format contract stable. A merged container, a
shared backing store, or a subclassing refactor fails the matching test.
"""

from __future__ import annotations

from s19_app.tui.cdfx import (
    ChangeList,
    MemoryChangeList,
    ResolutionStatus,
    UnifiedChangeSet,
)

from tests.conftest import unified_changeset_factory


# ---------------------------------------------------------------------------
# TC-012 — the container holds both halves (LLR-004.1)
# ---------------------------------------------------------------------------


def test_tc012_exposes_parameter_and_memory_halves_as_distinct_attributes() -> None:
    """A ``UnifiedChangeSet`` exposes both halves as distinct attributes (LLR-004.1).

    LLR-004.1 requires one parameter ``ChangeList`` and one
    ``MemoryChangeList`` held as distinct attributes for independent access;
    this asserts each accessor exists, is the right type, and the two are not
    the same object — so a merged or single-store container fails the test.
    """
    changeset = UnifiedChangeSet()

    assert isinstance(changeset.parameters, ChangeList)
    assert isinstance(changeset.memory, MemoryChangeList)
    # The two halves are distinct objects, not aliases of one backing store.
    assert changeset.parameters is not changeset.memory


def test_tc012_each_half_is_independently_accessible() -> None:
    """Each half is reachable and usable on its own (LLR-004.1).

    LLR-004.1's "independent access" clause means a caller can read and mutate
    either half through its own API without going through the other; this
    asserts a populated container surfaces each half's entries separately.
    """
    changeset = unified_changeset_factory()

    # The parameter half is reachable as a ChangeList and lists its entries.
    parameter_names = [e.parameter_name for e in changeset.parameters.entries]
    assert "IGN_ADVANCE_BASE" in parameter_names

    # The memory half is reachable as a MemoryChangeList and lists its entries.
    memory_addresses = [e.address for e in changeset.memory.entries]
    assert memory_addresses == [0x200, 0x100, 0x104]


def test_tc012_parameter_half_carries_no_resolution_result() -> None:
    """The parameter half is a plain ``ChangeList``, resolution-free (LLR-004.1).

    LLR-004.1 pins the parameter half as a plain batch-03 ``ChangeList`` that
    carries no ``ResolutionResult`` — resolution is a transient export-time
    computation (A-7). This asserts the half is exactly a ``ChangeList`` and
    exposes no resolution-result attribute, so a future container that smuggles
    resolution state into the parameter half fails the test.
    """
    changeset = UnifiedChangeSet()

    assert type(changeset.parameters) is ChangeList
    assert not hasattr(changeset.parameters, "resolution_result")
    assert not hasattr(changeset.parameters, "resolved_types")


# ---------------------------------------------------------------------------
# TC-013 — independent mutation, per-half counts, empty-state
#          (LLR-004.3, LLR-004.4, LLR-004.5)
# ---------------------------------------------------------------------------


def test_tc013_empty_container_reports_zero_counts_and_empty() -> None:
    """An empty container reports ``(0, 0)`` and reports empty (LLR-004.4/5).

    LLR-004.4 requires per-half counts and LLR-004.5 an empty-state query;
    this asserts the empty baseline so a count or empty-state defect surfaces
    before any mutation.
    """
    changeset = UnifiedChangeSet()

    assert changeset.counts() == (0, 0)
    assert changeset.is_empty() is True


def test_tc013_mutating_memory_half_leaves_parameter_half_unchanged() -> None:
    """Adding a memory change does not alter the parameter half (LLR-004.3).

    LLR-004.3's independence clause is what lets the two change kinds be edited
    side by side; this asserts a memory-half mutation leaves the parameter
    half's entry set byte-identical, so a shared-store regression fails here.
    """
    changeset = UnifiedChangeSet()
    parameter_snapshot = list(changeset.parameters.entries)

    changeset.memory.add(0x100, [0x01, 0x02])

    assert list(changeset.parameters.entries) == parameter_snapshot
    assert len(changeset.parameters) == 0
    assert len(changeset.memory) == 1


def test_tc013_mutating_parameter_half_leaves_memory_half_unchanged() -> None:
    """Adding a parameter change does not alter the memory half (LLR-004.3).

    The mirror of the previous case: a parameter-half mutation must leave the
    memory half untouched, so the independence guarantee holds in both
    directions.
    """
    changeset = UnifiedChangeSet()
    memory_snapshot = list(changeset.memory.entries)

    changeset.parameters.add("IGN_ADVANCE_BASE", None, 23)

    assert list(changeset.memory.entries) == memory_snapshot
    assert len(changeset.memory) == 0
    assert len(changeset.parameters) == 1


def test_tc013_per_half_counts_and_empty_state_after_mutation() -> None:
    """After two memory + one parameter change counts are ``(1, 2)`` (LLR-004.4/5).

    LLR-004.4 requires the counts reported per half (parameter first), and
    LLR-004.5 requires the populated container to not report empty; this
    pins the exact ``(1, 2)`` pair the requirement names, so a swapped tuple
    order or a summed total fails the test.
    """
    changeset = UnifiedChangeSet()

    changeset.memory.add(0x100, [0x01])
    changeset.memory.add(0x200, [0x02, 0x03])
    changeset.parameters.add("IGN_ADVANCE_BASE", None, 23)

    # Parameter count first, memory count second — never summed.
    assert changeset.counts() == (1, 2)
    assert changeset.is_empty() is False


def test_tc013_one_memory_change_alone_is_not_empty() -> None:
    """One memory change with no parameter change is not empty (LLR-004.5).

    LLR-004.5 defines empty as *both* halves at zero; this asserts a container
    empty in one half only does not report empty, so an ``or`` / ``and`` slip
    in the empty-state predicate fails the test.
    """
    changeset = UnifiedChangeSet()

    changeset.memory.add(0x100, [0x01])

    assert changeset.counts() == (0, 1)
    assert changeset.is_empty() is False


# ---------------------------------------------------------------------------
# TC-026 — the container composes the two list types, does not subclass them
#          (LLR-004.1, LLR-004.2 / constraint C-3)
# ---------------------------------------------------------------------------


def test_tc026_halves_are_instances_of_the_existing_list_types() -> None:
    """Each half is an instance of the existing batch-03 / increment-1 type (LLR-004.2).

    LLR-004.2 / constraint C-3 require the container to reference the existing
    ``ChangeList`` and ``MemoryChangeList`` types by composition; this asserts
    each half is genuinely an instance of those exact types, the runtime
    corroboration of the TC-027 byte-unchanged inspection.
    """
    changeset = unified_changeset_factory()

    assert isinstance(changeset.parameters, ChangeList)
    assert isinstance(changeset.memory, MemoryChangeList)


def test_tc026_unified_change_set_is_not_a_subclass() -> None:
    """``UnifiedChangeSet`` subclasses none of the composed types (C-3 / LLR-004.2).

    Constraint C-3 forbids subclassing ``ChangeList`` / ``MemoryChangeList`` and
    ``dict``; this asserts ``UnifiedChangeSet`` is a subclass of none of them,
    so a refactor that turns the container into a subclass — silently changing
    its public surface — fails the test.
    """
    assert not issubclass(UnifiedChangeSet, ChangeList)
    assert not issubclass(UnifiedChangeSet, MemoryChangeList)
    assert not issubclass(UnifiedChangeSet, dict)

    # The composed halves are members, not inherited behaviour: the container
    # itself is not iterable as a change-list / has no add() of its own.
    changeset = UnifiedChangeSet()
    assert not hasattr(changeset, "add")
    assert not hasattr(changeset, "entries")


def test_tc026_mutating_one_half_through_the_container_leaves_the_other() -> None:
    """Mutating either half via the container accessors leaves the other (TC-026).

    TC-026 corroborates LLR-004.3 once more at the composition seam: the two
    halves must be genuinely separate objects, so a mutation through one
    accessor cannot leak into the other. A shared backing store would fail
    here even if the type checks above passed.
    """
    changeset = unified_changeset_factory()
    parameter_count_before, memory_count_before = changeset.counts()

    changeset.memory.add(0x300, [0xFF])
    assert len(changeset.parameters) == parameter_count_before
    assert len(changeset.memory) == memory_count_before + 1

    changeset.parameters.add("NEW_PARAM", None, 7, ResolutionStatus.RESOLVED)
    assert len(changeset.memory) == memory_count_before + 1
    assert len(changeset.parameters) == parameter_count_before + 1


def test_tc026_factory_composes_both_source_factories() -> None:
    """``unified_changeset_factory`` composes the two per-kind factories (TC-026).

    The factory must build the container by composition from
    ``change_list_factory`` and ``memory_change_factory`` — this asserts the
    composed counts match the source factories (8 parameter entries inheriting
    the adversarial floats, 3 memory entries from the "base" variant), so the
    later write / round-trip tests rest on a known, non-trivial container.
    """
    changeset = unified_changeset_factory()

    # change_list_factory: 1 scalar + 3 array + 1 ASCII + 3 adversarial floats.
    assert changeset.counts() == (8, 3)
    assert changeset.is_empty() is False

    # The adversarial-float arm is inherited from change_list_factory, not
    # re-declared in the unified factory (Q-09 note).
    float_values = [
        e.value
        for e in changeset.parameters.entries
        if e.parameter_name == "FLOAT_ADV_BLOCK"
    ]
    assert float_values == [0.1, 5e-324, 8.98846567431158e307]
