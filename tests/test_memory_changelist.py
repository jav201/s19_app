"""
Memory-field change model tests — s19_app batch-04, increment 1; re-pointed
to the v2 ``changes`` model at batch-07 E3b (§6.6 dispositions).

Covers the pure change-entry model (``s19_app/tui/changes/model.py``) and the
interactive entry-list management (``services/change_service.py`` — the v2
home of add / edit / remove):

  - TC-001 — entry construction: an entry holds ``address``,
             ``encoded_bytes`` and a ``status`` field, preserves byte order
             and length, and exposes its addressed range as the half-open
             span ``(address, address + len(encoded_bytes))``.
  - TC-002 — add / edit / remove; the batch-04 in-place re-add rule is
             SUPERSEDED by the v2 collision contract (D1, resolved by
             LLR-001.5): an identical address is an explicit error, never a
             silent update.
  - TC-003 — deterministic ordering: two passes over the entries yield
             identical entry order, so repeated serialization is
             byte-identical.
  - TC-004 — model-coherence roll-up: a document built, edited and queried
             through the service API reports a consistent entry set.
  - TC-008 (ValueError arms only) — a malformed byte run is rejected at
             construction: a byte of ``256``, a negative byte, or an empty
             run each raises ``ValueError``.

These tests encode WHY each behaviour matters: the addressed-range derivation
backs the containment/collision validators, the duplicate-address error backs
one authoritative declaration per location (LLR-001.5), and the deterministic
order backs reproducible change-file serialization. A field rename, an
ordering change, or a dropped construction-time check fails the matching test.
"""

from __future__ import annotations

import pytest

from s19_app.tui.changes import (
    CHG_COLLISION,
    ChangeEntry,
    MemoryStatus,
    collision_issues,
)
from s19_app.tui.services.change_service import ChangeService
from s19_app.validation.model import ValidationSeverity

from tests.conftest import MEMORY_OVERLAP_PAIR, memory_change_factory


def _service_with(document) -> ChangeService:
    """Build a ChangeService owning the given document."""
    service = ChangeService()
    service.document = document
    return service


# ---------------------------------------------------------------------------
# TC-001 — entry construction (LLR-001.1)
# ---------------------------------------------------------------------------


def test_tc001_entry_reports_its_fields() -> None:
    """A change entry reports its documented fields (LLR-001.1).

    The entry holds an ``address``, an ``encoded_bytes`` run and a
    validation-status field; this asserts each is readable as constructed
    so a field rename or drop fails the test.
    """
    entry = ChangeEntry(
        "bytes",
        0x100,
        [0x01, 0x02, 0x03],
        status=MemoryStatus.INSIDE,
    )

    assert entry.address == 0x100
    assert entry.encoded_bytes == (0x01, 0x02, 0x03)
    assert entry.status is MemoryStatus.INSIDE


def test_tc001_status_defaults_to_unvalidated_no_image() -> None:
    """A freshly-built entry is ``unvalidated-no-image``.

    An entry is buildable before any image is loaded; until the containment
    validator runs it carries the default ``UNVALIDATED_NO_IMAGE`` status,
    mirroring the batch-03 ``unresolved-no-a2l`` pattern.
    """
    entry = ChangeEntry("bytes", 0x10, [0xFF])

    assert entry.status is MemoryStatus.UNVALIDATED_NO_IMAGE


def test_tc001_new_bytes_preserves_order_and_length() -> None:
    """The byte run preserves order and length (LLR-001.1 acceptance).

    The stored bytes are the source of truth for display and serialization, so
    the run must round-trip its exact ordered contents and count.
    """
    run = [0x10, 0x00, 0xAB, 0x10]
    entry = ChangeEntry("bytes", 0x4000, run)

    assert entry.encoded_bytes == (0x10, 0x00, 0xAB, 0x10)
    assert len(entry.encoded_bytes) == len(run)


def test_tc001_new_bytes_is_stored_as_an_immutable_tuple() -> None:
    """``encoded_bytes`` is stored as an immutable tuple.

    Storing the run as a ``tuple`` is what lets the display layer derive
    hex/ASCII/decimal forms with no risk of mutating the stored bytes;
    this pins the storage type so a regression to a mutable ``list`` fails.
    """
    entry = ChangeEntry("bytes", 0x100, [0x41, 0x42])

    assert isinstance(entry.encoded_bytes, tuple)


def test_tc001_addressed_range_is_the_half_open_span() -> None:
    """The entry exposes ``(address, address + len)`` (LLR-001.5).

    The addressed range is the span the containment validator tests against
    the loaded image's ranges; it must be the half-open ``(start, end)`` pair
    with ``end`` exclusive.
    """
    entry = ChangeEntry("bytes", 0x100, [0x41, 0x42])

    assert entry.addressed_range == (0x100, 0x102)


# ---------------------------------------------------------------------------
# TC-002 — add / edit / remove + duplicate-address semantics (D1 → LLR-001.5)
# ---------------------------------------------------------------------------


def test_tc002_add_then_remove_leaves_the_list_empty() -> None:
    """Adding then removing the same address leaves the list empty.

    The acceptance criterion is explicit: add then remove the same address ->
    empty list. This pins ``remove_entry`` as the inverse of ``add_entry``.
    """
    svc = ChangeService()
    svc.add_entry("0x100", "", "01 02")
    assert len(svc.document.entries) == 1

    svc.remove_entry("0x100")

    assert len(svc.document.entries) == 0
    assert all(e.address != 0x100 for e in svc.document.entries)


def test_tc002_edit_touches_only_the_target_entry() -> None:
    """Editing one entry changes only that entry's bytes.

    ``edit_entry`` must be surgical; this asserts a sibling entry's bytes are
    untouched so a broadcast bug is caught.
    """
    svc = ChangeService()
    svc.add_entry("0x100", "", "01")
    svc.add_entry("0x200", "", "02")

    svc.edit_entry("0x100", "", "AA BB")

    by_address = {e.address: e for e in svc.document.entries}
    assert by_address[0x100].encoded_bytes == (0xAA, 0xBB)
    assert by_address[0x200].encoded_bytes == (0x02,)


def test_tc002_readd_same_address_is_an_explicit_error_not_an_update() -> None:
    """A re-add at an existing address raises — never an in-place update.

    REWRITE (D1, resolved by LLR-001.5 at the 2026-06-10 gate): batch-04
    silently dedup-updated a re-added address; under the v2 contract an
    identical address is an explicit error. The interactive add refuses the
    duplicate, the original entry keeps its bytes, and no twin row appears.
    """
    svc = ChangeService()
    svc.add_entry("0x100", "", "01")

    with pytest.raises(ValueError):
        svc.add_entry("0x100", "", "09 0A")

    assert len(svc.document.entries) == 1
    assert svc.document.entries[0].encoded_bytes == (0x01,)


def test_tc002_duplicate_address_in_a_document_is_a_collision_error() -> None:
    """Two document entries at one address each collect a CHG-COLLISION ERROR.

    REWRITE (D1, resolved by LLR-001.5): the v2 file format keeps both
    entries — there is no silent dedup — and the collision rule flags each
    with one ERROR-severity ``CHG-COLLISION`` finding, in entry order.
    """
    entries = [
        ChangeEntry("bytes", 0x100, (0x01,)),
        ChangeEntry("bytes", 0x100, (0x09, 0x0A)),
    ]

    issues = collision_issues(entries)

    assert [issue.code for issue in issues] == [CHG_COLLISION, CHG_COLLISION]
    for issue in issues:
        assert issue.severity is ValidationSeverity.ERROR
    # Both declarations are kept — the error reports them, never collapses.
    assert [e.address for e in entries] == [0x100, 0x100]


def test_tc002_edit_missing_address_raises_keyerror() -> None:
    """Editing an absent address raises ``KeyError``.

    ``edit_entry`` targets an existing identity; addressing a non-existent
    entry is a caller error, surfaced as ``KeyError``.
    """
    svc = ChangeService()

    with pytest.raises(KeyError):
        svc.edit_entry("0xDEAD", "", "00")


def test_tc002_remove_missing_address_raises_keyerror() -> None:
    """Removing an absent address raises ``KeyError``.

    ``remove_entry`` targets an existing identity; a missing address is a
    caller error, surfaced as ``KeyError``.
    """
    svc = ChangeService()

    with pytest.raises(KeyError):
        svc.remove_entry("0xDEAD")


# ---------------------------------------------------------------------------
# TC-003 — deterministic ordering (LLR-001.4)
# ---------------------------------------------------------------------------


def test_tc003_two_serializations_have_identical_entry_order() -> None:
    """Two passes over the entries yield identical order.

    The entry list is what the v2 writer iterates; if its order were not
    deterministic, two serializations of the same document would differ
    byte-for-byte. The model pins **insertion order**, so two reads must
    match.
    """
    svc = ChangeService()
    svc.add_entry("0x300", "", "03")
    svc.add_entry("0x100", "", "01")
    svc.add_entry("0x200", "", "02")

    first = [e.address for e in svc.document.entries]
    second = [e.address for e in svc.document.entries]

    assert first == second
    # Pins the chosen rule: insertion order, NOT ascending address.
    assert first == [0x300, 0x100, 0x200]


def test_tc003_rows_is_a_copy_not_the_backing_store() -> None:
    """``rows`` returns a fresh list each call (robustness).

    Mutating the returned display-row list must not corrupt the document —
    the v2 snapshot accessor for table rendering is ``ChangeService.rows``,
    and a caller clearing its result must leave the entries intact.
    """
    svc = ChangeService()
    svc.add_entry("0x100", "", "01")

    snapshot = svc.rows(None)
    snapshot.clear()

    assert len(svc.document.entries) == 1


# ---------------------------------------------------------------------------
# TC-004 — model-coherence roll-up (LLR-003.4)
# ---------------------------------------------------------------------------


def test_tc004_built_edited_queried_list_is_consistent() -> None:
    """A built/edited/queried document reports a consistent entry set.

    The roll-up: exercise the whole entry-management API — build via the
    factory, edit one entry, remove another, add a fresh one — and assert the
    final entry set is exactly what those operations imply, with each entry's
    fields coherent.
    """
    svc = _service_with(memory_change_factory())
    assert len(svc.document.entries) == 3  # 0x200 + the two overlap entries

    svc.edit_entry("0x200", "", "0x11 0x22")
    svc.remove_entry("0x104")
    svc.add_entry("0x500", "", "0x55")

    addresses = [e.address for e in svc.document.entries]
    assert addresses == [0x200, 0x100, 0x500]
    by_address = {e.address: e for e in svc.document.entries}
    assert by_address[0x200].encoded_bytes == (0x11, 0x22)
    assert 0x104 not in by_address
    assert by_address[0x500].encoded_bytes == (0x55,)


def test_tc004_factory_overlap_pair_stays_two_distinct_entries() -> None:
    """The factory's overlap pair is two entries, not one (Q-03).

    The overlap pair is pinned at distinct start addresses (0x100, 0x104) so
    the two declarations stay distinct entries — this is the precondition for
    the collision rule to provoke anything at all.
    """
    document = memory_change_factory()
    by_address = {e.address: e for e in document.entries}

    (addr_a, len_a), (addr_b, len_b) = MEMORY_OVERLAP_PAIR
    assert addr_a != addr_b
    assert addr_a in by_address
    assert addr_b in by_address
    # The two addressed ranges genuinely intersect.
    assert by_address[addr_a].addressed_range[1] > addr_b
    assert (
        by_address[addr_b].addressed_range[0]
        < by_address[addr_a].addressed_range[1]
    )


# ---------------------------------------------------------------------------
# TC-008 — malformed-byte-run rejection, ValueError arms only
# ---------------------------------------------------------------------------


def test_tc008_byte_value_256_raises_valueerror() -> None:
    """A byte value of 256 is rejected at construction.

    A byte value greater than 255 is a malformed run; 256 is the boundary
    case and must raise ``ValueError`` — not be collected as a
    ``ValidationIssue``, which is the opposite (collect-don't-abort)
    semantics.
    """
    with pytest.raises(ValueError):
        ChangeEntry("bytes", 0x100, [0x01, 256, 0x03])


def test_tc008_negative_byte_value_raises_valueerror() -> None:
    """A negative byte value is rejected at construction.

    A negative byte never describes a recordable edit intent, so this
    assertion traces to the construction-time validity rule (the Q-02
    traceability fix).
    """
    with pytest.raises(ValueError):
        ChangeEntry("bytes", 0x100, [0x01, -1, 0x03])


def test_tc008_empty_new_bytes_run_raises_valueerror() -> None:
    """An empty byte run is rejected at construction.

    An entry with no bytes does not describe a recordable edit intent, so
    construction must raise ``ValueError``.
    """
    with pytest.raises(ValueError):
        ChangeEntry("bytes", 0x100, [])


def test_tc008_malformed_run_also_rejected_via_changelist_add() -> None:
    """``ChangeService.add_entry`` propagates the malformed-run ``ValueError``.

    The rejection must hold on the interactive ``add`` path too — a malformed
    run entered through the Patch Editor must never land a half-built entry in
    the list; ``add_entry`` builds the entry before mutating, so it raises and
    the list stays empty.
    """
    svc = ChangeService()

    with pytest.raises(ValueError):
        svc.add_entry("0x100", "", "256")

    assert len(svc.document.entries) == 0


def test_tc008_malformed_run_rejected_via_changelist_edit() -> None:
    """``ChangeService.edit_entry`` rejects a malformed run without corrupting.

    An edit that supplies a malformed run must raise ``ValueError`` and leave
    the target entry's existing bytes intact — the edit validates before it
    mutates the live entry.
    """
    svc = ChangeService()
    svc.add_entry("0x100", "", "01 02")

    with pytest.raises(ValueError):
        svc.edit_entry("0x100", "", "-1")

    assert svc.document.entries[0].encoded_bytes == (0x01, 0x02)
