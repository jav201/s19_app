"""
Unified change-set write -> read round-trip test — s19_app batch-04, increment 9.

Covers TC-025 — the unified change-set survives a full
``write_unified_to_workarea`` -> ``read_unified`` round-trip with no loss
(LLR-006.1, corroborating HLR-005 / HLR-006).

This is the strongest correctness test of the batch-04 unified-file stack: any
defect in the increment-5 writer or the increment-6 reader surfaces here. The
change-set under test is the production ``unified_changeset_factory`` —

  - the **parameter half** is ``change_list_factory()``: a scalar, a 1-D array
    of three integer elements, an ASCII string, plus a 1-D array of the three
    adversarial IEEE binary64 floats (``0.1``, the smallest positive denormal
    ``5e-324``, a 17-significant-digit value). The adversarial floats are the
    intended sensitivity: an **exact ``==``** comparison (no tolerance) only
    passes if the JSON path preserves full binary64 — a lossy intermediate
    string conversion in either the writer or the reader fails the test;
  - the **memory half** carries an ``inside``-sized run plus the pinned overlap
    pair (``base``); the ``partial`` / ``outside`` / ``gap-spanning`` variants
    are round-tripped too, each contributing a multi-byte run, so every byte of
    every run must come back in the exact order it went out.

The equality predicate is deliberately split per the Q-06 finding:

  - **parameter half** — equality is the ``(parameter_name, array_index)``
    identity key plus the **exact** ``value`` (``==``, no tolerance). The
    persisted resolution ``status`` round-trips through the file (a recognised
    ``ResolutionStatus`` token survives ``_coerce_resolution_status``), so it is
    asserted as well — but as a separate assertion, not folded into the value
    equality;
  - **memory half** — equality is the ``address`` key plus the **exact ordered**
    ``new_bytes`` sequence. The validation ``status`` is **excluded** from the
    equality predicate: the reader does not trust the persisted memory status —
    it deliberately re-derives it (every read entry takes the default
    ``UNVALIDATED_NO_IMAGE`` until a real image validates it, A-7). That
    re-derivation is asserted **separately** so the test still pins it.

Both halves' deterministic insertion order (LLR-001.4) is asserted to survive
the round-trip — a re-ordering write or read fails the test.

Every fixture is the production factory / writer (constraint C-9): the on-disk
file is exactly what the writer emits, never a hand-built JSON literal that
could silently drift from the format contract.
"""

from __future__ import annotations

from pathlib import Path

from s19_app.tui.cdfx import (
    MemoryStatus,
    ResolutionStatus,
    UnifiedChangeSet,
    read_unified,
    write_unified_to_workarea,
)

from tests.conftest import unified_changeset_factory


# ---------------------------------------------------------------------------
# Structural-equality helpers — the per-half equality predicates (Q-06).
# ---------------------------------------------------------------------------


def _parameter_value_map(
    changeset: UnifiedChangeSet,
) -> dict[tuple[str, int | None], object]:
    """
    Summary:
        Project a unified change-set's parameter half to an identity-keyed
        ``value`` map — the parameter-half equality predicate (TC-025).

    Args:
        changeset (UnifiedChangeSet): The change-set whose parameter half is
            projected — either the factory-built original or the round-tripped
            reconstruction.

    Returns:
        dict[tuple[str, int | None], object]: One entry per parameter
        ``ChangeListEntry``, keyed by its ``(parameter_name, array_index)``
        identity and valued by the entry's exact ``value``. Resolution
        ``status`` is intentionally excluded — it is asserted separately so the
        value equality is not coupled to it.

    Data Flow:
        - Iterates ``changeset.parameters.entries`` and reads each entry's
          identity ``key`` and ``value``.

    Dependencies:
        Used by:
            - test_tc025_parameter_half_round_trips_every_value
    """
    return {entry.key: entry.value for entry in changeset.parameters.entries}


def _memory_byte_map(
    changeset: UnifiedChangeSet,
) -> dict[int, tuple[int, ...]]:
    """
    Summary:
        Project a unified change-set's memory half to an address-keyed
        ``new_bytes`` map — the memory-half equality predicate (TC-025).

    Args:
        changeset (UnifiedChangeSet): The change-set whose memory half is
            projected — either the factory-built original or the round-tripped
            reconstruction.

    Returns:
        dict[int, tuple[int, ...]]: One entry per ``MemoryChange``, keyed by its
        integer ``address`` and valued by the exact ordered ``new_bytes`` run
        as a tuple. Validation ``status`` is intentionally excluded — the
        reader re-derives it (A-7), so it is asserted separately.

    Data Flow:
        - Iterates ``changeset.memory.entries`` and reads each entry's
          ``address`` and ``new_bytes`` run.

    Dependencies:
        Used by:
            - test_tc025_memory_half_round_trips_every_byte_run
    """
    return {
        entry.address: tuple(entry.new_bytes)
        for entry in changeset.memory.entries
    }


def _round_trip(
    changeset: UnifiedChangeSet, tmp_path: Path
) -> UnifiedChangeSet:
    """
    Summary:
        Write a unified change-set to a work-area JSON file and read it back,
        returning the reconstructed change-set — the shared round-trip driver
        for TC-025.

    Args:
        changeset (UnifiedChangeSet): The change-set to write then read.
        tmp_path (Path): The pytest temp directory used as the app base dir;
            ``write_unified_to_workarea`` creates its ``.s19tool/workarea/``
            under it and ``read_unified`` resolves the written path against it.

    Returns:
        UnifiedChangeSet: The change-set reconstructed by ``read_unified`` from
        the file the writer produced. The write must be clean (a non-``None``
        path, no issues) and the read must produce no issue — any issue is a
        round-trip defect and fails the calling test.

    Data Flow:
        - ``write_unified_to_workarea`` -> a JSON file under the work area.
        - ``read_unified`` of that exact path -> the reconstructed change-set.

    Dependencies:
        Uses:
            - write_unified_to_workarea
            - read_unified
        Used by:
            - every TC-025 test in this module.
    """
    path, write_issues = write_unified_to_workarea(
        changeset, tmp_path, "roundtrip.json"
    )
    assert path is not None, (
        f"the round-trip write was rejected: "
        f"{[i.code for i in write_issues]}"
    )
    assert write_issues == [], (
        f"the round-trip write produced issues: "
        f"{[i.code for i in write_issues]}"
    )

    reconstructed, read_issues = read_unified(str(path), tmp_path)
    assert read_issues == [], (
        f"the round-trip read produced issues: "
        f"{[i.code for i in read_issues]}"
    )
    return reconstructed


# ---------------------------------------------------------------------------
# TC-025 — parameter half: every value survives by exact ``==`` (LLR-006.1)
# ---------------------------------------------------------------------------


def test_tc025_parameter_half_round_trips_every_value(tmp_path: Path) -> None:
    """TC-025 — every parameter value survives the round-trip by exact ``==``.

    LLR-006.1 requires the reader to reconstruct the parameter half the writer
    emitted. This asserts the ``(parameter_name, array_index)``-keyed value map
    of the reconstructed change-set equals the original's **exactly** — the
    scalar ``23``, the integer array ``23/24/25`` and the ASCII string
    ``"REV_C"`` all come back unchanged. Equality is by ``==`` with no
    tolerance: a writer or reader that drops or mangles a value fails here.
    """
    original = unified_changeset_factory()

    reconstructed = _round_trip(original, tmp_path)

    assert _parameter_value_map(reconstructed) == _parameter_value_map(original)


def test_tc025_adversarial_floats_survive_full_binary64_precision(
    tmp_path: Path,
) -> None:
    """TC-025 — the three adversarial IEEE floats survive with no precision loss.

    The parameter half carries ``0.1`` (no short exact decimal), ``5e-324`` (the
    smallest positive binary64 denormal) and a 17-significant-digit value — the
    three values no lossy ``str()`` / ``%g`` / fixed-width text form can
    round-trip. This asserts each comes back **bit-exact** (``==``, no
    tolerance), so a lossy intermediate string conversion anywhere in the
    write -> read path is caught. This is the intended sensitivity of TC-025
    and the reason the round-trip is the strongest correctness test of the
    batch.
    """
    original = unified_changeset_factory()

    reconstructed = _round_trip(original, tmp_path)

    expected = {
        entry.key: entry.value
        for entry in original.parameters.entries
        if entry.parameter_name == "FLOAT_ADV_BLOCK"
    }
    actual = {
        entry.key: entry.value
        for entry in reconstructed.parameters.entries
        if entry.parameter_name == "FLOAT_ADV_BLOCK"
    }
    assert actual == expected
    # Spell the values out — a regression that silently rounds one would still
    # pass the dict comparison above only if the original were also wrong.
    float_values = [
        entry.value
        for entry in reconstructed.parameters.entries
        if entry.parameter_name == "FLOAT_ADV_BLOCK"
    ]
    assert float_values == [0.1, 5e-324, 8.98846567431158e307]


def test_tc025_parameter_half_preserves_insertion_order(
    tmp_path: Path,
) -> None:
    """TC-025 — the parameter half's deterministic order survives the round-trip.

    LLR-001.4's deterministic insertion order must carry through write and
    read. This asserts the reconstructed parameter half's
    ``(parameter_name, array_index)`` order is identical to the original's, so
    a re-ordering write or read fails the test.
    """
    original = unified_changeset_factory()

    reconstructed = _round_trip(original, tmp_path)

    assert [e.key for e in reconstructed.parameters.entries] == [
        e.key for e in original.parameters.entries
    ]


def test_tc025_parameter_resolution_status_round_trips(
    tmp_path: Path,
) -> None:
    """TC-025 — a recognised parameter resolution status survives the round-trip.

    The persisted ``status`` of a parameter entry round-trips through the file:
    a recognised ``ResolutionStatus`` token survives ``_coerce_resolution_status``
    on read. This is asserted **separately** from the value equality (Q-06) so
    the value-equality predicate is not coupled to the status. Every
    factory entry is ``RESOLVED``; the reconstruction must report the same.
    """
    original = unified_changeset_factory()

    reconstructed = _round_trip(original, tmp_path)

    statuses = {e.status for e in reconstructed.parameters.entries}
    assert statuses == {ResolutionStatus.RESOLVED}


# ---------------------------------------------------------------------------
# TC-025 — memory half: every byte run survives in exact order (LLR-006.1)
# ---------------------------------------------------------------------------


def test_tc025_memory_half_round_trips_every_byte_run(tmp_path: Path) -> None:
    """TC-025 — every memory byte run survives the round-trip in exact order.

    LLR-006.1 / LLR-005.3 require the reader to recover the exact integer
    ``address`` and the exact ordered ``new_bytes`` run of every memory entry.
    This asserts the ``address``-keyed byte map of the reconstructed change-set
    equals the original's exactly — including the pinned ``DEADBEEF`` run at
    ``0x200`` and the multi-byte overlap-pair runs. A byte dropped, re-ordered
    or mangled fails the test.
    """
    original = unified_changeset_factory()

    reconstructed = _round_trip(original, tmp_path)

    assert _memory_byte_map(reconstructed) == _memory_byte_map(original)
    # The base variant's pinned inside-range run — spelled out so a regression
    # that drops it cannot hide behind a both-sides-wrong dict comparison.
    assert _memory_byte_map(reconstructed)[0x200] == (0xDE, 0xAD, 0xBE, 0xEF)


def test_tc025_memory_half_preserves_insertion_order(tmp_path: Path) -> None:
    """TC-025 — the memory half's deterministic order survives the round-trip.

    LLR-001.4's deterministic insertion order must carry through write and
    read. This asserts the reconstructed memory half's ``address`` order is
    identical to the original's.
    """
    original = unified_changeset_factory()

    reconstructed = _round_trip(original, tmp_path)

    assert [e.address for e in reconstructed.memory.entries] == [
        e.address for e in original.memory.entries
    ]


def test_tc025_memory_status_is_re_derived_not_trusted_on_read(
    tmp_path: Path,
) -> None:
    """TC-025 — the persisted memory status is re-derived on read, not trusted.

    Per Q-06 / A-7 the reader does **not** trust a memory entry's persisted
    validation status — it re-derives it. This is why ``status`` is excluded
    from the memory-half equality predicate. This asserts the exclusion is real
    behaviour: every reconstructed memory entry takes the default
    ``UNVALIDATED_NO_IMAGE`` status regardless of what the file stored, because
    no firmware image was loaded for this read. The test pins the
    re-derivation that the equality predicate deliberately omits.
    """
    original = unified_changeset_factory()

    reconstructed = _round_trip(original, tmp_path)

    statuses = {e.status for e in reconstructed.memory.entries}
    assert statuses == {MemoryStatus.UNVALIDATED_NO_IMAGE}


# ---------------------------------------------------------------------------
# TC-025 — the round-trip holds for every memory-field variant + structurally
# ---------------------------------------------------------------------------


def test_tc025_round_trip_holds_for_every_memory_variant(
    tmp_path: Path,
) -> None:
    """TC-025 — write -> read is lossless for each memory-field factory variant.

    The ``base`` / ``partial`` / ``outside`` / ``gap-spanning`` variants each
    carry a different memory-field run shape (the multi-byte runs the increment
    instruction calls for). This asserts the parameter-value map and the
    memory-byte map both survive the round-trip for **every** variant, so a
    defect tied to one run shape (a long run, a gap-spanning run) is caught.
    """
    for variant in ("base", "partial", "outside", "gap-spanning"):
        original = unified_changeset_factory(variant)
        # A fresh sub-directory per variant so the work-area writes do not
        # collide and dedup-suffix.
        variant_dir = tmp_path / variant
        variant_dir.mkdir()

        reconstructed = _round_trip(original, variant_dir)

        assert _parameter_value_map(reconstructed) == _parameter_value_map(
            original
        ), f"parameter half drifted for memory variant {variant!r}"
        assert _memory_byte_map(reconstructed) == _memory_byte_map(
            original
        ), f"memory half drifted for memory variant {variant!r}"


def test_tc025_round_tripped_counts_match_the_original(
    tmp_path: Path,
) -> None:
    """TC-025 — the reconstructed change-set has the same per-half entry counts.

    A round-trip that dropped or duplicated an entry would change a half's
    count even if the surviving entries matched. This asserts
    ``UnifiedChangeSet.counts()`` of the reconstruction equals the original's
    — a coarse structural check that complements the per-entry maps.
    """
    original = unified_changeset_factory()

    reconstructed = _round_trip(original, tmp_path)

    assert reconstructed.counts() == original.counts()
    assert reconstructed.is_empty() == original.is_empty()
