"""
CDFX round-trip tests — s19_app batch-03, increment 10.

Implements **TC-024**: the end-to-end write→read structural-equality verdict
for the CDFX handler. A change-list built by ``change_list_factory`` — a
``None``-index scalar, a ``None``-index ASCII string, an integer-indexed 1-D
integer array, and an integer-indexed 1-D array of the three **adversarial IEEE
binary64 floats** — is serialized by ``write_cdfx`` and parsed back by
``read_cdfx``; the recovered change-list must be structurally identical to the
original.

TC-024 is the single end-to-end cross-check for two contracts that have only
unit-level coverage elsewhere:

- **LLR-004.8 — round-trip-safe floats.** The three adversarial floats
  (``0.1``, the denormal ``5e-324``, a 17-significant-digit value, from
  ``conftest.ADVERSARIAL_FLOATS``) are compared with **exact ``==`` and no
  tolerance**. A denormal truncates to ``0.0`` and a 17-digit value loses its
  tail under any ``str()`` / ``%g`` / fixed-width writer, so this test
  genuinely fails if the writer ever drops to a lossy float text representation
  — it is not tautological.
- **LLR-004.9 / LLR-005.6 — coalesce-on-write → expand-on-read.** The two array
  groups exercise the writer collapsing *N* ``(name, 0..N-1)`` entries into one
  ``VAL_BLK`` ``SW-INSTANCE`` and the reader re-expanding that one instance
  back into *N* keyed entries. The test asserts the recovered
  ``(parameter_name, array_index)`` key set **including the ``Optional[int]``
  shape** — scalar / string entries recover ``array_index is None``, an
  *N*-element array recovers exactly the keys ``(name, 0)…(name, N-1)``.

A writer that emitted one ``SW-INSTANCE`` per array entry, or a reader that did
not expand the ``VG``, fails the key-set assertion; a value-losing or
mis-decoding defect fails the per-key value assertion. Every fixture is
synthetic (constraint C-9).
"""

from __future__ import annotations

from pathlib import Path

from s19_app.tui.cdfx import read_cdfx, write_cdfx
from s19_app.tui.cdfx.changelist import ChangeList

from tests.conftest import (
    ADVERSARIAL_FLOATS,
    change_list_factory,
    change_list_resolution,
)


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _key_value_map(change_list: ChangeList) -> dict[tuple[str, int | None], object]:
    """Map every entry's ``(parameter_name, array_index)`` identity to its
    stored value — the structural shape the round-trip equality compares."""
    return {entry.key: entry.value for entry in change_list.entries}


def _round_trip(change_list: ChangeList) -> ChangeList:
    """Serialize ``change_list`` with ``write_cdfx`` and parse the bytes back
    with ``read_cdfx``; return the recovered change-list. Asserts the write
    produced no excluded / sparse / empty warnings — the factory's entries are
    all resolved and every array group is contiguous and zero-based."""
    resolution = change_list_resolution(change_list)
    data, write_issues = write_cdfx(change_list, resolution)
    assert [i.code for i in write_issues] == [], (
        f"the factory change-list is fully writable — write_cdfx emitted "
        f"unexpected issues: {[i.code for i in write_issues]}"
    )
    recovered, read_issues = read_cdfx(data)
    assert [i.code for i in read_issues] == [], (
        f"a writer-produced .cdfx must read back with no R-* issue, got "
        f"{[i.code for i in read_issues]}"
    )
    return recovered


# ---------------------------------------------------------------------------
# TC-024 — write → read structural equality.
# ---------------------------------------------------------------------------


def test_tc024_round_trip_recovers_the_entry_key_set() -> None:
    """TC-024 — a write→read cycle recovers exactly the original
    ``(parameter_name, array_index)`` key set, including the ``Optional[int]``
    shape (LLR-004.9 / LLR-005.6, LLR-001.1).

    The scalar and ASCII entries must recover ``array_index is None``; each
    3-element array must recover exactly the contiguous keys ``(name, 0..2)``.
    A writer that emitted one ``SW-INSTANCE`` per array entry, or a reader that
    did not expand the ``VG``, would not reproduce this key set.
    """
    original = change_list_factory()

    recovered = _round_trip(original)

    assert {e.key for e in recovered.entries} == {
        e.key for e in original.entries
    }


def test_tc024_round_trip_preserves_optional_int_index_shape() -> None:
    """TC-024 — the recovered indices keep the ``Optional[int]`` discriminator:
    ``None`` for the scalar / string entries, contiguous integers for each
    array (LLR-001.1 / LLR-005.6).

    This pins the shape, not just the count: a reader that gave a ``VALUE``
    instance ``array_index=0`` instead of ``None``, or expanded a ``VAL_BLK``
    to ``(name, 1..N)``, passes the count check but fails here.
    """
    recovered = _round_trip(change_list_factory())

    by_name: dict[str, list[int | None]] = {}
    for entry in recovered.entries:
        by_name.setdefault(entry.parameter_name, []).append(entry.array_index)

    assert by_name["IGN_ADVANCE_BASE"] == [None]
    assert by_name["CAL_LABEL"] == [None]
    assert by_name["FUEL_TRIM_TABLE"] == [0, 1, 2]
    assert by_name["FLOAT_ADV_BLOCK"] == [0, 1, 2]


def test_tc024_round_trip_preserves_scalar_and_string_values() -> None:
    """TC-024 — the scalar integer and the ASCII string survive the round-trip
    with their exact stored values (LLR-005.1 / LLR-005.6).
    """
    recovered = _round_trip(change_list_factory())
    values = _key_value_map(recovered)

    assert values[("IGN_ADVANCE_BASE", None)] == 23
    assert values[("CAL_LABEL", None)] == "REV_C"


def test_tc024_round_trip_preserves_integer_array_values() -> None:
    """TC-024 — every element of the integer 1-D array round-trips to its
    exact value in positional order (LLR-004.9 coalesce / LLR-005.6 expand).
    """
    recovered = _round_trip(change_list_factory())
    values = _key_value_map(recovered)

    assert values[("FUEL_TRIM_TABLE", 0)] == 23
    assert values[("FUEL_TRIM_TABLE", 1)] == 24
    assert values[("FUEL_TRIM_TABLE", 2)] == 25


def test_tc024_round_trip_preserves_adversarial_floats_exactly() -> None:
    """TC-024 — the three adversarial IEEE binary64 floats round-trip with
    **exact ``==`` equality, no tolerance** (LLR-004.8).

    ``0.1`` has no short exact decimal, ``5e-324`` is the smallest positive
    denormal (a fixed-width format truncates it to ``0.0``) and the 17-digit
    value loses its tail under ``%g`` — so this assertion can genuinely fail:
    it passes only if the writer emits full ``repr()``-precision ``V`` text.
    """
    recovered = _round_trip(change_list_factory())
    values = _key_value_map(recovered)

    for index, expected in enumerate(ADVERSARIAL_FLOATS):
        actual = values[("FLOAT_ADV_BLOCK", index)]
        assert actual == expected, (
            f"adversarial float #{index} did not round-trip exactly: "
            f"wrote {expected!r}, read back {actual!r} — the writer dropped "
            f"to a lossy float text representation (LLR-004.8 violated)"
        )
        # The denormal must not have collapsed to 0.0 — the sharpest failure
        # mode of a fixed-width formatter.
        assert actual != 0.0 or expected == 0.0


def test_tc024_round_trip_is_structurally_equal() -> None:
    """TC-024 — the full structural-equality verdict: the recovered change-list
    has the same key→value map as the original, end to end (HLR-004 / HLR-005).

    This is the single assertion that fails on any write defect producing a
    mis-shaped / value-losing instance and any read defect dropping or
    mis-decoding an instance.
    """
    original = change_list_factory()

    recovered = _round_trip(original)

    assert _key_value_map(recovered) == _key_value_map(original)


def test_tc024_round_trip_preserves_entry_order() -> None:
    """TC-024 — the recovered entries appear in the same order as the original
    (LLR-001.4): one ``SW-INSTANCE`` per parameter in first-appearance order,
    and within each array group the entries ascend by ``array_index``.
    """
    original = change_list_factory()

    recovered = _round_trip(original)

    assert [e.key for e in recovered.entries] == [
        e.key for e in original.entries
    ]


def test_tc024_round_trip_via_path(tmp_path: Path) -> None:
    """TC-024 — the round-trip holds when the ``.cdfx`` is written to disk and
    re-read from a resolved path, not only through in-memory bytes
    (LLR-005.1 / LLR-005.5).
    """
    original = change_list_factory()
    resolution = change_list_resolution(original)
    data, write_issues = write_cdfx(original, resolution)
    assert [i.code for i in write_issues] == []

    cdfx_path = tmp_path / "round_trip.cdfx"
    cdfx_path.write_bytes(data)

    recovered, read_issues = read_cdfx(cdfx_path, base_dir=tmp_path)

    assert [i.code for i in read_issues] == []
    assert _key_value_map(recovered) == _key_value_map(original)
