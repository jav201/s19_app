"""
Change-set file round-trip tests — s19_app batch-04, increment 9; re-pointed
to the v2 writer/reader (``s19_app/tui/changes/io.py``) at batch-07 E3b
(§6.6 dispositions).

TC-025 — write → read is lossless for the v2 change document: every byte
run survives in exact insertion order, the persisted containment status is
re-derived on read (never trusted), and the entry count is preserved. The
batch-04 parameter-half rows (value/status/float-precision round-trips)
RETIRED with the parameter flow (operator decision 2026-06-10; LLR-003.3) —
the v2 format is address-only.

These tests use the production serializer and reader end to end through the
work-area write path, so a wire-format drift between writer and reader is
caught here even when each side's unit tests pass in isolation.

Every fixture is synthetic and built in-test (constraint C-9).
"""

from __future__ import annotations

from pathlib import Path

from s19_app.tui.changes import CHG_COLLISION, MemoryStatus
from s19_app.tui.changes.io import read_change_document, write_change_document
from s19_app.tui.changes.model import ChangeDocument

from tests.conftest import change_document_factory


def _round_trip(document: ChangeDocument, base_dir: Path) -> ChangeDocument:
    """Write the document through the work-area path and read it back."""
    path, issues = write_change_document(document, base_dir, "roundtrip.json")
    assert path is not None, f"write was rejected: {[i.code for i in issues]}"
    return read_change_document(str(path), base_dir)


def _byte_map(document: ChangeDocument) -> dict[int, tuple[int, ...]]:
    """The address-keyed encoded-byte map of a document's entries."""
    return {e.address: e.encoded_bytes for e in document.entries}


# ---------------------------------------------------------------------------
# TC-025 — every byte run survives in exact order (LLR-001.2)
# ---------------------------------------------------------------------------


def test_tc025_entries_round_trip_every_byte_run(tmp_path: Path) -> None:
    """TC-025 — every entry's byte run survives the round-trip in exact order.

    The reader must recover the exact address and the exact ordered encoded
    run of every entry. This asserts the ``address``-keyed byte map of the
    reconstructed document equals the original's exactly — including the
    pinned ``DEADBEEF`` run at ``0x200`` and the string entry's encoded
    bytes. A byte dropped, re-ordered or mangled fails the test.
    """
    original = change_document_factory()

    reconstructed = _round_trip(original, tmp_path)

    assert _byte_map(reconstructed) == _byte_map(original)
    # The pinned inside-range run — spelled out so a regression that drops it
    # cannot hide behind a both-sides-wrong dict comparison.
    assert _byte_map(reconstructed)[0x200] == (0xDE, 0xAD, 0xBE, 0xEF)
    # The string entry's raw declaration survives too.
    string_entry = next(
        e for e in reconstructed.entries if e.entry_type == "string"
    )
    assert string_entry.value == "REV_C"


def test_tc025_entries_preserve_insertion_order(tmp_path: Path) -> None:
    """TC-025 — the document's deterministic order survives the round-trip.

    The deterministic insertion order must carry through write and read. This
    asserts the reconstructed entry ``address`` order is identical to the
    original's.
    """
    original = change_document_factory()

    reconstructed = _round_trip(original, tmp_path)

    assert [e.address for e in reconstructed.entries] == [
        e.address for e in original.entries
    ]


def test_tc025_memory_status_is_re_derived_not_trusted_on_read(
    tmp_path: Path,
) -> None:
    """TC-025 — the containment status is re-derived on read, not trusted.

    Per Q-06 / A-7 the reader does **not** trust a persisted validation
    status — the v2 wire format does not even carry one (``_encode_entry``
    emits only the declaration). This asserts every reconstructed entry takes
    the default ``UNVALIDATED_NO_IMAGE`` status regardless of what the
    in-memory original carried, because no firmware image was loaded for
    this read.
    """
    original = change_document_factory()
    for entry in original.entries:
        entry.status = MemoryStatus.INSIDE  # a stale pre-write stamp

    reconstructed = _round_trip(original, tmp_path)

    statuses = {e.status for e in reconstructed.entries}
    assert statuses == {MemoryStatus.UNVALIDATED_NO_IMAGE}


# ---------------------------------------------------------------------------
# TC-025 — the round-trip holds for every memory-field variant + structurally
# ---------------------------------------------------------------------------


def test_tc025_round_trip_holds_for_every_memory_variant(
    tmp_path: Path,
) -> None:
    """TC-025 — write → read is lossless for each memory-field factory variant.

    The ``base`` / ``partial`` / ``outside`` / ``gap-spanning`` variants each
    carry a different run shape (a long run, a gap-spanning run, the overlap
    pair). This asserts the byte map survives the round-trip for **every**
    variant, so a defect tied to one run shape is caught. The ``base``
    variant's overlap pair is an intra-document collision under v2
    (LLR-001.5): the read must flag it with exactly two ``CHG-COLLISION``
    errors while still parsing both declarations losslessly.
    """
    for variant in ("base", "partial", "outside", "gap-spanning"):
        original = change_document_factory(variant)
        # A fresh sub-directory per variant so the work-area writes do not
        # collide and dedup-suffix.
        variant_dir = tmp_path / variant
        variant_dir.mkdir()

        reconstructed = _round_trip(original, variant_dir)

        assert _byte_map(reconstructed) == _byte_map(
            original
        ), f"byte map drifted for memory variant {variant!r}"
        collision_codes = [
            i.code for i in reconstructed.issues if i.code == CHG_COLLISION
        ]
        expected_collisions = 2 if variant == "base" else 0
        assert len(collision_codes) == expected_collisions, (
            f"variant {variant!r} collision findings drifted: "
            f"{collision_codes}"
        )


def test_tc025_round_tripped_counts_match_the_original(
    tmp_path: Path,
) -> None:
    """TC-025 — the reconstructed document has the same entry count.

    A round-trip that dropped or duplicated an entry would change the count
    even if the surviving entries matched. This asserts the entry count of
    the reconstruction equals the original's — a coarse structural check that
    complements the per-entry byte map.
    """
    original = change_document_factory()

    reconstructed = _round_trip(original, tmp_path)

    assert len(reconstructed.entries) == len(original.entries)
