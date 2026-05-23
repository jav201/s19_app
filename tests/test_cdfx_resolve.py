"""
CDFX A2L-resolution tests — s19_app batch-03, increment 2 (migrated by
increment 5 to the ``Optional[int]`` ``array_index`` contract).

Covers ``s19_app/tui/cdfx/resolve.py`` — resolving each change-list entry
against the **enriched** A2L payload:

  - TC-004 — resolve a known parameter against the A2L (LLR-002.1). Also
             asserts the resolver delegates to ``tui/a2l.py`` and does not
             re-parse A2L text.
  - TC-005 — unresolved-name handling (LLR-002.2).
  - TC-006 — array-index range check (LLR-002.3): an integer index is
             range-checked; a ``None`` (scalar / string) index is not, and
             resolves on name alone.
  - TC-007 — resolution without a loaded A2L (LLR-002.4).

The synthetic A2L is built by ``make_patch_a2l`` (below) — a named scalar, a
1-D array of ``element_count`` 3, and an ASCII characteristic — and run through
the real ``parse_a2l_file`` → ``enrich_a2l_tags_with_values`` pipeline, so the
tests exercise resolution against the genuine enriched-tag shape. The bare
``extract_a2l_tags`` output is *not* used: per constraint C-1 / Phase-2 finding
A-01 a bare ``CHARACTERISTIC`` tag has ``datatype = None`` and the decode-
relevant fields are populated only after enrichment.
"""

from __future__ import annotations

from pathlib import Path

from s19_app.tui.a2l import enrich_a2l_tags_with_values, parse_a2l_file
from s19_app.tui.cdfx import ChangeList, ResolutionStatus
from s19_app.tui.cdfx.resolve import (
    ResolutionResult,
    ResolvedType,
    resolve_against_a2l,
)


# ---------------------------------------------------------------------------
# Test fixtures — make_patch_a2l (synthetic A2L) + a resolved-tag helper
# ---------------------------------------------------------------------------

# The synthetic A2L: three RECORD_LAYOUTs and three CHARACTERISTICs whose
# `deposit` token names a layout. After enrichment `_resolve_record_layout`
# reads the layout's datatype/count token, so the enriched tag carries
# `decode_type` / `element_count` / `char_type` even though the bare tag's
# `datatype` is None (A-01). FUEL_TRIM_TABLE is a 1-D array of element_count 3.
_PATCH_A2L_TEXT = """/begin PROJECT P
/begin MODULE M
/begin RECORD_LAYOUT RL_SCALAR
  UWORD
/end RECORD_LAYOUT
/begin RECORD_LAYOUT RL_ARRAY3
  UWORD 3
/end RECORD_LAYOUT
/begin RECORD_LAYOUT RL_ASCII
  UBYTE 8
/end RECORD_LAYOUT
/begin CHARACTERISTIC IGN_ADVANCE_BASE
VALUE 0x8000 RL_SCALAR 0 NO_COMPU_METHOD 0 65535
/end CHARACTERISTIC
/begin CHARACTERISTIC FUEL_TRIM_TABLE
VAL_BLK 0x8100 RL_ARRAY3 0 NO_COMPU_METHOD 0 65535
/end CHARACTERISTIC
/begin CHARACTERISTIC CAL_LABEL
ASCII 0x8200 RL_ASCII 0 NO_COMPU_METHOD 0 255
/end CHARACTERISTIC
/end MODULE
/end PROJECT
"""


def make_patch_a2l(tmp_path: Path) -> dict:
    """
    Summary:
        Write a small synthetic A2L to ``tmp_path`` and return its parsed
        payload — a named scalar, a 1-D array (``element_count`` 3) and an
        ASCII characteristic — for the CDFX resolution tests.

    Args:
        tmp_path (Path): The pytest ``tmp_path`` directory the ``.a2l`` file is
            written into.

    Returns:
        dict: The ``parse_a2l_file`` payload (``tags``, ``record_layouts_by_name``,
        ``compu_methods_by_name``, ...). Callers run ``enrich_a2l_tags_with_values``
        over it to obtain the enriched tags the resolver consumes.

    Data Flow:
        - Write the fixed synthetic A2L text to ``tmp_path/patch.a2l``.
        - Parse it through the real ``parse_a2l_file`` pipeline.

    Dependencies:
        Uses:
            - parse_a2l_file
        Used by:
            - TC-004, TC-005, TC-006 (the resolved / unresolved-name / range
              cases).
    """
    a2l_path = tmp_path / "patch.a2l"
    a2l_path.write_text(_PATCH_A2L_TEXT, encoding="utf-8")
    return parse_a2l_file(a2l_path)


def enriched_patch_tags(tmp_path: Path) -> list[dict]:
    """
    Summary:
        Build the enriched A2L tags for the synthetic patch A2L — the exact
        input shape the CDFX resolver consumes per constraint C-1.

    Args:
        tmp_path (Path): The pytest ``tmp_path`` passed through to
            :func:`make_patch_a2l`.

    Returns:
        list[dict]: The enriched tags from ``enrich_a2l_tags_with_values`` —
        each carries the post-enrichment ``decode_type`` / ``element_count`` /
        ``char_type`` fields (no S19 ``mem_map``, so no decoded values).

    Data Flow:
        - Parse the synthetic A2L via :func:`make_patch_a2l`.
        - Enrich the tags with ``mem_map=None`` — enrichment populates the
          type metadata without needing decoded values.

    Dependencies:
        Uses:
            - make_patch_a2l
            - enrich_a2l_tags_with_values
        Used by:
            - TC-004, TC-005, TC-006.
    """
    return enrich_a2l_tags_with_values(make_patch_a2l(tmp_path), None)


# ---------------------------------------------------------------------------
# TC-004 — resolve a known parameter against the A2L (LLR-002.1)
# ---------------------------------------------------------------------------


def test_tc004_known_scalar_resolves_with_its_type(tmp_path: Path) -> None:
    """A name present in the A2L resolves with its data type and element count.

    LLR-002.1: resolution looks the entry's name up among the enriched tags
    and returns the matched ``char_type`` / ``datatype`` / ``element_count``.
    The scalar ``IGN_ADVANCE_BASE`` must come back ``RESOLVED`` with a known
    type, proving the happy path works against the enriched payload.
    """
    cl = ChangeList()
    cl.add("IGN_ADVANCE_BASE", None, 23, ResolutionStatus.UNRESOLVED_NO_A2L)

    result = resolve_against_a2l(cl, enriched_patch_tags(tmp_path))

    entry = cl.get("IGN_ADVANCE_BASE")
    assert entry.status is ResolutionStatus.RESOLVED
    resolved = result.type_for(entry)
    assert resolved == ResolvedType(
        char_type="VALUE", datatype="UWORD", element_count=1
    )


def test_tc004_known_array_resolves_with_element_count_three(
    tmp_path: Path,
) -> None:
    """A 1-D array parameter resolves with its A2L ``element_count`` (here 3).

    The element count is what the LLR-002.3 range check needs; this asserts
    the resolver carries it through from the enriched tag — a regression that
    flattened arrays to a scalar would fail here.
    """
    cl = ChangeList()
    cl.add("FUEL_TRIM_TABLE", 1, 24, ResolutionStatus.UNRESOLVED_NO_A2L)

    result = resolve_against_a2l(cl, enriched_patch_tags(tmp_path))

    entry = cl.get("FUEL_TRIM_TABLE", 1)
    assert entry.status is ResolutionStatus.RESOLVED
    resolved = result.type_for(entry)
    assert resolved is not None
    assert resolved.char_type == "VAL_BLK"
    assert resolved.element_count == 3


def test_tc004_resolution_consumes_enriched_not_bare_tags(
    tmp_path: Path,
) -> None:
    """Resolution succeeds only against the *enriched* A2L pipeline (C-1, A-01).

    Phase-2 finding A-01: a bare ``extract_a2l_tags`` ``CHARACTERISTIC`` tag
    has ``datatype = None`` and no ``decode_type``. This test feeds the
    resolver the bare ``tags`` from ``parse_a2l_file`` (un-enriched) and then
    the enriched tags, and asserts only the enriched run resolves a data type
    — encoding *why* C-1 mandates the enriched pipeline so a future change
    that resolved against bare tags would fail.
    """
    bare_tags = make_patch_a2l(tmp_path)["tags"]
    assert all(t.get("datatype") is None for t in bare_tags)  # A-01 precondition

    cl_bare = ChangeList()
    cl_bare.add("IGN_ADVANCE_BASE", None, 23, ResolutionStatus.UNRESOLVED_NO_A2L)
    bare_result = resolve_against_a2l(cl_bare, bare_tags)
    bare_resolved = bare_result.type_for(cl_bare.get("IGN_ADVANCE_BASE"))
    assert bare_resolved is not None  # name still matches
    assert bare_resolved.datatype is None  # but no type without enrichment

    cl_enriched = ChangeList()
    cl_enriched.add(
        "IGN_ADVANCE_BASE", None, 23, ResolutionStatus.UNRESOLVED_NO_A2L
    )
    enriched_result = resolve_against_a2l(
        cl_enriched, enriched_patch_tags(tmp_path)
    )
    enriched_resolved = enriched_result.type_for(
        cl_enriched.get("IGN_ADVANCE_BASE")
    )
    assert enriched_resolved is not None
    assert enriched_resolved.datatype == "UWORD"  # type only after enrichment


def test_tc004_resolution_does_not_reparse_a2l_text(tmp_path: Path) -> None:
    """The resolver consumes pre-built tags and never reads an A2L file itself.

    LLR-002.1 acceptance: resolution "does not re-parse A2L text". The
    resolver's only A2L input is the in-memory enriched tag list; this test
    builds those tags once, deletes the on-disk ``.a2l`` file, then resolves —
    a resolver that re-parsed A2L text would fail with the file gone.
    """
    enriched = enriched_patch_tags(tmp_path)
    (tmp_path / "patch.a2l").unlink()  # the resolver must not need this file

    cl = ChangeList()
    cl.add("IGN_ADVANCE_BASE", None, 23, ResolutionStatus.UNRESOLVED_NO_A2L)
    result = resolve_against_a2l(cl, enriched)

    assert cl.get("IGN_ADVANCE_BASE").status is ResolutionStatus.RESOLVED
    assert isinstance(result, ResolutionResult)


# ---------------------------------------------------------------------------
# TC-005 — unresolved-name handling (LLR-002.2)
# ---------------------------------------------------------------------------


def test_tc005_unknown_name_marks_entry_unresolved(tmp_path: Path) -> None:
    """An entry naming no A2L parameter is marked ``UNRESOLVED``, not raised.

    LLR-002.2: an unknown name "shall mark the entry ``unresolved`` and shall
    not raise an exception". A raised ``KeyError`` here would crash the Patch
    Editor when an engineer mistypes a parameter name.
    """
    cl = ChangeList()
    cl.add("NOT_IN_THE_A2L", None, 99, ResolutionStatus.UNRESOLVED_NO_A2L)

    result = resolve_against_a2l(cl, enriched_patch_tags(tmp_path))

    entry = cl.get("NOT_IN_THE_A2L")
    assert entry.status is ResolutionStatus.UNRESOLVED
    assert result.type_for(entry) is None  # no type for an unknown name


def test_tc005_unknown_name_leaves_the_list_usable(tmp_path: Path) -> None:
    """An unresolved entry does not stop the other entries from resolving.

    The change-list "stays usable": a mistyped name marks only its own entry
    unresolved while a valid sibling still resolves — the collect-don't-abort
    spirit applied to resolution.
    """
    cl = ChangeList()
    cl.add("IGN_ADVANCE_BASE", None, 23, ResolutionStatus.UNRESOLVED_NO_A2L)
    cl.add("TYPO_PARAM", None, 1, ResolutionStatus.UNRESOLVED_NO_A2L)

    resolve_against_a2l(cl, enriched_patch_tags(tmp_path))

    assert cl.get("IGN_ADVANCE_BASE").status is ResolutionStatus.RESOLVED
    assert cl.get("TYPO_PARAM").status is ResolutionStatus.UNRESOLVED
    assert len(cl) == 2  # both entries still present


# ---------------------------------------------------------------------------
# TC-006 — array-index range check (LLR-002.3)
# ---------------------------------------------------------------------------


def test_tc006_index_past_element_count_is_out_of_range(tmp_path: Path) -> None:
    """Index 5 on a 3-element parameter is flagged ``INDEX_OUT_OF_RANGE``.

    LLR-002.3 acceptance: ``FUEL_TRIM_TABLE`` has ``element_count`` 3 (valid
    indices 0/1/2); index 5 is not less than the count, so the entry is
    out-of-range — without an exception.
    """
    cl = ChangeList()
    cl.add("FUEL_TRIM_TABLE", 5, 24, ResolutionStatus.UNRESOLVED_NO_A2L)

    resolve_against_a2l(cl, enriched_patch_tags(tmp_path))

    assert (
        cl.get("FUEL_TRIM_TABLE", 5).status
        is ResolutionStatus.INDEX_OUT_OF_RANGE
    )


def test_tc006_negative_index_is_out_of_range(tmp_path: Path) -> None:
    """A negative array index is flagged ``INDEX_OUT_OF_RANGE``.

    LLR-002.3 states the index is out of range when "negative or not less than
    the resolved A2L ``element_count``"; the negative arm is exercised here so
    a check that only tested the upper bound would fail.
    """
    cl = ChangeList()
    cl.add("FUEL_TRIM_TABLE", -1, 24, ResolutionStatus.UNRESOLVED_NO_A2L)

    resolve_against_a2l(cl, enriched_patch_tags(tmp_path))

    assert (
        cl.get("FUEL_TRIM_TABLE", -1).status
        is ResolutionStatus.INDEX_OUT_OF_RANGE
    )


def test_tc006_last_valid_array_index_resolves(tmp_path: Path) -> None:
    """Index 2 on a 3-element parameter resolves — the boundary is inclusive.

    The valid range is ``0 .. element_count - 1``; index 2 is the last valid
    slot of a 3-element array. An off-by-one that rejected it would fail here.
    """
    cl = ChangeList()
    cl.add("FUEL_TRIM_TABLE", 2, 25, ResolutionStatus.UNRESOLVED_NO_A2L)

    resolve_against_a2l(cl, enriched_patch_tags(tmp_path))

    assert cl.get("FUEL_TRIM_TABLE", 2).status is ResolutionStatus.RESOLVED


def test_tc006_scalar_none_index_resolves_without_range_check(
    tmp_path: Path,
) -> None:
    """A scalar entry (``array_index is None``) resolves on name alone.

    LLR-002.3 (migrated): the range check applies only to an integer index. A
    scalar entry carries ``array_index=None`` and is **not** range-checked —
    it resolves against its scalar A2L parameter (``element_count == 1``) on
    name alone. This test also proves the resolver's ``isinstance`` guard: a
    bare ``None < 0`` comparison would raise ``TypeError`` and crash every
    scalar entry's resolution.
    """
    cl = ChangeList()
    cl.add("IGN_ADVANCE_BASE", None, 23, ResolutionStatus.UNRESOLVED_NO_A2L)

    resolve_against_a2l(cl, enriched_patch_tags(tmp_path))

    assert cl.get("IGN_ADVANCE_BASE").status is ResolutionStatus.RESOLVED


def test_tc006_out_of_range_entry_still_carries_its_resolved_type(
    tmp_path: Path,
) -> None:
    """An out-of-range entry still records the resolved parameter type.

    The *parameter* resolved even though the *index* did not — the writer and
    UI need the type to render the row, so ``type_for`` returns the matched
    ``ResolvedType`` for an ``INDEX_OUT_OF_RANGE`` entry. The status, not the
    type lookup, is what flags the problem.
    """
    cl = ChangeList()
    cl.add("FUEL_TRIM_TABLE", 9, 1, ResolutionStatus.UNRESOLVED_NO_A2L)

    result = resolve_against_a2l(cl, enriched_patch_tags(tmp_path))

    entry = cl.get("FUEL_TRIM_TABLE", 9)
    assert entry.status is ResolutionStatus.INDEX_OUT_OF_RANGE
    resolved = result.type_for(entry)
    assert resolved is not None
    assert resolved.element_count == 3


# ---------------------------------------------------------------------------
# TC-007 — resolution without a loaded A2L (LLR-002.4)
# ---------------------------------------------------------------------------


def test_tc007_no_a2l_marks_every_entry_unresolved_no_a2l() -> None:
    """With no A2L, every entry is marked ``UNRESOLVED_NO_A2L``, no exception.

    LLR-002.4: while no A2L is loaded "the resolution function shall mark every
    change-list entry ``unresolved-no-a2l``". A ``None`` A2L stands for "no A2L
    loaded" (assumption A-2).
    """
    cl = ChangeList()
    cl.add("IGN_ADVANCE_BASE", None, 23, ResolutionStatus.RESOLVED)
    cl.add("FUEL_TRIM_TABLE", 1, 24, ResolutionStatus.RESOLVED)

    result = resolve_against_a2l(cl, None)

    for entry in cl.entries:
        assert entry.status is ResolutionStatus.UNRESOLVED_NO_A2L
    assert result.resolved_types == {}  # nothing resolved without an A2L


def test_tc007_empty_a2l_tag_list_is_treated_as_no_a2l() -> None:
    """An empty enriched-tag list is treated the same as no A2L (LLR-002.4).

    A loaded-but-empty A2L produces no tags; resolution must still mark entries
    ``unresolved-no-a2l`` rather than ``unresolved``, so the UI can show the
    "load an A2L" hint instead of a per-name "not found" warning.
    """
    cl = ChangeList()
    cl.add("ANY_PARAM", None, 1, ResolutionStatus.RESOLVED)

    resolve_against_a2l(cl, [])

    assert cl.get("ANY_PARAM").status is ResolutionStatus.UNRESOLVED_NO_A2L


def test_tc007_no_a2l_keeps_the_list_intact_and_returns_result() -> None:
    """Resolution with no A2L still returns a usable ``ResolutionResult``.

    LLR-002.4: entries "are still listed". The change-list keeps every entry
    and its values; only ``status`` changes, and the returned result wraps the
    same change-list.
    """
    cl = ChangeList()
    cl.add("P", None, 7, ResolutionStatus.RESOLVED)

    result = resolve_against_a2l(cl, None)

    assert result.change_list is cl
    assert len(cl) == 1
    assert cl.get("P").value == 7  # value untouched by resolution
