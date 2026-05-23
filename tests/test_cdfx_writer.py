"""
CDFX writer tests — s19_app batch-03, increments 4 and 6.

Covers ``s19_app/tui/cdfx/writer.py`` :func:`write_cdfx` — serializing a
resolved change-list into a CDF 2.0 ``.cdfx`` byte stream:

  - TC-011 — writer emits the CDF 2.0 backbone (LLR-004.1).
  - TC-012 — one ``SW-INSTANCE`` per resolved parameter (LLR-004.2).
  - TC-013 — scalar / array / string value encoding (LLR-004.3).
  - TC-014 — well-formed UTF-8 XML with a tool note (LLR-004.4, LLR-004.7).
  - TC-032 — dedicated tool-identification-note check (LLR-004.7).
  - TC-033 — writer-side round-trip-safe float emission (LLR-004.8).

The increment-6 amendment migrated the scalar fixtures: ``array_index`` is now
``Optional[int]`` (``None`` ≙ scalar / ASCII string, an integer ≙ an array
element — LLR-001.1). Increment-4's writer emitted one ``SW-INSTANCE`` per
change-list **entry** and built scalar entries with the positional
``array_index=0``; after the migration ``0`` means array element 0, so every
scalar fixture here is rebuilt with ``array_index=None`` and the writer now
coalesces an integer-index group into one ``VAL_BLK`` instance (LLR-004.9).
The standalone ``W-*`` validator and the ``W-ARRAY-SPARSE`` cases (TC-019a..h,
TC-038) are tested in ``tests/test_cdfx_w_rules.py``.

The resolved A2L type is not a field on the entry — it is carried in the
increment-2 ``ResolutionResult``. These tests build a ``ResolutionResult``
directly (the resolver's own behaviour is covered by
``tests/test_cdfx_resolve.py``), so the writer tests need only the
``(char_type, datatype)`` pair that drives the instance ``CATEGORY``.
"""

from __future__ import annotations

from xml.etree import ElementTree as ET

from s19_app.tui.cdfx.changelist import (
    ChangeList,
    ChangeListEntry,
    ResolutionStatus,
)
from s19_app.tui.cdfx.resolve import ResolutionResult, ResolvedType
from s19_app.tui.cdfx.writer import write_cdfx


# ---------------------------------------------------------------------------
# Helpers — build a resolved change-list without running the A2L pipeline.
# ---------------------------------------------------------------------------


def _resolved_change_list(
    entries: list[tuple[str, int | None, object, ResolvedType]],
) -> tuple[ChangeList, ResolutionResult]:
    """Build a change-list of RESOLVED entries plus its ResolutionResult.

    Each tuple is ``(parameter_name, array_index, value, resolved_type)``;
    ``array_index`` is ``None`` for a scalar / ASCII-string entry and an
    integer for an array element (LLR-001.1). The entry is added with status
    ``RESOLVED`` and its ``ResolvedType`` is recorded in the result's type map
    under the entry identity — the exact shape the resolver (increment 2)
    produces for a matched parameter.
    """
    change_list = ChangeList()
    result = ResolutionResult(change_list=change_list)
    for name, index, value, resolved_type in entries:
        entry = change_list.add(name, index, value, ResolutionStatus.RESOLVED)
        result.resolved_types[entry.key] = resolved_type
    return change_list, result


def _scalar_uword() -> ResolvedType:
    """The resolved type of a scalar unsigned-word characteristic."""
    return ResolvedType(char_type="VALUE", datatype="UWORD", element_count=1)


def _array_uword(count: int) -> ResolvedType:
    """The resolved type of a 1-D array characteristic of ``count`` elements."""
    return ResolvedType(
        char_type="VAL_BLK", datatype="UWORD", element_count=count
    )


def _ascii_type() -> ResolvedType:
    """The resolved type of an ASCII (string) characteristic."""
    return ResolvedType(char_type="ASCII", datatype=None, element_count=8)


def _local(tag: str) -> str:
    """Strip a namespace prefix from an ElementTree tag for assertions."""
    return tag.rsplit("}", 1)[-1] if tag.startswith("{") else tag


def _find(parent: ET.Element, tag: str) -> ET.Element | None:
    """First direct child of ``parent`` whose local name is ``tag``."""
    for child in parent:
        if _local(child.tag) == tag:
            return child
    return None


# ---------------------------------------------------------------------------
# TC-011 — writer emits the CDF 2.0 backbone (LLR-004.1)
# ---------------------------------------------------------------------------


def test_tc011_root_is_msrsw_with_cdf20_category() -> None:
    """The output root is ``MSRSW`` carrying ``CATEGORY`` text ``CDF20``.

    LLR-004.1: a CDF 2.0 document is identified by an ``MSRSW`` root with a
    non-empty ``SHORT-NAME`` and the ``CDF20`` version token. A wrong root tag
    or version token would make the file unreadable by vCDM — this pins both.
    """
    change_list, result = _resolved_change_list(
        [("IGN_ADVANCE_BASE", None, 23, _scalar_uword())]
    )

    data, _issues = write_cdfx(change_list, result)
    root = ET.fromstring(data)

    assert _local(root.tag) == "MSRSW"
    short_name = _find(root, "SHORT-NAME")
    assert short_name is not None and short_name.text
    category = _find(root, "CATEGORY")
    assert category is not None and category.text == "CDF20"


def test_tc011_instance_tree_backbone_chain_present() -> None:
    """The ``SW-SYSTEMS...SW-INSTANCE-TREE`` chain is present with names.

    LLR-004.1: the backbone chain ``SW-SYSTEMS → SW-SYSTEM →
    SW-INSTANCE-SPEC → SW-INSTANCE-TREE`` must exist, every container carrying
    a ``SHORT-NAME``, or the instance tree has nowhere to live and the file is
    not schema-shaped.
    """
    change_list, result = _resolved_change_list(
        [("IGN_ADVANCE_BASE", None, 23, _scalar_uword())]
    )

    data, _issues = write_cdfx(change_list, result)
    root = ET.fromstring(data)

    sw_systems = _find(root, "SW-SYSTEMS")
    assert sw_systems is not None
    sw_system = _find(sw_systems, "SW-SYSTEM")
    assert sw_system is not None
    assert _find(sw_system, "SHORT-NAME") is not None
    instance_spec = _find(sw_system, "SW-INSTANCE-SPEC")
    assert instance_spec is not None
    instance_tree = _find(instance_spec, "SW-INSTANCE-TREE")
    assert instance_tree is not None
    assert _find(instance_tree, "SHORT-NAME") is not None


# ---------------------------------------------------------------------------
# TC-012 — one SW-INSTANCE per resolved parameter (LLR-004.2)
# ---------------------------------------------------------------------------


def _instances(data: bytes) -> list[ET.Element]:
    """All ``SW-INSTANCE`` elements under the instance-tree backbone."""
    root = ET.fromstring(data)
    instance_tree = _find(
        _find(_find(_find(root, "SW-SYSTEMS"), "SW-SYSTEM"), "SW-INSTANCE-SPEC"),
        "SW-INSTANCE-TREE",
    )
    assert instance_tree is not None
    return [c for c in instance_tree if _local(c.tag) == "SW-INSTANCE"]


def test_tc012_scalar_entry_yields_value_category_instance() -> None:
    """A scalar entry produces a ``SW-INSTANCE`` with ``CATEGORY=VALUE``.

    LLR-004.2: a resolved scalar characteristic must serialize as a
    ``SW-INSTANCE`` whose ``CATEGORY`` is ``VALUE`` and whose ``SHORT-NAME``
    equals the change-list parameter name — that name is the join key vCDM
    uses to match the value back to the A2L.
    """
    change_list, result = _resolved_change_list(
        [("IGN_ADVANCE_BASE", None, 23, _scalar_uword())]
    )

    data, _issues = write_cdfx(change_list, result)
    instances = _instances(data)

    assert len(instances) == 1
    assert _find(instances[0], "SHORT-NAME").text == "IGN_ADVANCE_BASE"
    assert _find(instances[0], "CATEGORY").text == "VALUE"


def test_tc012_one_instance_per_resolved_parameter() -> None:
    """Three distinct resolved parameters produce three ``SW-INSTANCE``.

    LLR-004.2: the writer emits one instance per distinct resolved
    ``parameter_name`` — no merging across names, no dropping. Three scalar /
    string parameters of distinct names give exactly three instances.
    """
    change_list, result = _resolved_change_list(
        [
            ("IGN_ADVANCE_BASE", None, 23, _scalar_uword()),
            ("FUEL_TRIM", None, 24, _scalar_uword()),
            ("CAL_LABEL", None, "REV_C", _ascii_type()),
        ]
    )

    data, _issues = write_cdfx(change_list, result)

    assert len(_instances(data)) == 3


def test_tc012_array_entries_of_one_name_coalesce_to_one_instance() -> None:
    """Three array-element entries of one name yield exactly one instance.

    LLR-004.2 / LLR-004.9: a 1-D array parameter contributes one change-list
    entry per element index, but the writer coalesces those entries into a
    single ``SW-INSTANCE`` per ``parameter_name`` — three ``(FUEL_TRIM_TABLE,
    0..2)`` entries are **one** instance, not three. This is the increment-6
    rework of the increment-4 one-instance-per-entry behaviour.
    """
    array_type = _array_uword(3)
    change_list, result = _resolved_change_list(
        [
            ("FUEL_TRIM_TABLE", 0, 23, array_type),
            ("FUEL_TRIM_TABLE", 1, 24, array_type),
            ("FUEL_TRIM_TABLE", 2, 25, array_type),
        ]
    )

    data, _issues = write_cdfx(change_list, result)
    instances = _instances(data)

    assert len(instances) == 1
    assert _find(instances[0], "SHORT-NAME").text == "FUEL_TRIM_TABLE"
    assert _find(instances[0], "CATEGORY").text == "VAL_BLK"


def test_tc012_instance_order_matches_changelist_insertion_order() -> None:
    """SW-INSTANCE order is the change-list insertion order, byte-stable.

    LLR-001.4 / LLR-004.2: the writer iterates ``ChangeList.entries`` and adds
    no second ordering rule, so two writes of the same change-list are
    byte-identical and the instances follow insertion order.
    """
    change_list, result = _resolved_change_list(
        [
            ("ZEBRA", None, 1, _scalar_uword()),
            ("ALPHA", None, 2, _scalar_uword()),
            ("MIKE", None, 3, _scalar_uword()),
        ]
    )

    first, _ = write_cdfx(change_list, result)
    second, _ = write_cdfx(change_list, result)

    assert first == second  # byte-identical across repeated writes
    names = [_find(i, "SHORT-NAME").text for i in _instances(first)]
    assert names == ["ZEBRA", "ALPHA", "MIKE"]  # insertion, not sorted


# ---------------------------------------------------------------------------
# TC-013 — scalar / array / string value encoding (LLR-004.3)
# ---------------------------------------------------------------------------


def test_tc013_scalar_value_is_one_v_element() -> None:
    """A scalar entry encodes its value as a single ``V`` element.

    LLR-004.3: a ``VALUE`` instance carries exactly one ``V`` inside
    ``SW-VALUE-CONT/SW-VALUES-PHYS``.
    """
    change_list, result = _resolved_change_list(
        [("IGN_ADVANCE_BASE", None, 23, _scalar_uword())]
    )

    data, _issues = write_cdfx(change_list, result)
    instance = _instances(data)[0]
    values_phys = _find(_find(instance, "SW-VALUE-CONT"), "SW-VALUES-PHYS")

    vs = [c for c in values_phys if _local(c.tag) == "V"]
    assert len(vs) == 1
    assert vs[0].text == "23"


def test_tc013_array_value_is_one_vg_of_positional_v() -> None:
    """A 3-element array encodes as one ``VG`` of three positional ``V``.

    LLR-004.3 / LLR-004.9: the three ``(FUEL_TRIM_TABLE, 0..2)`` array-element
    entries coalesce into a single ``VAL_BLK`` ``SW-INSTANCE`` whose one ``VG``
    holds one ``V`` per element, ordered ascending by ``array_index`` — the
    index is positional ``V`` order only, never a ``SW-ARRAY-INDEX`` element.
    """
    array_type = _array_uword(3)
    change_list, result = _resolved_change_list(
        [
            ("FUEL_TRIM_TABLE", 0, 23, array_type),
            ("FUEL_TRIM_TABLE", 1, 24, array_type),
            ("FUEL_TRIM_TABLE", 2, 25, array_type),
        ]
    )

    data, _issues = write_cdfx(change_list, result)
    instances = _instances(data)

    assert len(instances) == 1
    instance = instances[0]
    assert _find(instance, "CATEGORY").text == "VAL_BLK"
    values_phys = _find(_find(instance, "SW-VALUE-CONT"), "SW-VALUES-PHYS")
    vgs = [c for c in values_phys if _local(c.tag) == "VG"]
    assert len(vgs) == 1
    vs = [c for c in vgs[0] if _local(c.tag) == "V"]
    assert [v.text for v in vs] == ["23", "24", "25"]


def test_tc013_array_vg_v_order_is_ascending_array_index() -> None:
    """The coalesced ``VG`` orders ``V`` ascending by ``array_index``.

    LLR-004.9: the writer sorts a coalesced array group by ``array_index``, so
    a change-list that inserts the elements out of order (index 2, then 0, then
    1) still produces the ascending ``[0],[1],[2]`` positional ``V`` order — the
    positional ``V`` slot must equal the array element index, not insertion
    order, or the read-side positional expansion (LLR-005.6) would mis-key.
    """
    array_type = _array_uword(3)
    change_list, result = _resolved_change_list(
        [
            ("FUEL_TRIM_TABLE", 2, 25, array_type),
            ("FUEL_TRIM_TABLE", 0, 23, array_type),
            ("FUEL_TRIM_TABLE", 1, 24, array_type),
        ]
    )

    data, _issues = write_cdfx(change_list, result)
    instance = _instances(data)[0]
    values_phys = _find(_find(instance, "SW-VALUE-CONT"), "SW-VALUES-PHYS")
    vg = _find(values_phys, "VG")

    vs = [c for c in vg if _local(c.tag) == "V"]
    assert [v.text for v in vs] == ["23", "24", "25"]


def test_tc013_string_value_is_one_vt_element() -> None:
    """An ASCII string entry encodes its value as a single ``VT`` element.

    LLR-004.3: an ``ASCII`` instance carries exactly one ``VT`` text value.
    """
    change_list, result = _resolved_change_list(
        [("CAL_LABEL", None, "REV_C", _ascii_type())]
    )

    data, _issues = write_cdfx(change_list, result)
    instance = _instances(data)[0]
    values_phys = _find(_find(instance, "SW-VALUE-CONT"), "SW-VALUES-PHYS")

    assert _find(instance, "CATEGORY").text == "ASCII"
    vts = [c for c in values_phys if _local(c.tag) == "VT"]
    assert len(vts) == 1 and vts[0].text == "REV_C"


def test_tc013_no_sw_array_index_element_in_output() -> None:
    """No ``SW-ARRAY-INDEX`` element appears anywhere in the writer output.

    LLR-004.3 / finding A-09: the change-list ``array_index`` is serialized as
    positional ``V`` order only. ``SW-ARRAY-INDEX`` is an unrelated CDFX
    construct (an array-of-parameters element) and must never be emitted.
    """
    array_type = _array_uword(2)
    change_list, result = _resolved_change_list(
        [
            ("FUEL_TRIM_TABLE", 0, 23, array_type),
            ("FUEL_TRIM_TABLE", 1, 24, array_type),
        ]
    )

    data, _issues = write_cdfx(change_list, result)
    root = ET.fromstring(data)

    assert all(_local(e.tag) != "SW-ARRAY-INDEX" for e in root.iter())


# ---------------------------------------------------------------------------
# TC-014 — well-formed UTF-8 XML with a tool note (LLR-004.4, LLR-004.7)
# ---------------------------------------------------------------------------


def test_tc014_output_has_xml_declaration_and_reparses() -> None:
    """The written bytes carry an XML declaration and re-parse cleanly.

    LLR-004.4: the writer output must be well-formed UTF-8 XML with an XML
    declaration, parseable by ``ElementTree`` without an exception.
    """
    change_list, result = _resolved_change_list(
        [("IGN_ADVANCE_BASE", None, 23, _scalar_uword())]
    )

    data, _issues = write_cdfx(change_list, result)

    assert data.startswith(b"<?xml")
    assert b'encoding="UTF-8"' in data
    # Re-parse must not raise — well-formedness verified end-to-end.
    ET.fromstring(data)


def test_tc014_output_carries_leading_tool_note_and_reparses() -> None:
    """The output carries the s19_app tool comment and stays well-formed.

    LLR-004.4 + LLR-004.7: a leading ``Created with s19_app CDF 2.0 Writer``
    XML comment is present and the document still re-parses — the comment is
    placed between the declaration and the root so it never breaks
    well-formedness. ElementTree discards the comment on re-parse, so the
    comment is asserted against the raw bytes (increment-4 risk note).
    """
    change_list, result = _resolved_change_list(
        [("IGN_ADVANCE_BASE", None, 23, _scalar_uword())]
    )

    data, _issues = write_cdfx(change_list, result)
    text = data.decode("utf-8")

    assert "Created with s19_app CDF 2.0 Writer" in text
    assert "<!--" in text and "-->" in text
    # The comment precedes the root element.
    assert text.index("<!--") < text.index("<MSRSW")
    ET.fromstring(data)  # still well-formed with the comment present


# ---------------------------------------------------------------------------
# TC-032 — dedicated tool-identification-note check (LLR-004.7)
# ---------------------------------------------------------------------------


def test_tc032_tool_note_is_a_leading_xml_comment() -> None:
    """The tool note is a leading XML comment, placed before the root.

    LLR-004.7 / TC-032: the dedicated check — the ``.cdfx`` carries a leading
    ``Created with s19_app CDF 2.0 Writer`` XML comment, after the declaration
    and before ``<MSRSW>``, and the document re-parses without exception.
    """
    change_list, result = _resolved_change_list(
        [("CAL_LABEL", None, "REV_C", _ascii_type())]
    )

    data, _issues = write_cdfx(change_list, result)
    text = data.decode("utf-8")

    decl_end = text.index("?>") + 2
    comment_start = text.index("<!--")
    root_start = text.index("<MSRSW")
    assert decl_end <= comment_start < root_start
    assert "Created with s19_app CDF 2.0 Writer" in text[comment_start:root_start]
    ET.fromstring(data)


def test_tc032_tool_note_present_even_on_empty_changelist() -> None:
    """A backbone-only ``.cdfx`` still carries the tool-identification note.

    LLR-004.6 + LLR-004.7: an empty change-list still produces a valid
    document; the tool note is part of every writer output, not just non-empty
    ones.
    """
    change_list = ChangeList()
    result = ResolutionResult(change_list=change_list)

    data, _issues = write_cdfx(change_list, result)

    assert b"Created with s19_app CDF 2.0 Writer" in data
    ET.fromstring(data)


# ---------------------------------------------------------------------------
# TC-033 — writer-side round-trip-safe float emission (LLR-004.8)
# ---------------------------------------------------------------------------


def _written_v_text(value: float) -> str:
    """Write one float scalar and return the text of its single ``V``."""
    change_list, result = _resolved_change_list(
        [("FLOAT_PARAM", None, value, _scalar_uword())]
    )
    data, _issues = write_cdfx(change_list, result)
    for elem in ET.fromstring(data).iter():
        if _local(elem.tag) == "V":
            return elem.text or ""
    raise AssertionError("no V element written")


def test_tc033_float_v_text_is_repr_precision() -> None:
    """A float ``V`` carries full ``repr()``-precision text.

    LLR-004.8: ``0.1`` must serialize as ``repr(0.1)`` ('0.1'), the value that
    re-parses exactly to the same binary64 float. A ``str()``-equivalent text
    is fine for this value, but the writer must use ``repr`` so the adversarial
    cases below also hold.
    """
    assert _written_v_text(0.1) == repr(0.1)


def test_tc033_denormal_float_v_text_survives() -> None:
    """The denormal ``5e-324`` is emitted at full precision, not as ``0.0``.

    LLR-004.8 / TC-033: a denormal would truncate to ``0.0`` under a
    fixed-width writer. ``repr(5e-324)`` keeps it ('5e-324'), and the emitted
    text re-parses ``== 5e-324`` exactly — the test fails on any lossy writer.
    """
    text = _written_v_text(5e-324)

    assert text == repr(5e-324)
    assert float(text) == 5e-324
    assert float(text) != 0.0


def test_tc033_seventeen_digit_float_v_text_survives() -> None:
    """A 17-significant-digit float keeps its full tail in the ``V`` text.

    LLR-004.8 / TC-033: a binary64 value can need 17 significant decimal
    digits to round-trip. ``%g`` / a fixed-width format would drop the tail.
    ``repr`` keeps it — the emitted text must re-parse ``==`` the original.
    """
    adversarial = 1.2345678901234567

    text = _written_v_text(adversarial)

    assert text == repr(adversarial)
    assert float(text) == adversarial


def test_tc033_integer_value_text_is_exact_at_large_magnitude() -> None:
    """A large integer ``V`` text is exact — never routed through ``float``.

    LLR-004.8 + finding Q-10: an unsigned value above 2**53 loses low bits if
    serialized via a binary64 ``float``. The writer renders an ``int`` with
    ``str()`` directly, so the exact decimal survives.
    """
    big = 2**64 - 1

    assert _written_v_text(big) == "18446744073709551615"
