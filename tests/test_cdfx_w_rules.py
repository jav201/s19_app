"""
CDFX standalone ``W-*`` validator tests — s19_app batch-03, increments 4 and 6.

Covers the write-time ``W-*`` rule set of ``s19_app/tui/cdfx/writer.py``
(:func:`validate_w_rules` / :func:`validate_w_rules_bytes`) and the
writer-provokable exclusion / sparse-array / empty-change-list paths of
:func:`write_cdfx` — the per-rule sub-cases TC-019a..TC-019h and the
array-coalescing sparse-rejection case TC-038 (LLR-006.1, LLR-004.5,
LLR-004.6, LLR-004.9).

The eight structural ``W-*`` codes split into two groups (requirements §5.8):

  - **Writer-output invariants** — ``W-XML-WELLFORMED``, ``W-ROOT-MSRSW``,
    ``W-BACKBONE``, ``W-CATEGORY-VALUE-CONSISTENT``. A correct writer can never
    emit these; they are verified by feeding the **standalone validator** a
    crafted broken element tree (TC-019a/b/c/g). The writer-cannot-provoke fact
    is recorded by an explicit ``analysis`` test per the §5.8 / Q-05 caveat.

  - **Writer-provokable codes** — ``W-INSTANCE-NAME``, ``W-INSTANCE-CATEGORY``,
    ``W-VALUE-PRESENT`` (provoked through the standalone validator with a
    crafted instance), and the LLR-004.5 exclusion + ``W-EMPTY-CHANGELIST``
    paths (provoked through the real :func:`write_cdfx`).

Two further codes are write-time **behavior** codes, not structural rules:
``W-INSTANCE-EXCLUDED`` (TC-019d, an unresolved entry dropped) and
``W-ARRAY-SPARSE`` (TC-038, a sparse / non-zero-based array group rejected).

The increment-6 amendment migrated the scalar fixtures: ``array_index`` is now
``Optional[int]`` — a scalar entry is built with ``array_index=None`` (an
integer ``0`` now means array element 0, LLR-001.1).

Every ``W-*`` test asserts the documented code and severity. The crafted-tree
fixtures carry a valid sibling instance where applicable so "others continue"
is observable, mirroring the read-side Q-04 discipline.
"""

from __future__ import annotations

from xml.etree import ElementTree as ET

from s19_app.tui.cdfx.changelist import ChangeList, ResolutionStatus
from s19_app.tui.cdfx.resolve import ResolutionResult, ResolvedType
from s19_app.tui.cdfx.writer import (
    validate_w_rules,
    validate_w_rules_bytes,
    write_cdfx,
)
from s19_app.validation.model import ValidationSeverity


# ---------------------------------------------------------------------------
# Crafted-tree builders — deliberately broken CDFX trees for the validator.
# ---------------------------------------------------------------------------


def _text_child(parent: ET.Element, tag: str, text: str) -> ET.Element:
    """Append a text-bearing child element and return it."""
    child = ET.SubElement(parent, tag)
    child.text = text
    return child


def _good_instance(
    parent: ET.Element,
    name: str,
    category: str = "VALUE",
    value: str = "1",
) -> ET.Element:
    """Append a structurally valid ``SW-INSTANCE`` (one scalar ``V``)."""
    instance = ET.SubElement(parent, "SW-INSTANCE")
    _text_child(instance, "SHORT-NAME", name)
    _text_child(instance, "CATEGORY", category)
    value_cont = ET.SubElement(instance, "SW-VALUE-CONT")
    values_phys = ET.SubElement(value_cont, "SW-VALUES-PHYS")
    _text_child(values_phys, "V", value)
    return instance


def _backbone() -> tuple[ET.Element, ET.Element]:
    """Build a valid ``MSRSW`` backbone; return ``(root, instance_tree)``."""
    msrsw = ET.Element("MSRSW")
    _text_child(msrsw, "SHORT-NAME", "S19APP_PATCH")
    _text_child(msrsw, "CATEGORY", "CDF20")
    sw_systems = ET.SubElement(msrsw, "SW-SYSTEMS")
    sw_system = ET.SubElement(sw_systems, "SW-SYSTEM")
    _text_child(sw_system, "SHORT-NAME", "ECU1")
    instance_spec = ET.SubElement(sw_system, "SW-INSTANCE-SPEC")
    instance_tree = ET.SubElement(instance_spec, "SW-INSTANCE-TREE")
    _text_child(instance_tree, "SHORT-NAME", "PatchSet")
    return msrsw, instance_tree


def _codes(issues: list) -> list[str]:
    """Project a list of ``ValidationIssue`` to its codes."""
    return [issue.code for issue in issues]


def _resolved_change_list(
    entries: list[
        tuple[str, int | None, object, ResolutionStatus, ResolvedType | None]
    ],
) -> tuple[ChangeList, ResolutionResult]:
    """Build a change-list + ResolutionResult with explicit per-entry status.

    ``array_index`` (the second tuple field) is ``None`` for a scalar / ASCII
    entry and an integer for an array element (LLR-001.1).
    """
    change_list = ChangeList()
    result = ResolutionResult(change_list=change_list)
    for name, index, value, status, resolved_type in entries:
        entry = change_list.add(name, index, value, status)
        if resolved_type is not None:
            result.resolved_types[entry.key] = resolved_type
    return change_list, result


# ---------------------------------------------------------------------------
# TC-019a — W-XML-WELLFORMED (writer-output invariant)
# ---------------------------------------------------------------------------


def test_tc019a_validator_flags_non_well_formed_bytes() -> None:
    """A non-well-formed byte stream yields one ``W-XML-WELLFORMED`` error.

    LLR-006.1: ``validate_w_rules_bytes`` parses the byte stream; an
    unparseable document is reported as exactly one ``W-XML-WELLFORMED`` issue
    at ``ERROR`` severity, never an uncaught exception.
    """
    issues = validate_w_rules_bytes(b"<MSRSW><SHORT-NAME>oops")

    assert _codes(issues) == ["W-XML-WELLFORMED"]
    assert issues[0].severity is ValidationSeverity.ERROR
    assert issues[0].artifact == "cdfx"


def test_tc019a_analysis_writer_cannot_emit_malformed_xml() -> None:
    """analysis: a correct writer can never provoke ``W-XML-WELLFORMED``.

    Requirements §5.8 / Q-05: ``W-XML-WELLFORMED`` is a writer-output
    invariant — ``write_cdfx`` builds the document with ``ElementTree``, which
    cannot produce non-well-formed XML. This test records that fact by
    asserting the real writer's output passes ``validate_w_rules_bytes`` with
    zero issues; the negative case is exercised only via the standalone
    validator (test above).
    """
    change_list, result = _resolved_change_list(
        [
            (
                "P",
                None,
                1,
                ResolutionStatus.RESOLVED,
                ResolvedType("VALUE", "UWORD", 1),
            )
        ]
    )

    data, _issues = write_cdfx(change_list, result)

    assert validate_w_rules_bytes(data) == []  # writer output is always valid


# ---------------------------------------------------------------------------
# TC-019b — W-ROOT-MSRSW (writer-output invariant)
# ---------------------------------------------------------------------------


def test_tc019b_validator_flags_wrong_root_tag() -> None:
    """A root tag other than ``MSRSW`` yields one ``W-ROOT-MSRSW`` error.

    LLR-006.1: the standalone validator fed a tree whose root is not ``MSRSW``
    reports exactly one ``W-ROOT-MSRSW`` issue at ``ERROR`` severity.
    """
    bad = ET.Element("NOT-MSRSW")

    issues = validate_w_rules(bad)

    assert _codes(issues) == ["W-ROOT-MSRSW"]
    assert issues[0].severity is ValidationSeverity.ERROR


def test_tc019b_analysis_writer_always_emits_msrsw_root() -> None:
    """analysis: the real writer always roots its output at ``MSRSW``.

    Requirements §5.8: ``W-ROOT-MSRSW`` is a writer invariant —
    ``write_cdfx`` always creates an ``MSRSW`` root, so the validator never
    fires it on writer output. Recorded by asserting no ``W-ROOT-MSRSW`` issue
    on a real write.
    """
    change_list, result = _resolved_change_list(
        [
            (
                "P",
                None,
                1,
                ResolutionStatus.RESOLVED,
                ResolvedType("VALUE", "UWORD", 1),
            )
        ]
    )

    data, _issues = write_cdfx(change_list, result)

    assert "W-ROOT-MSRSW" not in _codes(validate_w_rules(ET.fromstring(data)))


# ---------------------------------------------------------------------------
# TC-019c — W-BACKBONE (writer-output invariant)
# ---------------------------------------------------------------------------


def test_tc019c_validator_flags_missing_backbone() -> None:
    """An ``MSRSW`` with no instance-tree backbone yields one ``W-BACKBONE``.

    LLR-006.1: the standalone validator fed an ``MSRSW`` whose
    ``SW-SYSTEMS...SW-INSTANCE-TREE`` chain is incomplete reports exactly one
    ``W-BACKBONE`` issue at ``ERROR`` severity.
    """
    msrsw = ET.Element("MSRSW")
    _text_child(msrsw, "SHORT-NAME", "S19APP_PATCH")
    _text_child(msrsw, "CATEGORY", "CDF20")
    # No SW-SYSTEMS chain at all.

    issues = validate_w_rules(msrsw)

    assert _codes(issues) == ["W-BACKBONE"]
    assert issues[0].severity is ValidationSeverity.ERROR


def test_tc019c_validator_flags_partial_backbone() -> None:
    """A backbone broken partway down still yields one ``W-BACKBONE``.

    LLR-006.1: a missing link anywhere in the chain (here ``SW-INSTANCE-SPEC``
    is absent) is the same ``W-BACKBONE`` violation — the validator walks the
    full chain and reports a single issue when any link is missing.
    """
    msrsw = ET.Element("MSRSW")
    _text_child(msrsw, "SHORT-NAME", "S19APP_PATCH")
    _text_child(msrsw, "CATEGORY", "CDF20")
    sw_systems = ET.SubElement(msrsw, "SW-SYSTEMS")
    sw_system = ET.SubElement(sw_systems, "SW-SYSTEM")
    _text_child(sw_system, "SHORT-NAME", "ECU1")
    # SW-INSTANCE-SPEC / SW-INSTANCE-TREE deliberately omitted.

    issues = validate_w_rules(msrsw)

    assert _codes(issues) == ["W-BACKBONE"]


def test_tc019c_analysis_writer_always_emits_full_backbone() -> None:
    """analysis: the real writer always emits the complete backbone.

    Requirements §5.8: ``W-BACKBONE`` is a writer invariant — ``write_cdfx``
    builds the full ``SW-SYSTEMS...SW-INSTANCE-TREE`` chain unconditionally.
    Recorded by asserting no ``W-BACKBONE`` issue on a real write.
    """
    change_list = ChangeList()
    result = ResolutionResult(change_list=change_list)

    data, _issues = write_cdfx(change_list, result)  # even an empty write

    assert "W-BACKBONE" not in _codes(validate_w_rules(ET.fromstring(data)))


# ---------------------------------------------------------------------------
# TC-019d — W-INSTANCE-NAME + unresolved-exclusion (LLR-006.1, LLR-004.5)
# ---------------------------------------------------------------------------


def test_tc019d_validator_flags_empty_instance_name() -> None:
    """A ``SW-INSTANCE`` with an empty ``SHORT-NAME`` yields ``W-INSTANCE-NAME``.

    LLR-006.1: the standalone validator fed an instance whose ``SHORT-NAME`` is
    empty reports one ``W-INSTANCE-NAME`` issue at ``ERROR`` severity.
    """
    msrsw, instance_tree = _backbone()
    instance = ET.SubElement(instance_tree, "SW-INSTANCE")
    _text_child(instance, "SHORT-NAME", "   ")  # whitespace-only = empty
    _text_child(instance, "CATEGORY", "VALUE")
    value_cont = ET.SubElement(instance, "SW-VALUE-CONT")
    values_phys = ET.SubElement(value_cont, "SW-VALUES-PHYS")
    _text_child(values_phys, "V", "1")

    issues = validate_w_rules(msrsw)

    assert _codes(issues) == ["W-INSTANCE-NAME"]
    assert issues[0].severity is ValidationSeverity.ERROR


def test_tc019d_unresolved_entry_excluded_valid_sibling_written() -> None:
    """An unresolved entry is excluded with a warning; a valid sibling stays.

    LLR-004.5: a change-list with one ``UNRESOLVED`` entry and one ``RESOLVED``
    entry writes only the resolved entry as a ``SW-INSTANCE`` and emits exactly
    one warning ``ValidationIssue`` for the excluded one — the "others
    continue" intent.
    """
    change_list, result = _resolved_change_list(
        [
            ("UNKNOWN_PARAM", None, 5, ResolutionStatus.UNRESOLVED, None),
            (
                "IGN_ADVANCE_BASE",
                None,
                23,
                ResolutionStatus.RESOLVED,
                ResolvedType("VALUE", "UWORD", 1),
            ),
        ]
    )

    data, issues = write_cdfx(change_list, result)
    root = ET.fromstring(data)
    instances = [e for e in root.iter() if e.tag.rsplit("}", 1)[-1] == "SW-INSTANCE"]
    names = [
        e.text
        for inst in instances
        for e in inst
        if e.tag.rsplit("}", 1)[-1] == "SHORT-NAME"
    ]

    assert names == ["IGN_ADVANCE_BASE"]  # only the resolved entry written
    exclusions = [i for i in issues if i.code == "W-INSTANCE-EXCLUDED"]
    assert len(exclusions) == 1
    assert exclusions[0].severity is ValidationSeverity.WARNING
    assert exclusions[0].symbol == "UNKNOWN_PARAM"


def test_tc019d_index_out_of_range_entry_excluded() -> None:
    """An ``INDEX_OUT_OF_RANGE`` entry is excluded, gated on status not type.

    LLR-004.5 + increment-2 risk note: an out-of-range entry still has a
    resolved type in the type map, so the writer must gate on the entry
    ``status`` (excludes ``INDEX_OUT_OF_RANGE``), not on "is a type present".
    """
    change_list, result = _resolved_change_list(
        [
            (
                "FUEL_TRIM_TABLE",
                9,
                42,
                ResolutionStatus.INDEX_OUT_OF_RANGE,
                ResolvedType("VAL_BLK", "UWORD", 3),  # type IS present
            ),
        ]
    )

    data, issues = write_cdfx(change_list, result)
    root = ET.fromstring(data)

    assert not [e for e in root.iter() if e.tag.rsplit("}", 1)[-1] == "SW-INSTANCE"]
    assert "W-INSTANCE-EXCLUDED" in _codes(issues)


# ---------------------------------------------------------------------------
# TC-019e — W-INSTANCE-CATEGORY
# ---------------------------------------------------------------------------


def test_tc019e_validator_flags_unsupported_category() -> None:
    """An out-of-set ``CATEGORY`` yields exactly one ``W-INSTANCE-CATEGORY``.

    LLR-006.1: the standalone validator fed a ``SW-INSTANCE`` whose
    ``CATEGORY`` is outside the editable set (``VALUE``/``BOOLEAN``/``VAL_BLK``/
    ``ASCII``) — here ``MAP`` — reports one ``W-INSTANCE-CATEGORY`` issue at
    ``ERROR`` severity.
    """
    msrsw, instance_tree = _backbone()
    instance = ET.SubElement(instance_tree, "SW-INSTANCE")
    _text_child(instance, "SHORT-NAME", "SOME_MAP")
    _text_child(instance, "CATEGORY", "MAP")  # not editable
    value_cont = ET.SubElement(instance, "SW-VALUE-CONT")
    values_phys = ET.SubElement(value_cont, "SW-VALUES-PHYS")
    _text_child(values_phys, "V", "1")

    issues = validate_w_rules(msrsw)

    assert _codes(issues) == ["W-INSTANCE-CATEGORY"]
    assert issues[0].severity is ValidationSeverity.ERROR


# ---------------------------------------------------------------------------
# TC-019f — W-VALUE-PRESENT
# ---------------------------------------------------------------------------


def test_tc019f_validator_flags_instance_with_no_value() -> None:
    """A ``SW-INSTANCE`` with no ``V``/``VT`` yields one ``W-VALUE-PRESENT``.

    LLR-006.1: the standalone validator fed an instance whose
    ``SW-VALUE-CONT/SW-VALUES-PHYS`` carries no value element reports one
    ``W-VALUE-PRESENT`` issue at ``ERROR`` severity.
    """
    msrsw, instance_tree = _backbone()
    instance = ET.SubElement(instance_tree, "SW-INSTANCE")
    _text_child(instance, "SHORT-NAME", "EMPTY_PARAM")
    _text_child(instance, "CATEGORY", "VALUE")
    value_cont = ET.SubElement(instance, "SW-VALUE-CONT")
    ET.SubElement(value_cont, "SW-VALUES-PHYS")  # present but empty

    issues = validate_w_rules(msrsw)

    # An empty SW-VALUES-PHYS also makes CATEGORY=VALUE inconsistent (0 V).
    assert "W-VALUE-PRESENT" in _codes(issues)
    value_issue = next(i for i in issues if i.code == "W-VALUE-PRESENT")
    assert value_issue.severity is ValidationSeverity.ERROR


# ---------------------------------------------------------------------------
# TC-019g — W-CATEGORY-VALUE-CONSISTENT (writer-output invariant)
# ---------------------------------------------------------------------------


def test_tc019g_validator_flags_category_value_mismatch() -> None:
    """A ``VALUE`` instance carrying a ``VG`` yields ``W-CATEGORY-VALUE-CONSISTENT``.

    LLR-006.1: the standalone validator fed a deliberately inconsistent tree —
    ``CATEGORY=VALUE`` (which must carry exactly one ``V``) but holding a
    ``VG`` — reports one ``W-CATEGORY-VALUE-CONSISTENT`` issue at ``ERROR``
    severity.
    """
    msrsw, instance_tree = _backbone()
    instance = ET.SubElement(instance_tree, "SW-INSTANCE")
    _text_child(instance, "SHORT-NAME", "WRONG_SHAPE")
    _text_child(instance, "CATEGORY", "VALUE")
    value_cont = ET.SubElement(instance, "SW-VALUE-CONT")
    values_phys = ET.SubElement(value_cont, "SW-VALUES-PHYS")
    vg = ET.SubElement(values_phys, "VG")  # a VG is wrong for VALUE
    _text_child(vg, "V", "1")

    issues = validate_w_rules(msrsw)

    assert _codes(issues) == ["W-CATEGORY-VALUE-CONSISTENT"]
    assert issues[0].severity is ValidationSeverity.ERROR


def test_tc019g_analysis_writer_emits_consistent_category_and_value() -> None:
    """analysis: the real writer always matches value shape to ``CATEGORY``.

    Requirements §5.8: ``W-CATEGORY-VALUE-CONSISTENT`` is a writer invariant —
    ``write_cdfx`` picks the value encoding (``V`` / ``VG`` / ``VT``) from the
    same category it writes, so the shape is always consistent. Recorded by
    asserting no ``W-CATEGORY-VALUE-CONSISTENT`` issue across a scalar, an
    array and a string write.
    """
    change_list, result = _resolved_change_list(
        [
            (
                "SCALAR",
                None,
                1,
                ResolutionStatus.RESOLVED,
                ResolvedType("VALUE", "UWORD", 1),
            ),
            (
                "ARRAY",
                0,
                2,
                ResolutionStatus.RESOLVED,
                ResolvedType("VAL_BLK", "UWORD", 1),
            ),
            (
                "LABEL",
                None,
                "REV_C",
                ResolutionStatus.RESOLVED,
                ResolvedType("ASCII", None, 8),
            ),
        ]
    )

    data, _issues = write_cdfx(change_list, result)

    assert validate_w_rules(ET.fromstring(data)) == []


# ---------------------------------------------------------------------------
# TC-019h — W-EMPTY-CHANGELIST — empty and all-unresolved (LLR-004.6)
# ---------------------------------------------------------------------------


def test_tc019h_empty_changelist_yields_backbone_and_one_warning() -> None:
    """A literally-empty change-list yields a valid backbone + one warning.

    LLR-004.6: an empty change-list still produces a valid backbone-only
    ``MSRSW`` document and exactly one ``W-EMPTY-CHANGELIST`` warning.
    """
    change_list = ChangeList()
    result = ResolutionResult(change_list=change_list)

    data, issues = write_cdfx(change_list, result)
    root = ET.fromstring(data)

    assert root.tag.rsplit("}", 1)[-1] == "MSRSW"  # valid backbone-only file
    assert not [e for e in root.iter() if e.tag.rsplit("}", 1)[-1] == "SW-INSTANCE"]
    empties = [i for i in issues if i.code == "W-EMPTY-CHANGELIST"]
    assert len(empties) == 1
    assert empties[0].severity is ValidationSeverity.WARNING
    assert validate_w_rules(root) == []  # the backbone-only file is W-* clean


def test_tc019h_all_unresolved_yields_two_exclusions_plus_one_empty() -> None:
    """Two all-unresolved entries → two exclusion warnings + one empty warning.

    LLR-004.6 / finding A-05: ``W-EMPTY-CHANGELIST`` fires on the
    zero-*writable* condition, not only on a literally-empty list. Two
    ``UNRESOLVED`` entries therefore yield two ``W-INSTANCE-EXCLUDED`` warnings
    **and** one ``W-EMPTY-CHANGELIST`` — three warnings total.
    """
    change_list, result = _resolved_change_list(
        [
            ("UNKNOWN_A", None, 1, ResolutionStatus.UNRESOLVED, None),
            ("UNKNOWN_B", None, 2, ResolutionStatus.UNRESOLVED, None),
        ]
    )

    data, issues = write_cdfx(change_list, result)

    assert _codes(issues).count("W-INSTANCE-EXCLUDED") == 2
    assert _codes(issues).count("W-EMPTY-CHANGELIST") == 1
    assert len(issues) == 3
    assert all(i.severity is ValidationSeverity.WARNING for i in issues)
    # The deliverable is still a valid backbone-only document.
    assert validate_w_rules(ET.fromstring(data)) == []


# ---------------------------------------------------------------------------
# TC-038 — writer coalescing + W-ARRAY-SPARSE (LLR-004.9, LLR-006.1)
# ---------------------------------------------------------------------------


def _array_type(count: int) -> ResolvedType:
    """The resolved type of a 1-D array characteristic of ``count`` elements."""
    return ResolvedType(char_type="VAL_BLK", datatype="UWORD", element_count=count)


def _instances(data: bytes) -> list[ET.Element]:
    """All ``SW-INSTANCE`` elements anywhere in the writer output."""
    return [
        e
        for e in ET.fromstring(data).iter()
        if e.tag.rsplit("}", 1)[-1] == "SW-INSTANCE"
    ]


def test_tc038_contiguous_array_group_coalesces_to_one_val_blk() -> None:
    """``PARAM[0..2]`` coalesce into one ``VAL_BLK`` instance, one 3-``V`` ``VG``.

    LLR-004.9: three array-element entries of one ``parameter_name`` whose
    indices are the contiguous gapless zero-based sequence ``0,1,2`` are
    coalesced into exactly one ``VAL_BLK`` ``SW-INSTANCE`` carrying one ``VG``
    of three positional ``V`` ordered ascending by ``array_index``. No
    ``W-ARRAY-SPARSE`` is emitted — the group is well-formed.
    """
    change_list, result = _resolved_change_list(
        [
            ("PARAM", 0, 23, ResolutionStatus.RESOLVED, _array_type(3)),
            ("PARAM", 1, 24, ResolutionStatus.RESOLVED, _array_type(3)),
            ("PARAM", 2, 25, ResolutionStatus.RESOLVED, _array_type(3)),
        ]
    )

    data, issues = write_cdfx(change_list, result)
    instances = _instances(data)

    assert len(instances) == 1
    assert issues == []  # a contiguous group is not sparse
    instance = instances[0]
    assert next(
        c.text for c in instance if c.tag.rsplit("}", 1)[-1] == "CATEGORY"
    ) == "VAL_BLK"
    vgs = [e for e in instance.iter() if e.tag.rsplit("}", 1)[-1] == "VG"]
    assert len(vgs) == 1
    vs = [c.text for c in vgs[0] if c.tag.rsplit("}", 1)[-1] == "V"]
    assert vs == ["23", "24", "25"]  # ascending by array_index
    # The coalesced document still passes every structural W-* rule.
    assert validate_w_rules(ET.fromstring(data)) == []


def test_tc038_gap_array_group_rejected_with_one_w_array_sparse() -> None:
    """A gap (``PARAM[0]``, ``PARAM[2]``, no ``PARAM[1]``) → ``W-ARRAY-SPARSE``.

    LLR-004.9 sparse rule: a coalesced group whose integer indices are not the
    contiguous gapless zero-based sequence ``0..N-1`` is rejected — no
    ``SW-INSTANCE`` for that parameter and exactly one ``W-ARRAY-SPARSE``
    warning naming it. The writer never synthesizes a ``V`` for the missing
    index 1 — gap-filling would ship an unentered ECU value.
    """
    change_list, result = _resolved_change_list(
        [
            ("PARAM", 0, 23, ResolutionStatus.RESOLVED, _array_type(3)),
            ("PARAM", 2, 25, ResolutionStatus.RESOLVED, _array_type(3)),
        ]
    )

    data, issues = write_cdfx(change_list, result)

    assert _instances(data) == []  # no instance for the sparse parameter
    sparse = [i for i in issues if i.code == "W-ARRAY-SPARSE"]
    assert len(sparse) == 1
    assert sparse[0].severity is ValidationSeverity.WARNING
    assert sparse[0].symbol == "PARAM"
    # No V is synthesized for the missing index — the writer emits zero V.
    assert not [e for e in ET.fromstring(data).iter() if e.tag.rsplit("}", 1)[-1] == "V"]


def test_tc038_non_zero_based_array_group_rejected_with_one_w_array_sparse() -> None:
    """A non-zero-based group (``PARAM[1]``, ``PARAM[2]``) → ``W-ARRAY-SPARSE``.

    LLR-004.9 sparse rule: a group whose lowest index is not 0 cannot be
    represented as a positional ``VG`` without inventing element 0, so it is
    rejected exactly like a gapped group — no ``SW-INSTANCE``, one
    ``W-ARRAY-SPARSE`` warning naming the parameter.
    """
    change_list, result = _resolved_change_list(
        [
            ("PARAM", 1, 24, ResolutionStatus.RESOLVED, _array_type(3)),
            ("PARAM", 2, 25, ResolutionStatus.RESOLVED, _array_type(3)),
        ]
    )

    data, issues = write_cdfx(change_list, result)

    assert _instances(data) == []
    sparse = [i for i in issues if i.code == "W-ARRAY-SPARSE"]
    assert len(sparse) == 1
    assert sparse[0].symbol == "PARAM"


def test_tc038_sparse_only_changelist_yields_backbone_and_empty_warning() -> None:
    """A sparse-only change-list → backbone-only + W-ARRAY-SPARSE + W-EMPTY.

    LLR-004.9 + LLR-004.6: a change-list whose only entries form a single
    sparse array group writes a valid backbone-only ``.cdfx``, one
    ``W-ARRAY-SPARSE`` warning, **and** one ``W-EMPTY-CHANGELIST`` — the
    sparse exclusion feeds the LLR-004.6 zero-writable accounting exactly as a
    ``W-INSTANCE-EXCLUDED`` exclusion does.
    """
    change_list, result = _resolved_change_list(
        [
            ("PARAM", 0, 23, ResolutionStatus.RESOLVED, _array_type(3)),
            ("PARAM", 2, 25, ResolutionStatus.RESOLVED, _array_type(3)),
        ]
    )

    data, issues = write_cdfx(change_list, result)
    root = ET.fromstring(data)

    assert root.tag.rsplit("}", 1)[-1] == "MSRSW"  # valid backbone-only file
    assert _instances(data) == []
    assert _codes(issues).count("W-ARRAY-SPARSE") == 1
    assert _codes(issues).count("W-EMPTY-CHANGELIST") == 1
    assert len(issues) == 2
    assert all(i.severity is ValidationSeverity.WARNING for i in issues)
    assert validate_w_rules(root) == []  # backbone-only file is W-* clean


def test_tc038_sparse_group_does_not_block_a_valid_sibling_parameter() -> None:
    """A sparse group is rejected while a valid sibling parameter still writes.

    LLR-004.9: rejecting a sparse array is per-parameter — a contiguous array
    parameter and a scalar parameter in the same change-list are written
    normally; only the sparse ``PARAM`` is dropped, with one ``W-ARRAY-SPARSE``
    warning. The "others continue" collect-don't-abort intent.
    """
    change_list, result = _resolved_change_list(
        [
            # sparse group — index 1 missing
            ("SPARSE_ARR", 0, 1, ResolutionStatus.RESOLVED, _array_type(3)),
            ("SPARSE_ARR", 2, 3, ResolutionStatus.RESOLVED, _array_type(3)),
            # a valid contiguous array sibling
            ("GOOD_ARR", 0, 7, ResolutionStatus.RESOLVED, _array_type(2)),
            ("GOOD_ARR", 1, 8, ResolutionStatus.RESOLVED, _array_type(2)),
            # a valid scalar sibling
            ("GOOD_SCALAR", None, 9, ResolutionStatus.RESOLVED,
             ResolvedType("VALUE", "UWORD", 1)),
        ]
    )

    data, issues = write_cdfx(change_list, result)
    instances = _instances(data)
    names = [
        next(c.text for c in i if c.tag.rsplit("}", 1)[-1] == "SHORT-NAME")
        for i in instances
    ]

    assert names == ["GOOD_ARR", "GOOD_SCALAR"]  # SPARSE_ARR dropped, order kept
    assert _codes(issues) == ["W-ARRAY-SPARSE"]
    assert issues[0].symbol == "SPARSE_ARR"
    assert validate_w_rules(ET.fromstring(data)) == []
