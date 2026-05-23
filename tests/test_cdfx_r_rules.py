"""
CDFX read-time ``R-*`` rule tests — s19_app batch-03, increment 7.

Covers the read-time validation rule set of ``s19_app/tui/cdfx/reader.py``
(:func:`read_cdfx`) — the ``R-*`` structural / version codes of
``design-input/cdfx-research.md`` §7 and the LLR-008 A2L cross-check:

  - TC-020 — read-time structural rule violations emit ``R-*`` issues, and a
             valid sibling instance is still recovered (LLR-006.2, Q-04
             collect-don't-abort).
  - TC-021 — version-token tolerance on read (LLR-006.2, LLR-006.4).
  - TC-023 — unsupported instance categories are read-only, not fatal
             (LLR-006.2, LLR-006.5).
  - TC-029 — A2L name cross-check on load (LLR-008.1).
  - TC-030 — A2L array-length cross-check on load (LLR-008.2).
  - TC-031 — cross-check skipped without an A2L (LLR-008.3).

``make_rule_violation_cdfx`` is a parametrized generator — one ``.cdfx`` per
``R-*`` rule, **each carrying a valid sibling ``SW-INSTANCE``** so TC-020 can
assert the valid sibling is still recovered (the collect-don't-abort intent,
Q-04). Every fixture is synthetic and built in-test (constraint C-9).

The A2L cross-check (LLR-008) reads only the ``name`` and ``element_count``
fields of the enriched A2L tags, so these tests build minimal tag dicts of
exactly that shape rather than running the full A2L pipeline — the reader's
``a2l_tags`` parameter is documented as a ``list[dict]`` read for those two
fields.
"""

from __future__ import annotations

import pytest

from s19_app.tui.cdfx import read_cdfx
from s19_app.validation.model import ValidationSeverity


# ---------------------------------------------------------------------------
# Fixture builders — a valid sibling instance + the per-rule violation.
# ---------------------------------------------------------------------------

# A structurally valid VALUE SW-INSTANCE, used as the "sibling that survives"
# in every violation fixture (Q-04 collect-don't-abort).
_VALID_SIBLING = (
    b"<SW-INSTANCE><SHORT-NAME>VALID_SIBLING</SHORT-NAME>"
    b"<CATEGORY>VALUE</CATEGORY>"
    b"<SW-VALUE-CONT><SW-VALUES-PHYS><V>1</V>"
    b"</SW-VALUES-PHYS></SW-VALUE-CONT></SW-INSTANCE>"
)


def _wrap_backbone(instances: bytes, category: bytes = b"CDF20") -> bytes:
    """Wrap one or more ``SW-INSTANCE`` byte strings in a valid CDFX backbone."""
    return (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b"<MSRSW><SHORT-NAME>P</SHORT-NAME><CATEGORY>" + category + b"</CATEGORY>"
        b"<SW-SYSTEMS><SW-SYSTEM><SHORT-NAME>ECU1</SHORT-NAME>"
        b"<SW-INSTANCE-SPEC><SW-INSTANCE-TREE><SHORT-NAME>PatchSet</SHORT-NAME>"
        + instances
        + b"</SW-INSTANCE-TREE></SW-INSTANCE-SPEC></SW-SYSTEM></SW-SYSTEMS>"
        b"</MSRSW>"
    )


def make_rule_violation_cdfx(rule: str) -> bytes:
    """Build a ``.cdfx`` crafted to trip exactly one read-time ``R-*`` rule.

    Every variant — except the whole-document rules ``R-ROOT-MSRSW`` /
    ``R-BACKBONE-MISSING`` — also carries one valid ``SW-INSTANCE`` so the
    collect-don't-abort recovery (Q-04) is observable.
    """
    if rule == "R-ROOT-MSRSW":
        return (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b"<NOT-MSRSW><SHORT-NAME>P</SHORT-NAME></NOT-MSRSW>"
        )
    if rule == "R-BACKBONE-MISSING":
        return (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b"<MSRSW><SHORT-NAME>P</SHORT-NAME><CATEGORY>CDF20</CATEGORY>"
            b"</MSRSW>"
        )
    if rule == "R-INSTANCE-NO-NAME":
        nameless = (
            b"<SW-INSTANCE><CATEGORY>VALUE</CATEGORY>"
            b"<SW-VALUE-CONT><SW-VALUES-PHYS><V>5</V>"
            b"</SW-VALUES-PHYS></SW-VALUE-CONT></SW-INSTANCE>"
        )
        return _wrap_backbone(nameless + _VALID_SIBLING)
    if rule == "R-INSTANCE-NO-VALUE":
        valueless = (
            b"<SW-INSTANCE><SHORT-NAME>NO_VALUE</SHORT-NAME>"
            b"<CATEGORY>VALUE</CATEGORY>"
            b"<SW-VALUE-CONT><SW-VALUES-PHYS></SW-VALUES-PHYS>"
            b"</SW-VALUE-CONT></SW-INSTANCE>"
        )
        return _wrap_backbone(valueless + _VALID_SIBLING)
    if rule == "R-CATEGORY-VALUE-MISMATCH":
        # A VALUE instance carrying three V — a scalar must carry exactly one.
        mismatch = (
            b"<SW-INSTANCE><SHORT-NAME>MISMATCH</SHORT-NAME>"
            b"<CATEGORY>VALUE</CATEGORY>"
            b"<SW-VALUE-CONT><SW-VALUES-PHYS><V>1</V><V>2</V><V>3</V>"
            b"</SW-VALUES-PHYS></SW-VALUE-CONT></SW-INSTANCE>"
        )
        return _wrap_backbone(mismatch + _VALID_SIBLING)
    if rule == "R-VALUE-NOT-NUMERIC":
        non_numeric = (
            b"<SW-INSTANCE><SHORT-NAME>NOT_NUMERIC</SHORT-NAME>"
            b"<CATEGORY>VALUE</CATEGORY>"
            b"<SW-VALUE-CONT><SW-VALUES-PHYS><V>not-a-number</V>"
            b"</SW-VALUES-PHYS></SW-VALUE-CONT></SW-INSTANCE>"
        )
        return _wrap_backbone(non_numeric + _VALID_SIBLING)
    raise ValueError(f"unknown rule fixture: {rule}")


# ---------------------------------------------------------------------------
# TC-020 — read-time structural rule violations emit R-* issues (LLR-006.2)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("rule", "severity"),
    [
        ("R-ROOT-MSRSW", ValidationSeverity.ERROR),
        ("R-BACKBONE-MISSING", ValidationSeverity.ERROR),
        ("R-INSTANCE-NO-NAME", ValidationSeverity.ERROR),
        ("R-INSTANCE-NO-VALUE", ValidationSeverity.ERROR),
        ("R-CATEGORY-VALUE-MISMATCH", ValidationSeverity.WARNING),
        ("R-VALUE-NOT-NUMERIC", ValidationSeverity.WARNING),
    ],
)
def test_tc020_each_structural_rule_is_provoked_with_its_severity(
    rule: str,
    severity: ValidationSeverity,
) -> None:
    """Each ``R-*`` structural rule is provoked with its documented severity.

    LLR-006.2: every read-time structural rule code is provokable by a crafted
    fixture and emitted with the severity research §7 documents — the contract
    tests assert on.
    """
    _change_list, issues = read_cdfx(make_rule_violation_cdfx(rule))

    codes = [i.code for i in issues]
    assert rule in codes
    matched = next(i for i in issues if i.code == rule)
    assert matched.severity is severity


@pytest.mark.parametrize(
    "rule",
    [
        "R-INSTANCE-NO-NAME",
        "R-INSTANCE-NO-VALUE",
        "R-CATEGORY-VALUE-MISMATCH",
        "R-VALUE-NOT-NUMERIC",
    ],
)
def test_tc020_valid_sibling_is_recovered_despite_a_bad_instance(
    rule: str,
) -> None:
    """A violating instance does not abort the tree — the sibling is recovered.

    LLR-006.2 / Q-04: the reader collects, it does not abort. Each
    instance-level violation fixture carries one valid ``SW-INSTANCE``
    alongside the bad one; the valid sibling must still arrive in the
    change-list.
    """
    change_list, _issues = read_cdfx(make_rule_violation_cdfx(rule))

    assert change_list.get("VALID_SIBLING") is not None


def test_tc020_root_msrsw_violation_returns_empty_change_list() -> None:
    """A non-``MSRSW`` root yields ``R-ROOT-MSRSW`` and no entries (LLR-006.2).

    A document not rooted at ``MSRSW`` has an unknown shape — the reader cannot
    locate a backbone, so it returns an empty change-list rather than guessing.
    """
    change_list, issues = read_cdfx(make_rule_violation_cdfx("R-ROOT-MSRSW"))

    assert len(change_list) == 0
    assert [i.code for i in issues] == ["R-ROOT-MSRSW"]


def test_tc020_backbone_missing_violation_returns_empty_change_list() -> None:
    """A missing backbone yields ``R-BACKBONE-MISSING`` and no entries.

    LLR-006.2: with no ``SW-INSTANCE-TREE`` the reader has nowhere to look for
    instances — it reports the missing backbone and returns an empty list.
    """
    change_list, issues = read_cdfx(
        make_rule_violation_cdfx("R-BACKBONE-MISSING")
    )

    assert len(change_list) == 0
    assert [i.code for i in issues] == ["R-BACKBONE-MISSING"]


def test_tc020_value_not_numeric_keeps_the_value_as_raw_text() -> None:
    """A non-numeric ``V`` is flagged but kept as raw text (LLR-006.2).

    Research §7 ``R-VALUE-NOT-NUMERIC``: the value is "kept as raw text,
    flagged" — the reader still produces the entry, with the raw string.
    """
    change_list, _issues = read_cdfx(
        make_rule_violation_cdfx("R-VALUE-NOT-NUMERIC")
    )

    entry = change_list.get("NOT_NUMERIC")
    assert entry is not None and entry.value == "not-a-number"


# ---------------------------------------------------------------------------
# TC-021 — version-token tolerance on read (LLR-006.2, LLR-006.4)
# ---------------------------------------------------------------------------


def test_tc021_cdf21_token_reads_instances_with_one_version_info_issue() -> None:
    """A ``CDF21`` file reads its instances and emits one ``R-VERSION-UNKNOWN``.

    LLR-006.4: the reader targets CDF 2.0 but tolerates another version token —
    a ``CDF21`` document is still parsed, with exactly one info-level
    ``R-VERSION-UNKNOWN`` issue noting the version.
    """
    change_list, issues = read_cdfx(
        _wrap_backbone(_VALID_SIBLING, category=b"CDF21")
    )

    assert change_list.get("VALID_SIBLING") is not None
    version_issues = [i for i in issues if i.code == "R-VERSION-UNKNOWN"]
    assert len(version_issues) == 1
    assert version_issues[0].severity is ValidationSeverity.INFO


def test_tc021_cdf20_token_emits_no_version_issue() -> None:
    """The targeted ``CDF20`` token emits no version issue (LLR-006.4).

    The version tolerance fires only for a *non*-``CDF20`` token; a conformant
    CDF 2.0 file produces zero ``R-VERSION-UNKNOWN`` issues.
    """
    _change_list, issues = read_cdfx(_wrap_backbone(_VALID_SIBLING))

    assert [i.code for i in issues if i.code == "R-VERSION-UNKNOWN"] == []


# ---------------------------------------------------------------------------
# TC-023 — unsupported categories are read-only, not fatal (LLR-006.5)
# ---------------------------------------------------------------------------


def test_tc023_map_instance_loads_read_only_with_one_warning() -> None:
    """A ``MAP`` instance loads read-only with one ``R-CATEGORY-UNSUPPORTED``.

    LLR-006.5: a category outside the editable set (``MAP`` / ``STRUCTURE`` /
    ``*_ARRAY`` …) is not fatal — the instance loads as a read-only
    (``UNRESOLVED``) entry and emits exactly one warning.
    """
    map_instance = (
        b"<SW-INSTANCE><SHORT-NAME>FUEL_MAP_2D</SHORT-NAME>"
        b"<CATEGORY>MAP</CATEGORY>"
        b"<SW-VALUE-CONT><SW-VALUES-PHYS><VG><V>1</V><V>2</V></VG>"
        b"</SW-VALUES-PHYS></SW-VALUE-CONT></SW-INSTANCE>"
    )

    change_list, issues = read_cdfx(_wrap_backbone(map_instance))

    from s19_app.tui.cdfx.changelist import ResolutionStatus

    unsupported = [i for i in issues if i.code == "R-CATEGORY-UNSUPPORTED"]
    assert len(unsupported) == 1
    assert unsupported[0].severity is ValidationSeverity.WARNING

    entry = change_list.get("FUEL_MAP_2D")
    assert entry is not None
    assert entry.status is ResolutionStatus.UNRESOLVED


def test_tc023_unsupported_category_does_not_block_a_valid_sibling() -> None:
    """A ``MAP`` instance does not abort the read — the sibling is recovered.

    LLR-006.5: an unsupported category is read-only, not fatal — a valid
    sibling instance in the same document still loads as a normal entry.
    """
    map_then_valid = (
        b"<SW-INSTANCE><SHORT-NAME>FUEL_MAP_2D</SHORT-NAME>"
        b"<CATEGORY>MAP</CATEGORY>"
        b"<SW-VALUE-CONT><SW-VALUES-PHYS><VG><V>1</V></VG>"
        b"</SW-VALUES-PHYS></SW-VALUE-CONT></SW-INSTANCE>"
    ) + _VALID_SIBLING

    change_list, _issues = read_cdfx(_wrap_backbone(map_then_valid))

    assert change_list.get("VALID_SIBLING") is not None
    assert len(change_list) == 2


# ---------------------------------------------------------------------------
# TC-029 / TC-030 / TC-031 — A2L cross-check on load (LLR-008)
# ---------------------------------------------------------------------------

# The reader's cross-check reads only `name` and `element_count` from each
# enriched A2L tag (reader.read_cdfx docstring) — minimal tags of that shape.
_A2L_TAGS = [
    {"name": "IGN_ADVANCE_BASE", "element_count": 1},
    {"name": "FUEL_TRIM_TABLE", "element_count": 3},
]


def _array_instance(name: str, v_count: int) -> bytes:
    """A ``VAL_BLK`` ``SW-INSTANCE`` for ``name`` with ``v_count`` ``V`` elements."""
    vs = b"".join(b"<V>" + str(i).encode() + b"</V>" for i in range(v_count))
    return (
        b"<SW-INSTANCE><SHORT-NAME>" + name.encode() + b"</SHORT-NAME>"
        b"<CATEGORY>VAL_BLK</CATEGORY>"
        b"<SW-VALUE-CONT><SW-VALUES-PHYS><VG>" + vs + b"</VG>"
        b"</SW-VALUES-PHYS></SW-VALUE-CONT></SW-INSTANCE>"
    )


def test_tc029_name_not_in_a2l_emits_one_warning() -> None:
    """An instance named for a non-existent A2L parameter → one warning.

    LLR-008.1: with an A2L loaded, a ``SW-INSTANCE`` whose ``SHORT-NAME``
    matches no A2L parameter yields exactly one ``R-NAME-NOT-IN-A2L`` warning —
    surfacing a stale or mistyped change-list.
    """
    stranger = (
        b"<SW-INSTANCE><SHORT-NAME>NOT_IN_A2L</SHORT-NAME>"
        b"<CATEGORY>VALUE</CATEGORY>"
        b"<SW-VALUE-CONT><SW-VALUES-PHYS><V>1</V>"
        b"</SW-VALUES-PHYS></SW-VALUE-CONT></SW-INSTANCE>"
    )

    _change_list, issues = read_cdfx(
        _wrap_backbone(stranger), a2l_tags=_A2L_TAGS
    )

    name_issues = [i for i in issues if i.code == "R-NAME-NOT-IN-A2L"]
    assert len(name_issues) == 1
    assert name_issues[0].severity is ValidationSeverity.WARNING


def test_tc029_matching_name_emits_no_cross_check_warning() -> None:
    """An instance whose name is in the A2L emits no name cross-check warning.

    LLR-008.1: the cross-check fires only on a *missing* name — a matched name
    produces no ``R-NAME-NOT-IN-A2L`` issue.
    """
    valid = (
        b"<SW-INSTANCE><SHORT-NAME>IGN_ADVANCE_BASE</SHORT-NAME>"
        b"<CATEGORY>VALUE</CATEGORY>"
        b"<SW-VALUE-CONT><SW-VALUES-PHYS><V>12</V>"
        b"</SW-VALUES-PHYS></SW-VALUE-CONT></SW-INSTANCE>"
    )

    _change_list, issues = read_cdfx(
        _wrap_backbone(valid), a2l_tags=_A2L_TAGS
    )

    assert [i.code for i in issues if i.code == "R-NAME-NOT-IN-A2L"] == []


def test_tc030_array_length_mismatch_emits_one_warning() -> None:
    """A 4-element array against a 3-element A2L parameter → one warning.

    LLR-008.2: with an A2L loaded, a ``VAL_BLK`` instance whose ``V`` count
    differs from the A2L ``element_count`` yields exactly one
    ``R-ARRAY-LEN-MISMATCH`` warning.
    """
    _change_list, issues = read_cdfx(
        _wrap_backbone(_array_instance("FUEL_TRIM_TABLE", 4)),
        a2l_tags=_A2L_TAGS,
    )

    len_issues = [i for i in issues if i.code == "R-ARRAY-LEN-MISMATCH"]
    assert len(len_issues) == 1
    assert len_issues[0].severity is ValidationSeverity.WARNING


def test_tc030_matching_array_length_emits_no_mismatch_warning() -> None:
    """A 3-element array against a 3-element A2L parameter emits no mismatch.

    LLR-008.2: the length cross-check fires only on a *difference* — a
    ``V`` count equal to the A2L ``element_count`` produces no
    ``R-ARRAY-LEN-MISMATCH`` issue.
    """
    _change_list, issues = read_cdfx(
        _wrap_backbone(_array_instance("FUEL_TRIM_TABLE", 3)),
        a2l_tags=_A2L_TAGS,
    )

    assert [i.code for i in issues if i.code == "R-ARRAY-LEN-MISMATCH"] == []


def test_tc031_no_a2l_skips_cross_check_but_still_parses_entries() -> None:
    """With no A2L, a ``.cdfx`` parses into entries and emits no cross-checks.

    LLR-008.3: when no A2L is loaded the reader still produces change-list
    entries but emits zero ``R-NAME-NOT-IN-A2L`` / ``R-ARRAY-LEN-MISMATCH``
    issues — the cross-check is skipped entirely.
    """
    # A 4-element array named for a parameter that is NOT in any A2L — both
    # cross-check codes would fire if the A2L were present.
    change_list, issues = read_cdfx(
        _wrap_backbone(_array_instance("FUEL_TRIM_TABLE", 4))
    )

    assert len(change_list) == 4
    cross_codes = {"R-NAME-NOT-IN-A2L", "R-ARRAY-LEN-MISMATCH"}
    assert not any(i.code in cross_codes for i in issues)
