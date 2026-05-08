"""LLR-002.1 — Severity round-trip + bidirectional invariant + colour-name set.

Closes Phase 1 risk R-3: the severity colour string contract was previously
verified by inspection only. This module locks it down by parametrised unit
test plus an integration check on the ``large_project`` fixture.

Per LLR-002.1 acceptance criteria:
- Every ``ValidationSeverity`` round-trips through ``css_class_for_severity``
  to a non-empty CSS class drawn from the documented colour set.
- The mapping ``SEVERITY_CLASS_MAP`` is bidirectional: every severity has
  exactly one entry, and every entry's key is a defined severity member.
- The colour-name set ``{red, orange, green, white, grey}`` from
  ``REQUIREMENTS.md`` is part of the asserted contract.
- Integration: every ``(code, severity, css_class)`` triple emitted by
  ``validate_artifact_consistency`` on ``large_project`` honours the
  round-trip. This explicitly does NOT enumerate ``rules.py`` itself
  (LLR-002.1 forbids duplicating the rule→code mapping owned by LLR-008.2).
"""

from __future__ import annotations

import pytest

from s19_app.core import S19File
from s19_app.tui.a2l import parse_a2l_file
from s19_app.tui.color_policy import SEVERITY_CLASS_MAP, css_class_for_severity
from s19_app.tui.mac import parse_mac_file
from s19_app.validation import (
    ValidationSeverity,
    validate_artifact_consistency,
)


# ---------------------------------------------------------------------------
# Documented severity → colour mapping (per REQUIREMENTS.md §A2L/MAC row colour
# semantics and §Issues Tile Severity Policy). The CSS classes in
# ``color_policy.SEVERITY_CLASS_MAP`` use semantic names (``sev-error``,
# ``sev-warning``, …) rather than colour names; this table is the bridge.
# LLR-002.1: any rename to either side produces a Finding.
# ---------------------------------------------------------------------------

EXPECTED_COLOR_BY_SEVERITY: dict[ValidationSeverity, str] = {
    ValidationSeverity.ERROR: "red",
    ValidationSeverity.WARNING: "orange",
    ValidationSeverity.OK: "green",
    ValidationSeverity.INFO: "white",
    ValidationSeverity.NEUTRAL: "grey",
}

EXPECTED_CSS_BY_SEVERITY: dict[ValidationSeverity, str] = {
    ValidationSeverity.ERROR: "sev-error",
    ValidationSeverity.WARNING: "sev-warning",
    ValidationSeverity.INFO: "sev-info",
    ValidationSeverity.OK: "sev-ok",
    ValidationSeverity.NEUTRAL: "sev-neutral",
}

REQUIRED_COLOUR_SET = {"red", "orange", "green", "white", "grey"}


# ---------------------------------------------------------------------------
# TC-012 — Severity → CSS-class round-trip (forward, parametrised)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "severity",
    list(ValidationSeverity),
    ids=[sev.name for sev in ValidationSeverity],
)
def test_severity_round_trips_to_documented_css_class(severity: ValidationSeverity) -> None:
    """Every ``ValidationSeverity`` resolves to a non-empty, expected CSS class."""

    css_class = css_class_for_severity(severity)

    assert isinstance(css_class, str) and css_class, (
        f"css_class_for_severity({severity!r}) returned empty/non-str: {css_class!r}"
    )
    assert css_class in EXPECTED_CSS_BY_SEVERITY.values(), (
        f"{severity!r} mapped to unknown CSS class {css_class!r}; "
        f"expected one of {sorted(EXPECTED_CSS_BY_SEVERITY.values())}"
    )
    assert css_class == EXPECTED_CSS_BY_SEVERITY[severity], (
        f"{severity!r} expected to map to {EXPECTED_CSS_BY_SEVERITY[severity]!r} "
        f"but got {css_class!r} — Finding per LLR-002.1 (rename detected)."
    )


# ---------------------------------------------------------------------------
# Bidirectional invariant — every severity ⇒ exactly one entry, every entry
# key ⇒ a defined severity. No silent drops, no orphan keys.
# ---------------------------------------------------------------------------


def test_every_validation_severity_has_exactly_one_map_entry() -> None:
    """Each ``ValidationSeverity`` member has one and only one mapping row."""

    for severity in ValidationSeverity:
        assert severity in SEVERITY_CLASS_MAP, (
            f"{severity!r} is missing from SEVERITY_CLASS_MAP — "
            "Finding per LLR-002.1 (severity silently dropped)."
        )
    assert len(SEVERITY_CLASS_MAP) == len(list(ValidationSeverity)), (
        "SEVERITY_CLASS_MAP cardinality differs from ValidationSeverity members."
    )


def test_every_map_key_is_a_defined_validation_severity() -> None:
    """No orphan keys: every map key is a defined ``ValidationSeverity`` member."""

    valid_members = set(ValidationSeverity)
    for key in SEVERITY_CLASS_MAP:
        assert key in valid_members, (
            f"SEVERITY_CLASS_MAP key {key!r} is not a defined ValidationSeverity — "
            "Finding per LLR-002.1 (orphan map key)."
        )


def test_severity_class_map_values_are_unique() -> None:
    """Each severity maps to a distinct CSS class (no two severities share a class)."""

    values = list(SEVERITY_CLASS_MAP.values())
    assert len(values) == len(set(values)), (
        f"SEVERITY_CLASS_MAP has duplicate CSS class values: {values}"
    )


# ---------------------------------------------------------------------------
# Colour-name set as contract — REQUIREMENTS.md mandates the colour set
# {Red, Orange, Green, White, Grey}. The CSS classes are semantic names
# (``sev-error`` etc.); ``EXPECTED_COLOR_BY_SEVERITY`` is the documented
# bridge. Failing this test = Finding per LLR-002.1.
# ---------------------------------------------------------------------------


def test_colour_name_set_matches_requirements_contract() -> None:
    """The documented severity → colour mapping covers exactly the required colour set."""

    documented_colours = set(EXPECTED_COLOR_BY_SEVERITY.values())
    assert documented_colours == REQUIRED_COLOUR_SET, (
        f"Documented colour set {sorted(documented_colours)} does not match "
        f"REQUIREMENTS.md set {sorted(REQUIRED_COLOUR_SET)} — "
        "Finding per LLR-002.1 (colour-name contract drift)."
    )


def test_every_validation_severity_has_a_documented_colour() -> None:
    """No severity may exist without a documented colour mapping."""

    for severity in ValidationSeverity:
        assert severity in EXPECTED_COLOR_BY_SEVERITY, (
            f"{severity!r} has no entry in EXPECTED_COLOR_BY_SEVERITY — "
            "any new severity must be added to the colour contract."
        )


# ---------------------------------------------------------------------------
# Idempotency / determinism — cheap sanity check.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "severity",
    list(ValidationSeverity),
    ids=[sev.name for sev in ValidationSeverity],
)
def test_css_class_for_severity_is_idempotent(severity: ValidationSeverity) -> None:
    """Repeated calls on the same severity return the same CSS class."""

    first = css_class_for_severity(severity)
    second = css_class_for_severity(severity)
    assert first == second


# ---------------------------------------------------------------------------
# Integration — round-trip every (code, severity, css_class) triple emitted by
# ``validate_artifact_consistency`` on the ``large_project`` fixture. This is
# the LLR-002.1 acceptance bullet "Every issue code emitted by
# ``validate_artifact_consistency`` is enumerated with its severity and
# resulting CSS class". Per LLR-002.1, this MUST NOT duplicate the rule→code
# mapping (that contract belongs to LLR-008.2); the test only checks the
# round-trip given whatever codes the engine produces.
# ---------------------------------------------------------------------------


def test_validate_artifact_consistency_round_trip_on_large_project(
    large_project: dict,
) -> None:
    """Every issue emitted on ``large_project`` honours the severity → css round-trip."""

    s19 = S19File(str(large_project["s19"]))
    a2l_data = parse_a2l_file(large_project["a2l"])
    mac_payload = parse_mac_file(large_project["mac"])

    report = validate_artifact_consistency(
        mac_records=mac_payload.get("records", []),
        a2l_tags=(a2l_data or {}).get("tags", []),
        a2l_data=a2l_data,
        s19_ranges=s19.get_memory_ranges(),
    )

    # We require the fixture to actually exercise the engine; an empty issue
    # list would silently pass this test and defeat the integration intent.
    # ``large_project`` is documented to produce non-trivial findings.
    assert report.issues, (
        "large_project produced zero issues — fixture no longer exercises "
        "validate_artifact_consistency for the round-trip integration check."
    )

    seen_triples: set[tuple[str, ValidationSeverity, str]] = set()
    for issue in report.issues:
        css_class = css_class_for_severity(issue.severity)
        seen_triples.add((issue.code, issue.severity, css_class))
        assert css_class == EXPECTED_CSS_BY_SEVERITY[issue.severity], (
            f"Round-trip failure: code={issue.code!r}, severity={issue.severity!r}, "
            f"got css_class={css_class!r}, expected "
            f"{EXPECTED_CSS_BY_SEVERITY[issue.severity]!r}."
        )

    # Every observed severity must have been one of the documented members.
    observed_severities = {sev for _, sev, _ in seen_triples}
    assert observed_severities <= set(ValidationSeverity), (
        f"Engine emitted unknown severities: "
        f"{observed_severities - set(ValidationSeverity)}"
    )
