"""TC-012 / TC-013 — Calm Dark theme token budget + severity-class binding.

Batch batch-02-direction-b-restyle, Phase 3 increment 1. Covers:

- **TC-012** (LLR-005.1 / HLR-005) — theme token budget. Parses the extracted
  ``s19_app/tui/styles.tcss`` stylesheet and asserts: exactly one accent hue
  variable, the five ``sev-*`` rules present and unchanged in name, and no
  light-theme variant / second non-dark token set.
- **TC-013** (LLR-005.2 / HLR-005, HLR-014) — severity color source of truth.
  (a) no-regression anchor: re-asserts the ``test_color_policy_round_trip``
  behavior so the batch cannot silently change ``SEVERITY_CLASS_MAP``;
  (b) stylesheet binding: asserts ``styles.tcss`` defines a CSS rule for each
  of the five ``sev-*`` classes (Q-12 — a missing rule silently breaks
  severity coloring).

These are inspection-as-test cases: the stylesheet is parsed as text, not via
the Textual CSS engine, so the assertions are deterministic and explicit.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from s19_app.tui.color_policy import (
    SEVERITY_CLASS_MAP,
    css_class_for_severity,
)
from s19_app.validation import ValidationSeverity

# ---------------------------------------------------------------------------
# Stylesheet under test — resolved next to the app module that declares
# CSS_PATH = "styles.tcss" (Textual resolves CSS_PATH relative to that module).
# ---------------------------------------------------------------------------

STYLES_TCSS = Path(__file__).resolve().parents[1] / "s19_app" / "tui" / "styles.tcss"

#: The five severity CSS classes that color_policy.SEVERITY_CLASS_MAP owns.
#: This batch may retune their hex values but MUST NOT add / drop / rename one.
SEV_CLASSES = ("sev-error", "sev-warning", "sev-info", "sev-ok", "sev-neutral")


def _stylesheet_text() -> str:
    """Return the raw text of the extracted Calm Dark stylesheet."""

    assert STYLES_TCSS.is_file(), (
        f"styles.tcss not found at {STYLES_TCSS} — the inline CSS extraction "
        "(increment 1) did not land or CSS_PATH points elsewhere."
    )
    return STYLES_TCSS.read_text(encoding="utf-8")


def _strip_comments(text: str) -> str:
    """Drop ``/* ... */`` comment blocks so prose does not pollute matching."""

    return re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)


# ---------------------------------------------------------------------------
# TC-012 — theme token budget (LLR-005.1 / HLR-005)
# ---------------------------------------------------------------------------


def test_tc_012_exactly_one_accent_hue_variable() -> None:
    """TC-012: the stylesheet declares exactly one accent hue variable.

    The Calm Dark color budget (C-6) is one accent hue. The accent is declared
    as the custom variable ``$accent-calm``; no second accent variable may be
    declared.
    """

    code = _strip_comments(_stylesheet_text())

    # A variable *declaration* is `$name: value;` at the start of a statement.
    declarations = re.findall(r"(?m)^\s*\$([\w-]+)\s*:", code)
    accent_decls = [name for name in declarations if "accent" in name.lower()]

    assert accent_decls == ["accent-calm"], (
        f"TC-012: expected exactly one accent hue variable ($accent-calm), "
        f"found accent declarations: {accent_decls}"
    )


def test_tc_012_five_sev_rules_present_and_unchanged() -> None:
    """TC-012: all five ``sev-*`` rules are present with their canonical names.

    Severity class names are fixed by ``SEVERITY_CLASS_MAP`` (LLR-005.2). The
    stylesheet must carry exactly the five ``sev-*`` rules — no class dropped,
    renamed, or a sixth added.
    """

    code = _strip_comments(_stylesheet_text())
    sev_selectors = set(re.findall(r"\.(sev-[\w-]+)\b", code))

    assert sev_selectors == set(SEV_CLASSES), (
        f"TC-012: severity classes in styles.tcss = {sorted(sev_selectors)}; "
        f"expected exactly {sorted(SEV_CLASSES)} — no class added/dropped/renamed."
    )


def test_tc_012_severity_class_names_match_color_policy() -> None:
    """TC-012: the ``sev-*`` rule names equal the SEVERITY_CLASS_MAP values.

    Cross-checks the stylesheet against the source-of-truth map so a rename on
    either side is caught.
    """

    code = _strip_comments(_stylesheet_text())
    sev_selectors = set(re.findall(r"\.(sev-[\w-]+)\b", code))

    assert sev_selectors == set(SEVERITY_CLASS_MAP.values()), (
        "TC-012: stylesheet sev-* classes drifted from "
        f"SEVERITY_CLASS_MAP values {sorted(set(SEVERITY_CLASS_MAP.values()))}."
    )


def test_tc_012_mac_overlay_rule_preserved() -> None:
    """TC-012: the ``.mac_out_of_range`` MAC overlay rule is preserved."""

    code = _strip_comments(_stylesheet_text())

    assert re.search(r"\.mac_out_of_range\b", code), (
        "TC-012: the .mac_out_of_range MAC overlay rule is missing from "
        "styles.tcss — it must be preserved (pairs with MAC_ADDRESS_OVERLAY_STYLE)."
    )


def test_tc_012_no_light_theme_variant() -> None:
    """TC-012: no light-theme variant / second non-dark token set is present.

    Calm Dark is dark-only (C-7). The stylesheet must not declare a light
    variant or a parallel light token set.
    """

    code = _strip_comments(_stylesheet_text()).lower()

    assert "light" not in code, (
        "TC-012: a 'light' token / selector appears in styles.tcss — "
        "Calm Dark is dark-only, no light-theme variant is permitted."
    )


# ---------------------------------------------------------------------------
# TC-013(a) — no-regression anchor: severity color source of truth (LLR-005.2)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "severity",
    list(ValidationSeverity),
    ids=[sev.name for sev in ValidationSeverity],
)
def test_tc_013a_color_policy_round_trip_unchanged(
    severity: ValidationSeverity,
) -> None:
    """TC-013(a): every severity still round-trips through ``css_class_for_severity``.

    No-regression anchor — mirrors ``test_color_policy_round_trip.py``. The
    restyle batch must leave ``color_policy.py`` byte-identical; this asserts
    the observable contract (severity -> stable ``sev-*`` class) is intact.
    """

    css_class = css_class_for_severity(severity)

    assert css_class == SEVERITY_CLASS_MAP[severity], (
        f"TC-013(a): {severity!r} no longer round-trips to its mapped class; "
        f"got {css_class!r}, expected {SEVERITY_CLASS_MAP[severity]!r} — "
        "color_policy.py must stay unchanged by the restyle."
    )
    assert css_class in SEV_CLASSES, (
        f"TC-013(a): {severity!r} mapped to a non-sev-* class {css_class!r}."
    )


def test_tc_013a_severity_class_map_cardinality_unchanged() -> None:
    """TC-013(a): no severity is added or dropped from ``SEVERITY_CLASS_MAP``."""

    assert set(SEVERITY_CLASS_MAP) == set(ValidationSeverity), (
        "TC-013(a): SEVERITY_CLASS_MAP keys drifted from ValidationSeverity — "
        "the restyle introduced or removed a severity value."
    )
    assert len(SEVERITY_CLASS_MAP) == 5, (
        f"TC-013(a): expected 5 severity classes, got {len(SEVERITY_CLASS_MAP)}."
    )


# ---------------------------------------------------------------------------
# TC-013(b) — stylesheet binding: a CSS rule per sev-* class (Q-12)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("sev_class", SEV_CLASSES)
def test_tc_013b_stylesheet_defines_rule_for_each_sev_class(
    sev_class: str,
) -> None:
    """TC-013(b): ``styles.tcss`` defines a CSS rule for each ``sev-*`` class.

    A stylesheet that fails to define a rule for one of the five ``sev-*``
    classes would silently break severity coloring (Q-12). For each class,
    assert a ``.<class> { ... color: ... }`` rule exists.
    """

    code = _strip_comments(_stylesheet_text())

    # Match `.sev-foo { ... }` and require a `color:` declaration inside it.
    rule = re.search(
        rf"\.{re.escape(sev_class)}\s*\{{(?P<body>[^}}]*)\}}",
        code,
    )
    assert rule is not None, (
        f"TC-013(b): styles.tcss has no CSS rule for .{sev_class} — "
        "severity coloring would silently break for this class."
    )
    assert "color:" in rule.group("body"), (
        f"TC-013(b): the .{sev_class} rule defines no `color:` — "
        "the severity class would render with no color."
    )
