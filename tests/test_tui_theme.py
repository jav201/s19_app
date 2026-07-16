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

import asyncio
import re
from pathlib import Path

import pytest
from textual.color import Color
from textual.widgets import Static

from s19_app.tui import insight_style
from s19_app.tui.app import S19TuiApp
from s19_app.tui.color_policy import (
    SEVERITY_CLASS_MAP,
    css_class_for_severity,
)
from s19_app.tui.legend import COLOUR_SEVERITY
from s19_app.validation import ValidationSeverity

# ---------------------------------------------------------------------------
# Stylesheet under test — resolved next to the app module that declares
# CSS_PATH = "styles.tcss" (Textual resolves CSS_PATH relative to that module).
# ---------------------------------------------------------------------------

STYLES_TCSS = Path(__file__).resolve().parents[1] / "s19_app" / "tui" / "styles.tcss"

#: The five severity CSS classes that color_policy.SEVERITY_CLASS_MAP owns.
#: This batch may retune their hex values but MUST NOT add / drop / rename one.
SEV_CLASSES = ("sev-error", "sev-warning", "sev-info", "sev-ok", "sev-neutral")

#: The two pilot regimes every AT in this batch is claimed to run at (C-13).
#: Matches the ``_SIZES`` convention in tests/test_tui_a2l_detail.py,
#: tests/test_tui_mac_coverage.py and tests/test_tui_map_big.py.
_SIZES = ((80, 24), (120, 30))
_SIZE_IDS = [f"{w}x{h}" for w, h in _SIZES]


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


# ---------------------------------------------------------------------------
# AT-065a / AT-065b — batch-47 US-FND app-wide navy/pastel theme
# (HLR-065, LLR-065.3 / 065.4). The AT layer drives the live Textual app and
# asserts on RESOLVED styles, complementing the text-level TC-012/TC-013 checks
# above. ``insight_style`` is the palette source of truth (LLR-065.1); the
# navy/pastel hex values asserted here match the operator-approved SVG palette.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("size", _SIZES, ids=_SIZE_IDS)
def test_at065a_palette(tmp_path: Path, size: tuple[int, int]) -> None:
    """AT-065a: the navy/pastel palette is applied app-wide.

    Intent (HLR-065 / LLR-065.3): booting the app and navigating to the
    Workspace screen must resolve the navy depth-stack — the ``Screen``
    background is the app ``DEPTH_BG`` and a ``.db-pane`` surface is the
    ``DEPTH_PANEL`` step. This proves the ``$``-variable swap (bg-base /
    bg-panel) reached the rendered widget tree, not just the stylesheet text.
    RED before the theme (Screen bg was ``#11141a``, pane ``#171b23``); GREEN
    after (``#0a0e1b`` / ``#0f1525``).

    Run at BOTH pilot regimes (C-13): the palette is a per-widget resolved
    style, so it must hold in the narrow 80x24 regime — where the responsive
    ``width-narrow`` rules restack the panes — exactly as at 120x30.
    """

    async def _drive() -> tuple[Color, Color]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app.action_show_screen("workspace")
            await pilot.pause()
            panes = app.query(".db-pane")
            assert panes, "no .db-pane widgets mounted on the Workspace screen"
            return app.screen.styles.background, panes.first().styles.background

    screen_bg, pane_bg = asyncio.run(_drive())

    assert screen_bg == Color.parse(insight_style.DEPTH_BG), (
        f"AT-065a: Screen background {screen_bg} != DEPTH_BG "
        f"{insight_style.DEPTH_BG} — the navy $bg-base swap did not reach the "
        "rendered screen."
    )
    assert pane_bg == Color.parse(insight_style.DEPTH_PANEL), (
        f"AT-065a: .db-pane background {pane_bg} != DEPTH_PANEL "
        f"{insight_style.DEPTH_PANEL} — the navy $bg-panel swap did not reach "
        "the rendered panels."
    )


@pytest.mark.parametrize("size", _SIZES, ids=_SIZE_IDS)
def test_at065b_sev_semantics(tmp_path: Path, size: tuple[int, int]) -> None:
    """AT-065b: the ``sev-*`` contract survives the restyle (names + semantics).

    Two halves (LLR-065.4):

    1. ``css_class_for_severity`` still maps every ``ValidationSeverity`` to its
       canonical ``sev-*`` class — the frozen ``color_policy.py`` round-trip is
       intact (the restyle touched ``styles.tcss`` only).
    2. A live widget carrying ``sev-error`` resolves to the red-family hue — the
       class was neither dropped nor renamed, and the Inc-8 pastel restyle
       bound it to ``insight_style.RED``. RED before the theme (``#e06c75``);
       GREEN after (``#fd8383``).

    Run at BOTH pilot regimes (C-13): the severity binding is a resolved
    per-widget style and must not depend on the viewport regime.
    """

    # (1) round-trip — color_policy frozen, 0-diff.
    for severity in ValidationSeverity:
        assert css_class_for_severity(severity) == SEVERITY_CLASS_MAP[severity], (
            f"AT-065b: {severity!r} no longer round-trips to its mapped class."
        )

    # (2) resolved hue — sev-error is still applied and is red-family.
    async def _resolve_sev_error() -> Color:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            probe = Static("x", classes="sev-error")
            await app.screen.mount(probe)
            await pilot.pause()
            return probe.styles.color

    color = asyncio.run(_resolve_sev_error())
    assert color == Color.parse(insight_style.RED), (
        f"AT-065b: a sev-error widget resolved to {color}, expected the pastel "
        f"RED {insight_style.RED} — the restyle dropped/renamed the class or "
        "left it unbound."
    )


# ---------------------------------------------------------------------------
# AT-065c — the legend does not lie about its own colours (batch-47 M-1).
#
# Gap this closes: AT-065b probes ``sev-error`` ONLY, so a restyle may retune
# any OTHER sev-* class out of the hue family its legend LABEL names and no
# test notices. The legend is the operator's colour key — a row reading
# "Orange — warning: ..." that renders pale yellow is worse than no key at all,
# because it teaches the wrong mapping. This binds every COLOUR_SEVERITY label
# to the hue actually resolved by the class the legend row is painted with
# (screens.LegendScreen.compose -> css_class_for_severity).
# ---------------------------------------------------------------------------

#: Hue-family buckets as (name, half-open HSV-hue degree span). Deliberately
#: coarse: this asserts the legend's colour WORD, not an exact hex, so the
#: theme stays free to retune a shade without tripping the test — only a
#: cross-FAMILY drift (the kind that makes the label wrong) fails.
_HUE_FAMILIES: tuple[tuple[str, float, float], ...] = (
    ("Red", 345.0, 360.0),
    ("Red", 0.0, 15.0),
    ("Orange", 15.0, 45.0),
    ("Yellow", 45.0, 70.0),
    ("Green", 70.0, 170.0),
    ("Cyan", 170.0, 210.0),
    ("Blue", 210.0, 260.0),
    ("Purple", 260.0, 345.0),
)

#: Below this HSV saturation a colour reads as grey regardless of its hue.
_GREY_MAX_SATURATION = 0.15


def _hue_family(color: Color) -> str:
    """Classify a resolved Color into the colour WORD an operator would use.

    Greys are hue-unstable (a near-neutral RGB can land on any hue), so they
    are decided on saturation first; everything else falls into a hue bucket.
    """

    hue, saturation, _value = color.hsv
    if saturation < _GREY_MAX_SATURATION:
        return "Grey"
    degrees = hue * 360.0
    for name, low, high in _HUE_FAMILIES:
        if low <= degrees < high:
            return name
    raise AssertionError(f"hue {degrees:.1f}° fell outside every family bucket")


def test_at065c_legend_labels_match_resolved_hues(tmp_path: Path) -> None:
    """AT-065c: every legend colour LABEL matches the hue it actually renders.

    Intent: the legend modal paints each row with
    ``css_class_for_severity(COLOUR_SEVERITY[label])`` while showing the
    operator the word ``label``. Those two must agree — the legend's whole job
    is to be the authoritative key from colour to meaning, so a label naming a
    hue the row does not render inverts the key's value.

    This is a SEMANTIC test, not a snapshot: it asserts the colour family the
    label names, so retuning a shade within the family stays green and only a
    label/hue contradiction fails.
    """

    async def _resolve_all() -> dict[str, Color]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test() as pilot:
            await pilot.pause()
            probes = {
                label: Static("x", classes=css_class_for_severity(severity))
                for label, severity in COLOUR_SEVERITY.items()
            }
            for probe in probes.values():
                await app.screen.mount(probe)
            await pilot.pause()
            return {label: p.styles.color for label, p in probes.items()}

    resolved = asyncio.run(_resolve_all())

    # Substring match, so a qualified label ("Pale yellow") satisfies its
    # family ("Yellow") while a contradicting one ("Orange") still fails.
    mismatches = {
        label: (str(color), _hue_family(color))
        for label, color in resolved.items()
        if _hue_family(color).lower() not in label.lower()
    }
    assert not mismatches, (
        "AT-065c: legend colour label(s) contradict the hue the legend row "
        f"actually renders: {mismatches} — each entry reads "
        "label: (resolved_rgb, family_it_actually_is). The legend is the "
        "operator's colour key; fix the label or the class binding so the "
        "word and the hue agree."
    )
