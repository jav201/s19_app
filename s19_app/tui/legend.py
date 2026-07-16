"""Shared classification-legend data (batch-18, LLR-022.1).

The single source of truth for the operator-facing colour legend consumed by
BOTH the generated project report (Q1, ``report_service._legend_lines``) and the
in-app ``LegendScreen`` modal (Q2). The content MIRRORS the documented
semantics in ``REQUIREMENTS.md`` §3 and the severity classes in
``color_policy.SEVERITY_CLASS_MAP``.

Why this module exists (Phase-0 frozen-set finding): the natural home for a
shared legend table would be ``color_policy.py``, but that file is
ENGINE-FROZEN (git-frozen by ``tests/test_tui_directionb.py::_ENGINE_PATHS``)
and must not be edited. This NEW, non-frozen module holds the legend data
instead, so Q1 and Q2 read one table without touching the frozen file.

``COLOUR_SEVERITY`` couples the legend back to ``SEVERITY_CLASS_MAP``: every
severity the policy defines must be reachable through a legend colour, so a new
severity added to the engine without a legend colour fails the anti-drift unit
test (TC-S1). ``"White"`` is the default terminal foreground — a valid record
with no severity class — so it intentionally has no entry here.
"""

from __future__ import annotations

from typing import Dict, Tuple

from ..validation import ValidationSeverity
from .color_policy import FOCUS_HIGHLIGHT_STYLE, MAC_ADDRESS_OVERLAY_STYLE

# artifact -> classification -> (colour-name, meaning).
# For A2L/MAC the classification IS the colour; for Issues the tile category
# (Errors/Warnings/Optional info) carries its own colour in the tuple.
LegendRows = Dict[str, Tuple[str, str]]

# Rich style modifier tokens to discard when deriving a colour name from a
# style string (they carry weight/decoration, not colour).
_RICH_MODIFIERS = frozenset(
    {"bold", "italic", "dim", "underline", "reverse", "blink", "strike"}
)


def _colour_name_from_style(style: str) -> str:
    """
    Summary:
        Derive a display colour NAME from a Rich style string by dropping the
        modifier tokens and title-casing the remaining colour token AS-IS
        (LLR-059.3). The shade digit is deliberately RETAINED
        (``"bold orange3" -> "Orange3"``): it names the Rich colour the hex
        view actually paints, and keeping these Hex names disjoint from the
        ``COLOUR_SEVERITY`` keys is what stops an overlay row (an interaction
        highlight, NOT a severity) from being painted ``sev-*`` — see TC-322.

    Args:
        style (str): a Rich style string, e.g. ``"bold yellow"`` /
            ``"bold orange3"``.

    Returns:
        str: the title-cased colour token (``"Yellow"`` / ``"Orange3"``), or
        ``""`` if the style carries no non-modifier token.

    Raises:
        None.

    Data Flow:
        - Fed the two engine-frozen ``color_policy`` overlay-style constants
          (READ-only) to build the Hex legend rows + ``HEX_LEGEND_STYLES``.

    Dependencies:
        Uses:
            - _RICH_MODIFIERS
        Used by:
            - HEX_LEGEND_STYLES / the ``"Hex"`` LEGEND_TABLE block
            - tests/test_tui_legend.py (TC-322)

    Example:
        >>> _colour_name_from_style("bold yellow")
        'Yellow'
    """
    tokens = [tok for tok in style.split() if tok not in _RICH_MODIFIERS]
    return tokens[0].title() if tokens else ""


# The two byte-cell overlay styles the hex view actually paints
# (``hexview.render_hex_view_text``) mapped to their documented meaning. These
# are interaction highlights, NOT ``sev-*`` validation severities, so their
# colours are absent from COLOUR_SEVERITY (LLR-059.1). Meanings are markup-free
# (no ``[`` / ``]``) since the modal renders each row markup-enabled (S-01).
_HEX_STYLE_MEANINGS: Dict[str, str] = {
    FOCUS_HIGHLIGHT_STYLE: (
        "search / goto-focus highlight: the byte span matched by the last "
        "in-memory search or goto-address jump in the hex view"
    ),
    MAC_ADDRESS_OVERLAY_STYLE: (
        "MAC address overlay: a hex byte at an address referenced by a "
        "loaded MAC record"
    ),
}

# Hex colour NAME -> source overlay-style constant (the anti-drift coupling:
# TC-322 asserts the value set is exactly the two color_policy constants, so
# the legend cannot silently diverge from the hex render).
HEX_LEGEND_STYLES: Dict[str, str] = {
    _colour_name_from_style(style): style for style in _HEX_STYLE_MEANINGS
}

# The "Hex" legend rows, DERIVED (not hardcoded) from the overlay-style
# constants so the colour names track color_policy. For Hex the classification
# IS the colour, mirroring A2L/MAC.
_HEX_ROWS: LegendRows = {
    _colour_name_from_style(style): (_colour_name_from_style(style), meaning)
    for style, meaning in _HEX_STYLE_MEANINGS.items()
}

LEGEND_TABLE: Dict[str, LegendRows] = {
    "A2L": {
        "Red": (
            "Red",
            "schema/structural failure: malformed required field, invalid "
            "required reference, or hard-error duplicate symbol",
        ),
        "Green": (
            "Green",
            "memory checked — tag/range fully found in the loaded S19/HEX image",
        ),
        "White": (
            "White",
            "valid A2L record with no hard inconsistency, including valid "
            "records not present in the image",
        ),
        "Grey": (
            "Grey",
            "memory not checked yet, or no primary S19/HEX context loaded",
        ),
    },
    "MAC": {
        "Red": (
            "Red",
            "parse failed, invalid/missing name or hex address, or A2L↔MAC "
            "same-name address mismatch",
        ),
        "Pale yellow": (
            "Pale yellow",
            "warning: symbol only in MAC (not A2L), duplicate-address alias, "
            "or overlap ambiguity",
        ),
        "Green": (
            "Green",
            "exact name + address match with A2L",
        ),
        "White": (
            "White",
            "structurally valid MAC entry, no hard inconsistency, not "
            "positively cross-confirmed",
        ),
        "Grey": (
            "Grey",
            "no A2L loaded, or validation context missing",
        ),
    },
    "Issues": {
        "Errors": (
            "Red",
            "parse/structure errors, empty name, invalid/missing address, "
            "duplicate symbol, broken GROUP/FUNCTION references, or "
            "A2L↔MAC same-name mismatch",
        ),
        "Warnings": (
            "Pale yellow",
            "address/range out of S19 range, overlap ambiguity, "
            "symbol-only-in-MAC, symbol-only-in-A2L, or warning-policy alias",
        ),
        "Optional info": (
            "Cyan",
            "valid-but-not-image-backed, not-checked-without-primary-image, or "
            "virtual/dependent non-memory-backed objects",
        ),
    },
    # Hex byte-cell overlay highlights (interaction styles, not severities).
    # DERIVED from the color_policy overlay-style constants — see _HEX_ROWS.
    "Hex": _HEX_ROWS,
}

# Anti-drift coupling to SEVERITY_CLASS_MAP: each legend colour maps to the
# severity it represents. TC-S1 asserts every ValidationSeverity in
# SEVERITY_CLASS_MAP is reachable here. "White" (default foreground, no
# severity) is deliberately absent.
#
# Every KEY here is a colour WORD shown verbatim to the operator, while the row
# is painted with `css_class_for_severity(<value>)` — so a key must name the hue
# its severity class actually RESOLVES to, or the legend teaches a wrong key
# (AT-065c). WARNING is "Pale yellow", not "Orange": batch-47 Inc-8 rebound
# `.sev-warning` to insight_style.YELLOW (#f6ff8f), and WARNING-severity rows
# (MAC + Issues) are painted from that class. "Pale yellow" — rather than a bare
# "Yellow" — keeps these keys disjoint from the `_colour_name_from_style` Hex
# names ("Yellow" / "Orange3"), which are interaction styles and MUST NOT
# resolve a severity (LLR-059.1 / TC-322). The orange "MAC address overlay" cue
# is unaffected and stays documented in the "Hex" block via "Orange3"
# (= frozen MAC_ADDRESS_OVERLAY_STYLE).
COLOUR_SEVERITY: Dict[str, ValidationSeverity] = {
    "Red": ValidationSeverity.ERROR,
    "Pale yellow": ValidationSeverity.WARNING,
    "Cyan": ValidationSeverity.INFO,
    "Green": ValidationSeverity.OK,
    "Grey": ValidationSeverity.NEUTRAL,
}
