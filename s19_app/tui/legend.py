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

# artifact -> classification -> (colour-name, meaning).
# For A2L/MAC the classification IS the colour; for Issues the tile category
# (Errors/Warnings/Optional info) carries its own colour in the tuple.
LegendRows = Dict[str, Tuple[str, str]]

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
        "Orange": (
            "Orange",
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
            "Orange",
            "address/range out of S19 range, overlap ambiguity, "
            "symbol-only-in-MAC, symbol-only-in-A2L, or warning-policy alias",
        ),
        "Optional info": (
            "Cyan",
            "valid-but-not-image-backed, not-checked-without-primary-image, or "
            "virtual/dependent non-memory-backed objects",
        ),
    },
}

# Anti-drift coupling to SEVERITY_CLASS_MAP: each legend colour maps to the
# severity it represents. TC-S1 asserts every ValidationSeverity in
# SEVERITY_CLASS_MAP is reachable here. "White" (default foreground, no
# severity) is deliberately absent.
COLOUR_SEVERITY: Dict[str, ValidationSeverity] = {
    "Red": ValidationSeverity.ERROR,
    "Orange": ValidationSeverity.WARNING,
    "Cyan": ValidationSeverity.INFO,
    "Green": ValidationSeverity.OK,
    "Grey": ValidationSeverity.NEUTRAL,
}
