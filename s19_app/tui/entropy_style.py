"""
Entropy band → visual-style source for the Memory Map (batch-45, R-TUI-060).

Batch-45 replaces the Memory Map's severity/validity colouring with an
entropy-band view. This module is the single, NON-frozen source that maps each
:data:`~s19_app.tui.services.entropy_service.ENTROPY_BANDS` band label to its
visual style — a CSS-safe class token, a texture glyph, and a plain-language
meaning. It is deliberately kept OUT of the engine-frozen
``tui/color_policy.py`` (the ``sev-*`` severity domain) because entropy bands
are a different colour domain than validation severity: mixing them into
``color_policy`` would both trip the freeze guards and conflate two unrelated
semantics.

The label set is DERIVED from ``entropy_service.ENTROPY_BANDS`` rather than
re-declared here, so a band added upstream that has no style entry is caught by
the census test (``tests/test_entropy_style.py``) instead of silently rendering
unstyled.

Purity: like ``entropy_service`` (its label source) this module imports no
Textual symbol — it is headless pure data, so both the Memory-Map view code and
its tests can consume band styling without pulling a UI dependency into the test
surface. The colour hex values live in ``styles.tcss`` under the matching
``.band-*`` rules; this module owns only the class *tokens*, glyphs, and
meanings.

Colour-blind accessibility (C-10): bands are distinguishable by GLYPH and CLASS
token, not by colour alone — every band carries a distinct texture glyph so the
view remains readable without colour perception.
"""

from __future__ import annotations

from typing import Dict, Tuple

from s19_app.tui.services.entropy_service import ENTROPY_BANDS

#: Ordered band labels, DERIVED from :data:`ENTROPY_BANDS` (never re-declared)
#: so an upstream band change flows through to the census test.
ENTROPY_BAND_LABELS: Tuple[str, ...] = tuple(label for label, _lo, _hi in ENTROPY_BANDS)

#: Band label → CSS-safe class token used by the ``.band-*`` rules in
#: ``styles.tcss``. Labels contain ``/`` (not valid in a CSS class token), so
#: each maps to a stripped short token.
ENTROPY_BAND_CLASS: Dict[str, str] = {
    "constant/padding": "band-constant",
    "low": "band-low",
    "medium": "band-medium",
    "high/random": "band-high",
}

#: Band label → texture glyph (colour-blind cue, C-10): a distinct fill
#: character per band so bands are distinguishable without colour perception.
ENTROPY_BAND_GLYPH: Dict[str, str] = {
    "constant/padding": "·",
    "low": "░",
    "medium": "▒",
    "high/random": "▓",
}

#: Band label → plain-language meaning for legends and tooltips.
ENTROPY_BAND_MEANING: Dict[str, str] = {
    "constant/padding": "padding / fill",
    "low": "structured / tables",
    "medium": "calibration / data",
    "high/random": "code / compressed / random",
}


def band_style(label: str) -> Tuple[str, str, str]:
    """
    Summary:
        Resolve a band label to its ``(class, glyph, meaning)`` visual style,
        falling back to the highest band (``high/random``) for an unknown
        label. The fall-through mirrors
        :func:`entropy_service.classify_band`, which returns the top band for
        any value at or above the final cutoff — an unknown label is treated as
        the most-conservative (highest-entropy) band rather than raising.

    Args:
        label (str): A band label, normally one of :data:`ENTROPY_BAND_LABELS`.

    Returns:
        Tuple[str, str, str]: ``(class_token, glyph, meaning)`` for ``label``;
        the ``high/random`` triple when ``label`` is not a known band.

    Data Flow:
        - Looks ``label`` up in :data:`ENTROPY_BAND_CLASS` /
          :data:`ENTROPY_BAND_GLYPH` / :data:`ENTROPY_BAND_MEANING`; a miss in
          any map resolves that field to the ``high/random`` entry.
        - Called by the Memory-Map band renderer (later increment) once per
          cell/window to style it, and directly by the fall-through unit test
          (TC-060.2).

    Dependencies:
        Uses:
            - ENTROPY_BAND_CLASS / ENTROPY_BAND_GLYPH / ENTROPY_BAND_MEANING
        Used by:
            - s19_app.tui Memory-Map band renderer (batch-45, later increment)
            - tests/test_entropy_style.py

    Example:
        >>> band_style("low")
        ('band-low', '░', 'structured / tables')
        >>> band_style("nonsense-band")
        ('band-high', '▓', 'code / compressed / random')
    """
    fallback = "high/random"
    return (
        ENTROPY_BAND_CLASS.get(label, ENTROPY_BAND_CLASS[fallback]),
        ENTROPY_BAND_GLYPH.get(label, ENTROPY_BAND_GLYPH[fallback]),
        ENTROPY_BAND_MEANING.get(label, ENTROPY_BAND_MEANING[fallback]),
    )
