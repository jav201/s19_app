"""
Census / structural tests for the entropy band → style source (batch-45,
R-TUI-060, TC-060.2 backstop).

These are anti-drift guards, not behaviour tests: the style maps in
``entropy_style`` are DERIVED consumers of ``entropy_service.ENTROPY_BANDS``, so
a band added upstream without a matching class / glyph / meaning entry must
FAIL here rather than render unstyled. The distinctness checks encode the C-10
colour-blind requirement — bands must be separable by glyph AND class token,
never by colour alone.
"""

from __future__ import annotations

from s19_app.tui.entropy_style import (
    ENTROPY_BAND_CLASS,
    ENTROPY_BAND_GLYPH,
    ENTROPY_BAND_MEANING,
    band_style,
)
from s19_app.tui.services.entropy_service import ENTROPY_BANDS

_LABELS = [label for label, _lo, _hi in ENTROPY_BANDS]


def test_every_band_has_class_glyph_and_meaning() -> None:
    """TC-060.2: each ENTROPY_BANDS label has an entry in ALL THREE style maps.

    A band added upstream without a style entry (any of class/glyph/meaning)
    fails this test — the whole point of deriving labels from ENTROPY_BANDS
    instead of re-declaring them.
    """
    for label in _LABELS:
        assert label in ENTROPY_BAND_CLASS, f"missing class token for band {label!r}"
        assert label in ENTROPY_BAND_GLYPH, f"missing glyph for band {label!r}"
        assert label in ENTROPY_BAND_MEANING, f"missing meaning for band {label!r}"


def test_style_maps_have_no_extra_labels() -> None:
    """TC-060.2: the style maps carry EXACTLY the ENTROPY_BANDS labels.

    Catches a stale entry left behind if a band is removed/renamed upstream.
    """
    expected = set(_LABELS)
    assert set(ENTROPY_BAND_CLASS) == expected
    assert set(ENTROPY_BAND_GLYPH) == expected
    assert set(ENTROPY_BAND_MEANING) == expected


def test_class_tokens_pairwise_distinct() -> None:
    """C-10: bands must be distinguishable by class token (not colour alone)."""
    tokens = [ENTROPY_BAND_CLASS[label] for label in _LABELS]
    assert len(set(tokens)) == len(tokens), f"duplicate class tokens: {tokens}"


def test_glyphs_pairwise_distinct() -> None:
    """C-10: bands must be distinguishable by texture glyph (not colour alone)."""
    glyphs = [ENTROPY_BAND_GLYPH[label] for label in _LABELS]
    assert len(set(glyphs)) == len(glyphs), f"duplicate glyphs: {glyphs}"


def test_glyphs_and_tokens_are_non_empty() -> None:
    """C-10: every band carries a VISIBLE glyph + a real class token — colour is
    the secondary cue, so an empty glyph/token (which would leave colour as the
    only differentiator) must fail even though it stays 'pairwise distinct'."""
    for label in _LABELS:
        glyph = ENTROPY_BAND_GLYPH[label]
        token = ENTROPY_BAND_CLASS[label]
        assert glyph and not glyph.isspace(), f"band {label!r} has no visible glyph: {glyph!r}"
        assert token and not token.isspace(), f"band {label!r} has no class token: {token!r}"


def test_class_tokens_are_css_safe() -> None:
    """Class tokens carry no '/' or whitespace (labels do; tokens must not)."""
    for label, token in ENTROPY_BAND_CLASS.items():
        assert "/" not in token, f"class token {token!r} for {label!r} contains '/'"
        assert not any(ch.isspace() for ch in token), (
            f"class token {token!r} for {label!r} contains whitespace"
        )


def test_band_style_returns_triple_for_known_label() -> None:
    """band_style() returns the (class, glyph, meaning) triple for a known band."""
    for label in _LABELS:
        assert band_style(label) == (
            ENTROPY_BAND_CLASS[label],
            ENTROPY_BAND_GLYPH[label],
            ENTROPY_BAND_MEANING[label],
        )


def test_band_style_unknown_label_falls_through_to_high() -> None:
    """band_style() falls through to the high/random entry for an unknown label.

    Mirrors entropy_service.classify_band, which returns the top band for any
    value at/above the final cutoff.
    """
    high = "high/random"
    assert band_style("no-such-band") == (
        ENTROPY_BAND_CLASS[high],
        ENTROPY_BAND_GLYPH[high],
        ENTROPY_BAND_MEANING[high],
    )
