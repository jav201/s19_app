"""
Unit tests for the pure ``insight_style`` render helpers (batch-47, US-FND,
R-TUI-065, LLR-065.1 / LLR-065.2).

Layer-A white-box coverage of the foundation helper module: the dolphie-derived
palette constants and the four pure formatting primitives (``human_bytes``,
``label_value``, ``microbar``, ``threshold_style``). These are headless — no
Textual/Pilot surface — so they are asserted directly.

C-17 note: ``label_value`` / ``microbar`` MUST return ``rich.text.Text`` objects
built via constructor/append (never ``Text.from_markup``); the isinstance
assertions here are the primitive-level guard behind the screen-level hostile
input ATs of later increments.
"""

from __future__ import annotations

from rich.text import Text

from s19_app.tui.insight_style import (
    CYAN,
    DEPTH_BG,
    DEPTH_BORDER,
    DEPTH_ODD_ROW,
    DEPTH_PANEL,
    DGRAY,
    GREEN,
    HILITE,
    LABEL,
    LBLUE,
    PURPLE,
    RED,
    VALUE,
    YELLOW,
    human_bytes,
    label_value,
    microbar,
    threshold_style,
)


def test_palette_constants_present_and_correct() -> None:
    """LLR-065.1: palette constants importable and equal to the operator-approved
    dolphie hex values. WHY: the theme + every insight cue derive their colour
    from these; a drifted hex silently repaints the whole app off-palette.
    """
    assert LABEL == "#c5c7d2"
    assert VALUE == "#e9e9e9"
    assert GREEN == "#54efae"
    assert YELLOW == "#f6ff8f"
    assert RED == "#fd8383"
    assert HILITE == "#91abec"
    assert LBLUE == "#bbc8e8"
    assert DGRAY == "#969aad"
    assert PURPLE == "#b565f3"
    assert CYAN == "#7dd3fc"
    assert DEPTH_BG == "#0a0e1b"
    assert DEPTH_PANEL == "#0f1525"
    assert DEPTH_ODD_ROW == "#131a2c"
    assert DEPTH_BORDER == "#1b233a"


def test_human_bytes() -> None:
    """TC-065.1: ``human_bytes`` humanizes a byte count deterministically (BINARY).

    WHY: section/region size read-outs must be glanceable, stable, and aligned
    with the firmware/memory domain where spans are powers of two — a ``0x10000``
    region reads ``"64.0 KiB"``, not ``"65.5 KB"`` (operator decision 2026-07-15,
    §6.5 Amendment D). Sub-1024 shows an integer + ``B`` (no false precision);
    1024+ shows one decimal + a binary (1024-based) unit. ``0`` is the empty
    boundary from HLR-065; ``1024 → "1.0 KiB"`` and ``1 << 30 → "1.0 GiB"`` are
    the canonical binary thresholds (fixes the divisor at 1024).
    """
    assert human_bytes(0) == "0 B"
    assert human_bytes(1) == "1 B"
    assert human_bytes(512) == "512 B"
    assert human_bytes(1023) == "1023 B"
    assert human_bytes(1024) == "1.0 KiB"
    assert human_bytes(1536) == "1.5 KiB"
    assert human_bytes(0x10000) == "64.0 KiB"  # 65536 — a power-of-two span
    assert human_bytes(1 << 20) == "1.0 MiB"
    # 1 GiB → GiB band (canonical binary threshold); assert both unit and value.
    assert human_bytes(1 << 30).endswith(" GiB")
    assert human_bytes(1 << 30) == "1.0 GiB"


def test_microbar() -> None:
    """TC-065.2: ``microbar`` fills ``round(frac*width)`` cells, clamped to [0,1].

    WHY: the bar must be a faithful, deterministic proportion — frac=0 shows an
    empty bar, frac=1 a full bar, and out-of-range input is clamped rather than
    over/under-filling (a size ratio can momentarily exceed 1.0).
    """
    width = 10
    assert microbar(0.0, width).plain.count("█") == 0
    assert microbar(1.0, width).plain.count("█") == width
    assert microbar(0.5, width).plain.count("█") == round(width / 2)
    # banker's-rounding tie (round(2.5)==2) — pins round() vs int()/trunc regressions
    assert microbar(0.5, 5).plain.count("█") == 2
    # total cell count is always `width`, whatever the fill
    assert len(microbar(0.5, width).plain) == width
    assert len(microbar(0.0, width).plain) == width
    # clamping: below 0 → empty, above 1 → full
    assert microbar(-0.5, width).plain.count("█") == 0
    assert microbar(1.5, width).plain.count("█") == width
    # width 0 → empty Text, no crash
    assert microbar(1.0, 0).plain == ""


def test_microbar_returns_text() -> None:
    """TC-065.2 / TC-065.4: ``microbar`` returns ``rich.text.Text``, not ``str``.

    WHY (C-17): a bar rendered into a widget must be a Text object so no caller
    can accidentally route a markup string through ``from_markup``.
    """
    result = microbar(0.5, 8)
    assert isinstance(result, Text)
    assert not isinstance(result, str)


def test_label_value_returns_text() -> None:
    """TC-065.4: ``label_value`` returns ``rich.text.Text`` (never a markup str).

    WHY (C-17): this is the shared label/value primitive every stats line uses;
    returning a Text built via append means a hostile ``value`` renders literally
    and can never be markup-parsed.
    """
    result = label_value("Loader", "4 err")
    assert isinstance(result, Text)
    assert not isinstance(result, str)
    # both label and value survive verbatim in the plain text
    assert "Loader" in result.plain
    assert "4 err" in result.plain
    # a bracket-bearing value renders literally (no markup parse, no crash)
    hostile = label_value("Name", "[red]x[/red] sensor[unclosed")
    assert "[red]x[/red] sensor[unclosed" in hostile.plain


def test_threshold_style() -> None:
    """TC-065.3: ``threshold_style`` picks green/yellow/red by lower-inclusive band.

    WHY: coverage/health read-outs must colour deterministically at the exact
    cutoffs. Bands are lower-inclusive and assume higher pct = worse:
    pct < warn → GREEN, warn <= pct < bad → YELLOW, pct >= bad → RED. The
    boundary cases (pct == warn, pct == bad) are the documented edge.
    """
    warn, bad = 50.0, 80.0
    assert threshold_style(10.0, warn, bad) == GREEN
    assert threshold_style(65.0, warn, bad) == YELLOW
    assert threshold_style(95.0, warn, bad) == RED
    # boundaries: pct == warn → YELLOW (warn band), pct == bad → RED (bad band)
    assert threshold_style(warn, warn, bad) == YELLOW
    assert threshold_style(bad, warn, bad) == RED
    # just below each cutoff stays in the lower band
    assert threshold_style(49.999, warn, bad) == GREEN
    assert threshold_style(79.999, warn, bad) == YELLOW
