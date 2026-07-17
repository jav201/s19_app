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
    MICROBAR_EMPTY,
    MICROBAR_FILLED,
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


def test_microbar_floor_opt_in() -> None:
    """TC-065.2b / LLR-042.7: ``microbar(..., floor=True)`` guarantees >=1 filled
    cell for any NON-EMPTY range, while ``frac == 0`` still renders an empty bar.

    WHY: this is the section-row micro-bar's documented contract (ported from the
    retired ``coverage_bar_cells``: "at least 1 so any non-empty range shows a
    bar"). At the shipped ``SECTIONS_COVERAGE_BAR_WIDTH`` of 8, any range under
    6.25% of the largest — a 64 B vector table beside a 512 KiB image, i.e. the
    normal firmware shape — rounds to 0 cells and renders an INVISIBLE bar. The
    floor is opt-in: the MAC coverage strip and the Memory-Map region rows
    legitimately show an empty bar for "0 of N", so the default must not change.
    """
    from s19_app.tui.app import SECTIONS_COVERAGE_BAR_WIDTH

    width = SECTIONS_COVERAGE_BAR_WIDTH  # 8 — the shipped section-row bar width

    # Largest range → full bar.
    assert microbar(1.0, width, floor=True).plain.count("█") == width
    # Any non-empty range → at least one cell, however small the ratio.
    for frac in (0.00012, 0.03, 0.0625, 0.5):
        filled = microbar(frac, width, floor=True).plain.count("█")
        assert filled >= 1, f"non-empty range (frac={frac}) must show >=1 cell"
    # An EMPTY range still shows an empty bar — that distinction is the point.
    assert microbar(0.0, width, floor=True).plain.count("█") == 0
    assert microbar(-0.5, width, floor=True).plain.count("█") == 0
    # Monotonic non-decreasing in frac (a larger range never yields a narrower bar).
    fracs = [0.0, 0.00012, 0.03, 0.0625, 0.25, 0.5, 0.75, 1.0]
    counts = [microbar(f, width, floor=True).plain.count("█") for f in fracs]
    assert counts == sorted(counts), f"fill must be monotonic in frac; got {counts!r}"
    # Fixed-width track: total glyph count is always `width`, whatever the fill.
    for frac in fracs:
        assert len(microbar(frac, width, floor=True).plain) == width
    # width 0 → empty Text, no crash and no floored cell to place.
    assert microbar(1.0, 0, floor=True).plain == ""

    # NO LEAK: the default (floor=False) still rounds a tiny frac down to 0 — the
    # MAC coverage strip / Memory-Map region rows keep today's exact behavior.
    assert microbar(0.00012, width).plain.count("█") == 0
    assert microbar(0.00012, width, floor=False).plain.count("█") == 0


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


def test_tc078_4_microbar_unfloored() -> None:
    """TC-078.4: the CHECKS strip's bar is proportional (``floor=False``).

    WHY (LLR-078.4): ``floor=True`` guarantees a positive fraction at least one
    filled cell — right for a bar meaning "this row exists, here is its
    magnitude" (the Workspace section rows, LLR-042.7, whose floor batch-47
    Inc-9 had to RESTORE after a cleanup dropped it). The CHECKS pass/fail bar
    means "this fraction PASSED", which inverts the harm: it must never round a
    pass rate UP, because overstating passes understates a failure.

    ⚠ **The widely-repeated reason for this choice is WRONG, and this test is
    where it was caught.** Both 01b (AT-078b: "a floored bar would show 1
    filled cell and fail") and the Inc-4 brief state that flooring would render
    a run with ZERO passes as one filled cell. MEASURED: it does not.
    ``microbar``'s floor is gated on ``clamped > 0.0``
    (``insight_style.py:214``) — the helper's own docstring says so ("``frac <=
    0`` still renders an empty bar") — so a 0-pass run renders an EMPTY bar
    under BOTH settings, and no zero-case assertion anywhere can discriminate
    the floor. The conclusion (``floor=False``) survives; the stated reason does
    not.

    The REAL harm is a small-but-NONZERO rate: 1 passed of 20 is
    ``round(0.05 * 8) == 0`` cells honestly, and a floored bar paints 1 —
    overstating a 5% pass rate as 12.5%. That case is the behavioural
    discriminator asserted below; without it, ``floor=True`` is caught only by
    the structural AST arm.

    The zero-total boundary is asserted on the ARITHMETIC the strip performs
    (``passed / total`` guarded by ``total == 0 → 0.0``): the helper cannot be
    handed a ZeroDivisionError, so the guard lives at the call site and is
    asserted through the strip builder itself.
    """
    import ast
    import inspect
    import textwrap

    from s19_app.tui.screens_directionb import PatchEditorPanel

    # The helper's unfloored contract, at both extremes.
    assert microbar(0.0, 8).plain == MICROBAR_EMPTY * 8
    assert MICROBAR_FILLED not in microbar(0.0, 8).plain, (
        "frac=0.0 must yield ZERO filled cells; a FLOORED bar shows 1 and "
        "claims a pass that never happened"
    )
    assert microbar(1.0, 8).plain == MICROBAR_FILLED * 8
    # The contrast that makes the choice load-bearing: same frac, floored.
    assert microbar(0.01, 8, floor=True).plain.startswith(MICROBAR_FILLED)
    assert microbar(0.01, 8, floor=False).plain == MICROBAR_EMPTY * 8

    # The strip's CALL SITE must not floor. Walked via AST, NOT a substring
    # grep: `"floor=True" not in source` matched this method's own DOCSTRING
    # (which explains why flooring is wrong) and failed on correct code.
    tree = ast.parse(
        textwrap.dedent(inspect.getsource(PatchEditorPanel._check_strip_text))
    )
    microbar_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and getattr(node.func, "id", None) == "microbar"
    ]
    assert len(microbar_calls) == 1, (
        f"expected exactly one microbar call in the strip builder; found "
        f"{len(microbar_calls)}"
    )
    floor_kwargs = [
        kw for kw in microbar_calls[0].keywords if kw.arg == "floor"
    ]
    assert not floor_kwargs or floor_kwargs[0].value.value is False, (
        "the CHECKS strip's bar must be UNFLOORED (LLR-078.4) — it must pass "
        "floor=False or omit the argument; its call site floors the bar"
    )

    # The zero-total guard: no division on an empty run, and frac == 0.0.
    panel = PatchEditorPanel.__new__(PatchEditorPanel)
    zero = panel._check_strip_text(
        {"passed": 0, "failed": 0, "uncheckable": 0}
    )
    assert zero.plain.endswith(MICROBAR_EMPTY * 8), (
        f"a 0-total run must render an EMPTY bar; got {zero.plain!r}"
    )
    # all-passed -> frac == 1.0 -> a full bar
    full = panel._check_strip_text(
        {"passed": 4, "failed": 0, "uncheckable": 0}
    )
    assert full.plain.endswith(MICROBAR_FILLED * 8), (
        f"an all-passed run must render a FULL bar; got {full.plain!r}"
    )

    # The BEHAVIOURAL discriminator for the floor (see the ⚠ above): 1 passed
    # of 20 -> round(0.05 * 8) == 0 cells. A floored bar paints 1 and overstates
    # a 5% pass rate as 12.5%. The zero-total case CANNOT catch this.
    small = panel._check_strip_text(
        {"passed": 1, "failed": 19, "uncheckable": 0}
    )
    assert small.plain.endswith(MICROBAR_EMPTY * 8), (
        "a small-but-nonzero pass rate (1 of 20) must round DOWN to an empty "
        f"bar — a floored bar would overstate it; got {small.plain!r}"
    )
