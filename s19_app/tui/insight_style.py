"""
Pure render-helper primitives + dolphie palette for the screen-upgrade insight
layer (batch-47, US-FND, R-TUI-065).

This is the NON-frozen foundation module every screen story of batch-47 consumes
(Workspace / A2L / MAC / Memory-Map). It owns two things:

1. The dolphie-derived palette **constants** (LLR-065.1) — the operator-approved
   hex values for labels, values, the green/yellow/red state accents, the muted
   greys and pastel accents, and the four-step navy "depth stack" (bg → panel →
   odd-row → border). ``styles.tcss`` carries the matching ``$``-variables /
   ``.band-*`` rules for CSS-level theming; this module owns the same values as
   Python constants so renderers that build Rich ``Text`` inline (not via CSS
   classes) can colour from the single source.

2. Four pure, headless formatting **helpers** (LLR-065.2) — ``human_bytes``,
   ``label_value``, ``microbar``, ``threshold_style``. Like ``entropy_style``,
   this module imports no Textual symbol, so both the view code and the unit
   tests can consume it without pulling a UI dependency into the test surface.

C-17 (untrusted-text markup safety): the two ``Text``-returning helpers build a
``rich.text.Text`` via constructor + ``append`` and NEVER via
``Text.from_markup``. Any file-derived string passed as a ``value`` therefore
renders literally — bracketed / ANSI / unbalanced-markup input can never be
interpreted as Rich markup. This is the primitive-level guarantee behind the
screen-level hostile-input acceptance tests of later increments.
"""

from __future__ import annotations

from rich.text import Text

#: Muted label text (form field / stat labels).
LABEL = "#c5c7d2"
#: Bright value text (the datum a label describes).
VALUE = "#e9e9e9"
#: OK / healthy accent (in-image, full coverage, below-warn threshold).
GREEN = "#54efae"
#: Warning accent (partial coverage, warn band).
YELLOW = "#f6ff8f"
#: Error / bad accent (schema failure, bad band).
RED = "#fd8383"
#: Highlight / focus accent.
HILITE = "#91abec"
#: Pastel light-blue secondary accent.
LBLUE = "#bbc8e8"
#: Dim grey (secondary / "not yet checked" text).
DGRAY = "#969aad"
#: Purple accent (special markers).
PURPLE = "#b565f3"
#: Cyan accent (addresses).
CYAN = "#7dd3fc"

#: Navy "depth stack" — four steps from app background to panel border.
DEPTH_BG = "#0a0e1b"
DEPTH_PANEL = "#0f1525"
DEPTH_ODD_ROW = "#131a2c"
DEPTH_BORDER = "#1b233a"

#: Filled / empty cell glyphs for :func:`microbar` (deterministic).
MICROBAR_FILLED = "█"
MICROBAR_EMPTY = "░"

#: Binary (1024-based) size units for :func:`human_bytes`, ascending.
_SIZE_UNITS = ("KiB", "MiB", "GiB", "TiB", "PiB")


def human_bytes(n: int) -> str:
    """
    Summary:
        Humanize a byte count into a short, deterministic string using the
        BINARY (1024-based) convention, matching the firmware/memory domain
        where region sizes are powers of two (a ``0x10000`` span reads
        ``"64.0 KiB"``). Counts below 1024 render as an integer with a ``B``
        suffix (no false precision); 1024 and above render with one decimal
        place and the largest binary unit that keeps the mantissa under 1024.

    Args:
        n (int): A byte count (expected non-negative).

    Returns:
        str: e.g. ``"0 B"``, ``"512 B"``, ``"1.0 KiB"``, ``"1.5 KiB"``,
        ``"64.0 KiB"``, ``"1.0 MiB"``, ``"1.0 GiB"``. The divisor is binary
        (1024); ``1024`` bytes renders as ``"1.0 KiB"`` and ``1 << 30`` renders
        as ``"1.0 GiB"``.

    Data Flow:
        - Pure arithmetic on ``n``; no I/O.
        - Called by section/region size read-outs (Workspace + Memory-Map, later
          increments) and by ``tests/test_tui_insight_style.py`` (TC-065.1).

    Dependencies:
        Uses:
            - _SIZE_UNITS
        Used by:
            - s19_app.tui Workspace section rows + Memory-Map region rows
              (batch-47, later increments)
            - tests/test_tui_insight_style.py

    Example:
        >>> human_bytes(0)
        '0 B'
        >>> human_bytes(1024)
        '1.0 KiB'
        >>> human_bytes(65536)
        '64.0 KiB'
    """
    if n < 1024:
        return f"{n} B"
    value = float(n)
    unit = _SIZE_UNITS[0]
    for unit in _SIZE_UNITS:
        value /= 1024
        if value < 1024:
            break
    return f"{value:.1f} {unit}"


def label_value(label: str, value: str, style: str = "") -> Text:
    """
    Summary:
        Build a ``label value`` pair as a Rich ``Text``: a muted label, a
        separating space, then the value styled with ``style`` (or the bright
        default value colour). Constructed via ``append`` so the value renders
        literally regardless of its content (C-17-safe by construction).

    Args:
        label (str): The field label (rendered in :data:`LABEL`).
        value (str): The datum (rendered in ``style`` or :data:`VALUE`).
        style (str): Optional Rich style/colour for the value; empty → uses
            :data:`VALUE`.

    Returns:
        rich.text.Text: ``"<label> <value>"`` with the two segments styled
        independently. Never a ``str``; never markup-parsed.

    Data Flow:
        - Constructs a ``Text`` and appends the label + value segments; no
          markup parsing.
        - Called by stats-line renderers (later increments) and by
          ``tests/test_tui_insight_style.py`` (TC-065.4).

    Dependencies:
        Uses:
            - rich.text.Text ; LABEL ; VALUE
        Used by:
            - s19_app.tui stats/loader-fact lines (batch-47, later increments)
            - tests/test_tui_insight_style.py

    Example:
        >>> label_value("Loader", "4 err").plain
        'Loader 4 err'
    """
    text = Text()
    text.append(f"{label} ", style=LABEL)
    text.append(value, style=style or VALUE)
    return text


def microbar(frac: float, width: int, style: str = "", floor: bool = False) -> Text:
    """
    Summary:
        Render a proportional bar of ``width`` cells as a Rich ``Text``, filling
        ``round(frac * width)`` leading cells with :data:`MICROBAR_FILLED` and
        the remainder with :data:`MICROBAR_EMPTY`. ``frac`` is clamped to
        ``[0.0, 1.0]`` so an out-of-range ratio neither over- nor under-fills.
        With ``floor=True`` a positive ``frac`` is guaranteed at least one filled
        cell, so a small-but-present quantity never renders as an invisible bar.

    Args:
        frac (float): Fill fraction; clamped to ``[0.0, 1.0]``.
        width (int): Total cell count (expected ``>= 0``; ``0`` → empty Text).
        style (str): Optional Rich style/colour applied to the filled cells.
        floor (bool): When ``True`` and ``frac > 0`` and ``width > 0``, force at
            least one filled cell. ``frac <= 0`` still renders an empty bar —
            "present but tiny" and "absent" must stay distinguishable. Opt-in,
            defaulting to ``False``: the MAC coverage strip legitimately shows an
            EMPTY bar for ``0 of 2`` / ``0 of 0``, and the Memory-Map region rows
            keep the unfloored proportion, so only callers whose bar means "this
            row exists, here is its magnitude" (the Workspace section rows) may
            floor it (LLR-042.7).

    Returns:
        rich.text.Text: A ``width``-cell bar. Never a ``str``; the total glyph
        count always equals ``width``. Filled-cell count is deterministic:
        ``round(clamp(frac) * width)`` (banker's rounding via ``round``), raised
        to ``1`` when ``floor`` is set and ``frac > 0``.

    Data Flow:
        - Pure arithmetic + string build; no I/O, no markup parsing.
        - Called by section rows (``app.update_sections``, ``floor=True``), the
          MAC coverage strip (``validation_service``) and the Memory-Map region
          rows (``screens_directionb``), both unfloored, and by
          ``tests/test_tui_insight_style.py`` (TC-065.2 / TC-065.2b).

    Dependencies:
        Uses:
            - rich.text.Text ; MICROBAR_FILLED ; MICROBAR_EMPTY
        Used by:
            - s19_app.tui section rows, MAC coverage strip, Memory-Map region
              rows (batch-47)
            - tests/test_tui_insight_style.py

    Example:
        >>> microbar(0.5, 10).plain
        '█████░░░░░'
        >>> microbar(0.0, 4).plain
        '░░░░'
        >>> microbar(0.01, 8, floor=True).plain
        '█░░░░░░░'
    """
    clamped = min(1.0, max(0.0, frac))
    filled = round(clamped * width)
    if floor and clamped > 0.0 and width > 0:
        filled = max(1, min(width, filled))
    text = Text()
    if filled:
        text.append(MICROBAR_FILLED * filled, style=style or None)
    if width - filled:
        text.append(MICROBAR_EMPTY * (width - filled))
    return text


def threshold_style(pct: float, warn: float, bad: float) -> str:
    """
    Summary:
        Classify a percentage into a colour band and return the matching palette
        hex. Bands are lower-inclusive and assume a higher percentage is worse:
        ``pct < warn`` → :data:`GREEN`, ``warn <= pct < bad`` → :data:`YELLOW`,
        ``pct >= bad`` → :data:`RED`.

    Args:
        pct (float): The value to classify (typically ``0.0..100.0``).
        warn (float): Lower-inclusive cutoff into the warn (yellow) band.
        bad (float): Lower-inclusive cutoff into the bad (red) band.

    Returns:
        str: One of :data:`GREEN` / :data:`YELLOW` / :data:`RED`. Boundary
        cases: ``pct == warn`` → yellow, ``pct == bad`` → red.

    Data Flow:
        - Pure comparison; no I/O.
        - Called by coverage / health read-outs (later increments) and by
          ``tests/test_tui_insight_style.py`` (TC-065.3).

    Dependencies:
        Uses:
            - GREEN ; YELLOW ; RED
        Used by:
            - s19_app.tui coverage / health cues (batch-47, later increments)
            - tests/test_tui_insight_style.py

    Example:
        >>> threshold_style(10.0, 50.0, 80.0) == GREEN
        True
        >>> threshold_style(80.0, 50.0, 80.0) == RED
        True
    """
    if pct >= bad:
        return RED
    if pct >= warn:
        return YELLOW
    return GREEN
