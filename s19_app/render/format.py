"""Presentation-neutral format primitives for s19_app.

Owns the pure style constants and the microbar gauge (moved verbatim from
``s19_app/tui/insight_style.py``, batch-92 US-92-4 / PDR #D3-#D5) plus the
two pinned copies of the frozen ``s19_app/tui/color_policy.py`` highlight
styles (TC-655 pins the equality; ``color_policy`` stays canonical-for-tui).
"""

from rich.text import Text

#: OK / healthy accent (in-image, full coverage, below-warn threshold).
GREEN = "#54efae"
#: Muted label text (form field / stat labels).
LABEL = "#c5c7d2"
#: Bright value text (the datum a label describes).
VALUE = "#e9e9e9"
#: Dim grey (secondary / "not yet checked" text).
DGRAY = "#969aad"
#: Cyan accent (addresses).
CYAN = "#7dd3fc"

#: Pinned copies of the frozen ``s19_app/tui/color_policy.py`` styles
#: (TC-655 asserts value-equality; the freeze is respected, not edited).
FOCUS_HIGHLIGHT_STYLE = "bold yellow"
MAC_ADDRESS_OVERLAY_STYLE = "bold orange3"

MICROBAR_FILLED = "█"
MICROBAR_EMPTY = "░"


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
