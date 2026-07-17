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

2. Five pure, headless formatting **helpers** — ``human_bytes``,
   ``label_value``, ``microbar``, ``threshold_style`` (LLR-065.2) and
   ``cap_gauge_style`` (batch-48, LLR-079.4). Like ``entropy_style``, this
   module imports no Textual symbol, so both the view code and the unit tests
   can consume it without pulling a UI dependency into the test surface.

   ⚠ ``threshold_style`` and ``cap_gauge_style`` are DELIBERATELY separate, not
   one parametrised helper. Adding a palette parameter to ``threshold_style``
   would let any caller inject any three hues into any container — which is the
   very hole the batch-48 Inc-2b hue reservation exists to close — and it would
   not fit anyway: the gauge's escalation is **one hue at three intensities**,
   not three hues. Different codomain, different function; the four lines of
   band arithmetic they share are not worth an abstraction.

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
#: Magenta accent — **the BUDGET/CAPACITY family, and nothing else** (batch-48
#: Inc-5, operator-decided 2026-07-16).
#:
#: **Why it exists.** The Patch Editor's paste-cap gauge must escalate as its
#: buffer fills, and §6.5 Amendment F makes YELLOW ≡ *warning* app-wide — so the
#: obvious cue is :func:`threshold_style`'s GREEN/YELLOW/RED. **The operator
#: ruled that out for this surface:** inside ``#patch_editor_panel`` those three
#: hues are already claimed as **verdicts** (``_GLYPH_STYLE`` = a check
#: passed / was partial / failed; the pass-fail strip). A gauge painted yellow
#: there makes an analyst read one hue two ways in one container. The gauge
#: therefore keeps Amendment F's *semantics* (it escalates as a warning) and
#: takes a hue that **cannot be mistaken for a verdict**.
#:
#: **What it must never be confused with:** GREEN ``#54efae`` / YELLOW
#: ``#f6ff8f`` / RED ``#fd8383`` (verdicts) · Orange (the MAC-specific record
#: cue Amendment F preserved) · PURPLE ``#b565f3`` (kind role / apply chip) ·
#: CYAN ``#7dd3fc`` (address role / ``.sev-info``) · HILITE (entry chip).
#:
#: **MEASURED, not eyeballed** (``tests/test_tui_patch_json.py::
#: test_tc079_5_magenta_hue_distance``): hue **314.6°**, sat 45%, val 96% — the
#: pastel band the rest of the palette occupies (RED 48/99, PURPLE 58/95, CYAN
#: 50/99). Its nearest claimants are ``.band-high``/``only_a`` ``#e06c75``
#: (**40.7°**) and PURPLE (**40.8°**).
#:
#: ⚠ **Do NOT re-pick this by eye — but read WHY, because the reason changed.**
#: 40.7° is not a threshold this hue clears; it is the **maximum any hue on the
#: circle achieves** against the 14 claimants, and this hue is that maximum. The
#: test asserts optimality, not a floor, so a re-pick by eye will fail with the
#: correct hue in the message.
#:
#: ⚠ **Inc-5 shipped three false claims here; all are corrected above.** It said
#: **">= 43.0° from every chromatic claimant"** — measured against a complete
#: census that is not merely false but **unsatisfiable** (nothing reaches 43°).
#: It cited the test in ``test_tui_insight_style.py``; the test is in
#: ``test_tui_patch_json.py``. And it documented a "rejected lime arc at
#: [104.9°, 114.8°]" as its headline finding — **that arc does not exist**; it
#: was an artifact of omitting rich ``green`` (#008000, 120°, the
#: ``ValidationSeverity.OK`` style), which sits ~13° from it. The root cause of
#: all three: Inc-5's hue census was hand-curated and unchecked, and it omitted
#: ``#e06c75`` — 38.4°, i.e. **below Inc-5's own floor**. The census is now
#: guarded by ``test_tc079_5c_hue_census_is_complete``.
#:
#: **The surviving reasoning, which was right:** distance from the nearest
#: claimant is a necessary condition, not the objective — **not sitting between
#: two verdict hues is**. That is what disqualified Orange (37.7°, between RED
#: and YELLOW), and it is asserted as a computed predicate rather than prose.
MAGENTA = "#f586da"

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


def cap_gauge_style(pct: float, warn: float, bad: float) -> str:
    """
    Summary:
        Classify a **fill-against-a-capacity** percentage into an escalation
        step within the single :data:`MAGENTA` family, returning the matching
        Rich style string. Bands are lower-inclusive and assume a higher
        percentage is worse: ``pct < warn`` → :data:`DGRAY` (quiet — there is
        room), ``warn <= pct < bad`` → :data:`MAGENTA`, ``pct >= bad`` →
        ``"bold "`` + :data:`MAGENTA` (at/over the cap; content is being lost).

    Args:
        pct (float): The fill percentage (typically ``0.0..100.0``). Values
            outside the range classify by the same comparisons — there is no
            clamp, because a buffer *over* its cap is a real state.
        warn (float): Lower-inclusive cutoff into the warn band.
        bad (float): Lower-inclusive cutoff into the at-cap band.

    Returns:
        str: One of :data:`DGRAY`, :data:`MAGENTA`, or ``f"bold {MAGENTA}"``.
        **Never GREEN / YELLOW / RED** — that is this function's entire reason
        to exist. Boundary cases: ``pct == warn`` → magenta, ``pct == bad`` →
        bold magenta.

    Data Flow:
        - Pure comparison; no I/O.
        - Called by ``PatchEditorPanel._paste_gauge_text`` (LLR-079.4) and by
          ``tests/test_tui_insight_style.py`` (TC-079.5).

    Dependencies:
        Uses:
            - DGRAY ; MAGENTA
        Used by:
            - s19_app.tui.screens_directionb (the paste-cap gauge)
            - tests/test_tui_insight_style.py

    Example:
        >>> cap_gauge_style(10.0, 75.0, 100.0) == DGRAY
        True
        >>> cap_gauge_style(100.0, 75.0, 100.0) == f"bold {MAGENTA}"
        True
    """
    if pct >= bad:
        return f"bold {MAGENTA}"
    if pct >= warn:
        return MAGENTA
    return DGRAY
