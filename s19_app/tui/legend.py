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

from typing import Dict, List, NamedTuple, Tuple

from ..validation import ValidationSeverity
from .color_policy import FOCUS_HIGHLIGHT_STYLE, MAC_ADDRESS_OVERLAY_STYLE
from .entropy_style import band_style
from .services.entropy_service import ENTROPY_BANDS

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


# ---------------------------------------------------------------------------
# N8 — comprehensive per-view Legend content (batch 2026-07-23-batch-n8).
#
# The N8 Legend renders, per active rail view, an annotated example CARD on top
# then the real colour/entropy key below it. This block owns only the DATA (the
# card lines, the derived entropy band-key rows, and the small format/derivation
# helpers); the widget layout lives in ``LegendScreen.compose`` (screens.py,
# Inc-2/Inc-3). Keeping the copy here mirrors the existing ``LEGEND_TABLE`` →
# ``compose`` split (design decision D-2) and keeps ``legend.py`` widget-free.
#
# UNLIKE ``LEGEND_TABLE`` (bracket-free by rule S-01, since the modal renders
# rows markup-enabled), N8 lines MAY carry Textual/Rich markup. Every LITERAL
# ``[`` is therefore escaped as ``\[`` so it round-trips to a visible ``[``
# instead of opening a style tag (guarded by TC-N8-11 / AMD-9). Style tags like
# ``[b] … [/]`` are intentional and are consumed, not shown.
# ---------------------------------------------------------------------------

#: A card line's presentation role. ``LegendScreen.compose`` maps each role to a
#: widget CSS class: ``sub`` → bold sub-heading, ``line`` → rendered sample,
#: ``caption`` → dim annotation, ``warning_sample`` → the MAC reconciliation
#: sample row that Inc-2 paints inline ``orange3`` and tags
#: ``#legend_mac_warning_sample`` (AMD-7 / AMD-11).
ROLE_SUB = "sub"
ROLE_LINE = "line"
ROLE_CAPTION = "caption"
ROLE_WARNING_SAMPLE = "warning_sample"


class LegendLine(NamedTuple):
    """One annotated card line: its presentation ``role`` and its ``text``.

    ``text`` may contain Textual markup; literal brackets are escaped ``\\[``.
    """

    role: str
    text: str


class BandKeyRow(NamedTuple):
    """One entropy band-key row, DERIVED from ``ENTROPY_BANDS`` via ``band_style``.

    Carries everything ``compose`` needs to paint the row without re-declaring
    band facts: the texture ``glyph`` (C-10 primary cue), the band ``label``,
    the display ``range_text`` (e.g. ``"[5,7.2)"``), the plain-language
    ``meaning``, and the ``css_class`` (a ``band-*`` token, never ``sev-*``).
    """

    glyph: str
    label: str
    range_text: str
    meaning: str
    css_class: str


#: Closing note stating bands are an ENTROPY domain, distinct from severities
#: (rendered by ``compose`` after the band key — LLR-N8-3.2).
BAND_DOMAIN_NOTE = (
    "bands = bits/byte entropy over a 256 B window; boundary values go to the "
    "HIGHER band. Bands ≠ severities: an ENTROPY domain, separate from the "
    "sev-* severity domain."
)

#: The gap-hatch pseudo-row shown under the band key: an unmapped gap between
#: runs is not a band and carries no colour class (LLR-N8-3.2).
BAND_GAP_HATCH_NOTE = (
    "╱ gap hatch — unmapped gap between runs (NOT a band, no colour "
    "class)"
)


def format_cutoff(value: float) -> str:
    """
    Summary:
        Format an ``ENTROPY_BANDS`` cutoff for display as the single source of
        the transform shared by the map card and its acceptance test (AMD-10a):
        trim a trailing ``.0`` (``5.0`` -> ``"5"``), keep a real fraction
        (``7.2`` -> ``"7.2"``), and clamp the ``8.000001`` headroom sentinel
        (the top band's exclusive upper bound) to ``"8"`` so the range reads
        ``[7.2,8]`` rather than ``[7.2,8.000001)``.

    Args:
        value (float): A band cutoff from :data:`ENTROPY_BANDS` (0.0, 1.0, 5.0,
            7.2, or the 8.000001 sentinel).

    Returns:
        str: The display string for ``value`` — ``"8"`` for any value above the
        8.0 maximum entropy, otherwise ``value`` with an insignificant trailing
        zero trimmed (``format(value, "g")``).

    Raises:
        None.

    Data Flow:
        - Consumed by :func:`build_band_key_rows` to render each band's
          ``[lo,hi)`` range, and by the Memory-Map card copy, so display value
          and test assertion share one transform (no hand-listed cutoffs).

    Dependencies:
        Uses:
            - (none — pure arithmetic/format)
        Used by:
            - build_band_key_rows
            - tests/test_legend_n8.py

    Example:
        >>> format_cutoff(5.0)
        '5'
        >>> format_cutoff(7.2)
        '7.2'
        >>> format_cutoff(8.000001)
        '8'
    """
    if value > 8.0:
        return "8"
    return format(value, "g")


def build_band_key_rows() -> List[BandKeyRow]:
    """
    Summary:
        Build the Memory-Map entropy band key by DERIVING one row per band from
        :data:`ENTROPY_BANDS` via :func:`band_style` (LLR-N8-3.2 / design
        decision D-3), so an upstream band added, removed or re-cut flows
        through to the legend and its test without a hand-edit. Each row carries
        the band's glyph, label, half-open ``[lo,hi)`` range (the final band
        closed ``]`` at its inclusive maximum), meaning and ``band-*`` class.

    Args:
        None.

    Returns:
        List[BandKeyRow]: one :class:`BandKeyRow` per entry in
        :data:`ENTROPY_BANDS`, in band order — so ``len(...) ==
        len(ENTROPY_BANDS)``.

    Raises:
        None.

    Data Flow:
        - Reads :data:`ENTROPY_BANDS` (cutoffs) and calls :func:`band_style`
          (glyph/meaning/class) per band; formats cutoffs through
          :func:`format_cutoff`.
        - Consumed by ``LegendScreen.compose`` (Inc-3) to render the band key
          rows painted with their ``band-*`` classes.

    Dependencies:
        Uses:
            - ENTROPY_BANDS
            - band_style
            - format_cutoff
        Used by:
            - s19_app.tui.screens.LegendScreen.compose (Inc-3)
            - tests/test_legend_n8.py

    Example:
        >>> rows = build_band_key_rows()
        >>> rows[0].glyph, rows[0].range_text, rows[0].css_class
        ('·', '[0,1)', 'band-constant')
        >>> rows[-1].range_text
        '[7.2,8]'
    """
    rows: List[BandKeyRow] = []
    last = len(ENTROPY_BANDS) - 1
    for index, (label, lo, hi) in enumerate(ENTROPY_BANDS):
        css_class, glyph, meaning = band_style(label)
        close = "]" if index == last else ")"
        range_text = f"[{format_cutoff(lo)},{format_cutoff(hi)}{close}"
        rows.append(BandKeyRow(glyph, label, range_text, meaning, css_class))
    return rows


def _band_glyphs_spaced() -> str:
    """Ordered band glyphs (``· ░ ▒ ▓``) DERIVED from
    ``band_style`` (AMD-10b) — the workspace memory strip and the map band bar
    both draw their glyphs from this one source, never a hand-list."""
    return "  ".join(band_style(label)[1] for label, _lo, _hi in ENTROPY_BANDS)


def _map_band_bar_sample() -> str:
    """A representative band-bar strip built from the DERIVED band glyphs plus
    the gap hatch (LLR-N8-3.1: the sample uses ``·░▒▓`` and
    the gap glyph ``╱``)."""
    glyph = {label: band_style(label)[1] for label, _lo, _hi in ENTROPY_BANDS}
    return (
        glyph["medium"] * 6
        + glyph["high/random"] * 4
        + "╱" * 3
        + glyph["low"] * 6
        + glyph["constant/padding"] * 4
        + glyph["high/random"] * 4
    )


def _workspace_lines() -> List[LegendLine]:
    strip = f"{_band_glyphs_spaced()}  ╱  █"
    return [
        LegendLine(
            ROLE_SUB,
            "Memory strip (top) — one glyph per address cell; glyph "
            "carries meaning, colour secondary",
        ),
        LegendLine(ROLE_LINE, strip),
        LegendLine(
            ROLE_CAPTION,
            "· constant/padding (grey)   ░ low—structured/tables "
            "(green)   ▒ medium—calibration (amber)",
        ),
        LegendLine(
            ROLE_CAPTION,
            "▓ high/random—code (red)   ╱ gap/unmapped   █ "
            "fallback: valid green / invalid red / gap grey",
        ),
        LegendLine(ROLE_SUB, "Loaded panel — one slot per artifact"),
        LegendLine(
            ROLE_LINE,
            "[b]S19[/]  firmware.s19   1.2 KiB · 3 rng   = name · "
            "mapped bytes · range count",
        ),
        LegendLine(
            ROLE_LINE,
            "[b]MAC[/]  checks.mac   5 records      [b]A2L[/]  model.a2l   "
            "42 tags   = name · count",
        ),
        LegendLine(
            ROLE_CAPTION,
            r"(none) dim = not loaded · \[u] unload one · \[U] unload all",
        ),
        LegendLine(
            ROLE_SUB,
            "Data Sections (left pane) — one row per contiguous range",
        ),
        LegendLine(
            ROLE_LINE,
            "[b]✓ 0x00000000 – 0x000004FF   1.2 KiB ▒[/]",
        ),
        LegendLine(
            ROLE_CAPTION,
            "= ✓/✗ validity · start address · inclusive end "
            "· humanized size · dominant band glyph",
        ),
        LegendLine(
            ROLE_CAPTION,
            "green row = valid · red = invalid · █░░"
            "░░░░░ 8-cell bar = range size vs largest "
            "range",
        ),
        LegendLine(
            ROLE_CAPTION,
            "... N more ranges (see log) ... = over 200 · MAC out-of-range "
            "@ 0x… = amber, outside ranges",
        ),
        LegendLine(
            ROLE_SUB,
            "Hex view (center pane) — Search ASCII / Goto 0xADDR drive it",
        ),
        LegendLine(
            ROLE_LINE,
            "[b]0x00001000[/]  DE AD BE EF … 00  |.....|",
        ),
        LegendLine(
            ROLE_CAPTION,
            "= row address · 16 byte values (blank = unmapped) · ASCII "
            "gutter (. = non-printable)",
        ),
        LegendLine(ROLE_SUB, "Context / coverage stats (right pane)"),
        LegendLine(
            ROLE_LINE,
            "Coverage: 87.50%   Ranges: 3   Errors: 0   Warnings: 2",
        ),
        LegendLine(
            ROLE_CAPTION,
            "= % of image span covered by valid ranges · total ranges "
            "· ERROR issues · WARNING issues",
        ),
        LegendLine(
            ROLE_LINE,
            "Loader 0 err · ⚠4 OOO · Entry 0x00000000",
        ),
        LegendLine(
            ROLE_CAPTION,
            "= loader errors (red >0) · out-of-order S19 records "
            "(yellow >0) · entry point (— when absent)",
        ),
        LegendLine(
            ROLE_CAPTION,
            "A2L summary lines 1-20 / 142 = right-pane preview · No A2L "
            "loaded. = empty",
        ),
        LegendLine(ROLE_SUB, "Status bar (under every screen)"),
        LegendLine(
            ROLE_CAPTION,
            "last action · progress bar · 4 log-tail lines · "
            "empty: No file loaded - Ctrl+L (or 'l') / 'p'",
        ),
        LegendLine(
            ROLE_CAPTION,
            "(this view has no severity colour key — its cues are the "
            "glyphs and labels above)",
        ),
    ]


def _a2l_lines() -> List[LegendLine]:
    return [
        LegendLine(
            ROLE_SUB,
            "One table row — the 16 Explorer columns (sample values, in "
            "two halves)",
        ),
        LegendLine(
            ROLE_LINE,
            "[b]RPM_LIMIT ✓[/]  0x80040000  4  assigned  7500  7500.0  "
            "yes  flash",
        ),
        LegendLine(
            ROLE_CAPTION,
            "= Tag(name + ✓ in image / · not) · Address · "
            "Length(bytes, n/a) · Source(assigned/formula)",
        ),
        LegendLine(
            ROLE_CAPTION,
            "· Raw(decoded) · Physical(engineering value) · "
            "InMem(yes/no/n/a) · Region(flash/ram/unknown)",
        ),
        LegendLine(
            ROLE_LINE,
            "0..8000  rpm  —  MSB_FIRST  no  ENGINE  calibratable  UWORD",
        ),
        LegendLine(
            ROLE_CAPTION,
            "= Limits lo..hi · Unit · Bits mask · Endian · "
            "Virt · Func · Access · Dtype",
        ),
        LegendLine(
            ROLE_CAPTION,
            "Access: read_only / calibratable · Dtype: UWORD, "
            "FLOAT32_IEEE …",
        ),
        LegendLine(ROLE_SUB, "Summary line"),
        LegendLine(
            ROLE_LINE,
            "Page 2/7 | tags 201-400 / 1394 (page size 200; +/- to change) "
            "· 312 in image",
        ),
        LegendLine(
            ROLE_CAPTION,
            "= current page / pages · tag range shown / total · "
            "page-size hint · in-image counter (green)",
        ),
        LegendLine(ROLE_SUB, "Filter row"),
        LegendLine(
            ROLE_LINE,
            r"\[text]  \[Field: name]  (All | Invalid | In-Memory)  "
            r"\[Find next]  \[Page Prev/Next]",
        ),
        LegendLine(
            ROLE_CAPTION,
            "text narrows rows · Field targets one column · modes "
            "all/invalid/in-image · Find next · paging",
        ),
        LegendLine(
            ROLE_SUB,
            "Detail card (selected tag — fields beyond the table)",
        ),
        LegendLine(
            ROLE_CAPTION,
            "desc · unit/conv · layout(RECORD_LAYOUT) · byteorder "
            "· limits · display_identifier",
        ),
        LegendLine(
            ROLE_CAPTION,
            "~10 more fields stay in detail/log only (matrix dims, axis meta, "
            "decode errors, raw bytes…)",
        ),
    ]


def _map_lines() -> List[LegendLine]:
    return [
        LegendLine(
            ROLE_SUB,
            "Header + band bar (one proportional segment per merged run)",
        ),
        LegendLine(
            ROLE_LINE,
            "Entropy bands - 7 region(s), 262144 B mapped",
        ),
        LegendLine(
            ROLE_CAPTION,
            "= merged runs + mapped bytes · empty: No file loaded … / "
            "No entropy detail for this image.",
        ),
        LegendLine(ROLE_LINE, _map_band_bar_sample()),
        LegendLine(
            ROLE_CAPTION,
            "glyph repeated per segment · ╱╱╱ gap hatch = "
            "unmapped gap between runs (NOT a band)",
        ),
        LegendLine(
            ROLE_LINE,
            "80000000      80004000      80008000      8000C000      8000FFFF",
        ),
        LegendLine(
            ROLE_CAPTION,
            "address ruler — 5 ticks at 0/25/50/75/100 % of span (8-hex, "
            "no 0x prefix)",
        ),
        LegendLine(ROLE_SUB, "Region row (click to inspect + jump to hex)"),
        LegendLine(
            ROLE_LINE,
            "[b]░ 0x80000000  256 B  ██░░  3 sym  low "
            "↵[/]",
        ),
        LegendLine(
            ROLE_CAPTION,
            "= band glyph · start · size · 4-cell size bar(vs "
            "largest) · symbols · band label · ↵ open hex",
        ),
        LegendLine(ROLE_SUB, "At a glance"),
        LegendLine(
            ROLE_LINE,
            "░ low 4 ████ 66%   = per-band histogram: "
            "glyph · band · count · 6-cell bar · % of regions",
        ),
        LegendLine(ROLE_LINE, " ▁▂▅█▇▄▂▁ …"),
        LegendLine(
            ROLE_CAPTION,
            "sparkline — 24-col entropy profile, 9-level ramp "
            "\" ▁▂▃▄▅▆▇█\" "
            "(0 none → 8 max), band-coloured",
        ),
        LegendLine(ROLE_SUB, "Coverage stats + region inspector"),
        LegendLine(
            ROLE_CAPTION,
            "Coverage: 98.44% · Bytes covered · Valid/Invalid ranges "
            "· Gaps · Largest gap · Total issues",
        ),
        LegendLine(
            ROLE_CAPTION,
            "inspector: Status VALID/INVALID/GAP · Cell · Region(+A2L "
            "sym) · issues · Size · band · Peek",
        ),
        LegendLine(ROLE_SUB, "Hex overlays (painted in the map hex-peek)"),
        LegendLine(
            ROLE_CAPTION,
            "search / goto-focus highlight = byte span matched by the last "
            "in-memory search / goto jump",
        ),
        LegendLine(
            ROLE_CAPTION,
            "MAC address overlay = a hex byte at an address referenced by a "
            "loaded MAC record",
        ),
    ]


def _mac_lines() -> List[LegendLine]:
    return [
        LegendLine(ROLE_SUB, "Coverage strip"),
        LegendLine(
            ROLE_LINE,
            "MAC→S19 1 of 2 █████░░"
            "░░░ · A2L↔MAC 3 matches",
        ),
        LegendLine(
            ROLE_CAPTION,
            "= MAC addresses in the image (count + green bar) · A2L↔MAC "
            "same-address matches",
        ),
        LegendLine(ROLE_SUB, "One table row — the 8 columns"),
        LegendLine(
            ROLE_LINE,
            "[b]✓ VVT_ENABLE[/]  0x80040000  yes  yes  OK  12  —  "
            "MEAS:VVT_ENABLE",
        ),
        LegendLine(
            ROLE_CAPTION,
            "= Tag(glyph+name) · Address · InA2L · InMem · "
            "Status · SourceLine(.mac) · ParseErr · A2LMatch",
        ),
        LegendLine(ROLE_SUB, "Tag status glyphs (glyph is the primary cue)"),
        LegendLine(
            ROLE_LINE,
            "✗ parse error(red) · ⚠ out-of-image(orange) · "
            "✓ in image(green) · · not checked(grey)",
        ),
        LegendLine(
            ROLE_CAPTION,
            "MAC-only / no primary image stays grey — deliberately NOT "
            "green",
        ),
        LegendLine(ROLE_SUB, "Status vocabulary → row colour"),
        LegendLine(
            ROLE_CAPTION,
            "ERR_PARSE / A2L_ADDR_MISMATCH / NO_ADDR = error(red) · "
            "NOT_IN_A2L = warning",
        ),
        LegendLine(
            ROLE_CAPTION,
            "OUT_OF_IMAGE = info(white) · NO_A2L = neutral(grey) · "
            "OK = green",
        ),
        # Reconciliation block (mandatory fold-in #2 / AMD-7): the key names the
        # SEVERITY word (pale yellow) but the MAC table paints warning rows
        # inline orange3. Inc-2 paints the warning_sample row orange3 + tags it
        # #legend_mac_warning_sample (AMD-11); this data layer only carries the
        # text.
        LegendLine(
            ROLE_SUB,
            "Orange vs Pale yellow — two paint pipelines, one severity",
        ),
        LegendLine(
            ROLE_CAPTION,
            "the key names the SEVERITY (.sev-warning pale yellow, cross-view "
            "lists)",
        ),
        LegendLine(
            ROLE_WARNING_SAMPLE,
            "⚠ VVT_TEMP  0x80041234  yes  no  NOT_IN_A2L  17   ← what "
            "a warning row looks like",
        ),
        LegendLine(
            ROLE_CAPTION,
            "the MAC table paints this row inline orange3 (the MAC cue: ⚠ "
            "glyph, hex overlay, Sections labels)",
        ),
        LegendLine(
            ROLE_CAPTION,
            "two pipelines, one severity — trust the glyph (✗ ⚠ "
            "✓ ·) and the Status column, not the hue",
        ),
    ]


def _issues_lines() -> List[LegendLine]:
    return [
        LegendLine(
            ROLE_SUB,
            "Severity strip — whole-list distribution + 5-cell bars "
            "(red / pale yellow / cyan)",
        ),
        LegendLine(
            ROLE_LINE,
            "Errors 3 ███░░   Warnings 1 █░"
            "░░░   Info 2 ██░░░",
        ),
        LegendLine(ROLE_SUB, "Filter row"),
        LegendLine(
            ROLE_LINE,
            r"(All | Errors | Warnings)  \[Legend]   — Info rows appear "
            "only under All",
        ),
        LegendLine(ROLE_SUB, "Grouped list (order ERROR → WARNING → INFO)"),
        LegendLine(ROLE_LINE, "[b]✗ ERRORS (3)[/]"),
        LegendLine(
            ROLE_LINE,
            "   TRIPLE_NAME_ADDRESS_MISMATCH   VVT_ENABLE · 0x80040000 "
            "· addresses differ   a2l, mac, s19",
        ),
        LegendLine(
            ROLE_CAPTION,
            "= code chip · detail(symbol · 0xADDR · message) "
            "· related artifacts · ⚠/• head W/I groups",
        ),
        LegendLine(ROLE_SUB, "Issue-code families (E = error, W = warning)"),
        LegendLine(
            ROLE_CAPTION,
            "MAC: PARSE_ERROR · EMPTY_NAME · INVALID_ADDRESS · "
            "DUPLICATE_NAME (E) DUPLICATE_ADDRESS (E/W/I)",
        ),
        LegendLine(
            ROLE_CAPTION,
            "A2L: STRUCTURE_ERROR·INVALID_ADDRESS·DUPLICATE_SYMBOL(E) "
            "UNRECOGNIZED_BLOCK·BROKEN_REFERENCE(W)",
        ),
        LegendLine(
            ROLE_CAPTION,
            "CROSS: MAC_S19 / A2L_S19 OUT_OF_RANGE + OVERLAP_AMBIGUOUS (W) "
            "· MAC / A2L_ONLY_SYMBOL (W)",
        ),
        LegendLine(ROLE_CAPTION, "TRIPLE_NAME_ADDRESS_MISMATCH (E)"),
        LegendLine(ROLE_SUB, "Summary + Hex Peek"),
        LegendLine(
            ROLE_LINE,
            "total=6 | errors=3 | warnings=1 | info=2 | filter=all | page 1/1 "
            "rows 1-6/6",
        ),
        LegendLine(
            ROLE_CAPTION,
            "Hex Peek — ±6 hex rows around the selected issue's "
            "address · (issue has no address …)",
        ),
    ]


#: Per-view annotated example-card content, keyed by ``_active_screen_key``
#: (``workspace`` / ``a2l`` / ``map`` / ``mac`` / ``issues``). Each value is an
#: ordered list of :class:`LegendLine` transcribed at FULL density from
#: ``prototypes/legend_n8.kimi.NOTES.md`` / ``legend_n8.INVENTORY.md``. Rendered
#: by ``LegendScreen.compose`` (Inc-2/Inc-3) above the view's colour/band key.
LEGEND_EXAMPLES: Dict[str, List[LegendLine]] = {
    "workspace": _workspace_lines(),
    "a2l": _a2l_lines(),
    "map": _map_lines(),
    "mac": _mac_lines(),
    "issues": _issues_lines(),
}
