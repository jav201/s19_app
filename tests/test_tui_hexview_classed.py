"""White-box TCs for classed hex bytes — TC-066.6 / LLR-066.3 (batch-47, US-WS).

``render_hex_view_text`` classes each rendered hex byte by kind:

* ``0x00`` / ``0xFF``        -> dim grey (``insight_style.DGRAY``)
* printable ASCII 0x20..0x7E -> cyan     (``insight_style.CYAN``)
* every other byte           -> bright   (``insight_style.VALUE``)

The classing is applied as Rich ``Text`` spans over the two-hex-digit byte
cells only (the ASCII gutter is left as-is), so:

* the ``.plain`` string is UNCHANGED (styling adds spans, not characters), and
* the existing search/MAC highlight styles keep priority over the class style.

The public hex constants (``MAX_HEX_BYTES`` / ``MAX_HEX_ROWS`` / ``HEX_WIDTH`` /
``SEARCH_ENCODING`` / ``FOCUS_CONTEXT_ROWS``) are asserted unchanged here — they
are public API exported from ``s19_app.tui`` and must not move for this batch.
"""

from __future__ import annotations

from typing import Dict, List

from rich.text import Text

from s19_app.tui import (
    FOCUS_CONTEXT_ROWS,
    HEX_WIDTH,
    MAX_HEX_BYTES,
    MAX_HEX_ROWS,
    SEARCH_ENCODING,
)
from s19_app.tui.color_policy import FOCUS_HIGHLIGHT_STYLE
from s19_app.tui.hexview import render_hex_view_text
from s19_app.tui.insight_style import CYAN, DGRAY, VALUE


def _cell_styles(text: Text) -> Dict[str, List[str]]:
    """Map each styled span's covered text to the list of style strings on it."""
    out: Dict[str, List[str]] = {}
    for span in text.spans:
        seg = text.plain[span.start : span.end]
        out.setdefault(seg, []).append(str(span.style))
    return out


def test_tc066_6_classed_hex_bytes_by_kind() -> None:
    """A single row with 00/FF, a printable byte, and a non-printable byte carries
    the dim / cyan / bright class style on the matching hex byte cells."""
    mem_map = {0x1000: 0x00, 0x1001: 0xFF, 0x1002: 0x41, 0x1003: 0x1B}

    text = render_hex_view_text(mem_map, focus_address=None, row_bases=None, highlight=None)

    assert isinstance(text, Text)
    styles = _cell_styles(text)

    # 00 / FF -> dim grey.
    assert any(DGRAY in s for s in styles.get("00 ", [])), styles.get("00 ")
    assert any(DGRAY in s for s in styles.get("FF ", [])), styles.get("FF ")
    # printable ASCII 'A' -> cyan.
    assert any(CYAN in s for s in styles.get("41 ", [])), styles.get("41 ")
    # non-printable, non-00/FF (ESC) -> bright.
    assert any(VALUE in s for s in styles.get("1B ", [])), styles.get("1B ")


def test_tc066_6_printable_ascii_class_boundaries() -> None:
    """Pin the exact printable-ASCII class edges (0x20..0x7E cyan; just-outside
    bright) so an off-by-one in the range (`<` vs `<=`, or 0x7F) fails here."""
    mem_map = {0x1000: 0x1F, 0x1001: 0x20, 0x1002: 0x7E, 0x1003: 0x7F}

    text = render_hex_view_text(mem_map, focus_address=None, row_bases=None, highlight=None)
    styles = _cell_styles(text)

    # 0x1F (just below space) -> bright; 0x20 (space) -> cyan.
    assert any(VALUE in s for s in styles.get("1F ", [])), styles.get("1F ")
    assert any(CYAN in s for s in styles.get("20 ", [])), styles.get("20 ")
    # 0x7E (~) -> cyan; 0x7F (DEL) -> bright.
    assert any(CYAN in s for s in styles.get("7E ", [])), styles.get("7E ")
    assert any(VALUE in s for s in styles.get("7F ", [])), styles.get("7F ")


def test_tc066_6_three_distinct_class_styles_present() -> None:
    """The rendered hex Text carries at least one cell of each of the 3 classes."""
    mem_map = {0x1000: 0x00, 0x1001: 0x41, 0x1002: 0x1B}

    text = render_hex_view_text(mem_map, focus_address=None, row_bases=None, highlight=None)

    all_styles = " ".join(str(span.style) for span in text.spans)
    assert DGRAY in all_styles
    assert CYAN in all_styles
    assert VALUE in all_styles


def test_tc066_6_plain_output_unchanged_by_classing() -> None:
    """Classing adds spans, never characters: the plain text matches the byte layout."""
    mem_map = {0x1000: 0x00, 0x1001: 0xFF, 0x1002: 0x41, 0x1003: 0x1B}

    text = render_hex_view_text(mem_map, focus_address=None, row_bases=None, highlight=None)

    # Hex bytes and the ASCII gutter render exactly as before (00 FF are '.', 41 is 'A').
    assert "00 FF 41 1B" in text.plain
    assert "|..A." in text.plain  # gutter: 00/FF -> '.', 41 -> 'A', 1B -> '.', then padding


def test_tc066_6_highlight_style_takes_priority_over_class() -> None:
    """When a byte is search-highlighted, the highlight style wins over the class style."""
    mem_map = {0x1000: 0x41, 0x1001: 0x41, 0x1002: 0x41}

    text = render_hex_view_text(
        mem_map, focus_address=0x1000, row_bases=None, highlight=(0x1001, 1)
    )

    styles = _cell_styles(text)
    # The highlighted 'A' cell carries the focus highlight, not the cyan class.
    highlighted_cell_styles = styles.get("41 ", [])
    assert any(str(FOCUS_HIGHLIGHT_STYLE) in s for s in highlighted_cell_styles), highlighted_cell_styles
    # An unhighlighted 'A' cell still carries the cyan class.
    assert any(CYAN in s for s in highlighted_cell_styles), highlighted_cell_styles


def test_tc066_6_public_hex_constants_unchanged() -> None:
    """The public hex constants keep their pre-batch values (public API, must not move)."""
    assert MAX_HEX_BYTES == 65536
    assert HEX_WIDTH == 16
    assert MAX_HEX_ROWS == 512
    assert FOCUS_CONTEXT_ROWS == 64
    assert SEARCH_ENCODING == "ascii"


def test_tc066_6_output_is_rich_text_not_markup_string() -> None:
    """The styled output is a Rich Text (spans), never a markup-parsed string."""
    mem_map = {0x1000: 0x41}

    text = render_hex_view_text(mem_map, focus_address=None, row_bases=None, highlight=None)

    assert isinstance(text, Text)
    assert text.spans  # styling is carried by spans, not embedded markup
