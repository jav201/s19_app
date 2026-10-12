from typing import List

from rich.text import Text


def format_bytes(byte_list: List[int], width: int = 16) -> str:
    """
    Formats a list of bytes into a hex + ASCII line (like a hex dump).
    :param byte_list: List of integers (0–255)
    :param width: Number of bytes per line
    :return: Formatted string
    """
    hex_str = ' '.join(f"{b:02X}" for b in byte_list)
    ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in byte_list)
    return f"{hex_str:<{width * 3}} | {ascii_str}"


def is_printable(byte: int) -> bool:
    """
    Returns True if byte is a printable ASCII character.
    """
    return 32 <= byte <= 126


def safe_decode(byte_data: bytes, encoding: str = 'ascii') -> str:
    """
    Safely decode bytes to a string, replacing undecodable characters.
    """
    return byte_data.decode(encoding, errors='replace')


#: Every codepoint ``safe_text`` deletes, selected as a BYTE CLASS: C0
#: ``U+0000``–``U+001F``, ``DEL`` ``U+007F``, and C1 ``U+0080``–``U+009F``
#: (LLR-116.7). Naming the class rather than an escape-sequence shape is
#: normative and load-bearing: ``U+009B`` is single-byte CSI and ``U+009D``
#: single-byte OSC — functional equivalents of ``ESC [`` and ``ESC ]`` that
#: carry no ``\x1b`` at all — so a filter written as "strip ``\x1b``-introduced
#: sequences" passes both and reopens the hole with every test still green.
#: The class is closed at ``U+009F``: ``U+00A0`` (NBSP) and everything above it
#: are ordinary characters and survive byte-identically.
_CONTROL_SCRUB = dict.fromkeys((*range(0x00, 0x20), *range(0x7F, 0xA0)))


def safe_text(value: str, style: str = "") -> Text:
    """Build a markup- and control-char-safe ``Text`` from a hostile string.

    Summary:
        Delete every C0/C1 control codepoint from ``value``
        (:data:`_CONTROL_SCRUB`, LLR-116.7), then wrap the remainder as a
        ``Text`` with an explicit ``style`` so it is treated as literal
        content, never as Rich markup (LLR-041.11). Together these neutralise
        both hostile shapes carried by the never-scrubbed
        ``ValidationIssue.code``/``.message``/``.symbol`` and by A2L symbol
        names: markup tokens such as ``sensor[red]`` or
        ``x[link=file:///…]``, which survive as inert literal text, and raw
        terminal control bytes, which are removed. No ``MarkupError``, no
        style leak, no escape sequence reaching the painted strip
        (security B-1 / F2).

        **The two halves are not interchangeable.** ``Text()`` alone does not
        remove a control byte — before batch-77 this function returned
        ``'sensor\\x1b[31m_evil[red]'`` unchanged while its own docstring
        claimed otherwise. An escape payload stripped of its introducer
        (``\\x1b[31m`` → ``[31m``) is then inert precisely because ``Text()``
        does not parse markup.

    Args:
        value (str): The (possibly untrusted, file-derived) text to render.
        style (str): An optional Rich style applied to the whole span
            (developer-supplied, never file-derived).

    Returns:
        Text: A ``Text`` whose content is ``value`` with every C0/C1 control
        codepoint removed and every other character preserved verbatim.

    Data Flow:
        - Used for every file-derived string reaching the grid, the region
          rows or the detail pane; ``Text.from_markup`` is deliberately
          NOT used.
        - The scrub applies to developer-supplied arguments too. That is safe
          here: an AST census over all 80 parsed ``safe_text()`` calls in
          ``s19_app/`` found **0** with a control character in a string
          literal argument, and ``build_detail_text``'s newlines are appended
          directly to the ``Text``, never through this function.

    Dependencies:
        Used by:
            - ``MemoryMapPanel.render_ranges`` / ``build_detail_text`` /
              ``symbol_list_text`` / ``_region_hex_peek``

    Example:
        >>> safe_text("sensor[red]").plain
        'sensor[red]'
        >>> safe_text("sensor\\x1b[31m_evil[red]").plain
        'sensor[31m_evil[red]'
        >>> safe_text("a\\x9b31mb").plain
        'a31mb'
    """
    return Text(value.translate(_CONTROL_SCRUB), style=style)
