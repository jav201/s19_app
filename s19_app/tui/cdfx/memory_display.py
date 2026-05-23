"""
Memory-field change value display — s19_app batch-04, increment 3.

A :class:`~s19_app.tui.cdfx.memory.MemoryChange` stores its edit value as a raw
run of bytes (``new_bytes``, an immutable ``tuple[int, ...]``). This module
derives the *display* forms of that run — the text the Patch Editor shows the
engineer — without ever mutating the stored bytes. Three forms are produced
from the one stored run:

- **hex** — the primary form: each byte as a two-digit uppercase hexadecimal
  token, space-separated (``01 AB FF``) — LLR-003.1.
- **ascii** — a companion form: each byte in the printable ASCII range
  0x20-0x7E shown as its character, every other byte shown as the single fixed
  placeholder ``.`` (the period, byte 0x2E), so the ASCII string keeps
  one-character-per-byte positional alignment with the hex form — LLR-003.2.
- **decimal** — a companion form: each byte as its decimal value,
  space-separated (``65 66``) — LLR-003.2.

This is the raw-bytes peer of the batch-03 ``display.py`` (which formats an A2L
parameter value by its resolved type): same "derive a display string, never
mutate the source" discipline, but here the form is fixed by the raw-bytes
nature of the data, not chosen from an A2L type.

The module is **pure**: no XML, no JSON, no Textual, no file I/O. It imports
stdlib only and reads ``new_bytes`` strictly by iteration, so a render call can
never alter the entry's stored bytes (LLR-003.3).

Implements LLR-003.1, LLR-003.2 and the display half of LLR-003.3.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

# The single fixed placeholder for a byte outside the printable ASCII range.
# Pinned to "." (the period, byte 0x2E) — the conventional hex-dump
# placeholder — by LLR-003.2 so two implementations cannot disagree.
ASCII_PLACEHOLDER = "."

# Inclusive bounds of the printable ASCII range: space (0x20) through tilde
# (0x7E). A byte inside this range renders as its own character; any other
# byte renders as ASCII_PLACEHOLDER.
PRINTABLE_ASCII_MIN = 0x20
PRINTABLE_ASCII_MAX = 0x7E


@dataclass(frozen=True, slots=True)
class MemoryValueRendering:
    """
    Summary:
        The three display forms of a memory-change entry's stored byte run.

    A render result bundles all three forms of one ``new_bytes`` run so the
    Patch Editor can show the primary hex form and the ASCII / decimal
    companions from a single :func:`format_memory_value` call. The forms are
    positionally aligned: form for form, the *n*-th hex token, the *n*-th ASCII
    character and the *n*-th decimal token all describe the same byte.

    Attributes:
        hex (str): Space-separated two-digit uppercase hexadecimal tokens, one
            per byte — the primary form (LLR-003.1). Empty string for an empty
            run (a run an empty ``MemoryChange`` cannot hold — see the note in
            :func:`format_memory_value`).
        ascii (str): One character per byte — the byte's character when it is
            in the printable range 0x20-0x7E, the ``.`` placeholder otherwise
            (LLR-003.2). Length equals the byte count.
        decimal (str): Space-separated decimal byte values, one per byte
            (LLR-003.2).

    The dataclass is ``frozen`` — a rendering is a read-only derived view; it
    carries no reference to the source ``new_bytes`` tuple, so holding it can
    never mutate the entry (LLR-003.3).
    """

    hex: str
    ascii: str
    decimal: str


def format_memory_value(new_bytes: Sequence[int]) -> MemoryValueRendering:
    """
    Summary:
        Render a memory-change entry's stored byte run as its hex, ASCII and
        decimal display forms, without mutating the stored bytes.

    Args:
        new_bytes (Sequence[int]): The entry's stored byte run — an ordered
            sequence of integer byte values, each in the range 0-255
            (typically the ``tuple[int, ...]`` held by ``MemoryChange``). Read
            by iteration only; never mutated (LLR-003.3).

    Returns:
        MemoryValueRendering: The three positionally-aligned display forms —
            ``hex`` (primary), ``ascii`` and ``decimal``. For a single byte
            ``0x41`` the result is ``hex="41"``, ``ascii="A"``, ``decimal="65"``.

    Raises:
        None: Formatting never raises. ``MemoryChange.__post_init__`` already
            rejects a negative byte, a byte above 255 or an empty run at
            construction (LLR-002.5), so a byte run reaching this function is
            well-formed; an empty sequence still renders as three empty strings
            rather than raising.

    Data Flow:
        - Render each byte to its two-digit uppercase hex token; join on space.
        - Map each byte to its ASCII character or the ``.`` placeholder; join
          with no separator so one character lines up with one hex token.
        - Render each byte to its decimal text; join on space.
        - Bundle the three strings into a frozen MemoryValueRendering.

    Dependencies:
        Uses:
            - _ascii_char
        Used by:
            - The Patch Editor screen (increment 8) to render a memory-change
              row's value in hex, with ASCII / decimal companions.

    Example:
        >>> r = format_memory_value([0x01, 0xAB, 0xFF])
        >>> r.hex
        '01 AB FF'
        >>> format_memory_value([0x41, 0x42]).ascii
        'AB'
        >>> format_memory_value([0x41, 0x42]).decimal
        '65 66'
    """
    hex_form = " ".join(f"{byte_value:02X}" for byte_value in new_bytes)
    ascii_form = "".join(_ascii_char(byte_value) for byte_value in new_bytes)
    decimal_form = " ".join(str(byte_value) for byte_value in new_bytes)
    return MemoryValueRendering(
        hex=hex_form,
        ascii=ascii_form,
        decimal=decimal_form,
    )


def _ascii_char(byte_value: int) -> str:
    """
    Summary:
        Map one byte to its ASCII display character — the byte's own character
        when printable, the ``.`` placeholder otherwise (LLR-003.2).

    Args:
        byte_value (int): A single byte value in the range 0-255.

    Returns:
        str: A one-character string — ``chr(byte_value)`` when the byte is in
            the printable ASCII range 0x20-0x7E, otherwise ``ASCII_PLACEHOLDER``
            (``.``). Always exactly one character, so the ASCII form keeps
            one-character-per-byte alignment with the hex form.

    Data Flow:
        - Test the byte against the inclusive printable bounds.
        - Return its own character, or the fixed placeholder.

    Dependencies:
        Used by:
            - format_memory_value
    """
    if PRINTABLE_ASCII_MIN <= byte_value <= PRINTABLE_ASCII_MAX:
        return chr(byte_value)
    return ASCII_PLACEHOLDER
