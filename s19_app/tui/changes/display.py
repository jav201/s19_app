"""
Change-entry value display — s19_app batch-07, increment E3b (F-Q-09).

A :class:`~s19_app.tui.changes.model.ChangeEntry` stores its resolved target
value as a raw run of bytes (``encoded_bytes``, an immutable
``tuple[int, ...]``). This module derives the *display* forms of that run —
the text the Patch Editor shows the engineer — without ever mutating the
stored bytes. Three forms are produced from the one stored run:

- **hex** — the primary form: each byte as a two-digit uppercase hexadecimal
  token, space-separated (``01 AB FF``).
- **ascii** — a companion form: each byte in the printable ASCII range
  0x20-0x7E shown as its character, every other byte shown as the single fixed
  placeholder ``.`` (the period, byte 0x2E), so the ASCII string keeps
  one-character-per-byte positional alignment with the hex form.
- **decimal** — a companion form: each byte as its decimal value,
  space-separated (``65 66``).

Migrated verbatim from ``cdfx/memory_display.py`` (batch-04 LLR-003.1/.2/.3),
public names preserved — the declared destination of the 12 SURVIVES rows of
``tests/test_memory_display.py`` (batch-07 LLR-003.3 / §6.2 C-4).

The module is **pure**: no XML, no JSON, no Textual, no file I/O. It imports
stdlib only and reads the byte run strictly by iteration, so a render call can
never alter the entry's stored bytes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

# The single fixed placeholder for a byte outside the printable ASCII range.
# Pinned to "." (the period, byte 0x2E) — the conventional hex-dump
# placeholder — so two implementations cannot disagree.
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
        The three display forms of a change entry's stored byte run.

    A render result bundles all three forms of one ``encoded_bytes`` run so
    the Patch Editor can show the primary hex form and the ASCII / decimal
    companions from a single :func:`format_memory_value` call. The forms are
    positionally aligned: form for form, the *n*-th hex token, the *n*-th ASCII
    character and the *n*-th decimal token all describe the same byte.

    Attributes:
        hex (str): Space-separated two-digit uppercase hexadecimal tokens, one
            per byte — the primary form. Empty string for an empty run (a run
            an empty ``ChangeEntry`` cannot hold — see the note in
            :func:`format_memory_value`).
        ascii (str): One character per byte — the byte's character when it is
            in the printable range 0x20-0x7E, the ``.`` placeholder otherwise.
            Length equals the byte count.
        decimal (str): Space-separated decimal byte values, one per byte.

    The dataclass is ``frozen`` — a rendering is a read-only derived view; it
    carries no reference to the source ``encoded_bytes`` tuple, so holding it
    can never mutate the entry.
    """

    hex: str
    ascii: str
    decimal: str


def format_memory_value(new_bytes: Sequence[int]) -> MemoryValueRendering:
    """
    Summary:
        Render a change entry's stored byte run as its hex, ASCII and decimal
        display forms, without mutating the stored bytes.

    Args:
        new_bytes (Sequence[int]): The entry's stored byte run — an ordered
            sequence of integer byte values, each in the range 0-255
            (typically the ``tuple[int, ...]`` held by
            ``ChangeEntry.encoded_bytes``). Read by iteration only; never
            mutated.

    Returns:
        MemoryValueRendering: The three positionally-aligned display forms —
            ``hex`` (primary), ``ascii`` and ``decimal``. For a single byte
            ``0x41`` the result is ``hex="41"``, ``ascii="A"``, ``decimal="65"``.

    Raises:
        None: Formatting never raises. ``ChangeEntry.__post_init__`` already
            rejects a negative byte, a byte above 255 or an empty run at
            construction, so a byte run reaching this function is well-formed;
            an empty sequence still renders as three empty strings rather than
            raising.

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
            - The Patch Editor panel (via ``services/change_service.py`` row
              building) to render a change-entry row's value in hex, with
              ASCII / decimal companions.

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
        when printable, the ``.`` placeholder otherwise.

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
