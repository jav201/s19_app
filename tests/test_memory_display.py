"""
Memory-field change value display tests — s19_app batch-04, increment 3.

Covers the pure display layer (``s19_app/tui/cdfx/memory_display.py``):

  - TC-009 — hex display of the stored bytes (LLR-003.1): a byte run renders
             as space-separated two-digit uppercase hexadecimal tokens.
  - TC-010 — ASCII and decimal companion renderings (LLR-003.2): a printable
             run renders its ASCII characters and its decimal values; a
             non-printable byte renders as the *exact* placeholder character
             ``.`` (the period, byte 0x2E) pinned in LLR-003.2 — the CV-01
             closure clause asserts that exact character.
  - TC-011 — display derivation does not mutate stored bytes (LLR-003.3): an
             entry's stored ``new_bytes`` is byte-identical before and after
             every hex / ASCII / decimal rendering call.

These tests encode WHY each behaviour matters. The hex form is the primary
representation an engineer reads raw memory in, so its exact spelling (uppercase,
two-digit, space-separated) is contract, not cosmetics. The ASCII placeholder is
pinned to one character so two implementations cannot both pass while disagreeing
(LLR-003.2 rationale); TC-010 therefore asserts the literal ``.``. The
no-mutation guarantee is what lets the Patch Editor render a row repeatedly
without ever corrupting the stored edit intent; TC-011 fails the moment a render
path writes back to ``new_bytes``.
"""

from __future__ import annotations

from s19_app.tui.cdfx import (
    MemoryChange,
    MemoryValueRendering,
    format_memory_value,
)
from s19_app.tui.cdfx.memory_display import ASCII_PLACEHOLDER


# ---------------------------------------------------------------------------
# TC-009 — hex display of the stored bytes (LLR-003.1)
# ---------------------------------------------------------------------------


def test_tc009_hex_render_is_uppercase_two_digit_space_separated() -> None:
    """Bytes ``[0x01,0xAB,0xFF]`` render as ``01 AB FF`` (LLR-003.1).

    The acceptance criterion pins the exact spelling: two-digit, uppercase,
    single-space-separated. A lowercase, un-padded, or comma-joined regression
    fails this assertion.
    """
    rendering = format_memory_value([0x01, 0xAB, 0xFF])

    assert rendering.hex == "01 AB FF"


def test_tc009_hex_render_pads_small_bytes_to_two_digits() -> None:
    """A byte below 0x10 still renders as two digits (LLR-003.1).

    LLR-003.1 says "two-digit"; ``0x00`` and ``0x05`` must be ``00`` and ``05``,
    not ``0`` and ``5``, or the hex form would lose positional alignment with
    the ASCII and decimal companions.
    """
    rendering = format_memory_value([0x00, 0x05, 0x0F])

    assert rendering.hex == "00 05 0F"


def test_tc009_hex_render_of_a_single_byte_has_no_separator() -> None:
    """A one-byte run renders as a single token, no trailing space (LLR-003.1).

    The space is a *separator*, not a terminator; a single byte must produce
    exactly two characters so the form is stable for the common one-byte edit.
    """
    rendering = format_memory_value([0x7F])

    assert rendering.hex == "7F"


# ---------------------------------------------------------------------------
# TC-010 — ASCII and decimal companion renderings (LLR-003.2)
# ---------------------------------------------------------------------------


def test_tc010_printable_run_renders_ascii_characters() -> None:
    """Bytes ``[0x41,0x42]`` render ASCII ``AB`` (LLR-003.2 acceptance).

    Every byte of this run is in the printable range 0x20-0x7E, so the ASCII
    form is the run decoded as characters with no placeholder substitution.
    """
    rendering = format_memory_value([0x41, 0x42])

    assert rendering.ascii == "AB"


def test_tc010_printable_run_renders_decimal_values() -> None:
    """Bytes ``[0x41,0x42]`` render decimal ``65 66`` (LLR-003.2 acceptance).

    The decimal companion is the plain numeric view: space-separated decimal
    byte values, one per byte.
    """
    rendering = format_memory_value([0x41, 0x42])

    assert rendering.decimal == "65 66"


def test_tc010_non_printable_byte_renders_as_the_exact_dot_placeholder() -> None:
    """A non-printable byte renders as the exact ``.`` placeholder (CV-01).

    LLR-003.2 pins the placeholder to one fixed character — ``.``, the period,
    byte 0x2E — so two implementations cannot disagree and both pass. This
    asserts that *exact* character literally (the CV-01 closure clause), not
    merely "some placeholder". ``0x00`` (NUL) and ``0xFF`` are both outside the
    printable range 0x20-0x7E.
    """
    rendering = format_memory_value([0x00, 0x41, 0xFF])

    # The exact pinned character — period, byte 0x2E.
    assert rendering.ascii == ".A."
    assert rendering.ascii[0] == "."
    assert rendering.ascii[0] == "\x2e"
    assert ord(rendering.ascii[0]) == 0x2E
    assert rendering.ascii[2] == ASCII_PLACEHOLDER


def test_tc010_ascii_keeps_one_character_per_byte_alignment() -> None:
    """The ASCII form is exactly one character per byte (LLR-003.2 rationale).

    A non-printable byte is substituted, never dropped, so the ASCII string
    stays positionally aligned with the hex form — the *n*-th ASCII character
    describes the same byte as the *n*-th hex token.
    """
    run = [0x09, 0x41, 0x42, 0x7F, 0x20]
    rendering = format_memory_value(run)

    assert len(rendering.ascii) == len(run)
    # Tab (0x09) and DEL (0x7F) are non-printable; 'A' 'B' and space print.
    assert rendering.ascii == ".AB. "


def test_tc010_printable_range_boundaries_render_as_characters() -> None:
    """The boundary bytes 0x20 and 0x7E are printable (LLR-003.2 bounds).

    LLR-003.2 fixes the printable range *inclusively* at 0x20-0x7E. Space
    (0x20) and tilde (0x7E) are the endpoints and must render as their own
    characters, while 0x1F and 0x7F just outside fall to the placeholder.
    """
    inside = format_memory_value([0x20, 0x7E])
    outside = format_memory_value([0x1F, 0x7F])

    assert inside.ascii == " ~"
    assert outside.ascii == ".."


def test_tc010_returns_a_memory_value_rendering_with_all_three_forms() -> None:
    """``format_memory_value`` returns the three-form bundle (LLR-003.1/.2).

    The single entry point produces hex, ASCII and decimal together so the
    Patch Editor renders a row's value and its companions from one call.
    """
    rendering = format_memory_value([0x48, 0x69])

    assert isinstance(rendering, MemoryValueRendering)
    assert rendering.hex == "48 69"
    assert rendering.ascii == "Hi"
    assert rendering.decimal == "72 105"


# ---------------------------------------------------------------------------
# TC-011 — display derivation does not mutate stored bytes (LLR-003.3)
# ---------------------------------------------------------------------------


def test_tc011_stored_bytes_unchanged_after_rendering() -> None:
    """An entry's ``new_bytes`` is byte-identical after rendering (LLR-003.3).

    The stored bytes are the source of truth for serialization and export; a
    render call must derive its display strings without writing back. This
    snapshots the run, renders all three forms, and asserts the stored tuple is
    unchanged — identity and value both.
    """
    entry = MemoryChange(address=0x100, new_bytes=[0x41, 0x00, 0xFF])
    before = entry.new_bytes

    rendering = format_memory_value(entry.new_bytes)

    assert entry.new_bytes == (0x41, 0x00, 0xFF)
    assert entry.new_bytes is before
    # The rendering is genuinely derived, not a no-op.
    assert rendering.hex == "41 00 FF"


def test_tc011_repeated_rendering_is_stable_and_non_mutating() -> None:
    """Rendering the same entry twice yields identical output (LLR-003.3).

    If a render call mutated the stored bytes, a second call would observe a
    changed run and produce different text. Identical output across two calls,
    plus an unchanged stored run, pins the no-side-effect contract.
    """
    entry = MemoryChange(address=0x200, new_bytes=[0x10, 0x7E, 0x80])

    first = format_memory_value(entry.new_bytes)
    second = format_memory_value(entry.new_bytes)

    assert first == second
    assert entry.new_bytes == (0x10, 0x7E, 0x80)


def test_tc011_rendering_does_not_mutate_a_caller_supplied_list() -> None:
    """A mutable ``list`` argument is not modified by rendering (LLR-003.3).

    ``format_memory_value`` accepts any byte sequence; passing a plain ``list``
    must not see it mutated, so a caller can reuse the list afterwards.
    """
    run = [0x01, 0x9A, 0x2E]

    format_memory_value(run)

    assert run == [0x01, 0x9A, 0x2E]
