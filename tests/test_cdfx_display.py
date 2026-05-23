"""
CDFX type-driven value-display tests — s19_app batch-03, increment 3.

Covers ``s19_app/tui/cdfx/display.py`` — :func:`format_value`, which derives
the Patch Editor's display text for a change-list entry from the entry's
resolved A2L type:

  - TC-008 — type-driven display-format selection (LLR-003.1), including the
             ``FLOAT16_IEEE`` and large-``A_UINT64`` (> 2**53) boundary cases
             added per Phase-2 finding Q-10, and the integral-hex condition
             of finding A-03.
  - TC-009 — display-format fallback for unresolved entries (LLR-003.2).
  - TC-010 — physical value stored, display derived (LLR-003.3, display arm):
             rendering reads the stored value and never mutates it.

The resolved A2L type is not a field on the entry — the increment-1 model has
no slot for it. It is carried in the increment-2 ``ResolutionResult`` and
passed to ``format_value`` as a ``ResolvedType`` (or ``None``). These tests
construct ``ResolvedType`` directly: the resolver's own behaviour is covered by
``tests/test_cdfx_resolve.py``, so the display tests need only the type pair
``(char_type, datatype)`` that drives the selection.
"""

from __future__ import annotations

from s19_app.tui.cdfx import ChangeList, ChangeListEntry, ResolutionStatus
from s19_app.tui.cdfx.display import format_value
from s19_app.tui.cdfx.resolve import ResolvedType


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _entry(value: object) -> ChangeListEntry:
    """
    Summary:
        Build a single resolved change-list entry carrying ``value`` — a
        terse fixture for the display tests.

    Args:
        value (object): The physical value to store on the entry.

    Returns:
        ChangeListEntry: An entry named ``P`` at index 0 with ``value`` stored
        and status ``RESOLVED``.

    Dependencies:
        Used by:
            - The TC-008 / TC-009 / TC-010 display tests.
    """
    return ChangeListEntry(
        parameter_name="P",
        array_index=0,
        value=value,
        status=ResolutionStatus.RESOLVED,
    )


# ---------------------------------------------------------------------------
# TC-008 — type-driven display-format selection (LLR-003.1)
# ---------------------------------------------------------------------------


def test_tc008_unsigned_integral_value_shows_decimal_and_hex() -> None:
    """A ``UBYTE`` value 23 (IDENTICAL conversion) renders as ``23 / 0x17``.

    LLR-003.1 acceptance: an unsigned-integer parameter renders decimal with a
    hexadecimal companion when the physical value is integral. ``23`` is
    ``0x17`` — the test pins both the decimal and the hex form so a regression
    that dropped or mis-cased the companion fails.
    """
    rendered = format_value(_entry(23), ResolvedType("VALUE", "UBYTE", 1))

    assert rendered == "23 / 0x17"


def test_tc008_unsigned_fractional_value_shows_decimal_only() -> None:
    """A non-IDENTICAL unsigned parameter with a fractional physical value
    renders decimal only — no hexadecimal companion (finding A-03).

    The change-list stores the *physical* value; a non-IDENTICAL
    ``COMPU_METHOD`` produces a fractional physical value where ``hex()`` is
    meaningless. LLR-003.1's integral-hex condition forbids a companion here —
    a writer that always appended ``0x...`` would fail this test.
    """
    rendered = format_value(_entry(2.5), ResolvedType("VALUE", "UWORD", 1))

    assert rendered == "2.5"
    assert "0x" not in rendered


def test_tc008_large_a_uint64_above_2_53_renders_exact_decimal_and_hex() -> None:
    """A large ``A_UINT64`` near ``2**64-1`` renders exact decimal + hex (Q-10).

    Phase-2 finding Q-10: an unsigned value above ``2**53`` loses integer
    exactness if routed through a binary64 ``float``. ``2**64 - 1`` is integral
    and must render as its *exact* decimal and hexadecimal text. If
    ``format_value`` coerced the value through ``float`` the low bits would be
    lost and neither string below would match — this is the boundary case the
    requirement Q-10 demands.
    """
    big = 2**64 - 1  # 18446744073709551615 — well above 2**53

    rendered = format_value(_entry(big), ResolvedType("VALUE", "A_UINT64", 1))

    assert rendered == "18446744073709551615 / 0xffffffffffffffff"
    # The exact-integer arms — proof the value never round-tripped through float.
    assert str(big) in rendered
    assert hex(big) in rendered


def test_tc008_negative_signed_value_renders_with_leading_sign() -> None:
    """A negative ``SWORD`` renders as signed decimal with a leading ``-``.

    LLR-003.1 acceptance: signed-integer types render as signed decimal. The
    sign must be visible, and no hexadecimal companion is shown for a signed
    type (research §6) — both are asserted.
    """
    rendered = format_value(_entry(-1234), ResolvedType("VALUE", "SWORD", 1))

    assert rendered == "-1234"
    assert "0x" not in rendered


def test_tc008_positive_signed_value_renders_plain_decimal() -> None:
    """A positive signed value renders as plain decimal, no hex companion.

    Signed types never carry a hexadecimal companion regardless of sign; a
    positive ``SLONG`` is the companion case to the negative ``SWORD`` test.
    """
    rendered = format_value(_entry(77), ResolvedType("VALUE", "SLONG", 1))

    assert rendered == "77"
    assert "0x" not in rendered


def test_tc008_float32_value_renders_with_fractional_part() -> None:
    """A ``FLOAT32_IEEE`` value renders with a fractional part (``12.5``).

    LLR-003.1 acceptance: IEEE-float types render as fractional decimal so the
    engineer sees the value is a float, not an integer.
    """
    rendered = format_value(_entry(12.5), ResolvedType("VALUE", "FLOAT32_IEEE", 1))

    assert rendered == "12.5"


def test_tc008_float16_value_renders_with_fractional_part() -> None:
    """A ``FLOAT16_IEEE`` value renders fractionally — the Q-10 float boundary.

    Phase-2 finding Q-10: TC-008 originally exercised only ``FLOAT32_IEEE``.
    ``FLOAT16_IEEE`` is an IEEE-float ``datatype`` token and must route to the
    same fractional-decimal branch; this test pins that the float set covers
    all three IEEE tokens, not just the 32-bit one.
    """
    rendered = format_value(_entry(0.5), ResolvedType("VALUE", "FLOAT16_IEEE", 1))

    assert rendered == "0.5"


def test_tc008_float64_integral_value_still_renders_as_float() -> None:
    """An integer-valued ``FLOAT64_IEEE`` renders with a ``.0`` fractional tail.

    A float parameter whose physical value happens to be whole must still read
    as a float (``3.0``), not as a bare integer ``3`` — otherwise the engineer
    cannot tell a float parameter from an integer one.
    """
    rendered = format_value(_entry(3.0), ResolvedType("VALUE", "FLOAT64_IEEE", 1))

    assert rendered == "3.0"


def test_tc008_ascii_char_type_renders_as_quoted_string() -> None:
    """An ``ASCII``-``char_type`` parameter renders as a quoted string (A-02).

    Phase-2 finding A-02: ``ASCII`` is an A2L ``char_type``, not a ``datatype``
    token — there is no ``ASCII`` ``datatype``. The quoted-string form is
    therefore selected from ``char_type``; ``datatype`` here is irrelevant and
    deliberately set to ``UBYTE`` (an ASCII string is a ``UBYTE`` array) to
    prove the ASCII branch wins over the numeric branch.
    """
    rendered = format_value(_entry("REV_C"), ResolvedType("ASCII", "UBYTE", 8))

    assert rendered == '"REV_C"'


def test_tc008_ascii_branch_precedes_datatype_branch() -> None:
    """The ``ASCII`` ``char_type`` is checked before the ``datatype`` token.

    Even when ``datatype`` is a recognized unsigned token, an ``ASCII``
    ``char_type`` must select the quoted-string form — encoding the A-02
    selection order (``char_type`` first, then ``datatype``) so a reordering
    that consulted ``datatype`` first would fail.
    """
    rendered = format_value(_entry("8"), ResolvedType("ASCII", "ULONG", 1))

    assert rendered == '"8"'  # quoted string, NOT decimal+hex of 8


# ---------------------------------------------------------------------------
# TC-009 — display-format fallback for unresolved entries (LLR-003.2)
# ---------------------------------------------------------------------------


def test_tc009_unresolved_entry_value_renders_plain_decimal() -> None:
    """An unresolved entry's value renders as plain decimal text, no exception.

    LLR-003.2: while an entry is unresolved (no A2L data type available) the
    value renders as plain decimal. ``resolved_type=None`` is how
    ``ResolutionResult.type_for`` reports an unresolved entry.
    """
    entry = ChangeListEntry(
        parameter_name="MYSTERY",
        array_index=0,
        value=42,
        status=ResolutionStatus.UNRESOLVED,
    )

    rendered = format_value(entry, None)

    assert rendered == "42"
    assert "0x" not in rendered  # no type → no type-driven hex companion


def test_tc009_unresolved_float_value_renders_without_error() -> None:
    """An unresolved float value renders without raising (LLR-003.2).

    The fallback must not raise on any value kind; a float with no resolved
    type renders as its plain decimal text.
    """
    entry = ChangeListEntry(
        parameter_name="X",
        value=3.14,
        status=ResolutionStatus.UNRESOLVED_NO_A2L,
    )

    assert format_value(entry, None) == "3.14"


def test_tc009_resolved_but_unknown_datatype_falls_back_to_decimal() -> None:
    """A resolved entry with an unrecognized ``datatype`` token falls back.

    Resolution can return a type whose ``datatype`` is ``None`` (a bare tag) or
    a token outside the known unsigned/signed/float sets. The display must not
    raise — it falls back to plain decimal, the same safe path as LLR-003.2.
    """
    assert format_value(_entry(9), ResolvedType("VALUE", None, 1)) == "9"
    assert format_value(_entry(9), ResolvedType("VALUE", "WEIRD", 1)) == "9"


def test_tc009_unset_value_renders_as_empty_string() -> None:
    """An entry whose value is ``None`` renders as the empty string, no crash.

    An entry can exist before a value is typed (``ChangeList.add`` with no
    value). Formatting it must not raise; the empty string is the natural
    "nothing entered yet" display.
    """
    entry = ChangeListEntry(parameter_name="EMPTY", status=ResolutionStatus.RESOLVED)

    assert format_value(entry, None) == ""
    assert format_value(entry, ResolvedType("VALUE", "UBYTE", 1)) == ""


# ---------------------------------------------------------------------------
# TC-010 — physical value stored, display derived (LLR-003.3, display arm)
# ---------------------------------------------------------------------------


def test_tc010_formatting_does_not_mutate_the_stored_value() -> None:
    """Rendering the display form leaves the entry's stored value unchanged.

    LLR-003.3: the change-list stores the *physical* value; hex/ASCII rendering
    is derived for display only and "shall not alter the stored value". This
    test renders an entry several ways and asserts ``entry.value`` is the
    untouched physical value afterwards — the display-derivation invariant.
    """
    cl = ChangeList()
    cl.add("IGN_ADVANCE_BASE", 0, 23, ResolutionStatus.RESOLVED)
    entry = cl.get("IGN_ADVANCE_BASE", 0)

    # Render through several type branches.
    format_value(entry, ResolvedType("VALUE", "UBYTE", 1))
    format_value(entry, ResolvedType("VALUE", "SWORD", 1))
    format_value(entry, None)

    assert entry.value == 23  # stored physical value untouched
    assert isinstance(entry.value, int)  # not coerced to float / str


def test_tc010_hex_companion_is_derived_not_stored() -> None:
    """The hexadecimal companion is a display artifact, never the stored value.

    The stored value stays the decimal integer ``255``; the display form
    ``255 / 0xff`` is derived. Asserting the stored value is still ``255`` (not
    the string ``"0xff"``) pins that the hex form is rendering-only.
    """
    entry = _entry(255)

    rendered = format_value(entry, ResolvedType("VALUE", "UWORD", 1))

    assert rendered == "255 / 0xff"
    assert entry.value == 255  # stored value is the physical int, not the hex text


def test_tc010_string_value_stored_verbatim_quoted_only_for_display() -> None:
    """An ASCII value is stored unquoted; the quotes are added for display only.

    The change-list stores ``REV_C``; the display form is ``"REV_C"``. The
    quotes belong to the rendered text, not the stored value — a regression
    that stored the quoted form would fail the stored-value assertion.
    """
    entry = _entry("REV_C")

    rendered = format_value(entry, ResolvedType("ASCII", "UBYTE", 8))

    assert rendered == '"REV_C"'
    assert entry.value == "REV_C"  # stored value carries no quotes
