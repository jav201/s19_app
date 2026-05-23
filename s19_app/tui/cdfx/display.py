"""
Type-driven value display formatting for the CDFX change-list — s19_app
batch-03, increment 3.

The change-list stores each parameter's **physical** value verbatim (the
storage contract of LLR-003.3 / increment 1). This module derives the *display*
form of that value — the text the Patch Editor shows the engineer — without
ever mutating the stored value. The display form is chosen from the resolved
A2L type of the parameter so values read naturally: unsigned integers show
decimal with a hexadecimal companion, signed integers show a signed decimal,
IEEE floats show a fractional decimal, and ASCII/string parameters show a
quoted string.

The resolved A2L type is **not** a field on the entry — the increment-1 model
has no slot for it. It is carried alongside the change-list in the increment-2
:class:`~s19_app.tui.cdfx.resolve.ResolutionResult` and looked up per entry via
``ResolutionResult.type_for``. :func:`format_value` therefore takes the
``ResolvedType`` (or ``None``) explicitly rather than reading a non-existent
attribute.

Three Phase-2 findings shape the selection rules:

- **A-02** — A2L ``ASCII`` is a ``char_type`` (a characteristic-kind token),
  not a numeric ``datatype`` token; the quoted-string form is therefore
  selected from ``char_type``, not ``datatype``.
- **A-03** — the hexadecimal companion is well-defined only when the physical
  value is **integral**. The change-list stores the physical value, and a
  non-IDENTICAL ``COMPU_METHOD`` produces a fractional physical value where
  ``hex()`` has no meaning; such a value renders decimal-only.
- **Q-10** — a large ``A_UINT64`` above ``2**53`` loses integer exactness if
  routed through a binary64 ``float``. Integer values are kept as Python
  ``int`` end-to-end so an arbitrarily large unsigned value renders exactly.

This module is pure: no XML, no Textual, no file I/O.

Implements LLR-003.1 and LLR-003.2; completes the display half of LLR-003.3.
"""

from __future__ import annotations

from .changelist import ChangeListEntry, PhysicalValue
from .resolve import ResolvedType

# A2L numeric data-type tokens grouped by the display form they select. The
# float set is informational — the float branch is reached as the final
# numeric arm — but is kept explicit so the (char_type, datatype) selection
# table is readable in one place (LLR-003.1).
UNSIGNED_INT_DATATYPES: frozenset[str] = frozenset(
    {"UBYTE", "UWORD", "ULONG", "A_UINT64"}
)
SIGNED_INT_DATATYPES: frozenset[str] = frozenset(
    {"SBYTE", "SWORD", "SLONG", "A_INT64"}
)
IEEE_FLOAT_DATATYPES: frozenset[str] = frozenset(
    {"FLOAT16_IEEE", "FLOAT32_IEEE", "FLOAT64_IEEE"}
)

# The A2L characteristic-kind token that selects the quoted-string form. ASCII
# is a char_type, never a datatype (finding A-02).
ASCII_CHAR_TYPE = "ASCII"


def format_value(
    entry: ChangeListEntry,
    resolved_type: ResolvedType | None,
) -> str:
    """
    Summary:
        Render a change-list entry's stored physical value as the display text
        best suited to the parameter's resolved A2L type.

    Args:
        entry (ChangeListEntry): The change-list entry whose ``value`` is
            rendered. The value is read, never mutated (LLR-003.3).
        resolved_type (ResolvedType | None): The entry's resolved A2L type,
            obtained from ``ResolutionResult.type_for(entry)``. ``None`` means
            the entry did not resolve against an A2L — the display falls back
            to plain decimal (LLR-003.2).

    Returns:
        str: The display form of the value:
            - ``ASCII`` ``char_type`` → the value quoted (``"REV_C"``).
            - unsigned-integer ``datatype`` → decimal, with a ``0x`` companion
              appended **only when the value is integral** (``23 / 0x17``).
            - signed-integer ``datatype`` → signed decimal (``-5``).
            - IEEE-float ``datatype`` → fractional decimal (``12.5``).
            - unresolved entry or unknown ``datatype`` → plain decimal text.
        An entry whose value is ``None`` renders as the empty string.

    Raises:
        None: Formatting never raises; an unresolved or unknown type falls
            back to plain decimal text (LLR-003.2 "shall not raise").

    Data Flow:
        - A ``None`` value short-circuits to the empty string.
        - When ``resolved_type`` is ``None`` (unresolved entry), fall back to
          plain decimal (LLR-003.2).
        - An ``ASCII`` ``char_type`` selects the quoted-string form, ahead of
          any ``datatype`` check (finding A-02).
        - Otherwise the ``datatype`` token selects unsigned / signed / float;
          an unrecognized token falls back to plain decimal.

    Dependencies:
        Uses:
            - _format_unsigned
            - _hex_companion
        Used by:
            - The Patch Editor screen (increment 7) to render each row's value.

    Example:
        >>> from s19_app.tui.cdfx.changelist import ChangeListEntry
        >>> from s19_app.tui.cdfx.resolve import ResolvedType
        >>> e = ChangeListEntry("IGN_ADVANCE_BASE", 0, 23)
        >>> format_value(e, ResolvedType("VALUE", "UBYTE", 1))
        '23 / 0x17'
        >>> format_value(e, None)
        '23'
    """
    value = entry.value
    if value is None:
        return ""

    if resolved_type is None:
        return _plain_decimal(value)

    if resolved_type.char_type == ASCII_CHAR_TYPE:
        return f'"{value}"'

    datatype = resolved_type.datatype
    if datatype in UNSIGNED_INT_DATATYPES:
        return _format_unsigned(value)
    if datatype in SIGNED_INT_DATATYPES:
        return _format_signed(value)
    if datatype in IEEE_FLOAT_DATATYPES:
        return _format_float(value)

    # Resolved, but no recognized numeric datatype token — same safe fallback
    # as an unresolved entry (LLR-003.2).
    return _plain_decimal(value)


def _format_unsigned(value: PhysicalValue) -> str:
    """
    Summary:
        Render an unsigned-integer parameter's value as decimal, appending a
        hexadecimal companion only when the physical value is integral.

    Args:
        value (PhysicalValue): The stored physical value — an ``int`` for an
            IDENTICAL conversion, or a ``float`` when a non-IDENTICAL
            ``COMPU_METHOD`` produced a fractional physical value.

    Returns:
        str: ``"<decimal> / 0x<HEX>"`` when the value is integral (finding
            A-03), otherwise the decimal text alone — ``hex()`` of a fractional
            physical value is meaningless, so no companion is shown.

    Data Flow:
        - Compute the decimal text.
        - Ask :func:`_hex_companion` for the ``0x`` form; it returns ``None``
          for a fractional value, which suppresses the companion.

    Dependencies:
        Uses:
            - _hex_companion
        Used by:
            - format_value
    """
    decimal = _plain_decimal(value)
    companion = _hex_companion(value)
    if companion is None:
        return decimal
    return f"{decimal} / {companion}"


def _hex_companion(value: PhysicalValue) -> str | None:
    """
    Summary:
        Produce the ``0x`` hexadecimal companion for an integral physical
        value, or ``None`` when the value is fractional (finding A-03).

    Args:
        value (PhysicalValue): The stored physical value. An ``int`` is always
            integral; a ``float`` is integral only when it has no fractional
            part. A large ``A_UINT64`` above ``2**53`` arrives here as an
            ``int`` and is never routed through ``float`` (finding Q-10), so
            its hex text is exact.

    Returns:
        str | None: The lowercase ``0x``-prefixed hexadecimal text for an
            integral value (``hex()`` of the exact integer), or ``None`` when
            the value is fractional and therefore has no meaningful hex form.

    Data Flow:
        - An ``int`` value uses ``hex()`` directly — exact at any magnitude.
        - A ``float`` that ``is_integer()`` is converted with ``int()`` (exact,
          since it has no fractional part) before ``hex()``.
        - Any other value (a fractional ``float``) yields ``None``.

    Dependencies:
        Used by:
            - _format_unsigned
    """
    if isinstance(value, bool):
        # bool is an int subclass; treat it as the integer it is.
        return hex(int(value))
    if isinstance(value, int):
        return hex(value)
    if isinstance(value, float) and value.is_integer():
        return hex(int(value))
    return None


def _format_signed(value: PhysicalValue) -> str:
    """
    Summary:
        Render a signed-integer parameter's value as signed decimal.

    Args:
        value (PhysicalValue): The stored physical value.

    Returns:
        str: The decimal text; a negative value carries its leading ``-`` sign
            from Python's native ``str`` of the number. No hexadecimal
            companion is shown for signed types (research §6).

    Dependencies:
        Uses:
            - _plain_decimal
        Used by:
            - format_value
    """
    return _plain_decimal(value)


def _format_float(value: PhysicalValue) -> str:
    """
    Summary:
        Render an IEEE-float parameter's value as a fractional decimal.

    Args:
        value (PhysicalValue): The stored physical value — expected to be a
            ``float`` for an IEEE-float parameter, but an ``int`` stored
            against a float type is rendered with a fractional part too so the
            float nature of the parameter stays visible.

    Returns:
        str: The decimal text. An integer-valued float renders with a trailing
            ``.0`` (Python ``float`` ``str`` behaviour) so the value reads as a
            float, not an integer.

    Data Flow:
        - Coerce the value to ``float`` so an ``int`` stored against a float
          parameter still renders fractionally.
        - Use Python's ``str(float)`` — the shortest round-trip-faithful text.

    Dependencies:
        Used by:
            - format_value
    """
    return str(float(value))


def _plain_decimal(value: PhysicalValue) -> str:
    """
    Summary:
        Render any physical value as plain decimal text — the unresolved /
        unknown-type fallback (LLR-003.2).

    Args:
        value (PhysicalValue): The stored physical value — ``int``, ``float``
            or ``str``. ``None`` is handled by the caller and never reaches
            here.

    Returns:
        str: ``str(value)`` — the value's native text. For an ``int`` this is
            an exact decimal at any magnitude; for a ``str`` it is the string
            unchanged (an unresolved entry is rendered without quoting).

    Dependencies:
        Used by:
            - format_value
            - _format_unsigned
            - _format_signed
    """
    return str(value)
