"""The A2L definition model (Incs 2a, 2b and 3a).

This module builds *definitions* of scalar objects, VAL_BLK and MATRIX_DIM
arrays, curves and maps from the parse payload of
:func:`s19_app.tui.a2l.parse_a2l_file`. It decodes stored scalars, elements and
axis points into values and display texts, formats numbers for display, and
encodes an operator's text into the bytes of the object's whole span
(``describe`` / ``decode`` / ``display`` / ``encode`` of interface I-2), with
the cross-kind span index and the overlap guard of R-A2L-DEF.138.

The module is pure: standard library plus ``s19_app.tui.a2l`` only, no
``textual`` import, no file or clipboard I/O, no global mutable state, and it
never raises on file or image content — every failure is a :class:`Refusal`
value.  It reads ``a2l_data`` and the image and writes neither.
"""

from __future__ import annotations

import heapq
import math
import re
import struct
from bisect import bisect_left
from dataclasses import dataclass, field, replace
from decimal import Decimal
from types import MappingProxyType
from typing import Callable, Iterable, Mapping, Optional

from .a2l import (
    DATATYPE_SIZES,
    MAX_A2L_DECODE_BYTES,
    _apply_compu_method,
    _byte_order_from_section_lines,
    _decode_scalar,
    _flatten_body_tokens,
    _resolve_record_layout,
    _split_line_respecting_quotes,
    _strip_a2l_comments,
    _to_float,
    _walk_record_layout_components,
    encode_physical_to_raw_bytes,
    parse_begin_meta,
)


@dataclass(frozen=True)
class Refusal:
    """A code and a message the system gives in place of an edit, a decoded
    value or the bytes of an encoded value."""

    code: str
    message: str


@dataclass(frozen=True)
class Limits:
    """Two limit bounds, each with the word the file wrote for it.

    ``*_text`` is the file's word when ``_to_float`` read that side as a
    finite number, else ``""`` (so a message composes ``<lower>..<upper>``
    from the two directly).
    """

    lower: Optional[float]
    upper: Optional[float]
    lower_text: str
    upper_text: str


@dataclass(frozen=True)
class EnumEntry:
    """One enum table entry.

    ``raw`` is the pair's raw or the triple's min; ``raw_max`` is the triple's
    max, or ``None`` for a COMPU_VTAB pair; ``text`` is kept as the file writes
    it (never converted to a number).
    """

    raw: float
    raw_max: Optional[float]
    text: str


@dataclass(frozen=True)
class _EnumForm:
    """The enum table's reduced form (R-A2L-DEF.150): the public entries, the
    once-cleaned display texts and the private one-lookup index, built once per
    walk and shared by reference.  COMPU_VTAB holds ``first_of``; a
    COMPU_VTAB_RANGE holds ``ends`` / ``at_end`` / ``between``."""

    section_kind: str
    entries: tuple[EnumEntry, ...]
    default_text: Optional[str]
    texts: tuple[str, ...]
    default_display: Optional[str]
    first_of: Mapping
    ends: tuple[float, ...]
    at_end: tuple[Optional[int], ...]
    between: tuple[Optional[int], ...]


@dataclass(frozen=True)
class _TabForm:
    """A COMPU_TAB's reduced form for a TAB_INTP / TAB_NOINTP method
    (R-A2L-DEF.150): the frozen parse's sorted x / y, a NaN-x verdict and the
    echoed COMPU_TAB_REF word.  Read by :func:`_table_value`."""

    xs: tuple[float, ...]
    ys: tuple[object, ...]
    x_nan: bool
    ref_echo: str


@dataclass(frozen=True)
class Definition:
    """What the system knows about how one defined object stores, converts and
    shows its value.  A definition that cannot be edited carries a
    :class:`Refusal` and every field the system could read.  Field order is
    pinned by I-2; Inc 2b inserts ``shared_with`` after ``compu_tab_ref`` and
    Inc 3 appends defaulted fields after ``refusal``."""

    name: str
    section: str
    char_type: Optional[str]
    kind: str
    address: Optional[int]
    byte_length: Optional[int]
    datatype: Optional[str]
    byte_order: str
    bit_mask: Optional[int]
    bit_mask_text: Optional[str]
    conversion_type: Optional[str]
    method_name: Optional[str]
    display_format: Optional[str]
    decimals: Optional[int]
    unit: str
    limits: Limits
    extended_limits: Optional[Limits]
    enum_table: Optional[str]
    enum_entries: tuple[EnumEntry, ...]
    default_text: Optional[str]
    coeffs_linear: Optional[tuple[Optional[float], Optional[float]]]
    coeffs: Optional[tuple[Optional[float], ...]]
    compu_tab_ref: Optional[str]
    shared_with: Optional[str]
    refusal: Optional[Refusal]
    shape: tuple[int, ...] = ()
    element_count: Optional[int] = 1
    index_mode: Optional[str] = None
    values_offset: int = 0
    record_layout: Optional[str] = None
    axes: tuple[AxisDefinition, ...] = ()
    _name_echo: Optional[str] = field(default=None, compare=False, repr=False)
    _table_form: Optional[_EnumForm | _TabForm] = field(default=None, compare=False, repr=False)


@dataclass(frozen=True)
class Decoded:
    """A decoded value: number → (stored, physical, display text); enum →
    (stored, matched entry text or None, display text); text → (None, string,
    string)."""

    stored: Optional[int | float]
    value: Optional[int | float | str]
    text: str


@dataclass(frozen=True)
class Encoded:
    """The bytes an encode would write: the whole span from ``address``
    (``data`` is ``byte_length`` bytes), with ``notices`` the at-most-one
    R-A2L-DEF.44 notice when one applies, else ``()`` (I-2)."""

    address: int
    data: bytes
    notices: tuple[str, ...]


@dataclass(frozen=True)
class AxisDefinition:
    """One AXIS_DESCR of a curve or map (I-2).

    ``points`` is the element definition of the axis points; ``offset`` /
    ``count_offset`` are byte offsets in the object's record (STD_AXIS) or the
    axis object's record (COM_AXIS), ``None`` when absent; ``fixed_rule`` holds
    the FIX_AXIS parameters, computed at decode; ``axis_object_record`` is the
    axis object's record definition (COM_AXIS).
    """

    letter: str
    axis_kind: str
    point_count: Optional[int]
    points: Definition
    point_order: Optional[str]
    offset: Optional[int]
    count_offset: Optional[int]
    fixed_count: Optional[int]
    fixed_rule: Optional[tuple[str, tuple]]
    axis_object: Optional[str]
    axis_object_address: Optional[int]
    axis_object_record: Optional[Definition]
    monotony: str
    has_points: bool
    count_datatype: Optional[str] = None


@dataclass(frozen=True)
class DecodedAxis:
    """The decoded points of one axis: ``points`` is a tuple of ``Decoded`` or
    the ``Refusal`` in its place, or ``None`` when the axis has no points
    (R-A2L-DEF.100)."""

    letter: str
    points: Optional[tuple[Decoded | Refusal, ...]]


@dataclass(frozen=True)
class DecodedValues:
    """The decoded elements and axis points of an array, curve or map (I-2)."""

    values: tuple[Decoded | Refusal, ...]
    axes: tuple[DecodedAxis, ...]


#: The float datatypes: a bit mask never applies to them and ``display_text``
#: does not take the integer short-cut for them.
_FLOAT_DATATYPES = frozenset({"FLOAT16_IEEE", "FLOAT32_IEEE", "FLOAT64_IEEE"})

#: The signed datatypes for the bit-mask sign-bit rule of R-A2L-DEF.19.
_SIGNED_DATATYPES = frozenset({"SBYTE", "SWORD", "SLONG", "A_INT64"})

#: The conversion type words the definition model supports (R-A2L-DEF.12).
_SUPPORTED_CONVERSION_TYPES = frozenset(
    {"IDENTICAL", "LINEAR", "RAT_FUNC", "TAB_INTP", "TAB_NOINTP", "TAB_VERB"}
)

_ASCII_DIGITS = frozenset("0123456789")
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")

#: The ASAM datatypes a RECORD_LAYOUT component may carry (R-A2L-DEF.86).
#: ``BYTE`` / ``WORD`` / ``LONG`` are in DATATYPE_SIZES but are not ASAM
#: datatypes, so a layout component naming them is refused.
_COMPONENT_DATATYPES = frozenset(
    {
        "UBYTE",
        "SBYTE",
        "UWORD",
        "SWORD",
        "ULONG",
        "SLONG",
        "A_UINT64",
        "A_INT64",
        "FLOAT16_IEEE",
        "FLOAT32_IEEE",
        "FLOAT64_IEEE",
    }
)

#: The count datatypes a NO_AXIS_PTS_X|Y component may carry (E3S3-01): the
#: integer ones, so the current count is always an ``int``.
_COUNT_DATATYPES = frozenset(
    {"UBYTE", "SBYTE", "UWORD", "SWORD", "ULONG", "SLONG", "A_UINT64", "A_INT64"}
)

#: The alignment class each component datatype follows (mirrors the frozen
#: ``a2l._DATATYPE_ALIGNMENT_DIRECTIVE`` for the ASAM datatypes).
_DATATYPE_ALIGNMENT_CLASS = {
    "UBYTE": "ALIGNMENT_BYTE",
    "SBYTE": "ALIGNMENT_BYTE",
    "UWORD": "ALIGNMENT_WORD",
    "SWORD": "ALIGNMENT_WORD",
    "ULONG": "ALIGNMENT_LONG",
    "SLONG": "ALIGNMENT_LONG",
    "A_UINT64": "ALIGNMENT_INT64",
    "A_INT64": "ALIGNMENT_INT64",
    "FLOAT16_IEEE": "ALIGNMENT_FLOAT16_IEEE",
    "FLOAT32_IEEE": "ALIGNMENT_FLOAT32_IEEE",
    "FLOAT64_IEEE": "ALIGNMENT_FLOAT64_IEEE",
}

#: The axis kinds the definition model reads (R-A2L-DEF.92).
_AXIS_KINDS = frozenset({"STD_AXIS", "FIX_AXIS", "COM_AXIS"})

#: The magnitude above which a FIX point cannot be computed exactly (2^53).
_FIX_MAGNITUDE_BOUND = 1 << 53

#: The largest FIX_AXIS_PAR shift the model computes exactly (R-A2L-DEF.147).
_FIX_SHIFT_BOUND = 62

#: The largest point count the model reads (R-A2L-DEF.142).
_MAX_AXIS_POINTS = 1_048_576


def _clean(text: Optional[str]) -> Optional[str]:
    """Replace every control character (U+0000-U+001F, U+007F, U+0080-U+009F)
    with U+FFFD, per R-A2L-DEF.137, in a word taken from the file or operator.

    ``None`` passes through (callers compose ``(none)`` themselves).
    """
    if text is None:
        return None
    return "".join(
        "\uFFFD"
        if ord(ch) <= 0x1F or ord(ch) == 0x7F or (0x80 <= ord(ch) <= 0x9F)
        else ch
        for ch in text
    )


#: The cap on a file word echoed into a message (R-A2L-DEF.151): its first 256
#: characters, then ``…`` when it is longer.
_ECHO_LIMIT = 256
_ELLIPSIS = "\u2026"


def _echo(word: str) -> str:
    """Write a file word into a message: its first 256 characters, each
    character outside U+0021-U+007E written as U+FFFD, and ``…`` after them
    when the word is longer (R-A2L-DEF.151)."""
    cut = len(word) > _ECHO_LIMIT
    body = word[:_ECHO_LIMIT]
    return "".join(
        ch if 0x21 <= ord(ch) <= 0x7E else "\uFFFD" for ch in body
    ) + (_ELLIPSIS if cut else "")


def _finite_number(word: object) -> Optional[float]:
    """``_to_float`` of a word when that is a finite number, else ``None``.

    A non-finite word (``nan``, ``inf``) is not a number (E3S-10).
    """
    value = _to_float(word)
    if value is None:
        return None
    return value if math.isfinite(value) else None


def _fmt_address(address: int) -> str:
    """The address placeholder: ``0x`` and upper-case hex digits, ``-0x…`` when
    negative (``0x10``, ``-0x10``, ``0xFFFFFFFF``)."""
    if address < 0:
        return f"-0x{-address:X}"
    return f"0x{address:X}"


def _number_text(number: int, address: bool = False) -> str:
    """Write a number the file holds into a message (R-A2L-DEF.151).

    A number whose magnitude is at most 2^64 - 1 is written as
    :func:`_fmt_address` when ``address`` is true, else as its decimal text.
    A larger number is written as the .151 echo of its ``0x`` / ``-0x``
    hexadecimal word (cut at 256 characters, then ``…``), so no message can
    raise on a decimal conversion of a huge int and none exceeds 1,024
    characters.

    Args:
        number (int): The number the file wrote (a length, a MATRIX_DIM or an
            address).
        address (bool): True to write an address placeholder (``0x…``) for a
            number within the bound.

    Returns:
        str: The message text for the number.

    Raises:
        None.
    """
    if number.bit_length() <= 64:
        return _fmt_address(number) if address else str(number)
    return _echo(_fmt_address(number))


def _parse_bit_mask(word: Optional[str]) -> Optional[int]:
    """Read a BIT_MASK word as ``0x`` + hex digits or decimal digits.

    ``None`` when the word is not readable or is longer than 20 decimal / 16
    hex digits (no ``int()`` on it, E3S-03, E2-12).
    """
    if word is None or not word:
        return None
    if word[:2] in ("0x", "0X"):
        digits = word[2:]
        if not 1 <= len(digits) <= 16:
            return None
        if any(ch not in "0123456789abcdefABCDEF" for ch in digits):
            return None
        return int(word, 16)
    if not 1 <= len(word) <= 20:
        return None
    if any(ch not in _ASCII_DIGITS for ch in word):
        return None
    return int(word, 10)


def _read_count(word: Optional[str]) -> Optional[int]:
    """Read an enum table count: a run of ASCII digits of at most 9 digits, else
    ``None`` (no ``int()``/``_to_float`` on it, E3S-03)."""
    if word is None or not word:
        return None
    if len(word) > 9:
        return None
    if any(ch not in _ASCII_DIGITS for ch in word):
        return None
    return int(word)


def _read_address_word(word: Optional[str]) -> Optional[int]:
    """Read an address word (CTX *address word*): an optional ``-``, then
    ``0x`` / ``0X`` and 1 to 8 hex digits, or 1 to 10 ASCII digits; any other
    word is not a number (E3A-14).  No ``int()`` runs on a longer word.
    """
    if word is None:
        return None
    text = word
    negative = False
    if text.startswith("-"):
        negative = True
        text = text[1:]
    if text[:2] in ("0x", "0X"):
        digits = text[2:]
        if not 1 <= len(digits) <= 8:
            return None
        if any(ch not in _HEX_DIGITS for ch in digits):
            return None
        value = int(digits, 16)
    elif 1 <= len(text) <= 10 and all(ch in _ASCII_DIGITS for ch in text):
        value = int(text, 10)
    else:
        return None
    return -value if negative else value


def _object_line_words(section: Optional[dict]) -> list[list[str]]:
    """The object's own body lines with comments left out, one word list per
    line (``_strip_a2l_comments`` on the joined lines, split back at line ends,
    each line split by ``_split_line_respecting_quotes``)."""
    if section is None:
        return []
    text = _strip_a2l_comments("\n".join(section.get("lines") or []))
    return [_split_line_respecting_quotes(line) for line in text.split("\n")]


def _matrix_shape(dims: tuple[str, ...]) -> Optional[tuple[int, ...]]:
    """The MATRIX_DIM shape: 1 to 3 whole numbers of at least 1, every trailing
    ``1`` left out keeping at least one; ``None`` when there is no word, more
    than three, or a word that is not a whole number of at least 1.
    """
    if not dims or len(dims) > 3:
        return None
    numbers: list[int] = []
    for word in dims:
        number = _read_count(word)
        if number is None or number < 1:
            return None
        numbers.append(number)
    while len(numbers) > 1 and numbers[-1] == 1:
        numbers.pop()
    return tuple(numbers)


def _is_multi_value_matrix(dims: tuple[str, ...]) -> bool:
    """True when a MATRIX_DIM line is a *multi-value MATRIX_DIM line*: other
    than 1 to 3 words that are each ``1`` (E3A-02)."""
    return not (1 <= len(dims) <= 3 and all(word == "1" for word in dims))


def _dims_text(dims: tuple[str, ...]) -> str:
    """The ``<dims>`` placeholder: the MATRIX_DIM words as R-A2L-DEF.151 writes
    them, or ``(none)`` when there are none."""
    if not dims:
        return "(none)"
    return " ".join(_echo(word) for word in dims)


def _ratio(number: int | float) -> tuple[int, int]:
    """An ``int`` as itself and a ``float`` as its exact integer ratio, each as
    ``(numerator, power-of-two denominator)`` for the FIX point arithmetic.
    """
    if isinstance(number, int):
        return number, 1
    numerator, denominator = number.as_integer_ratio()
    return numerator, denominator


def _rational_to_number(numerator: int, denominator: int) -> int | float:
    """``numerator / denominator`` as an ``int`` when it divides exactly, else
    the correctly rounded double (Python's ``int / int``)."""
    quotient, remainder = divmod(numerator, denominator)
    if remainder == 0:
        return quotient
    return numerator / denominator


def _mask_shift(mask: int) -> int:
    """The number of 0 bits below the lowest 1 bit of ``mask``."""
    shift = 0
    while mask and not (mask & 1):
        mask >>= 1
        shift += 1
    return shift


def _raw_text(stored: int | float) -> str:
    """The ``<raw>`` placeholder: the integer text when the stored value is
    integral (finite and ``float.is_integer()``), else its ``%.15g`` text."""
    if isinstance(stored, float):
        if math.isfinite(stored) and stored.is_integer():
            return str(int(stored))
        return f"{stored:.15g}"
    return str(stored)


def _decode_binary16(raw: bytes, byte_order: str) -> float:
    """IEEE 754 binary16 via ``struct`` ``e`` (``_decode_scalar`` gives ``None``
    for FLOAT16_IEEE, BL-I2-7)."""
    prefix = ">" if byte_order == "big" else "<"
    (half,) = struct.unpack(f"{prefix}e", raw)
    return float(half)


def _read_limits(lower_word: object, upper_word: object) -> Limits:
    """The two limit words as a :class:`Limits` (a side whose word is not a
    finite number declares no limit and an empty text)."""
    lower = _finite_number(lower_word)
    upper = _finite_number(upper_word)
    return Limits(
        lower,
        upper,
        str(lower_word) if lower is not None else "",
        str(upper_word) if upper is not None else "",
    )


def describe_definition(name: str, a2l_data: dict) -> Definition:
    """Build the definition of one name; ``describe_definitions([name],
    a2l_data)[name]`` — one code path, every rule lives in
    :func:`describe_definitions`.

    Args:
        name (str): The A2L object name, case included.
        a2l_data (dict): The parse payload of ``parse_a2l_file`` (``sections``,
            ``tags``, ``record_layouts_by_name``, ``compu_tabs_by_name``).
            Read, never written.  ``compu_methods_by_name`` is built from
            ``sections``, not read.

    Returns:
        Definition: The definition of the name (a refusal carries every field
            the system could read).

    Raises:
        None: file and image content never raise.
    """
    return describe_definitions([name], a2l_data)[name]


def describe_definitions(names: Iterable[str], a2l_data: dict) -> dict[str, Definition]:
    """Build the definitions of ``names`` in one walk of ``a2l_data``.

    Builds the name maps once — the MEASUREMENT / CHARACTERISTIC sections of
    each name in file order, the first COMPU_METHOD of each name and the first
    COMPU_VTAB / COMPU_VTAB_RANGE of each name — then one pass over
    ``a2l_data["tags"]`` maps the tags of each name.  For each name (order
    kept, a repeated name maps once) it reads every field it can and applies
    the refusal order (name, kind, address and length, datatype, length against
    datatype, conversion method, conversion type, enum table, entries, bit
    mask).  A ``reads`` map (one per call) holds each shared section's read
    form once, so a name's time does not grow with the size of a section it
    shares (R-A2L-DEF.148): Inc 2a's forms under the bare ``id()`` of the
    section (the method record, enum table, table form and resolved layout
    datatype) and Inc 3a's under a ``(kind, id(section))`` tuple key
    (``("layout", id(entry))``, ``("mod_common", id(section))``,
    ``("axis_byte_order", id(section))``); the map is dropped when the call
    returns.

    Args:
        names (Iterable[str]): The names to describe.
        a2l_data (dict): The parse payload (as :func:`describe_definition`).

    Returns:
        dict[str, Definition]: One definition per requested name.

    Raises:
        None.
    """
    tags_by_name: dict[str, list[dict]] = {}
    for tag in a2l_data.get("tags") or []:
        tags_by_name.setdefault(tag.get("name"), []).append(tag)

    object_sections_by_name: dict[str, list[dict]] = {}
    compu_methods_by_name: dict[str, dict] = {}
    compu_tables_by_name: dict[str, dict] = {}
    axis_pts_by_name: dict[str, tuple[dict, tuple[str, ...], Optional[dict]]] = {}
    mod_common_of: dict[int, Optional[dict]] = {}
    record_layouts = a2l_data.get("record_layouts_by_name") or {}
    declared_spans = a2l_data.get("declared_spans") or []
    order = [0]
    ds_index = [0]
    tag_consumed: dict[str, int] = {}
    span_entries: list[tuple] = []

    def walk(nodes: Iterable[dict], mod_common: Optional[dict]) -> None:
        for node in nodes:
            order[0] += 1
            position = order[0]
            node_name = node.get("name")
            if node_name == "MODULE":
                child_common = next(
                    (
                        child
                        for child in node.get("children") or []
                        if child.get("name") == "MOD_COMMON"
                    ),
                    None,
                )
                walk(node.get("children") or [], child_common)
                continue
            parsed = parse_begin_meta(node.get("meta", "") or "")
            if node_name in ("MEASUREMENT", "CHARACTERISTIC"):
                object_sections_by_name.setdefault(parsed[0], []).append(node)
                mod_common_of[id(node)] = mod_common
                if node.get("end_line") is not None:
                    idx = tag_consumed.get(parsed[0], 0)
                    tags = tags_by_name.get(parsed[0]) or []
                    if idx < len(tags):
                        tag = tags[idx]
                        tag_consumed[parsed[0]] = idx + 1
                        address = tag.get("address")
                        if address is not None:
                            span_entries.append(
                                (
                                    position,
                                    parsed[0],
                                    node_name,
                                    address,
                                    tag.get("length"),
                                    tag.get("effective_byte_order") or "little",
                                )
                            )
            elif node_name == "COMPU_METHOD":
                compu_methods_by_name.setdefault(parsed[0], node)
            elif node_name in ("COMPU_VTAB", "COMPU_VTAB_RANGE"):
                compu_tables_by_name.setdefault(parsed[0], node)
            elif node_name in ("BLOB", "INSTANCE"):
                if ds_index[0] < len(declared_spans):
                    span = declared_spans[ds_index[0]]
                    ds_index[0] += 1
                    address = span.get("address")
                    if address is not None:
                        span_entries.append(
                            (
                                position,
                                span.get("name"),
                                node_name,
                                address,
                                span.get("length"),
                                "little",
                            )
                        )
            elif node_name == "AXIS_PTS":
                tokens = _flatten_body_tokens(
                    [node.get("meta", "") or ""] + (node.get("lines") or [])
                )
                header = tuple(tokens[:10])
                ref = header[0] if header else None
                layout_name = header[4] if len(header) > 4 else None
                layout_section = record_layouts.get(layout_name) if layout_name else None
                if ref is not None:
                    axis_pts_by_name.setdefault(ref, (node, header, layout_section))
                mod_common_of[id(node)] = mod_common
            walk(node.get("children") or [], mod_common)

    walk(a2l_data.get("sections") or [], None)

    span_index: dict[int, list[tuple]] = {}
    for entry in span_entries:
        _position, _name, _kind, address, byte_length, _byte_order = entry
        if byte_length is not None and byte_length >= 1:
            first_page = address >> 4
            last_page = (address + byte_length - 1) >> 4
            pages = range(first_page, last_page + 1)
        else:
            pages = (address >> 4,)
        for page in pages:
            span_index.setdefault(page, []).append(entry)

    result: dict[str, Definition] = {}
    reads: dict[object, object] = {}
    maps = {
        "axis_pts_by_name": axis_pts_by_name,
        "mod_common_of": mod_common_of,
        "reads": reads,
        "compu_methods_by_name": compu_methods_by_name,
        "compu_tables_by_name": compu_tables_by_name,
    }
    mask_cache: dict[str, Optional[int]] = {}

    def mask_of(other_name: str) -> Optional[int]:
        if other_name in mask_cache:
            return mask_cache[other_name]
        other = _describe_one(
            other_name,
            tags_by_name,
            object_sections_by_name,
            compu_methods_by_name,
            compu_tables_by_name,
            a2l_data,
            maps,
        )
        value = (
            other.bit_mask
            if (other.refusal is None and other.byte_length is not None)
            else None
        )
        mask_cache[other_name] = value
        return value

    for name in names:
        if name in result:
            continue
        definition = _describe_one(
            name,
            tags_by_name,
            object_sections_by_name,
            compu_methods_by_name,
            compu_tables_by_name,
            a2l_data,
            maps,
        )
        mask_cache[name] = (
            definition.bit_mask
            if (definition.refusal is None and definition.byte_length is not None)
            else None
        )
        result[name] = replace(
            definition,
            shared_with=_shared_with(definition, span_index, mask_of),
        )
    return result


def _describe_one(
    name: str,
    tags_by_name: dict[str, list[dict]],
    object_sections_by_name: dict[str, list[dict]],
    compu_methods_by_name: dict[str, dict],
    compu_tables_by_name: dict[str, dict],
    a2l_data: dict,
    maps: dict,
) -> Definition:
    """Read every field and the refusal for one name (the body of
    :func:`describe_definitions`)."""
    name_echo = _echo(name)
    empty = _empty_definition(name, name_echo)

    found = _find_tag(name, tags_by_name, object_sections_by_name)
    if found is None:
        return _with_refusal(
            empty, Refusal("A2L-DEF-NAME", f"{name_echo}: no tag of that name in the A2L")
        )
    if isinstance(found, Refusal):
        return _with_refusal(empty, found)

    tag, section = found

    # Copy the tag so the definition never mutates the parse payload
    # (R-A2L-DEF.58.1).
    tag = dict(tag)
    object_lines = _read_object_lines(section)

    address = tag.get("address")
    tag_length = tag.get("length")
    byte_order = tag.get("effective_byte_order") or "little"
    char_type = tag.get("char_type")
    section_name = tag.get("section") or ""

    method_name = tag.get("conversion")
    matrix = _read_matrix_dim(section)
    matrix_words = matrix[0] if matrix is not None else None
    fields, conv_refusal = _conversion_fields(
        name_echo,
        method_name,
        compu_methods_by_name,
        compu_tables_by_name,
        a2l_data.get("compu_tabs_by_name") or {},
        maps["reads"],
    )
    kind, kind_text = _object_kind(tag, fields["conversion_type"], matrix_words)

    object_format = object_lines.get("format")
    display_format = object_format if object_format is not None else fields["record_format"]
    decimals = (
        _display_decimals(object_format)
        if object_format is not None
        else fields["decimals"]
    )
    unit = object_lines.get("unit")
    if unit is None:
        unit = fields["record_unit"] or ""
    unit = unit or ""

    limits = _read_limits(tag.get("lower_limit"), tag.get("upper_limit"))
    extended_limits = object_lines.get("extended_limits")
    mask_word = object_lines.get("bit_mask")

    if kind in ("array", "curve", "map"):
        base = Definition(
            name=name,
            section=section_name,
            char_type=char_type,
            kind=kind,
            address=address,
            byte_length=tag_length,
            datatype=None,
            byte_order=byte_order,
            bit_mask=None,
            bit_mask_text=mask_word,
            conversion_type=fields["conversion_type"],
            method_name=method_name,
            display_format=display_format,
            decimals=decimals,
            unit=unit,
            limits=limits,
            extended_limits=extended_limits,
            enum_table=fields["enum_table"],
            enum_entries=fields["enum_entries"],
            default_text=fields["default_text"],
            coeffs_linear=fields["coeffs_linear"],
            coeffs=fields["coeffs"],
            compu_tab_ref=fields["compu_tab_ref"],
            shared_with=None,
            refusal=None,
            _name_echo=name_echo,
            _table_form=fields["table_form"],
        )
        return _describe_array(tag, section, a2l_data, base, maps)

    datatype = _resolve_datatype(tag, a2l_data, maps["reads"])

    # ---- the refusal order -------------------------------------------------
    refusal: Optional[Refusal] = None
    value_145 = False
    if kind is None:
        refusal = Refusal(
            "A2L-DEF-KIND",
            f"{name_echo}: the system has no definition for a {kind_text} object",
        )
    elif (
        section_name == "CHARACTERISTIC"
        and char_type == "VALUE"
        and matrix_words is not None
        and _is_multi_value_matrix(matrix_words)
    ):
        value_145 = True
        refusal = Refusal(
            "A2L-DEF-MATRIX",
            f"{name_echo}: the system cannot read MATRIX_DIM {_dims_text(matrix_words)} "
            "on a VALUE",
        )
    elif address is None or tag_length is None:
        refusal = Refusal(
            "A2L-DEF-ADDRESS", f"{name_echo}: the object has no address or no length"
        )
    elif (
        tag_length < 1
        or tag_length > MAX_A2L_DECODE_BYTES
        or address < 0
        or address + tag_length - 1 > 0xFFFFFFFF
    ):
        refusal = Refusal(
            "A2L-DEF-ADDRESS",
            f"{name_echo}: its span of {_number_text(tag_length)} bytes at "
            f"{_number_text(address, address=True)} cannot be read",
        )
    elif kind in ("number", "enum"):
        if datatype is None:
            refusal = Refusal(
                "A2L-DEF-DATATYPE",
                f"{name_echo}: the object declares no datatype the system can read",
            )
        elif tag_length != DATATYPE_SIZES[datatype]:
            refusal = Refusal(
                "A2L-DEF-LENGTH",
                f"{name_echo}: its length {_number_text(tag_length)} differs from the "
                f"{DATATYPE_SIZES[datatype]} bytes of {datatype}",
            )

    if refusal is None:
        refusal = conv_refusal

    mask_number: Optional[int] = None
    if kind in ("number", "enum") and mask_word is not None:
        mask_number = _parse_bit_mask(mask_word)

    if refusal is None and mask_word is not None:
        if _mask_byte_order_ambiguous(tag, section, object_lines, a2l_data, maps):
            refusal = Refusal(
                "A2L-DEF-MASK",
                f"{name_echo}: its byte order cannot be read",
            )
        elif kind == "text":
            refusal = Refusal(
                "A2L-DEF-MASK",
                f"{name_echo}: the bit mask {_echo(mask_word)} cannot be "
                f"applied to {_echo(char_type)}",
            )
        elif kind in ("number", "enum"):
            if (
                object_lines.get("bit_mask_count", 0) > 1
                or mask_number is None
                or not _check_bit_mask(mask_number, datatype)
            ):
                refusal = Refusal(
                    "A2L-DEF-MASK",
                    f"{name_echo}: the bit mask {_echo(mask_word)} cannot be "
                    f"applied to {datatype}",
                )

    return Definition(
        name=name,
        section=section_name,
        char_type=char_type,
        kind=kind or "",
        address=address,
        byte_length=None if value_145 else tag_length,
        datatype=datatype,
        byte_order=byte_order,
        bit_mask=mask_number if kind in ("number", "enum") else None,
        bit_mask_text=mask_word,
        conversion_type=fields["conversion_type"],
        method_name=method_name,
        display_format=display_format,
        decimals=decimals,
        unit=unit,
        limits=limits,
        extended_limits=extended_limits,
        enum_table=fields["enum_table"],
        enum_entries=fields["enum_entries"],
        default_text=fields["default_text"],
        coeffs_linear=fields["coeffs_linear"],
        coeffs=fields["coeffs"],
        compu_tab_ref=fields["compu_tab_ref"],
        shared_with=None,
        refusal=refusal,
        element_count=None if value_145 or kind is None else 1,
        _name_echo=name_echo,
        _table_form=fields["table_form"],
    )


def _empty_definition(name: str, name_echo: str) -> Definition:
    """A blank Definition (kind ``""``, element count ``None`` per E3A-03)."""
    return Definition(
        name=name,
        section="",
        char_type=None,
        kind="",
        address=None,
        byte_length=None,
        datatype=None,
        byte_order="little",
        bit_mask=None,
        bit_mask_text=None,
        conversion_type=None,
        method_name=None,
        display_format=None,
        decimals=None,
        unit="",
        limits=Limits(None, None, "", ""),
        extended_limits=None,
        enum_table=None,
        enum_entries=(),
        default_text=None,
        coeffs_linear=None,
        coeffs=None,
        compu_tab_ref=None,
        shared_with=None,
        refusal=None,
        element_count=None,
        _name_echo=name_echo,
        _table_form=None,
    )


def _with_refusal(definition: Definition, refusal: Refusal) -> Definition:
    """Return ``definition`` with ``refusal`` set (frozen dataclass helper)."""
    return replace(definition, refusal=refusal)


def _find_tag(
    name: str,
    tags_by_name: dict[str, list[dict]],
    object_sections_by_name: dict[str, list[dict]],
) -> tuple[dict, Optional[dict]] | Refusal | None:
    """Look up one name in the two maps ``describe_definitions`` builds.

    Exactly one tag and at most one section → that tag paired with that
    section (R-A2L-DEF.5, case included); more than one tag or more than one
    section → ``Refusal("A2L-DEF-NAME", "<name>: the A2L declares that name
    more than once")`` (R-A2L-DEF.139); ``None`` when no tag has the name.
    """
    tags = tags_by_name.get(name) or []
    sections = object_sections_by_name.get(name) or []
    if not tags:
        return None
    if len(tags) > 1 or len(sections) > 1:
        return Refusal(
            "A2L-DEF-NAME", f"{_echo(name)}: the A2L declares that name more than once"
        )
    return tags[0], sections[0] if sections else None


def _object_kind(
    tag: dict,
    conversion_type: Optional[str],
    matrix_words: Optional[tuple[str, ...]] = None,
) -> tuple[str | None, str]:
    """The kind and its text: ``(kind, kind_text)``.

    A CHARACTERISTIC of ``char_type`` ASCII → ``("text", "ASCII")``; VALUE →
    ``("enum"/"number", "VALUE")``; VAL_BLK → ``("array", "VAL_BLK")``; CURVE
    → ``("curve", "CURVE")``; MAP → ``("map", "MAP")``; a MEASUREMENT that has
    a multi-value MATRIX_DIM line → ``("array", "MEASUREMENT")``; a MEASUREMENT
    with no MATRIX_DIM line or 1 to 3 words each ``1`` → its scalar kind; every
    other object → ``(None, the <kind> text as the message writes it)``.
    """
    section = tag.get("section")
    char_type = tag.get("char_type")
    if section == "CHARACTERISTIC":
        if char_type == "ASCII":
            return "text", "ASCII"
        if char_type == "VALUE":
            kind = "enum" if conversion_type == "TAB_VERB" else "number"
            return kind, "VALUE"
        if char_type == "VAL_BLK":
            return "array", "VAL_BLK"
        if char_type == "CURVE":
            return "curve", "CURVE"
        if char_type == "MAP":
            return "map", "MAP"
        if char_type is None:
            return None, "(none)"
        return None, _echo(str(char_type))
    if section == "MEASUREMENT":
        if matrix_words is not None and _is_multi_value_matrix(matrix_words):
            return "array", "MEASUREMENT"
        kind = "enum" if conversion_type == "TAB_VERB" else "number"
        return kind, "MEASUREMENT"
    return None, "(none)"


def _find_component(layout: Mapping, name: str) -> Optional[tuple]:
    """The first component tuple of ``layout`` whose first word is ``name``, or
    ``None``."""
    for component in layout["components"]:
        if component[0] == name:
            return component
    return None


def _to_int_or_float(number: float) -> int | float:
    """A finite double as an ``int`` when it is integral, else the float."""
    if number.is_integer():
        return int(number)
    return number


def _axis_format(header: tuple[str, ...]) -> Optional[str]:
    """The FORMAT word of an axis header, else ``None``."""
    for i, word in enumerate(header):
        if word == "FORMAT" and i + 1 < len(header):
            return header[i + 1]
    return None


def _axis_byte_order(
    axis_object_section: dict,
    axis_object_layout_section: Optional[dict],
    maps: dict,
) -> str:
    """The axis object's byte order (its BYTE_ORDER line, else its layout's,
    else the MOD_COMMON's, else ``little``), read once per walk under
    ``("axis_byte_order", id(section))`` (R-A2L-DEF.114)."""
    key = ("axis_byte_order", id(axis_object_section))
    reads = maps["reads"]
    if key in reads:
        return reads[key]
    order = _byte_order_from_section_lines(axis_object_section.get("lines") or [])
    if order is None and axis_object_layout_section is not None:
        order = _byte_order_from_section_lines(
            axis_object_layout_section.get("lines") or []
        )
    if order is None:
        mod_common = _module_common(axis_object_section, maps)
        order = mod_common["byte_order"] if mod_common else None
    order = order or "little"
    reads[key] = order
    return order


def _conversion_fields(
    name: str,
    method_name: Optional[str],
    compu_methods_by_name: dict[str, dict],
    compu_tables_by_name: dict[str, dict],
    compu_tabs_by_name: dict[str, dict],
    reads: dict,
) -> tuple[dict, Optional[Refusal]]:
    """The conversion fields of one object or axis method and its first refusal
    (Inc 2's order: METHOD, CONVERSION, TABLE, TABLE-EMPTY), factored out of Inc
    2's describe so an object and each axis read a method one way.
    """
    empty: dict = {
        "conversion_type": None,
        "kind": "number",
        "coeffs_linear": None,
        "coeffs": None,
        "compu_tab_ref": None,
        "record_format": None,
        "record_unit": None,
        "enum_table": None,
        "enum_entries": (),
        "default_text": None,
        "decimals": None,
        "type_verdict": None,
        "type_echo": "(none)",
        "table_echo": "(none)",
        "table_form": None,
    }
    if method_name is None or method_name == "NO_COMPU_METHOD":
        return empty, None
    method_echo = _echo(method_name)
    record = _read_method_record(
        method_name,
        compu_methods_by_name,
        compu_tables_by_name,
        compu_tabs_by_name,
        reads,
    )
    if record is None:
        return empty, Refusal(
            "A2L-DEF-METHOD",
            f"{name}: the conversion method {method_echo} is not declared in the A2L",
        )
    conversion_type = record.get("conversion_type")
    type_verdict = record.get("type_verdict")
    type_echo = record.get("type_echo")
    table_echo = record.get("table_echo")
    fields = {
        "conversion_type": conversion_type,
        "kind": "number",
        "coeffs_linear": (
            tuple(record["coeffs_linear"])
            if record.get("coeffs_linear") is not None
            else None
        ),
        "coeffs": tuple(record["coeffs"]) if record.get("coeffs") is not None else None,
        "compu_tab_ref": record.get("compu_tab_ref"),
        "record_format": record.get("format"),
        "record_unit": record.get("unit"),
        "enum_table": None,
        "enum_entries": (),
        "default_text": None,
        "decimals": record.get("decimals"),
        "type_verdict": type_verdict,
        "type_echo": type_echo,
        "table_echo": table_echo,
        "table_form": record.get("table_form"),
    }
    refusal: Optional[Refusal] = None
    if type_verdict is None:
        refusal = Refusal(
            "A2L-DEF-CONVERSION",
            f"{name}: the conversion type {type_echo} of {method_echo} is not supported",
        )
    elif type_verdict == "TAB_VERB":
        fields["kind"] = "enum"
        fields["enum_table"] = record.get("compu_tab_ref")
        form = record.get("table_form")
        if fields["enum_table"] is None:
            refusal = Refusal(
                "A2L-DEF-TABLE",
                f"{name}: the table (none) of {method_echo} is not declared in the A2L",
            )
        elif form is None:
            refusal = Refusal(
                "A2L-DEF-TABLE",
                f"{name}: the table {table_echo} of {method_echo} is not declared in the A2L",
            )
        elif not form.entries:
            refusal = Refusal(
                "A2L-DEF-TABLE-EMPTY",
                f"{name}: the table {table_echo} has no entries",
            )
        else:
            fields["enum_entries"] = form.entries
            fields["default_text"] = form.default_text
    return fields, refusal


def _read_matrix_dim(
    section: Optional[dict],
) -> Optional[tuple[tuple[str, ...], Optional[tuple[int, ...]]]]:
    """The first MATRIX_DIM line's ``(words, shape)`` of the object's own lines,
    or ``None`` when there is no such line."""
    for words in _object_line_words(section):
        if words and words[0] == "MATRIX_DIM":
            dims = tuple(words[1:])
            return (dims, _matrix_shape(dims))
    return None


def _array_shape(
    tag: dict,
    section: Optional[dict],
    datatype: Optional[str],
    matrix: Optional[tuple[tuple[str, ...], Optional[tuple[int, ...]]]],
) -> Optional[tuple[int, ...]] | Refusal:
    """The array's shape: the MATRIX_DIM shape; else a VAL_BLK's first NUMBER;
    else the first LENGTH / DATA_SIZE line divided by the datatype's size — not
    a whole multiple → ``A2L-DEF-SHAPE``.  Then a LENGTH / DATA_SIZE line whose
    number differs from element count × size → ``A2L-DEF-LENGTH``.  ``None``
    when nothing gives a shape.
    """
    name_echo = _echo(tag.get("name") or "")
    size = DATATYPE_SIZES.get(datatype) if datatype else None
    lines = _object_line_words(section)
    number_word: Optional[str] = None
    length_word: Optional[str] = None
    for words in lines:
        if not words:
            continue
        if words[0] in ("LENGTH", "DATA_SIZE") and len(words) > 1 and length_word is None:
            length_word = words[1]
        elif words[0] == "NUMBER" and len(words) > 1 and number_word is None:
            number_word = words[1]
    shape: Optional[tuple[int, ...]] = None
    if matrix is not None and matrix[1] is not None:
        shape = matrix[1]
    elif tag.get("section") == "CHARACTERISTIC" and tag.get("char_type") == "VAL_BLK":
        number = _read_count(number_word) if number_word is not None else None
        if number is not None and number >= 1:
            shape = (number,)
    if shape is None:
        length = _read_count(length_word) if length_word is not None else None
        if length is not None and size:
            if length % size != 0:
                return Refusal(
                    "A2L-DEF-SHAPE",
                    f"{name_echo}: its length {length} is not a whole number of "
                    f"{datatype} values",
                )
            shape = (length // size,)
    if shape is None:
        return None
    length = _read_count(length_word) if length_word is not None else None
    if length is not None and size:
        element_count = 1
        for number in shape:
            element_count *= number
        if length != element_count * size:
            return Refusal(
                "A2L-DEF-LENGTH",
                f"{name_echo}: its length {length} differs from the "
                f"{element_count * size} bytes of {element_count} {datatype} values",
            )
    return shape


def _layout_form(
    name_echo: str,
    components: list[tuple],
    alignment: dict[str, int],
    fixed: dict[str, int],
    refusal: Optional[tuple[str, str]],
) -> Mapping:
    """The record layout's reduced read form (an immutable value)."""
    return MappingProxyType(
        {
            "name": name_echo,
            "components": tuple(components),
            "alignment": tuple(alignment.items()),
            "fixed": MappingProxyType(dict(fixed)),
            "refusal": refusal,
        }
    )


def _build_record_layout_form(entry: dict) -> Mapping:
    """Read a RECORD_LAYOUT section into its reduced form (R-A2L-DEF.82 … .87)."""
    name_echo = _echo(entry.get("name") or "")
    text = _strip_a2l_comments("\n".join(entry.get("lines") or []))
    components: list[tuple] = []
    seen: set[str] = set()
    alignment: dict[str, int] = {}
    fixed: dict[str, int] = {}
    parts: list[str] = []
    for words in (
        _split_line_respecting_quotes(line) for line in text.split("\n")
    ):
        if not words:
            continue
        head = words[0]
        if head in ("FNC_VALUES", "AXIS_PTS_X", "AXIS_PTS_Y"):
            if len(words) > 5:
                parts.append(words[5])
            elif head in seen:
                parts.append(head)
            else:
                components.append(tuple(words))
                seen.add(head)
        elif head in ("NO_AXIS_PTS_X", "NO_AXIS_PTS_Y"):
            if len(words) > 3:
                parts.append(words[3])
            elif head in seen:
                parts.append(head)
            else:
                components.append(tuple(words))
                seen.add(head)
        elif head in ("FIX_NO_AXIS_PTS_X", "FIX_NO_AXIS_PTS_Y"):
            number = _read_count(words[1]) if len(words) > 1 else None
            if number is None:
                parts.append(head)
            else:
                fixed[head[-1]] = number
        elif head.startswith("ALIGNMENT_"):
            number = _read_count(words[1]) if len(words) > 1 else None
            if number is None or number < 1:
                parts.append(head)
            else:
                alignment[head] = number
        elif len(words) == 1 and head == "DIRECT":
            continue
        else:
            parts.append(head)

    positions: list[Optional[int]] = []
    for component in components:
        positions.append(_read_count(component[1]) if len(component) > 1 else None)
    if any(position is None for position in positions) or len(set(positions)) != len(
        positions
    ):
        return _layout_form(
            name_echo,
            components,
            alignment,
            fixed,
            (
                "A2L-DEF-LAYOUT-POSITION",
                f"the positions of the record layout {name_echo} do not give one order",
            ),
        )
    if parts:
        return _layout_form(
            name_echo,
            components,
            alignment,
            fixed,
            (
                "A2L-DEF-LAYOUT-PART",
                f"the record layout {name_echo} holds {_echo(parts[0])}, "
                "which the system cannot read",
            ),
        )
    ordered = sorted(components, key=lambda component: positions[components.index(component)])
    for component in ordered:
        head = component[0]
        if head == "FNC_VALUES":
            mode = component[3] if len(component) > 3 else None
            if mode not in ("ROW_DIR", "COLUMN_DIR"):
                return _layout_form(
                    name_echo,
                    ordered,
                    alignment,
                    fixed,
                    (
                        "A2L-DEF-LAYOUT-MODE",
                        f"the record layout {name_echo} stores FNC_VALUES as "
                        f"{_echo(mode) if mode else '(none)'}, which the system cannot read",
                    ),
                )
            address = component[4] if len(component) > 4 else None
            if address != "DIRECT":
                return _layout_form(
                    name_echo,
                    ordered,
                    alignment,
                    fixed,
                    (
                        "A2L-DEF-LAYOUT-MODE",
                        f"the record layout {name_echo} stores FNC_VALUES as "
                        f"{_echo(address) if address else '(none)'}, which the system cannot read",
                    ),
                )
        elif head in ("AXIS_PTS_X", "AXIS_PTS_Y"):
            order = component[3] if len(component) > 3 else None
            if order not in ("INDEX_INCR", "INDEX_DECR"):
                return _layout_form(
                    name_echo,
                    ordered,
                    alignment,
                    fixed,
                    (
                        "A2L-DEF-LAYOUT-MODE",
                        f"the record layout {name_echo} stores {head} as "
                        f"{_echo(order) if order else '(none)'}, which the system cannot read",
                    ),
                )
            address = component[4] if len(component) > 4 else None
            if address != "DIRECT":
                return _layout_form(
                    name_echo,
                    ordered,
                    alignment,
                    fixed,
                    (
                        "A2L-DEF-LAYOUT-MODE",
                        f"the record layout {name_echo} stores {head} as "
                        f"{_echo(address) if address else '(none)'}, which the system cannot read",
                    ),
                )
    for component in ordered:
        head = component[0]
        datatype = component[2] if len(component) > 2 else None
        if head in ("NO_AXIS_PTS_X", "NO_AXIS_PTS_Y"):
            if datatype not in _COUNT_DATATYPES:
                return _layout_form(
                    name_echo,
                    ordered,
                    alignment,
                    fixed,
                    (
                        "A2L-DEF-LAYOUT-DATATYPE",
                        f"the record layout {name_echo} gives {head} the datatype "
                        f"{_echo(datatype) if datatype else '(none)'}, which the system cannot read",
                    ),
                )
        elif datatype not in _COMPONENT_DATATYPES:
            return _layout_form(
                name_echo,
                ordered,
                alignment,
                fixed,
                (
                    "A2L-DEF-LAYOUT-DATATYPE",
                    f"the record layout {name_echo} gives {head} the datatype "
                    f"{_echo(datatype) if datatype else '(none)'}, which the system cannot read",
                ),
            )
    return _layout_form(name_echo, ordered, alignment, fixed, None)


def _read_record_layout(
    name: Optional[str],
    a2l_data: dict,
    owner: str,
    maps: dict,
    section: Optional[dict] = None,
) -> Optional[Mapping | Refusal]:
    """Read a RECORD_LAYOUT once per walk into its reduced form (keyed by
    ``("layout", id(section))``), putting ``owner`` into a refusal's message at
    each call."""
    reads = maps["reads"]
    if section is None:
        entry = (a2l_data.get("record_layouts_by_name") or {}).get(name)
        if entry is None:
            return None
    else:
        entry = section
    key = ("layout", id(entry))
    if key in reads:
        form = reads[key]
    else:
        form = _build_record_layout_form(entry)
        reads[key] = form
    if form["refusal"] is not None:
        code, suffix = form["refusal"]
        return Refusal(code, f"{owner}: {suffix}")
    return form


def _place_components(layout: Mapping, counts: tuple[int, ...]) -> Optional[tuple[dict[str, int], int]]:
    """Place the layout's components (one ALIGNMENT entry per class, the
    components in position order) via the frozen walker: gives
    ``({component: offset}, last component's end)`` or ``None`` past the cap.
    """
    lines = [f"{cls} {number}" for cls, number in layout["alignment"]]
    for component in layout["components"]:
        lines.append(" ".join(component))
    walked = _walk_record_layout_components({"lines": lines}, list(counts))
    if walked is None:
        return None
    offsets = {entry["component"]: entry["offset"] for entry in walked}
    end = walked[-1]["end"] if walked else 0
    return offsets, end


def _build_mod_common_form(mc_section: dict) -> Mapping:
    """A MOD_COMMON's reduced read form: one ALIGNMENT entry per class (the
    first unreadable word's echo and line index, else the last number) and the
    byte order."""
    lines = mc_section.get("lines") or []
    text = _strip_a2l_comments("\n".join(lines))
    alignment: dict[str, list] = {}
    for index, words in enumerate(
        _split_line_respecting_quotes(line) for line in text.split("\n")
    ):
        if not words:
            continue
        head = words[0]
        if head.startswith("ALIGNMENT_"):
            word = words[1] if len(words) > 1 else None
            number = _read_count(word)
            if head not in alignment:
                alignment[head] = [None, None, None]
            if number is None or number < 1:
                if alignment[head][0] is None:
                    alignment[head][0] = _echo(word) if word is not None else "(none)"
                    alignment[head][1] = index
            else:
                alignment[head][2] = number
    return MappingProxyType(
        {
            "alignment": MappingProxyType(
                {cls: tuple(entry) for cls, entry in alignment.items()}
            ),
            "byte_order": _byte_order_from_section_lines(lines),
        }
    )


def _module_common(section: dict, maps: dict) -> Optional[Mapping]:
    """The MOD_COMMON read form of the MODULE ``section`` lies under, read once
    per walk under ``("mod_common", id(section))``."""
    mc_section = maps["mod_common_of"].get(id(section))
    if mc_section is None:
        return None
    key = ("mod_common", id(mc_section))
    reads = maps["reads"]
    if key not in reads:
        reads[key] = _build_mod_common_form(mc_section)
    return reads[key]


def _check_module_alignment(
    layout: Mapping,
    counts: tuple[int, ...],
    mod_common: Optional[Mapping],
) -> Optional[tuple[str, int, int] | tuple[str, str]]:
    """The MOD_COMMON alignment verdict for ``layout``: a
    ``(ALIGNMENT_<class>, word)`` for an unreadable line (.144), a
    ``(component, a, b)`` for a moved component (.89), or ``None``."""
    if mod_common is None:
        return None
    mc_alignment = mod_common["alignment"]
    layout_classes = {cls for cls, _ in layout["alignment"]}
    followed: set[str] = set()
    for component in layout["components"]:
        datatype = component[2] if len(component) > 2 else None
        cls = _DATATYPE_ALIGNMENT_CLASS.get(datatype)
        if cls is not None:
            followed.add(cls)
    relevant = [cls for cls in followed if cls not in layout_classes and cls in mc_alignment]
    unreadable: Optional[tuple[int, str, str]] = None
    for cls in relevant:
        echo, line_index, _last = mc_alignment[cls]
        if echo is not None and line_index is not None:
            if unreadable is None or line_index < unreadable[0]:
                unreadable = (line_index, cls, echo)
    if unreadable is not None:
        return (unreadable[1], unreadable[2])
    extra = [(cls, mc_alignment[cls][2]) for cls in relevant if mc_alignment[cls][2] is not None]
    if not extra:
        return None
    merged = dict(layout["alignment"])
    for cls, number in extra:
        merged[cls] = number
    new_layout = {"alignment": tuple(merged.items()), "components": layout["components"]}
    base_placed = _place_components(layout, counts)
    new_placed = _place_components(new_layout, counts)
    if base_placed is None or new_placed is None:
        return None
    base_offsets, _end = base_placed
    new_offsets, _end = new_placed
    for component in layout["components"]:
        cname = component[0]
        if base_offsets.get(cname) != new_offsets.get(cname):
            return (cname, base_offsets.get(cname, 0), new_offsets.get(cname, 0))
    return None


def _alignment_refusal(
    name_echo: str, layout: Mapping, counts: tuple[int, ...], mod_common: Optional[Mapping]
) -> Optional[Refusal]:
    """The ``A2L-DEF-ALIGNMENT`` refusal for a layout whose components move under
    the MOD_COMMON alignment, or whose MOD_COMMON line is unreadable."""
    moved = _check_module_alignment(layout, counts, mod_common)
    if moved is None:
        return None
    if len(moved) == 2:
        cls, word = moved
        return Refusal(
            "A2L-DEF-ALIGNMENT",
            f"{name_echo}: the MOD_COMMON line {cls} {word} cannot be read",
        )
    component, a, b = moved
    return Refusal(
        "A2L-DEF-ALIGNMENT",
        f"{name_echo}: {component} of the record layout {layout['name']} lies at "
        f"offset {a}, or at {b} under the MOD_COMMON alignment",
    )


def _find_axis_object(
    ref: str, axis_pts_by_name: dict
) -> Optional[tuple[dict, tuple[str, ...], Optional[dict]]]:
    """The first AXIS_PTS section of ``ref`` with its ten positional header words
    and its resolved layout section, or ``None``."""
    return axis_pts_by_name.get(ref)


def _read_fixed_rule(
    axis_name: str, header: tuple[str, ...], axis_section: dict, point_count: int
) -> tuple[str, tuple] | Refusal:
    """Read a FIX_AXIS's parameters and check them (.98, .141, .147, .99): the
    ``fixed_rule`` is the parameters (no point built), each an ``int`` where
    integral."""
    par: Optional[tuple[str, str, str]] = None
    par_dist: Optional[tuple[str, str, str]] = None
    for i, word in enumerate(header):
        if word == "FIX_AXIS_PAR" and par is None and len(header) - i > 3:
            par = (header[i + 1], header[i + 2], header[i + 3])
        elif word == "FIX_AXIS_PAR_DIST" and par_dist is None and len(header) - i > 3:
            par_dist = (header[i + 1], header[i + 2], header[i + 3])
    list_numbers: Optional[list[str]] = None
    for child in axis_section.get("children") or []:
        if child.get("name") == "FIX_AXIS_PAR_LIST":
            tokens = _flatten_body_tokens(
                [child.get("meta", "") or ""] + (child.get("lines") or [])
            )
            list_numbers = tokens
            break
    if par is not None:
        o_word, s_word, n_word = par
        o = _finite_number(o_word)
        s_or_d = _finite_number(s_word)
        n = _read_count(n_word)
        if o is None or s_or_d is None or n is None:
            return Refusal(
                "A2L-DEF-AXIS-FIX",
                f"{axis_name}: the fixed axis gives a point the system cannot read",
            )
        shift = _read_count(s_word)
        if shift is None or shift > _FIX_SHIFT_BOUND:
            return Refusal(
                "A2L-DEF-AXIS-FIX",
                f"{axis_name}: the fixed axis gives a point the system cannot compute exactly",
            )
        o_num, o_den = _ratio(o)
        den = o_den
        a = o_num
        b = (1 << shift) * den
        if (
            abs(a) > _FIX_MAGNITUDE_BOUND * den
            or abs(a + (n - 1) * b) > _FIX_MAGNITUDE_BOUND * den
        ):
            return Refusal(
                "A2L-DEF-AXIS-FIX",
                f"{axis_name}: the fixed axis gives a point the system cannot compute exactly",
            )
        rule: tuple[str, tuple] = ("PAR", (_to_int_or_float(o), shift, n))
    elif par_dist is not None:
        o_word, d_word, n_word = par_dist
        o = _finite_number(o_word)
        d = _finite_number(d_word)
        n = _read_count(n_word)
        if o is None or d is None or n is None:
            return Refusal(
                "A2L-DEF-AXIS-FIX",
                f"{axis_name}: the fixed axis gives a point the system cannot read",
            )
        o_num, o_den = _ratio(o)
        d_num, d_den = _ratio(d)
        den = max(o_den, d_den)
        a = o_num * (den // o_den)
        b = d_num * (den // d_den)
        if (
            abs(a) > _FIX_MAGNITUDE_BOUND * den
            or abs(a + (n - 1) * b) > _FIX_MAGNITUDE_BOUND * den
        ):
            return Refusal(
                "A2L-DEF-AXIS-FIX",
                f"{axis_name}: the fixed axis gives a point the system cannot compute exactly",
            )
        rule = ("PAR_DIST", (_to_int_or_float(o), _to_int_or_float(d), n))
    elif list_numbers is not None:
        for i, word in enumerate(list_numbers):
            number = _finite_number(word)
            if number is None:
                return Refusal(
                    "A2L-DEF-AXIS-FIX",
                    f"{axis_name}: the fixed axis gives a point the system cannot read",
                )
            list_numbers[i] = _to_int_or_float(number)
        n = len(list_numbers)
        rule = ("PAR_LIST", tuple(list_numbers))
    else:
        return Refusal("A2L-DEF-AXIS-FIX", f"{axis_name}: the fixed axis gives no points")
    if n != point_count:
        return Refusal(
            "A2L-DEF-AXIS-FIX-COUNT",
            f"{axis_name}: the fixed axis gives {n} points and declares {point_count}",
        )
    return rule


def _read_axis(
    name: str,
    name_echo: str,
    byte_order: str,
    letter: str,
    axis_section: dict,
    layout: Optional[Mapping],
    a2l_data: dict,
    maps: dict,
) -> AxisDefinition | Refusal:
    """Build one AXIS_DESCR (R-A2L-DEF.92 … .104, .116.1, .117.1, .141 … .143,
    .147)."""
    axis_name_raw = f"{name}.{letter}"
    axis_name = f"{name_echo}.{letter}"
    tokens = _flatten_body_tokens(
        [axis_section.get("meta", "") or ""] + (axis_section.get("lines") or [])
    )
    header = tuple(tokens)
    axis_kind = header[0] if header else None
    if axis_kind not in _AXIS_KINDS:
        return Refusal(
            "A2L-DEF-AXIS-KIND",
            f"{axis_name}: the system cannot read an axis of the kind "
            f"{_echo(axis_kind) if axis_kind else '(none)'}",
        )

    method_word = header[2] if len(header) > 2 else None
    lower_word = header[4] if len(header) > 4 else None
    upper_word = header[5] if len(header) > 5 else None

    ref: Optional[str] = None
    axis_object_section: Optional[dict] = None
    axis_object_header: Optional[tuple[str, ...]] = None
    axis_object_layout_section: Optional[dict] = None
    axis_object_layout: Optional[Mapping] = None
    axis_object_address: Optional[int] = None
    if axis_kind == "COM_AXIS":
        for i, word in enumerate(header):
            if word == "AXIS_PTS_REF":
                ref = header[i + 1] if i + 1 < len(header) else None
                break
        if ref is None:
            return Refusal(
                "A2L-DEF-AXIS-REF",
                f"{axis_name}: the A2L declares no axis object (none) with an address",
            )
        found = _find_axis_object(ref, maps["axis_pts_by_name"])
        if found is None:
            return Refusal(
                "A2L-DEF-AXIS-REF",
                f"{axis_name}: the A2L declares no axis object {_echo(ref)} with an address",
            )
        axis_object_section, axis_object_header, axis_object_layout_section = found
        axis_object_address = _read_address_word(
            axis_object_header[2] if len(axis_object_header) > 2 else None
        )
        if axis_object_address is None:
            return Refusal(
                "A2L-DEF-AXIS-REF",
                f"{axis_name}: the A2L declares no axis object {_echo(ref)} with an address",
            )
        axis_object_layout_name = (
            axis_object_header[4] if len(axis_object_header) > 4 else None
        )
        axis_object_layout = _read_record_layout(
            axis_object_layout_name, a2l_data, axis_name, maps, axis_object_layout_section
        )
        if axis_object_layout is None:
            return Refusal(
                "A2L-DEF-AXIS-LAYOUT",
                f"{axis_name}: the axis object {_echo(ref)} has no record layout "
                "with AXIS_PTS_X",
            )
        if isinstance(axis_object_layout, Refusal):
            return axis_object_layout
        if _find_component(axis_object_layout, "AXIS_PTS_X") is None:
            return Refusal(
                "A2L-DEF-AXIS-LAYOUT",
                f"{axis_name}: the axis object {_echo(ref)} has no record layout "
                "with AXIS_PTS_X",
            )

    max_word = (
        axis_object_header[7]
        if axis_kind == "COM_AXIS" and axis_object_header is not None and len(axis_object_header) > 7
        else (header[3] if len(header) > 3 else None)
    )
    point_count = _read_count(max_word) if max_word is not None else None
    if point_count is None or point_count < 1:
        return Refusal(
            "A2L-DEF-AXIS-MAX",
            f"{axis_name}: the axis declares no point count the system can read",
        )
    if point_count > _MAX_AXIS_POINTS:
        return Refusal(
            "A2L-DEF-AXIS-MAX",
            f"{axis_name}: the axis declares {point_count} points, more than 1048576",
        )

    fixed_rule: Optional[tuple[str, tuple]] = None
    if axis_kind == "FIX_AXIS":
        fixed_rule = _read_fixed_rule(axis_name, header, axis_section, point_count)
        if isinstance(fixed_rule, Refusal):
            return fixed_rule

    object_axis_component = None
    if layout is not None and not isinstance(layout, Refusal):
        object_axis_component = _find_component(layout, f"AXIS_PTS_{letter}")
    if axis_kind != "STD_AXIS" and object_axis_component is not None:
        layout_name = (
            layout["name"] if layout is not None and not isinstance(layout, Refusal) else "(none)"
        )
        return Refusal(
            "A2L-DEF-LAYOUT-AXIS",
            f"{name_echo}: the record layout {layout_name} holds AXIS_PTS_{letter} "
            f"for an axis of the kind {axis_kind}",
        )
    has_points = not (axis_kind == "STD_AXIS" and object_axis_component is None)

    count_layout = axis_object_layout if axis_kind == "COM_AXIS" else layout
    fixed_count: Optional[int] = None
    if count_layout is not None and not isinstance(count_layout, Refusal):
        fixed_count = count_layout["fixed"].get(letter)
    if fixed_count is not None:
        if fixed_count == 0 or fixed_count > point_count:
            return Refusal(
                "A2L-DEF-AXIS-CURRENT",
                f"{axis_name}: the record holds {fixed_count} points, outside 1 to {point_count}",
            )
        if fixed_count < point_count:
            return Refusal(
                "A2L-DEF-AXIS-PARTIAL",
                f"{axis_name}: the record holds {fixed_count} of its {point_count} points "
                "— a record with fewer points than its maximum is not supported",
            )

    points_fields, points_refusal = _conversion_fields(
        axis_name,
        method_word,
        maps["compu_methods_by_name"],
        maps["compu_tables_by_name"],
        a2l_data.get("compu_tabs_by_name") or {},
        maps["reads"],
    )
    points_datatype: Optional[str] = None
    point_order: Optional[str] = None
    if axis_kind == "COM_AXIS":
        ao_pts = _find_component(axis_object_layout, "AXIS_PTS_X")
        if ao_pts is not None:
            points_datatype = ao_pts[2] if len(ao_pts) > 2 else None
            point_order = ao_pts[3] if len(ao_pts) > 3 else None
    elif axis_kind == "STD_AXIS" and object_axis_component is not None:
        points_datatype = object_axis_component[2] if len(object_axis_component) > 2 else None
        point_order = object_axis_component[3] if len(object_axis_component) > 3 else None
    points_byte_order = (
        _axis_byte_order(axis_object_section, axis_object_layout_section, maps)
        if axis_kind == "COM_AXIS"
        else byte_order
    )
    points_format = _axis_format(header)
    if points_format is not None:
        points_display_format = points_format
        points_decimals = _display_decimals(points_format)
    else:
        points_display_format = points_fields["record_format"]
        points_decimals = points_fields["decimals"]
    points = Definition(
        name=axis_name_raw,
        section="AXIS_DESCR",
        char_type=None,
        kind="enum" if points_fields["kind"] == "enum" else "number",
        address=None,
        byte_length=DATATYPE_SIZES.get(points_datatype) if points_datatype else None,
        datatype=points_datatype,
        byte_order=points_byte_order,
        bit_mask=None,
        bit_mask_text=None,
        conversion_type=points_fields["conversion_type"],
        method_name=method_word,
        display_format=points_display_format,
        decimals=points_decimals,
        unit=points_fields["record_unit"] or "",
        limits=_read_limits(lower_word, upper_word),
        extended_limits=None,
        enum_table=points_fields["enum_table"],
        enum_entries=points_fields["enum_entries"],
        default_text=points_fields["default_text"],
        coeffs_linear=points_fields["coeffs_linear"],
        coeffs=points_fields["coeffs"],
        compu_tab_ref=points_fields["compu_tab_ref"],
        shared_with=None,
        refusal=points_refusal,
        _name_echo=axis_name,
        _table_form=points_fields["table_form"],
    )

    monotony = "STRICT_MON"
    for i, word in enumerate(header):
        if word == "MONOTONY" and i + 1 < len(header):
            monotony = header[i + 1]
            break

    offset: Optional[int] = None
    count_offset: Optional[int] = None
    count_datatype: Optional[str] = None
    axis_object_record: Optional[Definition] = None
    if axis_kind == "COM_AXIS":
        placed = _place_components(axis_object_layout, (point_count,))
        if placed is None or axis_object_address < 0 or (
            axis_object_address + placed[1] - 1 > 0xFFFFFFFF
        ):
            return Refusal(
                "A2L-DEF-AXIS-REF",
                f"{axis_name}: the record of the axis object {_echo(ref)} at "
                f"{_fmt_address(axis_object_address)} cannot be read",
            )
        offsets, end = placed
        offset = offsets.get("AXIS_PTS_X")
        count_offset = offsets.get("NO_AXIS_PTS_X")
        for component in axis_object_layout["components"]:
            if component[0] == "NO_AXIS_PTS_X":
                count_datatype = component[2] if len(component) > 2 else None
                break
        axis_object_record = Definition(
            name=ref,
            section="AXIS_PTS",
            char_type=None,
            kind="",
            address=axis_object_address,
            byte_length=end,
            datatype=None,
            byte_order=points_byte_order,
            bit_mask=None,
            bit_mask_text=None,
            conversion_type=None,
            method_name=None,
            display_format=None,
            decimals=None,
            unit="",
            limits=Limits(None, None, "", ""),
            extended_limits=None,
            enum_table=None,
            enum_entries=(),
            default_text=None,
            coeffs_linear=None,
            coeffs=None,
            compu_tab_ref=None,
            shared_with=None,
            refusal=None,
            record_layout=axis_object_header[4] if len(axis_object_header) > 4 else None,
            element_count=None,
            _name_echo=_echo(ref) if ref is not None else "(none)",
            _table_form=None,
        )

    return AxisDefinition(
        letter=letter,
        axis_kind=axis_kind,
        point_count=point_count,
        points=points,
        point_order=point_order if axis_kind != "FIX_AXIS" else None,
        offset=offset,
        count_offset=count_offset,
        fixed_count=fixed_count,
        fixed_rule=fixed_rule,
        axis_object=ref,
        axis_object_address=axis_object_address,
        axis_object_record=axis_object_record,
        monotony=monotony,
        has_points=has_points,
        count_datatype=count_datatype,
    )


def _describe_array(tag: dict, section: Optional[dict], a2l_data: dict, base: Definition, maps: dict) -> Definition:
    """Build an array, curve or map in the array refusal order (R-A2L-DEF.64
    … .104, .141 … .145, .147, .148, cited .7.1, .7.2)."""
    name_echo = base._name_echo
    kind = base.kind
    matrix = _read_matrix_dim(section)
    matrix_words = matrix[0] if matrix is not None else None

    refusal: Optional[Refusal] = None
    shape: tuple[int, ...] = ()
    datatype = base.datatype
    index_mode: Optional[str] = None
    values_offset = 0
    record_layout_name: Optional[str] = None
    layout: Optional[Mapping] = None
    axes_list: list[AxisDefinition] = []
    shape_refusal: Optional[Refusal] = None

    if matrix is not None and matrix[1] is None:
        refusal = Refusal(
            "A2L-DEF-MATRIX",
            f"{name_echo}: MATRIX_DIM {_dims_text(matrix_words)} is not 1 to 3 whole numbers of at least 1",
        )
    elif (
        kind in ("curve", "map")
        and matrix_words is not None
        and _is_multi_value_matrix(matrix_words)
    ):
        refusal = Refusal(
            "A2L-DEF-MATRIX",
            f"{name_echo}: the system cannot read MATRIX_DIM {_dims_text(matrix_words)} "
            f"on a {kind.upper()}",
        )

    if refusal is None and base.section == "MEASUREMENT":
        header_dt = tag.get("datatype")
        if header_dt in DATATYPE_SIZES:
            datatype = header_dt
        else:
            refusal = Refusal(
                "A2L-DEF-DATATYPE",
                f"{name_echo}: the object declares no datatype the system can read",
            )

    if refusal is None and base.section == "CHARACTERISTIC":
        record_layout_name = tag.get("record_layout_name") or tag.get("deposit")
        layout = _read_record_layout(record_layout_name, a2l_data, name_echo, maps)
        if layout is None:
            layout_echo = _echo(record_layout_name) if record_layout_name else "(none)"
            refusal = Refusal(
                "A2L-DEF-LAYOUT",
                f"{name_echo}: the record layout {layout_echo} is not declared in the A2L",
            )
        elif isinstance(layout, Refusal):
            refusal = layout
        else:
            fnc = _find_component(layout, "FNC_VALUES")
            if fnc is None:
                refusal = Refusal(
                    "A2L-DEF-LAYOUT-VALUES",
                    f"{name_echo}: the record layout {layout['name']} holds no FNC_VALUES",
                )
            else:
                datatype = fnc[2] if len(fnc) > 2 else None
                index_mode = fnc[3] if len(fnc) > 3 else None
    elif refusal is None and base.section == "MEASUREMENT":
        layout_word = None
        for words in _object_line_words(section):
            if words and words[0] == "LAYOUT" and len(words) > 1:
                layout_word = words[1]
                break
        if layout_word is None:
            index_mode = "ROW_DIR"
        elif layout_word in ("ROW_DIR", "COLUMN_DIR"):
            index_mode = layout_word
        else:
            refusal = Refusal(
                "A2L-DEF-LAYOUT-MODE",
                f"{name_echo}: the record layout (none) stores LAYOUT as "
                f"{_echo(layout_word)}, which the system cannot read",
            )

    axis_sections: list[dict] = []
    needed = 0
    if refusal is None and kind in ("curve", "map"):
        axis_sections = [
            child
            for child in (section.get("children") or [])
            if child.get("name") == "AXIS_DESCR"
        ]
        needed = 1 if kind == "curve" else 2
        if len(axis_sections) != needed:
            refusal = Refusal(
                "A2L-DEF-AXES",
                f"{name_echo}: a {kind.upper()} declares {len(axis_sections)} AXIS_DESCR "
                f"and needs {needed}",
            )
        else:
            for letter, axis_section in zip(("X", "Y"), axis_sections):
                axis = _read_axis(
                    base.name, name_echo, base.byte_order, letter, axis_section, layout, a2l_data, maps
                )
                if isinstance(axis, Refusal):
                    refusal = axis
                    break
                axes_list.append(axis)

    if kind == "array":
        result = _array_shape(tag, section, datatype, matrix)
        if isinstance(result, Refusal):
            shape_refusal = result
            shape = matrix[1] if matrix is not None and matrix[1] is not None else ()
        elif result is None:
            shape = ()
        else:
            shape = result
    else:
        if refusal is None and len(axes_list) == needed:
            shape = tuple(axis.point_count for axis in axes_list)

    element_count: Optional[int] = None
    if shape:
        element_count = 1
        for number in shape:
            element_count *= number

    if refusal is None and len(shape) == 3 and index_mode == "COLUMN_DIR":
        refusal = Refusal(
            "A2L-DEF-INDEX-MODE",
            f"{name_echo}: the system cannot read COLUMN_DIR in three dimensions",
        )

    byte_length: Optional[int] = None
    if base.section == "CHARACTERISTIC" and layout is not None and not isinstance(layout, Refusal) and shape:
        if kind == "array":
            size = DATATYPE_SIZES.get(datatype) if datatype else None
            byte_length = element_count * size if (size is not None and element_count is not None) else None
        placed = _place_components(layout, shape)
        if placed is None:
            if kind != "array":
                byte_length = None
        else:
            offsets, end = placed
            values_offset = offsets.get("FNC_VALUES", 0)
            if kind != "array":
                byte_length = end
            new_axes: list[AxisDefinition] = []
            for axis in axes_list:
                if axis.axis_kind == "STD_AXIS":
                    cnt_dt: Optional[str] = None
                    for component in layout["components"]:
                        if component[0] == f"NO_AXIS_PTS_{axis.letter}":
                            cnt_dt = component[2] if len(component) > 2 else None
                            break
                    axis = replace(
                        axis,
                        offset=offsets.get(f"AXIS_PTS_{axis.letter}"),
                        count_offset=offsets.get(f"NO_AXIS_PTS_{axis.letter}"),
                        count_datatype=cnt_dt,
                    )
                new_axes.append(axis)
            axes_list = new_axes
    elif base.section == "MEASUREMENT":
        size = DATATYPE_SIZES.get(datatype) if datatype else None
        byte_length = element_count * size if (size is not None and element_count is not None) else None

    if refusal is None and base.section == "CHARACTERISTIC" and layout is not None and not isinstance(layout, Refusal) and shape:
        mod_common = _module_common(section, maps)
        moved = _alignment_refusal(name_echo, layout, shape, mod_common)
        if moved is not None:
            refusal = moved
        else:
            for axis in axes_list:
                if axis.axis_kind == "COM_AXIS" and axis.axis_object is not None:
                    found = _find_axis_object(axis.axis_object, maps["axis_pts_by_name"])
                    if found is not None:
                        ao_section, _ao_header, ao_layout_section = found
                        ao_layout = _read_record_layout(
                            None, a2l_data, name_echo, maps, ao_layout_section
                        )
                        if ao_layout is not None and not isinstance(ao_layout, Refusal):
                            ao_mod_common = _module_common(ao_section, maps)
                            moved = _alignment_refusal(
                                name_echo, ao_layout, (axis.point_count,), ao_mod_common
                            )
                            if moved is not None:
                                refusal = moved
                                break

    if refusal is None and shape_refusal is not None:
        refusal = shape_refusal

    if refusal is None:
        if base.address is None or byte_length is None:
            refusal = Refusal(
                "A2L-DEF-ADDRESS",
                f"{name_echo}: the object has no address or no length",
            )
        elif (
            byte_length < 1
            or byte_length > MAX_A2L_DECODE_BYTES
            or base.address < 0
            or base.address + byte_length - 1 > 0xFFFFFFFF
        ):
            refusal = Refusal(
                "A2L-DEF-ADDRESS",
                f"{name_echo}: its span of {_number_text(byte_length)} bytes at "
                f"{_number_text(base.address, address=True)} cannot be read",
            )

    bit_mask: Optional[int] = None
    if refusal is None:
        conv_fields, conv_refusal = _conversion_fields(
            name_echo,
            base.method_name,
            maps["compu_methods_by_name"],
            maps["compu_tables_by_name"],
            a2l_data.get("compu_tabs_by_name") or {},
            maps["reads"],
        )
        if conv_refusal is not None:
            refusal = conv_refusal
        elif base.bit_mask_text is not None:
            bit_mask = _parse_bit_mask(base.bit_mask_text)
            if bit_mask is None or not _check_bit_mask(bit_mask, datatype):
                refusal = Refusal(
                    "A2L-DEF-MASK",
                    f"{name_echo}: the bit mask {_echo(base.bit_mask_text)} cannot be "
                    f"applied to {datatype}",
                )

    if refusal is None:
        for axis in axes_list:
            if axis.points.refusal is not None:
                refusal = axis.points.refusal
                break

    return replace(
        base,
        shape=shape,
        element_count=element_count,
        index_mode=index_mode,
        values_offset=values_offset,
        record_layout=record_layout_name,
        axes=tuple(axes_list),
        datatype=datatype,
        byte_length=byte_length,
        bit_mask=bit_mask,
        refusal=refusal,
    )


def _resolve_datatype(
    tag: dict, a2l_data: dict, reads: dict[int, object]
) -> Optional[str]:
    """The datatype: the tag's own word, else the record layout's ``decode_type``
    when that word is in the layout's tokens (R-A2L-022), else the datatype the
    deposit name spells (R-A2L-023; wraps BL-I2-13), else ``None``.

    The layout step is read once per walk (R-A2L-DEF.149): its result is
    ``reads[id(entry)]``, computed at the first object of the walk that names
    the layout and returned as stored at every later call, so the layout's
    first line is scanned once per walk, not once per object.
    """
    datatype = tag.get("datatype")
    if datatype in DATATYPE_SIZES:
        return datatype
    layouts = a2l_data.get("record_layouts_by_name") or {}
    layout_name = tag.get("record_layout_name") or tag.get("deposit")
    entry = layouts.get(layout_name) if layout_name else None
    if entry is not None:
        key = id(entry)
        if key in reads:
            resolved = reads[key]
        else:
            resolved = None
            layout = _resolve_record_layout(layout_name, layouts)
            if layout is not None:
                decode_type = layout.get("decode_type")
                if (
                    decode_type
                    and decode_type in DATATYPE_SIZES
                    and any(
                        token in DATATYPE_SIZES for token in (entry.get("tokens") or [])
                    )
                ):
                    resolved = decode_type
            reads[key] = resolved
        if resolved is not None:
            return resolved
    deposit = str(tag.get("deposit") or "")
    upper = deposit.upper()
    for dt in DATATYPE_SIZES:
        if f"__{dt}_Z" in upper or upper == dt:
            return dt
    return None


def _build_tab_form(
    ref: str, compu_tabs_by_name: dict[str, dict], reads: dict[int, object]
) -> Optional[_TabForm]:
    """The reduced COMPU_TAB form of the frozen parse's ``ref`` (R-A2L-DEF.150),
    built once per walk and stored in ``reads`` under ``id()`` of that entry."""
    entry = compu_tabs_by_name.get(ref)
    if entry is None:
        return None
    key = id(entry)
    if key in reads:
        return reads[key]
    tab_entries = entry.get("entries") or []
    xs = tuple(e[0] for e in tab_entries)
    ys = tuple(e[1] for e in tab_entries)
    x_nan = any(isinstance(xv, float) and math.isnan(xv) for xv in xs)
    form = _TabForm(xs=xs, ys=ys, x_nan=x_nan, ref_echo=_echo(ref))
    reads[key] = form
    return form


def _read_method_record(
    method_name: str,
    compu_methods_by_name: dict[str, dict],
    compu_tables_by_name: dict[str, dict],
    compu_tabs_by_name: dict[str, dict],
    reads: dict[int, object],
) -> Optional[Mapping]:
    """Read the first COMPU_METHOD of ``method_name`` as the conversion method
    record (the words of ``_flatten_body_tokens([meta] + lines)``, comments
    left out): ``<name> <long identifier> <type> <format> <unit>`` then the
    keyword groups ``COEFFS`` + 6, ``COEFFS_LINEAR`` + 2, ``COMPU_TAB_REF`` + 1.

    Read once per walk (R-A2L-DEF.149): the record is ``reads[id(section)]``,
    computed at the first call that names the section and returned as stored at
    every later call.  The stored form is a read-only
    :class:`types.MappingProxyType` of 11 fields: the 6 an object reads
    (``conversion_type``, ``format``, ``unit``, ``coeffs_linear`` and ``coeffs``
    as tuples or ``None``, ``compu_tab_ref``) and the 5 derived at reduction
    (``decimals``, ``type_verdict``, ``type_echo``, ``table_echo``,
    ``table_form``); it holds no ``name``, ``long_identifier``, ``formula`` or
    ``lines``.  A missing positional word is ``None``; a coefficient word that
    is not a finite number is ``None`` (E3S-10).  ``None`` when no map entry
    has the name.
    """
    section = compu_methods_by_name.get(method_name)
    if section is None:
        return None
    key = id(section)
    if key in reads:
        return reads[key]
    tokens = _flatten_body_tokens(
        [section.get("meta", "") or ""] + (section.get("lines") or [])
    )
    conversion_type = tokens[2] if len(tokens) > 2 else None
    fmt = tokens[3] if len(tokens) > 3 else None
    unit = tokens[4] if len(tokens) > 4 else None
    coeffs_linear: Optional[list[Optional[float]]] = None
    coeffs: Optional[list[Optional[float]]] = None
    compu_tab_ref: Optional[str] = None
    i = 5
    n = len(tokens)
    while i < n:
        head = tokens[i]
        if head == "COEFFS" and i + 6 < n:
            coeffs = [_finite_number(tokens[i + j]) for j in range(1, 7)]
            i += 7
            continue
        if head == "COEFFS_LINEAR" and i + 1 < n:
            a = _finite_number(tokens[i + 1])
            b = _finite_number(tokens[i + 2]) if i + 2 < n else None
            coeffs_linear = [a, b]
            i += 3
            continue
        if head == "COMPU_TAB_REF" and i + 1 < n:
            compu_tab_ref = tokens[i + 1]
            i += 2
            continue
        i += 1
    decimals = _display_decimals(fmt)
    type_verdict = (
        conversion_type if conversion_type in _SUPPORTED_CONVERSION_TYPES else None
    )
    type_echo = _echo(conversion_type) if conversion_type else "(none)"
    table_echo = _echo(compu_tab_ref) if compu_tab_ref else "(none)"
    table_form = None
    if type_verdict == "TAB_VERB":
        if compu_tab_ref is not None:
            table_form = _read_enum_table(compu_tab_ref, compu_tables_by_name, reads)
    elif type_verdict in ("TAB_INTP", "TAB_NOINTP"):
        if compu_tab_ref is not None:
            table_form = _build_tab_form(compu_tab_ref, compu_tabs_by_name, reads)
    form: Mapping = MappingProxyType(
        {
            "conversion_type": conversion_type,
            "format": fmt,
            "unit": unit,
            "coeffs_linear": None if coeffs_linear is None else tuple(coeffs_linear),
            "coeffs": None if coeffs is None else tuple(coeffs),
            "compu_tab_ref": compu_tab_ref,
            "decimals": decimals,
            "type_verdict": type_verdict,
            "type_echo": type_echo,
            "table_echo": table_echo,
            "table_form": table_form,
        }
    )
    reads[key] = form
    return form


def _build_enum_form(
    section_kind: str,
    entries: tuple[EnumEntry, ...],
    default_text: Optional[str],
) -> _EnumForm:
    """Reduce the parsed enum table to its immutable form: the public entries,
    the once-cleaned display texts and the private index (a dict from raw to the
    first entry for COMPU_VTAB; a segmentation over the sorted ends for
    COMPU_VTAB_RANGE), each of one lookup per element."""
    texts = tuple(_clean(entry.text) for entry in entries)
    default_display = _clean(default_text)
    empty: Mapping = MappingProxyType({})
    if section_kind == "COMPU_VTAB":
        first_of: dict[float, int] = {}
        for pos, entry in enumerate(entries):
            raw = entry.raw
            if isinstance(raw, float) and math.isnan(raw):
                continue
            if raw not in first_of:
                first_of[raw] = pos
        return _EnumForm(
            section_kind=section_kind,
            entries=entries,
            default_text=default_text,
            texts=texts,
            default_display=default_display,
            first_of=MappingProxyType(first_of),
            ends=(),
            at_end=(),
            between=(),
        )
    # COMPU_VTAB_RANGE: the sorted distinct ends of the ranges that can match
    # (min <= max, neither NaN; +-inf kept) and, per end and per open gap, the
    # position of the first range in file order that covers it.
    valid: list[tuple[int, float, float]] = []
    end_values: list[float] = []
    for pos, entry in enumerate(entries):
        lo = entry.raw
        hi = entry.raw_max
        if hi is None:
            continue
        if (isinstance(lo, float) and math.isnan(lo)) or (
            isinstance(hi, float) and math.isnan(hi)
        ):
            continue
        if lo <= hi:
            valid.append((pos, lo, hi))
            end_values.append(lo)
            end_values.append(hi)
    ends = tuple(sorted(set(end_values)))
    by_min = sorted(valid, key=lambda item: item[1])
    at_end: list[Optional[int]] = []
    heap: list[tuple[int, float, float]] = []
    ri = 0
    for end in ends:
        while ri < len(by_min) and by_min[ri][1] <= end:
            heapq.heappush(heap, by_min[ri])
            ri += 1
        while heap and heap[0][2] < end:
            heapq.heappop(heap)
        at_end.append(heap[0][0] if heap else None)
    between: list[Optional[int]] = []
    heap = []
    ri = 0
    for idx in range(len(ends) - 1):
        end = ends[idx]
        next_end = ends[idx + 1]
        while ri < len(by_min) and by_min[ri][1] <= end:
            heapq.heappush(heap, by_min[ri])
            ri += 1
        while heap and heap[0][2] < next_end:
            heapq.heappop(heap)
        between.append(heap[0][0] if heap else None)
    return _EnumForm(
        section_kind=section_kind,
        entries=entries,
        default_text=default_text,
        texts=texts,
        default_display=default_display,
        first_of=empty,
        ends=ends,
        at_end=tuple(at_end),
        between=tuple(between),
    )


def _read_enum_table(
    table_name: str, compu_tables_by_name: dict[str, dict], reads: dict[int, object]
) -> Optional[_EnumForm]:
    """Read the first COMPU_VTAB / COMPU_VTAB_RANGE of ``table_name`` as the
    enum form (:class:`_EnumForm`), or ``None`` when no map entry has the name.

    Read once per walk (R-A2L-DEF.149): the form is ``reads[id(section)]``,
    built at the first call that names the section and returned as stored (the
    same form, held by reference) at every later call.

    The count is a run of ASCII digits of at most 9 digits, else there are no
    entries.  Entries are read in file order, count-driven, at most ``n``; an
    entry whose raw / min / max is not a number is skipped; the text is kept as
    text.  A ``DEFAULT_VALUE`` word is recognised only where a raw / min / max
    is expected (E3A-16); the word after it is the default text.
    """
    section = compu_tables_by_name.get(table_name)
    if section is None:
        return None
    key = id(section)
    if key in reads:
        return reads[key]
    section_kind = section.get("name")
    tokens = _flatten_body_tokens(
        [section.get("meta", "") or ""] + (section.get("lines") or [])
    )
    if section_kind == "COMPU_VTAB":
        if len(tokens) < 4 or tokens[2] != "TAB_VERB":
            count = None
        else:
            count = _read_count(tokens[3])
        pos = 4
    else:  # COMPU_VTAB_RANGE
        count = _read_count(tokens[2]) if len(tokens) > 2 else None
        pos = 3

    entries: list[EnumEntry] = []
    default_text: Optional[str] = None
    n = len(tokens)
    i = pos
    if count is not None:
        read = 0
        while read < count and i < n:
            if tokens[i] == "DEFAULT_VALUE":
                break
            if section_kind == "COMPU_VTAB":
                if i + 1 >= n:
                    break
                raw = _to_float(tokens[i])
                text = tokens[i + 1]
                i += 2
                if raw is not None:
                    entries.append(EnumEntry(raw, None, text))
            else:
                if i + 2 >= n:
                    break
                raw_min = _to_float(tokens[i])
                raw_max = _to_float(tokens[i + 1])
                text = tokens[i + 2]
                i += 3
                if raw_min is not None and raw_max is not None:
                    entries.append(EnumEntry(raw_min, raw_max, text))
            read += 1
    if i < n and tokens[i] == "DEFAULT_VALUE":
        if i + 1 < n:
            default_text = tokens[i + 1]
    form = _build_enum_form(section_kind, tuple(entries), default_text)
    reads[key] = form
    return form


def _read_object_lines(section: Optional[dict]) -> dict:
    """The object record's words: ``header``, ``format``, ``extended_limits``,
    ``unit``, ``bit_mask`` (the raw word, readable or not, for every kind),
    ``bit_mask_count`` and ``byte_order_count`` (the numbers of those live
    keywords in the record, for the two Inc 2b residual guards).

    ``header`` is the first 8 words of a MEASUREMENT or the first 9 of a
    CHARACTERISTIC; the other keys are the first of each keyword after the
    header (``FORMAT``, ``EXTENDED_LIMITS`` + two finite numbers, ``PHYS_UNIT``
    / ``UNIT``, ``BIT_MASK``).  Section ``None`` → every key empty.
    """
    result: dict = {
        "header": [],
        "format": None,
        "extended_limits": None,
        "unit": None,
        "bit_mask": None,
        "bit_mask_count": 0,
        "byte_order_count": 0,
    }
    if section is None:
        return result
    tokens = _flatten_body_tokens(
        [section.get("meta", "") or ""] + (section.get("lines") or [])
    )
    header_len = 8 if section.get("name") == "MEASUREMENT" else 9
    result["header"] = tokens[:header_len]
    body = tokens[header_len:]
    result["bit_mask_count"] = sum(1 for word in body if word == "BIT_MASK")
    result["byte_order_count"] = sum(1 for word in body if word == "BYTE_ORDER")
    i = 0
    n = len(body)
    while i < n:
        word = body[i]
        if word == "FORMAT" and result["format"] is None and i + 1 < n:
            result["format"] = body[i + 1]
            i += 1
        elif word == "EXTENDED_LIMITS" and result["extended_limits"] is None and i + 2 < n:
            lo = _finite_number(body[i + 1])
            hi = _finite_number(body[i + 2])
            if lo is not None and hi is not None:
                result["extended_limits"] = Limits(lo, hi, body[i + 1], body[i + 2])
                i += 2
            # A line that does not hold two numbers consumes only its keyword, so the
            # next keyword (e.g. FORMAT) is still read (R-A2L-DEF.21/1, .22).
        elif word in ("PHYS_UNIT", "UNIT") and result["unit"] is None and i + 1 < n:
            result["unit"] = body[i + 1]
            i += 1
        elif word == "BIT_MASK" and result["bit_mask"] is None and i + 1 < n:
            result["bit_mask"] = body[i + 1]
            i += 1
        i += 1
    return result


def _check_bit_mask(mask: int, datatype: str) -> bool:
    """True when the mask fits its datatype: mask > 0, not a float datatype,
    below the datatype's bit width, and (for a signed datatype) not holding
    both bit 0 and the sign bit.  Only reached with a resolved datatype.
    """
    if mask <= 0:
        return False
    if datatype in _FLOAT_DATATYPES:
        return False
    size = DATATYPE_SIZES.get(datatype)
    if size is None:
        return False
    if mask >= (1 << (8 * size)):
        return False
    if datatype in _SIGNED_DATATYPES:
        sign_bit = 1 << (8 * size - 1)
        if (mask & 1) and (mask & sign_bit):
            return False
    return True


def _display_decimals(display_format: Optional[str]) -> Optional[int]:
    """The decimals of the display format ``%[<length>][.<decimals>]``
    optionally ended by ``f``: a decimals run of more than 2 digits gives 17
    (no ``int()`` on a long run), else ``min(<decimals>, 17)``; ``None`` when
    the text gives no decimals or is not of that form.
    """
    if display_format is None:
        return None
    text = display_format
    if not text.startswith("%"):
        return None
    i = 1
    n = len(text)
    while i < n and text[i] in _ASCII_DIGITS:
        i += 1
    if i >= n or text[i] != ".":
        return None
    i += 1
    start = i
    while i < n and text[i] in _ASCII_DIGITS:
        i += 1
    digits = text[start:i]
    if not digits:
        return None
    if text[i:] not in ("", "f"):
        return None
    if len(digits) > 2:
        return 17
    return min(int(digits), 17)


def decode_definition(
    definition: Definition, a2l_data: dict, image: Mapping[int, int]
) -> Decoded | Refusal:
    """Decode the stored bytes of a definition into a :class:`Decoded` (or its
    refusal when it has one, R-A2L-DEF.25).

    Text → ``Decoded(None, s, s)``; enum → ``Decoded(stored, entry text or
    None, _enum_text(...))``; number → the stored value for
    ``NO_COMPU_METHOD``, ``_table_value`` for a TAB form, else
    ``_apply_compu_method``; a value that is not a number, or a status
    ``error``, → ``A2L-DEF-DECODE``.  Reads ``image`` and ``a2l_data`` only.

    Args:
        definition (Definition): The definition to decode.
        a2l_data (dict): The parse payload (its ``compu_tabs_by_name`` serves
            the numeric conversion).
        image (Mapping[int, int]): address → byte, read only.

    Returns:
        Decoded | Refusal: the decoded value, or the definition's refusal.

    Raises:
        None.
    """
    if definition.refusal is not None:
        return definition.refusal
    name_echo = (
        definition._name_echo
        if definition._name_echo is not None
        else _echo(definition.name)
    )
    if definition.kind in ("array", "curve", "map"):
        return Refusal(
            "A2L-DEF-ELEMENTS",
            f"{name_echo}: it holds {definition.element_count} values — decode and "
            "encode it value by value",
        )
    stored = _read_stored_value(definition, image, name_echo)
    if isinstance(stored, Refusal):
        return stored
    return _decode_stored(definition, a2l_data, stored)


def _decode_stored(
    definition: Definition, a2l_data: dict, stored: int | float | bytes, suffix: str = ""
) -> Decoded | Refusal:
    """The conversion half of Inc 2's ``decode_definition``, moved unchanged and
    given a ``suffix`` (``[<i>]`` for an element, ``[<k>]`` for an axis point)
    written after the name echo in every refusal (R-A2L-DEF.119, E3S3-27).
    """
    label = (
        definition._name_echo
        if definition._name_echo is not None
        else _echo(definition.name)
    ) + suffix
    if definition.kind == "text":
        text = _ascii_text(stored)
        return Decoded(None, text, text)
    if definition.kind == "enum":
        entry_text = _enum_entry_text(definition, stored)
        return Decoded(stored, entry_text, _enum_text(definition, stored))
    table_form = definition._table_form
    if definition.method_name == "NO_COMPU_METHOD":
        value: object = stored
    elif isinstance(table_form, _TabForm):
        if table_form.x_nan:
            return Refusal(
                "A2L-DEF-DECODE",
                f"{label}: the table {table_form.ref_echo} has an x that is not a number",
            )
        value, table_error = _table_value(
            table_form, stored, definition.conversion_type == "TAB_INTP"
        )
        if table_error:
            return Refusal("A2L-DEF-DECODE", f"{label}: {table_error}")
    else:
        method = {
            "conversion_type": definition.conversion_type,
            "coeffs_linear": definition.coeffs_linear,
            "coeffs": definition.coeffs,
            "compu_tab_ref": definition.compu_tab_ref,
        }
        value, status, error = _apply_compu_method(
            stored,
            method,
            a2l_data.get("compu_tabs_by_name") or {},
            (definition.limits.lower, definition.limits.upper),
        )
        if status == "error":
            return Refusal("A2L-DEF-DECODE", f"{label}: {error}")
    if not isinstance(value, (int, float)):
        if isinstance(table_form, _TabForm):
            ref_echo = table_form.ref_echo
        elif definition.compu_tab_ref is not None:
            ref_echo = _echo(definition.compu_tab_ref)
        else:
            ref_echo = "(none)"
        return Refusal(
            "A2L-DEF-DECODE",
            f"{label}: the table {ref_echo} gives a value that is not a number",
        )
    return Decoded(stored, value, display_text(definition, value))


def element_name(definition: Definition, position: tuple) -> str:
    """An element index → ``<name>[<i>]`` / ``<name>[<i>,<j>]`` / …; an axis
    point ``(letter, k)`` → ``<name>.<letter>[<k>]`` (I-2; zero-based)."""
    if isinstance(position, tuple) and position and isinstance(position[0], str):
        letter, k = position
        return f"{definition.name}.{letter}[{k}]"
    return f"{definition.name}[{','.join(str(i) for i in position)}]"


def _element_indexes(shape: tuple[int, ...]):
    """Yield the element indexes in element order: the first index changing
    fastest (R-A2L-DEF.106)."""
    if not shape:
        return
    if len(shape) == 1:
        for i in range(shape[0]):
            yield (i,)
        return
    for tail in _element_indexes(shape[1:]):
        for i in range(shape[0]):
            yield (i,) + tail


def _element_offset(definition: Definition, index: tuple[int, ...]) -> int:
    """The byte offset in the record of element ``index`` (R-A2L-DEF.106, .107)."""
    size = DATATYPE_SIZES.get(definition.datatype) or 0
    if definition.index_mode == "COLUMN_DIR":
        if len(index) == 1:
            linear = index[0]
        else:
            i, j = index[0], index[1]
            linear = j + definition.shape[1] * i
    else:
        linear = 0
        stride = 1
        for pos, value in enumerate(index):
            linear += value * stride
            if pos < len(definition.shape):
                stride *= definition.shape[pos]
    return definition.values_offset + size * linear


def _point_offset(axis: AxisDefinition, k: int) -> int:
    """The byte offset of point ``k`` in its record (R-A2L-DEF.108, .109)."""
    size = DATATYPE_SIZES.get(axis.points.datatype) or 0
    if axis.point_order == "INDEX_DECR":
        return axis.offset + size * (axis.point_count - 1 - k)
    return axis.offset + size * k


def _fixed_points(fixed_rule: tuple[str, tuple]) -> tuple[int | float, ...]:
    """The stored points of a FIX_AXIS, computed exactly at decode (R-A2L-DEF.110
    … .112, .147): each point an ``int`` when the ratio divides, else the double
    nearest it."""
    kind, params = fixed_rule
    if kind == "PAR":
        o, s, n = params
        o_num, o_den = _ratio(o)
        den = o_den
        a = o_num
        b = (1 << s) * den
        return tuple(_rational_to_number(a + k * b, den) for k in range(n))
    if kind == "PAR_DIST":
        o, d, n = params
        o_num, o_den = _ratio(o)
        d_num, d_den = _ratio(d)
        den = max(o_den, d_den)
        a = o_num * (den // o_den)
        b = d_num * (den // d_den)
        return tuple(_rational_to_number(a + k * b, den) for k in range(n))
    return tuple(params)


def _axis_for(definition: Definition, letter: str) -> AxisDefinition:
    """The axis of ``letter`` in ``definition.axes``."""
    for axis in definition.axes:
        if axis.letter == letter:
            return axis
    raise KeyError(letter)


def _element_definition(
    definition: Definition, position: tuple, named: bool = True
) -> Definition:
    """The element definition of one element or axis point (a
    ``dataclasses.replace``; R-A2L-DEF.105, .121, .122)."""
    if isinstance(position, tuple) and position and isinstance(position[0], str):
        letter, k = position
        axis = _axis_for(definition, letter)
        points = axis.points
        if axis.axis_kind == "FIX_AXIS":
            address: Optional[int] = None
        else:
            base_address = (
                definition.address
                if axis.axis_kind == "STD_AXIS"
                else axis.axis_object_address
            )
            address = base_address + _point_offset(axis, k)
        name = element_name(definition, position) if named else points.name
        return replace(points, name=name, address=address, refusal=None)
    name = element_name(definition, position) if named else definition.name
    kind = "enum" if definition.conversion_type == "TAB_VERB" else "number"
    address = definition.address + _element_offset(definition, position)
    byte_length = DATATYPE_SIZES.get(definition.datatype) if definition.datatype else None
    return replace(
        definition,
        name=name,
        kind=kind,
        address=address,
        byte_length=byte_length,
        refusal=None,
        shape=(),
        element_count=1,
        index_mode=None,
        values_offset=0,
        record_layout=None,
        axes=(),
    )


def _current_count(axis: AxisDefinition, record: bytes) -> int | Refusal:
    """The current count of an axis's record: the NO_AXIS_PTS component's number
    in the image, the point count when there is none, or the ``.116.2`` /
    ``.117.2`` refusal (R-A2L-DEF.115, .116.2, .117.2)."""
    if axis.count_offset is None:
        return axis.point_count
    size = DATATYPE_SIZES.get(axis.count_datatype)
    label = axis.points._name_echo or _echo(axis.points.name)
    if size is None:
        return Refusal(
            "A2L-DEF-AXIS-CURRENT",
            f"{label}: the record holds (none) points, outside 1 to {axis.point_count}",
        )
    count = _decode_scalar(
        record[axis.count_offset : axis.count_offset + size],
        axis.count_datatype,
        axis.points.byte_order,
    )
    if isinstance(count, int):
        if count == axis.point_count:
            return count
        if 1 <= count < axis.point_count:
            return Refusal(
                "A2L-DEF-AXIS-PARTIAL",
                f"{label}: the record holds {count} of its {axis.point_count} points "
                "— a record with fewer points than its maximum is not supported",
            )
        return Refusal(
            "A2L-DEF-AXIS-CURRENT",
            f"{label}: the record holds {count} points, outside 1 to {axis.point_count}",
        )
    return Refusal(
        "A2L-DEF-AXIS-CURRENT",
        f"{label}: the record holds (none) points, outside 1 to {axis.point_count}",
    )


def _decode_axis(
    definition: Definition,
    axis: AxisDefinition,
    a2l_data: dict,
    image: Mapping[int, int],
    record: bytes,
) -> DecodedAxis | Refusal:
    """Decode one axis's points (R-A2L-DEF.100, .105, .108 … .115, .118)."""
    letter = axis.letter
    points = axis.points
    if axis.axis_kind == "FIX_AXIS":
        decoded = tuple(
            _decode_stored(points, a2l_data, point, suffix=f"[{k}]")
            for k, point in enumerate(_fixed_points(axis.fixed_rule))
        )
        return DecodedAxis(letter, decoded)
    if axis.axis_kind == "STD_AXIS" and not axis.has_points:
        return DecodedAxis(letter, None)
    if axis.axis_kind == "COM_AXIS":
        rec_def = axis.axis_object_record
        missing = 0
        values: list[int] = []
        for offset in range(rec_def.byte_length):
            current = rec_def.address + offset
            if current not in image:
                missing += 1
            else:
                values.append(image[current] & 0xFF)
        if missing:
            return Refusal(
                "A2L-DEF-AXIS-BYTES",
                f"{points._name_echo}: {_number_text(missing)} of the "
                f"{_number_text(rec_def.byte_length)} bytes of the axis object "
                f"{_echo(axis.axis_object) if axis.axis_object else '(none)'} are not in the image",
            )
        record_bytes = bytes(values)
    else:
        record_bytes = record
    count = _current_count(axis, record_bytes)
    if isinstance(count, Refusal):
        return count
    result: list[Decoded | Refusal] = []
    for k in range(count):
        element = _element_definition(definition, (letter, k), named=False)
        stored = _read_stored_value(element, image, points._name_echo)
        if isinstance(stored, Refusal):
            result.append(stored)
        else:
            result.append(_decode_stored(element, a2l_data, stored, suffix=f"[{k}]"))
    return DecodedAxis(letter, tuple(result))


def decode_values(
    definition: Definition, a2l_data: dict, image: Mapping[int, int]
) -> DecodedValues | Refusal:
    """Decode every element and axis point of an array, curve or map
    (R-A2L-DEF.105 … .119, .146), or one scalar element (R-A2L-DEF.146)."""
    if definition.refusal is not None:
        return definition.refusal
    name_echo = (
        definition._name_echo
        if definition._name_echo is not None
        else _echo(definition.name)
    )
    if definition.kind in ("number", "enum", "text"):
        return DecodedValues((decode_definition(definition, a2l_data, image),), ())
    missing = 0
    record_values: list[int] = []
    for offset in range(definition.byte_length):
        current = definition.address + offset
        if current not in image:
            missing += 1
        else:
            record_values.append(image[current] & 0xFF)
    if missing:
        return Refusal(
            "A2L-DEF-BYTES",
            f"{name_echo}: {_number_text(missing)} of its "
            f"{_number_text(definition.byte_length)} bytes are not in the image",
        )
    record = bytes(record_values)
    axes: list[DecodedAxis] = []
    for axis in definition.axes:
        decoded = _decode_axis(definition, axis, a2l_data, image, record)
        if isinstance(decoded, Refusal):
            return decoded
        axes.append(decoded)
    values: list[Decoded | Refusal] = []
    for index in _element_indexes(definition.shape):
        element = _element_definition(definition, index, named=False)
        stored = _read_stored_value(element, image, name_echo)
        if isinstance(stored, Refusal):
            values.append(stored)
        else:
            values.append(
                _decode_stored(
                    element,
                    a2l_data,
                    stored,
                    suffix=f"[{','.join(str(i) for i in index)}]",
                )
            )
    return DecodedValues(tuple(values), tuple(axes))


def _read_stored_value(
    definition: Definition, image: Mapping[int, int], name_echo: str
) -> int | float | bytes | Refusal:
    """Read the span's bytes and the stored value.

    ``n`` addresses not in the image → ``A2L-DEF-BYTES``.  Else: kind text →
    the bytes; a bit mask → the masked field shifted right by the mask shift
    (unsigned); FLOAT16_IEEE → IEEE 754 binary16; else ``_decode_scalar``.
    """
    address = definition.address
    length = definition.byte_length
    missing = 0
    values: list[int] = []
    for offset in range(length):
        current = address + offset
        if current not in image:
            missing += 1
        else:
            values.append(image[current] & 0xFF)
    if missing:
        return Refusal(
            "A2L-DEF-BYTES",
            f"{name_echo}: {_number_text(missing)} of its "
            f"{_number_text(length)} bytes are not in the image",
        )
    raw = bytes(values)
    if definition.kind == "text":
        return raw
    if definition.bit_mask is not None:
        word = int.from_bytes(raw, definition.byte_order)
        return (word & definition.bit_mask) >> _mask_shift(definition.bit_mask)
    if definition.datatype == "FLOAT16_IEEE":
        return _decode_binary16(raw, definition.byte_order)
    return _decode_scalar(raw, definition.datatype, definition.byte_order)


def _enum_position(form: _EnumForm, stored: int | float) -> Optional[int]:
    """The position in ``form.entries`` of the first entry that holds ``stored``
    (one lookup in the form's index), else ``None``."""
    if form.section_kind == "COMPU_VTAB":
        return form.first_of.get(stored)
    if isinstance(stored, float) and math.isnan(stored):
        return None
    ends = form.ends
    i = bisect_left(ends, stored)
    if i < len(ends) and ends[i] == stored:
        return form.at_end[i]
    if 0 < i < len(ends):
        return form.between[i - 1]
    return None


def _enum_entry_text(definition: Definition, stored: int | float) -> Optional[str]:
    """The raw text of the first entry in file order that holds ``stored``: one
    lookup in the enum form (the text by reference), else the linear first match
    of a hand-built definition (``_table_form`` ``None``)."""
    form = definition._table_form
    if isinstance(form, _EnumForm):
        pos = _enum_position(form, stored)
        return form.entries[pos].text if pos is not None else None
    for entry in definition.enum_entries:
        if entry.raw_max is None:
            if entry.raw == stored:
                return entry.text
        elif entry.raw <= stored <= entry.raw_max:
            return entry.text
    return None


def _enum_text(definition: Definition, stored: int | float) -> str:
    """The display text for an enum stored value: the first matching entry's
    cleaned text, else the default's, else ``<raw> (no text)``.  With the enum
    form the text is its stored string (cleaned once, by reference); without it
    the linear match is ``_clean``ed per call (R-A2L-DEF.137)."""
    form = definition._table_form
    if isinstance(form, _EnumForm):
        pos = _enum_position(form, stored)
        if pos is not None:
            return form.texts[pos]
        if form.default_display is not None:
            return form.default_display
        return f"{_raw_text(stored)} (no text)"
    entry = _enum_entry_text(definition, stored)
    if entry is not None:
        return _clean(entry)
    if definition.default_text is not None:
        return _clean(definition.default_text)
    return f"{_raw_text(stored)} (no text)"


def _first_equal_below(xs: tuple[float, ...], x: float, lo: int, d: float) -> int:
    """The first index ``j`` in ``[0, lo]`` whose distance ``x - xs[j]`` equals
    ``d`` (the rounded least distance below ``x``): the frozen ``min`` takes the
    first such entry.  Below ``x`` the distance does not increase with ``j``."""
    low, high = 0, lo
    while low < high:
        mid = (low + high) // 2
        if x - xs[mid] <= d:
            high = mid
        else:
            low = mid + 1
    return low


def _table_value(form: _TabForm, stored: int | float, interpolate: bool) -> tuple[object, str]:
    """The TAB_INTP / TAB_NOINTP value of ``stored`` on the reduced COMPU_TAB in
    O(log n), giving the (value, error) the frozen ``_table_lookup`` gives."""
    xs = form.xs
    ys = form.ys
    n = len(xs)
    if n == 0:
        return None, "lookup table is empty"
    x = float(stored)
    if not interpolate:
        i = bisect_left(xs, x)
        if i < n and xs[i] == x:
            return ys[i], ""
        lo: Optional[int] = None
        hi: Optional[int] = None
        if i > 0:
            lo = bisect_left(xs, xs[i - 1])
        if i < n:
            hi = i
        if lo is None:
            return ys[hi], ""
        if hi is None:
            d = x - xs[lo]
            return ys[_first_equal_below(xs, x, lo, d)], ""
        d_lo = x - xs[lo]
        d_hi = xs[hi] - x
        if d_lo <= d_hi:
            return ys[_first_equal_below(xs, x, lo, d_lo)], ""
        return ys[hi], ""
    if x <= xs[0]:
        return ys[0], ""
    if x >= xs[-1]:
        return ys[-1], ""
    i = bisect_left(xs, x)
    if not (0 < i < n and xs[i - 1] <= x <= xs[i]):
        return None, "value outside interpolation range"
    lx, ly = xs[i - 1], ys[i - 1]
    rx, ry = xs[i], ys[i]
    lyf = _to_float(ly)
    ryf = _to_float(ry)
    if lyf is None or ryf is None:
        return ly, ""
    if rx == lx:
        return lyf, ""
    ratio = (x - lx) / (rx - lx)
    return lyf + ratio * (ryf - lyf), ""


def _ascii_text(raw: bytes) -> str:
    """The bytes before the first 0x00 (all when none is 0x00), each 0x20-0x7E
    as its ASCII character and every other byte as U+FFFD."""
    out: list[str] = []
    for byte in raw:
        if byte == 0:
            break
        if 0x20 <= byte <= 0x7E:
            out.append(chr(byte))
        else:
            out.append("\uFFFD")
    return "".join(out)


def display_text(definition: Definition, value: int | float) -> str:
    """The display text of a decoded number (I-2; Inc 3 reuses it per element).

    In order (E3A-04): non-finite → ``nan``/``inf``/``-inf``; an integer
    datatype whose conversion is ``NO_COMPU_METHOD`` or IDENTICAL → the integer
    text; ``decimals`` with a float datatype or a conversion other than none /
    IDENTICAL → exactly ``d`` digits after the point (d ≥ 15 first rounds to 15
    significant digits); else the 15-significant-digit text (``%.15g``).  No
    unit.

    Args:
        definition (Definition): The definition (datatype, conversion type,
            decimals).
        value (int | float): The physical value to show.

    Returns:
        str: the display text.

    Raises:
        None.
    """
    if not math.isfinite(value):
        if math.isnan(value):
            return "nan"
        return "inf" if value > 0 else "-inf"
    datatype = definition.datatype
    conversion = definition.conversion_type
    if (
        datatype is not None
        and datatype not in _FLOAT_DATATYPES
        and conversion in (None, "IDENTICAL")
    ):
        return str(int(value))
    if definition.decimals is not None and (
        (datatype is not None and datatype in _FLOAT_DATATYPES)
        or conversion not in (None, "IDENTICAL")
    ):
        d = definition.decimals
        if d >= 15:
            # Round to 15 significant digits, then write exactly d decimals of that
            # decimal value (E3A-06); a float round-trip would bring back binary digits.
            return format(Decimal(f"{value:.15g}"), f".{d}f")
        return f"{value:.{d}f}"
    return f"{value:.15g}"


def _operator_echo(text: str) -> str:
    """Write an operator text into a message: its first 256 characters, each
    control character (U+0000-U+001F, U+007F, U+0080-U+009F) as U+FFFD, spaces
    and all other Unicode preserved, then ``…`` when the text is longer
    (R-A2L-DEF.151/7)."""
    cut = len(text) > _ECHO_LIMIT
    body = text[:_ECHO_LIMIT]
    return _clean(body) + (_ELLIPSIS if cut else "")


_NUMBER_TEXT_RE = re.compile(
    r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?", re.ASCII
)


def _parse_number_text(text: str) -> Optional[float]:
    """``float(text)`` when the whole text is the *number text* grammar (ASCII
    digits only, an optional point and exponent), else ``None`` — no ``_``,
    ``,``, hexadecimal, ``nan``, ``inf`` or other digit script (R-A2L-DEF.40).
    """
    if _NUMBER_TEXT_RE.fullmatch(text):
        return float(text)
    return None


def _pack_float32(value: float) -> float:
    """The nearest FLOAT32 to ``value`` (E3S-06), for limit comparisons."""
    try:
        return struct.unpack("<f", struct.pack("<f", value))[0]
    except (struct.error, OverflowError):
        return float(value)


def _limit_less(value: float, limit: float, datatype: Optional[str]) -> bool:
    """``value < limit``, compared packed as FLOAT32 for a FLOAT32_IEEE
    datatype (E3S-06)."""
    if datatype == "FLOAT32_IEEE":
        return _pack_float32(value) < _pack_float32(limit)
    return value < limit


def _limit_greater(value: float, limit: float, datatype: Optional[str]) -> bool:
    """``value > limit``, compared packed as FLOAT32 for a FLOAT32_IEEE
    datatype (E3S-06)."""
    if datatype == "FLOAT32_IEEE":
        return _pack_float32(value) > _pack_float32(limit)
    return value > limit


def _name_echo_of(definition: Definition) -> str:
    """The definition's name echo (P-2), the ``_echo`` fallback for a
    hand-built definition."""
    return (
        definition._name_echo
        if definition._name_echo is not None
        else _echo(definition.name)
    )


def _check_limits(
    definition: Definition, limit_value: float, text: str
) -> Refusal | str | None:
    """The limit check of the encode order (R-A2L-DEF.43 … .45).

    ``text`` is the final ``<text>`` of the message (the echoed operator text
    for the limit value, the stored display text for the written value).
    Returns a refusal outside the (extended) limits, the at-most-one notice
    inside the extended limits, or ``None``.
    """
    name_echo = _name_echo_of(definition)
    limits = definition.limits
    below = limits.lower is not None and _limit_less(
        limit_value, limits.lower, definition.datatype
    )
    above = limits.upper is not None and _limit_greater(
        limit_value, limits.upper, definition.datatype
    )
    if not (below or above):
        return None
    if definition.extended_limits is None:
        return Refusal(
            "A2L-DEF-LIMITS",
            f"{name_echo}: {text} is outside the limits "
            f"{limits.lower_text}..{limits.upper_text}",
        )
    extended = definition.extended_limits
    ebelow = extended.lower is not None and _limit_less(
        limit_value, extended.lower, definition.datatype
    )
    eabove = extended.upper is not None and _limit_greater(
        limit_value, extended.upper, definition.datatype
    )
    if ebelow or eabove:
        return Refusal(
            "A2L-DEF-EXTENDED",
            f"{name_echo}: {text} is outside the extended limits "
            f"{extended.lower_text}..{extended.upper_text}",
        )
    return (
        f"{name_echo}: {text} is outside the limits {limits.lower_text}.."
        f"{limits.upper_text} and inside the extended limits "
        f"{extended.lower_text}..{extended.upper_text}"
    )


def _encode_number(
    definition: Definition, a2l_data: dict, value: float
) -> bytes | Refusal:
    """The encode direction (R-A2L-DEF.41, .42) through the frozen
    ``encode_physical_to_raw_bytes`` on a mask-free tag view, or
    ``A2L-DEF-ENCODE`` ``<name>: <reason>``."""
    name_echo = _name_echo_of(definition)
    method_name = (
        "NO_COMPU_METHOD" if definition.kind == "enum" else definition.method_name
    )
    method_table: dict = {}
    if method_name is not None and method_name != "NO_COMPU_METHOD":
        method_table = {
            method_name: {
                "conversion_type": definition.conversion_type,
                "coeffs_linear": definition.coeffs_linear,
                "coeffs": definition.coeffs,
                "compu_tab_ref": definition.compu_tab_ref,
            }
        }
    tag = {
        "char_type": None,
        "matrix_dim": None,
        "datatype": definition.datatype,
        "length": definition.byte_length,
        "effective_byte_order": definition.byte_order,
        "compu_method_name": method_name,
        "lower_limit": None,
        "upper_limit": None,
    }
    raw, reason, _flags = encode_physical_to_raw_bytes(
        tag,
        value,
        method_table,
        a2l_data.get("compu_tabs_by_name") or {},
        None,
    )
    if reason is not None:
        return Refusal("A2L-DEF-ENCODE", f"{name_echo}: {reason}")
    return bytes(raw)


def _merge_bit_mask(
    definition: Definition, field: int, text: str, image: Mapping[int, int]
) -> bytes | Refusal:
    """Write ``field`` shifted into the mask and keep every other bit of the
    image's span (R-A2L-DEF.46, .47)."""
    name_echo = _name_echo_of(definition)
    address = definition.address
    missing = 0
    values: list[int] = []
    for offset in range(definition.byte_length):
        current = address + offset
        if current not in image:
            missing += 1
        else:
            values.append(image[current] & 0xFF)
    if missing:
        return Refusal(
            "A2L-DEF-BYTES",
            f"{name_echo}: {_number_text(missing)} of its "
            f"{_number_text(definition.byte_length)} bytes are not in the image",
        )
    word = int.from_bytes(bytes(values), definition.byte_order)
    mask = definition.bit_mask
    shift = _mask_shift(mask)
    if field < 0 or ((field << shift) & ~mask) != 0:
        return Refusal(
            "A2L-DEF-MASK-VALUE",
            f"{name_echo}: {_operator_echo(text)} does not fit the bit mask "
            f"{_echo(definition.bit_mask_text)}",
        )
    merged = (word & ~mask) | (field << shift)
    return merged.to_bytes(definition.byte_length, definition.byte_order)


def _encode_enum(definition: Definition, text: str) -> float | Refusal:
    """The raw of the first entry whose text equals ``text`` (case included),
    else ``A2L-DEF-ENUM`` (R-A2L-DEF.48, .49)."""
    name_echo = _name_echo_of(definition)
    for entry in definition.enum_entries:
        if entry.text == text:
            return entry.raw
    table_echo = (
        _echo(definition.enum_table)
        if definition.enum_table is not None
        else "(none)"
    )
    return Refusal(
        "A2L-DEF-ENUM",
        f"{name_echo}: '{_operator_echo(text)}' is not a text of {table_echo}",
    )


def _encode_ascii(definition: Definition, text: str) -> bytes | Refusal:
    """The text's printable-ASCII bytes padded with 0x00 to the byte length
    (R-A2L-DEF.50 … .52)."""
    name_echo = _name_echo_of(definition)
    length = definition.byte_length
    if len(text) > length:
        return Refusal(
            "A2L-DEF-TEXT-LENGTH",
            f"{name_echo}: the text has {len(text)} characters — at most "
            f"{length} fit",
        )
    for ch in text:
        if not (0x20 <= ord(ch) <= 0x7E):
            return Refusal(
                "A2L-DEF-TEXT-CHAR",
                f"{name_echo}: '{_operator_echo(ch)}' is not a printable ASCII "
                "character",
            )
    return text.encode("ascii") + b"\x00" * (length - len(text))


def _agrees_at_display_precision(
    definition: Definition, decoded: float, value: float
) -> bool:
    """The CTX *agree at the display precision* rule (R-A2L-DEF.54, .55)."""
    decimals = definition.decimals
    if decimals is not None and abs(decoded - value) <= 0.5 * (10.0 ** (-decimals)):
        return True
    if f"{decoded:.15g}" == f"{value:.15g}":
        return True
    if definition.datatype == "FLOAT32_IEEE" and f"{decoded:.6g}" == f"{value:.6g}":
        return True
    return False


def _selected_bits(
    address: int,
    byte_length: int,
    byte_order: str,
    bit_mask: Optional[int],
) -> dict[int, int]:
    """The bits an object selects (CTX *bits an object selects*): address →
    the bits of that byte the mask selects; 0xFF of every byte when the mask is
    ``None`` (R-A2L-DEF.138)."""
    if bit_mask is None:
        return {address + i: 0xFF for i in range(byte_length)}
    bits: dict[int, int] = {}
    for i in range(byte_length):
        if byte_order == "big":
            shift = 8 * (byte_length - 1 - i)
        else:
            shift = 8 * i
        byte_mask = (bit_mask >> shift) & 0xFF
        if byte_mask:
            bits[address + i] = byte_mask
    return bits


def _pair_exempt(
    definition: Definition, entry: tuple, mask_of: Callable[[str], Optional[int]]
) -> bool:
    """Whether the pair ``definition`` / ``entry`` is left out of the overlap
    guard: both masks read (the definition's own, and the neighbour's via
    ``mask_of``) and no common selected bit (R-A2L-DEF.138)."""
    if definition.refusal is not None:
        return False
    if definition.byte_length is None or definition.byte_length < 1:
        return False
    my_mask = definition.bit_mask
    if my_mask is None:
        return False
    if entry[2] in ("BLOB", "INSTANCE"):
        return False
    other_mask = mask_of(entry[1])
    if other_mask is None:
        return False
    my_bits = _selected_bits(
        definition.address, definition.byte_length, definition.byte_order, my_mask
    )
    other_bits = _selected_bits(entry[3], entry[4], entry[5], other_mask)
    for addr, mask in my_bits.items():
        if mask & other_bits.get(addr, 0):
            return False
    return True


def _entry_overlaps(definition: Definition, entry: tuple) -> bool:
    """Whether the entry's span (an interval, or its declared address as a
    fail-closed point when its length is unreadable) overlaps the definition's
    span."""
    if definition.byte_length is not None and definition.byte_length >= 1:
        first = definition.address
        last = definition.address + definition.byte_length - 1
    else:
        first = last = definition.address
    other_address = entry[3]
    other_length = entry[4]
    if other_length is not None and other_length >= 1:
        other_first = other_address
        other_last = other_address + other_length - 1
    else:
        other_first = other_last = other_address
    return first <= other_last and other_first <= last


def _shared_with(
    definition: Definition,
    span_index: Mapping[int, tuple],
    mask_of: Callable[[str], Optional[int]],
) -> Optional[str]:
    """The name of the first other entry, in cross-kind file order, whose span
    overlaps the definition's span (or whose declared address lies inside it
    when that entry has no readable length), unless the pair's clean masks
    select no common bit (R-A2L-DEF.138)."""
    address = definition.address
    if address is None:
        return None
    if definition.byte_length is not None and definition.byte_length >= 1:
        pages = range(
            address >> 4, ((address + definition.byte_length - 1) >> 4) + 1
        )
    else:
        pages = (address >> 4,)
    seen: set[int] = set()
    multi_page = len(pages) > 1
    candidates: list[tuple] = []
    for page in pages:
        for entry in span_index.get(page, ()):
            if multi_page:
                key = entry[0]
                if key in seen:
                    continue
                seen.add(key)
            candidates.append(entry)
    if multi_page:
        candidates.sort(key=lambda entry: entry[0])
    own_entry = True
    for entry in candidates:
        if own_entry and (
            entry[1] == definition.name
            and entry[2] == definition.section
            and entry[3] == definition.address
            and entry[4] == definition.byte_length
            and entry[5] == definition.byte_order
        ):
            own_entry = False
            continue
        if _entry_overlaps(definition, entry) and not _pair_exempt(
            definition, entry, mask_of
        ):
            return entry[1]
    return None


def _image_span_refusal(
    definition: Definition, image: Mapping[int, int], name_echo: str
) -> Optional[Refusal]:
    """The ``A2L-DEF-BYTES`` refusal when a byte of the span is not in the
    image, else ``None`` (the encode's step-6 check, every kind)."""
    missing = 0
    for offset in range(definition.byte_length):
        if definition.address + offset not in image:
            missing += 1
    if missing:
        return Refusal(
            "A2L-DEF-BYTES",
            f"{name_echo}: {_number_text(missing)} of its "
            f"{_number_text(definition.byte_length)} bytes are not in the image",
        )
    return None


def _exact_decimal(text: str) -> Optional[Decimal]:
    """The exact :class:`decimal.Decimal` of a number text, normalizing the
    trailing / leading point forms ``1.`` and ``.5`` that ``Decimal`` rejects;
    ``None`` when the text still does not read (the float round-trip then
    decides)."""
    normalized = text
    if normalized.endswith("."):
        normalized = normalized + "0"
    if normalized.startswith("."):
        normalized = "0" + normalized
    elif normalized.startswith("+."):
        normalized = "+0" + normalized[1:]
    elif normalized.startswith("-."):
        normalized = "-0" + normalized[1:]
    try:
        return Decimal(normalized)
    except Exception:
        return None


def _count_live_keyword(lines: list[str], keyword: str) -> int:
    """The number of times ``keyword`` appears in ``lines`` with comments left
    out (a live keyword)."""
    return sum(1 for token in _flatten_body_tokens(lines) if token == keyword)


def _mask_byte_order_ambiguous(
    tag: dict,
    section: Optional[dict],
    object_lines: dict,
    a2l_data: dict,
    maps: dict,
) -> bool:
    """Whether a masked definition's own object, record layout or MOD_COMMON
    holds more than one live BYTE_ORDER keyword (R-A2L-DEF.19/7)."""
    if object_lines.get("byte_order_count", 0) > 1:
        return True
    layouts = a2l_data.get("record_layouts_by_name") or {}
    layout_name = tag.get("record_layout_name") or tag.get("deposit")
    layout_section = layouts.get(layout_name) if layout_name else None
    if layout_section is not None and _count_live_keyword(
        [layout_section.get("meta", "") or ""] + (layout_section.get("lines") or []),
        "BYTE_ORDER",
    ) > 1:
        return True
    mc_section = (
        maps["mod_common_of"].get(id(section)) if section is not None else None
    )
    if mc_section is not None and _count_live_keyword(
        [mc_section.get("meta", "") or ""] + (mc_section.get("lines") or []),
        "BYTE_ORDER",
    ) > 1:
        return True
    return False


def encode_definition(
    definition: Definition,
    a2l_data: dict,
    text: str,
    image: Mapping[int, int],
) -> Encoded | Refusal:
    """Encode an operator's text into the bytes of the definition's whole span
    (I-2; the encode order of R-A2L-DEF.40 … .57, .138, .152).

    Args:
        definition (Definition): The definition to encode (its refusal is
            returned first, R-A2L-DEF.25).
        a2l_data (dict): The parse payload (its ``errors`` gate the write
            under R-A2L-DEF.152, its ``compu_tabs_by_name`` serves the encode
            direction).
        text (str): The operator's text.
        image (Mapping[int, int]): address → byte, read only.

    Returns:
        Encoded | Refusal: the whole span to write, or the first refusal of
            the encode order.

    Raises:
        None.
    """
    if definition.refusal is not None:
        return definition.refusal
    name_echo = _name_echo_of(definition)

    errors = a2l_data.get("errors") or []
    if errors:
        return Refusal(
            "A2L-DEF-PARSE",
            f"{name_echo}: the A2L cannot be edited while it has parse errors "
            f"— the first is {errors[0]}",
        )

    if definition.kind in ("array", "curve", "map"):
        return Refusal(
            "A2L-DEF-ELEMENTS",
            f"{name_echo}: it holds {definition.element_count} values — decode and "
            "encode it value by value",
        )

    if definition.kind == "text":
        data = _encode_ascii(definition, text)
        if isinstance(data, Refusal):
            return data
        byte_refusal = _image_span_refusal(definition, image, name_echo)
        if byte_refusal is not None:
            return byte_refusal
        if definition.shared_with is not None:
            return Refusal(
                "A2L-DEF-OVERLAP",
                f"{name_echo}: its bytes at {_fmt_address(definition.address)} "
                f"are shared with {_echo(definition.shared_with)}",
            )
        return Encoded(definition.address, data, ())

    trimmed = text.strip(" ")
    if definition.kind == "number":
        value = _parse_number_text(trimmed)
        if value is None:
            return Refusal(
                "A2L-DEF-NUMBER",
                f"{name_echo}: '{_operator_echo(trimmed)}' is not a number",
            )
        limit_value = value
    else:
        raw = _encode_enum(definition, trimmed)
        if isinstance(raw, Refusal):
            return raw
        limit_value = raw

    limits_outcome = _check_limits(definition, limit_value, _operator_echo(trimmed))
    if isinstance(limits_outcome, Refusal):
        return limits_outcome

    data = _encode_number(definition, a2l_data, limit_value)
    if isinstance(data, Refusal):
        return data

    byte_refusal = _image_span_refusal(definition, image, name_echo)
    if byte_refusal is not None:
        return byte_refusal

    if definition.bit_mask is not None:
        field = _decode_scalar(data, definition.datatype, definition.byte_order)
        data = _merge_bit_mask(definition, field, trimmed, image)
        if isinstance(data, Refusal):
            return data

    notices: tuple[str, ...] = ()
    if isinstance(limits_outcome, str):
        notices = (limits_outcome,)

    if definition.kind == "number":
        written_image = {definition.address + i: byte for i, byte in enumerate(data)}
        decoded = decode_definition(definition, a2l_data, written_image)
        if isinstance(decoded, Refusal):
            return Refusal(
                "A2L-DEF-PRECISION",
                f"{name_echo}: {_operator_echo(trimmed)} cannot be stored at the "
                "display precision — the nearest stored value is (none)",
            )
        p = decoded.value
        stored_text = decoded.text

        rejects = False
        if (
            definition.datatype is not None
            and definition.datatype not in _FLOAT_DATATYPES
            and definition.conversion_type in (None, "IDENTICAL")
        ):
            exact = _exact_decimal(trimmed)
            if exact is not None and exact != Decimal(int(p)):
                rejects = True
        if not rejects and not _agrees_at_display_precision(
            definition, p, limit_value
        ):
            rejects = True
        if rejects:
            return Refusal(
                "A2L-DEF-PRECISION",
                f"{name_echo}: {_operator_echo(trimmed)} cannot be stored at the "
                f"display precision — the nearest stored value is {stored_text}",
            )

        written_outcome = _check_limits(definition, p, stored_text)
        if isinstance(written_outcome, Refusal):
            return written_outcome
        if not notices and isinstance(written_outcome, str):
            notices = (written_outcome,)

    if definition.shared_with is not None:
        return Refusal(
            "A2L-DEF-OVERLAP",
            f"{name_echo}: its bytes at {_fmt_address(definition.address)} "
            f"are shared with {_echo(definition.shared_with)}",
        )
    return Encoded(definition.address, data, notices)
