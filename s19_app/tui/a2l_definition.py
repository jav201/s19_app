"""The A2L definition model, read side (Inc 2a).

This module builds the *definition* of one scalar A2L object (a VALUE
CHARACTERISTIC, an ASCII CHARACTERISTIC, or a MEASUREMENT whose MATRIX_DIM is
1 or absent) from the parse payload of :func:`s19_app.tui.a2l.parse_a2l_file`,
decodes its stored bytes into a value and a display text, and formats a number
for display.  It is the read side of interface I-2 (``describe`` / ``decode`` /
``display``); the write side (``encode``, the span index, the overlap guard and
the text-of-object bit-mask clauses) is Inc 2b and is not written here.

The module is pure: standard library plus ``s19_app.tui.a2l`` only, no
``textual`` import, no file or clipboard I/O, no global mutable state, and it
never raises on file or image content — every failure is a :class:`Refusal`
value.  It reads ``a2l_data`` and the image and writes neither.
"""

from __future__ import annotations

import heapq
import math
import struct
from bisect import bisect_left
from dataclasses import dataclass, field, replace
from decimal import Decimal
from types import MappingProxyType
from typing import Iterable, Mapping, Optional

from .a2l import (
    DATATYPE_SIZES,
    MAX_A2L_DECODE_BYTES,
    _apply_compu_method,
    _decode_scalar,
    _flatten_body_tokens,
    _resolve_record_layout,
    _to_float,
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
    refusal: Optional[Refusal]
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
            ``tags``, ``record_layouts_by_name``, ``compu_methods_by_name``,
            ``compu_tabs_by_name``).  Read, never written.

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
    mask).  A ``reads`` map (one per call, keyed by the ``id()`` of a section
    an object names) holds the method record, enum table and layout datatype
    each read once, so a name's time does not grow with the size of a section
    it shares (R-A2L-DEF.149); the map is dropped when the call returns.

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

    def _walk(nodes: list[dict]) -> None:
        for node in nodes:
            node_name = node.get("name")
            parsed = parse_begin_meta(node.get("meta", "") or "")
            if node_name in ("MEASUREMENT", "CHARACTERISTIC"):
                object_sections_by_name.setdefault(parsed[0], []).append(node)
            elif node_name == "COMPU_METHOD":
                compu_methods_by_name.setdefault(parsed[0], node)
            elif node_name in ("COMPU_VTAB", "COMPU_VTAB_RANGE"):
                compu_tables_by_name.setdefault(parsed[0], node)
            _walk(node.get("children") or [])

    _walk(a2l_data.get("sections") or [])

    result: dict[str, Definition] = {}
    reads: dict[int, object] = {}
    for name in names:
        if name in result:
            continue
        result[name] = _describe_one(
            name,
            tags_by_name,
            object_sections_by_name,
            compu_methods_by_name,
            compu_tables_by_name,
            a2l_data,
            reads,
        )
    return result


def _describe_one(
    name: str,
    tags_by_name: dict[str, list[dict]],
    object_sections_by_name: dict[str, list[dict]],
    compu_methods_by_name: dict[str, dict],
    compu_tables_by_name: dict[str, dict],
    a2l_data: dict,
    reads: dict[int, object],
) -> Definition:
    """Read every field and the refusal for one name (the body of
    :func:`describe_definitions`)."""
    name_echo = _echo(name)
    empty = Definition(
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
        refusal=None,
        _name_echo=name_echo,
        _table_form=None,
    )

    found = _find_tag(name, tags_by_name, object_sections_by_name)
    if found is None:
        return _with_refusal(
            empty, Refusal("A2L-DEF-NAME", f"{name_echo}: no tag of that name in the A2L")
        )
    if isinstance(found, Refusal):
        return _with_refusal(empty, found)

    tag, section = found

    # Copy the tag so the MEASUREMENT fill never mutates the parse payload
    # (R-A2L-DEF.58.1).
    tag = dict(tag)
    object_lines = _read_object_lines(section)

    # E2-1 / R-A2L-014: a MEASUREMENT whose tag lacks them is filled from the
    # header words (datatype, conversion word, limit words) and, with a
    # datatype, the length = size × MATRIX_DIM (1 when absent).
    if tag.get("section") == "MEASUREMENT":
        header = object_lines.get("header") or []
        if tag.get("datatype") is None and len(header) > 2:
            tag["datatype"] = header[2]
        if tag.get("conversion") is None and len(header) > 3:
            tag["conversion"] = header[3]
        if tag.get("lower_limit") is None and len(header) > 6:
            tag["lower_limit"] = header[6]
        if tag.get("upper_limit") is None and len(header) > 7:
            tag["upper_limit"] = header[7]
        if tag.get("length") is None and tag.get("datatype") in DATATYPE_SIZES:
            matrix_dim = tag.get("matrix_dim")
            mult = (
                matrix_dim
                if isinstance(matrix_dim, int) and not isinstance(matrix_dim, bool)
                else 1
            )
            tag["length"] = DATATYPE_SIZES[tag["datatype"]] * mult

    address = tag.get("address")
    byte_length = tag.get("length")
    datatype = _resolve_datatype(tag, a2l_data, reads)
    byte_order = tag.get("effective_byte_order") or "little"
    char_type = tag.get("char_type")
    section_name = tag.get("section") or ""

    method_name = tag.get("conversion")
    method_echo = _echo(method_name) if method_name is not None else "(none)"
    record: Optional[Mapping] = None
    if method_name is not None and method_name != "NO_COMPU_METHOD":
        record = _read_method_record(
            method_name,
            compu_methods_by_name,
            compu_tables_by_name,
            a2l_data.get("compu_tabs_by_name") or {},
            reads,
        )

    if record is not None:
        conversion_type = record.get("conversion_type")
        coeffs_linear: Optional[tuple[Optional[float], Optional[float]]] = (
            tuple(record["coeffs_linear"])
            if record.get("coeffs_linear") is not None
            else None
        )
        coeffs: Optional[tuple[Optional[float], ...]] = (
            tuple(record["coeffs"]) if record.get("coeffs") is not None else None
        )
        compu_tab_ref = record.get("compu_tab_ref")
        record_format = record.get("format")
        record_unit = record.get("unit")
        type_verdict = record.get("type_verdict")
        type_echo = record.get("type_echo")
        table_echo = record.get("table_echo")
    else:
        conversion_type = None
        coeffs_linear = None
        coeffs = None
        compu_tab_ref = None
        record_format = None
        record_unit = None
        type_verdict = None
        type_echo = "(none)"
        table_echo = "(none)"

    kind, kind_text = _object_kind(tag, conversion_type)

    object_format = object_lines.get("format")
    display_format = object_format if object_format is not None else record_format
    if object_format is not None:
        decimals = _display_decimals(object_format)
    else:
        decimals = record.get("decimals") if record is not None else None
    unit = object_lines.get("unit")
    if unit is None:
        unit = record_unit or ""
    unit = unit or ""

    limits = _read_limits(tag.get("lower_limit"), tag.get("upper_limit"))
    extended_limits = object_lines.get("extended_limits")

    mask_word = object_lines.get("bit_mask")
    mask_number: Optional[int] = None
    if kind in ("number", "enum") and mask_word is not None:
        mask_number = _parse_bit_mask(mask_word)

    enum_table: Optional[str] = None
    enum_entries: tuple[EnumEntry, ...] = ()
    default_text: Optional[str] = None
    table_form: Optional[_EnumForm | _TabForm] = None
    if kind == "enum":
        enum_table = compu_tab_ref
        enum_form = record.get("table_form") if record is not None else None
        if isinstance(enum_form, _EnumForm):
            table_form = enum_form
            enum_entries = enum_form.entries
            default_text = enum_form.default_text
    elif kind == "number" and type_verdict in ("TAB_INTP", "TAB_NOINTP"):
        tab_form = record.get("table_form") if record is not None else None
        if isinstance(tab_form, _TabForm):
            table_form = tab_form

    # ---- the refusal order -------------------------------------------------
    refusal: Optional[Refusal] = None
    if kind is None:
        kind_echo = kind_text
        if kind_text != "(none)" and not kind_text.startswith("MATRIX_DIM "):
            kind_echo = _echo(kind_text)
        refusal = Refusal(
            "A2L-DEF-KIND",
            f"{name_echo}: the system has no definition for a {kind_echo} object",
        )
    elif address is None or byte_length is None:
        refusal = Refusal(
            "A2L-DEF-ADDRESS", f"{name_echo}: the object has no address or no length"
        )
    elif (
        byte_length < 1
        or byte_length > MAX_A2L_DECODE_BYTES
        or address < 0
        or address + byte_length - 1 > 0xFFFFFFFF
    ):
        refusal = Refusal(
            "A2L-DEF-ADDRESS",
            f"{name_echo}: its span of {byte_length} bytes at "
            f"{_fmt_address(address)} cannot be read",
        )
    elif kind in ("number", "enum"):
        if datatype is None:
            refusal = Refusal(
                "A2L-DEF-DATATYPE",
                f"{name_echo}: the object declares no datatype the system can read",
            )
        elif byte_length != DATATYPE_SIZES[datatype]:
            refusal = Refusal(
                "A2L-DEF-LENGTH",
                f"{name_echo}: its length {byte_length} differs from the "
                f"{DATATYPE_SIZES[datatype]} bytes of {datatype}",
            )

    if refusal is None and method_name is not None and method_name != "NO_COMPU_METHOD":
        if record is None:
            refusal = Refusal(
                "A2L-DEF-METHOD",
                f"{name_echo}: the conversion method {method_echo} "
                "is not declared in the A2L",
            )
        elif type_verdict is None:
            refusal = Refusal(
                "A2L-DEF-CONVERSION",
                f"{name_echo}: the conversion type {type_echo} of "
                f"{method_echo} is not supported",
            )

    if refusal is None and kind == "enum":
        if enum_table is None:
            refusal = Refusal(
                "A2L-DEF-TABLE",
                f"{name_echo}: the table (none) of {method_echo} "
                "is not declared in the A2L",
            )
        elif table_form is None:
            refusal = Refusal(
                "A2L-DEF-TABLE",
                f"{name_echo}: the table {table_echo} of "
                f"{method_echo} is not declared in the A2L",
            )
        elif not enum_entries:
            refusal = Refusal(
                "A2L-DEF-TABLE-EMPTY",
                f"{name_echo}: the table {table_echo} has no entries",
            )

    if refusal is None and mask_word is not None:
        if kind == "text":
            refusal = Refusal(
                "A2L-DEF-MASK",
                f"{name_echo}: the bit mask {_echo(mask_word)} cannot be "
                f"applied to {_echo(char_type)}",
            )
        elif kind in ("number", "enum"):
            if mask_number is None or not _check_bit_mask(mask_number, datatype):
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
        byte_length=byte_length,
        datatype=datatype,
        byte_order=byte_order,
        bit_mask=mask_number if kind in ("number", "enum") else None,
        bit_mask_text=mask_word,
        conversion_type=conversion_type,
        method_name=method_name,
        display_format=display_format,
        decimals=decimals,
        unit=unit,
        limits=limits,
        extended_limits=extended_limits,
        enum_table=enum_table,
        enum_entries=enum_entries,
        default_text=default_text,
        coeffs_linear=coeffs_linear,
        coeffs=coeffs,
        compu_tab_ref=compu_tab_ref,
        refusal=refusal,
        _name_echo=name_echo,
        _table_form=table_form,
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


def _object_kind(tag: dict, conversion_type: Optional[str]) -> tuple[Optional[str], str]:
    """The scalar kind and its text: ``(kind, kind_text)``.

    A CHARACTERISTIC of ``char_type`` ASCII → ``("text", "ASCII")``; VALUE →
    ``("enum"/"number", "VALUE")``; a MEASUREMENT whose matrix_dim is None or 1
    → ``("enum"/"number", "MEASUREMENT")``; every other object → ``(None, the
    <kind> text)``.
    """
    section = tag.get("section")
    char_type = tag.get("char_type")
    if section == "CHARACTERISTIC":
        if char_type == "ASCII":
            return "text", "ASCII"
        if char_type == "VALUE":
            kind = "enum" if conversion_type == "TAB_VERB" else "number"
            return kind, "VALUE"
        if char_type is None:
            return None, "(none)"
        return None, str(char_type)
    if section == "MEASUREMENT":
        matrix_dim = tag.get("matrix_dim")
        if matrix_dim is None or matrix_dim == 1:
            kind = "enum" if conversion_type == "TAB_VERB" else "number"
            return kind, "MEASUREMENT"
        return None, f"MATRIX_DIM {matrix_dim} MEASUREMENT"
    return None, "(none)"


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
    if conversion_type:
        upper = str(conversion_type).upper()
        type_verdict = upper if upper in _SUPPORTED_CONVERSION_TYPES else None
    else:
        type_verdict = None
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
    ``unit`` and ``bit_mask`` (the raw word, readable or not, for every kind).

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
    }
    if section is None:
        return result
    tokens = _flatten_body_tokens(
        [section.get("meta", "") or ""] + (section.get("lines") or [])
    )
    header_len = 8 if section.get("name") == "MEASUREMENT" else 9
    result["header"] = tokens[:header_len]
    body = tokens[header_len:]
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
    None, _enum_text(...))``; number → the physical value via
    ``_apply_compu_method`` (identity for ``NO_COMPU_METHOD``), a status
    ``error`` → ``A2L-DEF-DECODE``.  Reads ``image`` and ``a2l_data`` only.

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
    stored = _read_stored_value(definition, image)
    if isinstance(stored, Refusal):
        return stored
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
                f"{name_echo}: the table {table_form.ref_echo} has an x that is not a number",
            )
        value, table_error = _table_value(
            table_form, stored, definition.conversion_type == "TAB_INTP"
        )
        if table_error:
            return Refusal("A2L-DEF-DECODE", f"{name_echo}: {table_error}")
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
            return Refusal("A2L-DEF-DECODE", f"{name_echo}: {error}")
    if not isinstance(value, (int, float)):
        if isinstance(table_form, _TabForm):
            ref_echo = table_form.ref_echo
        elif definition.compu_tab_ref is not None:
            ref_echo = _echo(definition.compu_tab_ref)
        else:
            ref_echo = "(none)"
        return Refusal(
            "A2L-DEF-DECODE",
            f"{name_echo}: the table {ref_echo} gives a value that is not a number",
        )
    return Decoded(stored, value, display_text(definition, value))


def _read_stored_value(
    definition: Definition, image: Mapping[int, int]
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
        name_echo = (
            definition._name_echo
            if definition._name_echo is not None
            else _echo(definition.name)
        )
        return Refusal(
            "A2L-DEF-BYTES",
            f"{name_echo}: {missing} of its {length} bytes "
            "are not in the image",
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
            lo = i - 1
            while lo > 0 and xs[lo - 1] == xs[lo]:
                lo -= 1
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
